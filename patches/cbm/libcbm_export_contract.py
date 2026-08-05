#!/usr/bin/env python3
"""Build and verify the static libcbm symbol-localization contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import mmap
import os
from pathlib import Path
import re
import shlex
import struct
import subprocess
import sys
import tempfile


SYMBOL = re.compile(r"^_?cbm_[A-Za-z0-9_]+$")
BINDING = re.compile(r"(?m)^\s*pub fn (cbm_[A-Za-z0-9_]+)\s*\(")
PE_REFPTR = re.compile(r"^\.refptr\.([A-Za-z_][A-Za-z0-9_@$?]*)$")
COFF_AMD64 = 0x8664
COFF_HEADER_BYTES = 20
COFF_SECTION_BYTES = 40
COFF_SYMBOL_BYTES = 18
COFF_RELOCATION_BYTES = 10
COFF_CLASS_EXTERNAL = 2
COFF_CLASS_STATIC = 3
COFF_SECTION_COMDAT = 0x00001000
COFF_AMD64_ADDR64 = 0x0001


class ContractError(Exception):
    def __init__(self, code: str, message: str, remediation: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.remediation = remediation


def refuse(code: str, message: str, remediation: str) -> None:
    raise ContractError(code, message, remediation)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as input_file:
            while chunk := input_file.read(8 * 1024 * 1024):
                digest.update(chunk)
    except OSError as error:
        refuse(
            "ASTRO_LIBCBM_EXPORT_INPUT_UNREADABLE",
            f"cannot hash {path}: {error}",
            "restore the exact generated object and rerun the native build",
        )
    return digest.hexdigest()


def read_bytes(path: Path, purpose: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as error:
        refuse(
            "ASTRO_LIBCBM_EXPORT_INPUT_UNREADABLE",
            f"cannot read {purpose} {path}: {error}",
            "restore the exact declared build input and rerun the native build",
        )


def durable_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        observed = path.read_bytes()
        if observed != data:
            refuse(
                "ASTRO_LIBCBM_EXPORT_WRITE_MISMATCH",
                f"durable readback differs for {path}",
                "inspect the build volume and rerun only after writes read back exactly",
            )
    finally:
        if temporary.exists():
            temporary.unlink()


def run_tool(arguments: list[str], purpose: str) -> str:
    try:
        completed = subprocess.run(
            arguments,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        refuse(
            "ASTRO_LIBCBM_EXPORT_TOOL_UNREACHABLE",
            f"cannot execute {purpose} tool {arguments[0]!r}: {error}",
            "bootstrap the pinned native GNU toolchain and pass its exact tool path",
        )
    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="replace").strip()
        refuse(
            "ASTRO_LIBCBM_EXPORT_TOOL_FAILED",
            f"{purpose} exited {completed.returncode}: {stderr}",
            "inspect the exact object/tool diagnostic; do not publish a partial archive",
        )
    stderr = completed.stderr.decode("utf-8", errors="replace").strip()
    if stderr:
        refuse(
            "ASTRO_LIBCBM_EXPORT_TOOL_DIAGNOSTIC",
            f"{purpose} emitted stderr despite exit 0: {stderr}",
            "treat analysis-tool warnings as structural failures and repair the object before publication",
        )
    try:
        return completed.stdout.decode("utf-8")
    except UnicodeDecodeError as error:
        refuse(
            "ASTRO_LIBCBM_EXPORT_TOOL_OUTPUT_INVALID",
            f"{purpose} emitted non-UTF-8 output: {error}",
            "use the pinned GNU analysis tool whose symbol output is UTF-8",
        )


def parse_nm(output: str, purpose: str) -> list[tuple[str, str, str]]:
    records: list[tuple[str, str, str]] = []
    malformed: list[str] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        fields = line.split()
        if len(fields) >= 3 and fields[0].endswith(":") and len(fields[2]) == 1:
            origin = fields[0][:-1]
            name = fields[1]
            symbol_type = fields[2]
        elif len(fields) >= 2 and len(fields[1]) == 1:
            origin = "<single-input>"
            name = fields[0]
            symbol_type = fields[1]
        else:
            malformed.append(line)
            continue
        records.append((name, symbol_type, origin))
    if malformed:
        refuse(
            "ASTRO_LIBCBM_EXPORT_NM_FORMAT_INVALID",
            f"cannot parse {purpose} nm output; first line: {malformed[0]!r}",
            "use pinned GNU nm with POSIX format; do not guess at the symbol table",
        )
    return records


def nm_records(nm: str, inputs: list[str], purpose: str) -> list[tuple[str, str, str]]:
    output = run_tool(
        [
            nm,
            "--format=posix",
            "--print-file-name",
            "--defined-only",
            "--extern-only",
            *inputs,
        ],
        purpose,
    )
    return parse_nm(output, purpose)


def coff_layout(data: mmap.mmap) -> dict[str, int]:
    if len(data) < COFF_HEADER_BYTES:
        refuse(
            "ASTRO_LIBCBM_COFF_HEADER_TRUNCATED",
            f"combined object has {len(data)} bytes, smaller than a COFF header",
            "inspect the failed partial link; never localize a truncated object",
        )
    machine, section_count, _timestamp, symbol_offset, symbol_count, optional_bytes, _flags = (
        struct.unpack_from("<HHLLLHH", data, 0)
    )
    if machine != COFF_AMD64:
        refuse(
            "ASTRO_LIBCBM_COFF_MACHINE_INVALID",
            f"combined object machine is 0x{machine:04x}, expected AMD64 0x{COFF_AMD64:04x}",
            "build with the pinned native x86_64 GNU toolchain",
        )
    if section_count == 0 or optional_bytes != 0:
        refuse(
            "ASTRO_LIBCBM_COFF_OBJECT_SHAPE_INVALID",
            f"combined object sections={section_count}, optional_header_bytes={optional_bytes}",
            "supply a standard relocatable COFF object, never an image or empty object",
        )
    section_table_bytes = section_count * COFF_SECTION_BYTES
    section_table_end = COFF_HEADER_BYTES + section_table_bytes
    if section_table_end > len(data):
        refuse(
            "ASTRO_LIBCBM_COFF_SECTION_TABLE_TRUNCATED",
            f"section table ends at {section_table_end}, object bytes={len(data)}",
            "restore every fixed 40-byte COFF section header before localization",
        )
    if symbol_offset < COFF_HEADER_BYTES or symbol_count == 0:
        refuse(
            "ASTRO_LIBCBM_COFF_SYMBOL_TABLE_MISSING",
            f"combined object symbol_offset={symbol_offset}, symbol_count={symbol_count}",
            "restore the complete partial-link symbol table before localization",
        )
    symbol_bytes = symbol_count * COFF_SYMBOL_BYTES
    string_offset = symbol_offset + symbol_bytes
    if string_offset + 4 > len(data):
        refuse(
            "ASTRO_LIBCBM_COFF_SYMBOL_TABLE_TRUNCATED",
            f"symbol table ends at {string_offset}, object bytes={len(data)}",
            "inspect partial-link output and never infer missing symbol/string bytes",
        )
    string_bytes = struct.unpack_from("<L", data, string_offset)[0]
    if string_bytes < 4 or string_offset + string_bytes != len(data):
        refuse(
            "ASTRO_LIBCBM_COFF_STRING_TABLE_INVALID",
            f"string_offset={string_offset}, declared_bytes={string_bytes}, object_bytes={len(data)}",
            "restore the canonical COFF string table immediately following the symbol table",
        )
    return {
        "machine": machine,
        "section_count": section_count,
        "section_table_offset": COFF_HEADER_BYTES,
        "section_table_bytes": section_table_bytes,
        "symbol_offset": symbol_offset,
        "symbol_count": symbol_count,
        "symbol_bytes": symbol_bytes,
        "string_offset": string_offset,
        "string_bytes": string_bytes,
    }


def coff_symbol_name(data: mmap.mmap, layout: dict[str, int], offset: int) -> str:
    name_field = data[offset : offset + 8]
    if name_field[:4] == b"\0\0\0\0":
        string_relative = struct.unpack_from("<L", name_field, 4)[0]
        if string_relative < 4 or string_relative >= layout["string_bytes"]:
            refuse(
                "ASTRO_LIBCBM_COFF_SYMBOL_NAME_OFFSET_INVALID",
                f"symbol at {offset} has string offset {string_relative}",
                "inspect the exact COFF string table; never guess a symbol name",
            )
        name_start = layout["string_offset"] + string_relative
        name_end = data.find(b"\0", name_start, len(data))
        if name_end < 0:
            refuse(
                "ASTRO_LIBCBM_COFF_SYMBOL_NAME_UNTERMINATED",
                f"symbol at {offset} has no NUL-terminated long name",
                "restore the exact COFF string table before localization",
            )
        name_bytes = data[name_start:name_end]
    else:
        name_bytes = name_field.split(b"\0", 1)[0]
    if not name_bytes:
        refuse(
            "ASTRO_LIBCBM_COFF_SYMBOL_NAME_EMPTY",
            f"symbol at {offset} has an empty name",
            "inspect the partial-link symbol table before localization",
        )
    try:
        return name_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        refuse(
            "ASTRO_LIBCBM_COFF_SYMBOL_NAME_INVALID",
            f"symbol at {offset} has a non-UTF-8 name: {error}",
            "use the pinned GNU toolchain's deterministic COFF naming",
        )


def coff_primary_symbols(
    data: mmap.mmap, layout: dict[str, int]
) -> list[dict[str, int | str]]:
    symbols: list[dict[str, int | str]] = []
    index = 0
    while index < layout["symbol_count"]:
        offset = layout["symbol_offset"] + index * COFF_SYMBOL_BYTES
        value, section_number, symbol_type, storage_class, auxiliary_count = struct.unpack_from(
            "<LhHBB", data, offset + 8
        )
        if section_number > layout["section_count"]:
            refuse(
                "ASTRO_LIBCBM_COFF_SYMBOL_SECTION_INVALID",
                f"symbol index {index} names section {section_number}, maximum {layout['section_count']}",
                "inspect the corrupt combined-object symbol table",
            )
        next_index = index + 1 + auxiliary_count
        if next_index > layout["symbol_count"]:
            refuse(
                "ASTRO_LIBCBM_COFF_AUXILIARY_TRUNCATED",
                f"symbol index {index} declares {auxiliary_count} auxiliary records past the table",
                "restore the complete 18-byte COFF auxiliary record sequence",
            )
        symbols.append(
            {
                "index": index,
                "offset": offset,
                "name": coff_symbol_name(data, layout, offset),
                "value": value,
                "section_number": section_number,
                "symbol_type": symbol_type,
                "storage_class": storage_class,
                "auxiliary_count": auxiliary_count,
            }
        )
        index = next_index
    if index != layout["symbol_count"]:
        refuse(
            "ASTRO_LIBCBM_COFF_SYMBOL_CARDINALITY_INVALID",
            f"symbol walk ended at {index}, expected {layout['symbol_count']}",
            "inspect the exact primary/auxiliary symbol sequence",
        )
    return symbols


def coff_section_name(data: mmap.mmap, layout: dict[str, int], offset: int) -> str:
    name_field = data[offset : offset + 8]
    if name_field.startswith(b"/"):
        encoded_offset = name_field[1:].split(b"\0", 1)[0]
        if not encoded_offset or not encoded_offset.isdigit():
            refuse(
                "ASTRO_LIBCBM_COFF_SECTION_NAME_OFFSET_INVALID",
                f"section at {offset} has invalid long-name field {name_field!r}",
                "restore the slash-decimal COFF section-name reference",
            )
        string_relative = int(encoded_offset)
        if string_relative < 4 or string_relative >= layout["string_bytes"]:
            refuse(
                "ASTRO_LIBCBM_COFF_SECTION_NAME_OFFSET_INVALID",
                f"section at {offset} has string offset {string_relative}",
                "inspect the exact COFF string table; never guess a section name",
            )
        name_start = layout["string_offset"] + string_relative
        name_end = data.find(b"\0", name_start, len(data))
        if name_end < 0:
            refuse(
                "ASTRO_LIBCBM_COFF_SECTION_NAME_UNTERMINATED",
                f"section at {offset} has no NUL-terminated long name",
                "restore the exact COFF string table before localization",
            )
        name_bytes = data[name_start:name_end]
    else:
        name_bytes = name_field.split(b"\0", 1)[0]
    if not name_bytes:
        refuse(
            "ASTRO_LIBCBM_COFF_SECTION_NAME_EMPTY",
            f"section at {offset} has an empty name",
            "inspect the partial-link section table before localization",
        )
    try:
        return name_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        refuse(
            "ASTRO_LIBCBM_COFF_SECTION_NAME_INVALID",
            f"section at {offset} has a non-UTF-8 name: {error}",
            "use the pinned GNU toolchain's deterministic COFF naming",
        )


def coff_sections(data: mmap.mmap, layout: dict[str, int]) -> list[dict[str, int | str]]:
    sections: list[dict[str, int | str]] = []
    for zero_based in range(layout["section_count"]):
        offset = layout["section_table_offset"] + zero_based * COFF_SECTION_BYTES
        (
            _virtual_size,
            _virtual_address,
            _raw_bytes,
            _raw_offset,
            relocation_offset,
            _line_offset,
            relocation_count,
            _line_count,
            characteristics,
        ) = struct.unpack_from("<LLLLLLHHI", data, offset + 8)
        relocation_end = relocation_offset + relocation_count * COFF_RELOCATION_BYTES
        if relocation_count > 0 and (
            relocation_offset == 0 or relocation_end > layout["symbol_offset"]
        ):
            refuse(
                "ASTRO_LIBCBM_COFF_RELOCATION_TABLE_INVALID",
                f"section {zero_based + 1} relocation range={relocation_offset}..{relocation_end}",
                "restore the exact fixed 10-byte COFF relocation records before localization",
            )
        sections.append(
            {
                "index": zero_based + 1,
                "offset": offset,
                "name": coff_section_name(data, layout, offset),
                "relocation_offset": relocation_offset,
                "relocation_count": relocation_count,
                "characteristics": characteristics,
            }
        )
    return sections


def coff_refptr_structurals(
    data: mmap.mmap,
    layout: dict[str, int],
    symbols: list[dict[str, int | str]],
) -> list[dict[str, int | str]]:
    sections = {int(section["index"]): section for section in coff_sections(data, layout)}
    symbols_by_index = {int(symbol["index"]): symbol for symbol in symbols}
    structurals: list[dict[str, int | str]] = []
    for symbol in symbols:
        name = str(symbol["name"])
        match = PE_REFPTR.fullmatch(name)
        if match is None:
            continue
        if (
            symbol["storage_class"] != COFF_CLASS_EXTERNAL
            or int(symbol["section_number"]) <= 0
            or int(symbol["value"]) != 0
            or int(symbol["symbol_type"]) != 0
            or int(symbol["auxiliary_count"]) != 0
        ):
            refuse(
                "ASTRO_LIBCBM_COFF_REFPTR_SYMBOL_INVALID",
                f"refptr {name} storage_class={symbol['storage_class']}, section={symbol['section_number']}, "
                f"value={symbol['value']}, type={symbol['symbol_type']}, aux={symbol['auxiliary_count']}",
                "restore the zero-valued untyped external COMDAT selection symbol with no auxiliary record",
            )
        section_number = int(symbol["section_number"])
        section = sections[section_number]
        expected_section_name = f".rdata${name}"
        if (
            section["name"] != expected_section_name
            or int(section["characteristics"]) & COFF_SECTION_COMDAT == 0
            or int(section["relocation_count"]) != 1
        ):
            refuse(
                "ASTRO_LIBCBM_COFF_REFPTR_SECTION_INVALID",
                f"refptr {name} section={section['name']}, flags=0x{int(section['characteristics']):08x}, "
                f"relocations={section['relocation_count']}",
                "restore the exact dedicated COMDAT refptr section with one relocation",
            )
        section_symbols = [
            candidate
            for candidate in symbols
            if candidate["storage_class"] == COFF_CLASS_STATIC
            and int(candidate["section_number"]) == section_number
        ]
        if section_symbols:
            refuse(
                "ASTRO_LIBCBM_COFF_REFPTR_SECTION_SYMBOL_INVALID",
                f"refptr {name} retains {len(section_symbols)} static symbols in its section: "
                f"{[candidate['name'] for candidate in section_symbols[:3]]}",
                "use the complete pinned GNU ld -r partial link, which consumes the section definition while preserving the COMDAT selector",
            )
        relocation_offset = int(section["relocation_offset"])
        virtual_address, target_index, relocation_type = struct.unpack_from(
            "<LLH", data, relocation_offset
        )
        target_symbol = symbols_by_index.get(target_index)
        expected_target = match.group(1)
        if (
            virtual_address != 0
            or relocation_type != COFF_AMD64_ADDR64
            or target_symbol is None
            or target_symbol["name"] != expected_target
        ):
            refuse(
                "ASTRO_LIBCBM_COFF_REFPTR_RELOCATION_INVALID",
                f"refptr {name} relocation offset={virtual_address}, type=0x{relocation_type:04x}, "
                f"target_index={target_index}, target={None if target_symbol is None else target_symbol['name']}",
                "restore the exact zero-offset AMD64 ADDR64 relocation to the name-bound target",
            )
        structurals.append(
            {
                "symbol": name,
                "symbol_index": int(symbol["index"]),
                "section": expected_section_name,
                "section_index": section_number,
                "section_definition": "absent-after-complete-partial-link",
                "relocation_offset": 0,
                "relocation_type": relocation_type,
                "target": expected_target,
                "target_index": target_index,
            }
        )
    structurals.sort(key=lambda structural: str(structural["symbol"]))
    structural_names = [str(structural["symbol"]) for structural in structurals]
    if len(structural_names) != len(set(structural_names)):
        refuse(
            "ASTRO_LIBCBM_COFF_REFPTR_DUPLICATE",
            "combined object contains duplicate defined refptr COMDAT selection symbols",
            "repair the partial-link COMDAT resolution before localization",
        )
    return structurals


def normalize(symbol: str) -> str:
    return symbol[1:] if symbol.startswith("_cbm_") else symbol


def binding_symbols(path: Path) -> tuple[list[str], str]:
    data = read_bytes(path, "committed bindgen ABI")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        refuse(
            "ASTRO_LIBCBM_EXPORT_BINDINGS_INVALID",
            f"committed bindings are not UTF-8: {error}",
            "regenerate and inspect the native bindgen candidate before promotion",
        )
    required = sorted(set(BINDING.findall(text)))
    if not required:
        refuse(
            "ASTRO_LIBCBM_EXPORT_REQUIRED_EMPTY",
            f"committed bindings {path} declare no cbm_* functions",
            "restore a non-empty inspected cbm-sys binding surface",
        )
    return required, sha256(data)


def object_arguments(path: Path) -> tuple[list[str], str]:
    data = read_bytes(path, "object response file")
    try:
        objects = shlex.split(data.decode("utf-8"), posix=True)
    except (UnicodeDecodeError, ValueError) as error:
        refuse(
            "ASTRO_LIBCBM_EXPORT_OBJECT_LIST_INVALID",
            f"object response file {path} is invalid: {error}",
            "regenerate the deterministic response file from LIBCBM_OBJS",
        )
    if not objects:
        refuse(
            "ASTRO_LIBCBM_EXPORT_OBJECT_LIST_EMPTY",
            f"object response file {path} is empty",
            "compile the declared libcbm translation units before localization",
        )
    return objects, sha256(data)


def export_inventory(
    records: list[tuple[str, str, str]],
) -> tuple[list[str], dict[str, list[str]]]:
    definitions: dict[str, list[tuple[str, str]]] = {}
    for actual, _symbol_type, origin in records:
        if SYMBOL.fullmatch(actual):
            definitions.setdefault(normalize(actual), []).append((actual, origin))
    duplicates = {
        logical: [f"{actual}@{origin}" for actual, origin in found]
        for logical, found in definitions.items()
        if len(found) != 1
    }
    if duplicates:
        first = sorted(duplicates)[0]
        refuse(
            "ASTRO_LIBCBM_EXPORT_DUPLICATE",
            f"export {first} has multiple definitions: {', '.join(duplicates[first])}",
            "remove the duplicate cbm_* definition; multiple-definition linker policy is not API authority",
        )
    actual = sorted(found[0][0] for found in definitions.values())
    return actual, duplicates


def prepare(args: argparse.Namespace) -> None:
    objects, response_hash = object_arguments(args.objects_response)
    required, bindings_hash = binding_symbols(args.bindings)
    records = nm_records(args.nm, [f"@{args.objects_response}"], "input-object symbol scan")
    exports, _ = export_inventory(records)
    if not exports:
        refuse(
            "ASTRO_LIBCBM_EXPORT_LIST_EMPTY",
            "input objects define no external cbm_* symbols",
            "restore the libcbm sources or correct the exact object response file",
        )
    observed_logical = {normalize(symbol) for symbol in exports}
    missing = sorted(set(required) - observed_logical)
    if missing:
        refuse(
            "ASTRO_LIBCBM_EXPORT_REQUIRED_MISSING",
            f"{len(missing)} required bindgen export(s) have no definition; first: {missing[0]}",
            "restore the missing C definition or remove the stale declaration through an inspected bindings update",
        )
    export_bytes = ("\n".join(exports) + "\n").encode("utf-8")
    durable_write(args.exports, export_bytes)
    audit = {
        "format": "astrolabe.libcbm-export-input.v1",
        "bindings": {
            "path": args.bindings.as_posix(),
            "sha256": bindings_hash,
            "required_count": len(required),
            "required_symbols": required,
        },
        "objects": {
            "response_path": args.objects_response.as_posix(),
            "response_sha256": response_hash,
            "count": len(objects),
        },
        "exports": {
            "path": args.exports.as_posix(),
            "sha256": sha256(export_bytes),
            "count": len(exports),
            "symbols": exports,
        },
    }
    durable_write(args.audit, json.dumps(audit, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def expected_exports(path: Path) -> tuple[list[str], str]:
    data = read_bytes(path, "export manifest")
    try:
        symbols = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        refuse(
            "ASTRO_LIBCBM_EXPORT_LIST_INVALID",
            f"export manifest is not UTF-8: {error}",
            "regenerate the manifest from the exact input-object symbol table",
        )
    if not symbols or any(not SYMBOL.fullmatch(symbol) for symbol in symbols):
        refuse(
            "ASTRO_LIBCBM_EXPORT_LIST_INVALID",
            "export manifest is empty or contains a non-cbm symbol",
            "regenerate the manifest from the exact input-object symbol table",
        )
    if symbols != sorted(set(symbols)):
        refuse(
            "ASTRO_LIBCBM_EXPORT_LIST_NONDETERMINISTIC",
            "export manifest is not strictly sorted and unique",
            "regenerate the deterministic manifest; do not reorder it by hand",
        )
    return symbols, sha256(data)


def localize(args: argparse.Namespace) -> None:
    expected, exports_hash = expected_exports(args.exports)
    expected_set = set(expected)
    pre_sha256 = file_sha256(args.reloc)
    localized_symbols: list[str] = []
    try:
        with args.reloc.open("r+b", buffering=0) as object_file:
            with mmap.mmap(object_file.fileno(), 0, access=mmap.ACCESS_WRITE) as data:
                layout = coff_layout(data)
                symbols = coff_primary_symbols(data, layout)
                structural_details = coff_refptr_structurals(data, layout, symbols)
                structural_symbols = {
                    str(structural["symbol"]) for structural in structural_details
                }
                required_counts = {symbol: 0 for symbol in expected}
                mutations: list[tuple[int, str]] = []
                external_defined_before = 0
                undefined_external_count = 0
                for symbol in symbols:
                    if symbol["storage_class"] != COFF_CLASS_EXTERNAL:
                        continue
                    name = str(symbol["name"])
                    section_number = int(symbol["section_number"])
                    value = int(symbol["value"])
                    if section_number == 0:
                        if value != 0:
                            refuse(
                                "ASTRO_LIBCBM_COFF_COMMON_SURVIVED",
                                f"external common symbol {name} retained size/value {value}",
                                "keep ld -d in the complete partial link so aligned commons are allocated before localization",
                            )
                        undefined_external_count += 1
                        continue
                    external_defined_before += 1
                    if name in expected_set:
                        required_counts[name] += 1
                    elif name in structural_symbols:
                        continue
                    else:
                        mutations.append((int(symbol["offset"]) + 16, name))
                missing = sorted(name for name, count in required_counts.items() if count == 0)
                duplicate = sorted(name for name, count in required_counts.items() if count != 1)
                if missing:
                    refuse(
                        "ASTRO_LIBCBM_COFF_REQUIRED_MISSING",
                        f"combined COFF object is missing required export {missing[0]}",
                        "inspect the exact partial-link inputs before mutating symbol storage classes",
                    )
                if duplicate:
                    refuse(
                        "ASTRO_LIBCBM_COFF_REQUIRED_DUPLICATE",
                        f"combined COFF export {duplicate[0]} has {required_counts[duplicate[0]]} definitions",
                        "remove duplicate API definitions before localization",
                    )
                for storage_class_offset, name in mutations:
                    if data[storage_class_offset] != COFF_CLASS_EXTERNAL:
                        refuse(
                            "ASTRO_LIBCBM_COFF_MUTATION_PRECONDITION_FAILED",
                            f"symbol {name} storage class changed before mutation",
                            "preserve exclusive ownership of the generated object during localization",
                        )
                    data[storage_class_offset] = COFF_CLASS_STATIC
                    localized_symbols.append(name)
                data.flush()
                os.fsync(object_file.fileno())
                post_symbols = coff_primary_symbols(data, layout)
                post_structural_details = coff_refptr_structurals(
                    data, layout, post_symbols
                )
                if post_structural_details != structural_details:
                    refuse(
                        "ASTRO_LIBCBM_COFF_REFPTR_POST_LOCALIZATION_MISMATCH",
                        "validated refptr structural records changed during storage-class localization",
                        "discard the generated object and inspect the exact symbol-table mutation",
                    )
                post_external_defined = sorted(
                    str(symbol["name"])
                    for symbol in post_symbols
                    if symbol["storage_class"] == COFF_CLASS_EXTERNAL
                    and symbol["section_number"] != 0
                )
                expected_external_defined = sorted(expected + sorted(structural_symbols))
                if post_external_defined != expected_external_defined:
                    refuse(
                        "ASTRO_LIBCBM_COFF_POST_LOCALIZATION_MISMATCH",
                        f"post-localization externals differ: expected={len(expected_external_defined)}, "
                        f"observed={len(post_external_defined)}",
                        "discard the generated object and inspect the exact symbol-table mutation",
                    )
    except (OSError, ValueError) as error:
        refuse(
            "ASTRO_LIBCBM_COFF_MUTATION_FAILED",
            f"cannot localize generated object {args.reloc}: {error}",
            "inspect the launcher-owned build volume and rerun only after exact writes are possible",
        )
    post_sha256 = file_sha256(args.reloc)
    if mutations and post_sha256 == pre_sha256:
        refuse(
            "ASTRO_LIBCBM_COFF_MUTATION_NOT_OBSERVED",
            "symbol storage classes were scheduled but the object hash did not change",
            "inspect write durability and never archive an unproven localized object",
        )
    localized_symbols.sort()
    audit = {
        "format": "astrolabe.libcbm-coff-localization.v1",
        "reloc": {
            "path": args.reloc.as_posix(),
            "bytes": args.reloc.stat().st_size,
            "pre_sha256": pre_sha256,
            "post_sha256": post_sha256,
        },
        "coff": layout,
        "exports": {
            "path": args.exports.as_posix(),
            "sha256": exports_hash,
            "retained_count": len(expected),
            "retained_symbols": expected,
        },
        "structural_externals": {
            "count": len(structural_details),
            "symbols": sorted(structural_symbols),
            "details": structural_details,
            "physical_match": True,
        },
        "localization": {
            "external_defined_before": external_defined_before,
            "localized_count": len(localized_symbols),
            "localized_symbols": localized_symbols,
            "undefined_external_count": undefined_external_count,
            "post_external_defined_match": True,
        },
    }
    durable_write(args.audit, json.dumps(audit, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def verify(args: argparse.Namespace) -> None:
    expected, exports_hash = expected_exports(args.exports)
    try:
        with args.reloc.open("rb", buffering=0) as object_file:
            with mmap.mmap(object_file.fileno(), 0, access=mmap.ACCESS_READ) as data:
                layout = coff_layout(data)
                symbols = coff_primary_symbols(data, layout)
                structural_details = coff_refptr_structurals(data, layout, symbols)
    except (OSError, ValueError) as error:
        refuse(
            "ASTRO_LIBCBM_COFF_READ_FAILED",
            f"cannot inspect generated object {args.reloc}: {error}",
            "restore the exact combined object and rerun the native build",
        )
    structural_symbols = sorted(
        str(structural["symbol"]) for structural in structural_details
    )
    expected_globals = sorted(expected + structural_symbols)
    sections = run_tool([args.objdump, "-h", str(args.reloc)], "relocatable section scan")
    section_names = {
        fields[1]
        for line in sections.splitlines()
        if len(fields := line.split()) >= 2 and fields[0].isdigit()
    }
    if ".drectve" in section_names:
        objects, _response_hash = object_arguments(args.objects_response)
        directive_origins: list[str] = []
        for object_path in objects:
            object_sections = run_tool(
                [args.objdump, "-h", object_path],
                f"input section scan for {object_path}",
            )
            if any(
                len(fields := line.split()) >= 2
                and fields[0].isdigit()
                and fields[1] == ".drectve"
                for line in object_sections.splitlines()
            ):
                directive_origins.append(object_path)
        refuse(
            "ASTRO_LIBCBM_EXPORT_DIRECTIVE_PRESENT",
            f"relocatable object {args.reloc} still contains .drectve; "
            f"input origins={directive_origins[:8]} (total={len(directive_origins)})",
            "distinguish aligned-common directives from exports; allocate commons during the partial link or apply the exact producer's static-build contract",
        )
    records = nm_records(args.nm, [str(args.reloc)], "relocatable symbol scan")
    actual = sorted(name for name, _symbol_type, _origin in records)
    missing = sorted(set(expected_globals) - set(actual))
    unexpected = sorted(set(actual) - set(expected_globals))
    if actual != expected_globals:
        refuse(
            "ASTRO_LIBCBM_EXPORT_RELOC_MISMATCH",
            f"relocatable global mismatch: missing={missing[:3]}, unexpected={unexpected[:3]}, "
            f"expected_count={len(expected_globals)}, actual_count={len(actual)}",
            "inspect COFF localization and never archive a non-exact global projection",
        )
    audit = {
        "format": "astrolabe.libcbm-export-reloc.v6",
        "reloc": {
            "path": args.reloc.as_posix(),
            "bytes": args.reloc.stat().st_size,
            "sha256": file_sha256(args.reloc),
            "section_count": len(section_names),
            "drectve_present": False,
        },
        "exports": {
            "path": args.exports.as_posix(),
            "sha256": exports_hash,
            "count": len(expected),
            "api_defined_globals_match": True,
            "all_defined_globals_classified": True,
            "defined_global_count": len(actual),
            "defined_globals": actual,
        },
        "structural_externals": {
            "count": len(structural_details),
            "symbols": structural_symbols,
            "details": structural_details,
            "physical_match": True,
        },
    }
    durable_write(args.audit, json.dumps(audit, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    subparsers = root.add_subparsers(dest="operation", required=True)
    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("--nm", required=True)
    prepare_parser.add_argument("--objects-response", required=True, type=Path)
    prepare_parser.add_argument("--bindings", required=True, type=Path)
    prepare_parser.add_argument("--exports", required=True, type=Path)
    prepare_parser.add_argument("--audit", required=True, type=Path)
    localize_parser = subparsers.add_parser("localize")
    localize_parser.add_argument("--reloc", required=True, type=Path)
    localize_parser.add_argument("--exports", required=True, type=Path)
    localize_parser.add_argument("--audit", required=True, type=Path)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--nm", required=True)
    verify_parser.add_argument("--objdump", required=True)
    verify_parser.add_argument("--objects-response", required=True, type=Path)
    verify_parser.add_argument("--reloc", required=True, type=Path)
    verify_parser.add_argument("--exports", required=True, type=Path)
    verify_parser.add_argument("--audit", required=True, type=Path)
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        if args.operation == "prepare":
            prepare(args)
        elif args.operation == "localize":
            localize(args)
        else:
            verify(args)
    except ContractError as error:
        print(
            f"{error.code}: {error.message}; remediation: {error.remediation}",
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
