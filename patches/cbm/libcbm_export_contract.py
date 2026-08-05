#!/usr/bin/env python3
"""Build and verify the static libcbm symbol-localization contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile


SYMBOL = re.compile(r"^_?cbm_[A-Za-z0-9_]+$")
BINDING = re.compile(r"(?m)^\s*pub fn (cbm_[A-Za-z0-9_]+)\s*\(")


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
    try:
        return completed.stdout.decode("utf-8")
    except UnicodeDecodeError as error:
        refuse(
            "ASTRO_LIBCBM_EXPORT_TOOL_OUTPUT_INVALID",
            f"{purpose} emitted non-UTF-8 output: {error}",
            "use the pinned GNU analysis tool whose symbol output is UTF-8",
        )


def parse_nm(output: str, purpose: str) -> list[tuple[str, str]]:
    records: list[tuple[str, str]] = []
    malformed: list[str] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        fields = line.split()
        if len(fields) >= 3 and fields[0].endswith(":") and len(fields[2]) == 1:
            origin = fields[0][:-1]
            name = fields[1]
        elif len(fields) >= 2 and len(fields[1]) == 1:
            origin = "<single-input>"
            name = fields[0]
        else:
            malformed.append(line)
            continue
        records.append((name, origin))
    if malformed:
        refuse(
            "ASTRO_LIBCBM_EXPORT_NM_FORMAT_INVALID",
            f"cannot parse {purpose} nm output; first line: {malformed[0]!r}",
            "use pinned GNU nm with POSIX format; do not guess at the symbol table",
        )
    return records


def nm_records(nm: str, inputs: list[str], purpose: str) -> list[tuple[str, str]]:
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


def export_inventory(records: list[tuple[str, str]]) -> tuple[list[str], dict[str, list[str]]]:
    definitions: dict[str, list[tuple[str, str]]] = {}
    for actual, origin in records:
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


def verify(args: argparse.Namespace) -> None:
    expected, exports_hash = expected_exports(args.exports)
    sections = run_tool([args.objdump, "-h", str(args.reloc)], "relocatable section scan")
    section_names = {
        fields[1]
        for line in sections.splitlines()
        if len(fields := line.split()) >= 2 and fields[0].isdigit()
    }
    if ".drectve" in section_names:
        refuse(
            "ASTRO_LIBCBM_EXPORT_DIRECTIVE_PRESENT",
            f"relocatable object {args.reloc} still contains .drectve",
            "identify the translation unit emitting dllexport and apply its static-build contract at compilation",
        )
    records = nm_records(args.nm, [str(args.reloc)], "relocatable symbol scan")
    actual = sorted(name for name, _origin in records)
    if actual != expected:
        missing = sorted(set(expected) - set(actual))
        unexpected = sorted(set(actual) - set(expected))
        refuse(
            "ASTRO_LIBCBM_EXPORT_RELOC_MISMATCH",
            f"relocatable globals differ from the manifest; missing={missing[:3]}, unexpected={unexpected[:3]}",
            "inspect ld retention and input relocations; never archive an unlocalized object",
        )
    reloc_data = read_bytes(args.reloc, "localized relocatable object")
    audit = {
        "format": "astrolabe.libcbm-export-reloc.v1",
        "reloc": {
            "path": args.reloc.as_posix(),
            "bytes": len(reloc_data),
            "sha256": sha256(reloc_data),
            "section_count": len(section_names),
            "drectve_present": False,
        },
        "exports": {
            "path": args.exports.as_posix(),
            "sha256": exports_hash,
            "count": len(expected),
            "defined_globals_match": True,
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
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--nm", required=True)
    verify_parser.add_argument("--objdump", required=True)
    verify_parser.add_argument("--reloc", required=True, type=Path)
    verify_parser.add_argument("--exports", required=True, type=Path)
    verify_parser.add_argument("--audit", required=True, type=Path)
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        if args.operation == "prepare":
            prepare(args)
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
