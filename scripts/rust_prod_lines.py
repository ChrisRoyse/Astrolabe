#!/usr/bin/env python3
"""Shared production-source view for Rust-scanning gate scripts (#118).

Replaces the old first-`#[cfg(test)]`-line truncation, which had two holes at
the redaction/shell-injection boundary:

- production code AFTER an inline `#[cfg(test)] mod tests { .. }` was invisible;
- out-of-line test module FILES (declared as `#[cfg(test)] mod x;` from a parent,
  e.g. `src/migration/tests.rs`) contain no `#[cfg(test)]` line of their own and
  were scanned as production code.

`strip_test_spans` blanks exactly the `#[cfg(test)]`-gated item spans (indices
preserved so enclosing-function attribution still works), using a
string/char/comment-aware scanner so braces and attribute markers inside
literals cannot confuse the span walk. `cfg_test_module_files` resolves
`#[cfg(test)] mod name;` declarations to the module files and directory
subtrees they gate. `code_view` exposes the comment/string-blanked text for
structural (non-comment-satisfiable) checks.
"""

from __future__ import annotations

import re
from pathlib import Path

_MOD_DECL_RE = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z0-9_]+)\s*;\s*$")


def code_view(text: str) -> str:
    """Return `text` with comments and string/char literal contents blanked.

    Newlines and code characters are preserved positionally, so line/column
    arithmetic on the view matches the original source.
    """
    out = []
    i = 0
    n = len(text)
    state = "normal"  # normal | line_comment | block_comment | string | raw_string
    block_nest = 0
    raw_hashes = 0

    def emit_blank(span: str) -> None:
        out.append("".join("\n" if ch == "\n" else " " for ch in span))

    while i < n:
        c = text[i]
        if state == "line_comment":
            if c == "\n":
                state = "normal"
                out.append("\n")
            else:
                out.append(" ")
            i += 1
            continue
        if state == "block_comment":
            if text.startswith("/*", i):
                block_nest += 1
                out.append("  ")
                i += 2
                continue
            if text.startswith("*/", i):
                block_nest -= 1
                if block_nest == 0:
                    state = "normal"
                out.append("  ")
                i += 2
                continue
            emit_blank(c)
            i += 1
            continue
        if state == "string":
            if c == "\\":
                emit_blank(text[i : i + 2])
                i += 2
                continue
            if c == '"':
                state = "normal"
            emit_blank(c)
            i += 1
            continue
        if state == "raw_string":
            if c == '"' and text[i + 1 : i + 1 + raw_hashes] == "#" * raw_hashes:
                state = "normal"
                emit_blank(text[i : i + 1 + raw_hashes])
                i += 1 + raw_hashes
                continue
            emit_blank(c)
            i += 1
            continue
        # normal state
        if text.startswith("//", i):
            state = "line_comment"
            out.append("  ")
            i += 2
            continue
        if text.startswith("/*", i):
            state = "block_comment"
            block_nest = 1
            out.append("  ")
            i += 2
            continue
        if c in ("r", "b"):
            match = re.match(r'b?r(#*)"', text[i:])
            if match:
                raw_hashes = len(match.group(1))
                state = "raw_string"
                emit_blank(text[i : i + match.end()])
                i += match.end()
                continue
            if text.startswith('b"', i):
                state = "string"
                out.append("b")
                emit_blank('"')
                i += 2
                continue
            out.append(c)
            i += 1
            continue
        if c == '"':
            state = "string"
            emit_blank(c)
            i += 1
            continue
        if c == "'":
            match = re.match(r"'(\\[^\n']*|[^'\\\n])'", text[i:])
            if match:
                emit_blank(text[i : i + match.end()])
                i += match.end()
            else:
                out.append(c)  # lifetime tick
                i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def line_depths(view_lines: list[str]) -> list[tuple[int, int, int, set[int]]]:
    """Per view line: (start_depth, end_depth, max_depth, semicolon_depths)."""
    infos = []
    depth = 0
    for line in view_lines:
        start = depth
        max_depth = depth
        semis: set[int] = set()
        for ch in line:
            if ch == "{":
                depth += 1
                max_depth = max(max_depth, depth)
            elif ch == "}":
                depth -= 1
            elif ch == ";":
                semis.add(depth)
        infos.append((start, depth, max_depth, semis))
    return infos


def strip_test_spans(lines: list[str]) -> list[str]:
    """Blank every `#[cfg(test)]`-gated item span; indices are preserved."""
    view_lines = code_view("\n".join(lines)).split("\n")
    infos = line_depths(view_lines)
    out = list(lines)
    i = 0
    n = len(lines)
    while i < n:
        if view_lines[i].strip() != "#[cfg(test)]":
            i += 1
            continue
        base_depth = infos[i][0]
        # Skip stacked attributes / blank lines between the cfg gate and its item.
        j = i + 1
        while j < n and (
            not view_lines[j].strip() or view_lines[j].lstrip().startswith("#[")
        ):
            j += 1
        # Walk the gated item to its end (semicolon at base depth, or braces
        # opened above base depth and closed back to it).
        end = j
        opened = False
        while end < n:
            _start, end_depth, max_depth, semis = infos[end]
            if max_depth > base_depth:
                opened = True
            if base_depth in semis and end_depth <= base_depth:
                break
            if opened and end_depth <= base_depth:
                break
            end += 1
        for k in range(i, min(end + 1, n)):
            out[k] = ""
        i = end + 1
    return out


def cfg_test_module_files(scan_root: Path) -> tuple[set[Path], set[Path]]:
    """Resolve `#[cfg(test)] mod name;` declarations under `scan_root`.

    Returns (test_files, test_dirs): module files that are entirely
    cfg(test)-gated, and directories whose whole subtree is.
    """
    test_files: set[Path] = set()
    test_dirs: set[Path] = set()
    for path in sorted(scan_root.glob("**/*.rs")):
        text = path.read_text(encoding="utf-8")
        if "#[cfg(test)]" not in text:
            continue
        view_lines = code_view(text).split("\n")
        for index, line in enumerate(view_lines):
            if line.strip() != "#[cfg(test)]":
                continue
            j = index + 1
            while j < len(view_lines) and (
                not view_lines[j].strip()
                or view_lines[j].lstrip().startswith("#[")
            ):
                j += 1
            if j >= len(view_lines):
                continue
            match = _MOD_DECL_RE.match(view_lines[j])
            if match is None:
                continue
            name = match.group(1)
            if path.name in ("lib.rs", "mod.rs", "main.rs"):
                base = path.parent
            else:
                base = path.parent / path.stem
            for candidate in (base / f"{name}.rs", base / name / "mod.rs"):
                if candidate.exists():
                    test_files.add(candidate.resolve())
            subtree = base / name
            if subtree.is_dir():
                test_dirs.add(subtree.resolve())
    return test_files, test_dirs


def is_test_only_file(path: Path, test_files: set[Path], test_dirs: set[Path]) -> bool:
    resolved = path.resolve()
    if resolved in test_files:
        return True
    return any(resolved.is_relative_to(directory) for directory in test_dirs)
