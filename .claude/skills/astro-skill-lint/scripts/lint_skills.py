#!/usr/bin/env python3
"""Fail-closed linter for Claude Code project skills.

Usage: python lint_skills.py [skills_root]
  skills_root defaults to <repo>/.claude/skills (repo root derived from this
  file's location). Exit 0 only when every check passes; otherwise prints one
  'FAIL <path>: <message>' line per violation and exits 1. No silent skips:
  every directory examined is reported.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# Official Claude Code frontmatter fields (code.claude.com/docs/en/skills,
# 2026-07) plus open-standard fields. Unknown keys are typos until proven
# otherwise -> hard fail.
ALLOWED_KEYS = {
    "name", "description", "when_to_use", "argument-hint", "arguments",
    "disable-model-invocation", "user-invocable", "allowed-tools",
    "disallowed-tools", "model", "effort", "context", "agent", "hooks",
    "paths", "shell", "license", "compatibility", "metadata",
}
BOOL_KEYS = {"disable-model-invocation", "user-invocable"}
NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
MAX_DESC = 1024          # open-standard cap
MAX_COMBINED = 1536      # Claude Code listing truncation (description + when_to_use)
MAX_BODY_LINES = 500     # official guidance
LINK_RE = re.compile(r"\]\(([^)#\s]+)(?:#[^)\s]*)?\)")
SKILL_DIR_RE = re.compile(r"\$\{CLAUDE_SKILL_DIR\}/([^`'\")\s]+)")
PROJECT_DIR_RE = re.compile(r"\$\{CLAUDE_PROJECT_DIR\}/([^`'\")\s]+)")


def parse_frontmatter(text: str, path: Path, errors: list[str]):
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        errors.append(f"FAIL {path}: no frontmatter ('---' must be line 1)")
        return None, []
    try:
        end = next(i for i in range(1, len(lines)) if lines[i].strip() == "---")
    except StopIteration:
        errors.append(f"FAIL {path}: frontmatter never closed with '---'")
        return None, []
    fm: dict[str, str] = {}
    for i, raw in enumerate(lines[1:end], start=2):
        if not raw.strip() or raw.strip().startswith("#"):
            continue
        if "\t" in raw:
            errors.append(f"FAIL {path}:{i}: tab character in frontmatter (YAML forbids tabs)")
        if raw.startswith((" ", "-")):
            # Nested structures (hooks, YAML lists) are legal YAML; this simple
            # linter only validates top-level scalar keys and skips nested lines.
            continue
        if ":" not in raw:
            errors.append(f"FAIL {path}:{i}: frontmatter line is not 'key: value' -> {raw!r}")
            continue
        key, _, value = raw.partition(":")
        fm[key.strip()] = value.strip()
    return fm, lines[end + 1:]


def lint_skill(skill_dir: Path, repo_root: Path, errors: list[str]) -> str | None:
    """Returns the skill name on success (for collision checks)."""
    md = skill_dir / "SKILL.md"
    if not md.is_file():
        errors.append(f"FAIL {skill_dir}: missing SKILL.md")
        return None
    text = md.read_text(encoding="utf-8")
    fm, body = parse_frontmatter(text, md, errors)
    if fm is None:
        return None

    for key in fm:
        if key not in ALLOWED_KEYS:
            errors.append(f"FAIL {md}: unknown frontmatter key {key!r} (typo?)")
    for key in BOOL_KEYS & fm.keys():
        if fm[key] not in ("true", "false"):
            errors.append(f"FAIL {md}: {key} must be literal true/false, got {fm[key]!r}")

    name = fm.get("name", skill_dir.name)
    if not NAME_RE.fullmatch(name) or len(name) > 64:
        errors.append(f"FAIL {md}: invalid name {name!r} (lowercase/digits/hyphens, <=64)")
    if name != skill_dir.name:
        errors.append(f"FAIL {md}: name {name!r} != directory {skill_dir.name!r}")

    desc = fm.get("description", "")
    if not desc:
        errors.append(f"FAIL {md}: description missing or empty (auto-invocation silently dies)")
    elif len(desc) > MAX_DESC:
        errors.append(f"FAIL {md}: description {len(desc)} chars > {MAX_DESC}")
    combined = len(desc) + len(fm.get("when_to_use", ""))
    if combined > MAX_COMBINED:
        errors.append(f"FAIL {md}: description+when_to_use {combined} chars > {MAX_COMBINED} (listing truncates)")

    if len(body) > MAX_BODY_LINES:
        errors.append(f"FAIL {md}: body {len(body)} lines > {MAX_BODY_LINES} (move detail to references/)")

    body_text = "\n".join(body)
    for rel in LINK_RE.findall(body_text):
        if rel.startswith(("http://", "https://", "mailto:")):
            continue
        if not (skill_dir / rel).exists():
            errors.append(f"FAIL {md}: dangling link -> {rel}")
    for rel in SKILL_DIR_RE.findall(body_text):
        if not (skill_dir / rel).exists():
            errors.append(f"FAIL {md}: dangling ${{CLAUDE_SKILL_DIR}}/{rel}")
    for rel in PROJECT_DIR_RE.findall(body_text):
        if not (repo_root / rel).exists():
            errors.append(f"FAIL {md}: dangling ${{CLAUDE_PROJECT_DIR}}/{rel}")
    return name


def main() -> int:
    repo_root = Path(__file__).resolve().parents[4]
    skills_root = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else repo_root / ".claude" / "skills"
    if not skills_root.is_dir():
        print(f"FAIL {skills_root}: skills root does not exist")
        return 1

    errors: list[str] = []
    names: dict[str, Path] = {}
    dirs = sorted(p for p in skills_root.iterdir() if p.is_dir())
    if not dirs:
        print(f"FAIL {skills_root}: contains no skill directories")
        return 1
    for skill_dir in dirs:
        before = len(errors)
        name = lint_skill(skill_dir, repo_root, errors)
        if name:
            if name in names:
                errors.append(f"FAIL {skill_dir}: duplicate skill name {name!r} (also {names[name]})")
            names[name] = skill_dir
        if len(errors) == before:
            print(f"OK   {skill_dir.name}")

    # A same-named .claude/commands file is shadowed by the skill -> ambiguity, fail.
    commands = repo_root / ".claude" / "commands"
    if commands.is_dir() and skills_root == repo_root / ".claude" / "skills":
        for cmd in commands.glob("*.md"):
            if cmd.stem in names:
                errors.append(f"FAIL {cmd}: command shadowed by skill {cmd.stem!r} — delete one")

    for e in errors:
        print(e)
    print(f"SUMMARY: {len(dirs)} skills, {len(errors)} violation(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
