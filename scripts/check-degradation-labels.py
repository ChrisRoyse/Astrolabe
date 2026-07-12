#!/usr/bin/env python3
"""Fail closed when a gate mislabels a degradation.

Standing invariant 3 is "no silent fallback -- every degradation labeled, every
skip counted". Two ways a gate can violate it by LYING about who owns missing
coverage, and this gate rejects both.

RULE 1 -- no CI-ownership claims.
    Hosted CI/CD is banned (owner directive, 2026-07-11): there is no
    `.github/`, no workflow, no required status check, and no CI job. A skip
    that names a CI job as its coverage owner is a FALSE claim about a system
    that does not exist.

RULE 2 -- platform-limited skips must carry the port-phase deferral.
    Astrolabe is Windows-only scope until the whole system is operational on
    native Windows (owner directive, 2026-07-11); the port to other platforms
    is a scheduled phase at the end. So a skip whose reason is "this needs a
    non-Windows host" is neither CI-owned nor a permanent gap nor a runbook
    someone should go execute now -- it is DEFERRED, and it must say so:

        SKIP[ASTRO_EGRESS_LINUX_REQUIRED]: <what is absent, and why>
        DEFERRED[ASTRO_PORT_PHASE]: <coverage> is deferred to the port phase
        (Windows-only scope); tracked in #238. Not passing evidence.

    A file that emits a `SKIP[ASTRO_*_LINUX_REQUIRED]` marker must also emit
    `DEFERRED[ASTRO_PORT_PHASE]` and reference the tracking issue. That keeps
    the deferral labeled and counted -- never silently ticked from a
    Windows-green aggregate, and never mistaken for abandonment.

Scanned: scripts/ and ci/ (vendor/ is pinned upstream and out of scope).
See docs/port-phase-deferrals.md for the deferral register.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


DEFAULT_ROOT = Path(__file__).resolve().parents[1]

SCAN_DIRS = ("scripts", "ci")

SCAN_SUFFIXES = {".sh", ".py", ".ps1", ".md", ".json", ".toml", ".yml", ".yaml"}

# The reusable classification token for coverage deliberately deferred to the
# port phase. Mechanical, greppable, and applied identically across the tracker.
PORT_PHASE_TOKEN = "DEFERRED[ASTRO_PORT_PHASE]"

# The issue that owns the port-phase deferral register.
DEFERRAL_ISSUE = "#238"

# Documents whose SUBJECT is these rules. They necessarily quote the banned
# phrasing in order to prohibit it, so scanning them for it is circular.
SUBJECT_MATTER_EXEMPT = {
    "scripts/check-degradation-labels.py": "defines the banned patterns",
    "scripts/test-degradation-labels.py": "drives the gate with violating fixtures",
    "ci/README.md": "states the CI ban and the rename-or-document decision",
}

# RULE 2 applies to a file that EMITS a platform-limited skip at runtime -- an
# `echo "SKIP[...]"` or `print("SKIP[...")`. Files that merely NAME the token as
# a contract string (check-gate-wiring.py asserting the marker exists,
# test-gate-wiring.py's fixtures) are validators, not emitters, and requiring
# them to also emit a deferral would be nonsense.
PLATFORM_SKIP_EMIT = re.compile(
    r"""(?:echo|print)\s*\(?\s*["']?\s*SKIP\[(ASTRO_[A-Z0-9_]*_LINUX_REQUIRED)\]""",
    re.MULTILINE,
)

# Two families:
#   "claim"   -- asserts a (nonexistent) CI job owns/provides coverage.
#   "mention" -- references banned GitHub Actions machinery at all.
# They are negated differently: a claim is excused by an explicit denial on the
# same line; a mention is excused by a line that STATES THE BAN (prose in the
# policy docs must be able to say "GitHub Actions is banned").
BANNED = (
    (
        re.compile(r"\bowned by\b[^.\n]*\bCI\b", re.IGNORECASE),
        "claims a CI job/system owns coverage",
        "claim",
    ),
    (
        re.compile(r"\bCI\b[^.\n]*\bowns?\b", re.IGNORECASE),
        "claims CI owns a gate",
        "claim",
    ),
    (
        re.compile(r"\brequired\s+(?:\w+\s+)?CI\s+jobs?\b", re.IGNORECASE),
        "cites a required CI job (none exist)",
        "claim",
    ),
    # The historical INFO marker said "the required Linux CI unix64 ABI" -- a CI
    # ownership claim with no "job" in it. Catch "required <...> CI" generally.
    (
        re.compile(r"\brequired\s+(?:\w+\s+){0,2}CI\b", re.IGNORECASE),
        "cites a required CI system as the reference/owner (none exists)",
        "claim",
    ),
    (
        re.compile(r"\bis required from CI\b", re.IGNORECASE),
        "defers coverage to CI",
        "claim",
    ),
    (
        re.compile(r"\bportable-gates\b"),
        "names the deleted `portable-gates` CI job",
        "claim",
    ),
    (
        re.compile(r"\buntil CI runs\b|\bwait for CI\b", re.IGNORECASE),
        "defers evidence until CI runs",
        "claim",
    ),
    (
        re.compile(r"\bGITHUB_STEP_SUMMARY\b|\bGITHUB_ACTIONS\b"),
        "GitHub Actions integration (banned)",
        "mention",
    ),
    (
        re.compile(r"github\.?\s*actions", re.IGNORECASE),
        "references GitHub Actions (banned)",
        "mention",
    ),
    (
        re.compile(r"\.github/"),
        "references GitHub Actions configuration (banned)",
        "mention",
    ),
    (
        re.compile(r"\brequired status check", re.IGNORECASE),
        "references a required status check (none exist)",
        "mention",
    ),
)

# An explicit denial on the same line is not a claim -- it is the honest label
# this gate exists to require.
CLAIM_NEGATIONS = (
    re.compile(r"\bno\s+CI\s+jobs?\s+owns?\b", re.IGNORECASE),
    re.compile(r"\bnever\s+(?:a\s+)?CI[- ]owned\b", re.IGNORECASE),
    re.compile(r"\bnever\s+a\s+CI\s+job\b", re.IGNORECASE),
    re.compile(r"\bno\s+gate\s+may\s+claim\s+a\s+CI\s+job\b", re.IGNORECASE),
    re.compile(r"\bnot\s+owned\s+by\s+CI\b", re.IGNORECASE),
    re.compile(r"\bmust\s+NOT\s+(?:claim|name)\b", re.IGNORECASE),
)

# A line that states the prohibition is prose ABOUT the ban, not a use of it.
MENTION_NEGATIONS = (
    re.compile(r"\bbanned\b", re.IGNORECASE),
    re.compile(r"\bis\s+deleted\b|\bare\s+deleted\b", re.IGNORECASE),
    re.compile(r"\bno\s+longer\s+exists?\b", re.IGNORECASE),
)

REMEDIATION_CI = (
    "hosted CI is banned and no CI job exists. Non-Windows coverage is DEFERRED "
    f"to the port phase: emit `{PORT_PHASE_TOKEN}` and reference {DEFERRAL_ISSUE}. "
    "See docs/port-phase-deferrals.md."
)

REMEDIATION_DEFERRAL = (
    f"a platform-limited skip must also emit `{PORT_PHASE_TOKEN}` naming "
    f"{DEFERRAL_ISSUE}, so the deferral is labeled and counted rather than "
    "silently absorbed into a Windows-green aggregate. "
    "See docs/port-phase-deferrals.md."
)


def scan_files(root: Path) -> list[Path]:
    found: list[Path] = []
    for directory in SCAN_DIRS:
        base = root / directory
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if path.is_file() and path.suffix.lower() in SCAN_SUFFIXES:
                found.append(path)
    return found


def violations(root: Path) -> list[str]:
    errors: list[str] = []
    for path in scan_files(root):
        relative = path.relative_to(root).as_posix()
        if relative in SUBJECT_MATTER_EXEMPT:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            errors.append(f"{relative}: cannot read: {exc}")
            continue

        # RULE 1: no CI-ownership claims, no GitHub Actions machinery.
        for number, line in enumerate(text.splitlines(), start=1):
            claim_negated = any(n.search(line) for n in CLAIM_NEGATIONS)
            mention_negated = any(n.search(line) for n in MENTION_NEGATIONS)
            for pattern, reason, family in BANNED:
                if family == "claim" and claim_negated:
                    continue
                if family == "mention" and mention_negated:
                    continue
                if pattern.search(line):
                    errors.append(
                        f"{relative}:{number}: {reason}\n"
                        f"      {line.strip()}\n"
                        f"      remediation: {REMEDIATION_CI}"
                    )
                    break

        # RULE 2: a platform-limited skip must carry the port-phase deferral.
        skips = sorted(set(PLATFORM_SKIP_EMIT.findall(text)))
        if skips and PORT_PHASE_TOKEN not in text:
            errors.append(
                f"{relative}: emits {', '.join(skips)} but never emits "
                f"{PORT_PHASE_TOKEN}\n"
                f"      remediation: {REMEDIATION_DEFERRAL}"
            )
        elif skips and DEFERRAL_ISSUE not in text:
            errors.append(
                f"{relative}: emits {PORT_PHASE_TOKEN} without naming the "
                f"tracking issue {DEFERRAL_ISSUE}\n"
                f"      remediation: {REMEDIATION_DEFERRAL}"
            )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    args = parser.parse_args()

    errors = violations(args.root.resolve())
    if errors:
        print(
            "ERROR: ASTRO_DEGRADATION_LABEL: a gate mislabels missing coverage "
            "(claims a nonexistent CI owner, or defers to the port phase without "
            "saying so).",
            file=sys.stderr,
        )
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 1
    print(
        "degradation labels verified: no CI-ownership claims; "
        f"every platform-limited skip carries {PORT_PHASE_TOKEN} ({DEFERRAL_ISSUE})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
