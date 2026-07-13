#!/usr/bin/env python3
"""PostToolUse hook: inject the ASTROLABE test doctrine whenever a tool call
touches test surface (#288).

Fires on Edit/Write/MultiEdit/NotebookEdit whose file path OR edited content
is test surface, and on Bash commands that run tests or gates. Emits
`hookSpecificOutput.additionalContext` telling the agent the astro-test skill
doctrine binds — the deterministic backstop for skill auto-triggering (the
skill's own `paths:`/description matching is advisory; this hook is not).

Contract (fail-loud, never fail-open silently):
  * Non-test tool call        -> exit 0, no output.
  * Test surface touched      -> exit 0, additionalContext JSON on stdout.
    First hit in a session prints the full doctrine block; later hits print a
    one-line reminder (throttle marker keyed by session_id in the OS temp dir;
    a marker write failure falls back to the FULL message — more information,
    never less — and logs the failure to stderr).
  * Malformed/absent stdin, unexpected internal error -> diagnostic on stderr
    naming exactly what failed + exit 1 (PostToolUse exit 1 is non-blocking
    but visible). No silent swallow, no bare `except: pass`.
"""

from __future__ import annotations

import json
import re
import sys
import tempfile
from pathlib import Path

EDIT_TOOLS = {"Edit", "Write", "MultiEdit", "NotebookEdit"}

# Path-shaped test surface (forward-slash normalized, case-insensitive).
PATH_PATTERNS = [
    r"(^|/)tests?/",                                   # any tests/ or test/ segment
    r"_test\.rs$",
    r"(^|/)test_[^/]*\.(rs|py)$",
    r"(^|/)tests\.rs$",
    r"\.config/nextest\.toml$",
    r"(^|/)ci/(hazard-suite\.json|cbm-test-totals\.md|known-skips\.md)$",
    r"(^|/)scripts/(test-[^/]+\.py|check-[^/]+\.(py|sh)|ci-[^/]+\.sh)$",
]
PATH_RE = re.compile("|".join(PATH_PATTERNS), re.IGNORECASE)

# Content-shaped test surface: Rust inline test modules live in src/*.rs
# (astrolabe-weave's tests are in src/lib.rs), so path matching alone misses
# them. Applied ONLY to code files (.rs/.py/.toml) — prose mentioning these
# words (docs, issue bodies, skill text) is not test surface (#288 FSV run
# caught the over-trigger on a .md edit).
CONTENT_RE = re.compile(
    r"#\[(tokio::)?test\]|#\[cfg\(test\)\]|\bmod tests\b|\btrybuild\b|\bnextest\b"
)
CONTENT_SCAN_SUFFIXES = (".rs", ".py", ".toml")

# Bash commands that run tests or test gates.
COMMAND_RE = re.compile(
    r"\bcargo\s+(nextest|test)\b"
    r"|\b(check|check-full|check-release)\.sh\b"
    r"|\bci-(cbm-test|rust-gate|cbm-lint)\.sh\b"
    r"|\bcheck-suite-impact\.py\b"
    r"|\bscripts/test-[^\s'\"]+\.py\b"
    r"|\binvoke-native-aggregate\.ps1\b"
    r"|\bpytest\b",
    re.IGNORECASE,
)

FULL_MSG = (
    "TEST SURFACE TOUCHED ({what}). The ASTROLABE test doctrine binds — invoke "
    "the astro-test skill NOW if it is not already loaded in this session. "
    "Hard rules (owner directive 2026-07-12, #280): the full suite (check.sh "
    "aggregate + CBM C suite) must finish <180s wall clock; NO single test may "
    "exceed 60s — decompose or delete it (never merely tier, never raise a "
    "timeout, never unlabeled #[ignore]); a suite runs only when code changes "
    "impact its declared input set (scripts/check-suite-impact.py, fail-closed: "
    "unknown => run); tests use REAL data and real stores — no mocks, no "
    "API-echo assertions — and prove outcomes by independent readback of "
    "persisted bytes (astro-fsv); every skip is named and counted; speed never "
    "comes from skipping coverage a change needs."
)
SHORT_MSG = (
    "Test surface touched ({what}) — astro-test doctrine applies (suite <180s, "
    "no test >60s, impact-gated suites, real data + FSV readback)."
)


def _norm(path: str) -> str:
    return path.replace("\\", "/")


def classify(tool_name: str, tool_input: dict) -> str | None:
    """Returns a short human label for WHAT matched, or None for no match."""
    if tool_name == "Bash":
        command = tool_input.get("command", "")
        m = COMMAND_RE.search(command)
        return f"command: {m.group(0)}" if m else None
    if tool_name in EDIT_TOOLS:
        file_path = _norm(str(tool_input.get("file_path", "") or tool_input.get("notebook_path", "")))
        if file_path and PATH_RE.search(file_path):
            return f"path: {file_path}"
        if file_path and not file_path.lower().endswith(CONTENT_SCAN_SUFFIXES):
            return None
        content = " ".join(
            str(tool_input.get(key, ""))
            for key in ("content", "new_string", "old_string", "new_source")
        )
        m = CONTENT_RE.search(content)
        if m:
            return f"content marker {m.group(0)!r} in {file_path or '<unknown path>'}"
    return None


def first_hit_this_session(session_id: str) -> bool:
    """True exactly once per session; falls back to True (full message) if the
    throttle marker cannot be written — fail toward more doctrine, and say why."""
    if not session_id:
        print("WARN[ASTRO_TEST_HOOK]: no session_id in hook input; cannot throttle", file=sys.stderr)
        return True
    marker = Path(tempfile.gettempdir()) / f"astro-test-hook-{session_id}"
    if marker.exists():
        return False
    try:
        marker.write_text("seen", encoding="utf-8")
    except OSError as exc:
        print(f"WARN[ASTRO_TEST_HOOK]: throttle marker write failed ({exc}); emitting full message", file=sys.stderr)
    return True


def main() -> int:
    raw = sys.stdin.read()
    if not raw.strip():
        print(
            "ERROR[ASTRO_TEST_HOOK]: empty stdin — expected PostToolUse JSON "
            "(tool_name, tool_input, session_id). Check the hook wiring in "
            ".claude/settings.json.",
            file=sys.stderr,
        )
        return 1
    try:
        payload = json.loads(raw)
    except ValueError as exc:
        print(f"ERROR[ASTRO_TEST_HOOK]: stdin is not valid JSON ({exc}); first 200 bytes: {raw[:200]!r}", file=sys.stderr)
        return 1
    if not isinstance(payload, dict):
        print(f"ERROR[ASTRO_TEST_HOOK]: hook input is {type(payload).__name__}, expected object", file=sys.stderr)
        return 1

    tool_name = str(payload.get("tool_name", ""))
    tool_input = payload.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        print(f"ERROR[ASTRO_TEST_HOOK]: tool_input is {type(tool_input).__name__}, expected object", file=sys.stderr)
        return 1

    what = classify(tool_name, tool_input)
    if what is None:
        return 0

    template = FULL_MSG if first_hit_this_session(str(payload.get("session_id", ""))) else SHORT_MSG
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": template.format(what=what),
        }
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
