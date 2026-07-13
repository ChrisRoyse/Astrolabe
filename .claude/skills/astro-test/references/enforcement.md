# Deterministic trigger enforcement (#288)

Skill auto-invocation is advisory: the model matches the request against skill
descriptions (and the `paths:` globs) and *decides* to load the skill. The
doctrine must not depend on that judgment, so a PostToolUse hook injects the
hard rules deterministically whenever a tool call touches test surface.

## Pieces

1. **`paths:` frontmatter** on `SKILL.md` — native Claude Code file-trigger:
   the skill auto-activates when the agent works with files matching the globs.
2. **`${CLAUDE_SKILL_DIR}/scripts/test_doctrine_context.py`** — PostToolUse
   hook, bundled with this skill (`.claude/*` is gitignored except
   `.claude/skills/`, so the skill tree is the tracked home). Matches Edit/Write/MultiEdit/NotebookEdit by file path **and by edited
   content** (`#[test]`, `#[cfg(test)]`, `mod tests` — inline Rust test modules
   live in `src/*.rs`, where path matching is blind), and Bash commands that
   run tests or gates. Emits `additionalContext` naming the astro-test skill
   and the hard rules. Full doctrine block on first hit per session, one-liner
   after (throttle marker in the OS temp dir keyed by `session_id`). Fail-loud:
   malformed input or internal error prints `ERROR[ASTRO_TEST_HOOK]: ...` to
   stderr and exits 1 (visible, non-blocking) — never a silent swallow.
3. **Hook wiring** — `.claude/settings.json` is **local-only (untracked)** in
   this repository, so the wiring lives there per machine:

```json
"hooks": {
  "PostToolUse": [
    {
      "matcher": "Edit|Write|MultiEdit|NotebookEdit|Bash",
      "hooks": [
        {
          "type": "command",
          "command": "python \"$CLAUDE_PROJECT_DIR/.claude/skills/astro-test/scripts/test_doctrine_context.py\""
        }
      ]
    }
  ]
}
```

## Subagent caveat

Subagents start with fresh context and do **not** inherit the parent's invoked
skills. Hooks fire for subagent tool calls too (same session), which is why the
hook — not the skill listing — is the enforcement layer. Orchestrators
delegating test-touching work (astro-fanout) must still restate the doctrine in
the delegation prompt: Explore/Plan-type agents skip CLAUDE.md entirely.

## Verifying the hook (FSV)

Feed it synthetic PostToolUse JSON on stdin and read back the marker:

```bash
printf '{"tool_name":"Bash","tool_input":{"command":"cargo nextest run"},"session_id":"probe"}' \
  | python .claude/skills/astro-test/scripts/test_doctrine_context.py
# expect: additionalContext JSON, exit 0; marker astro-test-hook-probe in $TMP
```

Edge triad: empty stdin → `ERROR[ASTRO_TEST_HOOK]` + exit 1; malformed JSON →
same; non-test tool input → silent exit 0. Evidence run recorded on #288.
