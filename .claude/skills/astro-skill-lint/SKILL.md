---
name: astro-skill-lint
description: Validates ASTROLABE project skills fail-closed — frontmatter parses, name matches directory, description within budget (≤1024 chars, ≤1536 combined with when_to_use), body ≤500 lines, referenced files exist, no unknown frontmatter keys, no command/skill name collisions. Use after creating or editing anything under .claude/skills or .claude/commands, and before committing skill changes.
allowed-tools: Bash(python *)
---

# Skill linter

Run from the repo root:

```
python ${CLAUDE_PROJECT_DIR}/.claude/skills/astro-skill-lint/scripts/lint_skills.py
```

- Exit 0 = every skill valid (per-skill `OK` lines + summary).
- Exit 1 = violations, one `FAIL <path>: <message>` line each. Fix and re-run until green; only proceed (commit, close) when the lint passes.
- An alternate skills root can be passed as the first argument (used for fixture testing the linter itself).

## Standing rules

- Every edit under `.claude/skills/` or `.claude/commands/` ends with a green lint run; paste the summary line in the commit-referenced issue comment.
- Malformed YAML fails soft at runtime (Claude Code loads the body with empty metadata and auto-invocation silently dies) — this linter is the only loud guard; treat its failure as a broken build.
- Keep bodies lean: content loaded once persists in context all session. Detail belongs in `references/` (one level deep), deterministic logic in `scripts/` with verbose fail-closed errors.
- New shared conventions (telemetry kinds, gate codes) update the owning reference file in the same commit.
