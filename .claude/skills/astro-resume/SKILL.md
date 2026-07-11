---
name: astro-resume
description: Resume protocol for ASTROLABE sessions — injects live git/lock/toolchain/issue state, then walks the mandatory re-reads (AGENTS.md, CLAUDE.md, active issue and all its comments) before any action. Use at the start of a fresh session on existing work, after context compaction, or when picking up another session's in-progress issue. Prevents redoing verified DoD items and acting on stale lock/toolchain assumptions.
---

# Resume protocol

## Live state (captured at invocation)

Branch and dirt:
!`git status --short --branch | head -25`

Recent commits:
!`git log --oneline -8`

Launcher lock:
!`cat .tmp/astrolabe-launcher.lock 2>/dev/null || echo "(absent)"`

target/:
!`ls -d target 2>/dev/null || echo "(absent)"`

In-progress issues:
!`gh issue list --label status:in-progress --json number,title --limit 20 --jq '.[] | "#\(.number) \(.title)"' 2>/dev/null || echo "(gh unavailable — fetch manually)"`

## Mandatory re-reads before acting

1. `AGENTS.md` and `CLAUDE.md` (the operating manual may have changed since your context was built — treat the on-disk version as authoritative over anything you remember).
2. The active issue **body and every comment** (`gh issue view N --comments`). Latest handoff/telemetry blocks are the resume point: `${CLAUDE_PROJECT_DIR}/.claude/skills/astro-telemetry/references/spec.md` §recipes.
3. Live Git/worktree state above — reconcile against the last handoff's `uncommitted` claim before touching anything.

## Rules

- Never redo a checked DoD item — verify it (run the named test/gate) and note the result.
- Sole-agent repo: a prior `status:in-progress` claim never prevents continuation, **unless** the claim comment is newer than 48h and evidently from another live session.
- Run the astro-gate preflight before any build; obey its verdict (a live lock or owned toolchain means read-only work).
- If the toolchain is occupied, pick non-colliding work: issue analysis, specs, docs, portable Python checks — never a competing build.
- Then continue via astro-issue.
