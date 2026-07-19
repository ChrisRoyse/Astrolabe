---
name: astro-handoff
description: Honest pause/stop/handoff for ASTROLABE sessions — verifies hygiene (target/ absent, no stray worktrees/branches/locks), records exactly what is done (verified vs unverified), what is not, the next concrete step, and any uncommitted local state on the active GitHub issue, then swaps status labels. Use before any pause, stop, or turn end with unfinished issue work, when context compaction is imminent, or when abandoning a claim. GitHub issues are the only handoff medium — never local SITREP/tmp files.
---

# Session handoff

A handoff exists so a zero-context successor can continue without re-deriving anything. It lives on the active issue — nowhere else.

## 1. Hygiene before writing

- Classify `.tmp/astrolabe-launcher.lock` through `scripts\launcher-lock-status.ps1`. Exact ownership is `(pid, owner_process_start_utc_ticks)`, never numeric PID alone. Only `absent` permits a new claim; `held` is read-only, and stale/PID-reused, unreadable, transition, or unevaluable state requires tracker-bound recovery.
- If `target/` exists and an exact retained handle/process identity proves this session owns it, delete it and verify absent. Otherwise leave it and record the classifier state/conflict.
- `git status --short` — know every uncommitted/untracked path. Remove stray temp files this session created; keep repo-controlled outputs out of the index.
- List stray worktrees/branches this session created (`git worktree list`, `git branch --list 'sweep/*'`) — remove finished ones or name them in the handoff.

## 2. The handoff comment (on the active issue)

State exactly, without optimism:
- **Done** — only items with verification evidence in this thread; anything unverified goes to Not done with a note.
- **Not done** — remaining scope, including partially-written code.
- **Next concrete step** — the single command/edit a successor runs first.
- **Uncommitted state** — paste `git status --short` (or "clean"); name any stash/branch/worktree holding work and any staged-but-ungated server edits.
- **Blockers/conflicts** — lock holders, red gates with issue links.

Embed the telemetry block (kind `handoff`, required keys `done[]`, `not_done[]`, `next`, `uncommitted`) per `${CLAUDE_PROJECT_DIR}/.claude/skills/astro-telemetry/references/spec.md`.

## 3. Labels

- Another agent can resume → swap `status:in-progress` → `status:ready`.
- Genuinely blocked → `status:blocked`, naming the blocker (issue link) in the comment.
- Never leave `status:in-progress` silently on a stopped effort.

## 4. Commit discipline

Committable verified work is committed and pushed (`Refs #N`) before the handoff. Unverified code is named in the handoff instead of being committed as if done — or committed to a clearly-named side branch, stated in the comment.
