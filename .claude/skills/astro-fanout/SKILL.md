---
name: astro-fanout
description: Parallel issue-completion playbook for ASTROLABE — fan out worktree-isolated subagents one per pure-Rust crate, keep astrolabe-server and cross-crate work sequential, consolidate server-pending branches into one native gate run, octopus-merge disjoint branches, orchestrator owns all GitHub state. Use when parallelizing work across multiple ready issues or crates, orchestrating subagent waves, or merging a completed wave. Not for single-issue work (astro-issue).
---

# Parallel fanout playbook

Proven pattern (Wave-1: 17 issues closed, 6 agents, 0 errors; see #65 history). The orchestrator owns ALL GitHub mutations; workers never push, label, comment, or close.

## What parallelizes

- **Cleanly:** single-crate work in pure-Rust crates (`astrolabe-domain`, `-ingest`, `-lower`, `-panel`, `-weave`, `-kernel`, `-guard`, `-oracle`, `-assay`, `-anchors`, `-provenance`). Disjoint files → clean octopus merge. Workers self-verify with `cargo check/test -p <crate>` (any native Windows toolchain works for pure-Rust; the launcher is NOT needed and hard-refuses non-canonical roots anyway).
- **Never in parallel:** anything touching `crates/astrolabe-server` (needs the GNU/libcbm launcher build and collides in `src/migration.rs`, #85), cross-crate issues sharing a crate pairwise, and any two efforts needing the one native toolchain simultaneously.

## Worker contract (put verbatim in every worker prompt)

- Work in your assigned worktree on branch `sweep/<crate>`; touch ONLY your crate's files.
- Never push, never touch GitHub (no comments/labels/closes) — return structured results instead.
- Verify honestly per astro-fsv; report `partial`/`blocked` rather than fake green. If the issue is already fixed in your base commit, say so with evidence — do not redo it.
- FSV-only doctrine (owner directive 2026-07-13): no aggregate/gate suite exists — verify with real data (no mocks) and FSV byte readback per astro-fsv.
- Server-side edits you cannot build: stage them, commit with `Refs #N` (NEVER `Closes #N`), and flag `server_pending: true`.
- Record out-of-scope discoveries in `new_problems` (title + evidence); the orchestrator files them.
- Return: `{issue, status: done|partial|blocked|already-fixed, evidence[], commits[], server_pending, new_problems[]}`.

## Orchestrator sequence

1. Preflight — check `.tmp/astrolabe-launcher.lock` and live toolchain processes; never start a wave while another session's live-locked build owns the toolchain.
2. Partition ready issues by crate; one worker per crate works its issues sequentially.
3. On completion: octopus-merge the disjoint `sweep/*` branches; run ONE consolidated `cargo test` + clippy as independent FSV of the merge.
4. **Server-pending consolidation:** merge all server-pending branches into one local tree, run ONE native `cargo test -p astrolabe-server` through the launcher from `C:/code/Astrolabe`; on green, publish each branch, close the `Refs` issues manually with that shared evidence. Before any `git reset --hard`, save an insurance patch of applied stash/edits (`git diff <file> > <scratchpad>/x.patch`).
5. Close each issue with evidence (astro-issue §7); file every `new_problems` entry (astro-new-issue); post a wave summary with telemetry kind `fanout` (`wave`, `agents`, `results{}`).
6. Cleanup: prune worktrees and `sweep/*` branches, delete `target/`, verify absent.

## Sizing

Worker tasks should be small and exact (issue number + crate + base commit); a worker that needs repo-wide context is a sign the issue belongs in the sequential lane.
