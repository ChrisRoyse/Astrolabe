---
name: astro-fanout
description: Parallel issue-completion playbook for ASTROLABE — fan out worktree-isolated subagents one per pure-Rust crate, keep astrolabe-server and cross-crate work sequential, consolidate server-pending branches into one native gate run, octopus-merge disjoint branches, orchestrator owns all GitHub state. Use when parallelizing work across multiple ready issues or crates, orchestrating subagent waves, or merging a completed wave. Not for single-issue work (astro-issue).
---

# Parallel fanout playbook

Proven pattern (Wave-1: 17 issues closed, 6 agents, 0 errors; see #65 history). The orchestrator owns ALL GitHub mutations; workers never push, label, comment, or close.

## What parallelizes

- **Cleanly:** single-crate work in pure-Rust crates (`astrolabe-domain`, `-ingest`, `-lower`, `-panel`, `-weave`, `-kernel`, `-guard`, `-oracle`, `-assay`, `-anchors`, `-provenance`). Disjoint files → clean octopus merge. Workers self-verify with `cargo check -p <crate>` for buildability plus manual FSV of their changed behavior (real data, persisted readback — never tests; owner directive 2026-07-14).
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

1. Preflight — run the authoritative launcher-lock classifier, not a numeric-PID/raw-JSON inference. Only `absent` permits a new claim; `held` is read-only, and stale/PID-reused, unreadable, transition, or unevaluable state requires explicit tracker-bound recovery. Never start a wave while another exact live process identity owns the toolchain.
2. Partition ready issues by crate; one worker per crate works its issues sequentially.
3. On completion: octopus-merge the disjoint `sweep/*` branches; run ONE consolidated `cargo check --workspace` + clippy for buildability, then manual FSV of the merged behavior against a real corpus (no tests — owner directive 2026-07-14).
4. **Server-pending consolidation:** merge all server-pending branches into one local tree, run ONE native build through the launcher from `C:/code/Astrolabe`, then manually exercise the real binary's changed surfaces against a real corpus with persisted readback; on that evidence, publish each branch and close the `Refs` issues. Before any `git reset --hard`, save an insurance patch of applied stash/edits (`git diff <file> > <scratchpad>/x.patch`).
5. Close each issue with evidence (astro-issue §7); file every `new_problems` entry (astro-new-issue); post a wave summary with telemetry kind `fanout` (`wave`, `agents`, `results{}`).
6. Cleanup: prune worktrees and `sweep/*` branches. Let each exact live launcher owner remove its own `target/`, then independently verify absence; never manually delete a target protected by non-absent or unevaluable protocol state.

## Sizing

Worker tasks should be small and exact (issue number + crate + base commit); a worker that needs repo-wide context is a sign the issue belongs in the sequential lane.

## Batch everything (owner directive 2026-07-15)

Never run N passes where one combined pass serves all. Concretely:

- **One consolidated build serves every close-gate.** Workers PRESERVE their built binaries, fixtures, and driver scripts to the session scratchpad (`<scratchpad>/<lane>/`) so the orchestrator re-verifies by re-running preserved artifacts — a lane that cleans its binary forces a redundant rebuild.
- **One combined probe script.** The orchestrator's independent readbacks for ALL pending closes run as a single script in a single pass (all issues' probes together), never sequential per-issue rounds.
- **Batch GitHub mutations.** All claims in one shell invocation; all closes/evidence comments of a round in one invocation; label swaps bundled.
- **Inside a lane:** build once, then run the full measurement matrix + edge triad against that one binary; rebuild only when code changed.
- **Reuse proven drivers.** Before writing a new FSV driver, check the scratchpad and prior-issue comments for an existing one (measure.sh / drive.sh pattern).
