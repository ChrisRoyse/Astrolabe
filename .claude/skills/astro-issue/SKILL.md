---
name: astro-issue
description: Drives one ASTROLABE GitHub issue through the mandatory lifecycle — pick, claim, verify prior progress, scoped work, FSV proof, gates, evidence, close. Use when starting, resuming, or closing work on a GitHub issue, choosing the next issue, checking a DoD box, or swapping status labels. Not for filing new issues (use astro-new-issue), running gates alone (use astro-gate), or pausing mid-issue (use astro-handoff).
argument-hint: [issue-number | pick]
allowed-tools: Bash(gh issue *), Bash(gh api *), Bash(git status *), Bash(git log *), Bash(git diff *)
---

# Issue lifecycle driver

Issue to work: `$ARGUMENTS` (if `pick` or empty, apply step 1 to choose one).

GitHub issues are the single source of truth. If it isn't recorded on an issue, it didn't happen. Every state-changing comment below carries an `astro-telemetry/v1` block — see `${CLAUDE_PROJECT_DIR}/.claude/skills/astro-telemetry/references/spec.md`. Comment templates: [references/templates.md](references/templates.md).

## 1. Pick

- `gh issue list --label status:ready --json number,title,milestone,labels --limit 100`
- Choose from the **lowest-numbered open milestone** (spine order `P0 → P1 → P2 → (P3 ∥ P4) → P5 → P6 → (P7 ∥ P8) → P9`, EPIC #65).
- Never start `status:blocked` or `status:needs-spec`. If an issue has `status:in-progress` with a claim comment newer than 48h **from another live session**, pick a different one; this is otherwise a sole-agent repo — a stale prior claim never prevents continuation.
- Anything touching `crates/astrolabe-server` (especially `src/migration.rs`, under decomposition per #85) is sequential-only work; do not run it concurrently with another server-touching effort.

## 2. Claim

- Comment: what you are about to do + plan in ≤5 bullets + telemetry block (kind `claim`).
- Swap label: `gh issue edit N --remove-label status:ready --add-label status:in-progress`.

## 3. Verify the claim before working

- Read the issue body **and every comment** (`gh issue view N --comments`). Prior sessions record completed work there.
- Never redo a checked DoD item. Re-verify it instead (run its named test/gate) and note the result.

## 4. Work in scope

- Implement ONLY the issue's Scope section. Discovered adjacent work → file via astro-new-issue and link it; never expand scope in place.
- Every verification follows astro-fsv (source-of-truth readback, never API echoes). Any work that writes, edits, runs, or removes tests follows astro-test (suite <180s, no test >60s, impact-gated suites, real data only).
- Every commit body references the issue (`Refs #N`; `Closes #N` only on the final commit **after** gates pass — never on server-pending work, see astro-fanout).
- Never write progress prose into `docs/astrolabe-blueprint.md` (design corrections only).
- No `todo!()`/stubs on shipped paths; fail-closed `{code, message, remediation}` errors; no silent fallback — every degradation labeled, every skip counted.

## 5. Prove, then check the box

A DoD checkbox may be checked only in the same session that ran its verification, with the test name + result pasted in a comment (kind `evidence`).

## 6. Gate

Run the issue's named gates + the required aggregate via astro-gate from `C:/code/Astrolabe`. Exit 125 / `DEFERRED[...]` / `SKIP[...]` are **not** passing evidence. One exception in kind (#280): `SKIP[ASTRO_SUITE_UNCHANGED]` is the impact gate proving your change did **not** touch that suite's input set - the suite's recorded green (`.astro-gate-cache/suite-green.json`) is the standing evidence, and any change inside the input set re-runs the suite by construction. It is lawful for closure only when the skipped suite is genuinely outside your change's blast radius. A gate that fails for a pre-existing reason: attribute it (astro-gate §attribution), file/link an issue — never skip silently.

## 7. Close

1. Closing comment: command, native execution context, output tail, telemetry block (kind `close`).
2. Every DoD box checked with evidence → `gh issue close N`.
3. Tick the issue's checkbox in EPIC #65; remove the `status:*` label.
4. Commit and push the verified state immediately.
5. Verify `target/` is absent (astro-gate §cleanup).

## Stopping early

Use astro-handoff. Never leave an issue silently in-progress.
