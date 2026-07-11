---
name: sitrep
description: Honest situation report for the current ASTROLABE session — raw assessment of git state, work in flight, green/red flags, and project health, recorded on the active GitHub issue (issues are the only durable state; no ./tmp SITREP files) and summarized inline. Use when asked for a sitrep/status/honest assessment, or before risky transitions. For a plain pause/stop record, astro-handoff alone suffices.
---

# SITREP

A sitrep is astro-handoff **plus** candid analysis. It is written for a zero-context successor and for the operator.

1. Execute the astro-handoff protocol in full (hygiene verification, done-verified vs not-done, next concrete step, uncommitted state, telemetry block kind `handoff` on the active issue).
2. In the same issue comment and inline to the operator, add the honest layer — raw, not diplomatic:
   - **Green flags** — what is genuinely solid, with the evidence that makes it solid.
   - **Red flags** — risks, smells, drift, unverified claims found in prior comments, hygiene debt (stray branches/worktrees/locks), anything that looks done but has no FSV evidence.
   - **Health call** — one paragraph: is this effort on track, stalled, or quietly broken? Say which and why.
   - **Recommended next steps** — ordered, concrete, each one command/edit deep.
3. Never write SITREP files to `./tmp` or anywhere on disk — the issue comment is the artifact. If no issue is active, file one first (astro-new-issue) or attach to EPIC #65 as a session report.
