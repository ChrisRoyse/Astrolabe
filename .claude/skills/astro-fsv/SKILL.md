---
name: astro-fsv
description: Full State Verification doctrine for ASTROLABE — identify the source of truth, execute, then independently read back the persisted bytes (SQLite artifact, vault, ledger, files), run the edge-case triad, use the smallest sufficient dataset, and format evidence for issue comments. Use when writing or reviewing tests, verifying any change/tool/gate result, deciding whether something "worked", or preparing closing evidence. Return values, API echoes, green checkmarks, and log lines are never evidence on their own.
user-invocable: true
---

# Full State Verification (FSV)

A result is real only after direct verification against the real artifact, process, or persisted data. Anything else is assumption.

## Protocol (every verification)

1. **Define the source of truth.** Where does the final result physically live? (lowered SQLite artifact, Calyx vault, ledger, registry, file on disk, process state, GitHub). Name it before running anything.
2. **Predict the outcome.** With synthetic input you constructed, state the expected output *before* execution (know that 2+2 must show 4, and where the 4 will appear).
3. **Execute.**
4. **Independent readback.** A *separate* read operation against the source of truth — not the mutation's return value:
   - SQLite: `sqlite3 <artifact> "SELECT ..."` (or a second connection), assert rows/bytes.
   - Files: re-open and compare bytes/hash, not the write call's success.
   - Ledger-paired mutations: verify the mutation AND its ledger entry both exist.
   - GitHub state: `gh issue view` / `gh api` readback after the mutation.
5. **Edge-case triad.** Empty input, maximum/limit input, invalid format. For each: print system state before and after to prove the outcome. Invalid input must fail closed with `{code, message, remediation}` — a fallback that hides the failure is a defect.
6. **Evidence.** Paste commands + readback output on the issue with an `astro-telemetry` block (kind `evidence`), per `${CLAUDE_PROJECT_DIR}/.claude/skills/astro-telemetry/references/spec.md`.

## Standing rules

- **Trigger→X→Y:** every process has an observable trigger and an intended persisted outcome. If Y can be physically checked, checking it is mandatory.
- **Smallest sufficient data:** before running the big dataset, ask what the smallest input is that would 100% prove the behavior — run that. Scale only when scale itself is the claim.
- **No mocks, no cover-ups:** tests use real data and real stores. Never write a test that passes while the project is broken. Determinism is seeded and worker-count-invariant.
- **Test timing budgets are doctrine (astro-test):** full suite <180s, no single test >60s (decompose or delete, never merely tier), suites run only when impacted (#280). Writing or changing any test loads astro-test alongside this skill.
- **Pre-existing vs mine:** before attributing a failure to your change, check `git log --oneline -S "<string>" -- <path>` and `git merge-base --is-ancestor <sha> HEAD`. File pre-existing failures as issues (astro-new-issue); never absorb them silently.
- **Exit codes:** in bash, `cmd | tail` masks failure — capture `${PIPESTATUS[0]}`.
- Native Windows execution from `C:/code/Astrolabe` only (astro-gate owns the mechanics).
