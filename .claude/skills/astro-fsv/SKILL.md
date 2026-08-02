---
name: astro-fsv
description: Manual Full State Verification doctrine for ASTROLABE — identify the source of truth, exercise the real artifact yourself, then independently read back the persisted bytes (SQLite artifact, vault, ledger, files), run the edge-case triad, use the smallest sufficient dataset, and format evidence for issue comments. Use when verifying any change/tool result, deciding whether something "worked", or preparing closing evidence. Tests, return values, API echoes, green checkmarks, and log lines are never evidence — only manually observed reality is.
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
- **No mocks, no cover-ups:** verification uses real data and real stores. Determinism is proven by repeated real runs compared byte-for-byte.
- **Manual FSV only — NO TESTS (owner directive 2026-07-14; extends the 2026-07-13 gate-deletion directive):** all test code was deleted from the repo (`#[cfg(test)]` modules, `tests/` dirs, the cbm C suite, trybuild, test scripts). Passing tests prove nothing; never write, run, or cite one — for verification, evidence, measurement, or closure. Verify by running the real artifact yourself (real binary, real corpus — this repo's own trees always qualify) and reading back persisted state by hand. Measurements are taken against the real running binary/server, never a test harness. `cargo check`/`cargo build` remain valid as buildability evidence.
- **Pre-existing vs mine:** before attributing a failure to your change, check `git log --oneline -S "<string>" -- <path>` and `git merge-base --is-ancestor <sha> HEAD`. File pre-existing failures as issues (astro-new-issue); never absorb them silently.
- **Exit codes:** in bash, `cmd | tail` masks failure — capture `${PIPESTATUS[0]}`.
- Native macOS / Apple Silicon execution from `/Users/steveabbey/Documents/Astrolabe` only, on `main`. Build directly with `cargo build --release -p astrolabe-server` — there is no launcher and no wrapper script. Promote the binary out of `target/` before deleting it, then `rm -rf target/` and verify absence.
