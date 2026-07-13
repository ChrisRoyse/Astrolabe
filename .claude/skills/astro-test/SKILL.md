---
name: astro-test
description: ASTROLABE test doctrine — binding rules for writing, editing, running, debugging, tiering, or deleting any test, and for touching test config. Owner directive 2026-07-12 (#280) — the full suite (check.sh aggregate + the CBM C suite) must finish under 180 seconds; no single test may exceed 60 seconds (decompose or delete it, never merely tier it); a suite runs only when code changes impact its declared input set (check-suite-impact.py, fail-closed); tests use real data and real stores (never mocks), verify persisted bytes (FSV), and fail closed. Use for any work involving #[test] code, tests/ directories, cargo test, cargo nextest, .config/nextest.toml profiles, the hazard-suite registry, the CBM C suite (ci-cbm-test.sh), gate self-tests (scripts/test-*.py), slow tests, flaky tests, soak or property or trybuild tests, test timing, or deciding whether a test may be added, skipped, or removed. Not for gate invocation mechanics (astro-gate) or evidence formatting (astro-fsv).
user-invocable: true
paths:
  - "crates/**/tests/**"
  - "**/*_test.rs"
  - "**/test_*.rs"
  - "**/tests.rs"
  - ".config/nextest.toml"
  - "ci/hazard-suite.json"
  - "ci/cbm-test-totals.md"
  - "ci/known-skips.md"
  - "scripts/test-*.py"
  - "scripts/check-*.py"
  - "scripts/check-*.sh"
  - "scripts/ci-*.sh"
  - "vendor/codebase-memory-mcp/tests/**"
  - "vendor/calyx/**/tests/**"
---

# ASTROLABE test doctrine

Tests exist to give a **correct pass/fail signal in the least wall-clock that still proves the change**. A slow test is a defect; a dishonest fast test is a worse one. Both get fixed at the root, never papered over.

## Hard rules (owner directives — binding, in force)

1. **Suite budget (2026-07-12, #280):** the entire test suite — the `check.sh` aggregate plus the CBM C suite — must complete in **under 180 seconds wall clock**. Anything over budget is a defect to engineer away (cache, shard, decompose, cut redundancy), tracked on an issue, never accepted as ambient cost.
2. **Per-test budget:** **no single test may run longer than 60 seconds.** An offender is **decomposed or deleted — never merely tiered, never timeout-raised, never `#[ignore]`d without a named counted label.** `slow-timeout = 60s` in `.config/nextest.toml` marks offenders in gate output (mark-only, no terminate — an honest slow test fails review, not mid-run). Precedent: the bridge trybuild `!Send` triple (213.6s of nested cargo) and the weave 4096 queue soak (~75s) were deleted under this directive (#280).
3. **Impact gating (#280):** **no suite runs when no code change impacts it.** `scripts/check-suite-impact.py` fingerprints each suite's declared input set — tracked blob SHAs + working-tree bytes of every dirty/untracked input + toolchain identity — against the recorded-green manifest (`.astro-gate-cache/suite-green.json`). Unchanged since green ⇒ `SKIP[ASTRO_SUITE_UNCHANGED]` (exit 3). **Any ambiguity ⇒ run (fail-closed).** `record-green` only ever runs after the suite itself passed. `check-release.sh` sets `ASTRO_SUITE_GATE=all` — the release tier always runs everything.
4. **Real data only:** no mocks, no fakes, no stubs, no API-echo assertions. Tests execute real stores (SQLite artifact, Calyx vault, ledger, files, processes) and prove outcomes by **independent readback of persisted bytes** (astro-fsv protocol). A test that passes while the project is broken is the worst defect a test can have.
5. **Fail closed:** invalid-input paths assert `{code, message, remediation}`; every skip is **named and counted**; no silent fallback in tests or harnesses; a red result is reported with its output, never absorbed.
6. **Speed never weakens HONEST/FSV:** the budget is met by cutting waste — over-testing, redundant rebuilds, unimpacted suites, oversized datasets — **never by skipping coverage a change actually needs.** Closure evidence still covers the real blast radius.

## Writing a test

- **Smallest sufficient dataset:** ask what the smallest input is that 100% proves the behavior, and use that. Predict the expected output before running (know that 2+2 must show 4, and where the 4 will appear). Scale only when scale itself is the claim. This is simultaneously the core FSV habit and the main speed lever.
- **Budget at authoring time:** estimate the test's wall clock as you write it. If honestly proving the claim needs >60s, split the claim into separately provable <60s pieces or shrink the dataset. A test that spawns a nested build/compile (trybuild-style) to prove a static property is over-testing — assert the property at the type level or with a trivial fixture.
- **Deterministic:** seeded, worker-count-invariant. Pair every mutation with its ledger entry where the contract requires one.
- **Sandboxed:** test-runners self-sandbox `env::temp_dir()` to `target/suite-tmp/tmp`. **Never set `CBM_CACHE_DIR` globally** — the CBM C tests hardcode `$HOME/.cache`; a global redirect regresses ~808 tests.
- **Edge-case triad** (astro-fsv): empty input, maximum/limit input, invalid format — invalid must fail closed, with before/after state printed.
- **Registries travel with the test:** a test added to or removed from hazard coverage updates `ci/hazard-suite.json` in the same commit; CBM C suite count changes update `ci/cbm-test-totals.md`; every baseline the test feeds moves with it.

## The suites

| Suite | Runner | Notes |
|---|---|---|
| Rust workspace | `cargo nextest` (`.config/nextest.toml`) | `default` profile = full coverage; `fast` profile = identical coverage post-#280 (kept for invocation compat); `slow-timeout=60s` mark-only |
| CBM C suite | `scripts/ci-cbm-test.sh` | ~5.7k tests, exact-count gate (`ci/cbm-test-totals.md`), `STEP_TIME` per-phase instrumentation |
| Hazard suite | `scripts/check-hazard-suite.py` over `ci/hazard-suite.json` | registered crash/soak scenarios; registry is the source of truth |
| Gate self-tests | `scripts/test-*.py` | change-gated via `.astro-gate-cache/` manifest; fail-closed controls must stay unconditional |

## Running tests

- **Preflight first, always** (astro-gate): launcher lock and toolchain occupancy rules bind before any test run.
- **Tier by blast radius** (CLAUDE.md fast-feedback doctrine): Tier 0 = `cargo nextest run -p <touched crates>`; Tier 1 = affected crates' full suites + fmt + lints; Tier 2 = the native aggregate — pre-merge-to-main or foundational surface only. Measure blast radius (`trace_path` + `detect_changes`) before choosing.
- Crates that link libcbm (`cbm-sys`, `astrolabe-bridge`, `astrolabe-server`) need the launcher; pure-Rust crates run with any native Windows toolchain.
- `GATE_TIME[<gate>]` / `GATE_TIME_TOTAL` lines are the timing surface. A gate whose time grows materially is a regression — file it (astro-new-issue) with the before/after numbers.

## Slow-test disposition (mandatory procedure)

1. **Measure** the single test honestly (nextest prints per-test durations; `STEP_TIME` for CBM phases).
2. **Root-cause** with first principles: over-testing (oversized dataset, nested builds, redundant IO, setup repeated per-case) vs an honestly heavy claim.
3. **Decompose or shrink first.** Delete only with the #280 directive cited and issue evidence; the claim the test proved must be re-proven by the decomposed tests or explicitly recorded as dropped coverage on an issue. Remove every registry reference in the same commit.
4. **Never:** raise a timeout to hide it, weaken assertions to speed it up, mock the store to avoid IO, or leave an unlabeled `#[ignore]`.

## Enforcement

This skill's `paths:` globs and description are the advisory triggers; the
deterministic backstop is the PostToolUse hook `${CLAUDE_SKILL_DIR}/scripts/test_doctrine_context.py`
(wired in the machine-local `.claude/settings.json`), which injects the hard
rules on any test-surface tool call — including inline `#[cfg(test)]` modules in
`src/*.rs` that path globs cannot see. Wiring, subagent caveats, and the FSV
probe recipe: [references/enforcement.md](references/enforcement.md).

## Cross-links

- **astro-fsv** — evidence protocol (source of truth, readback, triad, evidence formatting).
- **astro-gate** — preflight, launcher invocation, gate-code semantics (including `SKIP[ASTRO_SUITE_UNCHANGED]`), cleanup.
- **astro-new-issue** — file every discovered offender, timing regression, or coverage gap; never carry one silently.
