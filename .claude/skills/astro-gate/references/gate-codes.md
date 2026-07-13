# Gate verdict vocabulary and known codes

## Verdict semantics

| Form | Meaning | Passing evidence? |
|---|---|---|
| `PASS` / green suite counts | Gate ran to completion natively | Yes |
| `FAIL` | Gate ran, found a defect | No — attribute (pre-existing vs yours), then fix or file |
| exit `125` + `DEFERRED[ASTRO_NATIVE_AGGREGATE]` | `check-full.sh` hit its bounded workspace-test deadline; downstream suites did not run | **No.** Rerun with the printed `ASTROLABE_WORKSPACE_TEST_TIMEOUT_SECS=0` continuation for an intentional full run |
| `SKIP[CODE]` | Named, counted coverage gap on this host | **No.** It is a recorded gap; leave it recorded, never claim it |
| `INFO[CODE]` | Context about how the gate ran | Not a verdict |

## Known codes (2026-07)

| Code | Emitted by | Meaning / owner |
|---|---|---|
| `SKIP[ASTRO_EGRESS_LINUX_REQUIRED]` | `scripts/check.sh` | Linux/strace egress probe cannot run on Windows. Recorded gap tracked in #224 (closable by a manual Linux-host run or an explicit permanent-gap record). |
| `SKIP[ASTRO_CBM_CLANG_TIDY_LINUX_REQUIRED]` | `scripts/ci-cbm-lint.sh` | Platform-dependent clang-tidy has no owner with CI banned. Recorded gap tracked in #224 / #166–#170. The no-skip, cppcheck, clang-format, NOLINT gates still run and must pass. |
| `INFO[ASTRO_CBM_CPPCHECK_LINUX_ABI]` | `scripts/ci-cbm-lint.sh` | Blocking Cppcheck targets `unix64` for a stable cross-checkable analyzer ABI. Informational. |
| `DEFERRED[ASTRO_NATIVE_AGGREGATE]` | `scripts/check-full.sh` | Bounded workspace-test phase deadline reached (exit 125). Incomplete evidence. |
| `SKIP[ASTRO_SUITE_UNCHANGED]` | `scripts/check-suite-impact.py` (via check.sh workspace-block, ci-cbm-test.sh cbm-c-suite) | #280 impact gate: the suite's declared input set is byte-identical to its last recorded GREEN run, so it did not run. Fail-closed (any ambiguity ⇒ run); `ASTRO_SUITE_GATE=all` forces (check-release sets it). A lawful skip, not a gap — the recorded green in `.astro-gate-cache/suite-green.json` is the evidence pointer. |
| `INFO[ASTRO_SUITE_IMPACTED]` / `INFO[ASTRO_SUITE_GATE_FAILCLOSED]` / `INFO[ASTRO_SUITE_GATE_ALL]` / `INFO[ASTRO_SUITE_GREEN_RECORDED]` | `scripts/check-suite-impact.py` | Impact-gate context (changed ⇒ runs; unknown state ⇒ runs; forced; green fingerprint recorded after a pass). |
| `SKIP[ASTRO_RELEASE_TIER_RUST_GATE]` | `scripts/check-full.sh` | #280 tier restructure: full-graph fmt, workspace clippy, full nextest re-run, doctests, and the Calyx suite are run by check-release (`scripts/ci-rust-gate.sh`). Counted omission in check-full, never silent. |
| `SKIP[ASTRO_RELEASE_TIER_CBM_LINT]` | `scripts/check-full.sh` | #280 tier restructure: cppcheck, clang-format, NOLINT, cache-path lint run in check-release (`scripts/ci-cbm-lint.sh`). Counted omission in check-full. |
| `INFO[ASTRO_FAST_TIER_FULL_COVERAGE]` | `scripts/check.sh` | The nextest `fast` profile equals full workspace test coverage (the >60s tests were deleted under #280); the profile name survives for invocation compat. |
| `SKIP[ASTRO_FAST_TIER_DOCTESTS]` | `scripts/check.sh` | Doctests are the one remaining fast-tier omission; check-release runs them via ci-rust-gate.sh. |
| `INFO[CBM_INCREMENTAL_BUILD]` / `STEP_TIME[cbm:*]` / `SUITE_TIME[*]` / `SLOW_SUITE[CBM]` | `vendor/codebase-memory-mcp/scripts/test.sh` + `test-shards.sh` | CBM build premise unchanged ⇒ persistent object tree reused; per-phase and per-suite wall clocks; a suite >60s flags the #280 per-test-budget radar. |
| `INFO[ASTRO_CBM_PARITY_BINARY_CACHED]` | `scripts/cbm-prod-build.sh` | Parity prod binary restored from the content-keyed cache (working-tree-exact fingerprint incl. dirty files). A hit never weakens parity — the harness still runs against the binary. |

## Standing rules

- CI/CD is banned (owner directive 2026-07-11): no gate may cite a CI job as coverage owner, and no evidence may be deferred "until CI runs". `ci/` is local gate config only.
- Every skip is counted and named by the scripts; a new unnamed skip is a defect — file it.
- When a script here gains or loses a code, update this table in the same commit.
