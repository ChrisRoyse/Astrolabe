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
| `SKIP[ASTRO_SUITE_UNCHANGED]` | `scripts/check-suite-impact.py` (#280) | Suite's declared input set is byte-identical to its last recorded green (exit 3 from `should-run`). **The one skip that is not a coverage gap** — it re-certifies recorded evidence. Force with `ASTRO_SUITE_GATE=all`; check-release always runs all. |
| `INFO[ASTRO_SUITE_IMPACTED]` | `scripts/check-suite-impact.py` (#280) | Fingerprint changed or no recorded green — suite runs. |
| `INFO[ASTRO_SUITE_GATE_FAILCLOSED]` | `scripts/check-suite-impact.py` (#280) | Manifest absent/corrupt, unregistered suite, or fingerprint ambiguity — suite runs (unknown state never skips). |
| `INFO[ASTRO_SUITE_GATE_ALL]` / `INFO[ASTRO_SUITE_GREEN_RECORDED]` | `scripts/check-suite-impact.py` (#280) | Forced-run mode / green fingerprint recorded after a passing suite. Informational. |
| `SKIP[ASTRO_FAST_TIER_HEAVY_TESTS]` | `scripts/check.sh` fast path (#280, transitional) | Named counted heavy-test exclusion owned by check-full/check-release. Shrinking toward zero as offenders are decomposed/deleted per the astro-test doctrine. |
| `INFO[ASTRO_CBM_PARITY_BINARY_CACHED]` | `scripts/cbm-prod-build.sh` (#280) | CBM prod binary served from the content-keyed cache (tree + build wiring + toolchain); any key ambiguity forces a full rebuild. |
| `INFO[ASTRO_FMT_VENDOR_EXCLUDED]` | `scripts/check.sh` (#280) | Fast-path fmt is workspace-scoped; the full graph runs in `ci-rust-gate.sh` (release tier). |
| `GATE_TIME[<gate>]` / `GATE_TIME_TOTAL` | aggregate scripts (#280) | Per-gate and total wall-clock surface for the sub-180s budget. Not a verdict; a materially grown time is a regression to file. |

## Standing rules

- CI/CD is banned (owner directive 2026-07-11): no gate may cite a CI job as coverage owner, and no evidence may be deferred "until CI runs". `ci/` is local gate config only.
- Every skip is counted and named by the scripts; a new unnamed skip is a defect — file it.
- When a script here gains or loses a code, update this table in the same commit.
