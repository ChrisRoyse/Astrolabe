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

## Standing rules

- CI/CD is banned (owner directive 2026-07-11): no gate may cite a CI job as coverage owner, and no evidence may be deferred "until CI runs". `ci/` is local gate config only.
- Every skip is counted and named by the scripts; a new unnamed skip is a defect — file it.
- When a script here gains or loses a code, update this table in the same commit.
