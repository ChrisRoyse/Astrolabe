# Deferred-coverage register — every named `SKIP[...]` / `DEFERRED[...]` token

**Owner issue: #238.** This file is the single index of every named coverage
deferral Astrolabe carries: its owner issue, whether it is a real coverage gap,
and the exact condition that closes it. It exists so a reader of any green
verification evidence can look up a deferral and know what it does and does not
prove.

> **FSV-only era (2026-07-13, owner directive, commit `d90100d`).** The
> aggregate gate/check suite (`scripts/check*.sh`, `scripts/ci-*.sh`, the
> `ci/` directory, the gate self-tests) was **deleted**. Full State
> Verification against reality is the only verification doctrine. Consequences
> for this register:
>
> - No script emits these tokens per-run any more. The "Emitted by" columns
>   below are **historical** (they name the retired emitters for provenance).
> - The deferral inventory itself is **unchanged and still binding**: each
>   Category A/B row is a real coverage gap that remains named, counted,
>   tracked on its owner issue, and never presented as passing — the record
>   simply lives here and in the owner issues instead of in per-run gate
>   output.
> - Mechanical enforcement (`scripts/check-degradation-labels.py`, which
>   rejected CI-ownership claims and required `SKIP[ASTRO_*_LINUX_REQUIRED]`
>   to co-emit `DEFERRED[ASTRO_PORT_PHASE]`) was retired with the suite. The
>   rule it enforced is doctrine in `CLAUDE.md` and applies to any future
>   FSV instrument that labels a skip.
>
> **Extended 2026-07-14 (owner directive, #397):** all test code is deleted from
> the tree — no `#[cfg(test)]` modules, `tests/` dirs, C test corpus, or
> test/gate scripts remain. Any token above that named a test or doctest as its
> coverage owner (e.g. `SKIP[ASTRO_FAST_TIER_DOCTESTS]`,
> `SKIP[ASTRO_GATE_SELFTESTS_UNCHANGED]`) is historical provenance only; the gap
> it names, where still real, is closed exclusively by manual Full State
> Verification against the real artifact. No test is closure evidence.

> **Read this before interpreting green evidence.**
> Green Astrolabe verification proves the system on **native Windows
> (`x86_64-pc-windows-gnu`) only**. It says nothing about Linux or macOS.
> Windows-green is not cross-platform-green.

Companion document: **`docs/port-phase-deferrals.md`** — **RETIRED 2026-08-01.**
The Windows-only scope directive is withdrawn and `DEFERRED[ASTRO_PORT_PHASE]` is
no longer a valid label. Cross-platform work is ordinary in-scope work, and macOS
on Apple Silicon is the primary evidence-bearing host. Category A below is
retained as the historical index; each token it lists now needs its own owner
issue and closure condition rather than the retired port-phase umbrella. (The former `ci/known-skips.md` / `ci/cbm-test-totals.md`
baselines were deleted with the gate suite; the measured `windows-x64-mingw`
CBM baseline of record is 5764/18/0, recorded in the tracker.)

---

## How to read this register

Each token falls into exactly one category. **Only Categories A and B are
coverage gaps** — coverage the project does not currently have. Every gap is
named and counted regardless, per standing invariants 1 (no unlabeled claim)
and 3 (no silent fallback — every skip counted). Categories C–E record
retired gate-era token vocabularies for provenance; they were never coverage
gaps and their emitters no longer exist.

---

## Category A — Cross-platform coverage deferrals (owner #238, port phase)

These are the real coverage gaps against non-Windows platforms. Each is proven
on native Windows and **unproven anywhere else**. Closure condition for every
row: **a native run on the target platform, recorded on #238 with command,
host, and output** — which happens in the `Port — cross-platform (deferred)`
milestone (#11), not now. See `docs/port-phase-deferrals.md`.

| Token | Historical emitter (retired 2026-07-13) | Owner issue(s) | What is unproven | Closes when |
|---|---|---|---|---|
| `SKIP[ASTRO_CBM_CLANG_TIDY_LINUX_REQUIRED]` | `scripts/ci-cbm-lint.sh` | #238 (also #166, #167) | clang-tidy static analysis of the CBM C sources (analysis is platform-dependent) | clang-tidy runs on a Linux host in the port phase; evidence on #238 |
| `SKIP[ASTRO_EGRESS_LINUX_REQUIRED]` | `scripts/check-egress-deny.py` | #238 (wording scrub #224) | egress-deny proven by `strace` syscall injection — no Windows equivalent in the harness | the strace egress probe runs on a Linux host; evidence on #238 |
| `SKIP[ASTRO_CBM_SANITIZERS_LINUX_REQUIRED]` | `scripts/ci-cbm-test.sh` | #238 (also #174, #3) | ASan/UBSan/LSan over the CBM C suite — **MinGW-w64 GCC ships no sanitizer runtimes** (measured: the retired gate linked a `-fsanitize` probe and only skipped on genuine link failure) | the CBM suite runs under sanitizers on a sanitizer-capable host; evidence on #238 |
| `SKIP[ASTRO_CBM_INCREMENTAL_LINUX_REQUIRED]` | `scripts/ci-cbm-test.sh` | #238 | the upstream incremental suite (its setup builds a POSIX-single-quoted command through `system()`, which is `cmd.exe` on native Windows) | the incremental suite sets up and runs on a POSIX host; evidence on #238 |
| `DEFERRED[ASTRO_PORT_PHASE]` | many (umbrella; still used in DoD clauses and issue comments) | #238 | the co-named clause on any non-Windows platform | a native run on the named platform produces the evidence on #238 |

Non-token cross-platform gaps tracked under the same owner (they live in DoD
clauses and `docs/port-phase-deferrals.md`):

- **Cross-platform golden byte-parity** (#7, #10, #11, #13) — defended by an
  architectural `to_be_bytes` argument only; **an argument is not evidence**.
  Goldens are asserted on native Windows only. Closes when a Linux/macOS build
  reproduces the same bytes, recorded on #238.
- **`libcbm.a` build on Linux/macOS** (#3 DoD1) — the static archive is built
  only with the pinned MinGW-w64 GCC 14.1 toolchain. Closes when it builds under
  Linux/macOS toolchains, recorded on #238.

Analyzer-ABI note (not a coverage claim): the pinned Cppcheck configuration
targets `unix64` so findings are stable and cross-checkable. **That is an ABI
choice only and asserts no Linux coverage.**

---

## Category B — Non-port coverage-owner skip

A real coverage gap that is **not** a port-phase deferral — it is owned by a
specific fix issue, not the port milestone.

| Token | Historical emitter (retired 2026-07-13) | Owner issue | What is unproven | Closes when |
|---|---|---|---|---|
| `SKIP[ASTRO_CALYX_CLIPPY_VENDOR_PINNED]` | `scripts/ci-rust-gate.sh` | #234 | clippy over the Calyx sources (`too_many_arguments` / `manual_repeat_n` etc.) | the lints are fixed **directly in the now-owned Calyx source** (per EPIC #286 `calyx/` is owned first-class source — the token's "vendored/upstream-pinned" wording is stale and #234 is pending re-scope) and clippy over `calyx/` is clean in an FSV run |

---

## Categories C–E — Retired gate-era vocabularies (provenance only; never coverage gaps)

The former tiering/impact-gating skips (`SKIP[ASTRO_FAST_TIER_HEAVY_TESTS]`,
`SKIP[ASTRO_FAST_TIER_DOCTESTS]`, `SKIP[ASTRO_GATE_SELFTESTS_UNCHANGED]`,
`SKIP[ASTRO_CBM_SPAWN_FSV]`), the timeout continuations
(`DEFERRED[ASTRO_NATIVE_AGGREGATE]`, `DEFERRED[ASTRO_WORKSPACE_TEST_TIMEOUT]`),
the `SKIP[...REMOVED]` tombstones, and the `INFO[ASTRO_*]` informational
markers all belonged to the deleted tier/aggregate machinery. Their emitters no
longer exist and none of them ever denoted missing coverage. They are recorded
here only so an old log line can still be interpreted. No future FSV instrument
may reuse these token names for a different meaning.

---

## Closing any deferral

A row leaves Category A or B only when the real coverage runs and the evidence
is recorded on its owner issue with command, host, and output — the same FSV
standard as any other verification. Until then, every Category-A/B item is:
**named, counted, tracked, and not passing.**
