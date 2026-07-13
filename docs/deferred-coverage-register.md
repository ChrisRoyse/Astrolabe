# Deferred-coverage register — every named `SKIP[...]` / `DEFERRED[...]` token

**Owner issue: #238.** This file is the single index of *every* named
degradation token the Astrolabe gates can emit: its owner issue, whether it is a
real coverage gap, and the exact condition that closes it. It exists so a reader
of a green aggregate can look up any `SKIP[...]` or `DEFERRED[...]` line and know
what it does and does not prove.

> **Read this before interpreting a green aggregate.**
> A green Astrolabe gate proves the system on **native Windows
> (`x86_64-pc-windows-gnu`) only**. It says nothing about Linux or macOS.
> Windows-green is not cross-platform-green.

Two companion documents own the *doctrine* this register indexes:

- **`docs/port-phase-deferrals.md`** — the `DEFERRED[ASTRO_PORT_PHASE]`
  classification: why cross-platform evidence is deferred (not "CI-owned", not
  "a permanent gap", not "a runbook to run now"), and how to apply the label in
  a gate script or a DoD clause. Category A below is the tabular index into it.
- **`ci/known-skips.md`** / **`ci/cbm-test-totals.md`** — expected per-platform
  skip counts and the measured `windows-x64-mingw` baseline.

`scripts/check-degradation-labels.py` mechanically enforces, on every aggregate
run, that no file under `scripts/` or `ci/` claims a CI job owns coverage and
that every `SKIP[ASTRO_*_LINUX_REQUIRED]` co-emits `DEFERRED[ASTRO_PORT_PHASE]`
naming #238.

---

## How to read this register

Each token falls into exactly one category. **Only Categories A and B are
coverage gaps** — coverage the project does not currently have. Categories C–E
are *not* gaps: the coverage exists, just in a different tier/run, or the token
is purely informational. Every token is named and counted regardless, per
standing invariants 1 (no unlabeled claim) and 3 (no silent fallback — every
skip counted).

---

## Category A — Cross-platform coverage deferrals (owner #238, port phase)

These are the real coverage gaps against non-Windows platforms. Each is proven
on native Windows and **unproven anywhere else**. Closure condition for every
row: **a native run on the target platform, recorded on #238 with command,
host, and output** — which happens in the `Port — cross-platform (deferred)`
milestone (#11), not now. See `docs/port-phase-deferrals.md`.

| Token | Emitted by | Owner issue(s) | What is unproven | Closes when |
|---|---|---|---|---|
| `SKIP[ASTRO_CBM_CLANG_TIDY_LINUX_REQUIRED]` | `scripts/ci-cbm-lint.sh` | #238 (also #166, #167) | clang-tidy static analysis of the CBM C sources (analysis is platform-dependent) | clang-tidy runs on a Linux host in the port phase; evidence on #238 |
| `SKIP[ASTRO_EGRESS_LINUX_REQUIRED]` | `scripts/check-egress-deny.py` | #238 (wording scrub #224) | egress-deny proven by `strace` syscall injection — no Windows equivalent in the harness | the strace egress probe runs on a Linux host; evidence on #238 |
| `SKIP[ASTRO_CBM_SANITIZERS_LINUX_REQUIRED]` | `scripts/ci-cbm-test.sh` | #238 (also #174, #3) | ASan/UBSan/LSan over the CBM C suite — **MinGW-w64 GCC ships no sanitizer runtimes** (measured: the gate links a `-fsanitize` probe and only skips on genuine link failure) | the CBM suite runs under sanitizers on a sanitizer-capable host; evidence on #238 |
| `SKIP[ASTRO_CBM_INCREMENTAL_LINUX_REQUIRED]` | `scripts/ci-cbm-test.sh` | #238 | the upstream incremental suite (its setup builds a POSIX-single-quoted command through `system()`, which is `cmd.exe` on native Windows) | the incremental suite sets up and runs on a POSIX host; evidence on #238 |
| `DEFERRED[ASTRO_PORT_PHASE]` | many (umbrella) | #238 | the co-named clause on any non-Windows platform | a native run on the named platform produces the evidence on #238 |

Non-token cross-platform gaps tracked under the same owner (no gate emits them
per-run; they live in DoD clauses and `docs/port-phase-deferrals.md`):

- **Cross-platform golden byte-parity** (#7, #10, #11, #13) — defended by an
  architectural `to_be_bytes` argument only; **an argument is not evidence**.
  Goldens are asserted on native Windows only. Closes when a Linux/macOS build
  reproduces the same bytes, recorded on #238.
- **`libcbm.a` build on Linux/macOS** (#3 DoD1) — the static archive is built
  only with the pinned MinGW-w64 GCC 14.1 toolchain. Closes when it builds under
  Linux/macOS toolchains, recorded on #238.

Analyzer-ABI note (not a coverage claim): the blocking Cppcheck run targets
`unix64` and emits `INFO[ASTRO_CBM_CPPCHECK_LINUX_ABI]` so findings are stable
and cross-checkable. **That is an ABI choice only and asserts no Linux
coverage.**

---

## Category B — Non-port coverage-owner skip

A real coverage gap that is **not** a port-phase deferral — it is owned by a
specific fix issue, not the port milestone.

| Token | Emitted by | Owner issue | What is unproven | Closes when |
|---|---|---|---|---|
| `SKIP[ASTRO_CALYX_CLIPPY_VENDOR_PINNED]` | `scripts/ci-rust-gate.sh` | #234 | clippy over the Calyx sources (`too_many_arguments` / `manual_repeat_n` etc.) | the lints are fixed **directly in the now-owned Calyx source** (per EPIC #286 `vendor/calyx` is owned first-class source — the token's "vendored/upstream-pinned" wording is stale and #234 is pending re-scope) and the skip is removed, restoring the stage to blocking |

---

## Category C — Tiering / impact-gating skips (NOT coverage gaps)

The coverage **exists** — it simply runs in a higher tier or was skipped because
no code change impacted it (test-suite doctrine, #280/#288). Each is named and
counted; none is a gap.

| Token | Emitted by | Where the coverage actually runs | Closes / does-not-apply when |
|---|---|---|---|
| `SKIP[ASTRO_FAST_TIER_HEAVY_TESTS]` | `scripts/check.sh` | `scripts/ci-rust-gate.sh` (default nextest profile, every test) via `check-full.sh` | the full/release tier runs |
| `SKIP[ASTRO_FAST_TIER_DOCTESTS]` | `scripts/check.sh` | `ci-rust-gate.sh` (`cargo test --workspace --doc`) via `check-full.sh` | the full/release tier runs |
| `SKIP[ASTRO_GATE_SELFTESTS_UNCHANGED]` | `scripts/run-gate-selftests.py` | the same self-tests, when their fingerprinted inputs change, or on the release tier (`ASTRO_GATE_SELFTESTS=all`) | a self-test input changes, or the release tier forces all |
| `SKIP[ASTRO_CBM_SPAWN_FSV]` | `scripts/test-cbm-spawn-fsv.py` | the CBM spawn FSV self-test, when its prerequisites are present | the prerequisite artifact/toolchain is available |

---

## Category D — Timeout continuations (NOT coverage gaps — coverage did not RUN)

These do not mean "coverage we lack"; they mean the workspace-test phase hit its
wall-clock bound and the downstream suites **were not started**. They are
**never passing evidence**. Closure is a continuation run, not a fix.

| Token | Emitted by | Meaning | Closes when |
|---|---|---|---|
| `DEFERRED[ASTRO_NATIVE_AGGREGATE]` | `scripts/check-full.sh` | workspace-test deadline reached; downstream suites did not start (exit 125) | rerun with `ASTROLABE_WORKSPACE_TEST_TIMEOUT_SECS=0` (the printed `CONTINUATION[ASTRO_NATIVE_AGGREGATE]`) for an intentional full native run |
| `DEFERRED[ASTRO_WORKSPACE_TEST_TIMEOUT]` | `scripts/check.sh` | portable runtime checks were not started within the bound | rerun unbounded |

---

## Category E — Tombstones and informational markers (NOT gaps)

- **`SKIP[...REMOVED]`** tombstones (`ASTRO_CBM_CLANG_TIDY_REMOVED`,
  `ASTRO_CBM_INCREMENTAL_REMOVED`, `ASTRO_CBM_SANITIZERS_REMOVED`,
  `INFO[ASTRO_CBM_FORMAT_REMOVED]`) record that a former stage was deliberately
  removed. They assert no coverage and own no gap.
- **`INFO[ASTRO_*]`** markers (cache hits/misses/stores, parity-binary caching,
  format, `ASTRO_CBM_SANITIZERS_ACTIVE`, `ASTRO_CBM_RUN_SCOPED_STORE`,
  no-escape attribution/telemetry, debug-binaries-present, release-artifact
  dirty-tree, fast-tier-no-nextest, gate-selftests-all/failclosed) are
  informational only — they neither skip nor defer coverage.

---

## Closing any deferral

A row leaves Category A or B only when the real coverage runs and the evidence
is recorded on its owner issue with command, host, and output — the same FSV
standard as any other gate. Categories C–E are not gaps and close by running the
appropriate tier or need no closure at all.

Until then, every Category-A/B item is: **named, counted, tracked, and not
passing.**
