# CBM Registered-Test Totals

This file is the exact-count baseline for CBM C runtime test registrations on
platforms where the pinned-source `RUN_TEST(` count cannot equal the runtime
total. On POSIX labels every registration compiles and runs, so the gate
derives the expected count from the pinned source directly and this file is
not consulted. On native Windows two structural gaps make source derivation
impossible: registrations behind POSIX-only conditional compilation never
build, and the upstream incremental suite's fixture clone builds its shell
command with POSIX single quoting through `system()` (cmd.exe in a native
binary), so its setup always fails and its tests never register
(`SKIP[ASTRO_CBM_INCREMENTAL_LINUX_REQUIRED]`). That incremental coverage is
simply ABSENT on native Windows — no CI job owns it (hosted CI is banned) — and
it is `DEFERRED[ASTRO_PORT_PHASE]`, tracked in issue #238. See
`docs/port-phase-deferrals.md`.

The runtime total (passed + failed + skipped) must equal the recorded count
exactly; both growth and shrinkage fail. Re-derive this baseline whenever the
CBM vendor pin or the pinned Windows toolchain changes.

| System | Gate label | Expected registered tests | Basis |
|---|---|---:|---|
| CBM | windows-x64-mingw | 5782 | Measured native run at CBM pin `49358971c30820dac674b8e036877e3b6c0ff172` with MinGW-w64 GCC 14.1 (5764 passed, 18 skipped, 0 failed); pinned-source `RUN_TEST(` count is 6000 with the delta explained above. |
