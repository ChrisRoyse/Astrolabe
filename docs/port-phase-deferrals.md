# Port-phase deferrals — the `DEFERRED[ASTRO_PORT_PHASE]` register

**Owner issue: #238.** This file is the single register of coverage that
Astrolabe deliberately does not have yet, and why.

> For a complete index of *every* named `SKIP[...]` / `DEFERRED[...]` token the
> gates emit — its owner issue, whether it is a real coverage gap, and its exact
> closure condition — see **`docs/deferred-coverage-register.md`**. This file
> owns the `DEFERRED[ASTRO_PORT_PHASE]` doctrine that register indexes.

> **Read this before interpreting a green aggregate.**
> A green Astrolabe gate means **the system is proven on native Windows
> (`x86_64-pc-windows-gnu`)**. It does **not** mean the system is proven on
> Linux or macOS. Nothing in this repository has ever been verified on those
> platforms. Windows-green is not cross-platform-green.

## Scope directive (owner, 2026-07-11)

> "We need to only get this system running on Windows and no other system. Focus
> only on Windows only. Nothing else. We will port over to all other systems at
> the very end once everything is fully operational and built. We don't mess with
> that now."

Astrolabe is **Windows-only scope** until the whole system is operational on
native Windows. Porting to Linux and macOS is a **scheduled phase at the end**,
not abandoned work and not work anyone should be doing now.

## The classification

Three things are all false, and none of them may be written into a gate, a DoD
clause, or an issue comment:

| False label | Why it is false |
|---|---|
| "owned by the required Linux CI job" | Hosted CI/CD is **banned** (owner directive, 2026-07-11). `.github/` is deleted. There are no workflows, no required status checks, and no CI jobs. A CI job cannot own anything, because none exist. |
| "permanent coverage gap / accepted, will never have it" | False. We intend to port. Calling it permanent misrepresents a scheduled commitment as an abandoned one. |
| "run it on a Linux host to close" | False as an instruction. That work is deliberately **not being done now**; telling a reader to go do it contradicts the scope directive. |

The one true label:

```
DEFERRED[ASTRO_PORT_PHASE]
```

**Definition.** The implementation is proven on native Windows. Evidence on
other platforms is deliberately deferred to the port phase. The deferral is
**tracked (#238), labeled, and counted — and is never passing evidence.** It is
never silently ticked from a Windows-green aggregate.

This preserves standing invariant 1 (no unlabeled claim) and invariant 3 (no
silent fallback — every degradation labeled, every skip counted). A deferred
clause is labeled and counted exactly like a skip; it simply names the port
phase, rather than a CI job that does not exist, as the thing that will
eventually produce the evidence.

### How to apply it

**In a gate script** — emit the named skip (so it is counted), then the
classification (so it is owned):

```sh
echo "SKIP[ASTRO_EGRESS_LINUX_REQUIRED]: the strace egress probe needs a Linux host, so egress-deny is UNPROVEN on this platform."
echo "DEFERRED[ASTRO_PORT_PHASE]: strace egress-deny coverage is deferred to the port phase (Windows-only scope, owner directive 2026-07-11); tracked in #238. Not passing evidence; no CI job owns it."
```

`scripts/check-degradation-labels.py` **enforces this mechanically** on every
aggregate run: it fails closed if any file under `scripts/` or `ci/` claims a CI
job owns coverage, or emits a `SKIP[ASTRO_*_LINUX_REQUIRED]` without also
emitting `DEFERRED[ASTRO_PORT_PHASE]` and naming #238.

**In a DoD clause** — a clause whose evidence owner is a CI job or a non-Windows
platform is not "blocked" and must not be ticked. Rewrite it as:

```
- [x] <clause>, proven on native Windows (x86_64-pc-windows-gnu): <evidence>
- [ ] DEFERRED[ASTRO_PORT_PHASE]: cross-platform evidence for <clause> — tracked in #238
```

The Windows half closes on Windows evidence. The cross-platform half moves to
#238 and is settled in the port phase. **A Windows-green aggregate never ticks
the deferred half.**

## The register

Everything below is proven on native Windows and unproven elsewhere.

### 1. Linux-only analyzers and probes

| Coverage | Marker | Emitted by | Why it cannot run on Windows |
|---|---|---|---|
| CBM C `clang-tidy` analysis | `SKIP[ASTRO_CBM_CLANG_TIDY_LINUX_REQUIRED]` | `scripts/ci-cbm-lint.sh` | clang-tidy's analysis is platform-dependent. Tracked also in #166, #167. |
| `strace` egress-deny probe | `SKIP[ASTRO_EGRESS_LINUX_REQUIRED]` | `scripts/check-egress-deny.py` | The harness proves egress denial by `strace` syscall injection; there is no Windows equivalent in the harness. |
| ASan / UBSan / LSan on the CBM C suite | `SKIP[ASTRO_CBM_SANITIZERS_LINUX_REQUIRED]` | `scripts/ci-cbm-test.sh` | **MinGW-w64 GCC ships no sanitizer runtimes.** The probe is measured, never assumed: the gate compiles a `-fsanitize=address,undefined` probe and only skips when the link genuinely fails. Tracked also in #174, #3. |
| CBM incremental suite | `SKIP[ASTRO_CBM_INCREMENTAL_LINUX_REQUIRED]` | `scripts/ci-cbm-test.sh` | The upstream fixture clone builds its shell command with POSIX single quoting and runs it through `system()`, which is `cmd.exe` in a native Windows binary, so setup always fails. Its registrations are excluded from the `ci/cbm-test-totals.md` baseline. |

The blocking Cppcheck run targets `unix64` (`INFO[ASTRO_CBM_CPPCHECK_LINUX_ABI]`)
so findings stay stable and comparable across hosts. **That is an analyzer-ABI
choice only — it is not Linux coverage and asserts none.**

### 2. Cross-platform golden byte-parity (#7, #10, #11, #13)

Byte-identical goldens across platforms are currently defended by an
**architectural argument**, not by evidence: identity bytes are framed with
explicit `to_be_bytes` little-/big-endian-independent encoding and hashed as
pure bytes, so the encoding contains no platform-dependent term.

**An argument is not evidence.** The goldens are asserted on native Windows
only. Whether a Linux or macOS build reproduces the same bytes is **unproven**
and `DEFERRED[ASTRO_PORT_PHASE]`.

### 3. `libcbm.a` build on Linux/macOS (#3 DoD1)

The C half is built and linked as a static archive **only** with the pinned
MinGW-w64 GCC 14.1 toolchain, sharing one ABI with the `x86_64-pc-windows-gnu`
Rust host. Building `libcbm.a` under Linux/macOS toolchains is
`DEFERRED[ASTRO_PORT_PHASE]`.

### 4. Non-Windows platform labels in gate baselines

`ci/known-skips.md` records expected skip counts for `linux-x64-gcc`,
`linux-x64-clang`, and `macos-arm64-clang`. **Those rows have never been
executed.** They are retained as the port-phase baseline, not as evidence that
those platforms pass. `ci/cbm-test-totals.md` records only the measured
`windows-x64-mingw` row.

## Closing a deferral

A deferral leaves this register only when a **native run on that platform**
produces the evidence, recorded on #238 with the command, host, and output — the
same FSV standard as any other gate. That happens in the port phase.

Until then, every item above is: **named, counted, tracked, and not passing.**
