---
name: astro-gate
description: Runs ASTROLABE native verification correctly — preflight (launcher lock, toolchain occupancy, target/ state → verdict), launcher and aggregate invocation forms, gate-code semantics (SKIP/DEFERRED/INFO/exit 125, the #280 suite-impact gate, GATE_TIME timing surface), pre-existing-failure attribution, and mandatory target/ cleanup. Use before any cargo build/test/check or aggregate gate run, when interpreting gate output or a red gate, when a lock or another session's build is present, or when deciding build-vs-stage. Test-authoring and timing-budget rules live in astro-test.
allowed-tools: Bash(git log *), Bash(git merge-base *), Bash(tasklist *), Bash(ls *)
---

# Native gate runner

All evidence is produced natively on Windows from `C:/code/Astrolabe`. Post every gate run on the active issue with a telemetry block (kind `gate`), per `${CLAUDE_PROJECT_DIR}/.claude/skills/astro-telemetry/references/spec.md`.

## 1. Preflight — always first

```
pwsh -NoProfile -File ${CLAUDE_PROJECT_DIR}/.claude/skills/astro-gate/scripts/preflight.ps1
```

It prints one JSON verdict. Act on it; do not proceed on error output:

| Verdict | Meaning | Allowed actions |
|---|---|---|
| `LOCKED_LIVE` | `.tmp/astrolabe-launcher.lock` names a live PID | Lock is **inviolable** (#197): never remove it, stop its processes, or touch `target/`. Wait, or record the conflict on the active issue and do read-only work. |
| `LOCKED_DEAD` | Lock names only dead PIDs | Clean the lock/`target/` only **after** posting PID-probe evidence to the lock's driving issue. Live toolchain processes can still exist under a dead lock — re-check `astro_procs`. |
| `OWNED_BUSY` | Live rustc/cargo/cc1/make whose command line references this workspace/calyx/cbm | Toolchain is owned regardless of lock presence. Read-only, non-colliding work only. Never start a build; never clean `target/`. |
| `CPU_CONTENDED` | Live toolchain processes from unrelated projects | Builds permitted but slow; prefer targeted per-crate commands over the aggregate. |
| `FREE` | No lock, no live toolchain, no foreign `target/` | Full build/gate work permitted. |

Tracker-comment **before** acquiring or removing any lock, and re-read the driving issue's latest comments before acting on lock state.

## 2. Invocation forms

- **Launcher (all native cargo/C/aggregate work):**
  `$toolArgs = '["scripts/check-full.sh"]'; ./scripts/windows-gnu-toolchain.ps1 -Command 'C:\Program Files\Git\bin\bash.exe' -CommandArgsJson $toolArgs`
- **Aggregate:** only through `scripts/invoke-native-aggregate.ps1`, consuming its **stdout directly**. Never wrap in `Tee-Object`, a transcript, or redirection to any file — the invoking process is the evidence stream.
- **Long runs (#197 rule 4):** the binding budget is sub-180s for the full suite (#280, astro-test), but any run that can exceed a foreground tool-call timeout (cold caches, release tier, pre-#280 trees) must be launched detached, with the launcher PID posted to the driving issue at start, so other sessions verify liveness instead of guessing.
- **Fast paths:** pure-Rust crates: `cargo check -p <crate> --all-targets` / `cargo nextest run -p <crate>` (no C toolchain needed). Server changes: targeted `cargo test -p astrolabe-server` through the launcher bypasses the portable pre-check phase when that phase is red for tracked reasons. Formatter: `python scripts/native-cargo-fmt.py --all -- --check` (never bare `cargo fmt --all`).
- **Exit codes:** `cmd | tail` masks failure — capture `${PIPESTATUS[0]}`.
- Never set `CBM_CACHE_DIR` globally (the CBM C tests hardcode `$HOME/.cache`; redirecting regresses ~808 tests).

## 3. Reading results

Verdict vocabulary and every known code: [references/gate-codes.md](references/gate-codes.md). Non-negotiables:
- Exit `125` / `DEFERRED[...]` = downstream suites did not run — **not** passing evidence. Use the printed `ASTROLABE_WORKSPACE_TEST_TIMEOUT_SECS=0` continuation only for an intentional full run.
- `SKIP[...]` = recorded coverage gap (tracked, e.g. #224), never a pass. `INFO[...]` = context, not a verdict. One deliberate exception: `SKIP[ASTRO_SUITE_UNCHANGED]` (the #280 impact gate) means the suite's input set is byte-identical to its last recorded GREEN — it re-certifies existing evidence rather than recording a gap; force with `ASTRO_SUITE_GATE=all` (check-release always runs all).
- `GATE_TIME[<gate>]` / `GATE_TIME_TOTAL` lines are the timing surface (#280): compare against the sub-180s budget; a materially grown gate time is a regression to file.
- Never fake a gate result. A gate unavailable or red for pre-existing reasons gets an issue filed/linked (astro-new-issue).

## 4. Attributing a red gate

Before assuming your change broke it: `git log --oneline -S "<failing string>" -- <path>` and `git merge-base --is-ancestor <suspect-sha> HEAD`. Pre-existing layers get peeled one at a time, each with its own issue ("aggregate onion"). The aggregate has been fully green on main (522b5ce, 2026-07-11) — a red gate is attributable, not background noise.

## 5. Cleanup — after every batch

Delete `C:/code/Astrolabe/target` immediately after evidence capture (pass, fail, or interruption) and **verify it is absent**; also before issue close, pause, turn end, or handoff. `.sccache` survives the wipe by design (launcher-owned compilation cache). Only clean under an absent or proven-dead lock (§1).
