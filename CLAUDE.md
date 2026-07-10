# ASTROLABE — Agent Operating Manual

ASTROLABE fuses Calyx (Rust association-native DB engine, `vendor/calyx`) with codebase-memory-mcp (C code-graph MCP server, `vendor/codebase-memory-mcp`) into one Rust-host binary (`crates/astrolabe-server`) with the C half linked as `libcbm.a` (`crates/cbm-sys`, `crates/astrolabe-bridge`). Plan of record: `docs/astrolabe-blueprint.md`. **State of record: GitHub issues — nothing else.**

## The one rule that outranks all others

**GitHub issues are the single source of truth for what is done, in progress, and remaining.** The blueprint describes the *design*; it never records *progress*. If you learn something about project state, it goes in an issue comment. If it isn't on an issue, it didn't happen.

## Issue workflow (mandatory, in order)

1. **Pick**: choose an issue labeled `status:ready` in the lowest-numbered open milestone (phases must complete in dependency-spine order: `P0 → P1 → P2 → (P3 ∥ P4) → P5 → P6 → (P7 ∥ P8) → P9`; see EPIC #65). Never start a `status:blocked` or `status:needs-spec` issue.
2. **Claim**: comment on the issue: what you're about to do, your plan in ≤5 bullets. Swap label `status:ready` → `status:in-progress`. If the issue already has `status:in-progress` and a claim comment newer than 48h, pick a different issue.
3. **Verify the claim**: re-read the issue body **and all comments** — progress comments record what prior sessions already completed. Never redo checked DoD items; verify them instead (run the named test/gate) and note the result.
4. **Work in scope**: implement ONLY what the issue's Scope section says. Discovered adjacent work = file a new issue with labels + milestone + a `Blocked by:`/`Blocks:` line, and link it in a comment. Never expand scope in place.
5. **Commit discipline**: every commit message body must reference the issue (`Refs #N`, or `Closes #N` on the final commit). No commit may touch `docs/astrolabe-blueprint.md` to record progress — status prose in the blueprint is banned (design corrections are fine).
6. **Prove, then check the box**: a DoD checkbox may only be checked in the same session that ran its verification (test name + result pasted in a comment). Tests must verify persisted state (FSV byte readback), not API echoes.
7. **Gate before done**: run `bash scripts/check.sh` (or, on Windows, the portable subset it documents) plus the issue's named gates. Paste the tail of the output in the closing comment. If a gate fails for a pre-existing reason, file/link an issue for it — do not skip silently.
8. **Close**: when every DoD box is checked with evidence, close the issue, tick its checkbox in EPIC #65, and move the `status:*` label off. If you must stop early, comment exactly: what's done, what's not, the next concrete step, and any local uncommitted state; swap to `status:ready` if another agent can resume, or `status:blocked` naming the blocker.

## Standing invariants (every PR — the HONEST conjunct; violating these = do not merge)

1. No unlabeled claim — grounded responses carry `trust`, `freshness`, `provenance`.
2. No ungated confidence — refusal with deficit over confident guessing.
3. No silent fallback — every degradation labeled, every skip counted.
4. No constant that could be a measurement — new thresholds/weights are registry-declared knobs or measured values.
5. State verification over green checkmarks — tests read persisted bytes (FSV), assert seeded/worker-count-invariant determinism, pair every mutation with its ledger entry.
6. Production-ready or not merged — no `todo!()`/stubs on shipped paths; fail-closed `{code, message, remediation}` errors; docs on public APIs.

## Layout

- `crates/astrolabe-domain` — identity spine (canonical_input_bytes, CxId/series). `astrolabe-ingest` — SQLite→vault import, registry, projections, ledger verify. `astrolabe-lower` — vault→SQLite lowered artifact, team artifact. `astrolabe-panel` — lens panel S0–S22. `astrolabe-weave` — similarity graphs, cross-terms, reactive, anomalies. `astrolabe-kernel` — kernels, bridges, label propagation, skills. `astrolabe-guard` / `astrolabe-oracle` / `astrolabe-assay` / `astrolabe-anchors` / `astrolabe-provenance` — contract crates being brought live per phase. `astrolabe-bridge` + `cbm-sys` — FFI to libcbm. `astrolabe-server` — MCP surface.
- ⚠️ `crates/astrolabe-server/src/migration.rs` is under decomposition (see the refactor issue). **Do not add new code to it**; new MCP tool logic goes in the module structure that issue defines.
- Verification: `scripts/check.sh` (aggregate local gate), `scripts/release-predicate.py` (DONE predicate), `ci/` (gate configs). CI: `.github/workflows/ci.yml`.
- Vendored parents are pinned (`VENDORED.md`, `scripts/verify-pins.sh`). Never edit `vendor/` except via documented patch flow in `patches/`.

## Build notes

- Toolchain: pinned via `rust-toolchain.toml` (Rust 1.95, edition 2024). The C half needs GNU make + a C toolchain (`cbm-sys/build.rs` respects `MAKE`/`CC`/`CXX`/`AR`).
- Pure-Rust work: `cargo check -p <crate> --all-targets` is fast; full workspace check requires the C toolchain.
- Windows: some gates are POSIX/Linux-only (egress-deny needs strace). Run what's portable; never fake a gate result.
