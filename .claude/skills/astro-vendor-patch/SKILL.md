---
name: astro-vendor-patch
description: The only lawful way to change vendored code in ASTROLABE (vendor/calyx, vendor/codebase-memory-mcp) — subtree pins in VENDORED.md, the documented patches/ flow, the hash-checked CBM format overlay, and scripts/verify-pins.sh. Use when a fix appears to require edits under vendor/, when patching or building CBM C sources, when pins or VENDORED.md drift, or when a gate reports vendor tree modifications.
---

# Vendored code discipline

`vendor/calyx` and `vendor/codebase-memory-mcp` are pinned Git subtrees. The binding pin is the **exact tree SHA** recorded in `VENDORED.md`. Never edit files under `vendor/` in place — a dirty vendor tree fails `scripts/verify-pins.sh` and the aggregate.

## Decide first

1. **Can the change live on the Astrolabe side?** (wrapper in `crates/astrolabe-bridge`, shim in `patches/cbm/*.c`, build flag in `crates/cbm-sys/build.rs`). Prefer this always.
2. **Is it genuinely an upstream defect?** Then it goes through the patch flow below AND gets an issue tracking upstreaming (pattern: #228 — C mirror of a Rust-side fix).

## The patches/ flow (CBM)

`patches/cbm/` holds the only sanctioned vendor modifications:
- `apply_*.py` scripts materialize a **temporary, hash-checked overlay** — they verify the vendored source bytes against a recorded hash before patching a copy; they never write into `vendor/`. Read `patches/cbm/README.md` before touching anything.
- `astro_alloc_shim.c`, `astro_layout_probe.c`, `Makefile.cbm` are Astrolabe-side build inputs, not vendor edits.
- The CBM clang-format gate validates the overlay the same way — an in-place format run against either vendor tree is a defect.
- Adding a patch: new `apply_<name>_patch.py` with the source hash pinned, wired where the existing ones are consumed; document it in `patches/cbm/README.md`; add its hash-mismatch failure mode (must fail closed with the expected vs found hash).

## Updating a pin (rare, deliberate)

Follow `VENDORED.md` §Update Procedure verbatim: subtree pull/replace → `git add vendor/<name>` → read staged tree SHA via `git rev-parse "$(git write-tree):vendor/<name>"` → update the VENDORED.md table → `bash scripts/verify-pins.sh`. Submodules are forbidden; verify-pins also rejects `.gitmodules`, gitlinks, index-differing tracked vendor files, and non-ignored untracked vendor paths.

## FSV

After any patch/pin work: `bash scripts/verify-pins.sh` (native Git bash) must pass; `git status --porcelain vendor/` must be empty; the consuming build/gate must be re-run. Record all three on the issue (telemetry kind `evidence`).
