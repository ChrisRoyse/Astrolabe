# patches/calyx — upstream-pending reference (ASTROLABE #260)

> **This is NOT a build overlay.** Unlike `patches/cbm/` (whose `apply_*.py`
> materialize a hash-checked temporary overlay consumed by `cbm-sys/build.rs`
> at link time), Calyx is compiled **directly** from `vendor/calyx`. There is no
> Calyx overlay-materialization step, and none should be added for **test**
> hygiene: patching vendored test files would diverge the pin for non-shipping
> code — the anti-pattern #260 explicitly names. The correct fix is **upstream
> in `ChrisRoyse/Calyx`**, followed by a `vendor/calyx` pin bump.
>
> This directory carries the **reference implementation + proof** for that
> upstream change so it can be applied and re-pinned deliberately. It changes
> nothing in `vendor/` and is invisible to the build.

## The defect (#260)

Every Calyx FSV/test helper resolves a scratch root via
`std::env::temp_dir().join(format!("{prefix}-{pid}…"))` and **never removes the
directory on the panic / early-return path**. Representative sites:

- `crates/calyx-aster/tests/fsv_support/mod.rs:57-60` (`temp_root`) — the helper
  that produced the leaked `calyx-aster-issue2011-physical-residue-<pid>` dir in
  the flaky aggregate.
- `crates/calyx-aster/src/supply_chain/tests.rs:10-18` & `:112` — `temp_file` /
  `missing_weights_file_fails_closed`.
- `crates/calyx-testkit/src/lib.rs:19-27` (`fsv::fsv_root`) — the shared helper.

### Census (this pin, `6e0e344`)

| metric | value |
|---|---|
| `env::temp_dir()` occurrences | **495** |
| files | **412** |
| crates | **24** |
| distinct `calyx-*` scratch prefixes | dozens (`calyx-vault`, `calyx-web-api`, `calyx-mcp-test`, `calyx-cli-vault`, …) |

This scale is why the fix is upstream-only: it is a workspace-wide convention,
not a handful of edits.

## Env-inheritance audit (asked for by #260)

- **Which key gates the fallback?** A **per-suite** evidence-root env var (e.g.
  the calyx-aster suite's own key), resolved through
  `calyx_fsv::fsv_root(env_key)` / `env_fsv_root` (`crates/calyx-fsv/src/lib.rs`).
  It is **not** `CALYX_FSV_ROOT`; Calyx's own `scripts/check.sh:54-58`
  deliberately **refuses** a suite-wide `CALYX_FSV_ROOT` (collides — Calyx
  #1014), so every suite owns its root and the fallback is the *normal* path
  under a bare `cargo nextest run`.
- **Unset-key behavior today:** silent litter. `env_key` unset →
  `std::env::temp_dir().join("{prefix}-{pid}")` created, written, and **never
  removed** on panic/early-return. Proven below.
- **`env::temp_dir()` honors `TMP`/`TEMP`/`TMPDIR`** on Windows (GetTempPath2W),
  so the Astrolabe #246 redirect contains it *only while a process actually
  inherits that env*. A spawned child or a phase outside the redirect window
  leaks into the operator's real `%TEMP%` and trips the #237 no-escape gate —
  the intermittent aggregate RED (#278 attribution). **Containment must not
  depend on TMP redirection** — #260's thesis, confirmed.
- **Calyx's own containment is harness-level and Unix-only.**
  `scripts/tmp_scratch_guard.sh` does a pre/post `/tmp` sweep (`df -Pi`,
  `stat -c`, `id -u`) wired from `check.sh`. It does **not** run on Windows and
  is not RAII — exactly the "hygiene depends on the harness" coupling #260
  eliminates.

## The fix — `scratch_dir.rs` (std-only RAII)

`scratch_dir.rs` is the drop-in module for `crates/calyx-fsv/src/`. Design:

- **std-only** — Calyx depends on `tempfile` in **zero** crates; the fix must
  not add it. `Drop` calls `std::fs::remove_dir_all`.
- **`ScratchDir`** removes its dir on `Drop` — on normal return, on `?`/early
  return, and **while unwinding through a panic**.
- **`ScratchDir::keep()`** disarms cleanup for the operator-supplied evidence
  root (matches the existing `keep`-bool semantics).
- **`FsvScratch::resolve(env_key, prefix, name)`** is the RAII replacement for
  the `(PathBuf, keep_bool)` helpers: `Kept(PathBuf)` when the env key is set,
  `Owned(ScratchDir)` (self-cleaning) otherwise.
- **Boundary (honest):** `Drop` does **not** run on `SIGKILL`/`abort()`/launcher
  hard-timeout. This closes the panic/early-return path (the intermittent one);
  the hard-kill residual stays covered by the harness process-boundary sandbox
  (#246) or the suite sweep.

### Call-site conversion pattern

```rust
// BEFORE (leaks on panic):
let dir = fsv_support::temp_root("calyx-aster", "issue2011-physical-residue");
fsv_support::reset_dir(&dir);
// … test body; on panic `dir` survives …

// AFTER (self-cleans on panic):
let scratch = calyx_fsv::scratch_dir::ScratchDir::new(
    &std::env::temp_dir(), "calyx-aster", "issue2011-physical-residue")?;
let dir = scratch.path();            // borrow for the test lifetime
// … test body; `scratch` drops (removes `dir`) on any exit incl. panic …
```

For the env-gated helpers, replace `(PathBuf, bool)` returns with
`FsvScratch::resolve(env_key, prefix, name)?` and hold the value.

## Proof (FSV — `scripts/test-calyx-fsv-raii-patch.py`)

Compiles the **shipped** `scratch_dir.rs` against a faithful copy of the current
leak pattern with the pinned `rustc`, runs both under a sandboxed `TMP`, and
reads the filesystem back:

```
rustc: rustc 1.95.0
case1_leaks=true            # current pattern survives the panic  (defect)
case2_selfcleans=true       # ScratchDir removed on the panic path (fix)
readback case1 (expect leak) : ['calyx-aster-issue2011-physical-residue-…-0']
readback case2 (expect empty): []
PASS[ASTRO_CALYX_RAII_SELFTEST]
```

The self-test also fails closed if the guard ever *uses* `tempfile`, loses its
`Drop` impl, or if an enumerated producer disappears (census drift).

## Applying upstream + re-pinning (deliberate, out-of-band)

The two DoD-closing steps require access this repo cannot perform from a
worktree (push to `ChrisRoyse/Calyx`; a real subtree pull). Procedure:

1. In the standalone `Calyx` checkout: add `crates/calyx-fsv/src/scratch_dir.rs`
   (this module), `pub mod scratch_dir;` in `calyx-fsv/src/lib.rs`, and convert
   the enumerated producers (then the remaining 412 files mechanically) to hold
   a `ScratchDir`/`FsvScratch`. `cargo nextest run` per crate; confirm `%TEMP%`
   gains no `calyx-*` entries after a suite that panics.
2. Commit upstream; then in Astrolabe follow `VENDORED.md` §Update Procedure:
   subtree pull → `git add vendor/calyx` → refresh the tree SHA in `VENDORED.md`
   → `bash scripts/verify-pins.sh` clean.

Until then the leak is **mitigated** in Astrolabe (the #246 process-boundary
sandbox contains it; #278 attributes any escape) but **not fixed at the source**.
