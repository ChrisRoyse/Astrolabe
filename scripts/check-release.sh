#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TARGET_CLEANUP_OWNER="${ASTROLABE_TARGET_CLEANUP_OWNER:-check-release}"
if [[ "$TARGET_CLEANUP_OWNER" != "check-release" ]]; then
  echo "ERROR: invalid ASTROLABE_TARGET_CLEANUP_OWNER: $TARGET_CLEANUP_OWNER" >&2
  exit 2
fi

cleanup_target() {
  local status=$?
  if ! bash "$ROOT/scripts/clean-target.sh"; then
    return 1
  fi
  return "$status"
}
bash "$ROOT/scripts/clean-target.sh"
trap cleanup_target EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if command -v python >/dev/null 2>&1; then
  PYTHON_BIN="python"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="python3"
else
  echo "ERROR: python not found" >&2
  exit 1
fi

# #280 (owner directive 2026-07-12): check-release is the UNABRIDGED tier. It
# defeats both fail-closed fast-path gates — every suite runs regardless of the
# impact fingerprints (ASTRO_SUITE_GATE=all) and every gate-tooling self-test
# runs regardless of the change-gate manifest (ASTRO_GATE_SELFTESTS=all) — and
# it owns the non-test phases tiered out of check-full: the CBM static
# analysis (ci-cbm-lint.sh) and the full Rust lint/doc/Calyx gate
# (ci-rust-gate.sh).
export ASTRO_SUITE_GATE=all
export ASTRO_GATE_SELFTESTS=all
ASTROLABE_TARGET_CLEANUP_OWNER=check-release bash scripts/check-full.sh

# Native label + host derivation for the tiered phases (mirrors check-full.sh).
RUSTC_HOST="$(rustc -vV | sed -n 's/^host: //p')"
HOST_TARGET="${ASTROLABE_RUST_TARGET:-$RUSTC_HOST}"
case "$HOST_TARGET" in
  x86_64-pc-windows-gnu) DEFAULT_LABEL="windows-x64-mingw" ;;
  x86_64-unknown-linux-gnu)
    case "${CC:-cc}" in
      *clang*) DEFAULT_LABEL="linux-x64-clang" ;;
      *) DEFAULT_LABEL="linux-x64-gcc" ;;
    esac
    ;;
  aarch64-apple-darwin) DEFAULT_LABEL="macos-arm64-clang" ;;
  *) DEFAULT_LABEL="local-$HOST_TARGET" ;;
esac
LABEL="${ASTROLABE_CHECK_LABEL:-$DEFAULT_LABEL}"

bash scripts/ci-cbm-lint.sh
bash scripts/ci-rust-gate.sh "$LABEL" "$HOST_TARGET"

# #63/#283: the SHIPPED release artifact is the grammar-subset (`core`) variant.
# Rationale (recorded decision): the full grammar set (157 tree-sitter shims,
# ~1.19 GiB of static const parse tables) makes the release binary ~263 MiB,
# ~113 MiB over the #63 150 MiB gate; the parse tables are const data, immune to
# LTO/strip/opt-level. `core` compiles only CBM_GRAMMAR_CORE_LANGS and links
# grammar_stubs.c, which fails CLOSED on any dropped language with a labeled
# {code,message,remediation} CBM_GRAMMAR_STUBBED error naming the knob (never a
# silent parse miss) — satisfying the HONEST "no silent fallback" invariant, so
# core-by-default in the shipped artifact is acceptable. This is scoped to the
# release build ONLY: the Makefile default stays `full`, so check-full.sh above
# (workspace tests + the CBM C suite) exercised every grammar with no coverage
# loss. Switching the knob re-enters the libcbm config stamp (build.rs), forcing
# a grammar-object rebuild here regardless of any warm objects from check-full.
CBM_GRAMMAR_SET=core cargo build --workspace --release
"$PYTHON_BIN" scripts/check-binary-size.py
# #291: byte-level proof that the shipped release binaries carry no test-only
# failpoint marker (e.g. the calyx-aster crash-fsv env var). Runs on the real
# artifacts built just above, before the release predicate.
"$PYTHON_BIN" scripts/check-release-failpoint-strings.py
bash "$ROOT/scripts/release-predicate.sh" "$@"
