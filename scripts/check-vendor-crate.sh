#!/usr/bin/env bash
# scripts/check-vendor-crate.sh — targeted `cargo check --all-targets` for a crate
# that lives in the vendored calyx workspace, run from the canonical root (#298).
#
# Why this exists: vendor/calyx is a SEPARATE, excluded workspace (root Cargo.toml
# `exclude`). Astrolabe reaches the calyx crates only as path-dependencies, so
# their dev-dependencies (proptest, blake3, …) are pruned from the root graph.
# A bare `cargo check -p calyx-ward --all-targets` from the root therefore fails
# closed with `unresolved module or unlinked crate proptest` when it tries to
# build the crate's test targets. The correct targeted invocation resolves the
# crate against its OWNING workspace via `--manifest-path`; this helper wraps that
# so blast-radius checks against vendored crates are runnable from `C:\code\Astrolabe`.
#
# Usage:
#   scripts/check-vendor-crate.sh <crate> [extra cargo args...]
# Examples:
#   scripts/check-vendor-crate.sh calyx-ward
#   scripts/check-vendor-crate.sh calyx-registry --features ml-runtime
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

CALYX_MANIFEST="vendor/calyx/Cargo.toml"

if [[ $# -lt 1 ]]; then
  echo "ERROR[ASTRO_VENDOR_CHECK_NO_CRATE]: no crate given" >&2
  echo "  message: a vendored-calyx crate name is required" >&2
  echo "  remediation: run 'scripts/check-vendor-crate.sh <crate> [extra cargo args...]'," \
       "e.g. 'scripts/check-vendor-crate.sh calyx-ward'" >&2
  exit 2
fi

CRATE="$1"
shift

if [[ ! -f "$CALYX_MANIFEST" ]]; then
  echo "ERROR[ASTRO_VENDOR_CHECK_NO_MANIFEST]: $CALYX_MANIFEST not found" >&2
  echo "  message: the vendored calyx workspace manifest is missing" >&2
  echo "  remediation: run from the canonical workspace root (C:\\code\\Astrolabe)" >&2
  exit 2
fi

# Confirm the crate is a member of the calyx workspace; fail closed otherwise so a
# typo or an Astrolabe-workspace crate does not silently fall through.
if ! grep -q "^name = \"$CRATE\"$" "vendor/calyx/crates/$CRATE/Cargo.toml" 2>/dev/null; then
  echo "ERROR[ASTRO_VENDOR_CHECK_UNKNOWN_CRATE]: '$CRATE' is not a vendor/calyx crate" >&2
  echo "  message: no vendor/calyx/crates/$CRATE/Cargo.toml declaring package '$CRATE'" >&2
  echo "  remediation: for an Astrolabe-workspace crate use plain 'cargo check -p <crate>" \
       "--all-targets'; this helper is only for crates under vendor/calyx/crates/" >&2
  exit 2
fi

echo "INFO[ASTRO_VENDOR_CHECK]: cargo check -p $CRATE --all-targets --manifest-path $CALYX_MANIFEST $*"
exec cargo check -p "$CRATE" --all-targets --manifest-path "$CALYX_MANIFEST" "$@"
