#!/usr/bin/env bash
# Tier-0 inner-loop gate: verify ONLY the change's blast radius, fast, on a warm
# target/. Pairs with scripts/check-fast-select.py (blast-radius crate selection,
# FSV-verified) and the #264 .config/nextest.toml `fast` profile.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Base to diff against (what this change will merge into). Override via arg or env.
BASE="${1:-${ASTROLABE_FAST_BASE:-main}}"

# Inner-loop caching: WARM target/ (never wiped here — that is a session/boundary
# concern, per CLAUDE.md "Fast feedback loops"), incremental ON, sccache OFF
# (sccache + CARGO_INCREMENTAL conflict; the inner loop wants incremental reuse).
export CARGO_INCREMENTAL=1
unset RUSTC_WRAPPER SCCACHE_DIR 2>/dev/null || true

# Python for the selector.
if command -v python3 >/dev/null 2>&1; then PY=python3; elif command -v python >/dev/null 2>&1; then PY=python; else
  echo "ERROR[ASTRO_FASTGATE_NO_PYTHON]: python not found" >&2; exit 127; fi

# Changed files vs BASE: committed-since-base (two-dot incl. uncommitted) + untracked,
# repo-relative forward-slash, de-duplicated.
mapfile -t CHANGED < <(
  { git diff --name-only "$BASE" 2>/dev/null || true; \
    git ls-files --others --exclude-standard 2>/dev/null || true; } | sort -u
)

# Blast-radius selection. The selector fails closed with {code,message,remediation}
# and a distinct exit code: 3 no-changes, 4 unmapped, 10 foundational->Tier 2.
set +e
SELECT="$(cargo metadata --format-version 1 --no-deps 2>/dev/null | "$PY" scripts/check-fast-select.py "${CHANGED[@]}")"
rc=$?
set -e
if [[ $rc -ne 0 ]]; then
  # selector already printed the fail-closed envelope to stderr; propagate its code.
  # 10 = foundational surface -> the operator must run the full native aggregate.
  exit $rc
fi

read -ra PKGS <<< "$SELECT"   # e.g. -p astrolabe-panel -p astrolabe-weave
if [[ ${#PKGS[@]} -eq 0 ]]; then
  echo "ERROR[ASTRO_FASTGATE_EMPTY_SELECTION]: selector returned no packages" >&2
  echo "  remediation: this is a bug in check-fast-select.py; do not treat as pass" >&2
  exit 5
fi

echo "=== Tier-0 check-fast (base=$BASE): ${SELECT} ==="
t0=$(date +%s)
cargo check --all-targets "${PKGS[@]}"
cargo clippy "${PKGS[@]}" --all-targets -- -D warnings
cargo nextest run --profile fast "${PKGS[@]}"

# Format only the changed .rs files (fast; full-workspace fmt is a Tier-1/2 concern).
RS_CHANGED=()
for f in "${CHANGED[@]}"; do [[ "$f" == *.rs && -f "$f" ]] && RS_CHANGED+=("$f"); done
if [[ ${#RS_CHANGED[@]} -gt 0 ]]; then
  rustfmt --edition 2024 --check "${RS_CHANGED[@]}"
fi

echo "=== Tier-0 PASS in $(( $(date +%s) - t0 ))s :: covered ${SELECT} ==="
echo "NOTE: Tier-0 covers this change's blast radius only. Foundational changes and"
echo "      pre-merge-to-main still require the full native aggregate (Tier 2)."
