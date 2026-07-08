#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if command -v python >/dev/null 2>&1; then
  PYTHON_BIN="python"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="python3"
else
  echo "ERROR: python not found" >&2
  exit 1
fi

target_args=()
target_dir="$ROOT/target/debug"
if [[ -n "${ASTROLABE_RUST_TARGET:-}" ]]; then
  target_args=(--target "$ASTROLABE_RUST_TARGET")
  target_dir="$ROOT/target/$ASTROLABE_RUST_TARGET/debug"
fi

bin="${1:-$target_dir/astrolabe}"
if [[ ! -x "$bin" && -x "$bin.exe" ]]; then
  bin="$bin.exe"
fi

cargo build -p astrolabe-server --bin astrolabe "${target_args[@]}"
if [[ ! -x "$bin" ]]; then
  echo "ERROR: astrolabe binary not found or not executable: $bin" >&2
  exit 1
fi

vault_id="${ASTROLABE_VERIFY_CHAIN_VAULT_ID:-01ARZ3NDEKTSV4RRFFQ69G5FAV}"
vault_salt="${ASTROLABE_VERIFY_CHAIN_VAULT_SALT:-astrolabe-verify-chain-ci-salt}"
vault_dir="${ASTROLABE_VERIFY_CHAIN_VAULT:-$ROOT/target/astrolabe-verify-chain-vault}"
out_dir="${ASTROLABE_VERIFY_CHAIN_OUT:-$ROOT/target/astrolabe-verify-chain}"

rm -rf "$vault_dir" "$out_dir"
mkdir -p "$vault_dir" "$out_dir"

cargo run -p astrolabe-ingest --example build_verify_fixture "${target_args[@]}" -- \
  "$vault_dir" "$vault_id" "$vault_salt" > "$out_dir/build.txt"

printf '{"vault":"%s"}' "$vault_dir" | "$bin" cli verify_chain > "$out_dir/verify-chain.txt"
printf '{"vault":"%s"}' "$vault_dir" | "$bin" cli --json verify_chain > "$out_dir/verify-chain.json"
"$bin" verify --json --deep --vault "$vault_dir" --vault-id "$vault_id" --vault-salt "$vault_salt" \
  > "$out_dir/verify-deep.json"

"$PYTHON_BIN" - "$out_dir/verify-chain.json" "$out_dir/verify-deep.json" <<'PY'
import json
import sys

chain = json.load(open(sys.argv[1], encoding="utf-8"))
deep = json.load(open(sys.argv[2], encoding="utf-8"))

if chain.get("status") != "intact" or chain.get("ledger_rows") != 1:
    raise SystemExit(f"verify_chain did not prove the fixture ledger: {chain}")
if deep.get("ledger_chain_status") != "intact" or deep.get("ledger_rows") != 1:
    raise SystemExit(f"verify --deep did not include ledger proof: {deep}")
if deep.get("ledger_payload_rows") != 1:
    raise SystemExit(f"verify --deep did not redaction-check the ledger payload: {deep}")
PY

cat "$out_dir/verify-chain.txt"
