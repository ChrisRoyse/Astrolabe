set -e
echo "=== clippy calyx ==="
cargo clippy --manifest-path calyx/Cargo.toml -p calyx-aster -p calyx-cli -- -D warnings 2>&1 | tail -5
echo "=== clippy astrolabe-ingest ==="
cargo clippy -p astrolabe-ingest -- -D warnings 2>&1 | tail -5
echo "=== fmt check ==="
python scripts/native-cargo-fmt.py --all -- --check 2>&1 | tail -5
echo "=== build calyx binary ==="
cargo build --manifest-path calyx/Cargo.toml -p calyx-cli 2>&1 | tail -3
DEST="/c/Users/hotra/AppData/Local/Temp/claude/C--code-Astrolabe/098f3fa2-b5b3-42fd-8025-916181872161/scratchpad/wave22/input-store"
mkdir -p "$DEST"
cp calyx/target/debug/calyx.exe "$DEST/calyx.exe" 2>/dev/null || cp target/debug/calyx.exe "$DEST/calyx.exe"
ls -la "$DEST"
echo "=== tree provenance ==="
git rev-parse HEAD
sha256sum "$DEST/calyx.exe"
