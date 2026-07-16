set -e
set -o pipefail
S="/c/Users/hotra/AppData/Local/Temp/claude/C--code-Astrolabe/098f3fa2-b5b3-42fd-8025-916181872161/scratchpad/wave22/input-store"
cargo clippy --manifest-path calyx/Cargo.toml -p calyx-aster -p calyx-cli -- -D warnings > "$S/clippy.log" 2>&1
echo "CLIPPY_CALYX=OK"
cargo clippy -p astrolabe-ingest -- -D warnings > "$S/clippy2.log" 2>&1
echo "CLIPPY_INGEST=OK"
python scripts/native-cargo-fmt.py --all -- --check > "$S/fmt.log" 2>&1
echo "FMT=OK"
cargo build --manifest-path calyx/Cargo.toml -p calyx-cli > "$S/build.log" 2>&1
cp calyx/target/debug/calyx.exe "$S/calyx.exe"
echo "PROVENANCE commit=$(git rev-parse HEAD)"
sha256sum "$S/calyx.exe"
