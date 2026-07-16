set -e
cargo clippy --manifest-path calyx/Cargo.toml -p calyx-cli -- -D warnings 2>&1 | tail -2
cargo build --manifest-path calyx/Cargo.toml -p calyx-cli 2>&1 | tail -2
DEST="/c/Users/hotra/AppData/Local/Temp/claude/C--code-Astrolabe/098f3fa2-b5b3-42fd-8025-916181872161/scratchpad/wave22/input-store"
cp calyx/target/debug/calyx.exe "$DEST/calyx.exe"
echo "PROVENANCE commit=$(git rev-parse HEAD)"
sha256sum "$DEST/calyx.exe"
