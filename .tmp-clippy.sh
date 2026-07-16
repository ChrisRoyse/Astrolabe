set -o pipefail
cargo clippy --manifest-path calyx/Cargo.toml -p calyx-aster -p calyx-cli -- -D warnings > /c/Users/hotra/AppData/Local/Temp/claude/C--code-Astrolabe/098f3fa2-b5b3-42fd-8025-916181872161/scratchpad/wave22/input-store/clippy.log 2>&1
echo "CLIPPY_EXIT=$?"
