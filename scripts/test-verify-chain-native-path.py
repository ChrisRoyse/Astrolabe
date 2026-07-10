#!/usr/bin/env python3
"""Guard native-path handling in the Git Bash verify-chain gate."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check-astrolabe-verify-chain.sh"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"verify-chain native path contract failed: {message}")


def main() -> None:
    text = SCRIPT.read_text(encoding="utf-8")

    require(
        "native_path()" in text
        and 'MINGW*|MSYS*|CYGWIN*' in text
        and 'cygpath -m "$1"' in text,
        "the gate must convert Git Bash paths to Windows mixed paths",
    )
    require(
        'native_vault_dir="$(native_path "$vault_dir")"' in text
        and 'native_out_dir="$(native_path "$out_dir")"' in text,
        "native-bound fixture and result paths must be normalized once",
    )
    require(
        '"$native_vault_dir" "$vault_id" "$vault_salt"' in text,
        "the native fixture builder must receive the normalized vault path",
    )
    require(
        "printf '{\"vault\":\"%s\"}' \"$native_vault_dir\"" in text,
        "stdin JSON must contain the normalized vault path",
    )
    require(
        '--vault "$native_vault_dir"' in text,
        "the native deep verifier must receive the normalized vault path",
    )
    require(
        '"$native_out_dir/verify-chain.json" "$native_out_dir/verify-deep.json"' in text,
        "the native Python reader must receive normalized result paths",
    )

    print("verify-chain native path contract passed")


if __name__ == "__main__":
    main()
