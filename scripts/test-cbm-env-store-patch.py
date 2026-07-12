#!/usr/bin/env python3
"""Self-test for the CBM store-resolution overlay (#240/#241).

Verifies patches/cbm/env_apply_store_patch.py against the live pinned CBM sources:
  * every declared source hash still matches (the pin has not silently moved);
  * every reviewed edit applies with its expected occurrence count and changes
    the source (the patch is load-bearing);
  * the overlay is idempotent-safe — re-hashing a patched source no longer
    matches, so a double-apply fails closed;
  * the fail-closed properties the overlay must introduce are actually present
    (truncation detection in cbm_safe_getenv, an override consult in
    cbm_resolve_cache_dir, and NULL checks at the previously-unchecked sites);
  * the C header/impl and the Rust bridge agree on the store-path capacity.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CBM_ROOT = ROOT / "vendor" / "codebase-memory-mcp"
PATCH = ROOT / "patches" / "cbm" / "env_apply_store_patch.py"
CONFIG_C = ROOT / "patches" / "cbm" / "env_store_config.c"
CONFIG_H = ROOT / "patches" / "cbm" / "env_store_config.h"
BRIDGE = ROOT / "crates" / "astrolabe-bridge" / "src" / "lib.rs"
CONSTANTS = CBM_ROOT / "src" / "foundation" / "constants.h"


def load_patch_module():
    spec = importlib.util.spec_from_file_location("env_apply_store_patch", PATCH)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def expect(cond: bool, msg: str) -> None:
    if not cond:
        print(f"FAIL: {msg}", file=sys.stderr)
        raise SystemExit(1)
    print(f"ok: {msg}")


def main() -> None:
    if not CBM_ROOT.is_dir():
        print("SKIP: vendored CBM tree absent", file=sys.stderr)
        raise SystemExit(1)

    mod = load_patch_module()

    patched_by_file: dict[str, str] = {}
    for relative in mod.PATCHED_FILES:
        source = (CBM_ROOT / relative).read_text(encoding="utf-8")
        patched = mod.patch_source(relative, source)
        patched_by_file[relative] = patched
        expect(patched != source, f"{relative}: overlay changes the source (load-bearing)")

        # Double-apply must fail closed: the hash of the patched text no longer
        # matches the pin, so re-patching raises rather than corrupting.
        try:
            mod.patch_source(relative, patched)
        except ValueError:
            print(f"ok: {relative}: re-applying the overlay fails closed")
        else:
            print(f"FAIL: {relative}: overlay is not idempotent-safe", file=sys.stderr)
            raise SystemExit(1)

    platform = patched_by_file["src/foundation/platform.c"]
    expect(
        '#include "env_store_config.h"' in platform,
        "platform.c includes the Astrolabe store-config header",
    )
    expect(
        "cbm_astro_env_record_truncation" in platform,
        "platform.c cbm_safe_getenv records a truncation fault",
    )
    expect(
        "cbm_astro_cache_dir_override" in platform,
        "platform.c cbm_resolve_cache_dir consults the FFI override first (#240)",
    )
    expect(
        "cbm_astro_env_record_unresolvable_store" in platform,
        "platform.c cbm_resolve_cache_dir names the unresolvable-store fault (#241)",
    )
    expect(
        platform.count("char tmp[CBM_SZ_256]") == 0,
        "platform.c no longer reads env values into a 256-byte scratch buffer",
    )

    pipeline = patched_by_file["src/pipeline/pipeline.c"]
    expect(
        "if (!cache_dir) {" in pipeline and "free(path);" in pipeline,
        "pipeline.c resolve_db_path NULL-checks cbm_resolve_cache_dir (#241)",
    )

    http = patched_by_file["src/ui/http_server.c"]
    expect(
        "if (resolved) {" in http,
        "http_server.c handle_ui_config NULL-checks the resolver (#241)",
    )

    # Capacity agreement across the C header, the C impl static_assert, and Rust.
    declared = None
    for line in CONSTANTS.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("CBM_SZ_1K = "):
            declared = int(stripped[len("CBM_SZ_1K = "):].rstrip(","))
            break
    expect(declared is not None, "constants.h declares CBM_SZ_1K")
    header = CONFIG_H.read_text(encoding="utf-8")
    expect(
        f"#define CBM_ASTRO_STORE_PATH_CAP {declared}" in header,
        f"env_store_config.h caps the store path at CBM_SZ_1K ({declared})",
    )
    impl = CONFIG_C.read_text(encoding="utf-8")
    expect(
        "_Static_assert(CBM_ASTRO_STORE_PATH_CAP == CBM_SZ_1K" in impl,
        "env_store_config.c compile-asserts the capacity equals CBM_SZ_1K",
    )
    bridge = BRIDGE.read_text(encoding="utf-8")
    expect(
        f"const CBM_STORE_PATH_CAPACITY: usize = {declared};" in bridge,
        f"astrolabe-bridge CBM_STORE_PATH_CAPACITY tracks CBM_SZ_1K ({declared})",
    )

    print("test-cbm-env-store-patch: all cases passed")


if __name__ == "__main__":
    main()
