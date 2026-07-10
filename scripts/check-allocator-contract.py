#!/usr/bin/env python3
"""Guard Astrolabe's platform-specific allocator topology contract."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"allocator topology contract failed: {message}")


def normalized(text: str) -> str:
    return " ".join(text.split())


def main() -> None:
    allocator_doc = (ROOT / "docs" / "allocator.md").read_text(encoding="utf-8")
    blueprint = (ROOT / "docs" / "astrolabe-blueprint.md").read_text(encoding="utf-8")
    makefile = (ROOT / "patches" / "cbm" / "Makefile.cbm").read_text(encoding="utf-8")
    rust = (ROOT / "crates" / "cbm-sys" / "src" / "lib.rs").read_text(
        encoding="utf-8"
    )
    cbm = (
        ROOT / "vendor" / "codebase-memory-mcp" / "internal" / "cbm" / "cbm.c"
    ).read_text(encoding="utf-8")
    memory = (
        ROOT / "vendor" / "codebase-memory-mcp" / "src" / "foundation" / "mem.c"
    ).read_text(encoding="utf-8")
    single_gate = (ROOT / "scripts" / "check-single-mimalloc.sh").read_text(
        encoding="utf-8"
    )
    cargo_contract = "\n".join(
        path.read_text(encoding="utf-8")
        for path in [ROOT / "Cargo.toml", ROOT / "Cargo.lock"]
        + sorted((ROOT / "crates").glob("*/Cargo.toml"))
    ).lower()
    allocator_words = normalized(allocator_doc)
    blueprint_words = normalized(blueprint)

    for marker in (
        "exactly one mimalloc implementation",
        "Ordinary CBM C allocations continue to use libc",
        "mi_process_info` heap/commit counters do not account for those libc allocations",
        "Process-wide pressure uses `cbm_mem_rss()` with OS RSS",
        "Ownership remains explicit",
    ):
        require(marker in allocator_words, f"docs/allocator.md is missing {marker!r}")

    for stale_claim in (
        "single production allocator implementation for the CBM and Rust halves",
        "one heap, one RSS accounting",
        "one allocator, one budget",
        "both on mimalloc",
        "mimalloc unified as the global allocator for both C and Rust halves",
    ):
        require(
            stale_claim not in allocator_words and stale_claim not in blueprint_words,
            f"stale universal-heap claim remains: {stale_claim!r}",
        )

    override_block = "\n".join(
        [
            "MIMALLOC_OVERRIDE_DEFINE :=",
            "ifeq ($(IS_MINGW),yes)",
            "MIMALLOC_OVERRIDE_DEFINE := -DMI_MALLOC_OVERRIDE=1",
            "endif",
        ]
    )
    require(override_block in makefile, "MI_MALLOC_OVERRIDE must remain MinGW-only")
    require(
        makefile.count("-DMI_MALLOC_OVERRIDE=1") == 1,
        "exactly one conditional MI_MALLOC_OVERRIDE definition is allowed",
    )
    require(
        "-DCBM_BIND_TS_ALLOCATOR=1" in makefile,
        "production tree-sitter/SQLite allocator binding must remain enabled",
    )
    require(
        "ts_set_allocator(mi_malloc, mi_calloc, mi_realloc, mi_free);" in cbm
        and "sqlite3_config(SQLITE_CONFIG_MALLOC" in cbm,
        "cbm_alloc_init must bind tree-sitter and SQLite to mimalloc",
    )
    require(
        "size_t proc_rss = os_rss();" in memory
        and "size_t rss = cbm_mem_rss();" in memory,
        "memory pressure must retain process-RSS accounting",
    )

    require("#[global_allocator]" in rust, "Rust global allocator is missing")
    for shim in (
        "cbm_mimalloc_malloc_aligned",
        "cbm_mimalloc_zalloc_aligned",
        "cbm_mimalloc_realloc_aligned",
        "cbm_mimalloc_free",
    ):
        require(shim in rust, f"Rust global allocator is missing shim {shim}")
    require(
        "mimalloc" not in cargo_contract,
        "Cargo manifests/lock must not add a second Rust mimalloc dependency",
    )

    require(
        "one vendored mimalloc implementation and one CBM shim surface verified; "
        "allocator routing is platform-specific" in single_gate,
        "check-single-mimalloc.sh must state only the property it proves",
    )

    print("allocator topology contract verified")


if __name__ == "__main__":
    main()
