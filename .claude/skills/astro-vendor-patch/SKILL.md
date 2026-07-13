---
name: astro-vendor-patch
description: RETIRED (#286). The vendoring doctrine is dissolved — calyx/ and cbm/ are owned first-class source, edited in place. There is no pin, no patch applier, and no hash-checked overlay. Use when tempted to reach for pins/overlays/verify-pins for a CBM or Calyx change.
---

# Vendor-patch skill — RETIRED (#286)

The vendoring doctrine this skill described is **gone** (owner directive
2026-07-12, EPIC #286). `calyx/` and `cbm/` are now
this project's own first-class source: edited directly, evolved in place, on a
stable base this project fully controls. External churn in the origin repos is
irrelevant.

There is **no** pin file (`VENDORED.md` deleted), **no** `scripts/verify-pins.sh`
(deleted), and **no** `patches/cbm` applier / `astro_overlay.py` / hash-checked
overlay (deleted). Do not reach for any of them.

## What to do instead

- **Changing CBM C** (`cbm/`): edit the `.c`/`.h`
  directly. If a change must NOT reach every build artifact, guard it with an
  `ASTRO_*` macro and wire the flag in `patches/cbm/Makefile.cbm`
  (`LIBCBM_ASTRO_DEFS` for libcbm, `ASTRO_PROD_DEFS` for the production
  binaries). Update `scripts/test-cbm-overlay-sources.py` to guard the new
  behavior. See `patches/cbm/README.md`.
- **Changing Calyx** (`calyx/`): edit it as normal owned Rust source with
  normal review and tests.
- **Astrolabe glue** still lives in `patches/cbm/` (`Makefile.cbm`,
  `astro_spawn.{c,h}`, `env_store_config.{c,h}`, `astro_alloc_shim.c`,
  `astro_layout_probe.c`) and `crates/cbm-sys/build.rs`.

Doctrine of record: EPIC #286. Phase B relocated the parent trees out of
`vendor/` to top-level `calyx/` and `cbm/`; `patches/cbm/` remains the home of
the Astrolabe-owned libcbm build glue.
