#!/usr/bin/env python3
"""Guard the bounded, shell-safe native Windows libcbm build contract."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BUILD_RS = ROOT / "crates" / "cbm-sys" / "build.rs"
MAKEFILE = ROOT / "patches" / "cbm" / "Makefile.cbm"
MEM_C = ROOT / "vendor" / "codebase-memory-mcp" / "src" / "foundation" / "mem.c"
LAYOUT_PROBE = ROOT / "patches" / "cbm" / "astro_layout_probe.c"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"native Windows libcbm build contract failed: {message}")


def main() -> None:
    build_rs = BUILD_RS.read_text(encoding="utf-8")
    makefile = MAKEFILE.read_text(encoding="utf-8")
    mem_c = MEM_C.read_text(encoding="utf-8")

    require(LAYOUT_PROBE.is_file(), "the native C ABI layout probe must be present")

    require(
        '.arg(make_path(patched_makefile))' in build_rs,
        "cbm-sys must normalize the Makefile path before invoking GNU Make",
    )
    require(
        'format!("BUILD_DIR={}", make_path(build_dir))' in build_rs,
        "cbm-sys must normalize BUILD_DIR before exposing it to shell recipes",
    )
    require(
        '"LIBCBM_CONFIG_STAMP={}"' in build_rs
        and "make_path(config_stamp)" in build_rs,
        "cbm-sys must pass a normalized build-configuration stamp to GNU Make",
    )
    require(
        "value.replace('\\\\', \"/\")" in build_rs,
        "the Windows Make path conversion must replace backslashes",
    )
    require(
        "fn make_command_path(value: &str) -> String" in build_rs,
        "Make-facing executable overrides must use the shared path conversion",
    )
    for variable, local in [
        ("CC", "cc"),
        ("CXX", "cxx"),
        ("AR", "ar"),
        ("LD", "ld"),
        ("NM", "nm"),
        ("OBJCOPY", "objcopy"),
    ]:
        require(
            f'format!("{variable}={{}}", make_command_path(&{local}))' in build_rs,
            f"{variable} must be normalized before GNU Make receives it",
        )
    # #192 narrowed the rerun-if surface: the (now owned, #286) CBM trees are
    # deliberately NOT watched file-by-file. The Makefile and the Astrolabe glue
    # TUs are watched; within one build the Make depfiles + config stamp own
    # incremental correctness. Statements are split on ';' so multi-line println!
    # calls are evaluated whole.
    statements = build_rs.split(";")
    stale_tree_watches = [
        statement.strip()
        for statement in statements
        if "rerun-if-changed" in statement
        and any(
            f'join("{tree}")' in statement
            for tree in ("src", "internal/cbm", "vendored")
        )
    ]
    require(
        not stale_tree_watches,
        "the pinned CBM trees must not be watched file-by-file "
        f"(#192 rerun-if narrowing): {stale_tree_watches}",
    )
    require(
        "remove_dir_all" not in build_rs,
        "cbm-sys must preserve its libcbm build directory across ordinary reruns",
    )
    require(
        "write_if_changed(&config_stamp, &config)" in build_rs,
        "the build-configuration stamp must preserve mtime when content is unchanged",
    )
    require(
        "libcbm_build_config(&config_inputs)" in build_rs
        and "&build_script," in build_rs
        and "&patched_makefile," in build_rs
        and "&env_store_config_src," in build_rs
        and "&env_store_config_hdr," in build_rs
        and "config_inputs.extend(spawn_overlays" in build_rs,
        "the configuration stamp must cover build.rs, Makefile.cbm, and the "
        "Astrolabe-owned glue TUs (env-store config + the #227/#228 spawn helper)",
    )
    # #286: the overlays are absorbed into the owned CBM sources; the only
    # patches/cbm build inputs left are the Astrolabe glue TUs. Each must be
    # watched AND folded into the config stamp, or a change to the git-spawn
    # helper / env-store config would not rebuild libcbm.a.
    for glue in (
        "astro_spawn.c",
        "astro_spawn.h",
        "env_store_config.c",
        "env_store_config.h",
    ):
        require(
            f'repo_root.join("patches/cbm/{glue}")' in build_rs,
            f"Cargo must rebuild when the Astrolabe glue TU {glue} changes",
        )
    require(
        "for spawn_overlay in &spawn_overlays" in build_rs
        and "cargo:rerun-if-changed={}" in build_rs,
        "every spawn helper input must emit a rerun-if-changed directive",
    )
    require(
        'let layout_probe = repo_root.join("patches/cbm/astro_layout_probe.c");' in build_rs
        and "layout_probe.display()" in build_rs,
        "Cargo must rebuild when the native C ABI layout probe changes",
    )
    # #192 collapsed the former double bindgen parse: one layout-test-bearing
    # parse feeds both consumers — the OUT_DIR layout-test include gets the
    # superset verbatim, and the committed-bindings diff strips the layout-test
    # functions before comparing.
    require(
        "fn write_layout_test_bindings(" in build_rs
        and "write_layout_test_bindings(&out_dir, &generated);" in build_rs
        and ".layout_tests(true)" in build_rs
        and "generate_bindings(&cbm_root, &header)" in build_rs
        and "build_support::strip_layout_tests(generated)" in build_rs,
        "cbm-sys must generate target-local bindgen layout assertions from the "
        "single shared parse (#192)",
    )
    require(
        '"TARGET"' in build_rs
        and '"PATH"' in build_rs
        and '"CBM_SYS_ASAN"' in build_rs
        and '"PYTHON"' in build_rs,
        "the configuration stamp must cover target, tool lookup, overlay execution, and ASan mode",
    )
    require(
        "LIBCBM_DEPFILES = $(LIBCBM_OBJS:.o=.d)" in makefile,
        "every libcbm object must map to a compiler depfile",
    )
    require(
        "LIBCBM_DEPFLAGS = -MMD -MP" in makefile,
        "libcbm compiles must emit transitive-header depfiles",
    )
    require(
        "ASTRO_LAYOUT_PROBE_SRC = $(ASTROLABE_PATCH_DIR)/astro_layout_probe.c" in makefile
        and "ASTRO_LAYOUT_PROBE_OBJ = $(LIBCBM_DIR)/astro_layout_probe.o" in makefile
        and "$(ASTRO_LAYOUT_PROBE_OBJ)" in makefile
        and "-I$(ASTRO_FFI_INCLUDE_DIR) -c -o $@ $<" in makefile,
        "libcbm must compile and retain the native C ABI layout probe",
    )
    require(
        "-include $(LIBCBM_DEPFILES)" in makefile,
        "GNU Make must include generated libcbm depfiles",
    )
    require(
        "$(LIBCBM_OBJS): $(LIBCBM_CONFIG_STAMP)" in makefile,
        "every libcbm object must depend on the build-configuration stamp",
    )
    require(
        "$(LIBCBM_DIR)/$(UNIXCODER_BLOB_SRC:.S=.o): $(UNIXCODER_BLOB_SRC) "
        "vendored/nomic/code_vectors.bin" in makefile,
        "the assembler depfile gap must be covered by an explicit blob prerequisite",
    )

    libcbm_section = makefile.split("# ── Static library for Astrolabe FFI", 1)[1]
    libcbm_section = libcbm_section.split("# ── Build with embedded UI", 1)[0]
    compile_lines = [
        line.strip()
        for line in libcbm_section.splitlines()
        if line.startswith("\t$(CC) ") or line.startswith("\t$(CXX) ")
        if " -c " in line
    ]
    require(compile_lines, "libcbm compile recipes must be discoverable")
    dep_aware_flags = (
        "$(LIBCBM_CFLAGS)",
        "$(LIBCBM_CXXFLAGS)",
        "$(LIBCBM_GRAMMAR_CFLAGS)",
        "$(LIBCBM_SQLITE3_CFLAGS)",
        "$(LIBCBM_MIMALLOC_CFLAGS)",
        "$(LIBCBM_DEPFLAGS)",
    )
    missing_depflags = [
        line for line in compile_lines if not any(flag in line for flag in dep_aware_flags)
    ]
    require(
        not missing_depflags,
        f"all libcbm compile recipes must emit depfiles: {missing_depflags}",
    )
    require(
        "LIBCBM_OBJECTS_RSP = $(BUILD_DIR)/libcbm.objects.rsp" in makefile,
        "the libcbm object response file must be declared",
    )
    require(
        "$(file >$(LIBCBM_OBJECTS_RSP),$(LIBCBM_OBJS))" in makefile,
        "GNU Make must write the object response file without a shell command",
    )

    link_lines = [line.strip() for line in makefile.splitlines() if "$(LD) -r" in line]
    require(len(link_lines) == 1, "exactly one relocatable libcbm link command is required")
    require(
        "@$(LIBCBM_OBJECTS_RSP)" in link_lines[0],
        "the relocatable link must consume the response file",
    )
    require(
        "$(LIBCBM_OBJS)" not in link_lines[0],
        "the relocatable link must not expand every object on the command line",
    )
    require(
        "MINGW_RELOC_LD_FLAGS := --allow-multiple-definition" in makefile
        and "$(MINGW_RELOC_LD_FLAGS)" in link_lines[0],
        "MinGW relocatable linking must allow the known CRT import-symbol duplicates",
    )
    require(
        'if [ "$(IS_MINGW)" = "yes" ]; then $(OBJCOPY) --remove-section=.drectve $@; fi'
        in makefile,
        "MinGW static objects must discard DLL-only export directives",
    )
    require(
        'println!("cargo:rustc-link-lib=advapi32");' in build_rs,
        "native Windows links must include the token-privilege system library",
    )
    # #286: the pressure-log overlay is an in-place edit in the owned mem.c,
    # guarded by ASTRO_MEM_PRESSURE (libcbm defines it). Both size_t percentage
    # buffers are widened CBM_SZ_16 -> CBM_SZ_32 under the guard; the #else keeps
    # the original CBM_SZ_16 for the production/test artifacts.
    require(
        mem_c.count("char pct_str[CBM_SZ_32];") == 2
        and mem_c.count("char pct_str[CBM_SZ_16];") == 2
        and "#ifdef ASTRO_MEM_PRESSURE" in mem_c,
        "owned mem.c must widen both percentage buffers under ASTRO_MEM_PRESSURE "
        "with the original preserved in the #else",
    )
    # #286: libcbm turns on every absorbed feature it historically carried; the
    # production binaries get only the -Werror fixes and the worker diagnostics.
    require(
        "LIBCBM_ASTRO_DEFS = -DASTRO_ENV_STORE -DASTRO_SPAWN -DASTRO_SHELLARG" in makefile
        and "-DASTRO_MEM_PRESSURE -DASTRO_WORKER_DIAG" in makefile
        and "LIBCBM_CFLAGS += $(LIBCBM_ASTRO_DEFS) -I$(ASTROLABE_PATCH_DIR)" in makefile,
        "libcbm must define the five absorbed-overlay feature flags",
    )
    require(
        "ASTRO_PROD_DEFS = -DASTRO_UI_WERROR -DASTRO_WORKER_DIAG" in makefile
        and "ASTRO_ENV_STORE" not in makefile.split("ASTRO_PROD_DEFS", 1)[1].split("\n", 1)[0],
        "the production binaries must define only ASTRO_UI_WERROR + ASTRO_WORKER_DIAG",
    )
    require(
        "$(LIBCBM_DIR)/%.o: %.c" in makefile
        and "$(CC) $(LIBCBM_CFLAGS) -c -o $@ $<" in makefile,
        "the owned CBM sources must compile via the generic libcbm object rule",
    )

    print("native Windows libcbm build contract verified")


if __name__ == "__main__":
    main()
