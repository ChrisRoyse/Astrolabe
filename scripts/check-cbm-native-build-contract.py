#!/usr/bin/env python3
"""Guard the bounded, shell-safe native Windows libcbm build contract."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BUILD_RS = ROOT / "crates" / "cbm-sys" / "build.rs"
MAKEFILE = ROOT / "patches" / "cbm" / "Makefile.cbm"
MEM_PRESSURE_PATCH = ROOT / "patches" / "cbm" / "apply_mem_pressure_patch.py"
LAYOUT_PROBE = ROOT / "patches" / "cbm" / "astro_layout_probe.c"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"native Windows libcbm build contract failed: {message}")


def main() -> None:
    build_rs = BUILD_RS.read_text(encoding="utf-8")
    makefile = MAKEFILE.read_text(encoding="utf-8")
    mem_pressure_patch = MEM_PRESSURE_PATCH.read_text(encoding="utf-8")

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
    for source_dir in ('join("src")', 'join("internal/cbm")', 'join("vendored")'):
        require(
            source_dir in build_rs,
            f"Cargo must recursively watch the CBM {source_dir} directory",
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
        "libcbm_build_config(&build_script, &patched_makefile, &mem_pressure_patch)" in build_rs,
        "the configuration stamp must cover build.rs, Makefile.cbm, and source overlays",
    )
    require(
        'let mem_pressure_patch = repo_root.join("patches/cbm/apply_mem_pressure_patch.py");'
        in build_rs
        and "cargo:rerun-if-changed={}" in build_rs,
        "Cargo must rebuild when the CBM pressure-log overlay changes",
    )
    require(
        'let layout_probe = repo_root.join("patches/cbm/astro_layout_probe.c");' in build_rs
        and "layout_probe.display()" in build_rs,
        "Cargo must rebuild when the native C ABI layout probe changes",
    )
    require(
        "fn write_layout_test_bindings(" in build_rs
        and 'write_layout_test_bindings(&out_dir, &cbm_root, &header);' in build_rs
        and ".layout_tests(layout_tests)" in build_rs
        and "generate_bindings(cbm_root, header, true, false)" in build_rs,
        "cbm-sys must generate target-local type-only bindgen layout assertions",
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
    require(
        'PERCENT_BUFFER_DECLARATION = "char pct_str[CBM_SZ_16];"' in mem_pressure_patch
        and 'PATCHED_PERCENT_BUFFER_DECLARATION = "char pct_str[CBM_SZ_32];"'
        in mem_pressure_patch
        and "EXPECTED_PERCENT_BUFFER_COUNT = 2" in mem_pressure_patch,
        "the pressure-log overlay must expand exactly the two size_t percentage buffers",
    )
    require(
        "ASTRO_MEM_PRESSURE_PATCH = $(ASTROLABE_PATCH_DIR)/apply_mem_pressure_patch.py"
        in makefile
        and "ASTRO_MEM_PRESSURE_OVERLAY = $(LIBCBM_DIR)/src/foundation/mem.c" in makefile
        and "$(ASTRO_MEM_PRESSURE_OBJ): $(ASTRO_MEM_PRESSURE_OVERLAY)" in makefile
        and "$(PYTHON) $(ASTRO_MEM_PRESSURE_PATCH) $< $@" in makefile,
        "libcbm must compile the generated pressure-log overlay instead of mutating vendor mem.c",
    )
    require(
        "$(CC) $(LIBCBM_CFLAGS) -Isrc/foundation -c -o $@ $<" in makefile,
        "the generated foundation overlay must retain its original local-header search path",
    )

    print("native Windows libcbm build contract verified")


if __name__ == "__main__":
    main()
