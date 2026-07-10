#!/usr/bin/env python3
"""Guard the bounded, shell-safe native Windows libcbm build contract."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BUILD_RS = ROOT / "crates" / "cbm-sys" / "build.rs"
MAKEFILE = ROOT / "patches" / "cbm" / "Makefile.cbm"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"native Windows libcbm build contract failed: {message}")


def main() -> None:
    build_rs = BUILD_RS.read_text(encoding="utf-8")
    makefile = MAKEFILE.read_text(encoding="utf-8")

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
        "path.replace('\\\\', \"/\")" in build_rs,
        "the Windows Make path conversion must replace backslashes",
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
        "libcbm_build_config(&build_script, &patched_makefile)" in build_rs,
        "the configuration stamp must cover build.rs and Makefile.cbm",
    )
    require(
        '"TARGET"' in build_rs
        and '"PATH"' in build_rs
        and '"CBM_SYS_ASAN"' in build_rs,
        "the configuration stamp must cover target, tool lookup, and ASan mode",
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
        'if [ "$(IS_MINGW)" = "yes" ]; then $(OBJCOPY) --remove-section=.drectve $@; fi'
        in makefile,
        "MinGW static objects must discard DLL-only export directives",
    )
    require(
        'println!("cargo:rustc-link-lib=advapi32");' in build_rs,
        "native Windows links must include the token-privilege system library",
    )

    print("native Windows libcbm build contract verified")


if __name__ == "__main__":
    main()
