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
        "path.replace('\\\\', \"/\")" in build_rs,
        "the Windows Make path conversion must replace backslashes",
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
