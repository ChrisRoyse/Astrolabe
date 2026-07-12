mod build_support;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use build_support::normalize_bindings;

const LIBCBM_BUILD_ENV_VARS: &[&str] = &[
    "PATH",
    "MAKE",
    "CC",
    "CXX",
    "AR",
    "LD",
    "NM",
    "OBJCOPY",
    "PYTHON",
    "ARCHFLAGS",
    "CFLAGS_EXTRA",
    "CXXFLAGS_EXTRA",
    "CBM_SYS_ASAN",
    "STATIC",
];

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let repo_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("cbm-sys crate must live under crates/");
    let cbm_root = repo_root.join("vendor/codebase-memory-mcp");
    let patched_makefile = repo_root.join("patches/cbm/Makefile.cbm");
    let alloc_shim = repo_root.join("patches/cbm/astro_alloc_shim.c");
    let layout_probe = repo_root.join("patches/cbm/astro_layout_probe.c");
    let mem_pressure_patch = repo_root.join("patches/cbm/apply_mem_pressure_patch.py");
    // #240/#241: the store-resolution overlay. Its generator and the Astrolabe-owned
    // translation unit it calls into are build inputs exactly like the mem-pressure
    // patch: a change to either must invalidate every libcbm object.
    let env_store_patch = repo_root.join("patches/cbm/env_apply_store_patch.py");
    let env_store_config_src = repo_root.join("patches/cbm/env_store_config.c");
    let env_store_config_hdr = repo_root.join("patches/cbm/env_store_config.h");
    // #227/#228: the shell-free git-spawn helper, its shared overlay primitives,
    // and every generator that routes a CBM git shell-out through it. Each is a
    // build input exactly like the env-store overlay: a change to any of them
    // must invalidate every libcbm object so Cargo rebuilds the archive.
    let spawn_overlays = [
        repo_root.join("patches/cbm/astro_spawn.c"),
        repo_root.join("patches/cbm/astro_spawn.h"),
        repo_root.join("patches/cbm/astro_overlay.py"),
        repo_root.join("patches/cbm/apply_spawn_git_context_patch.py"),
        repo_root.join("patches/cbm/apply_spawn_artifact_patch.py"),
        repo_root.join("patches/cbm/apply_spawn_watcher_patch.py"),
        repo_root.join("patches/cbm/apply_spawn_githistory_patch.py"),
        repo_root.join("patches/cbm/apply_shellarg_str_util_patch.py"),
    ];
    let mimalloc_header = cbm_root.join("vendored/mimalloc/include/mimalloc.h");
    let header = manifest_dir.join("include/astro_ffi.h");
    let build_support = manifest_dir.join("build_support.rs");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let build_dir = out_dir.join("cbm-build");
    let config_stamp = out_dir.join("libcbm-build-config.stamp");

    println!("cargo:rerun-if-changed={}", header.display());
    println!("cargo:rerun-if-changed={}", build_support.display());
    println!("cargo:rerun-if-changed={}", patched_makefile.display());
    println!("cargo:rerun-if-changed={}", alloc_shim.display());
    println!("cargo:rerun-if-changed={}", layout_probe.display());
    println!("cargo:rerun-if-changed={}", mem_pressure_patch.display());
    println!("cargo:rerun-if-changed={}", env_store_patch.display());
    println!("cargo:rerun-if-changed={}", env_store_config_src.display());
    println!("cargo:rerun-if-changed={}", env_store_config_hdr.display());
    for spawn_overlay in &spawn_overlays {
        println!("cargo:rerun-if-changed={}", spawn_overlay.display());
    }
    // The vendored CBM tree is deliberately NOT watched file-by-file (#192).
    // It is pinned: every sanctioned change lands through the VENDORED.md pin
    // procedure (which rewrites the binding tree SHA below) or through the
    // watched patches/cbm inputs above, and scripts/verify-pins.sh rejects
    // direct vendor edits. Watching the whole src/, internal/cbm, and
    // vendored/ trees made any mtime churn re-run this script — paying the
    // make walk plus a full libclang bindgen parse — without any input Cargo
    // could not already see via VENDORED.md. Within one build, Make depfiles
    // (-MMD -MP) plus the config stamp own C-level incremental correctness.
    println!(
        "cargo:rerun-if-changed={}",
        repo_root.join("VENDORED.md").display()
    );
    println!("cargo:rustc-check-cfg=cfg(cbm_sys_asan)");
    println!(
        "cargo:rustc-env=CBM_MIMALLOC_VERSION={}",
        read_mimalloc_version(&mimalloc_header)
    );
    for var in LIBCBM_BUILD_ENV_VARS {
        println!("cargo:rerun-if-env-changed={var}");
    }
    println!("cargo:rerun-if-env-changed=ASTROLABE_UPDATE_BINDINGS");
    println!("cargo:rerun-if-env-changed=LIBCLANG_PATH");
    if env::var_os("CBM_SYS_ASAN").is_some() {
        println!("cargo:rustc-cfg=cbm_sys_asan");
    }

    let build_script = manifest_dir.join("build.rs");
    let mut config_inputs: Vec<&Path> = vec![
        &build_script,
        &patched_makefile,
        &mem_pressure_patch,
        &env_store_patch,
        &env_store_config_src,
        &env_store_config_hdr,
    ];
    config_inputs.extend(spawn_overlays.iter().map(|p| p.as_path()));
    let config = libcbm_build_config(&config_inputs);
    // Preserve mtime on no-op reruns so Make only invalidates objects when the
    // effective native build configuration changes.
    write_if_changed(&config_stamp, &config);
    run_make(&cbm_root, &patched_makefile, &build_dir, &config_stamp);
    // One libclang parse per build-script run (#192): generate the superset
    // (functions + layout tests) once, then derive both consumers from it —
    // the OUT_DIR layout-test include gets the superset verbatim (its module
    // allows clashing extern declarations and dead code), and the committed
    // bindings diff strips the layout-test functions before comparing.
    let generated = generate_bindings(&cbm_root, &header);
    write_layout_test_bindings(&out_dir, &generated);
    verify_bindings(&manifest_dir, &generated);
    emit_link_directives(&build_dir);
}

fn run_make(cbm_root: &Path, patched_makefile: &Path, build_dir: &Path, config_stamp: &Path) {
    let make = env::var("MAKE").unwrap_or_else(|_| "make".to_string());
    let mut command = Command::new(&make);
    // Build libcbm's 150+ translation units in parallel. `NUM_JOBS` is set by
    // Cargo to the parallelism it chose for this build (a provided measurement,
    // not a magic constant); mirroring it keeps the C compile within Cargo's job
    // budget instead of serializing every object. Falls back to 1 if unset.
    let make_jobs = env::var("NUM_JOBS").unwrap_or_else(|_| "1".to_string());
    command
        .current_dir(cbm_root)
        .arg(format!("-j{make_jobs}"))
        .arg("-f")
        .arg(make_path(patched_makefile))
        .arg(format!("BUILD_DIR={}", make_path(build_dir)))
        .arg(format!("LIBCBM_CONFIG_STAMP={}", make_path(config_stamp)))
        .arg("libcbm");

    if let Ok(cc) = env::var("CC") {
        command.arg(format!("CC={}", make_command_path(&cc)));
    }
    if let Ok(cxx) = env::var("CXX") {
        command.arg(format!("CXX={}", make_command_path(&cxx)));
    }
    if let Ok(ar) = env::var("AR") {
        command.arg(format!("AR={}", make_command_path(&ar)));
    }
    if let Ok(ld) = env::var("LD") {
        command.arg(format!("LD={}", make_command_path(&ld)));
    }
    if let Ok(nm) = env::var("NM") {
        command.arg(format!("NM={}", make_command_path(&nm)));
    }
    if let Ok(objcopy) = env::var("OBJCOPY") {
        command.arg(format!("OBJCOPY={}", make_command_path(&objcopy)));
    }
    let asan_enabled = env::var_os("CBM_SYS_ASAN").is_some();
    if asan_enabled || env::var_os("CFLAGS_EXTRA").is_some() {
        command.arg(format!(
            "CFLAGS_EXTRA={}",
            extra_flags("CFLAGS_EXTRA", asan_enabled)
        ));
    }
    if asan_enabled || env::var_os("CXXFLAGS_EXTRA").is_some() {
        command.arg(format!(
            "CXXFLAGS_EXTRA={}",
            extra_flags("CXXFLAGS_EXTRA", asan_enabled)
        ));
    }
    if asan_enabled {
        command.arg("LIBCBM_ASAN=1");
    }
    if let Ok(archflags) = env::var("ARCHFLAGS") {
        command.arg(format!("ARCHFLAGS={archflags}"));
    }

    let status = command.status().unwrap_or_else(|err| {
        panic!(
            "failed to execute `{make}` for libcbm.a: {err}. Install GNU make plus a C/C++ toolchain, \
             or set MAKE/CC/CXX/AR explicitly."
        )
    });
    if !status.success() {
        panic!("libcbm.a build failed with status {status}");
    }
}

fn libcbm_build_config(inputs: &[&Path]) -> Vec<u8> {
    let mut config = Vec::new();
    for path in inputs.iter().copied() {
        config.extend_from_slice(path.to_string_lossy().as_bytes());
        config.push(b'\n');
        config.extend_from_slice(&fs::read(path).unwrap_or_else(|err| {
            panic!(
                "failed to read libcbm build configuration input {}: {err}",
                path.display()
            )
        }));
        config.push(b'\n');
    }
    for var in std::iter::once("TARGET").chain(LIBCBM_BUILD_ENV_VARS.iter().copied()) {
        config.extend_from_slice(var.as_bytes());
        config.push(b'=');
        match env::var_os(var) {
            Some(value) => config.extend_from_slice(value.to_string_lossy().as_bytes()),
            None => config.extend_from_slice(b"<unset>"),
        }
        config.push(b'\n');
    }
    config
}

fn write_if_changed(path: &Path, contents: &[u8]) {
    if fs::read(path).is_ok_and(|existing| existing == contents) {
        return;
    }
    fs::write(path, contents).unwrap_or_else(|err| {
        panic!(
            "failed to write libcbm build configuration stamp {}: {err}",
            path.display()
        )
    });
}

fn make_path(path: &Path) -> String {
    let value = path.to_string_lossy();
    make_command_path(&value)
}

fn make_command_path(value: &str) -> String {
    if cfg!(windows) {
        value.replace('\\', "/")
    } else {
        value.to_owned()
    }
}

fn write_layout_test_bindings(out_dir: &Path, generated: &str) {
    write_if_changed(&out_dir.join("cbm-layout-tests.rs"), generated.as_bytes());
}

fn verify_bindings(manifest_dir: &Path, generated: &str) {
    let generated = build_support::strip_layout_tests(generated);
    let bindings_path = manifest_dir.join("src/bindings.rs");

    if env::var_os("ASTROLABE_UPDATE_BINDINGS").is_some() {
        fs::write(&bindings_path, &generated).expect("failed to update committed cbm bindings");
        return;
    }

    let committed = fs::read_to_string(&bindings_path).unwrap_or_else(|err| {
        panic!(
            "failed to read committed bindings at {}: {err}. Run \
             `ASTROLABE_UPDATE_BINDINGS=1 cargo build -p cbm-sys` to create them.",
            bindings_path.display()
        )
    });
    if normalize_bindings(&committed) != normalize_bindings(&generated) {
        panic!(
            "cbm-sys bindings are stale. Run \
             `ASTROLABE_UPDATE_BINDINGS=1 cargo build -p cbm-sys`, review \
             crates/cbm-sys/src/bindings.rs, and commit the result."
        );
    }
}

fn generate_bindings(cbm_root: &Path, header: &Path) -> String {
    let builder = bindgen::Builder::default()
        .header(header.display().to_string())
        .clang_arg(format!("-I{}", cbm_root.join("internal/cbm").display()))
        .clang_arg(format!(
            "-I{}",
            cbm_root
                .join("internal/cbm/vendored/ts_runtime/include")
                .display()
        ))
        .clang_arg(format!("-I{}", cbm_root.join("src").display()))
        .clang_arg(format!("-I{}", cbm_root.join("src/foundation").display()))
        .allowlist_type("CBM.*")
        .allowlist_type("cbm_.*")
        .allowlist_type("TS.*")
        .allowlist_var("CBM_.*")
        .allowlist_function("cbm_.*")
        .blocklist_function("cbm_mcp_server_run")
        .blocklist_function("cbm_store_get_db")
        .blocklist_type("FILE")
        .blocklist_type("_iobuf")
        .blocklist_type("_IO_.*")
        .blocklist_type("__off.*")
        .blocklist_type("sqlite3")
        .opaque_type("TS.*")
        .derive_default(true)
        .layout_tests(true);
    let bindings = builder
        .generate()
        .expect("failed to generate cbm-sys bindings");
    bindings.to_string()
}

fn emit_link_directives(build_dir: &Path) {
    println!("cargo:rustc-link-search=native={}", build_dir.display());
    println!("cargo:rustc-link-lib=static=cbm");

    let target = env::var("TARGET").unwrap_or_default();
    if target.contains("apple") {
        println!("cargo:rustc-link-lib=c++");
    } else {
        println!("cargo:rustc-link-lib=stdc++");
    }

    println!("cargo:rustc-link-lib=z");
    println!("cargo:rustc-link-lib=m");
    if !target.contains("windows") {
        println!("cargo:rustc-link-lib=pthread");
    }
    if target.contains("windows") {
        println!("cargo:rustc-link-lib=ws2_32");
        println!("cargo:rustc-link-lib=psapi");
        println!("cargo:rustc-link-lib=shell32");
        println!("cargo:rustc-link-lib=advapi32");
    }
    if env::var_os("CBM_SYS_ASAN").is_some() && target.contains("linux") {
        println!("cargo:rustc-link-lib=asan");
        println!("cargo:rustc-link-arg=-fsanitize=address");
    }
}

fn extra_flags(var: &str, asan_enabled: bool) -> String {
    let mut flags = env::var(var).unwrap_or_default();
    if asan_enabled {
        if !flags.is_empty() {
            flags.push(' ');
        }
        flags.push_str("-fsanitize=address -fno-omit-frame-pointer");
    }
    flags
}

fn read_mimalloc_version(header: &Path) -> String {
    let text = fs::read_to_string(header).unwrap_or_else(|err| {
        panic!(
            "failed to read vendored mimalloc header at {}: {err}",
            header.display()
        )
    });
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("#define MI_MALLOC_VERSION")
            && let Some(version) = rest.split_whitespace().next()
        {
            return version.to_string();
        }
    }
    panic!(
        "MI_MALLOC_VERSION not found in vendored mimalloc header {}",
        header.display()
    );
}
