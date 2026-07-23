mod build_support;

use std::env;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
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
    // #63/#283: declared grammar-set build knob. Selects which tree-sitter
    // grammars libcbm.a compiles in (`full` = every shim, the default; `core` =
    // the curated CBM_GRAMMAR_CORE_LANGS subset with grammar_stubs.c fail-closing
    // dropped languages via a labeled CBM_GRAMMAR_STUBBED error). Listing it here
    // makes a change to it (a) re-run this build script and (b) enter the libcbm
    // config stamp, so switching full<->core invalidates every grammar object.
    "CBM_GRAMMAR_SET",
];

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let repo_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("cbm-sys crate must live under crates/");
    let cbm_root = repo_root.join("cbm");
    let patched_makefile = repo_root.join("patches/cbm/Makefile.cbm");
    let alloc_shim = repo_root.join("patches/cbm/astro_alloc_shim.c");
    let layout_probe = repo_root.join("patches/cbm/astro_layout_probe.c");
    // #240/#241: the Astrolabe-owned store-configuration translation unit that the
    // (now in-place, ASTRO_ENV_STORE-guarded) CBM resolvers call into. A change to
    // it must invalidate every libcbm object.
    let env_store_config_src = repo_root.join("patches/cbm/env_store_config.c");
    let env_store_config_hdr = repo_root.join("patches/cbm/env_store_config.h");
    // #227/#228: the shell-free git-spawn helper the (in-place, ASTRO_SPAWN-guarded)
    // git shell-out sites call into. Its source and header are build inputs: a change
    // to either must invalidate every libcbm object so Cargo rebuilds the archive.
    let spawn_overlays = [
        repo_root.join("patches/cbm/astro_spawn.c"),
        repo_root.join("patches/cbm/astro_spawn.h"),
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
    println!("cargo:rerun-if-changed={}", env_store_config_src.display());
    println!("cargo:rerun-if-changed={}", env_store_config_hdr.display());
    for spawn_overlay in &spawn_overlays {
        println!("cargo:rerun-if-changed={}", spawn_overlay.display());
    }
    // #420: watch the owned CBM C source trees so an edit to ANY of them rebuilds
    // libcbm.a. cargo:rerun-if-changed on a directory recursively scans the whole
    // tree and re-runs on any file content change, addition, or deletion within it
    // (Cargo Book: "If the path points to a directory, it will scan the entire
    // directory for any modifications" — present since rust-lang/cargo cee088b,
    // well before the pinned 1.95 toolchain). Three directory emissions therefore
    // cover EVERY translation unit and header the Makefile.cbm `libcbm` target
    // compiles, with no hand-maintained per-file list that could silently drift:
    //   cbm/src/**      — foundation, store, cypher, mcp, discover, graph_buffer,
    //                     pipeline, simhash, semantic, traces, watcher, git, cli,
    //                     ui, plus vendored/yyjson.c reached via src includes
    //   cbm/internal/** — extraction (cbm.c, extract_*.c, helpers.c, lang_specs.c,
    //                     service_patterns.c), grammar_*.c, lsp/** (lsp_all unity),
    //                     ts_runtime.c, preprocessor.cpp, ac.c, lz4_store.c,
    //                     zstd_store.c, sqlite_writer.c, every *.h, AND
    //                     internal/cbm/vendored/{lz4,zstd,ts_runtime}
    //   cbm/vendored/** — mimalloc, sqlite3, yyjson, nomic (code_vectors blob),
    //                     tre (MinGW). Also the bindgen include roots.
    //
    // Directory (not per-file) watching is deliberate: it stays complete as sources
    // are added/removed, and it fires on any junk dropped into these trees — but the
    // trees only ever hold checked-in SOURCE. The libcbm build writes its objects to
    // OUT_DIR (BUILD_DIR is $OUT_DIR/cbm-build below), NEVER into cbm/, so watching
    // adds NO self-inflicted mtime churn; only a real source edit re-triggers the
    // make walk + bindgen parse, which is exactly the invalidation #420 requires.
    // This reverses the #192 speed-over-correctness choice that let a stale libcbm.a
    // link after an owned-C edit and silently invalidated FSV evidence (wave-16/17).
    // Make depfiles (-MMD -MP) + the config stamp still own C-level incrementalism
    // WITHIN a build; the Makefile and Astrolabe-owned TUs above remain watched too.
    for cbm_source_tree in ["src", "internal", "vendored"] {
        println!(
            "cargo:rerun-if-changed={}",
            cbm_root.join(cbm_source_tree).display()
        );
    }
    println!("cargo:rustc-check-cfg=cfg(cbm_sys_asan)");
    println!(
        "cargo:rustc-env=CBM_MIMALLOC_VERSION={}",
        read_mimalloc_version(&mimalloc_header)
    );
    for var in LIBCBM_BUILD_ENV_VARS {
        println!("cargo:rerun-if-env-changed={var}");
    }
    println!("cargo:rerun-if-env-changed=ASTROLABE_UPDATE_BINDINGS");
    println!("cargo:rerun-if-env-changed=ASTROLABE_BINDINGS_CANDIDATE");
    println!("cargo:rerun-if-env-changed=LIBCLANG_PATH");
    if env::var_os("CBM_SYS_ASAN").is_some() {
        println!("cargo:rustc-cfg=cbm_sys_asan");
    }

    let build_script = manifest_dir.join("build.rs");
    let mut config_inputs: Vec<&Path> = vec![
        &build_script,
        &patched_makefile,
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
    // Cargo's build-script contract grants this process one implicit job slot.
    // Nested GNU Make may use additional slots only through Cargo's shared
    // jobserver. Passing historical NUM_JOBS as an independent `make -jN`
    // multiplies concurrency when Cargo runs multiple cbm-sys feature builds.
    // Cargo explicitly documents CARGO_MAKEFLAGS -> MAKEFLAGS as the supported
    // GNU Make bridge. On our native Windows GNU toolchain the authorization is
    // a named semaphore; reject a present but unusable contract instead of
    // allowing Make to degrade to an independently parallel invocation.
    match env::var("CARGO_MAKEFLAGS") {
        Ok(flags) => {
            let has_jobserver = flags
                .split_ascii_whitespace()
                .any(|flag| flag.starts_with("--jobserver-auth=") && flag.len() > 17);
            if flags.trim().is_empty() || !has_jobserver {
                panic!(
                    "CBM_BUILD_JOBSERVER_INVALID[ASTRO_CBM_BUILD_JOBSERVER_INVALID]: \
                     CARGO_MAKEFLAGS is present but contains no non-empty --jobserver-auth value; \
                     refusing independent nested-build concurrency. remediation: invoke Cargo \
                     through the native launcher so Cargo can publish its Windows jobserver"
                );
            }
            command.env("MAKEFLAGS", flags);
        }
        Err(env::VarError::NotPresent) => {
            // With no Cargo jobserver, preserve the build script's one implicit
            // slot. Remove any unrelated ambient Make policy rather than
            // inheriting uncoordinated or unlimited parallelism.
            command.env_remove("MAKEFLAGS");
        }
        Err(env::VarError::NotUnicode(_)) => {
            panic!(
                "CBM_BUILD_JOBSERVER_INVALID[ASTRO_CBM_BUILD_JOBSERVER_INVALID]: \
                 CARGO_MAKEFLAGS is not valid Unicode; refusing an unevaluable nested-build \
                 concurrency contract. remediation: clear the malformed environment value and \
                 invoke Cargo through the native launcher"
            );
        }
    }
    command
        .current_dir(cbm_root)
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
    // #63/#283: forward the declared grammar-set knob to Make. Only forwarded
    // when explicitly set so the Makefile default (`full`) governs dev/test and
    // the CBM C suite; the release gate (check-release.sh) selects `core` for
    // the size-gated shipped artifact. The Makefile validates the value and
    // fails closed via `$(error ...)` on anything but `full`/`core`.
    if let Ok(grammar_set) = env::var("CBM_GRAMMAR_SET") {
        command.arg(format!("CBM_GRAMMAR_SET={grammar_set}"));
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
        panic!(
            "ASTROLABE_UPDATE_BINDINGS is unsafe: a native build runs inside a frozen launcher \
             lease and may not mutate tracked source. Set ASTROLABE_BINDINGS_CANDIDATE to one \
             fresh absolute path below the workspace .tmp directory, inspect that candidate \
             after launcher cleanup, then promote it outside the lease."
        );
    }

    if let Some(candidate) = env::var_os("ASTROLABE_BINDINGS_CANDIDATE") {
        let candidate = PathBuf::from(candidate);
        if !candidate.is_absolute() {
            panic!("ASTROLABE_BINDINGS_CANDIDATE must be an absolute path");
        }
        let workspace = manifest_dir
            .parent()
            .and_then(Path::parent)
            .expect("cbm-sys manifest must remain two levels below the workspace");
        let tmp = fs::canonicalize(workspace.join(".tmp"))
            .expect("workspace .tmp must exist before generating a bindings candidate");
        let parent = candidate
            .parent()
            .and_then(|path| fs::canonicalize(path).ok())
            .expect("bindings candidate parent must already exist and be readable");
        if parent != tmp && !parent.starts_with(&tmp) {
            panic!("ASTROLABE_BINDINGS_CANDIDATE must resolve below the workspace .tmp directory");
        }
        let candidate_bytes = generated.as_bytes().to_vec();
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
            .unwrap_or_else(|err| {
                panic!(
                    "failed to create fresh bindings candidate {}: {err}",
                    candidate.display()
                )
            });
        output
            .write_all(&candidate_bytes)
            .and_then(|()| output.sync_all())
            .unwrap_or_else(|err| {
                panic!(
                    "failed to durably write bindings candidate {}: {err}",
                    candidate.display()
                )
            });
        drop(output);
        let readback = fs::read(&candidate).unwrap_or_else(|err| {
            panic!(
                "failed to read back bindings candidate {}: {err}",
                candidate.display()
            )
        });
        if readback != candidate_bytes {
            panic!(
                "bindings candidate readback differs from generated bytes: {}",
                candidate.display()
            );
        }
        println!(
            "cargo:warning=durable cbm bindings candidate written to {} ({} bytes)",
            candidate.display(),
            candidate_bytes.len()
        );
    }

    let committed = fs::read_to_string(&bindings_path).unwrap_or_else(|err| {
        panic!(
            "failed to read committed bindings at {}: {err}. Run \
             a native launcher build with ASTROLABE_BINDINGS_CANDIDATE set to one fresh \
             absolute path below workspace .tmp, then inspect and promote that candidate \
             after the launcher lease ends.",
            bindings_path.display()
        )
    });
    if normalize_bindings(&committed) != normalize_bindings(&generated) {
        panic!(
            "cbm-sys bindings are stale. Run a native launcher build with \
             ASTROLABE_BINDINGS_CANDIDATE set to one fresh absolute path below workspace .tmp, \
             inspect and promote that candidate after the launcher lease ends, then rerun this \
             ordinary build."
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
