mod build_support;

use std::collections::{BTreeMap, HashMap};
use std::env;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{Value, json};

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

#[derive(Debug)]
struct BuildSourceDateEpoch {
    value: String,
    revision: String,
    repository_root: String,
}

fn build_source_date_epoch(repo_root: &Path) -> BuildSourceDateEpoch {
    let repository_root = fs::canonicalize(repo_root).unwrap_or_else(|error| {
        panic!(
            "cannot canonicalize Astrolabe repository root {}: {error}",
            repo_root.display()
        )
    });
    assert!(
        repository_root.join(".git").exists(),
        "cbm-sys must be built from the exact Git repository root: {}",
        repository_root.display()
    );

    let epoch_output = Command::new("git")
        .args(["-C"])
        .arg(&repository_root)
        .args([
            "log",
            "-1",
            "--no-show-signature",
            "--format=%H%n%ct",
            "HEAD",
            "--",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|error| {
            panic!(
                "cannot execute git while reading the libcbm HEAD epoch for {}: {error}",
                repository_root.display()
            )
        });
    if !epoch_output.status.success() {
        panic!(
            "libcbm Git repository has no readable HEAD commit epoch: {}",
            String::from_utf8_lossy(&epoch_output.stderr)
        );
    }
    let epoch_text =
        String::from_utf8(epoch_output.stdout).expect("Git HEAD epoch output is not valid UTF-8");
    let mut lines = epoch_text.lines();
    let revision = lines.next().unwrap_or_default();
    let value = lines.next().unwrap_or_default();
    assert!(
        lines.next().is_none()
            && matches!(revision.len(), 40 | 64)
            && revision.bytes().all(|byte| byte.is_ascii_hexdigit())
            && !value.is_empty()
            && value.bytes().all(|byte| byte.is_ascii_digit())
            && (value.len() == 1 || !value.starts_with('0'))
            && value.parse::<u64>().is_ok(),
        "Git returned a non-canonical HEAD revision/epoch pair"
    );
    BuildSourceDateEpoch {
        value: value.to_owned(),
        revision: revision.to_ascii_lowercase(),
        repository_root: make_command_path(&repository_root.to_string_lossy()),
    }
}

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
    let source_date_epoch = build_source_date_epoch(repo_root);

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
    //                     ts_runtime.c, ac.c, lz4_store.c,
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
    let config = libcbm_build_config(&config_inputs, &source_date_epoch);
    // Preserve mtime on no-op reruns so Make only invalidates objects when the
    // effective native build configuration changes.
    write_if_changed(&config_stamp, &config);
    run_make(
        &cbm_root,
        &patched_makefile,
        &build_dir,
        &config_stamp,
        &source_date_epoch,
    );
    let compilation_context = capture_compilation_context(
        repo_root,
        &cbm_root,
        &patched_makefile,
        &build_dir,
        &config_stamp,
        &source_date_epoch,
    );
    println!(
        "cargo:rustc-env=ASTROLABE_BUILD_COMPILATION_CONTEXT={}",
        compilation_context.display()
    );
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

fn run_make(
    cbm_root: &Path,
    patched_makefile: &Path,
    build_dir: &Path,
    config_stamp: &Path,
    source_date_epoch: &BuildSourceDateEpoch,
) {
    let mut command = make_command(cbm_root, patched_makefile, build_dir, config_stamp);
    command.env("SOURCE_DATE_EPOCH", &source_date_epoch.value);
    let make = env::var("MAKE").unwrap_or_else(|_| "make".to_string());
    command.arg("libcbm");

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

fn make_command(
    cbm_root: &Path,
    patched_makefile: &Path,
    build_dir: &Path,
    config_stamp: &Path,
) -> Command {
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
        .arg(format!("LIBCBM_CONFIG_STAMP={}", make_path(config_stamp)));

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

    command
}

#[derive(Debug)]
struct CapturedCompileCommand {
    file: String,
    language: &'static str,
    arguments: Vec<String>,
    preprocess_arguments: Vec<String>,
    dependencies: Vec<String>,
}

fn capture_compilation_context(
    repo_root: &Path,
    cbm_root: &Path,
    patched_makefile: &Path,
    build_dir: &Path,
    config_stamp: &Path,
    source_date_epoch: &BuildSourceDateEpoch,
) -> PathBuf {
    let mut dry_run = make_command(cbm_root, patched_makefile, build_dir, config_stamp);
    dry_run.env("SOURCE_DATE_EPOCH", &source_date_epoch.value);
    dry_run.args(["-n", "-B", "libcbm"]);
    let output = dry_run.output().unwrap_or_else(|error| {
        panic!("failed to enumerate exact libcbm compile commands: {error}")
    });
    if !output.status.success() {
        panic!(
            "exact libcbm compile-command enumeration failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let stdout = String::from_utf8(output.stdout)
        .expect("GNU make emitted non-UTF-8 compile-command enumeration output");

    let mut by_file = BTreeMap::<String, CapturedCompileCommand>::new();
    for line in stdout.lines() {
        let Some(arguments) = shlex::split(line) else {
            panic!("GNU make emitted an unparseable compile command: {line:?}");
        };
        if !arguments.iter().any(|argument| argument == "-c") {
            continue;
        }
        let Some(output_at) = arguments.iter().position(|argument| argument == "-o") else {
            continue;
        };
        if output_at + 1 >= arguments.len() {
            panic!("compile command has -o without an object path: {line:?}");
        }
        let source = arguments
            .last()
            .expect("a compile command cannot have an empty argv");
        if !source.ends_with(".c") && !source.ends_with(".cpp") {
            continue;
        }
        let file = repo_relative_path(repo_root, cbm_root, source).unwrap_or_else(|| {
            panic!("libcbm compile source is outside the Astrolabe repository: {source:?}")
        });
        let object = resolve_build_path(cbm_root, &arguments[output_at + 1]);
        let depfile = object.with_extension("d");
        let dependencies = read_depfile(repo_root, cbm_root, &depfile, &file);
        let language = if file.ends_with(".cpp") { "c++" } else { "c" };
        let command = CapturedCompileCommand {
            file: file.clone(),
            language,
            preprocess_arguments: compiler_preprocess_arguments(&arguments),
            arguments,
            dependencies,
        };
        if let Some(previous) = by_file.insert(file.clone(), command)
            && previous.arguments != by_file[&file].arguments
        {
            panic!("one libcbm translation unit has contradictory compile commands: {file}");
        }
    }
    if by_file.is_empty() {
        panic!("GNU make exposed no libcbm C/C++ translation-unit commands");
    }

    let mut baseline_by_query = HashMap::<Vec<String>, String>::new();
    let mut baselines = Vec::<Value>::new();
    let mut commands = Vec::<Value>::with_capacity(by_file.len());
    for command in by_file.values() {
        let language = command.language;
        let query = compiler_query_arguments(&command.arguments, language);
        let baseline_id = if let Some(id) = baseline_by_query.get(&query) {
            id.clone()
        } else {
            let id = format!("baseline-{:03}", baselines.len());
            let (predefined_macros, system_include_paths) =
                query_compiler_baseline(cbm_root, &query, &source_date_epoch.value);
            baselines.push(json!({
                "id": id,
                "language": language,
                "query_arguments": query,
                "predefined_macros": predefined_macros,
                "system_include_paths": system_include_paths,
            }));
            baseline_by_query.insert(query, id.clone());
            id
        };
        commands.push(json!({
            "file": command.file,
            "language": command.language,
            "directory": make_command_path(&cbm_root.to_string_lossy()),
            "arguments": command.arguments,
            "preprocess_arguments": command.preprocess_arguments,
            "baseline_id": baseline_id,
            "dependencies": command.dependencies,
        }));
    }

    let manifest = json!({
        "format": "astrolabe.compilation-context.v1",
        "source_root": make_command_path(&repo_root.to_string_lossy()),
        "source_date_epoch": {
            "value": &source_date_epoch.value,
            "provenance": "git_head_commit",
            "revision": &source_date_epoch.revision,
            "repository_root": &source_date_epoch.repository_root,
        },
        "baselines": baselines,
        "commands": commands,
    });
    let bytes =
        serde_json::to_vec(&manifest).expect("exact compilation-context manifest must serialize");
    let path = build_dir
        .parent()
        .expect("cbm build directory must have an OUT_DIR parent")
        .join("astrolabe-compilation-context.json");
    write_if_changed(&path, &bytes);
    path
}

fn compiler_preprocess_arguments(arguments: &[String]) -> Vec<String> {
    let source = arguments
        .last()
        .expect("compile command must name its translation unit");
    let mut preprocess = Vec::with_capacity(arguments.len());
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "-c"
            || argument == source
            || matches!(
                argument.as_str(),
                "-M" | "-MM" | "-MD" | "-MMD" | "-MP" | "-MG"
            )
        {
            index += 1;
            continue;
        }
        if matches!(argument.as_str(), "-o" | "-MF" | "-MT" | "-MQ" | "-MJ") {
            assert!(
                index + 1 < arguments.len(),
                "compile action option {argument} has no value"
            );
            index += 2;
            continue;
        }
        if (argument.starts_with("-o") && argument.len() > 2)
            || (argument.starts_with("-MF") && argument.len() > 3)
            || (argument.starts_with("-MT") && argument.len() > 3)
            || (argument.starts_with("-MQ") && argument.len() > 3)
            || (argument.starts_with("-MJ") && argument.len() > 3)
        {
            index += 1;
            continue;
        }
        preprocess.push(argument.clone());
        index += 1;
    }
    assert!(
        !preprocess.is_empty(),
        "preprocessing argv must retain its compiler"
    );
    preprocess
}

fn compiler_query_arguments(arguments: &[String], language: &str) -> Vec<String> {
    let mut query = Vec::with_capacity(arguments.len() + 6);
    let source = arguments
        .last()
        .expect("compile command must name its translation unit");
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "-c"
            || argument == source
            || argument == "-MMD"
            || argument == "-MD"
            || argument == "-MP"
        {
            index += 1;
            continue;
        }
        if matches!(
            argument.as_str(),
            "-o" | "-MF" | "-MT" | "-MQ" | "-MJ" | "-x"
        ) {
            index += 2;
            continue;
        }
        query.push(argument.clone());
        index += 1;
    }
    query.extend([
        "-dM".to_string(),
        "-E".to_string(),
        "-v".to_string(),
        "-x".to_string(),
        language.to_string(),
        "-".to_string(),
    ]);
    query
}

fn query_compiler_baseline(
    cbm_root: &Path,
    arguments: &[String],
    source_date_epoch: &str,
) -> (Vec<String>, Vec<String>) {
    let compiler = arguments
        .first()
        .expect("compiler baseline query requires argv[0]");
    let output = Command::new(compiler)
        .args(&arguments[1..])
        .current_dir(cbm_root)
        .env("SOURCE_DATE_EPOCH", source_date_epoch)
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|error| panic!("failed to query compiler baseline {compiler:?}: {error}"));
    if !output.status.success() {
        panic!(
            "compiler baseline query failed with {} for {:?}: {}",
            output.status,
            arguments,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let stdout = String::from_utf8(output.stdout)
        .expect("compiler predefined-macro output is not valid UTF-8");
    let stderr = String::from_utf8(output.stderr)
        .expect("compiler include-search output is not valid UTF-8");
    let predefined_macros = stdout
        .lines()
        .filter_map(|line| line.strip_prefix("#define "))
        .map(|definition| {
            let split = definition.find(char::is_whitespace);
            match split {
                Some(at) => format!("{}={}", &definition[..at], definition[at..].trim_start()),
                None => definition.to_string(),
            }
        })
        .collect::<Vec<_>>();
    if predefined_macros.is_empty() {
        panic!("compiler baseline query returned no predefined macros: {arguments:?}");
    }

    let mut system_include_paths = Vec::new();
    let mut in_search_list = false;
    for line in stderr.lines() {
        let trimmed = line.trim();
        if trimmed == "#include <...> search starts here:" {
            in_search_list = true;
            continue;
        }
        if trimmed == "End of search list." {
            break;
        }
        if in_search_list && !trimmed.is_empty() {
            let path = trimmed
                .strip_suffix(" (framework directory)")
                .unwrap_or(trimmed);
            system_include_paths.push(path.replace('\\', "/"));
        }
    }
    if system_include_paths.is_empty() {
        panic!("compiler baseline query returned no system include roots: {arguments:?}");
    }
    (predefined_macros, system_include_paths)
}

fn read_depfile(repo_root: &Path, cbm_root: &Path, depfile: &Path, source: &str) -> Vec<String> {
    let text = fs::read_to_string(depfile).unwrap_or_else(|error| {
        panic!(
            "compiler dependency record is missing for translation unit {source} at {}: {error}",
            depfile.display()
        )
    });
    let flattened = text.replace("\\\r\n", " ").replace("\\\n", " ");
    let Some(separator) = flattened.find(": ") else {
        panic!(
            "compiler dependency record has no target separator: {}",
            depfile.display()
        );
    };
    let mut dependencies = Vec::new();
    for token in flattened[separator + 2..].split_ascii_whitespace() {
        let token = token.replace("\\ ", " ");
        if let Some(relative) = repo_relative_path(repo_root, cbm_root, &token)
            && !dependencies.contains(&relative)
        {
            dependencies.push(relative);
        }
    }
    if !dependencies.iter().any(|dependency| dependency == source) {
        panic!(
            "compiler dependency record does not contain its translation unit {source}: {}",
            depfile.display()
        );
    }
    dependencies.sort();
    dependencies
}

fn resolve_build_path(cbm_root: &Path, raw: &str) -> PathBuf {
    let path = PathBuf::from(raw);
    if path.is_absolute() {
        path
    } else {
        cbm_root.join(path)
    }
}

fn repo_relative_path(repo_root: &Path, cbm_root: &Path, raw: &str) -> Option<String> {
    let candidate = resolve_build_path(cbm_root, raw);
    let absolute = fs::canonicalize(&candidate).ok()?;
    let canonical_root = fs::canonicalize(repo_root).ok()?;
    let relative = absolute.strip_prefix(canonical_root).ok()?;
    Some(relative.to_string_lossy().replace('\\', "/"))
}

fn libcbm_build_config(inputs: &[&Path], source_date_epoch: &BuildSourceDateEpoch) -> Vec<u8> {
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
    config.extend_from_slice(b"SOURCE_DATE_EPOCH=");
    config.extend_from_slice(source_date_epoch.value.as_bytes());
    config.push(b'\n');
    config.extend_from_slice(b"SOURCE_DATE_EPOCH_REVISION=");
    config.extend_from_slice(source_date_epoch.revision.as_bytes());
    config.push(b'\n');
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
