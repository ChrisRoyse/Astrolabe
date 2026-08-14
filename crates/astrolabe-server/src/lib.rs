#![forbid(unsafe_code)]

use std::env;
use std::error::Error;
use std::fs;
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use astrolabe_bridge::{BridgeError, CbmToolRunner, ErrorEnvelope};
use tracing::level_filters::LevelFilter;

mod migration;

mod activation_epoch;

mod connection_supervisor;

mod installer_cleanup;
use installer_cleanup::*;

mod hook_augment;
use hook_augment::*;

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");
pub(crate) const ASTRO_INDEX_WORKER_CACHE_DIR_ARG: &str = "_astrolabe_worker_cache_dir";
pub(crate) const ASTRO_INDEX_WORKER_TRANSITION_GRANT_ARG: &str =
    "_astrolabe_project_transition_writer";

type DynError = Box<dyn Error + Send + Sync + 'static>;

pub const LEGACY_TOOLS: &[&str] = &[
    "index_repository",
    "list_projects",
    "delete_project",
    "index_status",
    "search_graph",
    "trace_path",
    "detect_changes",
    "query_graph",
    "get_graph_schema",
    "get_code_snippet",
    "get_architecture",
    "search_code",
    "manage_adr",
    "ingest_traces",
];

pub const LEGACY_ALIASES: &[&str] = &["trace_call_path"];
const VERIFY_CHAIN_LOOP_DEFAULT_INTERVAL_MS: u64 = 60_000;
const VERIFY_CHAIN_LOOP_MIN_INTERVAL_MS: u64 = 1_000;

pub fn parent_system() -> astrolabe_domain::ParentSystem {
    astrolabe_domain::ParentSystem::CodebaseMemoryMcp
}

/// Registry-declared stack reserve (bytes) for any host thread that enters the
/// in-process CBM pipeline (#364). Re-exported so the binary entrypoint sizes
/// its host thread from the single declared knob.
pub use astrolabe_domain::knobs::cbm_pipeline_host_stack_bytes;

/// Name given to the sized host thread every binary entrypoint runs on.
const CBM_HOST_THREAD_NAME: &str = "astrolabe-cbm-host";

/// Exit code substituted when a computed exit code collides with the
/// external-termination signature `-1`/`0xFFFFFFFF` (#1059).
///
/// `Process.Kill()` / `Stop-Process -Force` terminate with `TerminateProcess(h,
/// -1)`, so an externally killed Astrolabe process exits `0xFFFFFFFF`. The g26
/// evidence run was destroyed exactly that way and the exit code proved nothing,
/// because nothing ruled out the process having produced `-1` itself. Astrolabe
/// therefore never self-exits `-1`: the collision is disclosed on stderr and
/// remapped to this sentinel, which makes `0xFFFFFFFF` provably foreign.
pub const EXIT_CODE_SENTINEL_COLLISION: u32 = 0xA57F_0006;

/// Structured code emitted when the collision above is observed.
pub const ASTRO_EXIT_CODE_SENTINEL_COLLISION: &str = "ASTRO_EXIT_CODE_SENTINEL_COLLISION";

/// Disambiguates a computed exit code from the external-termination signature.
///
/// This is fail-closed disclosure, not a fallback: a failing run still fails and
/// nothing is retried or downgraded. Only the *encoding* of the failure changes,
/// and the substitution is announced on stderr as one structured line so no
/// caller can silently read a remapped code.
pub(crate) fn disambiguate_external_termination_signature(code: i32) -> i32 {
    if code != -1 {
        return code;
    }
    eprintln!(
        "{{\"code\":\"{ASTRO_EXIT_CODE_SENTINEL_COLLISION}\",\
\"message\":\"computed process exit code -1 (0xFFFFFFFF) collides with the Windows \
external-termination signature written by TerminateProcess(handle, -1) \
(Process.Kill/Stop-Process -Force); it is remapped to 0x{EXIT_CODE_SENTINEL_COLLISION:08X} so \
0xFFFFFFFF stays provably foreign\",\
\"remediation\":\"treat this exit code as the original in-process failure and read the run \
stderr for its cause; if a run record instead shows 0xFFFFFFFF, the process was terminated by \
another process - read C:\\\\ProgramData\\\\astrolabe-kill-attribution\\\\kills.log\"}}"
    );
    EXIT_CODE_SENTINEL_COLLISION as i32
}

/// Runs [`run_from_env`] on an explicitly sized host thread and returns its
/// process exit code.
///
/// **Every binary entrypoint must call this, never [`run_from_env`] directly.**
///
/// A process main thread's stack reserve is fixed by the PE header at link time
/// (1–2 MiB by default) and cannot be resized after start. Any dispatch mode —
/// `cli <tool>`, the stdio server loop, hook-augment — can enter the in-process
/// CBM pipeline, whose predump passes need several MiB of frame. Because
/// mingw-w64 emits a `___chkstk_ms` probe in the prologue of any function whose
/// frame exceeds one page, an oversized frame faults on *function entry*, before
/// a single log line: the process dies with a diagnostic-free
/// `STATUS_STACK_OVERFLOW` (`0xC00000FD`) and publishes no database.
///
/// #364 introduced the sized host thread but wired it into `src/main.rs` only,
/// so the `codebase-memory-mcp` shim — the binary the installed MCP server and
/// every CLI driver actually execute — still entered the pipeline on the
/// undersized process main thread and died exactly that way (#730). Centralising
/// the bootstrap here makes that class of divergence unrepresentable: a new
/// entrypoint gets the declared reserve by construction.
///
/// #1059: this is also the single place every `astrolabe-server` entrypoint's
/// exit code passes through, so the external-termination sentinel guard lives
/// here rather than being copied into each `main`.
pub fn run_from_env_on_sized_host_thread() -> i32 {
    let host = thread::Builder::new()
        .name(CBM_HOST_THREAD_NAME.to_string())
        .stack_size(cbm_pipeline_host_stack_bytes())
        .spawn(run_from_env)
        .expect("spawn sized CBM host thread");
    let code = match host.join() {
        Ok(code) => code,
        Err(_) => {
            eprintln!("astrolabe: CBM host thread panicked");
            1
        }
    };
    disambiguate_external_termination_signature(code)
}

pub fn run_from_env() -> i32 {
    let args: Vec<String> = env::args().collect();
    if args.len() == 1 {
        match connection_supervisor::run_if_installed_generation() {
            Ok(Some(code)) => return code,
            Ok(None) => {}
            Err(error) => {
                connection_supervisor::report_error(&error);
                return 1;
            }
        }
    }
    if args
        .get(1)
        .is_some_and(|arg| arg == connection_supervisor::INTERNAL_WORKER_ARG)
        && let Err(error) = connection_supervisor::validate_worker_invocation(&args[1..])
    {
        connection_supervisor::report_error(&error);
        return 1;
    }
    let hook_mode = is_hook_augment_invocation(&args);
    // #392: a `cli <tool>` invocation reserves stderr for warn/error so the
    // supported `--args-file`/stdin forms emit empty stderr (unblocks #377). It
    // is detected here — mirroring the hook-mode early branch — so both the
    // tracing subscriber and the libcbm log floor are raised before any startup
    // logging can reach stderr. Server (no-arg) dispatch is unaffected and keeps
    // INFO.
    let cli_mode = is_cli_invocation(&args);
    let json_logs = match astrolabe_bridge::initialize_cbm_log_configuration() {
        Ok(json_logs) => json_logs,
        Err(error) => {
            report_startup_error(&error, None);
            return 1;
        }
    };
    let _hook_deadline = hook_mode.then(|| HookDeadline::start(HOOK_AUGMENT_BUDGET_MS));
    let profile_active = match astrolabe_bridge::initialize_cbm_profile_mode() {
        Ok(active) => active,
        Err(error) => {
            if hook_mode {
                return 0;
            }
            report_startup_error(&error, Some(json_logs));
            return 1;
        }
    };
    if !hook_mode {
        if let Err(error) = initialize_tracing(
            if cli_mode && !profile_active {
                cli_stderr_tracing_level()
            } else {
                LevelFilter::INFO
            },
            json_logs,
        ) {
            report_startup_error(&error, Some(json_logs));
            return 1;
        }
        if let Err(error) = astrolabe_bridge::route_cbm_logs_to_tracing() {
            report_startup_error(&error, Some(json_logs));
            return 1;
        }
    }
    let binary_path = env::current_exe()
        .ok()
        .and_then(|path| path.into_os_string().into_string().ok())
        .or_else(|| args.first().cloned());

    let startup = if hook_mode {
        astrolabe_bridge::initialize_cbm_host_process_silent(binary_path.as_deref())
    } else if cli_mode {
        astrolabe_bridge::initialize_cbm_host_process_cli(binary_path.as_deref())
    } else {
        astrolabe_bridge::initialize_cbm_host_process(binary_path.as_deref())
    };
    if let Err(err) = startup {
        if hook_mode {
            return 0;
        }
        report_startup_error(&err, Some(json_logs));
        return 1;
    }

    match dispatch(&args[1..]) {
        Ok(code) => code,
        Err(err) => {
            if hook_mode {
                return 0;
            }
            eprintln!("astrolabe: {err}");
            1
        }
    }
}

fn dispatch(args: &[String]) -> Result<i32, DynError> {
    if args.is_empty() {
        return run_server();
    }

    match args[0].as_str() {
        "cli" => run_cli(&args[1..]),
        connection_supervisor::INTERNAL_WORKER_ARG => run_server(),
        "hook-augment" => run_hook_augment(),
        "install" | "uninstall" | "update" => run_installer_command(args[0].as_str(), &args[1..]),
        "ingest-cbm" => run_ingest_cbm(&args[1..]),
        "verify" => run_verify(&args[1..]),
        "--version" | "-V" => {
            println!("astrolabe {}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
        "--help" | "-h" => {
            print_usage();
            Ok(0)
        }
        other => Err(format!("unknown dispatch mode '{other}'").into()),
    }
}

fn report_startup_error(error: &BridgeError, json_logs: Option<bool>) {
    let error = error.envelope();
    if json_logs != Some(false) {
        let record = serde_json::json!({
            "level": "error",
            "event": "startup.failed",
            "code": &error.code,
            "message": &error.message,
            "remediation": &error.remediation,
        });
        let record = serde_json::to_string(&record)
            .expect("startup error fields always serialize as a JSON object");
        eprintln!("{record}");
    } else {
        eprintln!(
            "astrolabe: startup failed: {}: {}; remediation: {}",
            error.code, error.message, error.remediation
        );
    }
}

fn initialize_tracing(max_level: LevelFilter, json_logs: bool) -> Result<(), BridgeError> {
    if json_logs {
        tracing_subscriber::fmt()
            .json()
            .flatten_event(true)
            .with_current_span(false)
            .with_span_list(false)
            .with_writer(io::stderr)
            .with_ansi(false)
            .with_target(false)
            .without_time()
            .with_max_level(max_level)
            .try_init()
            .map_err(|error| {
                BridgeError::new(ErrorEnvelope::new(
                    "ASTRO_TRACING_INIT_FAILED",
                    format!("the JSON tracing subscriber could not be installed: {error}"),
                    "Remove the conflicting process-global tracing subscriber and restart with one authoritative log format.",
                ))
            })?;
    } else {
        tracing_subscriber::fmt()
            .with_writer(io::stderr)
            .with_ansi(false)
            .with_target(false)
            .without_time()
            .with_max_level(max_level)
            .try_init()
            .map_err(|error| {
                BridgeError::new(ErrorEnvelope::new(
                    "ASTRO_TRACING_INIT_FAILED",
                    format!("the text tracing subscriber could not be installed: {error}"),
                    "Remove the conflicting process-global tracing subscriber and restart with one authoritative log format.",
                ))
            })?;
    }
    Ok(())
}

/// True when argv is a `cli <tool> ...` invocation. Mirrors
/// [`is_hook_augment_invocation`] so the CLI stderr log floor is decided from the
/// same early argv inspection (#392).
fn is_cli_invocation(args: &[String]) -> bool {
    args.get(1).is_some_and(|arg| arg == "cli")
}

/// The tracing `max_level` for CLI stderr, derived from the single
/// registry-declared `cli_stderr_log_level_floor` knob (a libcbm `CBMLogLevel`
/// ordinal: `0`=debug..`4`=none) so one number governs both this subscriber and
/// the libcbm log floor (#392).
fn cli_stderr_tracing_level() -> LevelFilter {
    match astrolabe_domain::knobs::cli_stderr_log_level_floor() {
        0 => LevelFilter::TRACE,
        1 => LevelFilter::INFO,
        2 => LevelFilter::WARN,
        3 => LevelFilter::ERROR,
        _ => LevelFilter::OFF,
    }
}

fn print_usage() {
    eprintln!(
        "Usage: astrolabe [cli <tool> --args-file <path> | cli <tool> (JSON on stdin) | cli verify_chain --args-file <path> | ingest-cbm --sqlite <db> --vault <dir> --project <name> --commit <id> --vault-id <id> --vault-salt <salt> [--json] | hook-augment | install|uninstall|update | verify --deep --vault <dir> --vault-id <id> --vault-salt <salt>]\nSupply cli tool arguments via --args-file <path> or piped stdin; passing raw JSON as an argv token is no longer supported and is refused (ASTRO_CLI_RAW_JSON_ARGV_REMOVED).\n`astrolabe cli <tool> --help` (or -h) prints the tool's arguments from its schema and exits without running the tool (#416).\n`astrolabe cli --json <tool>` prints the raw result JSON on stdout and exits 1 when the result is isError:true, else 0 (#419).\n`ingest-cbm` imports one already-generated, frozen-schema CBM SQLite source through the production panel into a durable Calyx vault and fails closed before publication on coverage or vector drift.\nverify --deep exits 0 when verified and 1 on a named failure such as ASTRO_VERIFY_DEEP_FAILED."
    );
}

fn run_server() -> Result<i32, DynError> {
    let _watchdog = ParentWatchdog::start();
    let activation = activation_epoch::observe_worker_activation()?;
    let background_eligible = matches!(
        activation,
        activation_epoch::WorkerActivation::Workspace
            | activation_epoch::WorkerActivation::Active(_)
    );
    tracing::info!(
        activation = %serde_json::to_string(&activation_epoch::activation_status_json()?)?,
        background_eligible,
        "server.activation_epoch"
    );
    let _verify_chain_loop = background_eligible
        .then(VerifyChainLoop::start)
        .transpose()?;
    let mut incremental_watcher_loop = background_eligible.then(IncrementalWatcherLoop::start);
    tracing::info!("server.start version={}", env!("CARGO_PKG_VERSION"));
    let runner = CbmToolRunner::new_default()?;
    let resident_result = serve_resident_jsonrpc(&runner);
    if let Some(watcher) = incremental_watcher_loop.as_mut() {
        watcher.stop();
    }
    resident_result?;
    tracing::info!("server.shutdown");
    Ok(0)
}

#[derive(Debug)]
struct ResidentJsonrpcFrame {
    request: String,
    content_length_framed: bool,
}

#[derive(Debug)]
enum ResidentInput {
    Frame(ResidentJsonrpcFrame),
    Eof,
    Failed(String),
}

/// Shipping resident transport. A dedicated reader may block on the client's
/// stdin pipe, while the thread-affine CBM owner keeps a real coordination
/// clock and can close an affected cached SQLite store between requests.
fn serve_resident_jsonrpc(runner: &CbmToolRunner) -> Result<(), DynError> {
    use std::sync::mpsc::{RecvTimeoutError, sync_channel};

    // Capacity one preserves the original sequential backpressure: at most one
    // complete request can wait while the owner executes the current request.
    let (sender, receiver) = sync_channel::<ResidentInput>(1);
    thread::Builder::new()
        .name("astrolabe-stdio-reader".to_string())
        .spawn(move || {
            let stdin = io::stdin();
            let mut reader = stdin.lock();
            loop {
                match read_jsonrpc_frame(&mut reader) {
                    Ok(Some(frame)) => {
                        if sender.send(ResidentInput::Frame(frame)).is_err() {
                            return;
                        }
                    }
                    Ok(None) => {
                        let _ = sender.send(ResidentInput::Eof);
                        return;
                    }
                    Err(error) => {
                        let _ = sender.send(ResidentInput::Failed(error.to_string()));
                        return;
                    }
                }
            }
        })?;

    let stdout = io::stdout();
    let mut writer = stdout.lock();
    let cadence = Duration::from_millis(astrolabe_domain::knobs::WATCHER_DEFAULT_POLL_INTERVAL_MS);
    loop {
        match receiver.recv_timeout(cadence) {
            Ok(ResidentInput::Frame(frame)) => {
                if runner.quiesce_project_transition()? {
                    tracing::info!("server.project_transition_quiesced");
                }
                if let Some(response) = dispatch_jsonrpc_request(&frame.request, &mut |request| {
                    migration::handle_jsonrpc_raw(runner, request)
                })? {
                    if frame.content_length_framed {
                        write!(
                            writer,
                            "Content-Length: {}\r\n\r\n{}",
                            response.len(),
                            response
                        )?;
                    } else {
                        writeln!(writer, "{response}")?;
                    }
                    writer.flush()?;
                }
            }
            Ok(ResidentInput::Eof) => return Ok(()),
            Ok(ResidentInput::Failed(error)) => {
                return Err(format!(
                    "ASTRO_RESIDENT_STDIN_READ_FAILED: {error}; remediation: inspect the MCP client's stdin pipe and framing"
                )
                .into());
            }
            Err(RecvTimeoutError::Timeout) => {
                if runner.quiesce_project_transition()? {
                    tracing::info!("server.project_transition_quiesced");
                }
            }
            Err(RecvTimeoutError::Disconnected) => {
                return Err("ASTRO_RESIDENT_STDIN_READER_DISCONNECTED: the owner lost its stdin reader without EOF or a structured read failure; remediation: inspect the reader thread failure and reconnect the MCP client".into());
            }
        }
    }
}

fn read_jsonrpc_frame<R: BufRead>(
    reader: &mut R,
) -> Result<Option<ResidentJsonrpcFrame>, DynError> {
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            return Ok(None);
        }
        trim_line_ending(&mut line);
        if line.is_empty() {
            continue;
        }
        if let Some(content_len) = parse_content_length(&line)? {
            read_content_headers(reader)?;
            let mut body = vec![0_u8; content_len];
            reader.read_exact(&mut body)?;
            return Ok(Some(ResidentJsonrpcFrame {
                request: String::from_utf8(body)?,
                content_length_framed: true,
            }));
        }
        return Ok(Some(ResidentJsonrpcFrame {
            request: line.clone(),
            content_length_framed: false,
        }));
    }
}

pub fn serve_jsonrpc<R, W>(runner: &CbmToolRunner, reader: R, writer: W) -> Result<(), DynError>
where
    R: BufRead,
    W: Write,
{
    serve_jsonrpc_with_handler(reader, writer, |request| {
        migration::handle_jsonrpc_raw(runner, request)
    })
}

fn serve_jsonrpc_with_handler<R, W, F>(
    mut reader: R,
    mut writer: W,
    mut handler: F,
) -> Result<(), DynError>
where
    R: BufRead,
    W: Write,
    F: FnMut(&str) -> Result<Option<String>, DynError>,
{
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            return Ok(());
        }
        trim_line_ending(&mut line);
        if line.is_empty() {
            continue;
        }

        if let Some(content_len) = parse_content_length(&line)? {
            read_content_headers(&mut reader)?;
            let mut body = vec![0_u8; content_len];
            reader.read_exact(&mut body)?;
            let request = String::from_utf8(body)?;
            if let Some(response) = dispatch_jsonrpc_request(&request, &mut handler)? {
                write!(
                    writer,
                    "Content-Length: {}\r\n\r\n{}",
                    response.len(),
                    response
                )?;
                writer.flush()?;
            }
            continue;
        }

        if let Some(response) = dispatch_jsonrpc_request(&line, &mut handler)? {
            writeln!(writer, "{response}")?;
            writer.flush()?;
        }
    }
}

fn dispatch_jsonrpc_request<F>(
    request_json: &str,
    handler: &mut F,
) -> Result<Option<String>, DynError>
where
    F: FnMut(&str) -> Result<Option<String>, DynError>,
{
    match handler(request_json) {
        Ok(response) => Ok(response),
        Err(error) => handler_error_response(request_json, error.as_ref()),
    }
}

fn handler_error_response(
    request_json: &str,
    error: &(dyn Error + Send + Sync + 'static),
) -> Result<Option<String>, DynError> {
    let envelope = request_error_payload(error);
    tracing::warn!(
        code = %envelope
            .get("code")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("ASTRO_MCP_HANDLER_INTERNAL"),
        message = %envelope
            .get("message")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default(),
        "server.request_handler_error"
    );
    let Ok(request) = serde_json::from_str::<serde_json::Value>(request_json) else {
        return Ok(None);
    };
    let Some(request) = request.as_object() else {
        return Ok(None);
    };
    let Some(id) = request
        .get("id")
        .filter(|id| id.is_string() || id.is_number() || id.is_null())
        .cloned()
    else {
        return Ok(None);
    };

    let method = request
        .get("method")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();

    let response = if method == "tools/call" {
        let text = serde_json::to_string(&envelope)?;
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "content": [{"type": "text", "text": text}],
                "structuredContent": envelope,
                "isError": true
            }
        })
    } else {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32603,
                "message": "Internal error",
                "data": envelope
            }
        })
    };
    Ok(Some(serde_json::to_string(&response)?))
}

/// Classify an error that escaped a request handler into the envelope the caller
/// is contractually told to act on.
///
/// #910: this used to downcast only to a directly-attached [`BridgeError`] and
/// relabel *everything else* `ASTRO_MCP_HANDLER_INTERNAL`, with a remediation
/// about inspecting "the named persisted store or lock". A caller who passed a
/// path that does not exist was therefore told the server had an internal fault
/// and sent to investigate store and lock state that the request never touched —
/// while the accurate diagnosis and remediation sat unread inside the message
/// string. `*_INTERNAL` also implies a retry might help, when the request can
/// never succeed unchanged.
///
/// Now any error carrying a structured envelope — a [`ToolFault`] or a
/// [`BridgeError`], at any depth of the source chain — keeps its own code and its
/// own remediation. `ASTRO_MCP_HANDLER_INTERNAL` is reserved for what it was
/// always meant to mean: a genuine internal fault that carries no envelope at
/// all, where "retry, then inspect diagnostics" is honest advice.
fn request_error_payload(error: &(dyn Error + Send + Sync + 'static)) -> serde_json::Value {
    if let Some(fault) = migration::tool_fault_from_error(error) {
        return fault;
    }
    serde_json::json!({
        "schema": migration::TOOL_FAULT_SCHEMA,
        "status": "error",
        "code": "ASTRO_MCP_HANDLER_INTERNAL",
        "message": error.to_string(),
        "remediation": "Retry the request after checking the named persisted store or lock; if it repeats, inspect Astrolabe diagnostics while keeping the MCP session open.",
    })
}

fn trim_line_ending(line: &mut String) {
    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
}

fn parse_content_length(line: &str) -> Result<Option<usize>, DynError> {
    let Some(raw) = line.strip_prefix("Content-Length:") else {
        return Ok(None);
    };
    let value = raw.trim().parse::<usize>()?;
    const MAX_FRAME: usize = 64 * 1024 * 1024;
    if value > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "content frame too large").into());
    }
    Ok(Some(value))
}

fn read_content_headers<R>(reader: &mut R) -> Result<(), DynError>
where
    R: BufRead,
{
    let mut header = String::new();
    loop {
        header.clear();
        if reader.read_line(&mut header)? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF while reading content headers",
            )
            .into());
        }
        trim_line_ending(&mut header);
        if header.is_empty() {
            return Ok(());
        }
    }
}

fn run_cli(args: &[String]) -> Result<i32, DynError> {
    let mut args = args.to_vec();
    let raw_json = strip_flag(&mut args, "--json");
    let progress = strip_flag(&mut args, "--progress");
    let index_worker = strip_flag(&mut args, "--index-worker");
    let response_out = strip_flag_value(&mut args, "--response-out");
    let worker_progress_out = strip_flag_value(&mut args, "--worker-progress-out");
    let worker_progress_attempt = strip_flag_value(&mut args, "--worker-progress-attempt");
    if worker_progress_out.is_some() != worker_progress_attempt.is_some() {
        return Err("ASTRO_INDEX_WORKER_PROGRESS_CONFIGURATION_MISSING: --worker-progress-out and --worker-progress-attempt must be supplied together".into());
    }
    if !index_worker && worker_progress_out.is_some() {
        return Err("ASTRO_INDEX_WORKER_PROGRESS_ROLE_INVALID: semantic progress arguments are private to --index-worker".into());
    }
    // #515/#530 internal pooled historical-index extraction serve worker. Spawned ONCE
    // per recycle interval by `run_git_archaeology` (git_archaeology.rs) and served every
    // evidence commit's extraction serially over an atomic request/response file handshake,
    // so a C-level CBM pipeline fault on a historical checkout is contained in THIS child
    // process (the host `index_repository` never hard-exits with a silent empty-stdout
    // rc=127) while the #515 per-commit spawn+init cost is amortized to once per interval.
    // Not a user-facing tool: it consumes `--pool-dir <dir>` and communicates only via the
    // handshake files under it. Handled before tool-name resolution because it is not a CBM
    // tool. A ParentWatchdog ties it to the parent so a dead parent never orphans it.
    if strip_flag(&mut args, "--archaeology-extract-serve") {
        let _worker_watchdog = ParentWatchdog::start();
        let pool_dir = strip_flag_value(&mut args, "--pool-dir").ok_or_else(|| -> DynError {
            "ASTRO_ARCHAEOLOGY_EXTRACT_SERVE_POOL_DIR_MISSING: --archaeology-extract-serve requires --pool-dir <path>".into()
        })?;
        return migration::run_archaeology_extract_serve(&pool_dir);
    }
    if args.is_empty() {
        return Err("Usage: astrolabe cli [--json] [--progress] <tool_name> [--args-file <path> | (JSON on stdin)] (raw '<json>' argv is no longer supported).\n  --json prints the raw tool result JSON on stdout and exits 1 when the result is isError:true (0 otherwise), so RC-based callers see tool failures (#419).\n  <tool_name> --help prints the tool's arguments and exits without running it (#416).".into());
    }

    let _worker_watchdog = index_worker.then(ParentWatchdog::start);
    let tool_name = args.remove(0);

    // #416: a per-tool `--help`/`-h` anywhere in the tool's argument tail prints
    // help and exits WITHOUT running the tool — the shipped host previously
    // swallowed `--help` into the empty-args path and silently executed the tool
    // (a silent-fallback-shaped defect). The scan is over the args AFTER the tool
    // name, matching the standalone cbm binary's contract exactly (both `--help`
    // and `-h`). Help is resolved before argument resolution so it never blocks on
    // stdin and before any store work, so no store is opened or mutated.
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        return run_cli_tool_help(&tool_name);
    }

    let args_json = resolve_cli_args(&args)?;
    let worker_configuration = if index_worker {
        Some(configure_index_worker(&args_json)?)
    } else {
        None
    };
    let (args_json, transition_writer_project) = worker_configuration.map_or_else(
        || (args_json, None),
        |configuration| {
            (
                configuration.args_json,
                configuration.transition_writer_project,
            )
        },
    );
    let worker_role = if index_worker {
        Some(astrolabe_bridge::CbmIndexWorkerRole::activate(
            response_out.as_deref(),
            worker_progress_out.as_deref(),
            worker_progress_attempt.as_deref(),
            transition_writer_project.as_deref(),
        )?)
    } else {
        None
    };
    if progress {
        eprintln!("astrolabe cli progress: start tool={tool_name}");
    }
    if tool_name == "verify_chain" {
        let code = run_verify_chain_cli(&args_json, raw_json, response_out.as_deref())?;
        if let Some(role) = worker_role.as_ref() {
            role.complete_progress()?;
        }
        if progress {
            eprintln!("astrolabe cli progress: done tool={tool_name} exit={code}");
        }
        return Ok(code);
    }

    let runner = CbmToolRunner::new_default()?;
    let outcome = if index_worker {
        runner
            .handle_tool_raw(&tool_name, &args_json)
            .map_err(DynError::from)
    } else {
        migration::handle_tool_raw(&runner, &tool_name, &args_json)
    };
    // #919: a caller-correctable refusal that escaped its handler as `Err` used
    // to leave the CLI through the top-level `astrolabe: {Display}` stderr line,
    // producing empty stdout and no JSON at all — even under `--json`. An agent
    // driving the CLI saw exit 1 and an English sentence where every other
    // refusal on the same surface gave it a structured result to read. Convert it
    // here, at the tool boundary, so the fault reaches the caller in exactly the
    // shape a handler-returned refusal has. A genuine internal fault carries no
    // envelope and still propagates to the existing stderr path.
    let result = match outcome {
        Ok(result) => result,
        Err(error) => match migration::tool_fault_result_from_error(error.as_ref()) {
            Some(fault_result) => fault_result?,
            None => return Err(error),
        },
    };
    if let Some(path) = response_out.as_ref() {
        fs::write(path, &result)?;
    }
    if index_worker {
        if let Some(role) = worker_role.as_ref() {
            role.complete_progress()?;
        }
        // #282 (attempt 15): the response file is a supervised worker's ONLY
        // result channel — its stdout/stderr are the supervisor's log handle
        // (or worse, whatever handle state the spawn produced), so printing
        // the result there at best duplicates the payload into the log and at
        // worst makes a fully-successful index depend on stdout health for
        // its exit code. Exit with the tool outcome and write nothing.
        return Ok(mcp_result_exit_code(&result));
    }

    if raw_json {
        // #419: the JSON payload is unchanged (byte-for-byte on stdout), but the
        // process exit code now reflects the tool outcome — `isError: true` exits
        // 1 so any RC-based caller (scripts, FSV drivers, agents checking `$?`)
        // sees the failure instead of reading a `--json` success. This matches the
        // non-`--json` path (`print_mcp_tool_result`) and the wider CLI convention
        // (git/gh/kubectl) that command failure is signalled by a non-zero exit,
        // with `--json` changing only stdout format, not the failure signal.
        println!("{result}");
        let code = mcp_result_exit_code(&result);
        if progress {
            eprintln!("astrolabe cli progress: done tool={tool_name} exit={code}");
        }
        return Ok(code);
    }

    let code = print_mcp_tool_result(&result)?;
    if progress {
        eprintln!("astrolabe cli progress: done tool={tool_name} exit={code}");
    }
    Ok(code)
}

/// Applies the supervisor-supplied cache directory inside the isolated worker
/// process, then strips only the cache/grant transport fields before libcbm sees
/// the tool arguments. Repository compilation context intentionally remains:
/// the C pipeline owns an exact copy for this generation. The parent process
/// never changes its global resolver, so other MCP runners cannot accidentally
/// resolve the transaction-owned stage.
struct IndexWorkerConfiguration {
    args_json: String,
    transition_writer_project: Option<String>,
}

fn configure_index_worker(args_json: &str) -> Result<IndexWorkerConfiguration, DynError> {
    let mut value: serde_json::Value = serde_json::from_str(args_json)?;
    let object = value.as_object_mut().ok_or_else(|| -> DynError {
        "ASTRO_INDEX_WORKER_ARGS_OBJECT_REQUIRED: supervised index arguments must be a JSON object"
            .into()
    })?;
    let cache_dir = object.remove(ASTRO_INDEX_WORKER_CACHE_DIR_ARG);
    let transition_grant = object.remove(ASTRO_INDEX_WORKER_TRANSITION_GRANT_ARG);
    let (cache_dir, transition_grant) = match (cache_dir, transition_grant) {
        (None, None) => {
            // Non-shadow supervisors (HTTP/session auto-index) use the inherited
            // resolver and do not carry Astrolabe's private stage binding.
            return Ok(IndexWorkerConfiguration {
                args_json: args_json.to_string(),
                transition_writer_project: None,
            });
        }
        (Some(cache_dir), Some(transition_grant)) => (cache_dir, transition_grant),
        _ => {
            return Err(
                "ASTRO_INDEX_WORKER_PRIVATE_BINDING_INCOMPLETE: the shadow worker cache and transition writer grant must be supplied together; remediation: preserve the request and inspect the parent supervisor argument builder"
                    .into(),
            );
        }
    };
    let cache_dir = cache_dir.as_str().ok_or_else(|| -> DynError {
        "ASTRO_INDEX_WORKER_CACHE_DIR_INVALID: supervised shadow worker cache directory must be a UTF-8 string"
            .into()
    })?;
    let requested = Path::new(cache_dir);
    let transition_writer_project =
        migration::validate_index_worker_transition_grant(transition_grant, &value, requested)?;
    let resolved = astrolabe_bridge::set_cbm_cache_dir(requested)?;
    if resolved != requested {
        return Err(format!(
            "ASTRO_INDEX_WORKER_CACHE_DIR_READBACK: worker resolved {} after transaction cache {} was requested",
            resolved.display(),
            requested.display()
        )
        .into());
    }
    Ok(IndexWorkerConfiguration {
        args_json: serde_json::to_string(&value)?,
        transition_writer_project: Some(transition_writer_project),
    })
}

/// Print per-tool `--help` for `astrolabe cli <tool> --help` (#416) and return 0
/// WITHOUT running the tool. cbm MCP tools are described by the single shared C
/// help formatter (one schema source of truth, branded `astrolabe`).
/// `verify_chain` is an astrolabe-host-only tool with no cbm input schema, so its
/// supported form is printed here directly. ASTROLABE-NATIVE tools served by the
/// Rust dispatch (not in the C schema registry — e.g. `get_provenance`,
/// `kernel_answer`, `anchor_erase`) are described from their `tool_defs` JSON
/// schema, matching the C formatter's output shape (#428). Only a tool in NEITHER
/// registry is refused fail-closed with a labeled `ASTRO_CLI_UNKNOWN_TOOL` error
/// rather than silently executed.
fn run_cli_tool_help(tool_name: &str) -> Result<i32, DynError> {
    if tool_name == "verify_chain" {
        println!("Usage:");
        println!("  astrolabe cli verify_chain --args-file <path-to-json>");
        println!("  echo '<json>' | astrolabe cli verify_chain");
        println!();
        println!("Arguments (JSON object keys):");
        println!(
            "  vault <string> [required]  Path to the vault directory whose ledger chain is verified (alias: vault_dir)"
        );
        return Ok(0);
    }
    let known = astrolabe_bridge::cbm_print_tool_help("astrolabe", tool_name)?;
    if known {
        return Ok(0);
    }
    // #428: the C schema registry does not know this tool, but the astrolabe-native
    // half of the surface (served by the Rust dispatch — e.g. get_provenance,
    // kernel_answer, anchor_erase) might. Consult the SAME native registry the run
    // path dispatches from (astrolabe_tool_definitions / is_advertised_astrolabe_tool)
    // and print real per-tool help derived from that tool's tool_defs JSON schema,
    // matching the C formatter's output shape. A native tool EXISTS and runs on this
    // surface, so refusing it with ASTRO_CLI_UNKNOWN_TOOL was a factual mislabel;
    // only a name in NEITHER registry is genuinely unknown.
    if migration::print_astrolabe_native_tool_help("astrolabe", tool_name)? {
        return Ok(0);
    }
    Err(format!(
        "ASTRO_CLI_UNKNOWN_TOOL: no such tool '{tool_name}', cannot print --help. \
         remediation: run `astrolabe cli <tool> --help` with a valid tool name; list the \
         available tools by running the server (`astrolabe`) and calling `tools/list`."
    )
    .into())
}

fn run_verify_chain_cli(
    args_json: &str,
    raw_json: bool,
    response_out: Option<&str>,
) -> Result<i32, DynError> {
    let value = serde_json::from_str::<serde_json::Value>(args_json)?;
    let vault = value
        .get("vault")
        .or_else(|| value.get("vault_dir"))
        .and_then(serde_json::Value::as_str)
        .ok_or("verify_chain requires JSON arg {\"vault\":\"<dir>\"}")?;

    let report = astrolabe_ingest::verify_chain_vault_path(vault)?;
    let json = serde_json::to_string(&report)?;
    if let Some(path) = response_out {
        fs::write(path, &json)?;
    }
    if raw_json {
        println!("{json}");
    } else {
        print_verify_chain_report(&report);
    }
    Ok(verify_chain_exit_code(&report))
}

fn print_verify_chain_report(report: &astrolabe_ingest::VerifyChainReport) {
    match report.status.as_str() {
        "intact" => println!(
            "ledger chain intact: rows={} checked={}..{} count={}",
            report.ledger_rows, report.checked_range_start, report.checked_range_end, report.count
        ),
        "broken" => println!(
            "ledger chain broken: at_seq={} quarantine_seq={} checked={}..{} expected_hash={} found_hash={}",
            report.at_seq.unwrap_or_default(),
            report.quarantine_seq.unwrap_or_default(),
            report.checked_range_start,
            report.checked_range_end,
            report.expected_hash.as_deref().unwrap_or(""),
            report.found_hash.as_deref().unwrap_or("")
        ),
        "corrupt" => println!(
            "ledger chain corrupt: at_seq={} quarantine_seq={} checked={}..{} reason={}",
            report.at_seq.unwrap_or_default(),
            report.quarantine_seq.unwrap_or_default(),
            report.checked_range_start,
            report.checked_range_end,
            report.reason.as_deref().unwrap_or("")
        ),
        other => println!("ledger chain {other}: rows={}", report.ledger_rows),
    }
}

fn verify_chain_exit_code(report: &astrolabe_ingest::VerifyChainReport) -> i32 {
    if report.is_intact() { 0 } else { 1 }
}

fn run_ingest_cbm(args: &[String]) -> Result<i32, DynError> {
    let mut args = args.to_vec();
    let raw_json = strip_flag(&mut args, "--json");
    let sqlite =
        strip_flag_value(&mut args, "--sqlite").ok_or("ingest-cbm requires --sqlite <db>")?;
    let vault_dir = strip_flag_value(&mut args, "--vault")
        .or_else(|| strip_flag_value(&mut args, "--vault-dir"))
        .ok_or("ingest-cbm requires --vault <dir>")?;
    let project =
        strip_flag_value(&mut args, "--project").ok_or("ingest-cbm requires --project")?;
    let commit = strip_flag_value(&mut args, "--commit").ok_or("ingest-cbm requires --commit")?;
    let vault_id = strip_flag_value(&mut args, "--vault-id")
        .ok_or("ingest-cbm requires --vault-id")?
        .parse::<calyx_core::VaultId>()?;
    let vault_salt =
        strip_flag_value(&mut args, "--vault-salt").ok_or("ingest-cbm requires --vault-salt")?;
    let panel_version = strip_flag_value(&mut args, "--panel-version")
        .map(|value| value.parse::<u32>())
        .transpose()?
        .unwrap_or(migration::SHADOW_PANEL_VERSION);
    if !args.is_empty() {
        return Err(format!("unknown ingest-cbm arguments: {}", args.join(" ")).into());
    }

    let vault = calyx_aster::vault::AsterVault::new_durable(
        &vault_dir,
        vault_id,
        vault_salt.as_bytes().to_vec(),
        calyx_aster::vault::VaultOptions::default(),
    )?;
    let workers = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .map_err(|error| {
            format!(
                "ASTRO_INGEST_PARALLELISM_UNAVAILABLE: failed to measure the host worker budget before importing CBM SQLite: {error}; remediation: correct the operating-system processor query failure and retry the unchanged source"
            )
        })?;
    let options = astrolabe_ingest::SqliteImportOptions::new(&project, &commit, panel_version)
        .with_workers(workers)
        .with_available_slots(migration::shadow_available_slots());
    match astrolabe_ingest::import_sqlite_to_vault(
        &sqlite,
        &vault,
        &migration::ShadowSlotRuntime,
        &options,
    ) {
        Ok(report) => {
            if raw_json {
                println!(
                    "{}",
                    serde_json::to_string(&serde_json::json!({
                        "schema": "astrolabe.ingest-cbm.v1",
                        "status": "imported",
                        "sqlite": sqlite,
                        "vault": vault_dir,
                        "project": project,
                        "panel_version": panel_version,
                        "report": report,
                    }))?
                );
            } else {
                println!(
                    "CBM semantic import complete: project={} panel_version={} nodes={} semantic_constellations={} present_atoms={} uncovered_atoms={} seq={}",
                    project,
                    panel_version,
                    report.sqlite_nodes,
                    report.semantic_constellation_inputs,
                    report.semantic_present_atoms,
                    report.semantic_uncovered_atoms,
                    report.seq,
                );
            }
            Ok(0)
        }
        Err(error) => {
            let code = error.code().unwrap_or("ASTRO_INGEST_INVALID");
            let remediation = error.remediation().unwrap_or(
                "Correct the named CBM source field or schema, preserve the prior vault generation, and retry the same import.",
            );
            if raw_json {
                println!(
                    "{}",
                    serde_json::to_string(&serde_json::json!({
                        "schema": "astrolabe.error.v1",
                        "status": "error",
                        "code": code,
                        "message": error.message(),
                        "remediation": remediation,
                        "sqlite": sqlite,
                        "vault": vault_dir,
                        "project": project,
                        "panel_version": panel_version,
                    }))?
                );
            } else {
                eprintln!("{code}: {}; remediation: {remediation}", error.message());
            }
            Ok(1)
        }
    }
}

fn run_verify(args: &[String]) -> Result<i32, DynError> {
    let mut args = args.to_vec();
    let raw_json = strip_flag(&mut args, "--json");
    let deep = strip_flag(&mut args, "--deep");
    let vault = strip_flag_value(&mut args, "--vault")
        .or_else(|| strip_flag_value(&mut args, "--vault-dir"))
        .ok_or("verify requires --vault <dir>")?;
    let vault_id = strip_flag_value(&mut args, "--vault-id").ok_or("verify requires --vault-id")?;
    let vault_salt =
        strip_flag_value(&mut args, "--vault-salt").ok_or("verify requires --vault-salt")?;
    if !deep {
        return Err("verify currently requires --deep".into());
    }
    if !args.is_empty() {
        return Err(format!("unknown verify arguments: {}", args.join(" ")).into());
    }

    let report = astrolabe_ingest::verify_deep_vault_path(&vault, &vault_id, &vault_salt)?;
    let complete_associations = astrolabe_weave::read_complete_association_state_vault_path(
        &vault,
        &vault_id,
        &vault_salt,
    )?;
    let projection_vault = migration::open_shadow_vault_historical_read_only(
        Path::new(&vault),
        &vault_id,
        &vault_salt,
        vec![
            calyx_aster::cf::ColumnFamily::Graph,
            calyx_aster::cf::ColumnFamily::Kernel,
            calyx_aster::cf::ColumnFamily::Ledger,
        ],
    )?;
    let composite_kernel_projection =
        astrolabe_ingest::verify_composite_kernel_projection(&projection_vault)?;
    if raw_json {
        let mut payload = serde_json::to_value(&report)?;
        let object = payload
            .as_object_mut()
            .ok_or("verify --deep report did not serialize as an object")?;
        object.insert(
            "complete_associations".to_string(),
            serde_json::to_value(&complete_associations)?,
        );
        object.insert(
            "composite_kernel_projection".to_string(),
            serde_json::to_value(&composite_kernel_projection)?,
        );
        println!("{}", serde_json::to_string(&payload)?);
    } else {
        println!(
            "series registry verified: series_rows={} reverse_rows={} qn_index_rows={} recurrence_rows={} split_rows={} sqlite_node_map_rows={} sqlite_structural_rows={} sqlite_constellation_rows={} sqlite_edge_rows={} ledger_chain_status={} ledger_rows={} ledger_payload_rows={} base_ledger_pairs={} association_constellations={} association_pairs={} association_computed={} association_typed_incompatible={} association_witness_state_hash={} composite_typed_edges={} composite_sim_edges={} composite_sim_only={} composite_nodes={} composite_edges={} composite_source_fingerprint={}",
            report.series_rows,
            report.reverse_rows,
            report.qn_index_rows,
            report.recurrence_rows,
            report.split_rows,
            report.sqlite_node_map_rows,
            report.sqlite_structural_rows,
            report.sqlite_constellation_rows,
            report.sqlite_edge_rows,
            report.ledger_chain_status,
            report.ledger_rows,
            report.ledger_payload_rows,
            report.base_ledger_pairs,
            complete_associations.constellation_count,
            complete_associations.expected_pair_count,
            complete_associations.computed_pair_count,
            complete_associations.typed_incompatible_pair_count,
            complete_associations.witness_state_hash,
            composite_kernel_projection.source_typed_edge_rows,
            composite_kernel_projection.source_sim_edge_rows,
            composite_kernel_projection.sim_only_source_edge_count,
            composite_kernel_projection.node_count,
            composite_kernel_projection.edge_count,
            composite_kernel_projection.source_fingerprint_blake3,
        );
    }
    Ok(0)
}

fn strip_flag(args: &mut Vec<String>, flag: &str) -> bool {
    if let Some(index) = args.iter().position(|arg| arg == flag) {
        args.remove(index);
        true
    } else {
        false
    }
}

fn strip_flag_value(args: &mut Vec<String>, flag: &str) -> Option<String> {
    let index = args.iter().position(|arg| arg == flag)?;
    args.remove(index);
    if index < args.len() {
        Some(args.remove(index))
    } else {
        None
    }
}

/// Fail-closed code for the removed raw-JSON argv form (#378). The deprecation
/// window closed at wave-15: #377 migrated every owned invocation site to
/// `--args-file`/stdin and recorded that this repo has no external installed
/// base to protect, so the form is rejected rather than warned.
const ASTRO_CLI_RAW_JSON_ARGV_REMOVED: &str = "ASTRO_CLI_RAW_JSON_ARGV_REMOVED";

/// How the leading `cli` argv supplies the tool JSON. [`CliArgSource::RawJsonArgv`]
/// is still *detected* here so it can be refused fail-closed (#378); `--args-file
/// <path>` and piped stdin are the only supported forms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CliArgSource {
    /// `cli <tool> --args-file <path>` — JSON read from a file.
    ArgsFile,
    /// `cli <tool> '{...}'` — raw JSON as an argv token (removed; refused fail-closed).
    RawJsonArgv,
}

/// Classify how the remaining `cli` arguments (after the tool name) supply the
/// tool JSON, performing no I/O. Returns `None` when the argv carries no
/// inline arguments, in which case the caller falls back to piped stdin (or an
/// empty object). Kept pure so the deprecation-vs-supported split is unit
/// testable without touching real stdin/stderr.
fn classify_cli_argv(args: &[String]) -> Option<CliArgSource> {
    if args.len() >= 2 && args[0] == "--args-file" {
        return Some(CliArgSource::ArgsFile);
    }
    if let Some(first) = args.first()
        && first.trim_start().starts_with('{')
    {
        return Some(CliArgSource::RawJsonArgv);
    }
    None
}

fn resolve_cli_args(args: &[String]) -> Result<String, DynError> {
    match classify_cli_argv(args) {
        Some(CliArgSource::ArgsFile) => Ok(fs::read_to_string(&args[1])?),
        Some(CliArgSource::RawJsonArgv) => Err(format!(
            "{ASTRO_CLI_RAW_JSON_ARGV_REMOVED}: passing raw JSON as a 'cli' argv token is no longer \
             supported. remediation: write the JSON to a file and pass `--args-file <path>`, or \
             pipe it on stdin (e.g. `astrolabe cli <tool> --args-file args.json` or \
             `echo '<json>' | astrolabe cli <tool>`)."
        )
        .into()),
        None => {
            if !io::stdin().is_terminal() {
                let mut text = String::new();
                io::stdin().read_to_string(&mut text)?;
                if !text.is_empty() {
                    return Ok(text);
                }
            }
            Ok("{}".to_string())
        }
    }
}

/// Exit code for an MCP tool result string: 1 for `isError: true`, else 0
/// (unparseable results count as success, matching `print_mcp_tool_result`).
fn mcp_result_exit_code(result: &str) -> i32 {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(result) else {
        return 0;
    };
    let is_error = value
        .get("isError")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    i32::from(is_error)
}

fn print_mcp_tool_result(result: &str) -> Result<i32, DynError> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(result) else {
        println!("{result}");
        return Ok(0);
    };
    let is_error = value
        .get("isError")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let text = value
        .get("content")
        .and_then(serde_json::Value::as_array)
        .and_then(|content| content.first())
        .and_then(|item| item.get("text"))
        .and_then(serde_json::Value::as_str);

    if let Some(text) = text {
        if is_error {
            eprintln!("{text}");
        } else {
            println!("{text}");
        }
    } else {
        println!("{result}");
    }

    Ok(if is_error { 1 } else { 0 })
}

struct ParentWatchdog {
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

struct VerifyChainLoop {
    shutdown: Option<std::sync::mpsc::Sender<()>>,
    handle: Option<JoinHandle<()>>,
}

struct IncrementalWatcherLoop {
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl IncrementalWatcherLoop {
    fn start() -> Self {
        let shutdown = Arc::new(AtomicBool::new(false));
        let thread_shutdown = Arc::clone(&shutdown);
        // #364: this loop enters the in-process CBM pipeline (via
        // run_incremental_watcher_loop -> handle_index_repository), which
        // consumes >2 MiB of stack before its first log line. A bare
        // `thread::spawn` gives Rust's default 2 MiB stack, which overflows with
        // a diagnostic-free STATUS_STACK_OVERFLOW (0xC00000FD). Size the host
        // thread from the registry-declared knob so real indexing cannot die
        // undiagnosed on a default stack.
        let handle = thread::Builder::new()
            .name("astrolabe-incremental-watcher".to_string())
            .stack_size(astrolabe_domain::knobs::cbm_pipeline_host_stack_bytes())
            .spawn(move || {
                if let Err(error) = migration::run_incremental_watcher_loop(thread_shutdown) {
                    tracing::warn!("incremental_watcher.stopped error={error}");
                }
            })
            .expect("spawn sized incremental-watcher thread");
        Self {
            shutdown,
            handle: Some(handle),
        }
    }

    fn stop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        astrolabe_bridge::request_supervised_index_shutdown();
        if let Some(handle) = self.handle.take()
            && let Err(error) = handle.join()
        {
            tracing::error!(
                code = "ASTRO_INCREMENTAL_WATCHER_JOIN_FAILED",
                panic = ?error,
                "incremental_watcher.join_failed"
            );
        }
    }
}

impl Drop for IncrementalWatcherLoop {
    fn drop(&mut self) {
        self.stop();
    }
}

impl VerifyChainLoop {
    fn start() -> Result<Self, DynError> {
        if verify_chain_loop_disabled()? {
            tracing::info!("verify_chain_loop.disabled source=ASTROLABE_VERIFY_CHAIN_LOOP");
            return Ok(Self {
                shutdown: None,
                handle: None,
            });
        }

        let interval = verify_chain_loop_interval()?;
        // #277: one-time deep boot gate before the steady-state bounded scrub lane
        // begins — re-hashes each project's whole persisted ledger from genesis and
        // refuses foreground admission on a tampered/damaged store. The readiness
        // record is durable before the server constructs its request runner.
        let report = migration::janitor_startup_verify_projects(
            u64::try_from(interval.as_millis()).map_err(|error| -> DynError {
                format!(
                    "ASTRO_VERIFY_CHAIN_INTERVAL_OVERFLOW: periodic interval cannot be \
                     represented as u64 milliseconds: {error}. Remediation: repair the \
                     ASTROLABE_VERIFY_CHAIN_INTERVAL_MS setting before restarting the server."
                )
                .into()
            })?,
        )?;
        if report.damaged_projects != 0 {
            return Err(format!(
                "ASTRO_VERIFY_CHAIN_STARTUP_DAMAGED: startup verification found {} damaged \
                 project vault(s) among {} checked / {} discovered; foreground MCP admission \
                 is refused. Remediation: inspect each project's persisted \
                 periodic_verify_error, repair the exact damaged chain, and run a deep verify \
                 before restarting the server.",
                report.damaged_projects, report.checked_projects, report.discovered_projects,
            )
            .into());
        }
        tracing::info!(
            "verify_chain_loop.ready checked_projects={} discovered_projects={} interval_ms={}",
            report.checked_projects,
            report.discovered_projects,
            interval.as_millis(),
        );

        let (shutdown_sender, shutdown_receiver) = std::sync::mpsc::channel();
        let handle = thread::spawn(move || {
            loop {
                match shutdown_receiver.recv_timeout(interval) {
                    Ok(()) => break,
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        tracing::error!(
                            "verify_chain_loop.shutdown_channel_disconnected \
                             code=ASTRO_VERIFY_CHAIN_SHUTDOWN_CHANNEL_DISCONNECTED"
                        );
                        break;
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                }
                if let Err(error) =
                    activation_epoch::require_active_generation("periodic_verify_chain_tick")
                {
                    tracing::warn!(
                        code = "ASTRO_INSTALLED_GENERATION_RETIRED",
                        error = %error,
                        "verify_chain_loop.retired"
                    );
                    break;
                }
                match migration::periodic_verify_chain_tick() {
                    Ok(report) => {
                        if report.skipped_import_in_progress_projects == 0 {
                            tracing::debug!(
                                "verify_chain_loop.tick checked_projects={}",
                                report.checked_projects
                            );
                        } else {
                            tracing::info!(
                                "verify_chain_loop.tick_contention \
                                 status=skipped_import_in_progress \
                                 operation=periodic_verify_scrub_project checked_projects={} \
                                 skipped_projects={}",
                                report.checked_projects,
                                report.skipped_import_in_progress_projects,
                            );
                        }
                    }
                    Err(error) => {
                        tracing::warn!("verify_chain_loop.tick_failed error={error}");
                    }
                }
            }
        });

        Ok(Self {
            shutdown: Some(shutdown_sender),
            handle: Some(handle),
        })
    }
}

impl Drop for VerifyChainLoop {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take()
            && shutdown.send(()).is_err()
        {
            tracing::error!(
                "verify_chain_loop.shutdown_send_failed \
                 code=ASTRO_VERIFY_CHAIN_SHUTDOWN_SEND_FAILED"
            );
        }
        if let Some(handle) = self.handle.take()
            && handle.join().is_err()
        {
            tracing::error!(
                "verify_chain_loop.thread_panicked \
                 code=ASTRO_VERIFY_CHAIN_THREAD_PANICKED"
            );
        }
    }
}

fn verify_chain_loop_disabled() -> Result<bool, DynError> {
    verify_chain_loop_disabled_from_raw(env::var("ASTROLABE_VERIFY_CHAIN_LOOP").ok().as_deref())
}

fn verify_chain_loop_disabled_from_raw(raw: Option<&str>) -> Result<bool, DynError> {
    let Some(value) = raw else {
        return Ok(false);
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "on" => Ok(false),
        "0" | "false" | "off" => Ok(true),
        other => Err(format!(
            "ASTRO_VERIFY_CHAIN_LOOP_POLICY_INVALID: ASTROLABE_VERIFY_CHAIN_LOOP is {other:?}, \
             expected one of 1/true/on or 0/false/off. Remediation: repair or remove the exact \
             environment value before restarting the server."
        )
        .into()),
    }
}

fn verify_chain_loop_interval() -> Result<Duration, DynError> {
    verify_chain_loop_interval_from_raw(
        env::var("ASTROLABE_VERIFY_CHAIN_INTERVAL_MS")
            .ok()
            .as_deref(),
    )
}

fn verify_chain_loop_interval_from_raw(raw: Option<&str>) -> Result<Duration, DynError> {
    let millis = match raw {
        None => VERIFY_CHAIN_LOOP_DEFAULT_INTERVAL_MS,
        Some(value) => value.trim().parse::<u64>().map_err(|error| -> DynError {
            format!(
                "ASTRO_VERIFY_CHAIN_INTERVAL_INVALID: ASTROLABE_VERIFY_CHAIN_INTERVAL_MS is \
                 {value:?}, not an unsigned integer: {error}. Remediation: repair or remove the \
                 exact environment value before restarting the server."
            )
            .into()
        })?,
    };
    if millis < VERIFY_CHAIN_LOOP_MIN_INTERVAL_MS {
        return Err(format!(
            "ASTRO_VERIFY_CHAIN_INTERVAL_BELOW_MINIMUM: ASTROLABE_VERIFY_CHAIN_INTERVAL_MS is \
             {millis}, below the declared minimum {VERIFY_CHAIN_LOOP_MIN_INTERVAL_MS}. \
             Remediation: configure an admitted interval without relying on silent clamping."
        )
        .into());
    }
    Ok(Duration::from_millis(millis))
}

impl ParentWatchdog {
    fn start() -> Self {
        let shutdown = Arc::new(AtomicBool::new(false));
        let Some(initial_parent) = astrolabe_bridge::parent_process_id() else {
            return Self {
                shutdown,
                handle: None,
            };
        };
        let handle = Self::spawn_watch(initial_parent, Arc::clone(&shutdown));
        Self { shutdown, handle }
    }

    /// Unix: a process is reparented to init (pid 1) when its parent dies, so a change in
    /// `getppid()` away from the parent seen at startup means the parent exited.
    #[cfg(unix)]
    fn spawn_watch(
        initial_parent: u32,
        thread_shutdown: Arc<AtomicBool>,
    ) -> Option<thread::JoinHandle<()>> {
        Some(thread::spawn(move || {
            let poll_interval = Duration::from_millis(500);
            while !thread_shutdown.load(Ordering::Relaxed) {
                thread::sleep(poll_interval);
                if thread_shutdown.load(Ordering::Relaxed) {
                    break;
                }
                if initial_parent > 1
                    && astrolabe_bridge::parent_process_id()
                        .is_some_and(|ppid| ppid != initial_parent)
                {
                    tracing::warn!("parent.exited reason=ppid_changed");
                    process::exit(0);
                }
            }
        }))
    }

    /// Windows (#253): there is no reparenting to observe, so open a `SYNCHRONIZE` handle to
    /// the parent and wait on it — the handle signals the instant the parent exits, so this
    /// is event-driven (no PID polling, no `STILL_ACTIVE` ambiguity). Bounded 50 ms waits
    /// let the cooperative `Drop` shutdown be observed between them.
    ///
    /// If the handle cannot be *opened*, we do NOT terminate a possibly-healthy server: that
    /// happens when the parent already exited (its EOF closes stdin, which terminates an
    /// stdio server anyway) or when SYNCHRONIZE is denied on a live higher-privilege parent
    /// (killing the server would be wrong). We log the labeled degradation and fall back to
    /// the stdin-EOF path. But a wait failure on an *established* parent handle is a genuine
    /// fault on a confirmed parent — there we fail closed and exit.
    #[cfg(windows)]
    fn spawn_watch(
        initial_parent: u32,
        thread_shutdown: Arc<AtomicBool>,
    ) -> Option<thread::JoinHandle<()>> {
        let watch = match astrolabe_bridge::ParentDeathWatch::open(initial_parent) {
            Ok(watch) => watch,
            Err(error) => {
                tracing::warn!(
                    "parent.watchdog reason=open_failed status=degraded_stdin_eof_fallback detail={error}"
                );
                return None;
            }
        };
        Some(thread::spawn(move || {
            while !thread_shutdown.load(Ordering::Relaxed) {
                match watch.wait(50) {
                    astrolabe_bridge::ParentWaitOutcome::Exited => {
                        tracing::warn!("parent.exited reason=handle_signaled");
                        process::exit(0);
                    }
                    astrolabe_bridge::ParentWaitOutcome::StillAlive => {}
                    astrolabe_bridge::ParentWaitOutcome::Failed(detail) => {
                        tracing::error!("parent.watchdog reason=wait_failed detail={detail}");
                        process::exit(0);
                    }
                }
            }
        }))
    }

    /// Platforms with no parent-death primitive: no watchdog thread. An stdio server still
    /// terminates on stdin EOF when its client goes away; this is a labeled no-op, not a
    /// silent one (the absence of a handle is observable in `index_status`/tests).
    #[cfg(not(any(unix, windows)))]
    fn spawn_watch(
        _initial_parent: u32,
        _thread_shutdown: Arc<AtomicBool>,
    ) -> Option<thread::JoinHandle<()>> {
        None
    }
}

impl Drop for ParentWatchdog {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}
