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

mod migration;

mod installer_cleanup;
use installer_cleanup::*;

mod hook_augment;
use hook_augment::*;

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

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
const VERIFY_CHAIN_LOOP_SLEEP_SLICE_MS: u64 = 100;

pub fn parent_system() -> astrolabe_domain::ParentSystem {
    astrolabe_domain::ParentSystem::CodebaseMemoryMcp
}

/// Registry-declared stack reserve (bytes) for any host thread that enters the
/// in-process CBM pipeline (#364). Re-exported so the binary entrypoint sizes
/// its host thread from the single declared knob.
pub use astrolabe_domain::knobs::cbm_pipeline_host_stack_bytes;

pub fn run_from_env() -> i32 {
    let args: Vec<String> = env::args().collect();
    let hook_mode = is_hook_augment_invocation(&args);
    let _hook_deadline = hook_mode.then(|| HookDeadline::start(HOOK_AUGMENT_BUDGET_MS));
    if !hook_mode {
        initialize_tracing();
        astrolabe_bridge::route_cbm_logs_to_tracing();
    }
    let binary_path = env::current_exe()
        .ok()
        .and_then(|path| path.into_os_string().into_string().ok())
        .or_else(|| args.first().cloned());

    let startup = if hook_mode {
        astrolabe_bridge::initialize_cbm_host_process_silent(binary_path.as_deref())
    } else {
        astrolabe_bridge::initialize_cbm_host_process(binary_path.as_deref())
    };
    if let Err(err) = startup {
        if hook_mode {
            return 0;
        }
        eprintln!("astrolabe: startup failed: {err}");
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
        "hook-augment" => run_hook_augment(),
        "install" | "uninstall" | "update" => run_installer_command(args[0].as_str(), &args[1..]),
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

fn initialize_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_ansi(false)
        .with_target(false)
        .without_time()
        .try_init();
}

fn print_usage() {
    eprintln!(
        "Usage: astrolabe [cli <tool> --args-file <path> | cli <tool> (JSON on stdin) | cli verify_chain --args-file <path> | hook-augment | install|uninstall|update | verify --deep --vault <dir> --vault-id <id> --vault-salt <salt>]\nSupply cli tool arguments via --args-file <path> or piped stdin; passing raw JSON as an argv token still works but is deprecated and warns.\nverify --deep exits 0 when verified and 1 on a named failure such as ASTRO_VERIFY_DEEP_FAILED."
    );
}

fn run_server() -> Result<i32, DynError> {
    let _watchdog = ParentWatchdog::start();
    let _verify_chain_loop = VerifyChainLoop::start();
    let _incremental_watcher_loop = IncrementalWatcherLoop::start();
    tracing::info!("server.start version={}", env!("CARGO_PKG_VERSION"));
    let runner = CbmToolRunner::new_default()?;
    let stdin = io::stdin();
    let stdout = io::stdout();
    serve_jsonrpc(&runner, stdin.lock(), stdout.lock())?;
    tracing::info!("server.shutdown");
    Ok(0)
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
    let envelope = request_error_envelope(error);
    tracing::warn!(
        code = %envelope.code,
        message = %envelope.message,
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

fn request_error_envelope(error: &(dyn Error + Send + Sync + 'static)) -> ErrorEnvelope {
    if let Some(error) = error.downcast_ref::<BridgeError>() {
        return error.envelope().clone();
    }
    ErrorEnvelope::new(
        "ASTRO_MCP_HANDLER_INTERNAL",
        error.to_string(),
        "Retry the request after checking the named persisted store or lock; if it repeats, inspect Astrolabe diagnostics while keeping the MCP session open.",
    )
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
    if args.is_empty() {
        return Err("Usage: astrolabe cli [--json] [--progress] <tool_name> [--args-file <path> | (JSON on stdin) | '<json>' (deprecated)]".into());
    }

    let _worker_watchdog = index_worker.then(ParentWatchdog::start);
    let _worker_role = if index_worker {
        Some(astrolabe_bridge::CbmIndexWorkerRole::activate(
            response_out.as_deref(),
        )?)
    } else {
        None
    };
    let tool_name = args.remove(0);
    let args_json = resolve_cli_args(&args)?;
    if progress {
        eprintln!("astrolabe cli progress: start tool={tool_name}");
    }
    if tool_name == "verify_chain" {
        let code = run_verify_chain_cli(&args_json, raw_json, response_out.as_deref())?;
        if progress {
            eprintln!("astrolabe cli progress: done tool={tool_name} exit={code}");
        }
        return Ok(code);
    }

    let runner = CbmToolRunner::new_default()?;
    let result = if index_worker {
        runner.handle_tool_raw(&tool_name, &args_json)?
    } else {
        migration::handle_tool_raw(&runner, &tool_name, &args_json)?
    };
    if let Some(path) = response_out.as_ref() {
        fs::write(path, &result)?;
    }
    if index_worker {
        // #282 (attempt 15): the response file is a supervised worker's ONLY
        // result channel — its stdout/stderr are the supervisor's log handle
        // (or worse, whatever handle state the spawn produced), so printing
        // the result there at best duplicates the payload into the log and at
        // worst makes a fully-successful index depend on stdout health for
        // its exit code. Exit with the tool outcome and write nothing.
        return Ok(mcp_result_exit_code(&result));
    }

    if raw_json {
        println!("{result}");
        if progress {
            eprintln!("astrolabe cli progress: done tool={tool_name} exit=0");
        }
        return Ok(0);
    }

    let code = print_mcp_tool_result(&result)?;
    if progress {
        eprintln!("astrolabe cli progress: done tool={tool_name} exit={code}");
    }
    Ok(code)
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

    let report = astrolabe_ingest::verify_deep_vault_path(vault, &vault_id, &vault_salt)?;
    if raw_json {
        println!("{}", serde_json::to_string(&report)?);
    } else {
        println!(
            "series registry verified: series_rows={} reverse_rows={} qn_index_rows={} recurrence_rows={} split_rows={} sqlite_node_map_rows={} sqlite_structural_rows={} sqlite_constellation_rows={} sqlite_edge_rows={} ledger_chain_status={} ledger_rows={} ledger_payload_rows={} base_ledger_pairs={}",
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
            report.base_ledger_pairs
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

/// How the leading `cli` argv supplies the tool JSON. Only [`CliArgSource::RawJsonArgv`]
/// is deprecated; `--args-file <path>` and piped stdin are the supported forms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CliArgSource {
    /// `cli <tool> --args-file <path>` — JSON read from a file.
    ArgsFile,
    /// `cli <tool> '{...}'` — raw JSON as an argv token (deprecated; still accepted).
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
        Some(CliArgSource::RawJsonArgv) => {
            eprintln!(
                "warning: passing raw JSON to 'cli' is deprecated; use --args-file <path> or piped stdin."
            );
            Ok(args[0].clone())
        }
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
    shutdown: Arc<AtomicBool>,
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
}

impl Drop for IncrementalWatcherLoop {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl VerifyChainLoop {
    fn start() -> Self {
        let shutdown = Arc::new(AtomicBool::new(false));
        if verify_chain_loop_disabled() {
            tracing::info!("verify_chain_loop.disabled source=ASTROLABE_VERIFY_CHAIN_LOOP");
            return Self {
                shutdown,
                handle: None,
            };
        }

        // #277: one-time deep boot gate before the steady-state bounded scrub lane
        // begins — re-hashes each project's whole persisted ledger from genesis and
        // fails closed (records status=error) on a tampered/damaged store, so the
        // per-tick scrub never runs atop already-corrupt state.
        match migration::janitor_startup_verify_projects() {
            Ok(0) => {}
            Ok(damaged) => {
                tracing::warn!(
                    "verify_chain_loop.startup_verify_failed_closed damaged_projects={damaged}"
                );
            }
            Err(error) => {
                tracing::warn!("verify_chain_loop.startup_verify_error error={error}");
            }
        }

        let interval = verify_chain_loop_interval();
        let thread_shutdown = Arc::clone(&shutdown);
        let handle = thread::spawn(move || {
            loop {
                if thread_shutdown.load(Ordering::Relaxed) {
                    break;
                }
                match migration::periodic_verify_chain_tick() {
                    Ok(report) => {
                        let checked = report
                            .get("checked_projects")
                            .and_then(serde_json::Value::as_u64)
                            .unwrap_or(0);
                        tracing::debug!("verify_chain_loop.tick checked_projects={checked}");
                    }
                    Err(error) => {
                        tracing::warn!("verify_chain_loop.tick_failed error={error}");
                    }
                }
                if sleep_until_verify_loop_shutdown(&thread_shutdown, interval) {
                    break;
                }
            }
        });

        Self {
            shutdown,
            handle: Some(handle),
        }
    }
}

impl Drop for VerifyChainLoop {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn verify_chain_loop_disabled() -> bool {
    verify_chain_loop_disabled_from_raw(env::var("ASTROLABE_VERIFY_CHAIN_LOOP").ok().as_deref())
}

fn verify_chain_loop_disabled_from_raw(raw: Option<&str>) -> bool {
    raw.is_some_and(|value| {
        let value = value.trim();
        value == "0" || value.eq_ignore_ascii_case("false") || value.eq_ignore_ascii_case("off")
    })
}

fn verify_chain_loop_interval() -> Duration {
    verify_chain_loop_interval_from_raw(
        env::var("ASTROLABE_VERIFY_CHAIN_INTERVAL_MS")
            .ok()
            .as_deref(),
    )
}

fn verify_chain_loop_interval_from_raw(raw: Option<&str>) -> Duration {
    let millis = raw
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(VERIFY_CHAIN_LOOP_DEFAULT_INTERVAL_MS)
        .max(VERIFY_CHAIN_LOOP_MIN_INTERVAL_MS);
    Duration::from_millis(millis)
}

fn sleep_until_verify_loop_shutdown(shutdown: &AtomicBool, duration: Duration) -> bool {
    let slice = Duration::from_millis(VERIFY_CHAIN_LOOP_SLEEP_SLICE_MS);
    let mut slept = Duration::ZERO;
    while slept < duration {
        if shutdown.load(Ordering::Relaxed) {
            return true;
        }
        let step = duration.saturating_sub(slept).min(slice);
        thread::sleep(step);
        slept = slept.saturating_add(step);
    }
    shutdown.load(Ordering::Relaxed)
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
    /// is event-driven (no PID polling, no `STILL_ACTIVE` ambiguity). Bounded 500 ms waits
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
                match watch.wait(500) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_exit_code_reflects_tool_outcome_not_stdout_health() {
        // success result -> 0; isError -> 1; unparseable -> 0 (same contract
        // print_mcp_tool_result has always had, now stdout-independent).
        assert_eq!(
            mcp_result_exit_code(r#"{"content":[{"type":"text","text":"ok"}],"isError":false}"#),
            0
        );
        assert_eq!(
            mcp_result_exit_code(r#"{"content":[{"type":"text","text":"boom"}],"isError":true}"#),
            1
        );
        assert_eq!(mcp_result_exit_code("not json"), 0);
        assert_eq!(mcp_result_exit_code(r#"{"content":[]}"#), 0);
    }
    #[test]
    fn cli_argv_classifier_only_flags_raw_json_argv_as_deprecated() {
        // #377: --args-file and stdin are the supported forms; only a raw-JSON
        // argv token routes through the deprecation branch. classify_cli_argv is
        // the pure seam that decides this, so we can assert the split without a
        // real stdin/stderr. Zero deprecation warnings for the supported forms
        // <=> classify never returns RawJsonArgv for them.

        // --args-file <path>: supported, never warns.
        assert_eq!(
            classify_cli_argv(&["--args-file".into(), "args.json".into()]),
            Some(CliArgSource::ArgsFile)
        );
        // --args-file with no value falls through to the stdin path (None), no warn.
        assert_eq!(classify_cli_argv(&["--args-file".into()]), None);
        // No inline args -> stdin fallback (None), no warn.
        assert_eq!(classify_cli_argv(&[]), None);
        // A non-JSON, non-flag first token (e.g. a bare value) -> stdin path, no warn.
        assert_eq!(classify_cli_argv(&["not-json".into()]), None);

        // Raw-JSON argv token: the ONLY deprecated form.
        assert_eq!(
            classify_cli_argv(&["{\"repo_path\":\".\"}".into()]),
            Some(CliArgSource::RawJsonArgv)
        );
        // Leading whitespace before '{' is still detected as raw JSON.
        assert_eq!(
            classify_cli_argv(&["  {\"a\":1}".into()]),
            Some(CliArgSource::RawJsonArgv)
        );
    }

    use std::io::Cursor;

    #[test]
    fn identifies_cbm_parent() {
        assert_eq!(
            parent_system(),
            astrolabe_domain::ParentSystem::CodebaseMemoryMcp
        );
    }

    #[test]
    fn lists_fourteen_legacy_tools_and_alias() {
        assert_eq!(LEGACY_TOOLS.len(), 14);
        assert!(LEGACY_TOOLS.contains(&"index_repository"));
        assert!(LEGACY_TOOLS.contains(&"ingest_traces"));
        assert_eq!(LEGACY_ALIASES, &["trace_call_path"]);
    }

    #[test]
    fn tool_error_remains_jsonrpc_result() {
        let runner = CbmToolRunner::new(":memory:").unwrap();
        let input = Cursor::new(
            br#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"not_a_tool","arguments":{}}}"#
                .as_slice(),
        );
        let mut output = Vec::new();
        serve_jsonrpc(&runner, input, &mut output).unwrap();

        let response: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert!(response.get("error").is_none());
        assert_eq!(response["id"], 7);
        assert_eq!(response["result"]["isError"], true);
    }

    #[test]
    fn tool_handler_error_is_structured_and_line_loop_continues() {
        let first = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"index_status","arguments":{}}}"#;
        let second = r#"{"jsonrpc":"2.0","id":2,"method":"ping","params":{}}"#;
        let input = Cursor::new(format!("{first}\n{second}\n"));
        let mut output = Vec::new();
        let mut calls = 0;

        serve_jsonrpc_with_handler(input, &mut output, |_| {
            calls += 1;
            if calls == 1 {
                return Err(io::Error::other("config database busy").into());
            }
            Ok(Some(
                r#"{"jsonrpc":"2.0","id":2,"result":{"alive":true}}"#.to_string(),
            ))
        })
        .unwrap();

        assert_eq!(calls, 2);
        let responses = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0]["id"], 1);
        assert_eq!(responses[0]["result"]["isError"], true);
        assert_eq!(
            responses[0]["result"]["structuredContent"]["code"],
            "ASTRO_MCP_HANDLER_INTERNAL"
        );
        assert_eq!(
            responses[0]["result"]["structuredContent"]["message"],
            "config database busy"
        );
        assert!(
            responses[0]["result"]["structuredContent"]["remediation"]
                .as_str()
                .is_some_and(|value| value.contains("Retry"))
        );
        assert_eq!(responses[1]["id"], 2);
        assert_eq!(responses[1]["result"]["alive"], true);
    }

    #[test]
    fn content_length_loop_continues_after_handler_error() {
        let first = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"index_status","arguments":{}}}"#;
        let second = r#"{"jsonrpc":"2.0","id":4,"method":"ping","params":{}}"#;
        let input = Cursor::new(format!(
            "Content-Length: {}\r\n\r\n{}Content-Length: {}\r\n\r\n{}",
            first.len(),
            first,
            second.len(),
            second
        ));
        let mut output = Vec::new();
        let mut calls = 0;

        serve_jsonrpc_with_handler(input, &mut output, |_| {
            calls += 1;
            if calls == 1 {
                return Err(io::Error::other("vault temporarily unavailable").into());
            }
            Ok(Some(
                r#"{"jsonrpc":"2.0","id":4,"result":{"alive":true}}"#.to_string(),
            ))
        })
        .unwrap();

        assert_eq!(calls, 2);
        let responses = framed_json_responses(&output);
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0]["id"], 3);
        assert_eq!(responses[0]["result"]["isError"], true);
        assert_eq!(responses[1]["id"], 4);
        assert_eq!(responses[1]["result"]["alive"], true);
    }

    #[test]
    fn non_tool_handler_error_uses_jsonrpc_internal_error() {
        let error = io::Error::other("poisoned request state");
        let response = handler_error_response(
            r#"{"jsonrpc":"2.0","id":"req-5","method":"ping","params":{}}"#,
            &error,
        )
        .unwrap()
        .expect("request with id receives an error response");
        let response: serde_json::Value = serde_json::from_str(&response).unwrap();

        assert_eq!(response["id"], "req-5");
        assert_eq!(response["error"]["code"], -32603);
        assert_eq!(response["error"]["message"], "Internal error");
        assert_eq!(
            response["error"]["data"]["code"],
            "ASTRO_MCP_HANDLER_INTERNAL"
        );
        assert_eq!(
            response["error"]["data"]["message"],
            "poisoned request state"
        );
        assert!(response["error"]["data"]["remediation"].is_string());
    }

    #[test]
    fn notification_handler_error_emits_nothing_and_loop_continues() {
        let notification = r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"index_status","arguments":{}}}"#;
        let request = r#"{"jsonrpc":"2.0","id":6,"method":"ping","params":{}}"#;
        let input = Cursor::new(format!("{notification}\n{request}\n"));
        let mut output = Vec::new();
        let mut calls = 0;

        serve_jsonrpc_with_handler(input, &mut output, |_| {
            calls += 1;
            if calls == 1 {
                return Err(io::Error::other("notification failed").into());
            }
            Ok(Some(
                r#"{"jsonrpc":"2.0","id":6,"result":{"alive":true}}"#.to_string(),
            ))
        })
        .unwrap();

        assert_eq!(calls, 2);
        let responses = String::from_utf8(output).unwrap();
        assert_eq!(responses.lines().count(), 1);
        let response: serde_json::Value = serde_json::from_str(responses.trim()).unwrap();
        assert_eq!(response["id"], 6);
        assert_eq!(response["result"]["alive"], true);
    }

    #[test]
    fn malformed_content_length_remains_transport_fatal() {
        let input = Cursor::new(b"Content-Length: nope\r\n\r\n".as_slice());
        let mut output = Vec::new();
        let error = serve_jsonrpc_with_handler(input, &mut output, |_| {
            panic!("handler must not run for malformed framing")
        })
        .expect_err("malformed Content-Length remains fatal");

        assert!(error.to_string().contains("invalid digit"));
        assert!(output.is_empty());
    }

    #[test]
    fn content_length_transport_returns_framed_response() {
        let runner = CbmToolRunner::new(":memory:").unwrap();
        let body = r#"{"jsonrpc":"2.0","id":3,"method":"ping","params":{}}"#;
        let input = Cursor::new(format!("Content-Length: {}\r\n\r\n{}", body.len(), body));
        let mut output = Vec::new();
        serve_jsonrpc(&runner, input, &mut output).unwrap();

        let out = String::from_utf8(output).unwrap();
        assert!(out.starts_with("Content-Length: "));
        assert!(out.contains(r#""id":3"#));
        assert!(out.contains(r#""result":{}"#));
    }

    fn framed_json_responses(mut bytes: &[u8]) -> Vec<serde_json::Value> {
        let mut responses = Vec::new();
        while !bytes.is_empty() {
            let header_end = bytes
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .expect("framed response header terminator");
            let header = std::str::from_utf8(&bytes[..header_end]).unwrap();
            let content_len = header
                .strip_prefix("Content-Length:")
                .expect("Content-Length response header")
                .trim()
                .parse::<usize>()
                .unwrap();
            let body_start = header_end + 4;
            let body_end = body_start + content_len;
            responses.push(serde_json::from_slice(&bytes[body_start..body_end]).unwrap());
            bytes = &bytes[body_end..];
        }
        responses
    }

    #[test]
    fn mcp_result_printer_returns_error_exit_code() {
        let code = print_mcp_tool_result(
            r#"{"content":[{"type":"text","text":"unknown tool"}],"isError":true}"#,
        )
        .unwrap();
        assert_eq!(code, 1);
    }

    #[test]
    fn hook_token_uses_longest_identifier_and_bounds_noise() {
        assert_eq!(
            hook_extract_token(".*short someIndexedSymbol more.*").as_deref(),
            Some("someIndexedSymbol")
        );
        assert!(hook_extract_token("a|bc|123").is_none());
        let long = format!("prefix {}", "A".repeat(HOOK_MAX_TOKEN_BYTES + 20));
        assert_eq!(
            hook_extract_token(&long).unwrap().len(),
            HOOK_MAX_TOKEN_BYTES
        );
    }

    #[test]
    fn hook_path_walk_handles_posix_and_windows_roots() {
        assert!(hook_path_is_abs("/tmp/repo/src"));
        assert!(hook_path_is_abs("C:/repo/src"));
        assert!(hook_path_is_abs("C:"));
        assert!(!hook_path_is_abs("repo/src"));
        assert_eq!(hook_parent("/tmp/repo/src").as_deref(), Some("/tmp/repo"));
        assert_eq!(hook_parent("/tmp"), None);
        assert_eq!(hook_parent("C:/repo/src").as_deref(), Some("C:/repo"));
        assert_eq!(hook_parent("C:/repo"), None);
        assert_eq!(hook_parent("C:"), None);
    }

    #[test]
    fn hook_context_formats_search_graph_hits_with_provisional_label() {
        let raw = serde_json::json!({
            "content": [{
                "type": "text",
                "text": serde_json::json!({
                    "results": [{
                        "qualified_name": "demo.someIndexedSymbol",
                        "name": "someIndexedSymbol",
                        "file_path": "src/main.c",
                        "label": "Function"
                    }]
                }).to_string()
            }],
            "isError": false
        })
        .to_string();

        let HookSearch::Hits(context) =
            hook_context_from_search_graph(&raw, "someIndexedSymbol").expect("hook result parses")
        else {
            panic!("expected hook hits");
        };
        assert!(context.contains("trust=provisional"));
        assert!(context.contains("demo.someIndexedSymbol"));
        assert!(context.contains("src/main.c"));
    }

    #[test]
    fn hook_context_distinguishes_errors_from_empty_results() {
        let empty = serde_json::json!({
            "content": [{"type": "text", "text": "{\"results\":[]}"}],
            "isError": false
        })
        .to_string();
        assert!(matches!(
            hook_context_from_search_graph(&empty, "nothing").unwrap(),
            HookSearch::NoHits
        ));

        let error = r#"{"content":[{"type":"text","text":"missing project"}],"isError":true}"#;
        assert!(matches!(
            hook_context_from_search_graph(error, "nothing").unwrap(),
            HookSearch::ToolError
        ));
    }

    #[test]
    fn installer_cleanup_strips_path_block_and_removes_empty_file() {
        let dir = temp_dir("installer-path-cleanup");
        fs::create_dir_all(&dir).expect("create cleanup dir");
        let profile = dir.join(".profile");
        fs::write(
            &profile,
            "\n# Added by codebase-memory-mcp install\nexport PATH=\"/tmp/.local/bin:$PATH\"\n",
        )
        .unwrap();
        cleanup_path_block_file(&profile).unwrap();
        assert!(!profile.exists());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn installer_cleanup_removes_codex_session_remainder() {
        let text = "[[hooks.SessionStart]]\nmatcher = \"startup|resume|clear|compact\"\n\n[[hooks.SessionStart.hooks]]\ntype = \"command\"\ncommand = 'echo \"Code discovery: prefer codebase-memory-mcp\"'\n# <<< codebase-memory-mcp SessionStart <<<\n\n[other]\nvalue = true\n";
        let cleaned = strip_codex_session_remainder(text);
        assert!(!cleaned.contains("codebase-memory-mcp"));
        assert!(cleaned.contains("[other]"));
    }

    #[test]
    fn installer_cleanup_recognizes_empty_generated_json() {
        assert!(is_empty_json_config(r#"{"mcpServers":{},"hooks":{}}"#));
        assert!(is_empty_json_config(r#"{"mcp":{"servers":[]}}"#));
        assert!(is_empty_json_config(r#"{"context_servers":{}}"#));
        assert!(!is_empty_json_config(r#"{"mcpServers":{"demo":{}}}"#));
    }

    #[test]
    fn installer_cleanup_paths_match_native_platform_roots() {
        let home = Path::new("fixture-home");
        let app_data = PathBuf::from("fixture-appdata");
        let local_app_data = PathBuf::from("fixture-localappdata");
        let xdg_config = PathBuf::from("fixture-xdg");

        let windows_config = installer_config_dir_for(
            InstallerPlatform::Windows,
            home,
            Some(app_data.clone()),
            Some(xdg_config.clone()),
        );
        let windows_local = installer_local_dir_for(
            InstallerPlatform::Windows,
            home,
            Some(local_app_data.clone()),
            windows_config.clone(),
        );
        let windows_paths =
            known_installer_config_files_for_dirs(home, &windows_config, &windows_local);
        assert!(windows_paths.contains(&home.join(".config/opencode/opencode.json")));
        assert!(windows_paths.contains(&home.join(".config/opencode/AGENTS.md")));
        assert!(windows_paths.contains(&local_app_data.join("Zed/settings.json")));
        assert!(windows_paths.contains(
            &app_data.join("Code/User/globalStorage/kilocode.kilo-code/settings/mcp_settings.json")
        ));
        assert!(windows_paths.contains(&app_data.join("Code/User/mcp.json")));

        let mac_config = installer_config_dir_for(
            InstallerPlatform::Macos,
            home,
            Some(app_data),
            Some(xdg_config.clone()),
        );
        assert_eq!(mac_config, home.join("Library/Application Support"));
        assert_eq!(
            installer_local_dir_for(InstallerPlatform::Macos, home, None, mac_config.clone()),
            mac_config
        );

        let posix_config = installer_config_dir_for(
            InstallerPlatform::Posix,
            home,
            None,
            Some(xdg_config.clone()),
        );
        assert_eq!(posix_config, xdg_config);
        assert_eq!(
            installer_config_dir_for(InstallerPlatform::Posix, home, None, None),
            home.join(".config")
        );
    }

    #[test]
    fn verify_requires_deep_flag() {
        let err = run_verify(&[
            "--vault".to_string(),
            "target/nope".to_string(),
            "--vault-id".to_string(),
            "00000000000000000000000000".to_string(),
            "--vault-salt".to_string(),
            "salt".to_string(),
        ])
        .expect_err("missing deep is refused");

        assert!(err.to_string().contains("--deep"));
    }

    #[test]
    fn verify_deep_success_exit_code_is_zero() {
        let dir = temp_dir("verify-deep-empty");
        fs::create_dir_all(&dir).expect("create verify dir");

        let code = run_verify(&[
            "--deep".to_string(),
            "--vault".to_string(),
            dir.display().to_string(),
            "--vault-id".to_string(),
            "01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string(),
            "--vault-salt".to_string(),
            "salt".to_string(),
        ])
        .expect("empty durable dir verifies as zero rows");

        assert_eq!(code, 0);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn verify_chain_exit_codes_are_documented() {
        let mut report = astrolabe_ingest::VerifyChainReport {
            status: "intact".to_string(),
            ledger_rows: 1,
            checked_range_start: 0,
            checked_range_end: 1,
            count: 1,
            at_seq: None,
            expected_hash: None,
            found_hash: None,
            reason: None,
            quarantine_seq: None,
            remediation: None,
        };
        assert_eq!(verify_chain_exit_code(&report), 0);

        report.status = "broken".to_string();
        report.at_seq = Some(0);
        report.quarantine_seq = Some(0);
        assert_eq!(verify_chain_exit_code(&report), 1);
    }

    #[test]
    fn verify_chain_loop_env_controls_are_explicit() {
        assert!(verify_chain_loop_disabled_from_raw(Some("0")));
        assert!(verify_chain_loop_disabled_from_raw(Some("false")));
        assert!(verify_chain_loop_disabled_from_raw(Some("OFF")));
        assert!(!verify_chain_loop_disabled_from_raw(None));
        assert!(!verify_chain_loop_disabled_from_raw(Some("1")));

        assert_eq!(
            verify_chain_loop_interval_from_raw(None),
            Duration::from_millis(VERIFY_CHAIN_LOOP_DEFAULT_INTERVAL_MS)
        );
        assert_eq!(
            verify_chain_loop_interval_from_raw(Some("25")),
            Duration::from_millis(VERIFY_CHAIN_LOOP_MIN_INTERVAL_MS)
        );
        assert_eq!(
            verify_chain_loop_interval_from_raw(Some("2500")),
            Duration::from_millis(2500)
        );
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!("astrolabe-server-{name}-{}", std::process::id()));
        fs::remove_dir_all(&dir).ok();
        dir
    }
}
