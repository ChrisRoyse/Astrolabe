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
    // #392: a `cli <tool>` invocation reserves stderr for warn/error so the
    // supported `--args-file`/stdin forms emit empty stderr (unblocks #377). It
    // is detected here — mirroring the hook-mode early branch — so both the
    // tracing subscriber and the libcbm log floor are raised before any startup
    // logging can reach stderr. Server (no-arg) dispatch is unaffected and keeps
    // INFO.
    let cli_mode = is_cli_invocation(&args);
    let _hook_deadline = hook_mode.then(|| HookDeadline::start(HOOK_AUGMENT_BUDGET_MS));
    if !hook_mode {
        initialize_tracing(if cli_mode {
            cli_stderr_tracing_level()
        } else {
            LevelFilter::INFO
        });
        astrolabe_bridge::route_cbm_logs_to_tracing();
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

fn initialize_tracing(max_level: LevelFilter) {
    let _ = tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_ansi(false)
        .with_target(false)
        .without_time()
        .with_max_level(max_level)
        .try_init();
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
        "Usage: astrolabe [cli <tool> --args-file <path> | cli <tool> (JSON on stdin) | cli verify_chain --args-file <path> | hook-augment | install|uninstall|update | verify --deep --vault <dir> --vault-id <id> --vault-salt <salt>]\nSupply cli tool arguments via --args-file <path> or piped stdin; passing raw JSON as an argv token is no longer supported and is refused (ASTRO_CLI_RAW_JSON_ARGV_REMOVED).\n`astrolabe cli <tool> --help` (or -h) prints the tool's arguments from its schema and exits without running the tool (#416).\n`astrolabe cli --json <tool>` prints the raw result JSON on stdout and exits 1 when the result is isError:true, else 0 (#419).\nverify --deep exits 0 when verified and 1 on a named failure such as ASTRO_VERIFY_DEEP_FAILED."
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
    // #515 internal isolated historical-index extraction worker. Spawned per evidence
    // commit by `run_git_archaeology` (git_archaeology.rs) so a C-level CBM pipeline
    // fault on a historical checkout is contained in THIS child process instead of
    // hard-exiting the host `index_repository` with a silent empty-stdout rc=127. Not
    // a user-facing tool: it consumes `--args-file` + `--response-out` and writes only
    // the serialized pipeline rows. Handled before tool-name resolution because it is
    // not a CBM tool. A ParentWatchdog ties it to the parent so a dead parent never
    // orphans it.
    if strip_flag(&mut args, "--archaeology-extract") {
        let _worker_watchdog = ParentWatchdog::start();
        let args_file = strip_flag_value(&mut args, "--args-file").ok_or_else(|| -> DynError {
            "ASTRO_ARCHAEOLOGY_EXTRACT_ARGS_MISSING: --archaeology-extract requires --args-file <path>".into()
        })?;
        let resp = response_out.clone().ok_or_else(|| -> DynError {
            "ASTRO_ARCHAEOLOGY_EXTRACT_RESPONSE_MISSING: --archaeology-extract requires --response-out <path>".into()
        })?;
        let args_json = fs::read_to_string(&args_file).map_err(|error| -> DynError {
            format!("ASTRO_ARCHAEOLOGY_EXTRACT_ARGS_UNREADABLE: could not read --archaeology-extract args file {args_file}: {error}").into()
        })?;
        return migration::run_archaeology_extract_worker(&args_json, &resp);
    }
    if args.is_empty() {
        return Err("Usage: astrolabe cli [--json] [--progress] <tool_name> [--args-file <path> | (JSON on stdin)] (raw '<json>' argv is no longer supported).\n  --json prints the raw tool result JSON on stdout and exits 1 when the result is isError:true (0 otherwise), so RC-based callers see tool failures (#419).\n  <tool_name> --help prints the tool's arguments and exits without running it (#416).".into());
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
