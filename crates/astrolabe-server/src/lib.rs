#![forbid(unsafe_code)]

use std::env;
use std::error::Error;
use std::fs;
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::process;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use astrolabe_bridge::CbmToolRunner;

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

pub fn parent_system() -> astrolabe_domain::ParentSystem {
    astrolabe_domain::ParentSystem::CodebaseMemoryMcp
}

pub fn run_from_env() -> i32 {
    initialize_tracing();
    astrolabe_bridge::route_cbm_logs_to_tracing();

    let args: Vec<String> = env::args().collect();
    let binary_path = env::current_exe()
        .ok()
        .and_then(|path| path.into_os_string().into_string().ok())
        .or_else(|| args.first().cloned());

    if let Err(err) = astrolabe_bridge::initialize_cbm_host_process(binary_path.as_deref()) {
        eprintln!("astrolabe: startup failed: {err}");
        return 1;
    }

    match dispatch(&args[1..]) {
        Ok(code) => code,
        Err(err) => {
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
        "Usage: astrolabe [cli <tool> '<json>' | cli verify_chain '{{\"vault\":\"<dir>\"}}' | verify --deep --vault <dir> --vault-id <id> --vault-salt <salt>]\nverify --deep exits 0 when verified and 1 on a named failure such as ASTRO_VERIFY_DEEP_FAILED."
    );
}

fn run_server() -> Result<i32, DynError> {
    let _watchdog = ParentWatchdog::start();
    tracing::info!("server.start version={}", env!("CARGO_PKG_VERSION"));
    let runner = CbmToolRunner::new_default()?;
    let stdin = io::stdin();
    let stdout = io::stdout();
    serve_jsonrpc(&runner, stdin.lock(), stdout.lock())?;
    tracing::info!("server.shutdown");
    Ok(0)
}

pub fn serve_jsonrpc<R, W>(
    runner: &CbmToolRunner,
    mut reader: R,
    mut writer: W,
) -> Result<(), DynError>
where
    R: BufRead,
    W: Write,
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
            if let Some(response) = runner.handle_jsonrpc_raw(&request)? {
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

        if let Some(response) = runner.handle_jsonrpc_raw(&line)? {
            writeln!(writer, "{response}")?;
            writer.flush()?;
        }
    }
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
    let index_worker = strip_flag(&mut args, "--index-worker");
    let response_out = strip_flag_value(&mut args, "--response-out");
    if args.is_empty() {
        return Err("Usage: astrolabe cli [--json] <tool_name> [json_args]".into());
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
    if tool_name == "verify_chain" {
        return run_verify_chain_cli(&args_json, raw_json, response_out.as_deref());
    }

    let runner = CbmToolRunner::new_default()?;
    let result = runner.handle_tool_raw(&tool_name, &args_json)?;
    if let Some(path) = response_out.as_ref() {
        fs::write(path, &result)?;
    }

    if raw_json {
        println!("{result}");
        return Ok(0);
    }

    print_mcp_tool_result(&result)
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

fn resolve_cli_args(args: &[String]) -> Result<String, DynError> {
    if args.len() >= 2 && args[0] == "--args-file" {
        return Ok(fs::read_to_string(&args[1])?);
    }
    if let Some(first) = args.first()
        && first.trim_start().starts_with('{')
    {
        eprintln!(
            "warning: passing raw JSON to 'cli' is deprecated; use --args-file or piped stdin."
        );
        return Ok(first.clone());
    }
    if !io::stdin().is_terminal() {
        let mut text = String::new();
        io::stdin().read_to_string(&mut text)?;
        if !text.is_empty() {
            return Ok(text);
        }
    }
    Ok("{}".to_string())
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

impl ParentWatchdog {
    fn start() -> Self {
        let shutdown = Arc::new(AtomicBool::new(false));
        let Some(initial_parent) = astrolabe_bridge::parent_process_id() else {
            return Self {
                shutdown,
                handle: None,
            };
        };

        let thread_shutdown = Arc::clone(&shutdown);
        let handle = thread::spawn(move || {
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
        });

        Self {
            shutdown,
            handle: Some(handle),
        }
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

    #[test]
    fn mcp_result_printer_returns_error_exit_code() {
        let code = print_mcp_tool_result(
            r#"{"content":[{"type":"text","text":"unknown tool"}],"isError":true}"#,
        )
        .unwrap();
        assert_eq!(code, 1);
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

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!("astrolabe-server-{name}-{}", std::process::id()));
        fs::remove_dir_all(&dir).ok();
        dir
    }
}
