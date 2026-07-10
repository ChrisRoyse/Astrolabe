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

const HOOK_AUGMENT_BUDGET_MS: u64 = 300;
const HOOK_STDIN_CAP_BYTES: u64 = 256 * 1024;
const HOOK_MIN_TOKEN_BYTES: usize = 4;
const HOOK_MAX_TOKEN_BYTES: usize = 96;
const HOOK_RESULT_LIMIT: u64 = 5;
const HOOK_MAX_WALKUP: usize = 8;
const VERIFY_CHAIN_LOOP_DEFAULT_INTERVAL_MS: u64 = 60_000;
const VERIFY_CHAIN_LOOP_MIN_INTERVAL_MS: u64 = 1_000;
const VERIFY_CHAIN_LOOP_SLEEP_SLICE_MS: u64 = 100;

pub fn parent_system() -> astrolabe_domain::ParentSystem {
    astrolabe_domain::ParentSystem::CodebaseMemoryMcp
}

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

fn is_hook_augment_invocation(args: &[String]) -> bool {
    args.get(1).is_some_and(|arg| arg == "hook-augment")
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
        "Usage: astrolabe [cli <tool> '<json>' | cli verify_chain '{{\"vault\":\"<dir>\"}}' | hook-augment | install|uninstall|update | verify --deep --vault <dir> --vault-id <id> --vault-salt <salt>]\nverify --deep exits 0 when verified and 1 on a named failure such as ASTRO_VERIFY_DEEP_FAILED."
    );
}

fn run_server() -> Result<i32, DynError> {
    let _watchdog = ParentWatchdog::start();
    let _verify_chain_loop = VerifyChainLoop::start();
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
        return Err("Usage: astrolabe cli [--json] [--progress] <tool_name> [json_args]".into());
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

fn run_hook_augment() -> Result<i32, DynError> {
    let output = hook_augment_output().ok().flatten();
    if let Some(output) = output {
        println!("{output}");
    }
    Ok(0)
}

fn run_installer_command(command: &str, args: &[String]) -> Result<i32, DynError> {
    let code = astrolabe_bridge::run_cbm_installer_command(command, args)?;
    if command == "uninstall" && code == 0 {
        cleanup_installer_leftovers()?;
    }
    Ok(code)
}

fn cleanup_installer_leftovers() -> Result<(), DynError> {
    let Some(home) = installer_home_dir() else {
        return Ok(());
    };
    for rel in [
        ".claude/hooks/cbm-code-discovery-gate",
        ".claude/hooks/cbm-session-reminder",
        ".claude/hooks/cbm-subagent-reminder",
    ] {
        remove_file_if_exists(home.join(rel))?;
    }
    cleanup_path_blocks(&home)?;
    for path in known_installer_config_files(&home) {
        cleanup_known_installer_file(&path)?;
    }
    Ok(())
}

fn installer_home_dir() -> Option<PathBuf> {
    env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .or_else(|| env::var_os("USERPROFILE").filter(|value| !value.is_empty()))
        .map(PathBuf::from)
}

fn installer_config_dir(home: &Path) -> PathBuf {
    env::var_os("XDG_CONFIG_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config"))
}

fn known_installer_config_files(home: &Path) -> Vec<PathBuf> {
    let config = installer_config_dir(home);
    vec![
        home.join(".claude/settings.json"),
        home.join(".claude/.mcp.json"),
        home.join(".claude.json"),
        home.join(".codex/config.toml"),
        home.join(".codex/AGENTS.md"),
        home.join(".gemini/settings.json"),
        home.join(".gemini/GEMINI.md"),
        home.join(".gemini/config/mcp_config.json"),
        home.join(".gemini/antigravity-cli/settings.json"),
        home.join(".gemini/antigravity-cli/AGENTS.md"),
        config.join("opencode/opencode.json"),
        config.join("opencode/AGENTS.md"),
        config.join("zed/settings.json"),
        config.join("Code/User/globalStorage/kilocode.kilo-code/settings/mcp_settings.json"),
        config.join("Code/User/mcp.json"),
        home.join(".kilocode/rules/codebase-memory-mcp.md"),
        home.join(".cursor/mcp.json"),
        home.join(".openclaw/openclaw.json"),
        home.join(".kiro/settings/mcp.json"),
        home.join(".junie/mcp/mcp.json"),
        home.join("CONVENTIONS.md"),
    ]
}

fn cleanup_path_blocks(home: &Path) -> Result<(), DynError> {
    for path in [
        home.join(".profile"),
        home.join(".bashrc"),
        home.join(".bash_profile"),
        home.join(".zshrc"),
        home.join(".config/fish/config.fish"),
    ] {
        if path.exists() {
            cleanup_path_block_file(&path)?;
        }
    }
    Ok(())
}

fn cleanup_path_block_file(path: &Path) -> Result<(), DynError> {
    let text = fs::read_to_string(path)?;
    let lines = text.lines().collect::<Vec<_>>();
    let mut out = Vec::new();
    let mut i = 0;
    let mut changed = false;
    while i < lines.len() {
        if lines[i].trim() == "# Added by codebase-memory-mcp install"
            && lines
                .get(i + 1)
                .is_some_and(|line| line.contains(".local/bin"))
        {
            changed = true;
            i += 2;
        } else {
            out.push(lines[i]);
            i += 1;
        }
    }
    if !changed {
        return Ok(());
    }
    if out.iter().all(|line| line.trim().is_empty()) {
        remove_file_if_exists(path)?;
    } else {
        fs::write(path, format!("{}\n", out.join("\n")))?;
    }
    Ok(())
}

fn cleanup_known_installer_file(path: &Path) -> Result<(), DynError> {
    if !path.exists() {
        return Ok(());
    }
    let text = fs::read_to_string(path)?;
    let cleaned = if path.file_name().and_then(|name| name.to_str()) == Some("config.toml") {
        strip_codex_session_remainder(&text)
    } else {
        text.clone()
    };
    if cleaned != text {
        if cleaned.trim().is_empty() {
            remove_file_if_exists(path)?;
        } else {
            fs::write(path, cleaned)?;
        }
        return Ok(());
    }
    if text.trim().is_empty() || is_empty_json_config(&text) {
        remove_file_if_exists(path)?;
    }
    Ok(())
}

fn strip_codex_session_remainder(text: &str) -> String {
    let begin = "# >>> codebase-memory-mcp SessionStart >>>";
    let end = "# <<< codebase-memory-mcp SessionStart <<<";
    let mut out = text.to_string();
    while let Some(end_start) = out.find(end) {
        let end_after = (end_start + end.len()).min(out.len());
        let remove_start = out[..end_start]
            .rfind(begin)
            .or_else(|| out[..end_start].rfind("[[hooks.SessionStart]]"))
            .unwrap_or(end_start);
        let remove_start = out[..remove_start]
            .rfind('\n')
            .map_or(remove_start, |idx| idx + 1);
        let remove_end = if out[end_after..].starts_with('\n') {
            end_after + 1
        } else {
            end_after
        };
        out.replace_range(remove_start..remove_end, "");
    }
    out
}

fn is_empty_json_config(text: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return false;
    };
    json_value_is_empty(&value)
}

fn json_value_is_empty(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(object) => {
            object.is_empty()
                || object.iter().all(|(key, value)| {
                    matches!(
                        key.as_str(),
                        "mcpServers" | "hooks" | "mcp" | "servers" | "context_servers"
                    ) && json_value_is_empty(value)
                })
        }
        serde_json::Value::Array(array) => array.is_empty(),
        serde_json::Value::Null => true,
        _ => false,
    }
}

fn remove_file_if_exists(path: impl AsRef<Path>) -> Result<(), DynError> {
    match fs::remove_file(path.as_ref()) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn hook_augment_output() -> Result<Option<String>, DynError> {
    let mut input = String::new();
    io::stdin()
        .take(HOOK_STDIN_CAP_BYTES + 1)
        .read_to_string(&mut input)?;
    if input.len() > HOOK_STDIN_CAP_BYTES as usize {
        return Ok(None);
    }

    let payload = serde_json::from_str::<serde_json::Value>(&input)?;
    let tool = payload
        .get("tool_name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if tool != "Grep" && tool != "Glob" {
        return Ok(None);
    }

    let pattern = payload
        .get("tool_input")
        .and_then(|input| input.get("pattern"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let Some(token) = hook_extract_token(pattern) else {
        return Ok(None);
    };

    let cwd = payload
        .get("cwd")
        .and_then(serde_json::Value::as_str)
        .map(normalize_hook_path)
        .or_else(|| {
            env::current_dir()
                .ok()
                .and_then(|path| path.into_os_string().into_string().ok())
                .map(|path| normalize_hook_path(&path))
        });
    let Some(cwd) = cwd else {
        return Ok(None);
    };
    if !hook_path_is_abs(&cwd) {
        return Ok(None);
    }

    let runner = CbmToolRunner::new_default()?;
    let Some(context) = hook_resolve_context(&runner, &cwd, &token)? else {
        return Ok(None);
    };
    Ok(Some(
        serde_json::json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "additionalContext": context
            }
        })
        .to_string(),
    ))
}

fn normalize_hook_path(path: &str) -> String {
    path.replace('\\', "/")
}

fn hook_extract_token(pattern: &str) -> Option<String> {
    let bytes = pattern.as_bytes();
    let mut best_start = 0;
    let mut best_len = 0;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_alphabetic() || bytes[i] == b'_' {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            let len = i - start;
            if len > best_len {
                best_start = start;
                best_len = len;
            }
        } else {
            i += 1;
        }
    }
    if best_len < HOOK_MIN_TOKEN_BYTES {
        return None;
    }
    let len = best_len.min(HOOK_MAX_TOKEN_BYTES);
    Some(pattern[best_start..best_start + len].to_string())
}

fn hook_path_is_abs(path: &str) -> bool {
    let bytes = path.as_bytes();
    if bytes.first() == Some(&b'/') {
        return true;
    }
    bytes.len() >= 2
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes.len() == 2 || bytes[2] == b'/')
}

fn hook_parent(path: &str) -> Option<String> {
    let slash = path.rfind('/')?;
    if slash == 0 {
        return None;
    }
    let bytes = path.as_bytes();
    if slash == 2 && bytes.get(1) == Some(&b':') {
        return None;
    }
    Some(path[..slash].to_string())
}

fn hook_resolve_context(
    runner: &CbmToolRunner,
    cwd: &str,
    token: &str,
) -> Result<Option<String>, DynError> {
    let mut dir = cwd.to_string();
    for _ in 0..HOOK_MAX_WALKUP {
        if !hook_path_is_abs(&dir) {
            break;
        }
        if let Ok(project) = astrolabe_bridge::cbm_project_name_from_path(&dir) {
            let args = serde_json::json!({
                "project": project,
                "name_pattern": format!(".*{token}.*"),
                "limit": HOOK_RESULT_LIMIT
            })
            .to_string();
            let raw = migration::handle_tool_raw(runner, "search_graph", &args)?;
            match hook_context_from_search_graph(&raw, token)? {
                HookSearch::Hits(context) => return Ok(Some(context)),
                HookSearch::NoHits => return Ok(None),
                HookSearch::ToolError => {}
            }
        }
        let Some(parent) = hook_parent(&dir) else {
            break;
        };
        dir = parent;
    }
    Ok(None)
}

enum HookSearch {
    Hits(String),
    NoHits,
    ToolError,
}

fn hook_context_from_search_graph(raw: &str, token: &str) -> Result<HookSearch, DynError> {
    let value = serde_json::from_str::<serde_json::Value>(raw)?;
    if value
        .get("isError")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(HookSearch::ToolError);
    }

    let inner = value
        .get("structuredContent")
        .cloned()
        .or_else(|| {
            value
                .get("content")
                .and_then(serde_json::Value::as_array)
                .and_then(|items| items.first())
                .and_then(|item| item.get("text"))
                .and_then(serde_json::Value::as_str)
                .and_then(|text| serde_json::from_str::<serde_json::Value>(text).ok())
        })
        .unwrap_or(serde_json::Value::Null);

    let Some(results) = inner.get("results").and_then(serde_json::Value::as_array) else {
        return Ok(HookSearch::NoHits);
    };
    if results.is_empty() {
        return Ok(HookSearch::NoHits);
    }

    let mut context = format!(
        "[astrolabe] {} graph symbol(s) match \"{}\" (advisory, freshness=best_effort, trust=provisional; normal search results are unaffected):",
        results.len(),
        token
    );
    for result in results.iter().take(HOOK_RESULT_LIMIT as usize) {
        let qualified_name = result
            .get("qualified_name")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty());
        let name = result
            .get("name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let display = qualified_name.unwrap_or(name);
        let file_path = result
            .get("file_path")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let label = result
            .get("label")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        context.push_str("\n- ");
        context.push_str(display);
        if !file_path.is_empty() {
            context.push_str("  ");
            context.push_str(file_path);
        }
        if !label.is_empty() {
            context.push_str("  ");
            context.push_str(label);
        }
    }
    Ok(HookSearch::Hits(context))
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

struct VerifyChainLoop {
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

struct HookDeadline {
    done: Arc<AtomicBool>,
}

impl HookDeadline {
    fn start(budget_ms: u64) -> Self {
        let done = Arc::new(AtomicBool::new(false));
        let thread_done = Arc::clone(&done);
        let _ = thread::spawn(move || {
            thread::sleep(Duration::from_millis(budget_ms));
            if !thread_done.load(Ordering::Relaxed) {
                process::exit(0);
            }
        });
        Self { done }
    }
}

impl Drop for HookDeadline {
    fn drop(&mut self) {
        self.done.store(true, Ordering::Relaxed);
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
