use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{ResidentJsonrpcFrame, read_jsonrpc_frame};

pub(crate) const INTERNAL_WORKER_ARG: &str = "__astrolabe_mcp_connection_worker_v1";

const PUBLICATION_SCHEMA: &str = "astrolabe.global-mcp-publication.v5";
const ACTIVATION_SCHEMA: &str = "astrolabe.global-mcp-activation.v3";
const JOURNAL_CONTRACT_SCHEMA: &str = "astrolabe.global-mcp-connection-journal.v1";
const JOURNAL_RECORD_SCHEMA: &str = "astrolabe.global-mcp-connection-record.v1";
const MAX_STDERR_TAIL_BYTES: usize = 64 * 1024;
const RELAY_CHANNEL_CAPACITY: usize = 8;
const WORKER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub(crate) struct SupervisorError {
    code: &'static str,
    message: String,
    remediation: &'static str,
}

impl SupervisorError {
    fn new(code: &'static str, message: impl Into<String>, remediation: &'static str) -> Self {
        Self {
            code,
            message: message.into(),
            remediation,
        }
    }

    fn as_value(&self) -> Value {
        json!({
            "code": self.code,
            "message": self.message,
            "remediation": self.remediation,
        })
    }
}

impl fmt::Display for SupervisorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}: {}; remediation: {}",
            self.code, self.message, self.remediation
        )
    }
}

impl Error for SupervisorError {}

pub(crate) fn report_error(error: &SupervisorError) {
    let payload = serde_json::to_string(&json!({
        "level": "error",
        "event": "mcp.connection_supervisor.failed",
        "error": error.as_value(),
    }))
    .unwrap_or_else(|_| format!("{{\"code\":\"{}\"}}", error.code));
    eprintln!("{payload}");
}

#[derive(Debug, Clone)]
struct InstalledGeneration {
    executable_path: PathBuf,
    generation_path: PathBuf,
    generation_id: String,
    install_root: PathBuf,
    publication_path: PathBuf,
    connections_root: PathBuf,
    generation_connections_path: PathBuf,
}

#[derive(Debug)]
struct VerifiedPublication {
    executable_sha256: String,
    executable_bytes: u64,
    publication_sha256: String,
    tree_sha: String,
}

#[derive(Debug, Clone)]
struct ProcessIdentity {
    pid: u32,
    process_start_utc_ticks: u64,
}

impl ProcessIdentity {
    fn current() -> Result<Self, SupervisorError> {
        let pid = std::process::id();
        let process_start_utc_ticks = astrolabe_bridge::process_start_utc_ticks(pid).map_err(
            |error| {
                SupervisorError::new(
                    "ASTRO_MCP_SUPERVISOR_IDENTITY_FAILED",
                    format!("the supervisor process generation could not be read: {error}"),
                    "Preserve the installed generation and inspect the Windows process query failure before starting another MCP connection.",
                )
            },
        )?;
        Ok(Self {
            pid,
            process_start_utc_ticks,
        })
    }

    fn for_pid(pid: u32, role: &'static str) -> Result<Self, SupervisorError> {
        let process_start_utc_ticks = astrolabe_bridge::process_start_utc_ticks(pid).map_err(
            |error| {
                SupervisorError::new(
                    "ASTRO_MCP_CONNECTION_PROCESS_IDENTITY_FAILED",
                    format!("the exact {role} process generation for pid {pid} could not be read: {error}"),
                    "Inspect the named process and Windows process-query error; do not infer identity from a numeric PID.",
                )
            },
        )?;
        Ok(Self {
            pid,
            process_start_utc_ticks,
        })
    }

    fn as_value(&self) -> Value {
        json!({
            "pid": self.pid,
            "process_start_utc_ticks": self.process_start_utc_ticks,
        })
    }
}

pub(crate) fn run_if_installed_generation() -> Result<Option<i32>, SupervisorError> {
    let Some(generation) = detect_installed_generation()? else {
        return Ok(None);
    };

    let supervisor = ProcessIdentity::current()?;
    let client_pid = astrolabe_bridge::parent_process_id().ok_or_else(|| {
        SupervisorError::new(
            "ASTRO_MCP_CLIENT_IDENTITY_UNRESOLVED",
            "the installed MCP supervisor could not resolve its immediate client process",
            "Launch the immutable generation from a real MCP client and inspect the Windows parent-process query if the failure repeats.",
        )
    })?;
    let client = ProcessIdentity::for_pid(client_pid, "client")?;
    let mut journal = ConnectionJournal::create(&generation, &supervisor, &client)?;
    journal.append(
        "connection_opened",
        json!({
            "generation_id": generation.generation_id,
            "executable_path": generation.executable_path,
            "publication_path": generation.publication_path,
            "supervisor": supervisor.as_value(),
            "client": client.as_value(),
            "protocol": "mcp-stdio-jsonrpc",
        }),
    )?;

    match run_supervisor(&generation, &supervisor, &client, &mut journal) {
        Ok(code) => Ok(Some(code)),
        Err(error) => {
            let terminal = json!({
                "verdict": "failed",
                "cause": error.code,
                "error": error.as_value(),
                "supervisor": supervisor.as_value(),
                "client": client.as_value(),
            });
            if let Err(journal_error) = journal.append("connection_terminal", terminal) {
                eprintln!(
                    "{}",
                    serde_json::to_string(&json!({
                        "level": "error",
                        "event": "mcp.connection_journal.terminal_append_failed",
                        "original_error": error.as_value(),
                        "journal_error": journal_error.as_value(),
                        "journal_path": journal.path,
                    }))
                    .unwrap_or_else(|_| {
                        "{\"code\":\"ASTRO_MCP_CONNECTION_JOURNAL_TERMINAL_APPEND_FAILED\"}"
                            .to_string()
                    })
                );
            }
            Err(error)
        }
    }
}

fn detect_installed_generation() -> Result<Option<InstalledGeneration>, SupervisorError> {
    let executable_path = env::current_exe().map_err(|error| {
        SupervisorError::new(
            "ASTRO_MCP_EXECUTABLE_PATH_FAILED",
            format!("the running executable path could not be resolved: {error}"),
            "Inspect the process image path and launch Astrolabe from an ordinary local file.",
        )
    })?;
    if executable_path.file_name().and_then(|name| name.to_str()) != Some("codebase-memory-mcp.exe")
    {
        return Ok(None);
    }
    let Some(generation_path) = executable_path.parent() else {
        return Ok(None);
    };
    let Some(generations_root) = generation_path.parent() else {
        return Ok(None);
    };
    if generations_root.file_name().and_then(|name| name.to_str()) != Some("generations") {
        return Ok(None);
    }
    let install_root = generations_root.parent().ok_or_else(|| {
        SupervisorError::new(
            "ASTRO_MCP_GENERATION_LAYOUT_INVALID",
            format!(
                "installed executable has no install root above {}",
                generations_root.display()
            ),
            "Publish the executable through the Astrolabe global MCP publisher before activation.",
        )
    })?;
    let generation_id = generation_path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            SupervisorError::new(
                "ASTRO_MCP_GENERATION_ID_INVALID",
                format!(
                    "installed generation directory has no UTF-8 identity: {}",
                    generation_path.display()
                ),
                "Publish a fresh content-addressed generation with the repository publisher.",
            )
        })?
        .to_string();
    let connections_root = install_root.join("connections");
    Ok(Some(InstalledGeneration {
        executable_path: executable_path.clone(),
        generation_path: generation_path.to_path_buf(),
        generation_id: generation_id.clone(),
        install_root: install_root.to_path_buf(),
        publication_path: generation_path.join("publication.json"),
        generation_connections_path: connections_root.join(&generation_id),
        connections_root,
    }))
}

fn run_supervisor(
    generation: &InstalledGeneration,
    supervisor: &ProcessIdentity,
    client: &ProcessIdentity,
    journal: &mut ConnectionJournal,
) -> Result<i32, SupervisorError> {
    let publication = verify_publication(generation)?;
    journal.append(
        "generation_verified",
        json!({
            "generation_id": generation.generation_id,
            "generation_path": generation.generation_path,
            "install_root": generation.install_root,
            "tree_sha": publication.tree_sha,
            "publication_sha256": publication.publication_sha256,
            "executable": {
                "path": generation.executable_path,
                "bytes": publication.executable_bytes,
                "sha256": publication.executable_sha256,
            },
            "connection_journal": {
                "root": generation.connections_root,
                "generation_path": generation.generation_connections_path,
                "connection_path": journal.path,
            },
        }),
    )?;

    let mut command = Command::new(&generation.executable_path);
    command
        .arg(INTERNAL_WORKER_ARG)
        .arg(&generation.generation_id)
        .arg(supervisor.pid.to_string())
        .arg(supervisor.process_start_utc_ticks.to_string())
        .arg(&publication.publication_sha256)
        .arg(&publication.executable_sha256)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = command.spawn().map_err(|error| {
        SupervisorError::new(
            "ASTRO_MCP_WORKER_SPAWN_FAILED",
            format!(
                "the exact same-generation MCP worker {} could not start: {error}",
                generation.executable_path.display()
            ),
            "Inspect the immutable generation and runtime closure; do not substitute or retry another executable.",
        )
    })?;
    let mut worker = OwnedWorker::new(child);
    let worker_identity = ProcessIdentity::for_pid(worker.child.id(), "worker")?;
    let worker_stdin = worker.child.stdin.take().ok_or_else(|| {
        SupervisorError::new(
            "ASTRO_MCP_WORKER_STDIN_MISSING",
            "the spawned worker did not expose its owned stdin pipe",
            "Preserve the connection journal and inspect process creation; do not reconnect.",
        )
    })?;
    let worker_stdout = worker.child.stdout.take().ok_or_else(|| {
        SupervisorError::new(
            "ASTRO_MCP_WORKER_STDOUT_MISSING",
            "the spawned worker did not expose its owned stdout pipe",
            "Preserve the connection journal and inspect process creation; do not reconnect.",
        )
    })?;
    let worker_stderr = worker.child.stderr.take().ok_or_else(|| {
        SupervisorError::new(
            "ASTRO_MCP_WORKER_STDERR_MISSING",
            "the spawned worker did not expose its owned stderr pipe",
            "Preserve the connection journal and inspect process creation; do not reconnect.",
        )
    })?;
    journal.append(
        "worker_started",
        json!({
            "worker": worker_identity.as_value(),
            "supervisor": supervisor.as_value(),
            "client": client.as_value(),
            "executable_path": generation.executable_path,
            "executable_sha256": publication.executable_sha256,
            "publication_sha256": publication.publication_sha256,
            "retry_count": 0,
        }),
    )?;

    let relay = relay_connection(
        &mut worker,
        worker_stdin,
        worker_stdout,
        worker_stderr,
        journal,
        &worker_identity,
    )?;
    worker.reaped = true;
    journal.append("connection_terminal", relay.terminal)?;
    Ok(relay.exit_code)
}

pub(crate) fn validate_worker_invocation(args: &[String]) -> Result<(), SupervisorError> {
    if args.len() != 6 || args.first().map(String::as_str) != Some(INTERNAL_WORKER_ARG) {
        return Err(SupervisorError::new(
            "ASTRO_MCP_WORKER_ARGUMENTS_INVALID",
            format!("the private worker received {} arguments", args.len()),
            "Start the installed generation through an MCP client; never invoke the private worker directly.",
        ));
    }
    let generation = detect_installed_generation()?.ok_or_else(|| {
        SupervisorError::new(
            "ASTRO_MCP_WORKER_NOT_INSTALLED",
            "the private MCP worker was invoked outside an immutable installed generation",
            "Start the workspace artifact without private arguments, or publish and activate it before global use.",
        )
    })?;
    if args[1] != generation.generation_id {
        return Err(SupervisorError::new(
            "ASTRO_MCP_WORKER_GENERATION_MISMATCH",
            format!(
                "worker argument generation '{}' differs from its physical generation '{}'",
                args[1], generation.generation_id
            ),
            "Preserve the connection journal and inspect the spawning supervisor; do not run a different generation.",
        ));
    }
    let expected_parent_pid = parse_worker_u32(&args[2], "parent pid")?;
    let expected_parent_ticks = parse_worker_u64(&args[3], "parent process start ticks")?;
    let actual_parent_pid = astrolabe_bridge::parent_process_id().ok_or_else(|| {
        SupervisorError::new(
            "ASTRO_MCP_WORKER_PARENT_UNRESOLVED",
            "the private worker could not resolve its immediate supervisor pid",
            "Preserve the connection journal and inspect the exact process tree.",
        )
    })?;
    if actual_parent_pid != expected_parent_pid {
        return Err(SupervisorError::new(
            "ASTRO_MCP_WORKER_PARENT_MISMATCH",
            format!(
                "worker parent pid {actual_parent_pid} differs from the bound supervisor pid {expected_parent_pid}"
            ),
            "Preserve the process tree and connection journal; do not accept an unbound worker.",
        ));
    }
    let actual_parent_ticks = astrolabe_bridge::process_start_utc_ticks(actual_parent_pid)
        .map_err(|error| {
            SupervisorError::new(
                "ASTRO_MCP_WORKER_PARENT_IDENTITY_FAILED",
                format!("the worker could not read its supervisor generation: {error}"),
                "Inspect the exact Windows process identity and preserve the connection journal.",
            )
        })?;
    if actual_parent_ticks != expected_parent_ticks {
        return Err(SupervisorError::new(
            "ASTRO_MCP_WORKER_PARENT_GENERATION_MISMATCH",
            format!(
                "worker parent creation ticks {actual_parent_ticks} differ from the bound supervisor ticks {expected_parent_ticks}"
            ),
            "Preserve the process tree and connection journal; a numeric PID alone never authorizes this worker.",
        ));
    }
    verify_worker_binding(&generation, &args[4], &args[5])
}

/// Revalidates the worker's small receipt and physical image metadata without
/// rereading the complete executable. The supervisor already hashed the exact
/// image immediately before `Command::spawn`; this worker is bound to that
/// exact supervisor process generation and receives both measured digests as
/// arguments. Rehashing the ~284 MiB image here would double cold I/O for every
/// agent connection without adding a new correctness observation.
fn verify_worker_binding(
    generation: &InstalledGeneration,
    expected_publication_sha256: &str,
    expected_executable_sha256: &str,
) -> Result<(), SupervisorError> {
    let receipt_bytes = fs::read(&generation.publication_path).map_err(|error| {
        SupervisorError::new(
            "ASTRO_MCP_WORKER_PUBLICATION_READ_FAILED",
            format!("worker could not read its adjacent publication receipt: {error}"),
            "Preserve the immutable generation and connection journal; do not continue through receipt drift.",
        )
    })?;
    let actual_publication_sha256 = sha256_bytes(&receipt_bytes);
    if actual_publication_sha256 != expected_publication_sha256 {
        return Err(SupervisorError::new(
            "ASTRO_MCP_WORKER_PUBLICATION_MISMATCH",
            format!(
                "worker publication SHA-256 {actual_publication_sha256} differs from its supervisor binding {expected_publication_sha256}"
            ),
            "Preserve the immutable generation and connection journal; do not continue through receipt drift.",
        ));
    }
    let receipt: Value = serde_json::from_slice(&receipt_bytes).map_err(|error| {
        SupervisorError::new(
            "ASTRO_MCP_WORKER_PUBLICATION_JSON_INVALID",
            format!("worker publication receipt is invalid JSON: {error}"),
            "Preserve the receipt and publish a fresh v5 immutable generation.",
        )
    })?;
    require_json_string(&receipt, "/schema", PUBLICATION_SCHEMA)?;
    require_json_string(&receipt, "/generation/id", &generation.generation_id)?;
    require_json_path(&receipt, "/generation/root", &generation.generation_path)?;
    require_json_path(
        &receipt,
        "/artifact/installed_path",
        &generation.executable_path,
    )?;
    require_json_string(&receipt, "/artifact/sha256", expected_executable_sha256)?;
    require_json_string(
        &receipt,
        "/client_activation/transaction_schema",
        ACTIVATION_SCHEMA,
    )?;
    require_json_string(
        &receipt,
        "/connection_journal/schema",
        JOURNAL_CONTRACT_SCHEMA,
    )?;
    let expected_bytes = receipt
        .pointer("/artifact/bytes")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            SupervisorError::new(
                "ASTRO_MCP_WORKER_ARTIFACT_BYTES_INVALID",
                "worker publication artifact byte length is absent or invalid",
                "Preserve the receipt and publish a fresh v5 immutable generation.",
            )
        })?;
    let metadata = fs::metadata(&generation.executable_path).map_err(|error| {
        SupervisorError::new(
            "ASTRO_MCP_WORKER_ARTIFACT_METADATA_FAILED",
            format!("worker executable metadata could not be read: {error}"),
            "Preserve the immutable generation and inspect its exact executable.",
        )
    })?;
    if !metadata.is_file() || !metadata.permissions().readonly() || metadata.len() != expected_bytes
    {
        return Err(SupervisorError::new(
            "ASTRO_MCP_WORKER_ARTIFACT_METADATA_MISMATCH",
            format!(
                "worker executable metadata differs from the supervisor-verified receipt (bytes={}; expected_bytes={expected_bytes}; read_only={})",
                metadata.len(),
                metadata.permissions().readonly()
            ),
            "Preserve the changed generation and activate a freshly published exact artifact.",
        ));
    }
    Ok(())
}

fn parse_worker_u32(value: &str, name: &str) -> Result<u32, SupervisorError> {
    value.parse::<u32>().map_err(|error| {
        SupervisorError::new(
            "ASTRO_MCP_WORKER_ARGUMENTS_INVALID",
            format!("private worker {name} '{value}' is invalid: {error}"),
            "Start the installed generation through its MCP supervisor.",
        )
    })
}

fn parse_worker_u64(value: &str, name: &str) -> Result<u64, SupervisorError> {
    value.parse::<u64>().map_err(|error| {
        SupervisorError::new(
            "ASTRO_MCP_WORKER_ARGUMENTS_INVALID",
            format!("private worker {name} '{value}' is invalid: {error}"),
            "Start the installed generation through its MCP supervisor.",
        )
    })
}

fn verify_publication(
    generation: &InstalledGeneration,
) -> Result<VerifiedPublication, SupervisorError> {
    let receipt_bytes = fs::read(&generation.publication_path).map_err(|error| {
        SupervisorError::new(
            "ASTRO_MCP_PUBLICATION_READ_FAILED",
            format!(
                "adjacent publication receipt {} could not be read: {error}",
                generation.publication_path.display()
            ),
            "Preserve the immutable generation and publish a complete v5 generation before activation.",
        )
    })?;
    let receipt_metadata = fs::metadata(&generation.publication_path).map_err(|error| {
        SupervisorError::new(
            "ASTRO_MCP_PUBLICATION_METADATA_FAILED",
            format!("publication receipt metadata could not be read: {error}"),
            "Preserve the immutable generation and inspect the adjacent receipt.",
        )
    })?;
    if !receipt_metadata.is_file() || !receipt_metadata.permissions().readonly() {
        return Err(SupervisorError::new(
            "ASTRO_MCP_PUBLICATION_NOT_IMMUTABLE",
            format!(
                "publication receipt is not one read-only ordinary file: {}",
                generation.publication_path.display()
            ),
            "Publish a fresh immutable generation and activate only its exact receipt.",
        ));
    }
    let publication_sha256 = sha256_bytes(&receipt_bytes);
    let receipt: Value = serde_json::from_slice(&receipt_bytes).map_err(|error| {
        SupervisorError::new(
            "ASTRO_MCP_PUBLICATION_JSON_INVALID",
            format!("adjacent publication receipt is not valid JSON: {error}"),
            "Preserve the invalid receipt and publish a fresh v5 immutable generation.",
        )
    })?;
    require_json_string(&receipt, "/schema", PUBLICATION_SCHEMA)?;
    require_json_string(&receipt, "/generation/id", &generation.generation_id)?;
    require_json_path(&receipt, "/generation/root", &generation.generation_path)?;
    require_json_path(
        &receipt,
        "/artifact/installed_path",
        &generation.executable_path,
    )?;
    require_json_path(
        &receipt,
        "/client_activation/command",
        &generation.executable_path,
    )?;
    require_json_string(
        &receipt,
        "/client_activation/transaction_schema",
        ACTIVATION_SCHEMA,
    )?;
    require_json_string(
        &receipt,
        "/connection_journal/schema",
        JOURNAL_CONTRACT_SCHEMA,
    )?;
    require_json_path(
        &receipt,
        "/connection_journal/root",
        &generation.connections_root,
    )?;
    require_json_path(
        &receipt,
        "/connection_journal/generation_path",
        &generation.generation_connections_path,
    )?;
    let expected_hash = json_string(&receipt, "/artifact/sha256")?;
    if expected_hash.len() != 64
        || !expected_hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SupervisorError::new(
            "ASTRO_MCP_PUBLICATION_ARTIFACT_HASH_INVALID",
            format!("publication artifact SHA-256 is malformed: '{expected_hash}'"),
            "Publish a fresh generation from an independently hashed native artifact.",
        ));
    }
    let expected_bytes = receipt
        .pointer("/artifact/bytes")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            SupervisorError::new(
                "ASTRO_MCP_PUBLICATION_ARTIFACT_BYTES_INVALID",
                "publication artifact byte length is absent or not an unsigned integer",
                "Publish a fresh generation from an independently measured native artifact.",
            )
        })?;
    let artifact_metadata = fs::metadata(&generation.executable_path).map_err(|error| {
        SupervisorError::new(
            "ASTRO_MCP_ARTIFACT_METADATA_FAILED",
            format!("installed executable metadata could not be read: {error}"),
            "Preserve the generation and inspect its exact executable bytes.",
        )
    })?;
    if !artifact_metadata.is_file() || !artifact_metadata.permissions().readonly() {
        return Err(SupervisorError::new(
            "ASTRO_MCP_ARTIFACT_NOT_IMMUTABLE",
            format!(
                "installed executable is not one read-only ordinary file: {}",
                generation.executable_path.display()
            ),
            "Publish and activate a fresh immutable generation.",
        ));
    }
    if artifact_metadata.len() != expected_bytes {
        return Err(SupervisorError::new(
            "ASTRO_MCP_ARTIFACT_LENGTH_MISMATCH",
            format!(
                "installed executable has {} bytes but publication requires {expected_bytes}",
                artifact_metadata.len()
            ),
            "Preserve the changed generation and activate a freshly published exact artifact.",
        ));
    }
    let actual_hash = sha256_file(&generation.executable_path)?;
    if actual_hash != expected_hash {
        return Err(SupervisorError::new(
            "ASTRO_MCP_ARTIFACT_HASH_MISMATCH",
            format!(
                "installed executable SHA-256 {actual_hash} differs from publication {expected_hash}"
            ),
            "Preserve the changed generation and activate a freshly published exact artifact; do not substitute another binary.",
        ));
    }
    let receipt_readback = fs::read(&generation.publication_path).map_err(|error| {
        SupervisorError::new(
            "ASTRO_MCP_PUBLICATION_READBACK_FAILED",
            format!("publication receipt readback failed after artifact verification: {error}"),
            "Preserve the generation and inspect receipt stability before reconnecting.",
        )
    })?;
    if receipt_readback != receipt_bytes {
        return Err(SupervisorError::new(
            "ASTRO_MCP_PUBLICATION_CHANGED_DURING_VERIFICATION",
            "publication receipt bytes changed while the connection generation was being verified",
            "Preserve both observations and publish a new immutable generation.",
        ));
    }
    let tree_sha = json_string(&receipt, "/tree_sha")?.to_string();
    Ok(VerifiedPublication {
        executable_sha256: actual_hash,
        executable_bytes: expected_bytes,
        publication_sha256,
        tree_sha,
    })
}

fn require_json_string(
    document: &Value,
    pointer: &'static str,
    expected: &str,
) -> Result<(), SupervisorError> {
    let actual = json_string(document, pointer)?;
    if actual != expected {
        return Err(SupervisorError::new(
            "ASTRO_MCP_PUBLICATION_CONTRACT_MISMATCH",
            format!("publication {pointer} is '{actual}', expected '{expected}'"),
            "Preserve the receipt and publish a fresh generation with the current connection-supervisor contract.",
        ));
    }
    Ok(())
}

fn require_json_path(
    document: &Value,
    pointer: &'static str,
    expected: &Path,
) -> Result<(), SupervisorError> {
    let actual = json_string(document, pointer)?;
    if normalize_path_text(Path::new(actual)) != normalize_path_text(expected) {
        return Err(SupervisorError::new(
            "ASTRO_MCP_PUBLICATION_PATH_MISMATCH",
            format!(
                "publication {pointer} is '{}', expected '{}'",
                actual,
                expected.display()
            ),
            "Preserve the receipt and activate only the exact executable in its declared immutable generation.",
        ));
    }
    Ok(())
}

fn json_string<'a>(document: &'a Value, pointer: &'static str) -> Result<&'a str, SupervisorError> {
    document
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            SupervisorError::new(
                "ASTRO_MCP_PUBLICATION_FIELD_MISSING",
                format!("publication field {pointer} is absent or not a string"),
                "Preserve the receipt and publish a complete v5 immutable generation.",
            )
        })
}

fn normalize_path_text(path: &Path) -> String {
    let mut text = path.to_string_lossy().replace('/', "\\");
    if let Some(without_prefix) = text.strip_prefix("\\\\?\\") {
        text = without_prefix.to_string();
    }
    while text.len() > 3 && text.ends_with('\\') {
        text.pop();
    }
    text.to_lowercase()
}

fn sha256_file(path: &Path) -> Result<String, SupervisorError> {
    let file = File::open(path).map_err(|error| {
        SupervisorError::new(
            "ASTRO_MCP_ARTIFACT_READ_FAILED",
            format!(
                "installed executable {} could not be opened: {error}",
                path.display()
            ),
            "Preserve the generation and inspect the exact artifact read failure.",
        )
    })?;
    let mut reader = BufReader::with_capacity(1024 * 1024, file);
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let count = reader.read(&mut buffer).map_err(|error| {
            SupervisorError::new(
                "ASTRO_MCP_ARTIFACT_READ_FAILED",
                format!("installed executable hash read failed: {error}"),
                "Preserve the generation and inspect the exact artifact read failure.",
            )
        })?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

struct ConnectionJournal {
    path: PathBuf,
    next_sequence: u64,
    previous_record_sha256: Option<String>,
}

impl ConnectionJournal {
    fn create(
        generation: &InstalledGeneration,
        supervisor: &ProcessIdentity,
        client: &ProcessIdentity,
    ) -> Result<Self, SupervisorError> {
        ensure_ordinary_directory(&generation.install_root, false)?;
        ensure_ordinary_directory(&generation.connections_root, true)?;
        ensure_ordinary_directory(&generation.generation_connections_path, true)?;
        let connection_id = format!(
            "{}-{}-client-{}-{}",
            supervisor.pid,
            supervisor.process_start_utc_ticks,
            client.pid,
            client.process_start_utc_ticks
        );
        let path = generation.generation_connections_path.join(connection_id);
        fs::create_dir(&path).map_err(|error| {
            SupervisorError::new(
                "ASTRO_MCP_CONNECTION_JOURNAL_CREATE_FAILED",
                format!("connection journal {} could not be created without replacement: {error}", path.display()),
                "Preserve the existing path and inspect the exact process generations; never reuse a connection journal.",
            )
        })?;
        ensure_ordinary_directory(&path, false)?;
        Ok(Self {
            path,
            next_sequence: 0,
            previous_record_sha256: None,
        })
    }

    fn append(&mut self, kind: &'static str, event: Value) -> Result<String, SupervisorError> {
        let sequence = self.next_sequence;
        let record = json!({
            "schema": JOURNAL_RECORD_SCHEMA,
            "sequence": sequence,
            "previous_record_sha256": self.previous_record_sha256,
            "recorded_unix_ms": unix_millis()?,
            "kind": kind,
            "event": event,
        });
        let mut bytes = serde_json::to_vec(&record).map_err(|error| {
            SupervisorError::new(
                "ASTRO_MCP_CONNECTION_JOURNAL_SERIALIZE_FAILED",
                format!("connection journal sequence {sequence} could not serialize: {error}"),
                "Preserve the connection directory and inspect the non-serializable record.",
            )
        })?;
        bytes.push(b'\n');
        let sha256 = sha256_bytes(&bytes);
        let path = self
            .path
            .join(format!("{sequence:020}-{kind}-{sha256}.json"));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| {
                SupervisorError::new(
                    "ASTRO_MCP_CONNECTION_JOURNAL_APPEND_FAILED",
                    format!("connection record {} could not be created: {error}", path.display()),
                    "Preserve the journal and inspect the exact sequence collision or disk failure; do not skip a record.",
                )
            })?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| {
                SupervisorError::new(
                    "ASTRO_MCP_CONNECTION_JOURNAL_FLUSH_FAILED",
                    format!(
                        "connection record {} could not be durably flushed: {error}",
                        path.display()
                    ),
                    "Preserve the partial record and inspect disk state before another connection.",
                )
            })?;
        drop(file);
        let readback = fs::read(&path).map_err(|error| {
            SupervisorError::new(
                "ASTRO_MCP_CONNECTION_JOURNAL_READBACK_FAILED",
                format!(
                    "connection record {} could not be read back: {error}",
                    path.display()
                ),
                "Preserve the record and inspect its physical bytes before another connection.",
            )
        })?;
        if readback != bytes || sha256_bytes(&readback) != sha256 {
            return Err(SupervisorError::new(
                "ASTRO_MCP_CONNECTION_JOURNAL_READBACK_MISMATCH",
                format!(
                    "connection record {} differs after durable write",
                    path.display()
                ),
                "Preserve the record and disk state; do not continue this connection.",
            ));
        }
        self.next_sequence += 1;
        self.previous_record_sha256 = Some(sha256.clone());
        Ok(sha256)
    }
}

fn ensure_ordinary_directory(path: &Path, create_if_absent: bool) -> Result<(), SupervisorError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(SupervisorError::new(
                    "ASTRO_MCP_CONNECTION_DIRECTORY_INVALID",
                    format!(
                        "connection state path is not one ordinary directory: {}",
                        path.display()
                    ),
                    "Preserve the path and replace it only through an explicit operator-owned recovery transaction.",
                ));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound && create_if_absent => {
            fs::create_dir(path).map_err(|create_error| {
                SupervisorError::new(
                    "ASTRO_MCP_CONNECTION_DIRECTORY_CREATE_FAILED",
                    format!("connection state directory {} could not be created: {create_error}", path.display()),
                    "Inspect the exact parent directory and disk state; do not redirect diagnostics elsewhere.",
                )
            })?;
        }
        Err(error) => {
            return Err(SupervisorError::new(
                "ASTRO_MCP_CONNECTION_DIRECTORY_READ_FAILED",
                format!(
                    "connection state directory {} could not be read: {error}",
                    path.display()
                ),
                "Inspect the exact path and disk state; do not redirect diagnostics elsewhere.",
            ));
        }
    }
    Ok(())
}

fn unix_millis() -> Result<u128, SupervisorError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .map_err(|error| {
            SupervisorError::new(
                "ASTRO_MCP_CONNECTION_CLOCK_INVALID",
                format!("system time precedes the Unix epoch: {error}"),
                "Correct the host clock before opening another MCP connection.",
            )
        })
}

struct OwnedWorker {
    child: Child,
    reaped: bool,
}

impl OwnedWorker {
    fn new(child: Child) -> Self {
        Self {
            child,
            reaped: false,
        }
    }
}

impl Drop for OwnedWorker {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

enum RelayEvent {
    ClientFrame(ResidentJsonrpcFrame),
    ClientEof,
    ClientReadFailed(String),
    WorkerFrame(ResidentJsonrpcFrame),
    WorkerEof,
    WorkerReadFailed(String),
    WorkerStderr(Vec<u8>),
    WorkerStderrEof,
    WorkerStderrReadFailed(String),
}

struct RelayResult {
    exit_code: i32,
    terminal: Value,
}

#[derive(Debug)]
struct TerminalCause {
    code: &'static str,
    message: String,
    remediation: &'static str,
    expected_shutdown: bool,
}

fn relay_connection(
    worker: &mut OwnedWorker,
    worker_stdin: ChildStdin,
    worker_stdout: impl Read + Send + 'static,
    worker_stderr: impl Read + Send + 'static,
    journal: &mut ConnectionJournal,
    worker_identity: &ProcessIdentity,
) -> Result<RelayResult, SupervisorError> {
    let (sender, receiver) = mpsc::sync_channel(RELAY_CHANNEL_CAPACITY);
    spawn_client_reader(sender.clone())?;
    spawn_worker_reader(sender.clone(), worker_stdout)?;
    spawn_worker_stderr_reader(sender, worker_stderr)?;

    let mut worker_input = Some(worker_stdin);
    let stdout = io::stdout();
    let mut client_output = stdout.lock();
    let mut stderr_tail = Vec::new();
    let mut stderr_total_bytes = 0_u64;
    let mut stderr_truncated = false;
    let mut request_sequence = 0_u64;
    let mut pending = BTreeMap::<String, u64>::new();
    let mut last_requested_id = None::<Value>;
    let mut last_completed_id = None::<Value>;
    let mut terminal = None::<TerminalCause>;
    let mut shutdown_started = None::<Instant>;
    let mut child_status = None::<ExitStatus>;
    let mut worker_stdout_closed = false;
    let mut worker_stderr_closed = false;
    let mut kill_sent = false;

    loop {
        if child_status.is_none() {
            match worker.child.try_wait() {
                Ok(status) => child_status = status,
                Err(error) => {
                    set_terminal(
                        &mut terminal,
                        TerminalCause {
                            code: "ASTRO_MCP_WORKER_STATUS_FAILED",
                            message: format!("worker exit status could not be queried: {error}"),
                            remediation: "Preserve the connection journal and exact worker process state; do not reconnect automatically.",
                            expected_shutdown: false,
                        },
                    );
                }
            }
        }
        if child_status.is_some() && terminal.is_none() {
            set_terminal(
                &mut terminal,
                TerminalCause {
                    code: "ASTRO_MCP_WORKER_EXITED",
                    message: "the private worker exited while the client connection remained open"
                        .to_string(),
                    remediation: "Read the exact exit status, stderr tail, and last request from this connection journal; fix that cause before starting a new session.",
                    expected_shutdown: false,
                },
            );
        }

        if let Some(cause) = terminal.as_ref() {
            worker_input.take();
            if !cause.expected_shutdown && child_status.is_none() && !kill_sent {
                worker.child.kill().map_err(|error| {
                    SupervisorError::new(
                        "ASTRO_MCP_WORKER_TERMINATION_FAILED",
                        format!("owned worker could not be terminated after {}: {error}", cause.code),
                        "Preserve the live worker and connection journal; inspect the exact process before manual action.",
                    )
                })?;
                kill_sent = true;
                shutdown_started.get_or_insert_with(Instant::now);
            } else if cause.expected_shutdown {
                shutdown_started.get_or_insert_with(Instant::now);
            }
        }

        if let Some(started) = shutdown_started {
            if child_status.is_none() && started.elapsed() >= WORKER_SHUTDOWN_TIMEOUT {
                if !kill_sent {
                    worker.child.kill().map_err(|error| {
                        SupervisorError::new(
                            "ASTRO_MCP_WORKER_SHUTDOWN_TIMEOUT_KILL_FAILED",
                            format!("worker exceeded the shutdown budget and could not be terminated: {error}"),
                            "Preserve the live worker and journal; inspect the exact process before manual action.",
                        )
                    })?;
                    kill_sent = true;
                }
                terminal = Some(TerminalCause {
                    code: "ASTRO_MCP_WORKER_SHUTDOWN_TIMEOUT",
                    message: format!(
                        "worker did not exit within {} ms after its stdin closed",
                        WORKER_SHUTDOWN_TIMEOUT.as_millis()
                    ),
                    remediation: "Inspect the last request and worker stderr tail; fix the blocked shutdown path before another connection.",
                    expected_shutdown: false,
                });
            }
        }

        if child_status.is_some() && worker_stdout_closed && worker_stderr_closed {
            break;
        }

        match receiver.recv_timeout(Duration::from_millis(50)) {
            Ok(RelayEvent::ClientFrame(frame)) => {
                if terminal.is_some() {
                    continue;
                }
                request_sequence += 1;
                let metadata = message_metadata(&frame.request);
                let request_id = metadata.get("id").cloned().filter(|value| !value.is_null());
                if let Some(id) = request_id.as_ref() {
                    let key = serde_json::to_string(id).map_err(|error| {
                        SupervisorError::new(
                            "ASTRO_MCP_REQUEST_ID_SERIALIZE_FAILED",
                            format!("JSON-RPC request id could not serialize: {error}"),
                            "Preserve the request bytes and connection journal; use a valid string or integer MCP request id.",
                        )
                    })?;
                    pending.insert(key, request_sequence);
                    last_requested_id = Some(id.clone());
                }
                journal.append(
                    "request_received",
                    json!({
                        "request_sequence": request_sequence,
                        "content_length_framed": frame.content_length_framed,
                        "bytes": frame.request.len(),
                        "sha256": sha256_bytes(frame.request.as_bytes()),
                        "message": metadata,
                    }),
                )?;
                let input = worker_input.as_mut().ok_or_else(|| {
                    SupervisorError::new(
                        "ASTRO_MCP_WORKER_STDIN_CLOSED",
                        "the worker stdin closed before a received client request could be forwarded",
                        "Read the terminal journal and fix the first worker failure; do not retry the request.",
                    )
                })?;
                if let Err(error) = write_frame(input, &frame) {
                    set_terminal(
                        &mut terminal,
                        TerminalCause {
                            code: "ASTRO_MCP_WORKER_STDIN_WRITE_FAILED",
                            message: format!(
                                "request {request_sequence} could not be written to the worker: {error}"
                            ),
                            remediation: "Read the worker exit status and stderr tail in this journal; fix the exact worker failure before a new session.",
                            expected_shutdown: false,
                        },
                    );
                }
            }
            Ok(RelayEvent::ClientEof) => {
                set_terminal(
                    &mut terminal,
                    TerminalCause {
                        code: "ASTRO_MCP_CLIENT_STDIN_EOF",
                        message: "the MCP client closed the supervisor input stream".to_string(),
                        remediation: "No remediation is required for an intentional client shutdown; inspect the client if EOF was unexpected.",
                        expected_shutdown: true,
                    },
                );
            }
            Ok(RelayEvent::ClientReadFailed(error)) => {
                set_terminal(
                    &mut terminal,
                    TerminalCause {
                        code: "ASTRO_MCP_CLIENT_STDIN_READ_FAILED",
                        message: format!("client framing or stdin read failed: {error}"),
                        remediation: "Inspect the MCP client's exact framing and pipe; fix it before opening a new connection.",
                        expected_shutdown: false,
                    },
                );
            }
            Ok(RelayEvent::WorkerFrame(frame)) => {
                let metadata = message_metadata(&frame.request);
                let response_id = metadata.get("id").cloned().filter(|value| !value.is_null());
                let completed_sequence = response_id.as_ref().and_then(|id| {
                    serde_json::to_string(id)
                        .ok()
                        .and_then(|key| pending.remove(&key))
                });
                if response_id.is_some() && completed_sequence.is_none() {
                    set_terminal(
                        &mut terminal,
                        TerminalCause {
                            code: "ASTRO_MCP_WORKER_RESPONSE_ID_UNKNOWN",
                            message: format!(
                                "worker emitted response for an unknown id: {response_id:?}"
                            ),
                            remediation: "Inspect the exact request/response journal and fix JSON-RPC correlation before reconnecting.",
                            expected_shutdown: false,
                        },
                    );
                    continue;
                }
                if let Some(id) = response_id.as_ref() {
                    last_completed_id = Some(id.clone());
                }
                journal.append(
                    "response_received",
                    json!({
                        "request_sequence": completed_sequence,
                        "content_length_framed": frame.content_length_framed,
                        "bytes": frame.request.len(),
                        "sha256": sha256_bytes(frame.request.as_bytes()),
                        "message": metadata,
                        "identity_fields": collect_identity_fields(&frame.request),
                    }),
                )?;
                if terminal.is_none() {
                    if let Err(error) = write_frame(&mut client_output, &frame) {
                        set_terminal(
                            &mut terminal,
                            TerminalCause {
                                code: "ASTRO_MCP_CLIENT_STDOUT_WRITE_FAILED",
                                message: format!(
                                    "worker response could not be written to client stdout: {error}"
                                ),
                                remediation: "Inspect the client process and stdout pipe plus this journal; do not reconnect automatically.",
                                expected_shutdown: false,
                            },
                        );
                    }
                }
            }
            Ok(RelayEvent::WorkerEof) => {
                worker_stdout_closed = true;
                if terminal.is_none() {
                    set_terminal(
                        &mut terminal,
                        TerminalCause {
                            code: "ASTRO_MCP_WORKER_STDOUT_EOF",
                            message:
                                "worker stdout closed while the client connection remained open"
                                    .to_string(),
                            remediation: "Read the exact exit status, stderr tail, and last request from this journal before starting another session.",
                            expected_shutdown: false,
                        },
                    );
                }
            }
            Ok(RelayEvent::WorkerReadFailed(error)) => {
                worker_stdout_closed = true;
                set_terminal(
                    &mut terminal,
                    TerminalCause {
                        code: "ASTRO_MCP_WORKER_STDOUT_READ_FAILED",
                        message: format!("worker stdout framing or read failed: {error}"),
                        remediation: "Inspect the worker and its exact emitted bytes; fix framing before another connection.",
                        expected_shutdown: false,
                    },
                );
            }
            Ok(RelayEvent::WorkerStderr(bytes)) => {
                stderr_total_bytes = stderr_total_bytes.saturating_add(bytes.len() as u64);
                append_bounded_tail(&mut stderr_tail, &bytes, &mut stderr_truncated);
                let mut stderr = io::stderr().lock();
                let _ = stderr.write_all(&bytes).and_then(|()| stderr.flush());
            }
            Ok(RelayEvent::WorkerStderrEof) => worker_stderr_closed = true,
            Ok(RelayEvent::WorkerStderrReadFailed(error)) => {
                worker_stderr_closed = true;
                set_terminal(
                    &mut terminal,
                    TerminalCause {
                        code: "ASTRO_MCP_WORKER_STDERR_READ_FAILED",
                        message: format!("worker stderr diagnostics could not be read: {error}"),
                        remediation: "Preserve the journal and process state; restore the diagnostic pipe before another connection.",
                        expected_shutdown: false,
                    },
                );
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                set_terminal(
                    &mut terminal,
                    TerminalCause {
                        code: "ASTRO_MCP_RELAY_CHANNEL_DISCONNECTED",
                        message: "all relay readers disconnected without complete terminal events"
                            .to_string(),
                        remediation: "Preserve the journal and inspect all three stdio reader threads before another connection.",
                        expected_shutdown: false,
                    },
                );
                worker_stdout_closed = true;
                worker_stderr_closed = true;
            }
        }
    }

    let status = child_status.ok_or_else(|| {
        SupervisorError::new(
            "ASTRO_MCP_WORKER_EXIT_STATUS_MISSING",
            "worker pipes closed without an exact process exit status",
            "Preserve the journal and inspect the exact worker generation before another connection.",
        )
    })?;
    let mut cause = terminal.unwrap_or(TerminalCause {
        code: "ASTRO_MCP_WORKER_EXITED",
        message: "worker exited without a prior client or pipe terminal event".to_string(),
        remediation: "Inspect the exact exit status and stderr tail before another connection.",
        expected_shutdown: false,
    });
    if cause.expected_shutdown && !status.success() {
        cause = TerminalCause {
            code: "ASTRO_MCP_WORKER_SHUTDOWN_FAILED",
            message: format!("worker exited unsuccessfully after client EOF: {status}"),
            remediation: "Inspect the exact stderr tail and last request; fix worker shutdown before another connection.",
            expected_shutdown: false,
        };
    }
    let stderr_sha256 = sha256_bytes(&stderr_tail);
    let exit_code = if cause.expected_shutdown && status.success() {
        0
    } else {
        1
    };
    let terminal_value = json!({
        "verdict": if exit_code == 0 { "closed" } else { "failed" },
        "cause": cause.code,
        "message": cause.message,
        "remediation": cause.remediation,
        "worker": worker_identity.as_value(),
        "worker_exit": {
            "display": status.to_string(),
            "code": status.code(),
            "success": status.success(),
            "kill_sent": kill_sent,
        },
        "request_count": request_sequence,
        "pending_request_count": pending.len(),
        "last_requested_id": last_requested_id,
        "last_completed_id": last_completed_id,
        "stderr": {
            "total_bytes": stderr_total_bytes,
            "tail_bytes": stderr_tail.len(),
            "tail_sha256": stderr_sha256,
            "tail_utf8_lossy": String::from_utf8_lossy(&stderr_tail),
            "truncated": stderr_truncated,
        },
        "retry_count": 0,
    });
    Ok(RelayResult {
        exit_code,
        terminal: terminal_value,
    })
}

fn set_terminal(target: &mut Option<TerminalCause>, candidate: TerminalCause) {
    if target.is_none() {
        *target = Some(candidate);
    }
}

fn spawn_client_reader(sender: SyncSender<RelayEvent>) -> Result<(), SupervisorError> {
    thread::Builder::new()
        .name("astrolabe-supervisor-client-reader".to_string())
        .spawn(move || {
            let stdin = io::stdin();
            let mut reader = stdin.lock();
            loop {
                match read_jsonrpc_frame(&mut reader) {
                    Ok(Some(frame)) => {
                        if sender.send(RelayEvent::ClientFrame(frame)).is_err() {
                            return;
                        }
                    }
                    Ok(None) => {
                        let _ = sender.send(RelayEvent::ClientEof);
                        return;
                    }
                    Err(error) => {
                        let _ = sender.send(RelayEvent::ClientReadFailed(error.to_string()));
                        return;
                    }
                }
            }
        })
        .map(|_| ())
        .map_err(|error| {
            SupervisorError::new(
                "ASTRO_MCP_CLIENT_READER_SPAWN_FAILED",
                format!("client stdin reader thread could not start: {error}"),
                "Preserve the connection journal and inspect process thread resources.",
            )
        })
}

fn spawn_worker_reader(
    sender: SyncSender<RelayEvent>,
    worker_stdout: impl Read + Send + 'static,
) -> Result<(), SupervisorError> {
    thread::Builder::new()
        .name("astrolabe-supervisor-worker-reader".to_string())
        .spawn(move || {
            let mut reader = BufReader::new(worker_stdout);
            loop {
                match read_jsonrpc_frame(&mut reader) {
                    Ok(Some(frame)) => {
                        if sender.send(RelayEvent::WorkerFrame(frame)).is_err() {
                            return;
                        }
                    }
                    Ok(None) => {
                        let _ = sender.send(RelayEvent::WorkerEof);
                        return;
                    }
                    Err(error) => {
                        let _ = sender.send(RelayEvent::WorkerReadFailed(error.to_string()));
                        return;
                    }
                }
            }
        })
        .map(|_| ())
        .map_err(|error| {
            SupervisorError::new(
                "ASTRO_MCP_WORKER_READER_SPAWN_FAILED",
                format!("worker stdout reader thread could not start: {error}"),
                "Preserve the connection journal and inspect process thread resources.",
            )
        })
}

fn spawn_worker_stderr_reader(
    sender: SyncSender<RelayEvent>,
    mut worker_stderr: impl Read + Send + 'static,
) -> Result<(), SupervisorError> {
    thread::Builder::new()
        .name("astrolabe-supervisor-worker-stderr".to_string())
        .spawn(move || {
            let mut buffer = vec![0_u8; 4096];
            loop {
                match worker_stderr.read(&mut buffer) {
                    Ok(0) => {
                        let _ = sender.send(RelayEvent::WorkerStderrEof);
                        return;
                    }
                    Ok(count) => {
                        if sender
                            .send(RelayEvent::WorkerStderr(buffer[..count].to_vec()))
                            .is_err()
                        {
                            return;
                        }
                    }
                    Err(error) => {
                        let _ = sender.send(RelayEvent::WorkerStderrReadFailed(error.to_string()));
                        return;
                    }
                }
            }
        })
        .map(|_| ())
        .map_err(|error| {
            SupervisorError::new(
                "ASTRO_MCP_WORKER_STDERR_READER_SPAWN_FAILED",
                format!("worker stderr reader thread could not start: {error}"),
                "Preserve the connection journal and inspect process thread resources.",
            )
        })
}

fn write_frame(writer: &mut impl Write, frame: &ResidentJsonrpcFrame) -> io::Result<()> {
    if frame.content_length_framed {
        write!(
            writer,
            "Content-Length: {}\r\n\r\n{}",
            frame.request.len(),
            frame.request
        )?;
    } else {
        writeln!(writer, "{}", frame.request)?;
    }
    writer.flush()
}

fn append_bounded_tail(tail: &mut Vec<u8>, bytes: &[u8], truncated: &mut bool) {
    if bytes.len() >= MAX_STDERR_TAIL_BYTES {
        tail.clear();
        tail.extend_from_slice(&bytes[bytes.len() - MAX_STDERR_TAIL_BYTES..]);
        *truncated = true;
        return;
    }
    let combined = tail.len() + bytes.len();
    if combined > MAX_STDERR_TAIL_BYTES {
        let remove = combined - MAX_STDERR_TAIL_BYTES;
        tail.drain(..remove);
        *truncated = true;
    }
    tail.extend_from_slice(bytes);
}

fn message_metadata(message: &str) -> Value {
    let Ok(document) = serde_json::from_str::<Value>(message) else {
        return json!({
            "valid_json": false,
            "id": Value::Null,
            "method": Value::Null,
            "tool": Value::Null,
            "project": Value::Null,
        });
    };
    json!({
        "valid_json": true,
        "jsonrpc": document.get("jsonrpc").cloned().unwrap_or(Value::Null),
        "id": document.get("id").cloned().unwrap_or(Value::Null),
        "method": document.get("method").cloned().unwrap_or(Value::Null),
        "tool": document.pointer("/params/name").cloned().unwrap_or(Value::Null),
        "project": document
            .pointer("/params/arguments/project")
            .or_else(|| document.pointer("/params/project"))
            .cloned()
            .unwrap_or(Value::Null),
    })
}

fn collect_identity_fields(message: &str) -> Value {
    let Ok(document) = serde_json::from_str::<Value>(message) else {
        return Value::Object(Default::default());
    };
    let mut output = serde_json::Map::new();
    collect_identity_fields_from_value(&document, "$", 0, &mut output);
    Value::Object(output)
}

fn collect_identity_fields_from_value(
    value: &Value,
    path: &str,
    depth: usize,
    output: &mut serde_json::Map<String, Value>,
) {
    if depth > 12 || output.len() >= 64 {
        return;
    }
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let child_path = format!("{path}/{key}");
                if is_identity_key(key) && !child.is_array() && !child.is_object() {
                    output.insert(child_path.clone(), child.clone());
                }
                collect_identity_fields_from_value(child, &child_path, depth + 1, output);
            }
        }
        Value::Array(array) => {
            for (index, child) in array.iter().take(64).enumerate() {
                collect_identity_fields_from_value(
                    child,
                    &format!("{path}/{index}"),
                    depth + 1,
                    output,
                );
            }
        }
        Value::String(text) if text.starts_with('{') => {
            if let Ok(nested) = serde_json::from_str::<Value>(text) {
                collect_identity_fields_from_value(
                    &nested,
                    &format!("{path}/$json"),
                    depth + 1,
                    output,
                );
            }
        }
        _ => {}
    }
}

fn is_identity_key(key: &str) -> bool {
    matches!(
        key,
        "project"
            | "project_id"
            | "canonical_root"
            | "root"
            | "db_path"
            | "db_sha256"
            | "store_id"
            | "store_path"
            | "vault_id"
            | "vault_path"
            | "generation"
            | "generation_id"
            | "kernel_id"
            | "kernel_generation"
            | "indexed_commit"
            | "head_sha"
    )
}
