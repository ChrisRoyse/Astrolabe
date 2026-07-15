//! `query_graph` `as_of` time-travel (#43 final leg).
//!
//! `query_graph` is a CBM-native Cypher tool: without `as_of` it is served
//! byte-for-byte by libcbm against the project's live store and is NEVER altered
//! here. The only divergence is an opt-in `as_of=<epoch_millis>` knob, which
//! serves the Cypher read against a **temporally-consistent historical view** of
//! the graph:
//!
//! 1. The shadow vault is opened read-only and the wall-clock `as_of` is resolved
//!    to an MVCC snapshot sequence through the vault's own `time_index` CF
//!    ([`AsterVault::as_of`]) — the greatest committed seqno at or before the
//!    timestamp, fail-closed (`CALYX_TIMETRAVEL_*`) when the vault has no write at
//!    or before `t` or `t` is below the retention horizon.
//! 2. The timestamp is quantized to a cache bucket `floor(t / width)` (`width` is
//!    the registry-declared [`AS_OF_BUCKET_WIDTH_MS_KNOB`]). Each bucket owns a
//!    private store directory whose `<project>.db` is the lowered SQLite of that
//!    bucket-floor snapshot ([`lower_cbm_sqlite_at`], a pure function of the
//!    seqno). Every `t` in a bucket reuses that one lowered artifact
//!    byte-for-byte; crossing into a new bucket re-lowers (a boundary miss).
//! 3. The Cypher read runs against the bucket's `<project>.db` in a **child
//!    process** ([`run_as_of_child`]) that owns its own `CBM_CACHE_DIR=store_dir`.
//!    The parent server's process-global CBM store is NEVER repointed on the
//!    `as_of` path, so no concurrent live `query_graph` on another thread can ever
//!    observe a historical store — and a leaked switch can never serve historical
//!    bytes to a live query (#395 root-cause fix; the former process-global
//!    `set_cbm_cache_dir` switch under a serialize-mutex is gone). Child
//!    infrastructure failure (spawn/crash/timeout/no-response) fails closed with
//!    [`ASTRO_QUERY_GRAPH_AS_OF_CHILD_FAILED`]; the live store is never a fallback.
//!
//! The Cypher read subset is unchanged: the same query runs, only against the
//! historical `<project>.db`. Every `as_of` response carries a labeled `as_of`
//! block plus `trust`/`freshness`/`provenance` (invariant 1).

use super::*;
use std::io::Read;
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

/// Surface schema tag for the `as_of` envelope block.
pub(crate) const QUERY_GRAPH_AS_OF_SCHEMA: &str = "astrolabe.query_graph.as_of.v1";

/// Stable refusal code: `as_of` was supplied but is not a non-negative integer
/// count of epoch milliseconds.
pub(crate) const ASTRO_QUERY_GRAPH_AS_OF_INVALID: &str = "ASTRO_QUERY_GRAPH_AS_OF_INVALID";
/// Stable refusal code: `as_of` needs the shadow vault, but the project carries
/// no `project` argument.
pub(crate) const ASTRO_QUERY_GRAPH_AS_OF_PROJECT: &str = "ASTRO_QUERY_GRAPH_AS_OF_PROJECT";
/// Stable refusal code: the project is not shadow-indexed, so there is no vault
/// history to time-travel.
pub(crate) const ASTRO_QUERY_GRAPH_AS_OF_SHADOW: &str = "ASTRO_QUERY_GRAPH_AS_OF_SHADOW";
/// Stable refusal code: the isolated historical-store child process failed as
/// infrastructure (spawn error, crash, non-zero exit with no response, timeout,
/// or unparseable output). The live store is NEVER consulted as a fallback.
pub(crate) const ASTRO_QUERY_GRAPH_AS_OF_CHILD_FAILED: &str =
    "ASTRO_QUERY_GRAPH_AS_OF_CHILD_FAILED";

/// Wall-clock ceiling for the historical-store child `query_graph`. The bucket's
/// `<project>.db` is already lowered by the parent before the child spawns, so
/// the child only runs the Cypher read; this ceiling is generous enough for a
/// large-graph read yet bounded so a wedged child can never hang the serving
/// thread. No registry knob governs per-tool timeouts today (the timeout
/// constants in this tree — `CONFIG_DB_BUSY_TIMEOUT_MS`, `DEFAULT_FUSION_TIMEOUT_MS`
/// — are all named consts), so this follows the same pattern; promote it to a
/// knob if a tool-timeout registry family is introduced.
const AS_OF_CHILD_TIMEOUT_MS: u64 = 120_000;
/// Poll cadence while waiting for the historical-store child to exit.
const AS_OF_CHILD_POLL_MS: u64 = 20;
/// Windows `CREATE_NO_WINDOW`: the astrolabe binary is a console app, so a
/// parent with no console of its own (an stdio MCP server) would otherwise
/// allocate one for the child. The child's stdio is fully redirected here, so
/// suppressing the console is always correct.
#[cfg(windows)]
const AS_OF_CHILD_CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Monotonic disambiguator for per-request child scratch files, so concurrent
/// `as_of` queries against the same bucket never collide on the args/response
/// temp paths.
static AS_OF_CHILD_SEQ: AtomicU64 = AtomicU64::new(0);

/// True when the request opted into an `as_of` historical read.
pub(crate) fn query_graph_as_of_requested(args: &Map<String, Value>) -> bool {
    args.contains_key("as_of")
}

/// Parses `as_of` as a non-negative epoch-millisecond integer.
fn parse_as_of_millis(value: &Value) -> Option<u64> {
    match value {
        Value::Number(n) => n.as_u64(),
        // A JSON string of digits is accepted for clients that cannot express a
        // 64-bit integer natively; anything else is refused.
        Value::String(s) => s.parse::<u64>().ok(),
        _ => None,
    }
}

/// The effective bucket width from its registry declaration (single source of the
/// default; invariant 4).
fn as_of_bucket_width_ms() -> u64 {
    as_of_bucket_knob(AS_OF_BUCKET_WIDTH_MS_KNOB)
        .map_or(AS_OF_BUCKET_DEFAULT_WIDTH_MS, |knob| knob.default)
}

/// MCP entry point for `query_graph`.
///
/// Without `as_of` this is a byte-identical passthrough to the CBM tool. With
/// `as_of` it serves the Cypher read against the historical `<project>.db`
/// lowered from the vault at the resolved snapshot, and labels the envelope.
pub(crate) fn handle_query_graph(
    runner: &CbmToolRunner,
    args_json: &str,
) -> Result<String, DynError> {
    let Ok(args) = serde_json::from_str::<Value>(args_json) else {
        return Ok(runner.handle_tool_raw("query_graph", args_json)?);
    };
    let Some(args_obj) = args.as_object() else {
        return Ok(runner.handle_tool_raw("query_graph", args_json)?);
    };
    let Some(as_of_value) = args_obj.get("as_of") else {
        // Pure legacy request — CBM serves it byte-for-byte against the live store.
        return Ok(runner.handle_tool_raw("query_graph", args_json)?);
    };

    let Some(as_of_millis) = parse_as_of_millis(as_of_value) else {
        return coded_error(
            ASTRO_QUERY_GRAPH_AS_OF_INVALID,
            "query_graph as_of must be a non-negative integer count of epoch milliseconds",
            "Pass as_of=<epoch_millis>, e.g. as_of=1720000000000.",
        );
    };
    let Some(project) = status_project_from_args(args_obj)? else {
        return coded_error(
            ASTRO_QUERY_GRAPH_AS_OF_PROJECT,
            "query_graph as_of requires a project to resolve the shadow vault history",
            "Pass project=\"<name>\" alongside as_of.",
        );
    };
    if read_dial(&project)? != MigrationDial::Shadow {
        return coded_error(
            ASTRO_QUERY_GRAPH_AS_OF_SHADOW,
            format!("project {project:?} is not shadow-indexed; as_of needs the vault timeline"),
            "Run index_repository with calyx=\"shadow\" for this project before an as_of query.",
        );
    }

    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    let width_ms = as_of_bucket_width_ms();
    let bucket = as_of_millis / width_ms;
    let canonical_millis = bucket.saturating_mul(width_ms);

    let (store_dir, resolved_seq, cache_hit) =
        prepare_as_of_store(&cache_dir, &project, bucket, canonical_millis)?;

    // Strip the Astrolabe-only `as_of` knob before the CBM tool sees it. The
    // child receives the plain query, so it takes the byte-identical live
    // passthrough against ITS store (the historical `<project>.db`) and never
    // re-enters this `as_of` branch (no recursion).
    let mut sanitized = args_obj.clone();
    sanitized.remove("as_of");
    let sanitized_json = serde_json::to_string(&Value::Object(sanitized))?;

    // Run the historical Cypher in a child process that owns its own
    // `CBM_CACHE_DIR`. The parent's process-global CBM store is untouched, so a
    // concurrent live `query_graph` can never observe the historical store
    // (#395); the read is served by the child, not the parent's in-process CBM
    // store, so `runner` is not consulted on this branch.
    let raw = run_as_of_child(&store_dir, &sanitized_json)?;

    let meta = AsOfMeta {
        requested_millis: as_of_millis,
        canonical_millis,
        bucket,
        bucket_width_ms: width_ms,
        resolved_seq,
        cache_hit,
        store: store_dir.display().to_string(),
    };
    label_as_of_result(&raw, &meta)
}

/// Runs the sanitized (no-`as_of`) `query_graph` against the prepared historical
/// store `store_dir` in a **child process** that owns its own `CBM_CACHE_DIR`,
/// returning the child's raw MCP tool-result JSON string.
///
/// This is the #395 root-cause fix: isolating the historical read in a child
/// means the parent's process-global CBM store is never repointed, so a
/// concurrent live `query_graph` on another thread can never observe a historical
/// store (and a leaked switch can never serve historical bytes to a live query).
/// The child resolves its store purely from the inherited `CBM_CACHE_DIR=store_dir`
/// — `set_cbm_cache_dir`'s in-process override buffer is C process-global state
/// that a fresh child does NOT inherit, so the environment variable is the only
/// channel that survives the process boundary — so it touches only the bucket's
/// `<project>.db`.
///
/// The child is invoked as
/// `<self> cli query_graph --args-file <req> --response-out <resp>`, reading the
/// plain query from a file and writing the exact raw tool result to `<resp>`
/// (`run_cli` writes `--response-out` byte-for-byte before any stdout shaping),
/// which keeps the served envelope byte-compatible with the in-process path.
///
/// Failure semantics (invariant 3 — never a silent live fallback):
/// * A child **infrastructure** failure (spawn error, crash, timeout, or a
///   missing/empty/unparseable response file) fails closed with a
///   [`ASTRO_QUERY_GRAPH_AS_OF_CHILD_FAILED`] `{code, message, remediation}`
///   envelope (returned as `Ok`, matching this module's other refusals; it
///   carries `isError: true` so [`label_as_of_result`] surfaces it verbatim).
/// * A tool-level Cypher error is NOT an infrastructure failure: the child still
///   writes a valid `isError` envelope to `--response-out` and exits `1`, which is
///   returned verbatim for [`label_as_of_result`] to surface unrelabelled.
fn run_as_of_child(store_dir: &Path, sanitized_json: &str) -> Result<String, DynError> {
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(e) => {
            return as_of_child_error(format!(
                "cannot resolve the astrolabe binary (current_exe) to spawn the as_of child: {e}"
            ));
        }
    };

    // Per-request scratch files inside the bucket store dir (created with the
    // store, cleaned with it and by the RAII guard below); unique across
    // concurrent requests via pid + a monotonic counter.
    let unique = format!(
        "{}-{}",
        std::process::id(),
        AS_OF_CHILD_SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let args_path = store_dir.join(format!(".asof-req-{unique}.json"));
    let resp_path = store_dir.join(format!(".asof-resp-{unique}.json"));
    let _scratch = AsOfChildScratch {
        args: args_path.clone(),
        resp: resp_path.clone(),
    };

    if let Err(e) = fs::write(&args_path, sanitized_json) {
        return as_of_child_error(format!(
            "cannot stage as_of child args at {}: {e}",
            args_path.display()
        ));
    }

    let mut cmd = Command::new(&exe);
    cmd.arg("cli")
        .arg("query_graph")
        .arg("--args-file")
        .arg(&args_path)
        .arg("--response-out")
        .arg(&resp_path)
        .env("CBM_CACHE_DIR", store_dir)
        .stdin(Stdio::null())
        // The result is read back from `--response-out`; stdout is discarded so
        // the child cannot block on a full stdout pipe while we poll for exit.
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    cmd.creation_flags(AS_OF_CHILD_CREATE_NO_WINDOW);

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            return as_of_child_error(format!(
                "cannot spawn the as_of query_graph child {}: {e}",
                exe.display()
            ));
        }
    };

    // Drain stderr on a helper thread so a chatty child can never block on a full
    // stderr pipe while the poll loop waits for it to exit.
    let stderr_pipe = child.stderr.take();
    let stderr_handle = thread::spawn(move || {
        let mut buf = String::new();
        if let Some(mut pipe) = stderr_pipe {
            let _ = pipe.read_to_string(&mut buf);
        }
        buf
    });

    let deadline = Instant::now() + Duration::from_millis(AS_OF_CHILD_TIMEOUT_MS);
    let poll = Duration::from_millis(AS_OF_CHILD_POLL_MS);
    let exit_status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                thread::sleep(poll);
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                let tail = as_of_stderr_tail(&stderr_handle.join().unwrap_or_default());
                return as_of_child_error(format!(
                    "failed while waiting on the as_of query_graph child: {e}{tail}"
                ));
            }
        }
    };
    let tail = as_of_stderr_tail(&stderr_handle.join().unwrap_or_default());

    let Some(status) = exit_status else {
        return as_of_child_error(format!(
            "as_of query_graph child exceeded the {AS_OF_CHILD_TIMEOUT_MS}ms ceiling and was killed{tail}"
        ));
    };

    // A non-empty, parseable response file is the child's success channel:
    // `run_cli` writes `--response-out` only after the tool produced a result, so
    // its presence means the read completed and a non-zero exit merely mirrors an
    // `isError` envelope (surfaced verbatim). Absence/garbage => infrastructure
    // failure, and the live store is never consulted as a fallback.
    match fs::read_to_string(&resp_path) {
        Ok(raw) if !raw.trim().is_empty() && serde_json::from_str::<Value>(&raw).is_ok() => Ok(raw),
        Ok(_) => as_of_child_error(format!(
            "as_of query_graph child ({}) wrote no parseable response{tail}",
            describe_child_exit(&status)
        )),
        Err(e) => as_of_child_error(format!(
            "as_of query_graph child ({}) left no readable response file ({e}){tail}",
            describe_child_exit(&status)
        )),
    }
}

/// The fail-closed `{code, message, remediation}` result for a historical-store
/// child infrastructure failure. Returned as `Ok` (like this module's other
/// refusals) with `isError: true` so [`label_as_of_result`] surfaces it verbatim.
fn as_of_child_error(message: impl Into<String>) -> Result<String, DynError> {
    coded_error(
        ASTRO_QUERY_GRAPH_AS_OF_CHILD_FAILED,
        message,
        "The as_of (historical) read runs in an isolated child process and failed as \
         infrastructure; retry, and if it persists inspect the reported stderr tail. The live \
         query_graph path is unaffected and is never used as a fallback for a failed as_of read.",
    )
}

/// Human-readable child-exit description for the failure message.
fn describe_child_exit(status: &std::process::ExitStatus) -> String {
    match status.code() {
        Some(code) => format!("exit code {code}"),
        None => "terminated without an exit code".to_string(),
    }
}

/// The last bounded chunk of the child's stderr, appended to a failure message.
/// Empty (and appends nothing) when the child was silent.
fn as_of_stderr_tail(stderr: &str) -> String {
    /// Max stderr bytes carried into the error message.
    const MAX: usize = 600;
    let trimmed = stderr.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let tail = if trimmed.len() > MAX {
        let start = trimmed.len() - MAX;
        // Advance to the next char boundary so slicing never splits a UTF-8 code point.
        let boundary = (start..trimmed.len())
            .find(|&i| trimmed.is_char_boundary(i))
            .unwrap_or(trimmed.len());
        &trimmed[boundary..]
    } else {
        trimmed
    };
    format!("; stderr tail: {tail}")
}

/// Deletes the per-request child scratch files (args + response) on drop, so a
/// historical read leaves no residue in the bucket store dir on any exit path.
struct AsOfChildScratch {
    args: PathBuf,
    resp: PathBuf,
}

impl Drop for AsOfChildScratch {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.args);
        let _ = fs::remove_file(&self.resp);
    }
}

/// Ensures the bucket's historical store directory holds a `<project>.db` lowered
/// from the vault at the bucket-floor snapshot, lowering it on a boundary miss.
/// Returns the store dir, the resolved MVCC seqno, and whether the artifact was
/// already cached.
fn prepare_as_of_store(
    cache_dir: &Path,
    project: &str,
    bucket: u64,
    canonical_millis: u64,
) -> Result<(PathBuf, u64, bool), DynError> {
    let (vault_dir, vault_id, vault_salt) = shadow_vault_config_at(cache_dir, project)?;
    if !vault_dir.exists() {
        return Err(format!("shadow vault dir missing: {}", vault_dir.display()).into());
    }
    // Read-only over all CFs: the lowering reads Base/Graph/Ledger and the
    // time-travel resolution reads the TimeIndex CF.
    let vault = open_shadow_vault_read_only(&vault_dir, &vault_id, &vault_salt, Vec::new())?;
    let snapshot = vault.as_of(canonical_millis)?;
    let resolved_seq = snapshot.seqno();

    let store_dir = as_of_bucket_store_dir(cache_dir, project, bucket);
    // The CBM native store db for a project is `<store_dir>/<project>.db`
    // (`super::sqlite_path`); placing the historical lowered artifact there lets
    // libcbm resolve it as the project's graph store when pointed at store_dir.
    let db_path = sqlite_path(&store_dir, project);
    if db_path.exists() {
        return Ok((store_dir, resolved_seq, true));
    }
    fs::create_dir_all(&store_dir)?;
    let options = LowerSqliteOptions::new(project.to_string())
        .with_lowered_at(format!("as_of:{canonical_millis}"));
    lower_cbm_sqlite_at(&vault, &db_path, &options, resolved_seq)?;
    drop(snapshot);
    Ok((store_dir, resolved_seq, false))
}

/// Per-(cache_dir-relative) bucket store directory for a project's historical
/// views. Kept under the cache dir so it shares the store's lifecycle and is
/// cleaned with it.
fn as_of_bucket_store_dir(cache_dir: &Path, project: &str, bucket: u64) -> PathBuf {
    // Structural sanitization: the project must flatten to ONE traversal-free,
    // device-free Windows path component BY CONSTRUCTION, for any input class —
    // not merely for the inputs a test happens to plant. Three hazard classes:
    //   (a) `.`/`..` traversal components,
    //   (b) any ".." substring (never representable: a dot is only admitted when
    //       the previous emitted byte is not a dot, so consecutive dots collapse
    //       to `._` while building),
    //   (c) Windows reserved device names (CON/PRN/AUX/NUL/COM1-9/LPT1-9, with
    //       any extension — `nul.txt` IS the NUL device; the superscript
    //       COM¹/²/³ forms are non-ASCII and already fold to '_' in the char
    //       filter).
    // A name that still lands in a hazard class is disambiguated by suffixing a
    // short hash of the RAW project string: deterministic, collision-safe (the
    // hash input is the raw name, so two distinct raw names cannot converge),
    // and cache-appropriate (nothing needs to survive but uniqueness).
    let mut safe = String::with_capacity(project.len());
    for ch in project.chars() {
        let mapped = if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
            ch
        } else {
            '_'
        };
        if mapped == '.' && safe.ends_with('.') {
            safe.push('_');
        } else {
            safe.push(mapped);
        }
    }
    const RESERVED_DEVICE_STEMS: [&str; 22] = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    let stem = safe.split('.').next().unwrap_or("").to_ascii_uppercase();
    if safe.is_empty() || safe == "." || RESERVED_DEVICE_STEMS.contains(&stem.as_str()) {
        // The hash must land in the STEM (prefix position): device reservation
        // is decided by the name before the first dot, so a suffix after an
        // extension ("nul.txt-p1234") would leave the stem "nul" reserved.
        let digest = Sha256::digest(project.as_bytes());
        safe = format!(
            "p{:02x}{:02x}{:02x}{:02x}-{safe}",
            digest[0], digest[1], digest[2], digest[3]
        );
    }
    debug_assert!(
        !safe.is_empty() && safe != "." && safe != ".." && !safe.contains(".."),
        "sanitized project component must be traversal-free by construction: {safe}"
    );
    cache_dir
        .join(".astrolabe-asof")
        .join(safe)
        .join(format!("bucket-{bucket}"))
}

/// The `as_of` provenance metadata stamped onto a served historical result.
pub(crate) struct AsOfMeta {
    requested_millis: u64,
    canonical_millis: u64,
    bucket: u64,
    bucket_width_ms: u64,
    resolved_seq: u64,
    cache_hit: bool,
    store: String,
}

impl AsOfMeta {
    fn as_of_block(&self) -> Value {
        json!({
            "schema": QUERY_GRAPH_AS_OF_SCHEMA,
            "requested_millis": self.requested_millis,
            "bucket": self.bucket,
            "bucket_width_ms": self.bucket_width_ms,
            "canonical_millis": self.canonical_millis,
            "resolved_seq": self.resolved_seq,
            "cache_hit": self.cache_hit,
            "store": self.store,
            "knob_registry_version": astrolabe_lower::AS_OF_BUCKET_KNOB_REGISTRY_VERSION,
        })
    }
}

/// Labels a CBM `query_graph` result served against a historical store with the
/// `as_of` provenance block and the trust/freshness/provenance envelope. Pure
/// JSON→JSON transform (the FSV workhorse): the `structuredContent` object and
/// the mirrored `content[0].text` payload are kept byte-consistent.
pub(crate) fn label_as_of_result(raw: &str, meta: &AsOfMeta) -> Result<String, DynError> {
    if tool_result_is_error(raw)? {
        // A Cypher error over the historical store is surfaced verbatim — never
        // relabeled as a grounded answer.
        return Ok(raw.to_string());
    }
    let mut envelope: Value = serde_json::from_str(raw)?;

    if let Some(structured) = envelope
        .get_mut("structuredContent")
        .and_then(Value::as_object_mut)
    {
        label_as_of_obj(structured, meta);
    }
    if let Some(text) = envelope
        .get_mut("content")
        .and_then(Value::as_array_mut)
        .and_then(|items| items.first_mut())
        .and_then(|item| item.get_mut("text"))
        && let Some(raw_text) = text.as_str()
        && let Ok(mut text_value) = serde_json::from_str::<Value>(raw_text)
        && let Some(text_obj) = text_value.as_object_mut()
    {
        label_as_of_obj(text_obj, meta);
        *text = Value::String(serde_json::to_string(&text_value)?);
    }

    Ok(serde_json::to_string(&envelope)?)
}

/// Stamps one CBM result object with the `as_of` block and envelope labels.
fn label_as_of_obj(obj: &mut Map<String, Value>, meta: &AsOfMeta) {
    obj.insert("as_of".to_string(), meta.as_of_block());
    // Envelope labels (invariant 1): the answer is grounded in a Cypher read of
    // the historical lowered store; freshness is `historical` because it is a
    // pinned time-travel view, not the live graph.
    obj.insert("trust".to_string(), json!("grounded"));
    obj.insert("freshness".to_string(), json!("historical"));
    obj.insert(
        "provenance".to_string(),
        json!(format!(
            "{QUERY_GRAPH_AS_OF_SCHEMA}: Cypher read of the vault lowered at MVCC seq {} \
             (as_of={}ms, bucket {}), served from {} store",
            meta.resolved_seq,
            meta.requested_millis,
            meta.bucket,
            if meta.cache_hit {
                "cached"
            } else {
                "freshly-lowered"
            }
        )),
    );
}

/// A coded fail-closed `query_graph` result in the CBM tool-result envelope shape.
fn coded_error(
    code: &str,
    message: impl Into<String>,
    remediation: &str,
) -> Result<String, DynError> {
    let message = message.into();
    let payload = json!({
        "code": code,
        "message": message,
        "remediation": remediation,
    });
    Ok(serde_json::to_string(&json!({
        "content": [{"type": "text", "text": serde_json::to_string(&payload)?}],
        "structuredContent": payload,
        "isError": true,
    }))?)
}

/// The Astrolabe `as_of` extension advertised on the CBM `query_graph` schema in
/// tools/list, so a client can discover the opt-in time-travel (#43).
pub(crate) fn query_graph_astrolabe_property_overlay() -> Vec<(String, Value)> {
    vec![(
        "as_of".to_string(),
        json!({
            "type": "integer",
            "minimum": 0,
            "description": "Astrolabe extension (#43): epoch-millisecond timestamp for a \
                time-travel Cypher read. When set, the query runs against a temporally-consistent \
                historical view of the graph — the vault is resolved to the greatest committed \
                MVCC snapshot at or before this time (via the time_index CF) and lowered to a \
                per-time-bucket store. Fails closed if the vault has no state at or before the \
                timestamp. Omitted keeps the byte-identical live query."
        }),
    )]
}
