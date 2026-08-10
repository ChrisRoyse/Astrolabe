use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{DynError, migration::ActivationToolFault};

pub(crate) const ACTIVE_GENERATION_SCHEMA: &str = "astrolabe.global-mcp-active-generation.v1";
const ACTIVE_GENERATION_MAX_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct InstalledWorkerContext {
    pub(crate) generation_id: String,
    pub(crate) generation_path: PathBuf,
    pub(crate) active_generation_path: PathBuf,
    pub(crate) executable_path: PathBuf,
    pub(crate) executable_sha256: String,
    pub(crate) publication_path: PathBuf,
    pub(crate) publication_sha256: String,
}

#[derive(Debug)]
pub(crate) struct ActivationFence {
    pub(crate) epoch: u64,
    pub(crate) generation_id: String,
    pub(crate) record_sha256: String,
    // On Windows, this handle admits only FILE_SHARE_READ. The activation
    // transaction therefore cannot replace the authority while a mutation
    // admitted under this fence is still able to publish.
    _lease: fs::File,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ActivationIdentity {
    pub(crate) epoch: u64,
    pub(crate) generation_id: String,
    pub(crate) record_sha256: String,
}

impl ActivationFence {
    pub(crate) fn identity(&self) -> ActivationIdentity {
        ActivationIdentity {
            epoch: self.epoch,
            generation_id: self.generation_id.clone(),
            record_sha256: self.record_sha256.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ActiveGenerationRecord {
    pub(crate) epoch: u64,
    pub(crate) transaction_id: String,
    pub(crate) generation_id: String,
    pub(crate) generation_path: PathBuf,
    pub(crate) record_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum WorkerActivation {
    Workspace,
    Active(ActiveGenerationRecord),
    Retired(ActiveGenerationRecord),
}

static INSTALLED_WORKER: OnceLock<InstalledWorkerContext> = OnceLock::new();

pub(crate) fn register_installed_worker(mut context: InstalledWorkerContext) -> Result<(), String> {
    context.generation_path = canonical_context_path(&context.generation_path, "generation root")?;
    context.active_generation_path = canonical_context_path(
        &context.active_generation_path,
        "active-generation authority",
    )?;
    context.executable_path =
        canonical_context_path(&context.executable_path, "worker executable")?;
    context.publication_path =
        canonical_context_path(&context.publication_path, "publication receipt")?;
    if let Some(existing) = INSTALLED_WORKER.get() {
        if existing == &context {
            return Ok(());
        }
        return Err(format!(
            "ASTRO_ACTIVE_GENERATION_CONTEXT_CONFLICT: worker context was already bound to generation {:?} at {}, not {:?} at {}; remediation: preserve the process and connection journal and start one exact installed worker generation",
            existing.generation_id,
            existing.generation_path.display(),
            context.generation_id,
            context.generation_path.display(),
        ));
    }
    INSTALLED_WORKER.set(context).map_err(|context| {
        format!(
            "ASTRO_ACTIVE_GENERATION_CONTEXT_CONFLICT: worker context could not bind generation {:?} at {}; remediation: preserve the process and connection journal and start one exact installed worker generation",
            context.generation_id,
            context.generation_path.display(),
        )
    })
}

pub(crate) fn observe_worker_activation() -> Result<WorkerActivation, DynError> {
    let Some(context) = INSTALLED_WORKER.get() else {
        return Ok(WorkerActivation::Workspace);
    };
    let record = read_active_generation(context)?;
    if record.generation_id == context.generation_id
        && record.generation_path == context.generation_path
    {
        Ok(WorkerActivation::Active(record))
    } else {
        Ok(WorkerActivation::Retired(record))
    }
}

pub(crate) fn require_active_generation(
    operation: &str,
) -> Result<Option<ActivationFence>, DynError> {
    match observe_worker_activation()? {
        WorkerActivation::Workspace => Ok(None),
        WorkerActivation::Active(observed) => {
            let context = INSTALLED_WORKER
                .get()
                .expect("installed context exists for an active observation");
            let (record, lease) = read_active_generation_with_lease(context, true)?;
            if record.generation_id != context.generation_id
                || record.generation_path != context.generation_path
            {
                return Err(ActivationToolFault::new(
                    "ASTRO_INSTALLED_GENERATION_RETIRED",
                    format!(
                        "operation {operation:?} raced activation away from worker generation {:?}; observed active epoch={} generation={:?} record_sha256={}, leased active epoch={} generation={:?} record_sha256={}",
                        context.generation_id,
                        observed.epoch,
                        observed.generation_id,
                        observed.record_sha256,
                        record.epoch,
                        record.generation_id,
                        record.record_sha256,
                    ),
                    "preserve staged state and reconnect through the currently activated immutable generation",
                )
                .with_detail("operation", operation)
                .with_detail("worker_generation_id", context.generation_id.clone())
                .with_detail("observed_active_epoch", observed.epoch)
                .with_detail(
                    "observed_active_generation_id",
                    observed.generation_id.clone(),
                )
                .with_detail(
                    "observed_activation_record_sha256",
                    observed.record_sha256.clone(),
                )
                .with_detail("leased_active_epoch", record.epoch)
                .with_detail("leased_active_generation_id", record.generation_id.clone())
                .with_detail(
                    "leased_activation_record_sha256",
                    record.record_sha256.clone(),
                )
                .into());
            }
            Ok(Some(ActivationFence {
                epoch: record.epoch,
                generation_id: record.generation_id,
                record_sha256: record.record_sha256,
                _lease: lease.expect("installed mutation read requested one retained lease"),
            }))
        }
        WorkerActivation::Retired(record) => {
            let context = INSTALLED_WORKER
                .get()
                .expect("installed context exists for a retired observation");
            Err(ActivationToolFault::new(
                "ASTRO_INSTALLED_GENERATION_RETIRED",
                format!(
                    "operation {operation:?} is mutation-capable, but worker generation {:?} is not active; active epoch={} generation={:?} record_sha256={}",
                    context.generation_id,
                    record.epoch,
                    record.generation_id,
                    record.record_sha256,
                ),
                "keep this transport for admitted read-only calls and reconnect through the currently activated immutable generation before mutating state",
            )
            .with_detail("operation", operation)
            .with_detail("worker_generation_id", context.generation_id.clone())
            .with_detail("active_epoch", record.epoch)
            .with_detail("active_generation_id", record.generation_id.clone())
            .with_detail(
                "activation_record_sha256",
                record.record_sha256.clone(),
            )
            .into())
        }
    }
}

pub(crate) fn verify_activation_fence(
    fence: Option<&ActivationFence>,
    operation: &str,
) -> Result<(), DynError> {
    let Some(expected) = fence else {
        if INSTALLED_WORKER.get().is_some() {
            return Err(format!(
                "ASTRO_ACTIVE_GENERATION_FENCE_MISSING: installed operation {operation:?} has no activation fence; remediation: preserve staged state and restart the operation through the active installed generation"
            )
            .into());
        }
        return Ok(());
    };
    let current = require_active_generation(operation)?.ok_or_else(|| -> DynError {
        format!(
            "ASTRO_ACTIVE_GENERATION_FENCE_CONTEXT_LOST: installed operation {operation:?} became an uninstalled workspace operation; remediation: preserve staged state and inspect the worker invocation"
        )
        .into()
    })?;
    if current.identity() != expected.identity() {
        return Err(format!(
            "ASTRO_ACTIVE_GENERATION_FENCE_CHANGED: operation {operation:?} began at epoch={} generation={:?} record_sha256={}, but the current fence is epoch={} generation={:?} record_sha256={}; remediation: preserve the staged generation and restart it only through the current active installed generation",
            expected.epoch,
            expected.generation_id,
            expected.record_sha256,
            current.epoch,
            current.generation_id,
            current.record_sha256,
        )
        .into());
    }
    Ok(())
}

pub(crate) fn admit_tool_call(
    tool_name: &str,
    args_json: &str,
) -> Result<Option<ActivationFence>, DynError> {
    match observe_worker_activation()? {
        WorkerActivation::Workspace => Ok(None),
        WorkerActivation::Active(_) if retired_read_call_allowed(tool_name, args_json) => Ok(None),
        WorkerActivation::Active(_) => require_active_generation(tool_name),
        WorkerActivation::Retired(_) if retired_read_call_allowed(tool_name, args_json) => Ok(None),
        WorkerActivation::Retired(record) => {
            let context = INSTALLED_WORKER
                .get()
                .expect("installed context exists for a retired observation");
            Err(ActivationToolFault::new(
                "ASTRO_INSTALLED_GENERATION_RETIRED",
                format!(
                    "tool {tool_name:?} is not admitted as a read-only call on retired worker generation {:?}; active epoch={} generation={:?} record_sha256={}",
                    context.generation_id,
                    record.epoch,
                    record.generation_id,
                    record.record_sha256,
                ),
                "reconnect through the currently activated immutable generation before invoking this tool",
            )
            .with_detail("tool", tool_name)
            .with_detail("worker_generation_id", context.generation_id.clone())
            .with_detail("active_epoch", record.epoch)
            .with_detail("active_generation_id", record.generation_id.clone())
            .with_detail(
                "activation_record_sha256",
                record.record_sha256.clone(),
            )
            .into())
        }
    }
}

pub(crate) fn activation_status_json() -> Result<Value, DynError> {
    Ok(match observe_worker_activation()? {
        WorkerActivation::Workspace => json!({
            "schema": ACTIVE_GENERATION_SCHEMA,
            "status": "workspace",
            "mutation_eligible": true,
            "source": "non-installed workspace process",
        }),
        WorkerActivation::Active(record) => activation_record_json("active", true, &record),
        WorkerActivation::Retired(record) => activation_record_json("retired", false, &record),
    })
}

pub(crate) fn installed_owner_fields() -> Result<Value, DynError> {
    let process_start_utc_ticks = astrolabe_bridge::process_start_utc_ticks(std::process::id())?;
    Ok(match observe_worker_activation()? {
        WorkerActivation::Workspace => json!({
            "generation_scope": "workspace",
            "generation_id": Value::Null,
            "activation_epoch": Value::Null,
            "activation_record_sha256": Value::Null,
            "process_start_utc_ticks": process_start_utc_ticks,
        }),
        WorkerActivation::Active(record) => json!({
            "generation_scope": "installed-active",
            "generation_id": record.generation_id,
            "activation_epoch": record.epoch,
            "activation_record_sha256": record.record_sha256,
            "process_start_utc_ticks": process_start_utc_ticks,
        }),
        WorkerActivation::Retired(record) => {
            let context = INSTALLED_WORKER
                .get()
                .expect("installed context exists for a retired observation");
            json!({
                "generation_scope": "installed-retired",
                "generation_id": context.generation_id,
                "activation_epoch": record.epoch,
                "activation_record_sha256": record.record_sha256,
                "active_generation_id": record.generation_id,
                "process_start_utc_ticks": process_start_utc_ticks,
            })
        }
    })
}

fn read_active_generation(
    context: &InstalledWorkerContext,
) -> Result<ActiveGenerationRecord, DynError> {
    Ok(read_active_generation_with_lease(context, false)?.0)
}

fn read_active_generation_with_lease(
    context: &InstalledWorkerContext,
    retain_mutation_lease: bool,
) -> Result<(ActiveGenerationRecord, Option<fs::File>), DynError> {
    let metadata = fs::symlink_metadata(&context.active_generation_path).map_err(|error| -> DynError {
        format!(
            "ASTRO_ACTIVE_GENERATION_READ_FAILED: active-generation authority {} could not be inspected for installed generation {:?}: {error}; remediation: preserve the install root and complete one activation-v4 transaction before admitting background or mutation work",
            context.active_generation_path.display(),
            context.generation_id,
        )
        .into()
    })?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(format!(
            "ASTRO_ACTIVE_GENERATION_TYPE_INVALID: active-generation authority {} is not one ordinary file; remediation: preserve the install root and repair the exact activation transaction without following or replacing the unexpected entry",
            context.active_generation_path.display(),
        )
        .into());
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    if retain_mutation_lease {
        // FILE_SHARE_READ only: reads coexist; write/delete/atomic replacement
        // wait or fail explicitly until the admitted mutation drops its fence.
        options.share_mode(0x0000_0001);
    }
    let mut file = options.open(&context.active_generation_path).map_err(|error| -> DynError {
        format!(
            "ASTRO_ACTIVE_GENERATION_OPEN_FAILED: active-generation authority {} could not be opened{}: {error}; remediation: preserve the install root and inspect the exact sharing or read failure",
            context.active_generation_path.display(),
            if retain_mutation_lease { " with a mutation fence" } else { "" },
        )
        .into()
    })?;
    let opened_metadata = file.metadata().map_err(|error| -> DynError {
        format!(
            "ASTRO_ACTIVE_GENERATION_METADATA_FAILED: opened active-generation authority {} could not be inspected: {error}; remediation: preserve the open failure evidence and repair the exact activation authority",
            context.active_generation_path.display(),
        )
        .into()
    })?;
    if !opened_metadata.is_file() {
        return Err(format!(
            "ASTRO_ACTIVE_GENERATION_OPENED_TYPE_INVALID: opened active-generation authority {} is not one ordinary file; remediation: preserve the entry and repair the exact activation authority",
            context.active_generation_path.display(),
        )
        .into());
    }
    let byte_len = usize::try_from(opened_metadata.len()).map_err(|error| -> DynError {
        format!(
            "ASTRO_ACTIVE_GENERATION_LENGTH_INVALID: active-generation authority length cannot be represented: {error}; remediation: preserve the file and inspect its exact metadata"
        )
        .into()
    })?;
    if byte_len == 0 || byte_len > ACTIVE_GENERATION_MAX_BYTES {
        return Err(format!(
            "ASTRO_ACTIVE_GENERATION_LENGTH_INVALID: active-generation authority {} has {byte_len} bytes, expected 1..={ACTIVE_GENERATION_MAX_BYTES}; remediation: preserve the file and complete one bounded activation-v4 transaction",
            context.active_generation_path.display(),
        )
        .into());
    }
    let mut bytes = Vec::with_capacity(byte_len);
    file.read_to_end(&mut bytes).map_err(|error| -> DynError {
        format!(
            "ASTRO_ACTIVE_GENERATION_READ_FAILED: active-generation authority {} could not be read: {error}; remediation: preserve the install root and inspect the exact file read failure",
            context.active_generation_path.display(),
        )
        .into()
    })?;
    if bytes.len() != byte_len {
        return Err(format!(
            "ASTRO_ACTIVE_GENERATION_LENGTH_CHANGED: active-generation authority {} metadata reported {byte_len} bytes but the read returned {}; remediation: retry only after the activation transaction reaches a stable atomic replacement",
            context.active_generation_path.display(),
            bytes.len(),
        )
        .into());
    }
    let value: Value = serde_json::from_slice(&bytes).map_err(|error| -> DynError {
        format!(
            "ASTRO_ACTIVE_GENERATION_JSON_INVALID: active-generation authority {} is not valid JSON: {error}; remediation: preserve the bytes and repair the exact activation transaction",
            context.active_generation_path.display(),
        )
        .into()
    })?;
    require_string(&value, "/schema", ACTIVE_GENERATION_SCHEMA)?;
    require_path(&value, "/authority_path", &context.active_generation_path)?;
    let epoch = value
        .pointer("/activation_epoch")
        .and_then(Value::as_u64)
        .filter(|epoch| *epoch > 0)
        .ok_or_else(|| -> DynError {
            "ASTRO_ACTIVE_GENERATION_EPOCH_INVALID: activation_epoch must be one positive u64; remediation: preserve the authority and complete one valid activation-v4 transaction".into()
        })?;
    let transaction_id = json_string(&value, "/transaction_id")?;
    if transaction_id.trim().is_empty() {
        return Err("ASTRO_ACTIVE_GENERATION_TRANSACTION_INVALID: transaction_id is empty; remediation: preserve the authority and complete one valid activation-v4 transaction".into());
    }
    let generation_id = json_string(&value, "/generation/id")?;
    let generation_path = canonical_record_path(&value, "/generation/path")?;
    let publication_path = canonical_record_path(&value, "/publication/path")?;
    let artifact_path = canonical_record_path(&value, "/artifact/path")?;
    let expected_publication_path = fs::canonicalize(generation_path.join("publication.json"))
        .map_err(|error| -> DynError {
            format!(
                "ASTRO_ACTIVE_GENERATION_PUBLICATION_UNRESOLVED: active generation publication below {} could not be canonicalized: {error}; remediation: preserve the authority and restore its exact immutable publication receipt",
                generation_path.display(),
            )
            .into()
        })?;
    let expected_artifact_path = fs::canonicalize(generation_path.join("codebase-memory-mcp.exe"))
        .map_err(|error| -> DynError {
            format!(
                "ASTRO_ACTIVE_GENERATION_ARTIFACT_UNRESOLVED: active generation artifact below {} could not be canonicalized: {error}; remediation: preserve the authority and restore its exact immutable executable",
                generation_path.display(),
            )
            .into()
        })?;
    if publication_path != expected_publication_path || artifact_path != expected_artifact_path {
        return Err(format!(
            "ASTRO_ACTIVE_GENERATION_LAYOUT_MISMATCH: active generation {:?} at {} binds publication {} and artifact {}, expected {} and {}; remediation: preserve every immutable generation byte and repair the exact activation authority",
            generation_id,
            generation_path.display(),
            publication_path.display(),
            artifact_path.display(),
            expected_publication_path.display(),
            expected_artifact_path.display(),
        )
        .into());
    }
    for pointer in [
        "/publication/sha256",
        "/artifact/sha256",
        "/codex/after_sha256",
        "/claude_code/after_sha256",
    ] {
        let hash = json_string(&value, pointer)?;
        if !valid_sha256(&hash) {
            return Err(format!(
                "ASTRO_ACTIVE_GENERATION_HASH_INVALID: {pointer} is not one lowercase SHA-256 digest; remediation: preserve the authority and repair the activation record"
            )
            .into());
        }
    }
    let artifact_bytes = value
        .pointer("/artifact/bytes")
        .and_then(Value::as_u64)
        .filter(|bytes| *bytes > 0)
        .ok_or_else(|| -> DynError {
            "ASTRO_ACTIVE_GENERATION_ARTIFACT_BYTES_INVALID: /artifact/bytes must be one positive u64; remediation: preserve the authority and repair the activation record".into()
        })?;
    if generation_id == context.generation_id && generation_path == context.generation_path {
        require_path(&value, "/publication/path", &context.publication_path)?;
        require_string(&value, "/publication/sha256", &context.publication_sha256)?;
        require_path(&value, "/artifact/path", &context.executable_path)?;
        require_string(&value, "/artifact/sha256", &context.executable_sha256)?;
        let executable_bytes = context.executable_path.metadata()?.len();
        if artifact_bytes != executable_bytes {
            return Err(format!(
                "ASTRO_ACTIVE_GENERATION_ARTIFACT_BYTES_MISMATCH: active authority binds {artifact_bytes} bytes but the worker executable has {executable_bytes}; remediation: preserve the immutable generation and repair its activation authority"
            )
            .into());
        }
    }
    Ok((
        ActiveGenerationRecord {
            epoch,
            transaction_id,
            generation_id,
            generation_path,
            record_sha256: format!("{:x}", Sha256::digest(&bytes)),
        },
        retain_mutation_lease.then_some(file),
    ))
}

fn retired_read_call_allowed(tool_name: &str, args_json: &str) -> bool {
    match tool_name {
        "list_projects" | "search_graph" | "query_graph" | "trace_path" | "trace_call_path"
        | "get_code_snippet" | "get_graph_schema" | "get_architecture" | "search_code"
        | "index_status" | "detect_changes" | "detect_anomalies" | "get_provenance"
        | "get_readiness" | "get_kernel" | "kernel_answer" => true,
        "manage_adr" => json_mode(args_json)
            .as_deref()
            .is_some_and(|mode| matches!(mode, "get" | "sections")),
        "optimizer_status" => json_mode(args_json)
            .as_deref()
            .is_none_or(|mode| mode == "status"),
        "measure_bits" => {
            serde_json::from_str::<Value>(args_json)
                .ok()
                .and_then(|value| value.get("refresh").and_then(Value::as_bool))
                != Some(true)
        }
        "discover_associations" => json_mode(args_json).as_deref() == Some("read"),
        _ => false,
    }
}

fn json_mode(args_json: &str) -> Option<String> {
    serde_json::from_str::<Value>(args_json)
        .ok()
        .and_then(|value| value.get("mode")?.as_str().map(ToOwned::to_owned))
}

fn activation_record_json(
    status: &str,
    mutation_eligible: bool,
    record: &ActiveGenerationRecord,
) -> Value {
    let worker_generation = INSTALLED_WORKER
        .get()
        .map(|context| context.generation_id.as_str());
    json!({
        "schema": ACTIVE_GENERATION_SCHEMA,
        "status": status,
        "mutation_eligible": mutation_eligible,
        "worker_generation_id": worker_generation,
        "active_generation_id": record.generation_id,
        "active_generation_path": record.generation_path,
        "activation_epoch": record.epoch,
        "activation_transaction_id": record.transaction_id,
        "activation_record_sha256": record.record_sha256,
    })
}

fn json_string(value: &Value, pointer: &str) -> Result<String, DynError> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            format!(
                "ASTRO_ACTIVE_GENERATION_FIELD_INVALID: {pointer} is absent or empty; remediation: preserve the authority and repair the activation transaction"
            )
            .into()
        })
}

fn require_string(value: &Value, pointer: &str, expected: &str) -> Result<(), DynError> {
    let actual = json_string(value, pointer)?;
    if actual != expected {
        return Err(format!(
            "ASTRO_ACTIVE_GENERATION_FIELD_MISMATCH: {pointer} is {actual:?}, expected {expected:?}; remediation: preserve the authority and repair the exact activation transaction"
        )
        .into());
    }
    Ok(())
}

fn require_path(value: &Value, pointer: &str, expected: &Path) -> Result<(), DynError> {
    let actual = canonical_record_path(value, pointer)?;
    let expected = fs::canonicalize(expected).map_err(|error| -> DynError {
        format!(
            "ASTRO_ACTIVE_GENERATION_EXPECTED_PATH_UNRESOLVED: expected {pointer} path {} could not be canonicalized: {error}; remediation: preserve the worker and repair its exact immutable generation layout",
            expected.display(),
        )
        .into()
    })?;
    if actual != expected {
        return Err(format!(
            "ASTRO_ACTIVE_GENERATION_PATH_MISMATCH: {pointer} is {}, expected {}; remediation: preserve the authority and repair the exact activation transaction",
            actual.display(),
            expected.display(),
        )
        .into());
    }
    Ok(())
}

fn canonical_record_path(value: &Value, pointer: &str) -> Result<PathBuf, DynError> {
    let raw = PathBuf::from(json_string(value, pointer)?);
    fs::canonicalize(&raw).map_err(|error| {
        format!(
            "ASTRO_ACTIVE_GENERATION_PATH_UNRESOLVED: {pointer} path {} could not be canonicalized: {error}; remediation: preserve the authority and restore the exact immutable generation entry",
            raw.display(),
        )
        .into()
    })
}

fn canonical_context_path(path: &Path, role: &str) -> Result<PathBuf, String> {
    fs::canonicalize(path).map_err(|error| {
        format!(
            "ASTRO_ACTIVE_GENERATION_CONTEXT_PATH_UNRESOLVED: installed {role} {} could not be canonicalized: {error}; remediation: preserve the worker invocation and repair the exact immutable generation layout",
            path.display(),
        )
    })
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
