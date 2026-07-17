use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use calyx_core::CalyxError;
#[cfg(windows)]
use calyx_registry::OnnxRuntimeAttestation;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ulid::Ulid;

use super::super::warm::resident_support::ResidentLensAttestation;
use super::discovery::unix_now_ms;
use crate::durable_write;
use crate::error::{CliError, CliResult};

pub(super) const LIFECYCLE_SCHEMA_V2: &str = "calyx-panel-resident-lifecycle-v2";
pub(super) const LIFECYCLE_SCHEMA: &str = "calyx-panel-resident-lifecycle-v3";
const LIFECYCLE_CORRUPT: &str = "CALYX_PANEL_RESIDENT_LIFECYCLE_CORRUPT";
const LIFECYCLE_DURABILITY: &str = "CALYX_PANEL_RESIDENT_LIFECYCLE_DURABILITY";
const SUPERVISOR_ALREADY_RUNNING: &str = "CALYX_PANEL_RESIDENT_ALREADY_RUNNING";
const GENESIS_EVENT_SHA256: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum LifecyclePhase {
    Loading,
    LoadedIdle,
    LoadedBusy,
    Unloading,
    Unloaded,
    Faulted,
    Stopping,
    Stopped,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum RequestStage {
    Queued,
    WorkerRequestFlushed,
    /// Legacy v3 stage name retained so existing journals remain replayable.
    WorkerStarted,
    GpuSynchronized,
    HostMaterialized,
    TerminalReceived,
    PublicFlushComplete,
    Released,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum RequestOutcome {
    Succeeded,
    Failed,
    Abandoned,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LifecycleRequestRecord {
    pub(super) request_id: String,
    pub(super) generation: Option<u64>,
    pub(super) stage: RequestStage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) outcome: Option<RequestOutcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) error: Option<LifecycleErrorRecord>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LifecycleErrorRecord {
    pub(super) code: String,
    pub(super) message: String,
    pub(super) remediation: String,
    pub(super) at_unix_ms: u64,
}

impl LifecycleErrorRecord {
    pub(super) fn from_cli_error(error: &CliError) -> Self {
        Self {
            code: error.code().to_string(),
            message: error.message().to_string(),
            remediation: error.remediation().to_string(),
            at_unix_ms: unix_now_ms(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LifecycleState {
    pub(super) supervisor_pid: u32,
    pub(super) worker_pid: Option<u32>,
    pub(super) worker_descendant_pids: Vec<u32>,
    pub(super) phase: LifecyclePhase,
    pub(super) generation: u64,
    pub(super) queued_requests: u64,
    pub(super) in_flight: u64,
    pub(super) idle_ttl_ms: u64,
    pub(super) max_load_secs: u64,
    pub(super) max_request_secs: u64,
    pub(super) idle_deadline_unix_ms: Option<u64>,
    pub(super) load_attempt_count: u64,
    pub(super) load_success_count: u64,
    pub(super) load_failure_count: u64,
    pub(super) unload_count: u64,
    pub(super) last_worker_start_unix_ms: Option<u64>,
    pub(super) last_completion_unix_ms: Option<u64>,
    pub(super) last_unload_unix_ms: Option<u64>,
    pub(super) frozen_panel_fingerprint: String,
    pub(super) lens_attestations: Vec<ResidentLensAttestation>,
    #[cfg(windows)]
    pub(super) onnx_runtime_attestation: Option<OnnxRuntimeAttestation>,
    pub(super) last_error: Option<LifecycleErrorRecord>,
}

impl LifecycleState {
    pub(super) fn unloaded(
        supervisor_pid: u32,
        idle_ttl_ms: u64,
        max_load_secs: u64,
        max_request_secs: u64,
        frozen_panel_fingerprint: String,
        lens_attestations: Vec<ResidentLensAttestation>,
    ) -> Self {
        Self {
            supervisor_pid,
            worker_pid: None,
            worker_descendant_pids: Vec::new(),
            phase: LifecyclePhase::Unloaded,
            generation: 0,
            queued_requests: 0,
            in_flight: 0,
            idle_ttl_ms,
            max_load_secs,
            max_request_secs,
            idle_deadline_unix_ms: None,
            load_attempt_count: 0,
            load_success_count: 0,
            load_failure_count: 0,
            unload_count: 0,
            last_worker_start_unix_ms: None,
            last_completion_unix_ms: None,
            last_unload_unix_ms: None,
            frozen_panel_fingerprint,
            lens_attestations,
            #[cfg(windows)]
            onnx_runtime_attestation: None,
            last_error: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LifecycleProjection {
    pub(super) schema: String,
    pub(super) sequence: u64,
    pub(super) event: String,
    pub(super) supervisor_pid: u32,
    pub(super) worker_pid: Option<u32>,
    pub(super) worker_descendant_pids: Vec<u32>,
    pub(super) phase: LifecyclePhase,
    pub(super) generation: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub(super) queued_requests: u64,
    pub(super) in_flight: u64,
    pub(super) idle_ttl_ms: u64,
    pub(super) max_load_secs: u64,
    pub(super) max_request_secs: u64,
    pub(super) idle_deadline_unix_ms: Option<u64>,
    pub(super) load_attempt_count: u64,
    pub(super) load_success_count: u64,
    pub(super) load_failure_count: u64,
    pub(super) unload_count: u64,
    pub(super) last_worker_start_unix_ms: Option<u64>,
    pub(super) last_completion_unix_ms: Option<u64>,
    pub(super) last_unload_unix_ms: Option<u64>,
    pub(super) frozen_panel_fingerprint: String,
    pub(super) lens_attestations: Vec<ResidentLensAttestation>,
    #[cfg(windows)]
    pub(super) onnx_runtime_attestation: Option<OnnxRuntimeAttestation>,
    pub(super) last_error: Option<LifecycleErrorRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) request: Option<LifecycleRequestRecord>,
    pub(super) recorded_at_unix_ms: u64,
    pub(super) previous_event_sha256: String,
    pub(super) event_sha256: String,
}

impl LifecycleProjection {
    pub(super) fn state(&self) -> LifecycleState {
        LifecycleState {
            supervisor_pid: self.supervisor_pid,
            worker_pid: self.worker_pid,
            worker_descendant_pids: self.worker_descendant_pids.clone(),
            phase: self.phase,
            generation: self.generation,
            queued_requests: self.queued_requests,
            in_flight: self.in_flight,
            idle_ttl_ms: self.idle_ttl_ms,
            max_load_secs: self.max_load_secs,
            max_request_secs: self.max_request_secs,
            idle_deadline_unix_ms: self.idle_deadline_unix_ms,
            load_attempt_count: self.load_attempt_count,
            load_success_count: self.load_success_count,
            load_failure_count: self.load_failure_count,
            unload_count: self.unload_count,
            last_worker_start_unix_ms: self.last_worker_start_unix_ms,
            last_completion_unix_ms: self.last_completion_unix_ms,
            last_unload_unix_ms: self.last_unload_unix_ms,
            frozen_panel_fingerprint: self.frozen_panel_fingerprint.clone(),
            lens_attestations: self.lens_attestations.clone(),
            #[cfg(windows)]
            onnx_runtime_attestation: self.onnx_runtime_attestation.clone(),
            last_error: self.last_error.clone(),
        }
    }
}

pub(super) struct LifecycleStore {
    _supervisor_lock: File,
    journal_path: PathBuf,
    snapshot_path: PathBuf,
    journal: File,
    journal_len: u64,
    last: Option<LifecycleProjection>,
    recovered_requests: Vec<LifecycleRequestRecord>,
    request_states: BTreeMap<String, ReplayedRequest>,
    poisoned: bool,
}

impl LifecycleStore {
    pub(super) fn open(home: &Path) -> CliResult<Self> {
        let resident_dir = home.join("resident");
        fs::create_dir_all(&resident_dir).map_err(|error| {
            durability_error(format!(
                "create resident lifecycle directory {} failed: {error}",
                resident_dir.display()
            ))
        })?;
        let journal_path = resident_dir.join("lifecycle.jsonl");
        let snapshot_path = resident_dir.join("lifecycle.json");
        let supervisor_lock_path = resident_dir.join("supervisor.lock");
        let previous_lock_owner = fs::read_to_string(&supervisor_lock_path).ok();
        let mut supervisor_lock = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .share_mode(0)
            .open(&supervisor_lock_path)
            .map_err(|error| {
                let owner = previous_lock_owner
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .unwrap_or("owner metadata unavailable");
                already_running_error(format!(
                    "acquire exclusive resident supervisor lock {} failed: {error}; recorded owner: {owner}",
                    supervisor_lock_path.display()
                ))
            })?;
        let lock_record = serde_json::json!({
            "schema": "calyx-panel-resident-supervisor-lock-v1",
            "supervisor_pid": std::process::id(),
            "started_at_unix_ms": unix_now_ms(),
            "home": home,
            "executable": std::env::current_exe().ok(),
        });
        let mut lock_bytes = serde_json::to_vec_pretty(&lock_record).map_err(|error| {
            durability_error(format!(
                "serialize resident supervisor lock {} failed: {error}",
                supervisor_lock_path.display()
            ))
        })?;
        lock_bytes.push(b'\n');
        supervisor_lock.write_all(&lock_bytes).map_err(|error| {
            durability_error(format!(
                "write resident supervisor lock {} failed: {error}",
                supervisor_lock_path.display()
            ))
        })?;
        supervisor_lock.flush().map_err(|error| {
            durability_error(format!(
                "flush resident supervisor lock {} failed: {error}",
                supervisor_lock_path.display()
            ))
        })?;
        supervisor_lock.sync_all().map_err(|error| {
            durability_error(format!(
                "sync resident supervisor lock {} failed: {error}",
                supervisor_lock_path.display()
            ))
        })?;
        let journal_bytes = match fs::read(&journal_path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => {
                return Err(durability_error(format!(
                    "read resident lifecycle journal {} failed: {error}",
                    journal_path.display()
                )));
            }
        };
        let replay = replay_journal(&journal_path, &journal_bytes)?;
        let journal = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&journal_path)
            .map_err(|error| {
                durability_error(format!(
                    "open resident lifecycle journal {} for append failed: {error}",
                    journal_path.display()
                ))
            })?;
        let LifecycleReplay { last, requests } = replay;
        let recovered_requests = requests.values().map(|state| state.last.clone()).collect();
        let store = Self {
            _supervisor_lock: supervisor_lock,
            journal_path,
            snapshot_path,
            journal,
            journal_len: u64::try_from(journal_bytes.len()).map_err(|_| {
                corrupt_error("resident lifecycle journal length exceeds u64 capacity")
            })?,
            last,
            recovered_requests,
            request_states: requests,
            poisoned: false,
        };
        store.reconcile_snapshot()?;
        Ok(store)
    }

    pub(super) fn last(&self) -> Option<&LifecycleProjection> {
        self.last.as_ref()
    }

    pub(super) fn take_recovered_requests(&mut self) -> Vec<LifecycleRequestRecord> {
        std::mem::take(&mut self.recovered_requests)
    }

    pub(super) fn journal_path(&self) -> &Path {
        &self.journal_path
    }

    pub(super) fn snapshot_path(&self) -> &Path {
        &self.snapshot_path
    }

    pub(super) fn append(
        &mut self,
        event: impl Into<String>,
        state: &LifecycleState,
    ) -> CliResult<LifecycleProjection> {
        self.append_request(event, state, None)
    }

    pub(super) fn append_request(
        &mut self,
        event: impl Into<String>,
        state: &LifecycleState,
        request: Option<LifecycleRequestRecord>,
    ) -> CliResult<LifecycleProjection> {
        if self.poisoned {
            return Err(durability_error(format!(
                "resident lifecycle store {} is faulted after an earlier durability failure",
                self.journal_path.display()
            )));
        }
        let event = event.into();
        if event.trim().is_empty() {
            return Err(corrupt_error("resident lifecycle event name is blank"));
        }
        self.verify_journal_length()?;

        let sequence = match self.last.as_ref() {
            Some(record) => record.sequence.checked_add(1).ok_or_else(|| {
                corrupt_error("resident lifecycle sequence exhausted u64 capacity")
            })?,
            None => 1,
        };
        let previous_event_sha256 = self.last.as_ref().map_or_else(
            || GENESIS_EVENT_SHA256.to_string(),
            |record| record.event_sha256.clone(),
        );
        let mut projection = projection_from_state(
            sequence,
            event,
            state,
            request,
            unix_now_ms(),
            previous_event_sha256.clone(),
        );
        projection.event_sha256 = event_sha256(&projection).map_err(|error| {
            durability_error(format!(
                "serialize resident lifecycle hash material failed: {error}"
            ))
        })?;
        let line_number = usize::try_from(sequence).unwrap_or(usize::MAX);
        validate_replayed_record(
            &self.journal_path,
            line_number,
            &projection,
            sequence,
            &previous_event_sha256,
        )?;
        let mut proposed_request_states = self.request_states.clone();
        validate_replayed_request(
            &self.journal_path,
            line_number,
            self.last.as_ref(),
            &projection,
            &mut proposed_request_states,
        )?;
        let mut journal_record = serde_json::to_vec(&projection).map_err(|error| {
            durability_error(format!(
                "serialize resident lifecycle journal event failed: {error}"
            ))
        })?;
        journal_record.push(b'\n');
        let next_journal_len = self
            .journal_len
            .checked_add(u64::try_from(journal_record.len()).map_err(|_| {
                corrupt_error("resident lifecycle journal record length exceeds u64 capacity")
            })?)
            .ok_or_else(|| corrupt_error("resident lifecycle journal length overflow"))?;

        if let Err(error) = self.journal.write_all(&journal_record) {
            self.poisoned = true;
            return Err(durability_error(format!(
                "append resident lifecycle event {} sequence {} to {} failed: {error}",
                projection.event,
                projection.sequence,
                self.journal_path.display()
            )));
        }
        if let Err(error) = self.journal.flush() {
            self.poisoned = true;
            return Err(durability_error(format!(
                "flush resident lifecycle event {} sequence {} to {} failed: {error}",
                projection.event,
                projection.sequence,
                self.journal_path.display()
            )));
        }
        if let Err(error) = self.journal.sync_all() {
            self.poisoned = true;
            return Err(durability_error(format!(
                "sync resident lifecycle event {} sequence {} to {} failed: {error}",
                projection.event,
                projection.sequence,
                self.journal_path.display()
            )));
        }

        if let Err(error) = self.publish_and_verify_snapshot(&projection) {
            self.poisoned = true;
            return Err(error);
        }
        self.journal_len = next_journal_len;
        self.last = Some(projection.clone());
        self.request_states = proposed_request_states;
        Ok(projection)
    }

    fn verify_journal_length(&self) -> CliResult {
        let observed = self.journal.metadata().map_err(|error| {
            durability_error(format!(
                "inspect resident lifecycle journal {} failed: {error}",
                self.journal_path.display()
            ))
        })?;
        if observed.len() != self.journal_len {
            return Err(corrupt_error(format!(
                "resident lifecycle journal {} changed outside this store: expected {} bytes, observed {} bytes",
                self.journal_path.display(),
                self.journal_len,
                observed.len()
            )));
        }
        Ok(())
    }

    fn reconcile_snapshot(&self) -> CliResult {
        let Some(expected) = &self.last else {
            if self.snapshot_path.exists() {
                return Err(corrupt_error(format!(
                    "resident lifecycle snapshot {} exists without an authoritative journal event",
                    self.snapshot_path.display()
                )));
            }
            return Ok(());
        };

        match read_snapshot(&self.snapshot_path) {
            Ok(observed) if projections_equal(&observed, expected)? => Ok(()),
            Ok(_) | Err(_) => self.publish_and_verify_snapshot(expected),
        }
    }

    fn publish_and_verify_snapshot(&self, projection: &LifecycleProjection) -> CliResult {
        let mut bytes = serde_json::to_vec_pretty(projection).map_err(|error| {
            durability_error(format!(
                "serialize resident lifecycle snapshot failed: {error}"
            ))
        })?;
        bytes.push(b'\n');
        durable_write::write_bytes_atomic(
            &self.snapshot_path,
            &bytes,
            "resident lifecycle snapshot",
        )
        .map_err(|error| {
            durability_error(format!(
                "publish resident lifecycle snapshot {} failed: {}: {}; remediation: {}",
                self.snapshot_path.display(),
                error.code(),
                error.message(),
                error.remediation()
            ))
        })?;
        let observed = read_snapshot(&self.snapshot_path)?;
        if !projections_equal(&observed, projection)? {
            return Err(durability_error(format!(
                "resident lifecycle snapshot {} readback differs from journal sequence {} hash {}",
                self.snapshot_path.display(),
                projection.sequence,
                projection.event_sha256
            )));
        }
        Ok(())
    }
}

struct LifecycleReplay {
    last: Option<LifecycleProjection>,
    requests: BTreeMap<String, ReplayedRequest>,
}

#[derive(Clone)]
struct ReplayedRequest {
    last: LifecycleRequestRecord,
    admitted: bool,
}

fn replay_journal(path: &Path, bytes: &[u8]) -> CliResult<LifecycleReplay> {
    if bytes.is_empty() {
        return Ok(LifecycleReplay {
            last: None,
            requests: BTreeMap::new(),
        });
    }
    if bytes.last() != Some(&b'\n') {
        return Err(corrupt_error(format!(
            "resident lifecycle journal {} ends with a truncated event (missing newline)",
            path.display()
        )));
    }

    let mut expected_sequence = Some(1_u64);
    let mut expected_previous = GENESIS_EVENT_SHA256.to_string();
    let mut last = None;
    let mut requests = BTreeMap::<String, ReplayedRequest>::new();
    let lines: Vec<_> = bytes.split(|byte| *byte == b'\n').collect();
    for (line_index, line) in lines.iter().enumerate() {
        if line.iter().all(u8::is_ascii_whitespace) {
            if line_index + 1 == lines.len() && line.is_empty() {
                continue;
            }
            return Err(corrupt_error(format!(
                "resident lifecycle journal {} line {} is blank outside the hash chain",
                path.display(),
                line_index + 1
            )));
        }
        let raw_record = serde_json::from_slice::<serde_json::Value>(line).map_err(|error| {
            corrupt_error(format!(
                "resident lifecycle journal {} line {} is not a complete lifecycle envelope: {error}",
                path.display(),
                line_index + 1
            ))
        })?;
        let record = serde_json::from_value::<LifecycleProjection>(raw_record.clone()).map_err(
            |error| {
                corrupt_error(format!(
                    "resident lifecycle journal {} line {} does not match lifecycle schema: {error}",
                    path.display(),
                    line_index + 1
                ))
            },
        )?;
        let typed_record = serde_json::to_value(&record).map_err(|error| {
            corrupt_error(format!(
                "resident lifecycle journal {} line {} cannot be normalized for verification: {error}",
                path.display(),
                line_index + 1
            ))
        })?;
        if raw_record != typed_record {
            return Err(corrupt_error(format!(
                "resident lifecycle journal {} line {} contains fields outside schema {}",
                path.display(),
                line_index + 1,
                LIFECYCLE_SCHEMA
            )));
        }
        let sequence = expected_sequence.ok_or_else(|| {
            corrupt_error(format!(
                "resident lifecycle journal {} contains an event after sequence {} exhausted u64 capacity",
                path.display(),
                u64::MAX
            ))
        })?;
        validate_replayed_record(path, line_index + 1, &record, sequence, &expected_previous)?;
        validate_replayed_request(path, line_index + 1, last.as_ref(), &record, &mut requests)?;
        expected_sequence = sequence.checked_add(1);
        expected_previous.clone_from(&record.event_sha256);
        last = Some(record);
    }
    Ok(LifecycleReplay { last, requests })
}

fn validate_replayed_request(
    path: &Path,
    line_number: usize,
    previous: Option<&LifecycleProjection>,
    record: &LifecycleProjection,
    requests: &mut BTreeMap<String, ReplayedRequest>,
) -> CliResult {
    if record.schema == LIFECYCLE_SCHEMA_V2 {
        return Ok(());
    }
    let previous_queued = previous.map_or(0, |previous| previous.queued_requests);
    let previous_in_flight = previous.map_or(0, |previous| previous.in_flight);
    if previous.is_some_and(|previous| previous.schema == LIFECYCLE_SCHEMA_V2)
        && record.event == "legacy_requests_recovered_abandoned"
        && previous_in_flight != 0
        && record.request.is_none()
        && record.queued_requests == 0
        && record.in_flight == 0
        && record.last_error.as_ref().is_some_and(|error| {
            error.code == "CALYX_PANEL_RESIDENT_LEGACY_REQUESTS_ABANDONED_ON_RESTART"
        })
    {
        return Ok(());
    }
    let Some(request) = record.request.as_ref() else {
        if record.queued_requests != previous_queued || record.in_flight != previous_in_flight {
            return Err(request_semantic_error(
                path,
                line_number,
                format!(
                    "event {:?} changed queued/in_flight from {previous_queued}/{previous_in_flight} to {}/{} without a request record",
                    record.event, record.queued_requests, record.in_flight
                ),
            ));
        }
        return Ok(());
    };
    if !request
        .request_id
        .parse::<Ulid>()
        .is_ok_and(|parsed| parsed.to_string() == request.request_id.as_str())
    {
        return Err(request_semantic_error(
            path,
            line_number,
            format!(
                "request_id {:?} is not a canonical ULID",
                request.request_id
            ),
        ));
    }
    match record.event.as_str() {
        "request_queued" => {
            if requests.contains_key(&request.request_id)
                || request.stage != RequestStage::Queued
                || request.generation.is_some()
                || request.outcome.is_some()
                || request.error.is_some()
                || previous_queued.checked_add(1) != Some(record.queued_requests)
                || record.in_flight != previous_in_flight
            {
                return Err(request_semantic_error(
                    path,
                    line_number,
                    format!(
                        "request_queued has invalid identity/stage/counters for {}",
                        request.request_id
                    ),
                ));
            }
            requests.insert(
                request.request_id.clone(),
                ReplayedRequest {
                    last: request.clone(),
                    admitted: false,
                },
            );
        }
        "lease_acquired" => {
            let Some(state) = requests.get_mut(&request.request_id) else {
                return Err(request_semantic_error(
                    path,
                    line_number,
                    format!(
                        "lease_acquired has no queued request {}",
                        request.request_id
                    ),
                ));
            };
            if state.admitted
                || state.last.stage != RequestStage::Queued
                || request.stage != RequestStage::Queued
                || request.generation != Some(record.generation)
                || request.outcome.is_some()
                || request.error.is_some()
                || record.queued_requests.checked_add(1) != Some(previous_queued)
                || previous_in_flight.checked_add(1) != Some(record.in_flight)
            {
                return Err(request_semantic_error(
                    path,
                    line_number,
                    format!("lease_acquired is inconsistent for {}", request.request_id),
                ));
            }
            state.admitted = true;
            state.last = request.clone();
        }
        "request_stage" => {
            let Some(state) = requests.get_mut(&request.request_id) else {
                return Err(request_semantic_error(
                    path,
                    line_number,
                    format!("request_stage has no active request {}", request.request_id),
                ));
            };
            if !state.admitted
                || request.generation != state.last.generation
                || !valid_replayed_stage_transition(state.last.stage, request.stage)
                || request.outcome.is_some()
                || request.error.is_some()
                || record.queued_requests != previous_queued
                || record.in_flight != previous_in_flight
            {
                return Err(request_semantic_error(
                    path,
                    line_number,
                    format!(
                        "request_stage {:?}->{:?} is inconsistent for {}",
                        state.last.stage, request.stage, request.request_id
                    ),
                ));
            }
            state.last = request.clone();
        }
        "request_released" | "request_recovered_abandoned" | "request_recovered_succeeded" => {
            let Some(state) = requests.get(&request.request_id) else {
                return Err(request_semantic_error(
                    path,
                    line_number,
                    format!(
                        "request release has no active request {}",
                        request.request_id
                    ),
                ));
            };
            let succeeded = request.outcome == Some(RequestOutcome::Succeeded);
            let recovered_abandoned = record.event == "request_recovered_abandoned";
            let recovered_succeeded = record.event == "request_recovered_succeeded";
            let recovery = recovered_abandoned || recovered_succeeded;
            let counters_valid = if recovery {
                record.queued_requests == 0 && record.in_flight == 0
            } else if state.admitted {
                record.queued_requests == previous_queued
                    && record.in_flight.checked_add(1) == Some(previous_in_flight)
            } else {
                record.queued_requests.checked_add(1) == Some(previous_queued)
                    && record.in_flight == previous_in_flight
            };
            if request.stage != RequestStage::Released
                || request.outcome.is_none()
                || (state.admitted && request.generation != state.last.generation)
                || (succeeded
                    && (state.last.stage != RequestStage::PublicFlushComplete
                        || request.error.is_some()))
                || (!succeeded && request.error.is_none())
                || (recovered_abandoned && request.outcome != Some(RequestOutcome::Abandoned))
                || (recovered_succeeded && request.outcome != Some(RequestOutcome::Succeeded))
                || !counters_valid
            {
                return Err(request_semantic_error(
                    path,
                    line_number,
                    format!("request release is inconsistent for {}", request.request_id),
                ));
            }
            requests.remove(&request.request_id);
        }
        other => {
            return Err(request_semantic_error(
                path,
                line_number,
                format!("event {other:?} carries an unexpected request record"),
            ));
        }
    }
    Ok(())
}

fn valid_replayed_stage_transition(current: RequestStage, next: RequestStage) -> bool {
    matches!(
        (current, next),
        (RequestStage::Queued, RequestStage::WorkerStarted)
            | (RequestStage::Queued, RequestStage::WorkerRequestFlushed)
            | (RequestStage::WorkerStarted, RequestStage::GpuSynchronized)
            | (
                RequestStage::WorkerRequestFlushed,
                RequestStage::GpuSynchronized
            )
            | (
                RequestStage::GpuSynchronized,
                RequestStage::HostMaterialized
            )
            | (
                RequestStage::HostMaterialized,
                RequestStage::TerminalReceived
            )
            | (RequestStage::WorkerStarted, RequestStage::TerminalReceived)
            | (
                RequestStage::WorkerRequestFlushed,
                RequestStage::TerminalReceived
            )
            | (
                RequestStage::TerminalReceived,
                RequestStage::PublicFlushComplete
            )
    )
}

fn request_semantic_error(path: &Path, line_number: usize, detail: String) -> CliError {
    corrupt_error(format!(
        "resident lifecycle journal {} line {} has an impossible request history: {detail}",
        path.display(),
        line_number
    ))
}

fn validate_replayed_record(
    path: &Path,
    line_number: usize,
    record: &LifecycleProjection,
    expected_sequence: u64,
    expected_previous: &str,
) -> CliResult {
    if record.schema != LIFECYCLE_SCHEMA && record.schema != LIFECYCLE_SCHEMA_V2 {
        return Err(corrupt_error(format!(
            "resident lifecycle journal {} line {} schema is {:?}, expected {:?} or legacy {:?}",
            path.display(),
            line_number,
            record.schema,
            LIFECYCLE_SCHEMA,
            LIFECYCLE_SCHEMA_V2,
        )));
    }
    if record.schema == LIFECYCLE_SCHEMA_V2
        && (record.queued_requests != 0 || record.request.is_some())
    {
        return Err(corrupt_error(format!(
            "resident lifecycle journal {} line {} carries v3 request fields under legacy schema {}",
            path.display(),
            line_number,
            LIFECYCLE_SCHEMA_V2
        )));
    }
    if record.sequence != expected_sequence {
        return Err(corrupt_error(format!(
            "resident lifecycle journal {} line {} sequence is {}, expected {}",
            path.display(),
            line_number,
            record.sequence,
            expected_sequence
        )));
    }
    if record.event.trim().is_empty() {
        return Err(corrupt_error(format!(
            "resident lifecycle journal {} line {} has a blank event name",
            path.display(),
            line_number
        )));
    }
    if record.previous_event_sha256 != expected_previous {
        return Err(corrupt_error(format!(
            "resident lifecycle journal {} line {} previous hash is {}, expected {}",
            path.display(),
            line_number,
            record.previous_event_sha256,
            expected_previous
        )));
    }
    let observed_hash = event_sha256(record).map_err(|error| {
        corrupt_error(format!(
            "resident lifecycle journal {} line {} cannot be hashed deterministically: {error}",
            path.display(),
            line_number
        ))
    })?;
    if record.event_sha256 != observed_hash {
        return Err(corrupt_error(format!(
            "resident lifecycle journal {} line {} event hash is {}, recomputed {}",
            path.display(),
            line_number,
            record.event_sha256,
            observed_hash
        )));
    }
    Ok(())
}

fn projection_from_state(
    sequence: u64,
    event: String,
    state: &LifecycleState,
    request: Option<LifecycleRequestRecord>,
    recorded_at_unix_ms: u64,
    previous_event_sha256: String,
) -> LifecycleProjection {
    LifecycleProjection {
        schema: LIFECYCLE_SCHEMA.to_string(),
        sequence,
        event,
        supervisor_pid: state.supervisor_pid,
        worker_pid: state.worker_pid,
        worker_descendant_pids: state.worker_descendant_pids.clone(),
        phase: state.phase,
        generation: state.generation,
        queued_requests: state.queued_requests,
        in_flight: state.in_flight,
        idle_ttl_ms: state.idle_ttl_ms,
        max_load_secs: state.max_load_secs,
        max_request_secs: state.max_request_secs,
        idle_deadline_unix_ms: state.idle_deadline_unix_ms,
        load_attempt_count: state.load_attempt_count,
        load_success_count: state.load_success_count,
        load_failure_count: state.load_failure_count,
        unload_count: state.unload_count,
        last_worker_start_unix_ms: state.last_worker_start_unix_ms,
        last_completion_unix_ms: state.last_completion_unix_ms,
        last_unload_unix_ms: state.last_unload_unix_ms,
        frozen_panel_fingerprint: state.frozen_panel_fingerprint.clone(),
        lens_attestations: state.lens_attestations.clone(),
        #[cfg(windows)]
        onnx_runtime_attestation: state.onnx_runtime_attestation.clone(),
        last_error: state.last_error.clone(),
        request,
        recorded_at_unix_ms,
        previous_event_sha256,
        event_sha256: String::new(),
    }
}

#[derive(Serialize)]
struct LifecycleHashMaterialV2<'a> {
    schema: &'a str,
    sequence: u64,
    event: &'a str,
    supervisor_pid: u32,
    worker_pid: Option<u32>,
    worker_descendant_pids: &'a [u32],
    phase: LifecyclePhase,
    generation: u64,
    in_flight: u64,
    idle_ttl_ms: u64,
    max_load_secs: u64,
    max_request_secs: u64,
    idle_deadline_unix_ms: Option<u64>,
    load_attempt_count: u64,
    load_success_count: u64,
    load_failure_count: u64,
    unload_count: u64,
    last_worker_start_unix_ms: Option<u64>,
    last_completion_unix_ms: Option<u64>,
    last_unload_unix_ms: Option<u64>,
    frozen_panel_fingerprint: &'a str,
    lens_attestations: &'a [ResidentLensAttestation],
    #[cfg(windows)]
    onnx_runtime_attestation: &'a Option<OnnxRuntimeAttestation>,
    last_error: &'a Option<LifecycleErrorRecord>,
    recorded_at_unix_ms: u64,
    previous_event_sha256: &'a str,
}

#[derive(Serialize)]
struct LifecycleHashMaterialV3<'a> {
    schema: &'a str,
    sequence: u64,
    event: &'a str,
    supervisor_pid: u32,
    worker_pid: Option<u32>,
    worker_descendant_pids: &'a [u32],
    phase: LifecyclePhase,
    generation: u64,
    queued_requests: u64,
    in_flight: u64,
    idle_ttl_ms: u64,
    max_load_secs: u64,
    max_request_secs: u64,
    idle_deadline_unix_ms: Option<u64>,
    load_attempt_count: u64,
    load_success_count: u64,
    load_failure_count: u64,
    unload_count: u64,
    last_worker_start_unix_ms: Option<u64>,
    last_completion_unix_ms: Option<u64>,
    last_unload_unix_ms: Option<u64>,
    frozen_panel_fingerprint: &'a str,
    lens_attestations: &'a [ResidentLensAttestation],
    #[cfg(windows)]
    onnx_runtime_attestation: &'a Option<OnnxRuntimeAttestation>,
    last_error: &'a Option<LifecycleErrorRecord>,
    request: &'a Option<LifecycleRequestRecord>,
    recorded_at_unix_ms: u64,
    previous_event_sha256: &'a str,
}

fn event_sha256(record: &LifecycleProjection) -> Result<String, serde_json::Error> {
    if record.schema == LIFECYCLE_SCHEMA_V2 {
        return serde_json::to_vec(&LifecycleHashMaterialV2 {
            schema: &record.schema,
            sequence: record.sequence,
            event: &record.event,
            supervisor_pid: record.supervisor_pid,
            worker_pid: record.worker_pid,
            worker_descendant_pids: &record.worker_descendant_pids,
            phase: record.phase,
            generation: record.generation,
            in_flight: record.in_flight,
            idle_ttl_ms: record.idle_ttl_ms,
            max_load_secs: record.max_load_secs,
            max_request_secs: record.max_request_secs,
            idle_deadline_unix_ms: record.idle_deadline_unix_ms,
            load_attempt_count: record.load_attempt_count,
            load_success_count: record.load_success_count,
            load_failure_count: record.load_failure_count,
            unload_count: record.unload_count,
            last_worker_start_unix_ms: record.last_worker_start_unix_ms,
            last_completion_unix_ms: record.last_completion_unix_ms,
            last_unload_unix_ms: record.last_unload_unix_ms,
            frozen_panel_fingerprint: &record.frozen_panel_fingerprint,
            lens_attestations: &record.lens_attestations,
            #[cfg(windows)]
            onnx_runtime_attestation: &record.onnx_runtime_attestation,
            last_error: &record.last_error,
            recorded_at_unix_ms: record.recorded_at_unix_ms,
            previous_event_sha256: &record.previous_event_sha256,
        })
        .map(|bytes| sha256_hex(&bytes));
    }
    let material = LifecycleHashMaterialV3 {
        schema: &record.schema,
        sequence: record.sequence,
        event: &record.event,
        supervisor_pid: record.supervisor_pid,
        worker_pid: record.worker_pid,
        worker_descendant_pids: &record.worker_descendant_pids,
        phase: record.phase,
        generation: record.generation,
        queued_requests: record.queued_requests,
        in_flight: record.in_flight,
        idle_ttl_ms: record.idle_ttl_ms,
        max_load_secs: record.max_load_secs,
        max_request_secs: record.max_request_secs,
        idle_deadline_unix_ms: record.idle_deadline_unix_ms,
        load_attempt_count: record.load_attempt_count,
        load_success_count: record.load_success_count,
        load_failure_count: record.load_failure_count,
        unload_count: record.unload_count,
        last_worker_start_unix_ms: record.last_worker_start_unix_ms,
        last_completion_unix_ms: record.last_completion_unix_ms,
        last_unload_unix_ms: record.last_unload_unix_ms,
        frozen_panel_fingerprint: &record.frozen_panel_fingerprint,
        lens_attestations: &record.lens_attestations,
        #[cfg(windows)]
        onnx_runtime_attestation: &record.onnx_runtime_attestation,
        last_error: &record.last_error,
        request: &record.request,
        recorded_at_unix_ms: record.recorded_at_unix_ms,
        previous_event_sha256: &record.previous_event_sha256,
    };
    serde_json::to_vec(&material).map(|bytes| sha256_hex(&bytes))
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

fn read_snapshot(path: &Path) -> CliResult<LifecycleProjection> {
    let bytes = fs::read(path).map_err(|error| {
        durability_error(format!(
            "read resident lifecycle snapshot {} failed: {error}",
            path.display()
        ))
    })?;
    let raw_projection = serde_json::from_slice::<serde_json::Value>(&bytes).map_err(|error| {
        durability_error(format!(
            "decode resident lifecycle snapshot {} failed: {error}",
            path.display()
        ))
    })?;
    let projection = serde_json::from_value::<LifecycleProjection>(raw_projection.clone())
        .map_err(|error| {
            durability_error(format!(
                "decode resident lifecycle snapshot {} failed: {error}",
                path.display()
            ))
        })?;
    let typed_projection = serde_json::to_value(&projection).map_err(|error| {
        durability_error(format!(
            "normalize resident lifecycle snapshot {} failed: {error}",
            path.display()
        ))
    })?;
    if raw_projection != typed_projection {
        return Err(durability_error(format!(
            "resident lifecycle snapshot {} contains fields outside schema {}",
            path.display(),
            LIFECYCLE_SCHEMA
        )));
    }
    Ok(projection)
}

fn projections_equal(left: &LifecycleProjection, right: &LifecycleProjection) -> CliResult<bool> {
    let left = serde_json::to_vec(left).map_err(|error| {
        durability_error(format!(
            "serialize resident lifecycle snapshot readback failed: {error}"
        ))
    })?;
    let right = serde_json::to_vec(right).map_err(|error| {
        durability_error(format!(
            "serialize authoritative resident lifecycle event failed: {error}"
        ))
    })?;
    Ok(left == right)
}

fn corrupt_error(message: impl Into<String>) -> CliError {
    CliError::from(CalyxError {
        code: LIFECYCLE_CORRUPT,
        message: message.into(),
        remediation: "preserve lifecycle.jsonl and lifecycle.json, stop the resident supervisor, and repair or restore the lifecycle journal before retrying",
    })
}

fn durability_error(message: impl Into<String>) -> CliError {
    CliError::from(CalyxError {
        code: LIFECYCLE_DURABILITY,
        message: message.into(),
        remediation: "stop the resident supervisor, verify CALYX_HOME storage health and permissions, then retry without deleting the lifecycle journal",
    })
}

fn already_running_error(message: impl Into<String>) -> CliError {
    CliError::from(CalyxError {
        code: SUPERVISOR_ALREADY_RUNNING,
        message: message.into(),
        remediation: "use the existing resident supervisor recorded in CALYX_HOME/resident/supervisor.lock, or stop that exact process before starting another supervisor for the same home",
    })
}
