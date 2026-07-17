use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Write};
use std::net::Shutdown;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use calyx_core::{CalyxError, SlotShape, SlotState};

use super::deadline::{DeadlineStream, connect_before, deadline_after, read_bounded_line};
use super::job::ResidentGenerationJob;
use super::source::FrozenResidentSource;
use super::*;

pub(super) const WORKER_GATE_ENV: &str = "CALYX_PANEL_RESIDENT_WORKER_GATE";
pub(super) const WORKER_AUTH_PREFIX: &[u8] = b"CALYX_PANEL_RESIDENT_AUTH1 ";

const WORKER_START_FAILED: &str = "CALYX_PANEL_RESIDENT_WORKER_START_FAILED";
const WORKER_STOP_FAILED: &str = "CALYX_PANEL_RESIDENT_WORKER_STOP_FAILED";
const WORKER_FROZEN_VIOLATION: &str = "CALYX_LENS_FROZEN_VIOLATION";
const WORKER_STOP_GRACE: Duration = Duration::from_secs(5);
const WORKER_SHUTDOWN_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
const ASSIGNMENT_GATE_SCHEMA: &str = "calyx-panel-resident-worker-assignment-v1";
const ASSIGNMENT_AUDIT_SCHEMA: &str = "calyx-panel-resident-worker-assignment-audit-v1";
const MAX_ASSIGNMENT_GATE_BYTES: u64 = 16 * 1024;

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorkerAssignment {
    schema: String,
    pub(super) worker_pid: u32,
    pub(super) supervisor_pid: u32,
    pub(super) generation: u64,
    pub(super) frozen_fingerprint: String,
    job_name: String,
    nonce: String,
}

#[derive(Debug, serde::Serialize)]
struct WorkerAssignmentAudit<'a> {
    schema: &'static str,
    worker_pid: u32,
    supervisor_pid: u32,
    generation: u64,
    frozen_fingerprint: &'a str,
    assignment_verified: bool,
    exact_job_member_pids: [u32; 1],
    private_channel_auth: &'static str,
    credential_redacted: bool,
}

pub(super) struct WorkerProcess {
    pub(super) generation: u64,
    pub(super) bind: SocketAddr,
    pub(super) ready: ReadyResponse,
    child: Child,
    job: ResidentGenerationJob,
    auth_secret: String,
}

impl WorkerProcess {
    pub(super) fn spawn(
        original_args: &[String],
        home: &Path,
        source: &FrozenResidentSource,
        generation: u64,
        max_load_secs: u64,
        max_request_secs: u64,
    ) -> CliResult<Self> {
        let generation_dir = home
            .join("resident")
            .join("generations")
            .join(format!("{generation:020}"));
        std::fs::create_dir_all(
            generation_dir
                .parent()
                .expect("generation directory has parent"),
        )?;
        std::fs::create_dir(&generation_dir).map_err(|error| {
            worker_error(
                WORKER_START_FAILED,
                format!(
                    "create unique resident generation directory {}: {error}",
                    generation_dir.display()
                ),
                "preserve the resident lifecycle journal and use its next generation number",
            )
        })?;
        let ready_path = generation_dir.join("ready.json");
        let progress_path = generation_dir.join("warm-progress.jsonl");
        let gate_path = generation_dir.join("assigned.job");
        let stdout_path = generation_dir.join("worker.stdout.log");
        let stderr_path = generation_dir.join("worker.stderr.log");
        let stdout = create_log(&stdout_path)?;
        let stderr = create_log(&stderr_path)?;
        let executable = std::env::current_exe().map_err(|error| {
            worker_error(
                WORKER_START_FAILED,
                format!("resolve current calyx executable: {error}"),
                "run the resident supervisor from a stable native Calyx executable",
            )
        })?;
        let supervisor_pid = std::process::id();
        let job = ResidentGenerationJob::create(supervisor_pid, generation, &source.fingerprint)?;
        let auth_secret = job.nonce().to_string();
        let mut command = Command::new(&executable);
        command.arg("__panel-resident-worker");
        append_worker_args(&mut command, original_args, &ready_path, &progress_path);
        command
            .env(WORKER_GATE_ENV, &gate_path)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        let mut child = command.spawn().map_err(|error| {
            worker_error(
                WORKER_START_FAILED,
                format!(
                    "spawn resident generation {generation} from {}: {error}",
                    executable.display()
                ),
                "inspect the generation logs and native executable permissions, then retry",
            )
        })?;
        if let Err(error) = job.assign_child(&child) {
            return Err(cleanup_spawn_failure(&job, &mut child, 81, error));
        }
        let assignment = WorkerAssignment {
            schema: ASSIGNMENT_GATE_SCHEMA.to_string(),
            worker_pid: child.id(),
            supervisor_pid,
            generation,
            frozen_fingerprint: source.fingerprint.clone(),
            job_name: job.name().to_string(),
            nonce: auth_secret.clone(),
        };
        if let Err(error) = write_assignment_gate(&gate_path, &assignment) {
            return Err(cleanup_spawn_failure(&job, &mut child, 82, error));
        }

        let ready = match wait_for_ready(
            &mut child,
            &ready_path,
            generation,
            Duration::from_secs(max_load_secs),
            &stdout_path,
            &stderr_path,
        ) {
            Ok(ready) => ready,
            Err(error) => {
                return Err(cleanup_spawn_failure(&job, &mut child, 83, error));
            }
        };
        if ready.process_id != child.id()
            || ready.worker_pid != Some(child.id())
            || ready.generation != generation
            || ready.max_load_secs != max_load_secs
            || ready.max_request_secs != max_request_secs
        {
            let error = worker_error(
                WORKER_START_FAILED,
                format!(
                    "resident generation handshake mismatch: child_pid={} ready_process_id={} ready_worker_pid={:?} expected_generation={} ready_generation={} expected_max_load_secs={} ready_max_load_secs={} expected_max_request_secs={} ready_max_request_secs={}",
                    child.id(),
                    ready.process_id,
                    ready.worker_pid,
                    generation,
                    ready.generation,
                    max_load_secs,
                    ready.max_load_secs,
                    max_request_secs,
                    ready.max_request_secs
                ),
                "preserve generation logs and restart from one native Calyx build",
            );
            return Err(cleanup_spawn_failure(&job, &mut child, 84, error));
        }
        if ready.frozen_panel_fingerprint != source.fingerprint {
            let error = worker_error(
                WORKER_FROZEN_VIOLATION,
                format!(
                    "resident generation {generation} loaded fingerprint {}, supervisor froze {}",
                    ready.frozen_panel_fingerprint, source.fingerprint
                ),
                "preserve the changed source bytes and restart the supervisor against one explicit frozen panel version",
            );
            return Err(cleanup_spawn_failure(&job, &mut child, 85, error));
        }
        if let Err(error) = validate_ready_slot_contracts(&ready) {
            return Err(cleanup_spawn_failure(&job, &mut child, 85, error));
        }
        if let Err(error) = ensure_loopback(ready.bind) {
            return Err(cleanup_spawn_failure(&job, &mut child, 85, error));
        }
        match child.try_wait() {
            Ok(None) => {}
            Ok(Some(status)) => {
                let error = worker_error(
                    WORKER_START_FAILED,
                    format!(
                        "resident generation {generation} worker PID {} exited {status} immediately after publishing readiness",
                        child.id()
                    ),
                    "preserve generation logs and restart only after fixing the post-readiness worker failure",
                );
                return Err(cleanup_spawn_failure(&job, &mut child, 87, error));
            }
            Err(error) => {
                let error = worker_error(
                    WORKER_START_FAILED,
                    format!(
                        "inspect resident generation {generation} worker PID {} after readiness: {error}",
                        child.id()
                    ),
                    "preserve generation logs and restart from one native Calyx build",
                );
                return Err(cleanup_spawn_failure(&job, &mut child, 88, error));
            }
        }
        if let Err(error) = job.verify_exact_members(&[child.id()]) {
            return Err(cleanup_spawn_failure(&job, &mut child, 89, error));
        }
        let bind = ready.bind;
        Ok(Self {
            generation,
            bind,
            ready,
            child,
            job,
            auth_secret,
        })
    }

    pub(super) fn process_id(&self) -> u32 {
        self.child.id()
    }

    pub(super) fn auth_secret(&self) -> &str {
        &self.auth_secret
    }

    pub(super) fn member_process_ids(&self) -> CliResult<Vec<u32>> {
        self.job.member_process_ids()
    }

    pub(super) fn is_alive(&mut self) -> CliResult<bool> {
        self.child
            .try_wait()
            .map(|status| status.is_none())
            .map_err(|error| {
                worker_error(
                    WORKER_START_FAILED,
                    format!(
                        "inspect resident worker PID {} generation {}: {error}",
                        self.child.id(),
                        self.generation
                    ),
                    "preserve generation logs and fault the generation before retrying",
                )
            })
    }

    pub(super) fn verify_live_exact(&mut self) -> CliResult {
        if !self.is_alive()? {
            return Err(worker_error(
                WORKER_START_FAILED,
                format!(
                    "resident worker PID {} generation {} is not live",
                    self.child.id(),
                    self.generation
                ),
                "preserve generation logs and fault the generation before retrying",
            ));
        }
        self.job.verify_exact_members(&[self.child.id()])
    }

    pub(super) fn stop(mut self) -> CliResult<Vec<u32>> {
        let result = self.stop_orderly();
        match result {
            Ok(members) => Ok(members),
            Err(error) => Err(cleanup_spawn_failure(&self.job, &mut self.child, 86, error)),
        }
    }

    pub(super) fn terminate(mut self, exit_code: u32) -> CliResult<Vec<u32>> {
        let members_before = match self.job.member_process_ids() {
            Ok(members) => members,
            Err(error) => {
                return Err(cleanup_spawn_failure(
                    &self.job,
                    &mut self.child,
                    exit_code,
                    error,
                ));
            }
        };
        terminate_reap_and_verify(&self.job, &mut self.child, exit_code)?;
        Ok(members_before)
    }

    fn stop_orderly(&mut self) -> CliResult<Vec<u32>> {
        let members_before = self.job.member_process_ids()?;
        if self.is_alive()? {
            request_worker_shutdown(self.bind, &self.auth_secret)?;
        }
        if !wait_child(&mut self.child, WORKER_STOP_GRACE)? {
            return Err(worker_error(
                WORKER_STOP_FAILED,
                format!(
                    "resident generation {} did not stop within {:?}",
                    self.generation, WORKER_STOP_GRACE
                ),
                "terminate and reap the generation Job Object before declaring VRAM unloaded",
            ));
        }
        wait_for_empty_job(&self.job)?;
        Ok(members_before)
    }
}

fn validate_ready_slot_contracts(ready: &ReadyResponse) -> CliResult {
    if ready.slot_count == 0 || ready.slot_contracts.len() != ready.slot_count {
        return Err(worker_error(
            WORKER_START_FAILED,
            format!(
                "resident generation {} published slot_count={} with {} full-panel contracts",
                ready.generation,
                ready.slot_count,
                ready.slot_contracts.len()
            ),
            "preserve the readiness artifact and rebuild the worker from the exact frozen panel",
        ));
    }
    let mut slots = BTreeSet::new();
    let mut keys = BTreeSet::new();
    for contract in &ready.slot_contracts {
        let shape_valid = match contract.shape {
            SlotShape::Dense(dim) | SlotShape::Sparse(dim) => dim > 0,
            SlotShape::Multi { token_dim } => token_dim > 0,
        };
        if contract.slot == 0
            || contract.key.trim().is_empty()
            || contract.lens_id.trim().is_empty()
            || !slots.insert(contract.slot)
            || !keys.insert(contract.key.as_str())
            || !shape_valid
        {
            return Err(worker_error(
                WORKER_START_FAILED,
                format!(
                    "resident generation {} published an invalid or duplicate full-panel contract for slot={} key={:?} lens={} shape={:?}",
                    ready.generation, contract.slot, contract.key, contract.lens_id, contract.shape
                ),
                "preserve the readiness artifact and fix the frozen panel contract before loading a generation",
            ));
        }
    }
    let expected_attested_lenses = ready
        .slot_contracts
        .iter()
        .filter(|contract| contract.state == SlotState::Active && contract.registered)
        .map(|contract| contract.lens_id.as_str())
        .collect::<BTreeSet<_>>();
    let observed_attested_lenses = ready
        .lens_attestations
        .iter()
        .map(|attestation| attestation.lens_id.as_str())
        .collect::<BTreeSet<_>>();
    if expected_attested_lenses != observed_attested_lenses
        || ready.slot_contracts.iter().any(|contract| {
            contract.state == SlotState::Active
                && contract.registered
                && !ready.lens_attestations.iter().any(|attestation| {
                    attestation.lens_id == contract.lens_id
                        && attestation.modality == contract.modality
                        && attestation.placement == contract.placement
                })
        })
        || ready.lens_attestations.iter().any(|attestation| {
            !ready.slot_contracts.iter().any(|contract| {
                contract.slot == attestation.slot
                    && contract.key == attestation.key
                    && contract.lens_id == attestation.lens_id
                    && contract.modality == attestation.modality
                    && contract.placement == attestation.placement
                    && contract.state == SlotState::Active
                    && contract.registered
            })
        })
    {
        return Err(worker_error(
            WORKER_START_FAILED,
            format!(
                "resident generation {} full-panel contracts do not match its active registered lens execution attestations",
                ready.generation
            ),
            "preserve the readiness artifact and reject the generation until every active registered contract has matching execution evidence",
        ));
    }
    Ok(())
}

impl WorkerAssignment {
    fn validate(self) -> CliResult<Self> {
        if self.schema != ASSIGNMENT_GATE_SCHEMA {
            return Err(worker_error(
                WORKER_START_FAILED,
                format!(
                    "resident worker assignment schema {} does not match {}",
                    self.schema, ASSIGNMENT_GATE_SCHEMA
                ),
                "start workers only through the matching native resident supervisor binary",
            ));
        }
        let current_pid = std::process::id();
        if self.worker_pid != current_pid
            || self.supervisor_pid == 0
            || self.supervisor_pid == current_pid
            || self.generation == 0
            || !valid_fingerprint(&self.frozen_fingerprint)
            || !valid_nonce(&self.nonce)
        {
            return Err(worker_error(
                WORKER_START_FAILED,
                format!(
                    "resident worker assignment identity is invalid: current_pid={current_pid} worker_pid={} supervisor_pid={} generation={} fingerprint_len={} nonce_len={}",
                    self.worker_pid,
                    self.supervisor_pid,
                    self.generation,
                    self.frozen_fingerprint.len(),
                    self.nonce.len()
                ),
                "reject the generation and restart it only through the resident supervisor",
            ));
        }
        ResidentGenerationJob::verify_current_worker(
            &self.job_name,
            &self.nonce,
            self.supervisor_pid,
            self.generation,
            &self.frozen_fingerprint,
        )?;
        Ok(self)
    }

    pub(super) fn auth_secret(&self) -> &str {
        &self.nonce
    }
}

pub(super) fn await_assignment_gate() -> CliResult<WorkerAssignment> {
    let path = std::env::var_os(WORKER_GATE_ENV)
        .map(PathBuf::from)
        .ok_or_else(|| {
            worker_error(
                WORKER_START_FAILED,
                "hidden resident worker is missing its Job Object assignment gate",
                "start workers only through `calyx panel resident serve`",
            )
        })?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match std::fs::metadata(&path) {
            Ok(metadata) if metadata.len() > MAX_ASSIGNMENT_GATE_BYTES => {
                return Err(worker_error(
                    WORKER_START_FAILED,
                    format!(
                        "resident worker assignment gate {} is {} bytes, limit is {}",
                        path.display(),
                        metadata.len(),
                        MAX_ASSIGNMENT_GATE_BYTES
                    ),
                    "preserve the malformed gate and restart the generation through the resident supervisor",
                ));
            }
            Ok(metadata) if metadata.len() > 0 => {
                let bytes = std::fs::read(&path).map_err(|error| {
                    worker_error(
                        WORKER_START_FAILED,
                        format!(
                            "read resident worker assignment gate {}: {error}",
                            path.display()
                        ),
                        "inspect the supervisor generation directory and Job Object assignment",
                    )
                })?;
                let assignment: WorkerAssignment =
                    serde_json::from_slice(&bytes).map_err(|error| {
                        worker_error(
                            WORKER_START_FAILED,
                            format!(
                                "decode resident worker assignment gate {}: {error}",
                                path.display()
                            ),
                            "preserve the malformed gate and restart the generation through the matching resident supervisor",
                        )
                    })?;
                let assignment = assignment.validate()?;
                write_assignment_audit(&path, &assignment)?;
                return Ok(assignment);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(worker_error(
                    WORKER_START_FAILED,
                    format!(
                        "read resident worker assignment gate {}: {error}",
                        path.display()
                    ),
                    "inspect the supervisor generation directory and Job Object assignment",
                ));
            }
        }
        if Instant::now() >= deadline {
            return Err(worker_error(
                WORKER_START_FAILED,
                format!(
                    "resident worker assignment gate {} was not published within 30 seconds",
                    path.display()
                ),
                "inspect the supervisor Job Object assignment failure and never run this worker unguarded",
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn append_worker_args(
    command: &mut Command,
    original_args: &[String],
    ready_path: &Path,
    progress_path: &Path,
) {
    let mut index = 0;
    while index < original_args.len() {
        let flag = &original_args[index];
        if matches!(flag.as_str(), "--bind" | "--ready-out" | "--progress-out") {
            index += 2;
            continue;
        }
        command.arg(flag);
        if let Some(value) = original_args.get(index + 1) {
            command.arg(value);
        }
        index += 2;
    }
    command
        .arg("--bind")
        .arg("127.0.0.1:0")
        .arg("--ready-out")
        .arg(ready_path)
        .arg("--progress-out")
        .arg(progress_path);
}

fn create_log(path: &Path) -> CliResult<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            worker_error(
                WORKER_START_FAILED,
                format!("create resident worker log {}: {error}", path.display()),
                "preserve the generation directory and use a new generation number",
            )
        })
}

fn write_assignment_gate(path: &Path, assignment: &WorkerAssignment) -> CliResult {
    let mut bytes = serde_json::to_vec_pretty(assignment).map_err(|error| {
        worker_error(
            WORKER_START_FAILED,
            format!(
                "serialize resident worker assignment gate {}: {error}",
                path.display()
            ),
            "preserve the generation directory and restart from one native resident supervisor binary",
        )
    })?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_ASSIGNMENT_GATE_BYTES {
        return Err(worker_error(
            WORKER_START_FAILED,
            format!(
                "serialized resident worker assignment gate {} is {} bytes, limit is {}",
                path.display(),
                bytes.len(),
                MAX_ASSIGNMENT_GATE_BYTES
            ),
            "reduce the assignment metadata before spawning a resident generation",
        ));
    }
    crate::durable_write::write_bytes_atomic(path, &bytes, "resident worker assignment gate")
        .map_err(|error| {
            worker_error(
                WORKER_START_FAILED,
                format!(
                    "publish generation Job Object assignment gate {}: {}: {}",
                    path.display(),
                    error.code(),
                    error.message()
                ),
                "inspect CALYX_HOME storage permissions; never start a GPU worker without a durable authenticated gate",
            )
        })
}

fn write_assignment_audit(path: &Path, assignment: &WorkerAssignment) -> CliResult {
    let audit = WorkerAssignmentAudit {
        schema: ASSIGNMENT_AUDIT_SCHEMA,
        worker_pid: assignment.worker_pid,
        supervisor_pid: assignment.supervisor_pid,
        generation: assignment.generation,
        frozen_fingerprint: &assignment.frozen_fingerprint,
        assignment_verified: true,
        exact_job_member_pids: [assignment.worker_pid],
        private_channel_auth: "generation-nonce-preamble-v1",
        credential_redacted: true,
    };
    let mut bytes = serde_json::to_vec_pretty(&audit).map_err(|error| {
        worker_error(
            WORKER_START_FAILED,
            format!(
                "serialize redacted resident worker assignment audit {}: {error}",
                path.display()
            ),
            "preserve the generation directory and restart from one native resident supervisor binary",
        )
    })?;
    bytes.push(b'\n');
    crate::durable_write::write_bytes_atomic(path, &bytes, "resident worker assignment audit")
        .map_err(|error| {
            worker_error(
                WORKER_START_FAILED,
                format!(
                    "replace resident worker assignment gate {} with redacted audit: {}: {}",
                    path.display(),
                    error.code(),
                    error.message()
                ),
                "inspect CALYX_HOME storage permissions; never load a model while its reusable worker credential remains on disk",
            )
        })
}

pub(super) fn write_worker_auth_line(writer: &mut impl Write, auth_secret: &str) -> CliResult {
    if !valid_nonce(auth_secret) {
        return Err(worker_error(
            WORKER_START_FAILED,
            "resident worker authentication secret is not a valid generation nonce",
            "discard the generation and create its credential through ResidentGenerationJob",
        ));
    }
    writer.write_all(WORKER_AUTH_PREFIX)?;
    writer.write_all(auth_secret.as_bytes())?;
    writer.write_all(b"\n")?;
    Ok(())
}

fn valid_fingerprint(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_nonce(value: &str) -> bool {
    value.len() == 52
        && value.is_ascii()
        && ulid::Ulid::from_string(&value[..26]).is_ok()
        && ulid::Ulid::from_string(&value[26..]).is_ok()
}

fn cleanup_spawn_failure(
    job: &ResidentGenerationJob,
    child: &mut Child,
    exit_code: u32,
    primary: CliError,
) -> CliError {
    match terminate_reap_and_verify(job, child, exit_code) {
        Ok(()) => primary,
        Err(cleanup) => worker_error(
            WORKER_STOP_FAILED,
            format!(
                "resident worker failure cleanup did not prove an empty generation: primary_code={} primary_message={}; cleanup_code={} cleanup_message={}",
                primary.code(),
                primary.message(),
                cleanup.code(),
                cleanup.message()
            ),
            "inspect the named generation Job Object and recorded PIDs; do not retry GPU loading until every member is proven absent",
        ),
    }
}

fn terminate_reap_and_verify(
    job: &ResidentGenerationJob,
    child: &mut Child,
    exit_code: u32,
) -> CliResult {
    let mut failures = Vec::new();
    if let Err(error) = job.terminate(exit_code) {
        failures.push(format!(
            "terminate_job={} {}",
            error.code(),
            error.message()
        ));
    }

    let needs_kill = match child.try_wait() {
        Ok(Some(_)) => false,
        Ok(None) => true,
        Err(error) => {
            failures.push(format!("inspect_worker={error}"));
            true
        }
    };
    if needs_kill {
        let kill_error = child.kill().err();
        match wait_child(child, WORKER_STOP_GRACE) {
            Ok(true) => {}
            Ok(false) => {
                if let Some(error) = kill_error {
                    failures.push(format!("kill_worker={error}"));
                }
                failures.push(format!(
                    "wait_worker=PID {} remained live beyond {:?}",
                    child.id(),
                    WORKER_STOP_GRACE
                ));
            }
            Err(error) => {
                if let Some(kill_error) = kill_error {
                    failures.push(format!("kill_worker={kill_error}"));
                }
                failures.push(format!("wait_worker={} {}", error.code(), error.message()));
            }
        }
    }

    if let Err(error) = wait_for_empty_job(job) {
        failures.push(format!("query_empty={} {}", error.code(), error.message()));
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(worker_error(
            WORKER_STOP_FAILED,
            format!(
                "resident worker PID {} cleanup failures: {}",
                child.id(),
                failures.join("; ")
            ),
            "keep the Job Object handle open, terminate every member, wait for the worker, and query until membership is empty",
        ))
    }
}

fn wait_for_empty_job(job: &ResidentGenerationJob) -> CliResult {
    let started = Instant::now();
    loop {
        let remaining = job.member_process_ids()?;
        if remaining.is_empty() {
            return Ok(());
        }
        if started.elapsed() >= WORKER_STOP_GRACE {
            return Err(worker_error(
                WORKER_STOP_FAILED,
                format!(
                    "resident generation retains descendant PIDs {remaining:?} after termination"
                ),
                "inspect and terminate the named generation Job Object descendants before declaring VRAM unloaded",
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn wait_for_ready(
    child: &mut Child,
    ready_path: &Path,
    generation: u64,
    timeout: Duration,
    stdout_path: &Path,
    stderr_path: &Path,
) -> CliResult<ReadyResponse> {
    let started = Instant::now();
    loop {
        match std::fs::read(ready_path) {
            Ok(bytes) => {
                let ready: ReadyResponse = serde_json::from_slice(&bytes).map_err(|error| {
                    worker_error(
                        WORKER_START_FAILED,
                        format!(
                            "decode resident generation {generation} readiness {}: {error}",
                            ready_path.display()
                        ),
                        "preserve generation logs and restart from one native Calyx build",
                    )
                })?;
                if ready.schema != READY_SCHEMA || !ready.ready || !ready.warm_ready {
                    return Err(worker_error(
                        WORKER_START_FAILED,
                        format!(
                            "resident generation {generation} readiness schema={} ready={} warm_ready={}",
                            ready.schema, ready.ready, ready.warm_ready
                        ),
                        "preserve generation logs and restart from one native Calyx build",
                    ));
                }
                return Ok(ready);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(worker_error(
                    WORKER_START_FAILED,
                    format!(
                        "read resident generation {generation} readiness {}: {error}",
                        ready_path.display()
                    ),
                    "inspect the generation directory permissions and worker logs",
                ));
            }
        }
        if let Some(status) = child.try_wait()? {
            return Err(worker_error(
                WORKER_START_FAILED,
                format!(
                    "resident generation {generation} worker PID {} exited {status} before readiness; stdout={} stderr={}",
                    child.id(),
                    stdout_path.display(),
                    stderr_path.display()
                ),
                "inspect both generation logs and fix the exact warm-load failure before retrying",
            ));
        }
        if started.elapsed() >= timeout {
            return Err(worker_error(
                WORKER_START_FAILED,
                format!(
                    "resident generation {generation} worker PID {} exceeded {:?} warm-load deadline; stdout={} stderr={}",
                    child.id(),
                    timeout,
                    stdout_path.display(),
                    stderr_path.display()
                ),
                "inspect generation progress and increase --max-load-secs only if the real frozen panel needs it",
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn request_worker_shutdown(bind: SocketAddr, auth_secret: &str) -> CliResult {
    let deadline = deadline_after(WORKER_SHUTDOWN_REQUEST_TIMEOUT)?;
    let mut stream = connect_before(&bind, deadline)?;
    let response = {
        let mut stream = DeadlineStream::new(&mut stream, deadline);
        write_worker_auth_line(&mut stream, auth_secret)?;
        stream.write_all(br#"{"op":"shutdown"}"#)?;
        stream.write_all(b"\n")?;
        stream.flush()?;
        let mut reader = BufReader::new(stream);
        read_bounded_line(
            &mut reader,
            MAX_RESIDENT_JSON_LINE_BYTES,
            "resident worker shutdown response",
        )?
    };
    let _ = stream.shutdown(Shutdown::Both);
    let response = serde_json::from_slice::<Value>(&response).map_err(|error| {
        worker_error(
            WORKER_STOP_FAILED,
            format!("resident worker {bind} returned invalid shutdown JSON: {error}"),
            "terminate the generation Job Object and inspect worker logs",
        )
    })?;
    if response.get("ok") != Some(&Value::Bool(true)) {
        return Err(worker_error(
            WORKER_STOP_FAILED,
            format!("resident worker {bind} did not acknowledge shutdown: {response}"),
            "terminate the generation Job Object and inspect worker logs",
        ));
    }
    Ok(())
}

fn wait_child(child: &mut Child, timeout: Duration) -> CliResult<bool> {
    let started = Instant::now();
    loop {
        if child.try_wait()?.is_some() {
            return Ok(true);
        }
        if started.elapsed() >= timeout {
            return Ok(false);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn worker_error(
    code: &'static str,
    message: impl Into<String>,
    remediation: &'static str,
) -> CliError {
    CliError::from(CalyxError {
        code,
        message: message.into(),
        remediation,
    })
}
