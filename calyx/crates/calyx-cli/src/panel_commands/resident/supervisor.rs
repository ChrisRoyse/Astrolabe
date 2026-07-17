use std::io::{BufReader, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use calyx_core::{CalyxError, Placement, SlotShape, SlotState};
use ulid::Ulid;

use super::codec::{decode_binary, encode_binary, read_frame, write_frame};
use super::deadline::{
    DeadlineStream, connect_before, deadline_after, ensure_before, read_bounded_line,
};
use super::discovery::{
    RESIDENT_DISCOVERY_SCHEMA, ResidentDiscovery, remove_resident_discovery, unix_now_ms,
    write_resident_discovery,
};
use super::dispatch::{RequestClass, validate_public_request};
use super::lifecycle::{
    LIFECYCLE_SCHEMA_V2, LifecycleErrorRecord, LifecyclePhase, LifecycleProjection,
    LifecycleRequestRecord, LifecycleState, LifecycleStore, RequestOutcome, RequestStage,
};
use super::source::{FrozenResidentSource, freeze_source};
use super::stream::{decode_binary_request, write_stream_frame};
use super::worker::{WorkerProcess, write_worker_auth_line};
use super::*;

const IDLE_TTL_MS: u64 = 60_000;
const IDLE_TTL: Duration = Duration::from_millis(IDLE_TTL_MS);
const WORKER_LIVENESS_POLL: Duration = Duration::from_millis(500);
const PUBLIC_SOCKET_TIMEOUT: Duration = Duration::from_secs(30);
const BACK_PRESSURE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(2);
const WORKER_LOST: &str = "CALYX_PANEL_RESIDENT_WORKER_LOST";
const WORKER_PROTOCOL_INVALID: &str = "CALYX_PANEL_RESIDENT_WORKER_PROTOCOL_INVALID";
const WORKER_REPORTED_ERROR: &str = "CALYX_PANEL_RESIDENT_WORKER_REPORTED_ERROR";
const CLIENT_ABORTED_GENERATION: &str = "CALYX_PANEL_RESIDENT_CLIENT_ABORTED_GENERATION";
const BACK_PRESSURE: &str = "CALYX_PANEL_RESIDENT_BACK_PRESSURE";
const STOPPING: &str = "CALYX_PANEL_RESIDENT_STOPPING";

struct Supervisor {
    original_args: Vec<String>,
    home: PathBuf,
    source: FrozenResidentSource,
    bind: SocketAddr,
    started: Instant,
    max_load_secs: u64,
    max_request_secs: u64,
    ready_out: Option<PathBuf>,
    accepting: AtomicBool,
    inner: Mutex<SupervisorInner>,
    changed: Condvar,
}

struct SupervisorInner {
    state: LifecycleState,
    projection: LifecycleProjection,
    store: LifecycleStore,
    worker: Option<WorkerProcess>,
    last_worker_ready: Option<ReadyResponse>,
    idle_deadline: Option<Instant>,
    worker_transition: Option<WorkerTransition>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkerTransition {
    Loading(u64),
    Unloading(u64),
}

#[derive(Clone)]
struct WorkerEndpoint {
    generation: u64,
    bind: SocketAddr,
    process_id: u32,
    template_source: String,
    slot_contracts: Vec<ResidentSlotContract>,
    auth_secret: String,
    request_timeout: Duration,
}

struct ProductiveLease {
    supervisor: Arc<Supervisor>,
    endpoint: WorkerEndpoint,
    request_id: String,
    stage: RequestStage,
    completed: bool,
}

enum PendingRequestState {
    Untracked,
    Queued,
    Admitted(u64),
    Disarmed,
}

struct PendingRequestGuard {
    supervisor: Arc<Supervisor>,
    request_id: String,
    state: PendingRequestState,
}

impl PendingRequestGuard {
    fn new(supervisor: Arc<Supervisor>, request_id: String) -> Self {
        Self {
            supervisor,
            request_id,
            state: PendingRequestState::Untracked,
        }
    }

    fn mark_admitted(&mut self, generation: u64) {
        self.state = PendingRequestState::Admitted(generation);
    }

    fn mark_queued(&mut self) {
        self.state = PendingRequestState::Queued;
    }

    fn disarm(&mut self) {
        self.state = PendingRequestState::Disarmed;
    }

    fn cancel(&mut self, error: &CliError, outcome: RequestOutcome) -> CliResult {
        let state = std::mem::replace(&mut self.state, PendingRequestState::Disarmed);
        let result = match state {
            PendingRequestState::Untracked => Ok(()),
            PendingRequestState::Queued => {
                self.supervisor
                    .cancel_queued_request(&self.request_id, error, outcome)
            }
            PendingRequestState::Admitted(generation) => {
                let invalidation = self
                    .supervisor
                    .invalidate_generation(generation, clone_cli_error(error))
                    .err();
                let release = self
                    .supervisor
                    .release_failed(generation, &self.request_id, outcome, error, None)
                    .err();
                match merge_optional_errors(
                    "resident admitted-request invalidation and release",
                    invalidation,
                    release,
                ) {
                    Some(error) => Err(error),
                    None => Ok(()),
                }
            }
            PendingRequestState::Disarmed => Ok(()),
        };
        if result.is_err() {
            self.supervisor.accepting.store(false, Ordering::SeqCst);
        }
        result
    }
}

impl Drop for PendingRequestGuard {
    fn drop(&mut self) {
        if matches!(
            &self.state,
            PendingRequestState::Untracked | PendingRequestState::Disarmed
        ) {
            return;
        }
        let error = CliError::from(CalyxError {
            code: CLIENT_ABORTED_GENERATION,
            message: format!(
                "resident request {} unwound before a productive lease was handed to its handler",
                self.request_id
            ),
            remediation: "inspect the first handler panic and lifecycle journal; retry only after the queued/admitted request is durably abandoned",
        });
        if let Err(cleanup_error) = self.cancel(&error, RequestOutcome::Abandoned) {
            self.supervisor.accepting.store(false, Ordering::SeqCst);
            eprintln!(
                "CALYX_PANEL_RESIDENT_RUNTIME phase=pending_request_unwind_error request_id={} code={} message={}",
                self.request_id,
                cleanup_error.code(),
                cleanup_error.message()
            );
        }
    }
}

impl ProductiveLease {
    fn endpoint(&self) -> WorkerEndpoint {
        self.endpoint.clone()
    }

    fn advance(&mut self, next: RequestStage) -> CliResult {
        if !valid_stage_transition(self.stage, next) {
            return Err(CliError::runtime(format!(
                "resident request {} attempted invalid stage transition {:?} -> {:?}",
                self.request_id, self.stage, next
            )));
        }
        self.supervisor.record_request_stage(
            &self.request_id,
            Some(self.endpoint.generation),
            next,
            None,
            None,
        )?;
        self.stage = next;
        Ok(())
    }

    fn complete_success(mut self) -> CliResult {
        if self.stage != RequestStage::PublicFlushComplete {
            return Err(CliError::runtime(format!(
                "resident request {} cannot complete from stage {:?}; public flush is not proven",
                self.request_id, self.stage
            )));
        }
        // A failed durable append must not make Drop release this lease twice.
        // `release_success` always performs the in-memory completion first.
        self.completed = true;
        self.supervisor.release_success(
            self.endpoint.generation,
            &self.request_id,
            RequestOutcome::Succeeded,
            None,
        )
    }

    fn fail(mut self, error: &CliError, outcome: RequestOutcome) -> CliResult {
        self.completed = true;
        self.fail_inner(error, outcome, None)
    }

    fn fail_reported(
        mut self,
        failure: &WorkerReportedFailure,
        outcome: RequestOutcome,
    ) -> CliResult {
        self.completed = true;
        self.fail_inner(
            &failure.supervisor_error,
            outcome,
            Some(&failure.lifecycle_error),
        )
    }

    fn fail_inner(
        &self,
        error: &CliError,
        outcome: RequestOutcome,
        lifecycle_error: Option<&LifecycleErrorRecord>,
    ) -> CliResult {
        let invalidation_error = self
            .supervisor
            .invalidate_generation_with_record(
                self.endpoint.generation,
                clone_cli_error(error),
                lifecycle_error.cloned(),
            )
            .err();
        let release_error = self
            .supervisor
            .release_failed(
                self.endpoint.generation,
                &self.request_id,
                outcome,
                error,
                lifecycle_error,
            )
            .err();
        match merge_optional_errors(
            "resident productive-request invalidation and release",
            invalidation_error,
            release_error,
        ) {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

impl Drop for ProductiveLease {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        self.completed = true;
        let error = CliError::from(CalyxError {
            code: CLIENT_ABORTED_GENERATION,
            message: format!(
                "resident request {} dropped unexpectedly at stage {:?} in generation {}",
                self.request_id, self.stage, self.endpoint.generation
            ),
            remediation: "inspect the lifecycle request stages; retry the complete request after the supervisor reaps the abandoned generation",
        });
        if let Err(cleanup_error) = self.fail_inner(&error, RequestOutcome::Abandoned, None) {
            self.supervisor.accepting.store(false, Ordering::SeqCst);
            eprintln!(
                "CALYX_PANEL_RESIDENT_RUNTIME phase=lease_abandon_error generation={} request_id={} code={} message={}",
                self.endpoint.generation,
                self.request_id,
                cleanup_error.code(),
                cleanup_error.message()
            );
        }
    }
}

fn valid_stage_transition(current: RequestStage, next: RequestStage) -> bool {
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

pub(super) fn serve(args: &[String]) -> CliResult {
    let mut flags = parse_serve_flags(args)?;
    let bind = flags.bind.unwrap_or(parse_addr(DEFAULT_BIND)?);
    ensure_loopback(bind)?;
    let home = super::server::resolve_home_with(flags.home.take(), calyx_home)?;
    if flags.template.is_some() == flags.vault.is_some() {
        return Err(CliError::usage(
            "calyx panel resident serve requires exactly one of --template <name-or-id> or --vault <vault>",
        ));
    }
    if flags.template.is_some() && (!flags.slots.is_empty() || flags.modality.is_some()) {
        return Err(CliError::from(CalyxError {
            code: "CALYX_PANEL_RESIDENT_TEMPLATE_SCOPE_UNSUPPORTED",
            message: "saved-template residency does not yet implement --slot or --modality as a construction-time scope".to_string(),
            remediation: "remove the scope flags to load the complete frozen template, or use a vault source whose persisted panel supports exact slot/modality scoping; track saved-template scope support in issue #546",
        }));
    }
    let source = freeze_source(&home, &flags)?;
    let listener = TcpListener::bind(bind)?;
    let local_addr = listener.local_addr()?;
    let supervisor = Supervisor::open(
        args.to_vec(),
        home.clone(),
        source,
        local_addr,
        flags.max_load_secs.unwrap_or(DEFAULT_MAX_LOAD_SECS),
        flags.max_request_secs.unwrap_or(DEFAULT_MAX_REQUEST_SECS),
        flags.ready_out.clone(),
    )?;
    supervisor.preload()?;
    let idle_monitor = supervisor.start_idle_monitor();
    let served = (|| -> CliResult {
        let ready = supervisor.readiness()?;
        if let Some(path) = supervisor.ready_out.clone() {
            write_json_file(path, &ready)?;
        }
        let discovery_path = write_resident_discovery(
            &home,
            &ResidentDiscovery {
                schema: RESIDENT_DISCOVERY_SCHEMA.to_string(),
                bind: local_addr,
                process_id: std::process::id(),
                vault: supervisor.source.canonical_vault.clone(),
                template: supervisor.source.template.clone(),
                written_at_unix_ms: unix_now_ms(),
            },
        )?;
        eprintln!(
            "CALYX_PANEL_RESIDENT_RUNTIME phase=supervisor_ready path={} bind={} fingerprint={}",
            discovery_path.display(),
            local_addr,
            supervisor.source.fingerprint
        );
        print_json(&ready)?;
        serve_loop(listener, Arc::clone(&supervisor))
    })();
    let stopped = supervisor.shutdown();
    let monitor_stopped = join_monitor(idle_monitor);
    let removed = remove_resident_discovery(&home, std::process::id());
    match (served, stopped) {
        (Err(serve_error), Err(shutdown_error)) => {
            return Err(combine_runtime_errors(
                "resident serve loop and shutdown both failed",
                serve_error,
                shutdown_error,
            ));
        }
        (Err(error), Ok(())) | (Ok(()), Err(error)) => return Err(error),
        (Ok(()), Ok(())) => {}
    }
    monitor_stopped?;
    removed
}

impl Supervisor {
    fn open(
        original_args: Vec<String>,
        home: PathBuf,
        source: FrozenResidentSource,
        bind: SocketAddr,
        max_load_secs: u64,
        max_request_secs: u64,
        ready_out: Option<PathBuf>,
    ) -> CliResult<Arc<Self>> {
        let mut store = LifecycleStore::open(&home)?;
        let legacy_in_flight = store
            .last()
            .filter(|projection| projection.schema == LIFECYCLE_SCHEMA_V2)
            .map_or(0, |projection| projection.in_flight);
        let previous = store.last().map(LifecycleProjection::state);
        let recovered_requests = store.take_recovered_requests();
        let mut state = LifecycleState::unloaded(
            std::process::id(),
            IDLE_TTL_MS,
            max_load_secs,
            max_request_secs,
            source.fingerprint.clone(),
            Vec::new(),
        );
        if let Some(previous) = previous {
            state.generation = previous.generation;
            state.load_attempt_count = previous.load_attempt_count;
            state.load_success_count = previous.load_success_count;
            state.load_failure_count = previous.load_failure_count;
            state.unload_count = previous.unload_count;
            state.last_worker_start_unix_ms = previous.last_worker_start_unix_ms;
            state.last_completion_unix_ms = previous.last_completion_unix_ms;
            state.last_unload_unix_ms = previous.last_unload_unix_ms;
            if previous.frozen_panel_fingerprint == source.fingerprint {
                state.lens_attestations = previous.lens_attestations;
                state.onnx_runtime_attestation = previous.onnx_runtime_attestation;
            }
        }
        if legacy_in_flight != 0 {
            state.last_error = Some(LifecycleErrorRecord {
                code: "CALYX_PANEL_RESIDENT_LEGACY_REQUESTS_ABANDONED_ON_RESTART".to_string(),
                message: format!(
                    "resident supervisor recovered {legacy_in_flight} in-flight request(s) from a legacy lifecycle journal that did not record request identities"
                ),
                remediation: "inspect the preceding legacy supervisor logs and source of truth before retrying those requests; future requests carry exact ULIDs and stages".to_string(),
                at_unix_ms: unix_now_ms(),
            });
            store.append("legacy_requests_recovered_abandoned", &state)?;
        }
        for request in recovered_requests {
            let (event, outcome, recovered_error) = if request.stage
                == RequestStage::PublicFlushComplete
            {
                (
                    "request_recovered_succeeded",
                    RequestOutcome::Succeeded,
                    None,
                )
            } else {
                (
                        "request_recovered_abandoned",
                        RequestOutcome::Abandoned,
                        Some(LifecycleErrorRecord {
                            code: "CALYX_PANEL_RESIDENT_REQUEST_ABANDONED_ON_RESTART".to_string(),
                            message: format!(
                                "resident supervisor restarted before request {} reached a proven public flush; last_stage={:?} generation={:?}",
                                request.request_id, request.stage, request.generation
                            ),
                            remediation: "inspect the preceding worker/supervisor logs and verify the source-of-truth mutation did not occur, then retry the complete request through the new generation".to_string(),
                            at_unix_ms: unix_now_ms(),
                        }),
                    )
            };
            store.append_request(
                event,
                &state,
                Some(LifecycleRequestRecord {
                    request_id: request.request_id,
                    generation: request.generation,
                    stage: RequestStage::Released,
                    outcome: Some(outcome),
                    error: recovered_error,
                }),
            )?;
        }
        let projection = store.append("supervisor_started", &state)?;
        Ok(Arc::new(Self {
            original_args,
            home,
            source,
            bind,
            started: Instant::now(),
            max_load_secs,
            max_request_secs,
            ready_out,
            accepting: AtomicBool::new(true),
            inner: Mutex::new(SupervisorInner {
                state,
                projection,
                store,
                worker: None,
                last_worker_ready: None,
                idle_deadline: None,
                worker_transition: None,
            }),
            changed: Condvar::new(),
        }))
    }

    fn preload(self: &Arc<Self>) -> CliResult {
        self.ensure_loaded()
    }

    fn start_idle_monitor(self: &Arc<Self>) -> JoinHandle<()> {
        let supervisor = Arc::clone(self);
        std::thread::spawn(move || supervisor.idle_monitor())
    }

    fn acquire(self: &Arc<Self>) -> CliResult<ProductiveLease> {
        let request_id = Ulid::new().to_string();
        let mut pending = PendingRequestGuard::new(Arc::clone(self), request_id.clone());
        {
            let mut inner = self.lock()?;
            if !self.accepting.load(Ordering::SeqCst) {
                return Err(stopping_error());
            }
            inner.state.queued_requests =
                inner.state.queued_requests.checked_add(1).ok_or_else(|| {
                    CliError::runtime("resident queued request counter overflowed")
                })?;
            pending.mark_queued();
            inner.state.idle_deadline_unix_ms = None;
            inner.idle_deadline = None;
            if matches!(
                inner.state.phase,
                LifecyclePhase::LoadedIdle | LifecyclePhase::LoadedBusy
            ) {
                inner.state.phase = LifecyclePhase::LoadedBusy;
            }
            if let Err(error) = self.persist_request(
                &mut inner,
                "request_queued",
                LifecycleRequestRecord {
                    request_id: request_id.clone(),
                    generation: None,
                    stage: RequestStage::Queued,
                    outcome: None,
                    error: None,
                },
            ) {
                inner.state.queued_requests -= 1;
                pending.disarm();
                self.changed.notify_all();
                return Err(error);
            }
            self.changed.notify_all();
        }

        let acquired = self.acquire_queued(&request_id, &mut pending);
        match acquired {
            Ok(endpoint) => {
                pending.disarm();
                Ok(ProductiveLease {
                    supervisor: Arc::clone(self),
                    endpoint,
                    request_id,
                    stage: RequestStage::Queued,
                    completed: false,
                })
            }
            Err(error) => {
                let cleanup_error = pending.cancel(&error, RequestOutcome::Failed).err();
                Err(merge_error(
                    "resident acquisition and queued-request cleanup",
                    error,
                    cleanup_error,
                ))
            }
        }
    }

    fn acquire_queued(
        self: &Arc<Self>,
        request_id: &str,
        pending: &mut PendingRequestGuard,
    ) -> CliResult<WorkerEndpoint> {
        loop {
            self.ensure_loaded()?;
            let mut inner = self.lock()?;
            if !self.accepting.load(Ordering::SeqCst) {
                return Err(stopping_error());
            }
            if !matches!(
                inner.state.phase,
                LifecyclePhase::LoadedIdle | LifecyclePhase::LoadedBusy
            ) {
                continue;
            }
            if inner.state.in_flight != 0 {
                drop(self.wait(inner)?);
                continue;
            }
            let endpoint = match inner.worker.as_ref() {
                Some(worker) => WorkerEndpoint {
                    generation: worker.generation,
                    bind: worker.bind,
                    process_id: worker.process_id(),
                    template_source: worker.ready.template_source.clone(),
                    slot_contracts: worker.ready.slot_contracts.clone(),
                    auth_secret: worker.auth_secret().to_string(),
                    request_timeout: Duration::from_secs(self.max_request_secs),
                },
                None => continue,
            };
            if inner.state.queued_requests == 0 {
                return Err(CliError::runtime(format!(
                    "resident request {request_id} reached admission with queued_requests=0"
                )));
            }
            let prior_queued = inner.state.queued_requests;
            let prior_in_flight = inner.state.in_flight;
            inner.state.queued_requests -= 1;
            inner.state.in_flight = prior_in_flight
                .checked_add(1)
                .ok_or_else(|| CliError::runtime("resident productive lease counter overflowed"))?;
            inner.state.phase = LifecyclePhase::LoadedBusy;
            inner.state.idle_deadline_unix_ms = None;
            inner.idle_deadline = None;
            pending.mark_admitted(endpoint.generation);
            if let Err(error) = self.persist_request(
                &mut inner,
                "lease_acquired",
                LifecycleRequestRecord {
                    request_id: request_id.to_string(),
                    generation: Some(endpoint.generation),
                    stage: RequestStage::Queued,
                    outcome: None,
                    error: None,
                },
            ) {
                // No lease escapes this function, so the logical acquisition
                // did not happen even if durability faulted mid-publication.
                inner.state.queued_requests = prior_queued;
                inner.state.in_flight = prior_in_flight;
                inner.state.phase = LifecyclePhase::Faulted;
                inner.state.idle_deadline_unix_ms = None;
                inner.idle_deadline = None;
                pending.mark_queued();
                self.changed.notify_all();
                return Err(error);
            }
            return Ok(endpoint);
        }
    }

    fn ensure_loaded(self: &Arc<Self>) -> CliResult {
        loop {
            if !self.accepting.load(Ordering::SeqCst) {
                return Err(stopping_error());
            }
            let mut inner = self.lock()?;
            match inner.state.phase {
                LifecyclePhase::LoadedIdle | LifecyclePhase::LoadedBusy => {
                    let health_error = match inner.worker.as_mut() {
                        Some(worker) => worker.verify_live_exact().err(),
                        None => Some(worker_error(
                            format!(
                                "resident generation {} has loaded state without an owned worker",
                                inner.state.generation
                            ),
                            "inspect the lifecycle journal; the next valid request will load a clean frozen generation",
                        )),
                    };
                    let Some(error) = health_error else {
                        return Ok(());
                    };
                    let generation = inner.state.generation;
                    drop(inner);
                    self.invalidate_generation(generation, clone_cli_error(&error))?;
                    return Err(error);
                }
                LifecyclePhase::Unloaded => {
                    let generation = inner.state.generation.checked_add(1).ok_or_else(|| {
                        CliError::runtime("resident generation counter exhausted")
                    })?;
                    let load_attempt_count = inner
                        .state
                        .load_attempt_count
                        .checked_add(1)
                        .ok_or_else(|| {
                            CliError::runtime("resident load attempt counter exhausted")
                        })?;
                    inner.state.generation = generation;
                    inner.state.phase = LifecyclePhase::Loading;
                    inner.state.load_attempt_count = load_attempt_count;
                    inner.state.last_error = None;
                    inner.worker_transition = Some(WorkerTransition::Loading(generation));
                    if let Err(error) = self.persist(&mut inner, "load_started") {
                        inner.worker_transition = None;
                        self.changed.notify_all();
                        return Err(error);
                    }
                    drop(inner);
                    return self.load_generation(generation);
                }
                LifecyclePhase::Faulted
                    if inner.worker.is_none()
                        && inner.state.in_flight == 0
                        && inner.worker_transition.is_none() =>
                {
                    inner.state.phase = LifecyclePhase::Unloaded;
                    inner.state.worker_pid = None;
                    inner.state.worker_descendant_pids.clear();
                    let persisted = self.persist(&mut inner, "fault_reaped");
                    self.changed.notify_all();
                    persisted?;
                }
                LifecyclePhase::Loading | LifecyclePhase::Unloading | LifecyclePhase::Faulted => {
                    drop(self.wait(inner)?);
                }
                LifecyclePhase::Stopping | LifecyclePhase::Stopped => {
                    return Err(stopping_error());
                }
            }
        }
    }

    fn load_generation(self: &Arc<Self>, generation: u64) -> CliResult {
        let worker = match WorkerProcess::spawn(
            &self.original_args,
            &self.home,
            &self.source,
            generation,
            self.max_load_secs,
            self.max_request_secs,
        ) {
            Ok(worker) => worker,
            Err(error) => return self.finish_load_failure(generation, error, None),
        };
        let members = match worker.member_process_ids() {
            Ok(members) => members,
            Err(error) => return self.finish_load_failure(generation, error, Some(worker)),
        };
        let worker_pid = worker.process_id();
        let worker_ready = worker.ready.clone();
        let now = unix_now_ms();
        let mut inner = match self.lock() {
            Ok(inner) => inner,
            Err(error) => return self.finish_load_failure(generation, error, Some(worker)),
        };
        if inner.worker_transition != Some(WorkerTransition::Loading(generation))
            || inner.state.phase != LifecyclePhase::Loading
            || inner.state.generation != generation
            || !self.accepting.load(Ordering::SeqCst)
        {
            drop(inner);
            return self.finish_load_failure(
                generation,
                worker_error(
                    format!(
                        "resident generation {generation} finished loading after its lifecycle moved on"
                    ),
                    "inspect the lifecycle journal for a concurrent stop or fault",
                ),
                Some(worker),
            );
        }
        let load_success_count = match inner.state.load_success_count.checked_add(1) {
            Some(count) => count,
            None => {
                drop(inner);
                return self.finish_load_failure(
                    generation,
                    CliError::runtime("resident load success counter exhausted"),
                    Some(worker),
                );
            }
        };
        inner.state.phase = if inner.state.queued_requests == 0 {
            LifecyclePhase::LoadedIdle
        } else {
            LifecyclePhase::LoadedBusy
        };
        inner.state.worker_pid = Some(worker_pid);
        inner.state.worker_descendant_pids = members;
        inner.state.load_success_count = load_success_count;
        inner.state.last_worker_start_unix_ms = Some(now);
        inner.state.idle_deadline_unix_ms =
            (inner.state.queued_requests == 0).then_some(now.saturating_add(IDLE_TTL_MS));
        inner.state.lens_attestations = worker_ready.lens_attestations.clone();
        inner.state.onnx_runtime_attestation = worker_ready.onnx_runtime_attestation.clone();
        inner.idle_deadline = (inner.state.queued_requests == 0).then(|| Instant::now() + IDLE_TTL);
        inner.last_worker_ready = Some(worker_ready);
        if let Err(error) = self.persist(&mut inner, "load_succeeded") {
            drop(inner);
            return self.finish_load_persist_failure(generation, error, worker);
        }
        inner.worker = Some(worker);
        inner.worker_transition = None;
        self.changed.notify_all();
        Ok(())
    }

    fn finish_load_failure(
        &self,
        generation: u64,
        error: CliError,
        worker: Option<WorkerProcess>,
    ) -> CliResult {
        let cleanup_error = worker.and_then(|worker| worker.terminate(87).err());
        let mut inner = match self.lock() {
            Ok(inner) => inner,
            Err(lock_error) => {
                self.changed.notify_all();
                return Err(merge_error(
                    "resident load-failure cleanup and lifecycle lock",
                    lock_error,
                    cleanup_error,
                ));
            }
        };
        if inner.worker_transition != Some(WorkerTransition::Loading(generation))
            || inner.state.generation != generation
        {
            self.changed.notify_all();
            return Err(merge_error(
                "resident load failure and worker cleanup after lifecycle advanced",
                error,
                cleanup_error,
            ));
        }
        inner.worker_transition = None;
        inner.worker = None;
        if cleanup_error.is_none() {
            inner.state.worker_pid = None;
            inner.state.worker_descendant_pids.clear();
        }
        inner.state.idle_deadline_unix_ms = None;
        inner.idle_deadline = None;
        let failure = cleanup_error.as_ref().unwrap_or(&error);
        inner.state.phase = LifecyclePhase::Faulted;
        inner.state.last_error = Some(LifecycleErrorRecord::from_cli_error(failure));
        inner.state.load_failure_count = match inner.state.load_failure_count.checked_add(1) {
            Some(count) => count,
            None => {
                self.accepting.store(false, Ordering::SeqCst);
                self.changed.notify_all();
                return Err(merge_error(
                    "resident load failure, worker cleanup, and accounting",
                    merge_error(
                        "resident load failure and worker cleanup",
                        error,
                        cleanup_error,
                    ),
                    Some(CliError::runtime("resident load failure counter exhausted")),
                ));
            }
        };
        let persist_error = self.persist(&mut inner, "load_failed").err();
        if cleanup_error.is_some() {
            self.accepting.store(false, Ordering::SeqCst);
        }
        if persist_error.is_none() && cleanup_error.is_none() {
            let accepting = self.accepting.load(Ordering::SeqCst);
            inner.state.phase = if accepting {
                LifecyclePhase::Unloaded
            } else {
                LifecyclePhase::Stopping
            };
            inner.state.last_error = Some(LifecycleErrorRecord::from_cli_error(&error));
            let event = if accepting {
                "load_failure_reaped"
            } else {
                "load_cancelled_for_shutdown"
            };
            if let Err(reap_error) = self.persist(&mut inner, event) {
                self.changed.notify_all();
                return Err(combine_runtime_errors(
                    "resident load failure and reaped-state persistence",
                    error,
                    reap_error,
                ));
            }
        }
        self.changed.notify_all();
        Err(merge_error(
            "resident load failure, worker cleanup, and fault persistence",
            merge_error(
                "resident load failure and worker cleanup",
                error,
                cleanup_error,
            ),
            persist_error,
        ))
    }

    fn finish_load_persist_failure(
        &self,
        generation: u64,
        error: CliError,
        worker: WorkerProcess,
    ) -> CliResult {
        let cleanup_error = worker.terminate(87).err();
        if let Ok(mut inner) = self.lock() {
            if inner.worker_transition == Some(WorkerTransition::Loading(generation)) {
                inner.worker_transition = None;
                inner.worker = None;
                if cleanup_error.is_none() {
                    inner.state.worker_pid = None;
                    inner.state.worker_descendant_pids.clear();
                }
                inner.state.idle_deadline_unix_ms = None;
                inner.idle_deadline = None;
                inner.state.phase = LifecyclePhase::Faulted;
                inner.state.last_error = Some(LifecycleErrorRecord::from_cli_error(
                    cleanup_error.as_ref().unwrap_or(&error),
                ));
            }
        }
        self.changed.notify_all();
        Err(merge_error(
            "resident load-success persistence and worker cleanup",
            error,
            cleanup_error,
        ))
    }

    fn cancel_queued_request(
        &self,
        request_id: &str,
        error: &CliError,
        outcome: RequestOutcome,
    ) -> CliResult {
        let mut inner = self.lock()?;
        if inner.state.queued_requests == 0 {
            return Err(CliError::runtime(format!(
                "resident request {request_id} cancelled with queued_requests=0"
            )));
        }
        inner.state.queued_requests -= 1;
        let generation = (inner.state.generation != 0).then_some(inner.state.generation);
        let persisted = self.persist_request(
            &mut inner,
            "request_released",
            LifecycleRequestRecord {
                request_id: request_id.to_string(),
                generation,
                stage: RequestStage::Released,
                outcome: Some(outcome),
                error: Some(LifecycleErrorRecord::from_cli_error(error)),
            },
        );
        self.changed.notify_all();
        persisted
    }

    fn release_success(
        &self,
        generation: u64,
        request_id: &str,
        outcome: RequestOutcome,
        error: Option<&CliError>,
    ) -> CliResult {
        let mut inner = self.lock()?;
        if inner.state.generation != generation {
            return Err(CliError::runtime(format!(
                "resident lease generation {generation} does not match current generation {}",
                inner.state.generation
            )));
        }
        if inner.state.in_flight == 0 {
            return Err(CliError::runtime(format!(
                "resident generation {generation} released a lease with in_flight=0"
            )));
        }
        inner.state.in_flight -= 1;
        let now = unix_now_ms();
        inner.state.last_completion_unix_ms = Some(now);
        if inner.state.in_flight == 0 {
            if inner.worker_transition.is_none() {
                if inner.worker.is_some()
                    && inner.state.phase != LifecyclePhase::Faulted
                    && self.accepting.load(Ordering::SeqCst)
                {
                    if inner.state.queued_requests == 0 {
                        inner.state.phase = LifecyclePhase::LoadedIdle;
                        inner.state.idle_deadline_unix_ms = Some(now.saturating_add(IDLE_TTL_MS));
                        inner.idle_deadline = Some(Instant::now() + IDLE_TTL);
                    } else {
                        inner.state.phase = LifecyclePhase::LoadedBusy;
                        inner.state.idle_deadline_unix_ms = None;
                        inner.idle_deadline = None;
                    }
                } else if inner.worker.is_none() {
                    inner.state.phase = if self.accepting.load(Ordering::SeqCst) {
                        LifecyclePhase::Unloaded
                    } else {
                        LifecyclePhase::Stopping
                    };
                    inner.state.worker_pid = None;
                    inner.state.worker_descendant_pids.clear();
                    inner.state.idle_deadline_unix_ms = None;
                    inner.idle_deadline = None;
                } else if !self.accepting.load(Ordering::SeqCst) {
                    inner.state.phase = LifecyclePhase::Stopping;
                }
            }
        }
        let persisted = self.persist_request(
            &mut inner,
            "request_released",
            LifecycleRequestRecord {
                request_id: request_id.to_string(),
                generation: Some(generation),
                stage: RequestStage::Released,
                outcome: Some(outcome),
                error: error.map(LifecycleErrorRecord::from_cli_error),
            },
        );
        self.changed.notify_all();
        persisted
    }

    fn release_failed(
        &self,
        generation: u64,
        request_id: &str,
        outcome: RequestOutcome,
        error: &CliError,
        lifecycle_error: Option<&LifecycleErrorRecord>,
    ) -> CliResult {
        let mut inner = self.lock()?;
        if inner.state.generation != generation {
            return Err(CliError::runtime(format!(
                "resident failed lease generation {generation} does not match current generation {}",
                inner.state.generation
            )));
        }
        if inner.state.in_flight == 0 {
            return Err(CliError::runtime(format!(
                "resident generation {generation} released failed request {request_id} with in_flight=0"
            )));
        }
        inner.state.in_flight -= 1;
        inner.state.idle_deadline_unix_ms = None;
        inner.idle_deadline = None;
        if inner.state.in_flight == 0 && inner.worker_transition.is_none() {
            if inner.worker.is_none() {
                if inner.state.phase != LifecyclePhase::Faulted
                    || self.accepting.load(Ordering::SeqCst)
                {
                    inner.state.phase = if self.accepting.load(Ordering::SeqCst) {
                        LifecyclePhase::Unloaded
                    } else {
                        LifecyclePhase::Stopping
                    };
                }
                if inner.state.phase != LifecyclePhase::Faulted {
                    inner.state.worker_pid = None;
                    inner.state.worker_descendant_pids.clear();
                }
            } else {
                inner.state.phase = LifecyclePhase::Faulted;
                self.accepting.store(false, Ordering::SeqCst);
            }
        }
        let persisted = self.persist_request(
            &mut inner,
            "request_released",
            LifecycleRequestRecord {
                request_id: request_id.to_string(),
                generation: Some(generation),
                stage: RequestStage::Released,
                outcome: Some(outcome),
                error: Some(
                    lifecycle_error
                        .cloned()
                        .unwrap_or_else(|| LifecycleErrorRecord::from_cli_error(error)),
                ),
            },
        );
        self.changed.notify_all();
        persisted
    }

    fn invalidate_generation(&self, generation: u64, error: CliError) -> CliResult {
        self.invalidate_generation_with_record(generation, error, None)
    }

    fn invalidate_generation_with_record(
        &self,
        generation: u64,
        error: CliError,
        lifecycle_error: Option<LifecycleErrorRecord>,
    ) -> CliResult {
        let (worker, fault_persist_error) = {
            let mut inner = self.lock()?;
            if inner.state.generation != generation {
                return Ok(());
            }
            if inner.worker_transition == Some(WorkerTransition::Unloading(generation)) {
                return Ok(());
            }
            inner.state.phase = LifecyclePhase::Faulted;
            inner.state.idle_deadline_unix_ms = None;
            inner.idle_deadline = None;
            inner.state.last_error = Some(
                lifecycle_error
                    .clone()
                    .unwrap_or_else(|| LifecycleErrorRecord::from_cli_error(&error)),
            );
            let worker = inner.worker.take();
            if worker.is_some() {
                inner.worker_transition = Some(WorkerTransition::Unloading(generation));
            }
            let persist_error = self.persist(&mut inner, "worker_faulted").err();
            (worker, persist_error)
        };
        let owned_worker = worker.is_some();
        let cleanup_error = worker.and_then(|worker| worker.terminate(88).err());
        let mut inner = self.lock()?;
        if inner.worker_transition == Some(WorkerTransition::Unloading(generation)) {
            inner.worker_transition = None;
        }
        if owned_worker && cleanup_error.is_none() {
            inner.state.worker_pid = None;
            inner.state.worker_descendant_pids.clear();
        }
        let counter_error = if owned_worker && cleanup_error.is_none() {
            match inner.state.unload_count.checked_add(1) {
                Some(count) => {
                    inner.state.unload_count = count;
                    inner.state.last_unload_unix_ms = Some(unix_now_ms());
                    None
                }
                None => Some(CliError::runtime("resident unload counter exhausted")),
            }
        } else {
            None
        };
        if let Some(cleanup_error) = cleanup_error.as_ref().or(counter_error.as_ref()) {
            inner.state.phase = LifecyclePhase::Faulted;
            inner.state.last_error = Some(LifecycleErrorRecord::from_cli_error(cleanup_error));
            self.accepting.store(false, Ordering::SeqCst);
        } else if inner.state.in_flight == 0 {
            inner.state.phase = if self.accepting.load(Ordering::SeqCst) {
                LifecyclePhase::Unloaded
            } else {
                LifecyclePhase::Stopping
            };
        }
        let reap_event = if cleanup_error.is_some() {
            "worker_reap_failed"
        } else if counter_error.is_some() {
            "worker_reap_accounting_failed"
        } else {
            "worker_reaped"
        };
        let reaped_persist_error = if fault_persist_error.is_none() {
            self.persist(&mut inner, reap_event).err()
        } else {
            None
        };
        self.changed.notify_all();
        let terminal_error = merge_optional_errors(
            "resident worker fault persistence and reap",
            merge_optional_errors(
                "resident worker fault persistence and termination",
                fault_persist_error,
                cleanup_error,
            ),
            merge_optional_errors(
                "resident worker reap accounting and persistence",
                counter_error,
                reaped_persist_error,
            ),
        );
        match terminal_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn request_stop(&self) -> CliResult {
        let first_request = self.accepting.swap(false, Ordering::SeqCst);
        let mut inner = self.lock()?;
        inner.state.idle_deadline_unix_ms = None;
        inner.idle_deadline = None;
        if !first_request || inner.state.phase == LifecyclePhase::Stopped {
            self.changed.notify_all();
            return Ok(());
        }
        if inner.worker_transition.is_none() && inner.state.phase != LifecyclePhase::Faulted {
            inner.state.phase = LifecyclePhase::Stopping;
        }
        let persisted = self.persist(&mut inner, "shutdown_requested");
        self.changed.notify_all();
        persisted
    }

    fn shutdown(&self) -> CliResult {
        let request_error = self.request_stop().err();
        let (worker, generation, prior_fault, unload_started_error) = {
            let mut inner = self.lock()?;
            while inner.state.queued_requests > 0
                || inner.state.in_flight > 0
                || inner.worker_transition.is_some()
            {
                inner = self.wait(inner)?;
            }
            if inner.state.phase == LifecyclePhase::Stopped {
                return match request_error {
                    Some(error) => Err(error),
                    None => Ok(()),
                };
            }
            let prior_fault = if inner.state.phase == LifecyclePhase::Faulted {
                inner.state.last_error.clone().or_else(|| {
                    Some(LifecycleErrorRecord {
                        code: "CALYX_PANEL_RESIDENT_FAULTED_WITHOUT_ERROR".to_string(),
                        message: "resident supervisor entered shutdown faulted without an exact last_error record".to_string(),
                        remediation: "preserve the lifecycle journal and inspect the first transition into the faulted phase".to_string(),
                        at_unix_ms: unix_now_ms(),
                    })
                })
            } else {
                None
            };
            inner.state.phase = LifecyclePhase::Stopping;
            inner.state.idle_deadline_unix_ms = None;
            inner.idle_deadline = None;
            let generation = inner.state.generation;
            let worker = inner.worker.take();
            let persist_error = if worker.is_some() {
                inner.worker_transition = Some(WorkerTransition::Unloading(generation));
                inner.state.phase = LifecyclePhase::Unloading;
                self.persist(&mut inner, "shutdown_unload_started").err()
            } else {
                None
            };
            (worker, generation, prior_fault, persist_error)
        };
        let owned_worker = worker.is_some();
        let cleanup_error = worker.and_then(|worker| worker.stop().err());
        let mut inner = self.lock()?;
        if inner.worker_transition == Some(WorkerTransition::Unloading(generation)) {
            inner.worker_transition = None;
        }
        if owned_worker && cleanup_error.is_none() {
            inner.state.worker_pid = None;
            inner.state.worker_descendant_pids.clear();
        }
        inner.state.idle_deadline_unix_ms = None;
        inner.idle_deadline = None;
        let counter_error = if owned_worker && cleanup_error.is_none() {
            match inner.state.unload_count.checked_add(1) {
                Some(count) => {
                    inner.state.unload_count = count;
                    inner.state.last_unload_unix_ms = Some(unix_now_ms());
                    None
                }
                None => Some(CliError::runtime("resident unload counter exhausted")),
            }
        } else {
            None
        };
        let exact_fault = cleanup_error
            .as_ref()
            .map(LifecycleErrorRecord::from_cli_error)
            .or_else(|| {
                counter_error
                    .as_ref()
                    .map(LifecycleErrorRecord::from_cli_error)
            })
            .or_else(|| {
                unload_started_error
                    .as_ref()
                    .map(LifecycleErrorRecord::from_cli_error)
            })
            .or_else(|| {
                request_error
                    .as_ref()
                    .map(LifecycleErrorRecord::from_cli_error)
            })
            .or_else(|| prior_fault.clone());
        let prior_fault_error = prior_fault.as_ref().map(prior_fault_cli_error);
        let mut terminal_error = merge_optional_errors(
            "resident shutdown cleanup and lifecycle failures",
            merge_optional_errors(
                "resident shutdown worker cleanup and accounting",
                cleanup_error,
                counter_error,
            ),
            merge_optional_errors(
                "resident shutdown persistence and prior fault",
                merge_optional_errors(
                    "resident shutdown request and unload-start persistence",
                    request_error,
                    unload_started_error,
                ),
                prior_fault_error,
            ),
        );
        if let Some(exact_fault) = exact_fault {
            inner.state.phase = LifecyclePhase::Faulted;
            inner.state.last_error = Some(exact_fault.clone());
            if let Err(persist_error) = self.persist(&mut inner, "shutdown_worker_failed") {
                inner.state.last_error = Some(exact_fault);
                terminal_error = Some(combine_terminal_errors(terminal_error, persist_error));
            }
        } else {
            inner.state.phase = LifecyclePhase::Stopped;
            terminal_error = self.persist(&mut inner, "supervisor_stopped").err();
        }
        self.changed.notify_all();
        match terminal_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn idle_monitor(self: Arc<Self>) {
        loop {
            let mut inner = match self.lock() {
                Ok(inner) => inner,
                Err(error) => {
                    self.accepting.store(false, Ordering::SeqCst);
                    eprintln!(
                        "CALYX_PANEL_RESIDENT_RUNTIME phase=monitor_lock_error code={} message={}",
                        error.code(),
                        error.message()
                    );
                    return;
                }
            };
            if let Some((generation, error)) = loaded_worker_failure(&mut inner) {
                drop(inner);
                if let Err(invalidation_error) = self.invalidate_generation(generation, error) {
                    self.accepting.store(false, Ordering::SeqCst);
                    eprintln!(
                        "CALYX_PANEL_RESIDENT_RUNTIME phase=monitor_worker_reconcile_error generation={} code={} message={}",
                        generation,
                        invalidation_error.code(),
                        invalidation_error.message()
                    );
                    return;
                }
                continue;
            }
            if !self.accepting.load(Ordering::SeqCst) && inner.worker_transition.is_none() {
                return;
            }
            if matches!(
                inner.state.phase,
                LifecyclePhase::Stopping | LifecyclePhase::Stopped
            ) {
                return;
            }
            let Some(deadline) = inner.idle_deadline else {
                if let Err(error) = self.wait(inner) {
                    self.accepting.store(false, Ordering::SeqCst);
                    eprintln!(
                        "CALYX_PANEL_RESIDENT_RUNTIME phase=monitor_wait_error code={} message={}",
                        error.code(),
                        error.message()
                    );
                    return;
                }
                continue;
            };
            if inner.state.phase != LifecyclePhase::LoadedIdle
                || inner.state.queued_requests != 0
                || inner.state.in_flight != 0
                || inner.worker_transition.is_some()
            {
                inner.idle_deadline = None;
                continue;
            }
            let now = Instant::now();
            if now < deadline {
                let timeout = deadline
                    .saturating_duration_since(now)
                    .min(WORKER_LIVENESS_POLL);
                match self.changed.wait_timeout(inner, timeout) {
                    Ok((guard, _)) => drop(guard),
                    Err(_) => self.accepting.store(false, Ordering::SeqCst),
                }
                continue;
            }
            inner.state.phase = LifecyclePhase::Unloading;
            inner.state.idle_deadline_unix_ms = None;
            inner.idle_deadline = None;
            let generation = inner.state.generation;
            let worker = inner.worker.take();
            let owned_worker = worker.is_some();
            inner.worker_transition = Some(WorkerTransition::Unloading(generation));
            let started_persist_error = self.persist(&mut inner, "idle_unload_started").err();
            drop(inner);
            let cleanup_error = match worker {
                Some(worker) => worker.stop().err(),
                None => Some(worker_error(
                    format!(
                        "resident generation {generation} reached its idle deadline without an owned worker"
                    ),
                    "preserve the lifecycle journal and restart the resident supervisor",
                )),
            };
            let mut inner = match self.lock() {
                Ok(inner) => inner,
                Err(error) => {
                    self.accepting.store(false, Ordering::SeqCst);
                    eprintln!(
                        "CALYX_PANEL_RESIDENT_RUNTIME phase=idle_unload_final_lock_error generation={} code={} message={}",
                        generation,
                        error.code(),
                        error.message()
                    );
                    return;
                }
            };
            if inner.worker_transition == Some(WorkerTransition::Unloading(generation)) {
                inner.worker_transition = None;
            }
            if owned_worker && cleanup_error.is_none() {
                inner.state.worker_pid = None;
                inner.state.worker_descendant_pids.clear();
            }
            let counter_error = if owned_worker && cleanup_error.is_none() {
                match inner.state.unload_count.checked_add(1) {
                    Some(count) => {
                        inner.state.unload_count = count;
                        inner.state.last_unload_unix_ms = Some(unix_now_ms());
                        None
                    }
                    None => Some(CliError::runtime("resident unload counter exhausted")),
                }
            } else {
                None
            };
            let exact_unload_error = cleanup_error
                .as_ref()
                .or(counter_error.as_ref())
                .or(started_persist_error.as_ref())
                .map(LifecycleErrorRecord::from_cli_error);
            let unload_error = merge_optional_errors(
                "resident idle unload cleanup and lifecycle failures",
                merge_optional_errors(
                    "resident idle unload termination and accounting",
                    cleanup_error,
                    counter_error,
                ),
                started_persist_error,
            );
            if let Some(error) = &unload_error {
                let exact_error = exact_unload_error
                    .unwrap_or_else(|| LifecycleErrorRecord::from_cli_error(error));
                inner.state.phase = LifecyclePhase::Faulted;
                inner.state.last_error = Some(exact_error.clone());
                self.accepting.store(false, Ordering::SeqCst);
                if let Err(persist_error) = self.persist(&mut inner, "idle_unload_failed") {
                    inner.state.last_error = Some(exact_error);
                    eprintln!(
                        "CALYX_PANEL_RESIDENT_RUNTIME phase=idle_unload_failure_persist_error unload_code={} unload_message={} persist_code={} persist_message={}",
                        error.code(),
                        error.message(),
                        persist_error.code(),
                        persist_error.message()
                    );
                }
            } else {
                inner.state.phase = if self.accepting.load(Ordering::SeqCst) {
                    LifecyclePhase::Unloaded
                } else {
                    LifecyclePhase::Stopping
                };
                if let Err(error) = self.persist(&mut inner, "idle_unload_completed") {
                    self.accepting.store(false, Ordering::SeqCst);
                    eprintln!(
                        "CALYX_PANEL_RESIDENT_RUNTIME phase=unload_complete_persist_error code={} message={}",
                        error.code(),
                        error.message()
                    );
                }
            }
            self.changed.notify_all();
            if unload_error.is_some() {
                return;
            }
        }
    }

    fn readiness(&self) -> CliResult<ReadyResponse> {
        let mut inner = self.lock()?;
        if let Some((generation, error)) = loaded_worker_failure(&mut inner) {
            drop(inner);
            self.invalidate_generation(generation, error)?;
            inner = self.lock()?;
        }
        let warm = inner.last_worker_ready.clone();
        let warm_ready = inner.worker.is_some()
            && matches!(
                inner.state.phase,
                LifecyclePhase::LoadedIdle | LifecyclePhase::LoadedBusy
            );
        let accepting = self.accepting.load(Ordering::SeqCst)
            && !matches!(
                inner.state.phase,
                LifecyclePhase::Faulted | LifecyclePhase::Stopping | LifecyclePhase::Stopped
            );
        let idle_remaining_ms = inner.idle_deadline.map(|deadline| {
            deadline
                .saturating_duration_since(Instant::now())
                .as_millis() as u64
        });
        Ok(ReadyResponse {
            ok: true,
            schema: READY_SCHEMA.to_string(),
            ready: accepting,
            accepting_requests: accepting,
            warm_ready,
            phase: inner.state.phase,
            residency_scope: "stable_supervisor_generation_worker".to_string(),
            process_id: std::process::id(),
            supervisor_pid: std::process::id(),
            worker_pid: inner.state.worker_pid,
            worker_descendant_pids: inner.state.worker_descendant_pids.clone(),
            generation: inner.state.generation,
            queued_requests: inner.state.queued_requests,
            in_flight: inner.state.in_flight,
            bind: self.bind,
            uptime_ms: self.started.elapsed().as_millis(),
            source_of_truth: self.source.source_of_truth.clone(),
            home: self.home.clone(),
            template_selector: self.source.selector.clone(),
            template_source: warm.as_ref().map_or_else(
                || self.source.selector.clone(),
                |ready| ready.template_source.clone(),
            ),
            ready_out: self.ready_out.clone(),
            max_resident_vram_mib: warm
                .as_ref()
                .map_or(DEFAULT_MAX_RESIDENT_VRAM_MIB, |ready| {
                    ready.max_resident_vram_mib
                }),
            declared_template_vram_mib: warm
                .as_ref()
                .map_or(0, |ready| ready.declared_template_vram_mib),
            resident_overhead_multiplier: warm
                .as_ref()
                .map_or(0.0, |ready| ready.resident_overhead_multiplier),
            estimated_resident_vram_mib: warm
                .as_ref()
                .map_or(0, |ready| ready.estimated_resident_vram_mib),
            max_load_secs: self.max_load_secs,
            max_request_secs: self.max_request_secs,
            idle_ttl_ms: IDLE_TTL_MS,
            idle_remaining_ms,
            idle_deadline_unix_ms: inner.state.idle_deadline_unix_ms,
            load_attempt_count: inner.state.load_attempt_count,
            load_success_count: inner.state.load_success_count,
            load_failure_count: inner.state.load_failure_count,
            unload_count: inner.state.unload_count,
            lifecycle_sequence: inner.projection.sequence,
            lifecycle_journal: Some(inner.store.journal_path().to_path_buf()),
            lifecycle_snapshot: Some(inner.store.snapshot_path().to_path_buf()),
            frozen_panel_fingerprint: self.source.fingerprint.clone(),
            last_error: inner.state.last_error.clone(),
            load_parallelism: warm.as_ref().map_or(0, |ready| ready.load_parallelism),
            load_ms: warm.as_ref().map_or(0, |ready| ready.load_ms),
            probe_ms: warm.as_ref().map_or(0, |ready| ready.probe_ms),
            slot_count: warm.as_ref().map_or(0, |ready| ready.slot_count),
            slot_contracts: warm
                .as_ref()
                .map_or_else(Vec::new, |ready| ready.slot_contracts.clone()),
            slot_scope: warm
                .as_ref()
                .map_or_else(Vec::new, |ready| ready.slot_scope.clone()),
            content_lens_count: warm.as_ref().map_or(0, |ready| ready.content_lens_count),
            registry_lens_count: warm.as_ref().map_or(0, |ready| ready.registry_lens_count),
            warmed_lens_count: warm.as_ref().map_or(0, |ready| ready.warmed_lens_count),
            warmed_lens_scope: warm.as_ref().map_or_else(
                || "unique_active_registered_lenses".to_string(),
                |ready| ready.warmed_lens_scope.clone(),
            ),
            lens_attestations: inner.state.lens_attestations.clone(),
            onnx_runtime_attestation: inner.state.onnx_runtime_attestation.clone(),
            gpu_content_lens_count: warm
                .as_ref()
                .map_or(0, |ready| ready.gpu_content_lens_count),
            cpu_content_lens_count: warm
                .as_ref()
                .map_or(0, |ready| ready.cpu_content_lens_count),
        })
    }

    fn persist(&self, inner: &mut SupervisorInner, event: &str) -> CliResult {
        let state = inner.state.clone();
        match inner.store.append(event, &state) {
            Ok(projection) => {
                inner.projection = projection;
                Ok(())
            }
            Err(error) => {
                self.accepting.store(false, Ordering::SeqCst);
                inner.state.phase = LifecyclePhase::Faulted;
                inner.state.last_error = Some(LifecycleErrorRecord::from_cli_error(&error));
                Err(error)
            }
        }
    }

    fn persist_request(
        &self,
        inner: &mut SupervisorInner,
        event: &str,
        request: LifecycleRequestRecord,
    ) -> CliResult {
        let state = inner.state.clone();
        match inner.store.append_request(event, &state, Some(request)) {
            Ok(projection) => {
                inner.projection = projection;
                Ok(())
            }
            Err(error) => {
                self.accepting.store(false, Ordering::SeqCst);
                inner.state.phase = LifecyclePhase::Faulted;
                inner.state.last_error = Some(LifecycleErrorRecord::from_cli_error(&error));
                Err(error)
            }
        }
    }

    fn record_request_stage(
        &self,
        request_id: &str,
        generation: Option<u64>,
        stage: RequestStage,
        outcome: Option<RequestOutcome>,
        error: Option<&CliError>,
    ) -> CliResult {
        let mut inner = self.lock()?;
        if let Some(generation) = generation
            && inner.state.generation != generation
        {
            return Err(CliError::runtime(format!(
                "resident request {request_id} stage {:?} names generation {generation}, current generation is {}",
                stage, inner.state.generation
            )));
        }
        let persisted = self.persist_request(
            &mut inner,
            "request_stage",
            LifecycleRequestRecord {
                request_id: request_id.to_string(),
                generation,
                stage,
                outcome,
                error: error.map(LifecycleErrorRecord::from_cli_error),
            },
        );
        self.changed.notify_all();
        persisted
    }

    fn lock(&self) -> CliResult<MutexGuard<'_, SupervisorInner>> {
        self.inner.lock().map_err(|_| {
            CliError::from(CalyxError {
                code: "CALYX_PANEL_RESIDENT_LIFECYCLE_CORRUPT",
                message: "resident supervisor state mutex is poisoned".to_string(),
                remediation: "preserve lifecycle files and restart the supervisor after inspecting the first panic",
            })
        })
    }

    fn wait<'a>(
        &self,
        guard: MutexGuard<'a, SupervisorInner>,
    ) -> CliResult<MutexGuard<'a, SupervisorInner>> {
        self.changed.wait(guard).map_err(|_| {
            CliError::runtime("resident supervisor state mutex was poisoned while waiting")
        })
    }
}

fn join_monitor(handle: JoinHandle<()>) -> CliResult {
    handle.join().map_err(|_| {
        CliError::runtime("resident idle monitor panicked before supervisor shutdown completed")
    })
}

fn reap_finished_handlers(handlers: &mut Vec<JoinHandle<()>>) -> CliResult {
    let mut index = 0;
    while index < handlers.len() {
        if handlers[index].is_finished() {
            let handle = handlers.swap_remove(index);
            join_client_handler(handle)?;
        } else {
            index += 1;
        }
    }
    Ok(())
}

fn join_handlers(handlers: Vec<JoinHandle<()>>) -> CliResult {
    let mut first_error = None;
    for handler in handlers {
        if let Err(error) = join_client_handler(handler)
            && first_error.is_none()
        {
            first_error = Some(error);
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn join_client_handler(handle: JoinHandle<()>) -> CliResult {
    handle.join().map_err(|_| {
        CliError::runtime("resident client handler panicked before its connection was released")
    })
}

fn serve_loop(listener: TcpListener, supervisor: Arc<Supervisor>) -> CliResult {
    listener.set_nonblocking(true)?;
    let handler_limit = std::thread::available_parallelism()
        .map_err(|error| CliError::runtime(format!("measure resident handler capacity: {error}")))?
        .get();
    let mut handlers = Vec::new();
    let mut accept_error = None;
    while supervisor.accepting.load(Ordering::SeqCst) {
        if let Err(error) = reap_finished_handlers(&mut handlers) {
            accept_error = Some(error);
            if let Err(stop_error) = supervisor.request_stop() {
                eprintln!(
                    "CALYX_PANEL_RESIDENT_RUNTIME phase=handler_reap_stop_persist_error code={} message={}",
                    stop_error.code(),
                    stop_error.message()
                );
            }
            break;
        }
        match listener.accept() {
            Ok((stream, peer)) => {
                if !peer.ip().is_loopback() {
                    let _ = stream.shutdown(Shutdown::Both);
                    continue;
                }
                if handlers.len() >= handler_limit {
                    if let Err(error) = reject_back_pressure(stream) {
                        eprintln!(
                            "CALYX_PANEL_RESIDENT_RUNTIME phase=back_pressure_response_error code={} message={}",
                            error.code(),
                            error.message()
                        );
                    }
                    continue;
                }
                let supervisor = Arc::clone(&supervisor);
                handlers.push(std::thread::spawn(move || {
                    if let Err(error) = handle_client(stream, supervisor) {
                        eprintln!(
                            "CALYX_PANEL_RESIDENT_RUNTIME phase=client_error code={} message={} remediation={}",
                            error.code(),
                            error.message(),
                            error.remediation()
                        );
                    }
                }));
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => {
                accept_error = Some(error.into());
                if let Err(stop_error) = supervisor.request_stop() {
                    eprintln!(
                        "CALYX_PANEL_RESIDENT_RUNTIME phase=accept_stop_persist_error code={} message={}",
                        stop_error.code(),
                        stop_error.message()
                    );
                }
                break;
            }
        }
    }
    let joined = join_handlers(handlers);
    match accept_error {
        Some(error) => {
            joined?;
            Err(error)
        }
        None => joined,
    }
}

fn reject_back_pressure(mut stream: TcpStream) -> CliResult {
    let deadline = deadline_after(BACK_PRESSURE_RESPONSE_TIMEOUT)?;
    let mut ingress = stream.try_clone()?;
    let mut reader = BufReader::new(DeadlineStream::new(&mut ingress, deadline));
    let first_line = read_bounded_line(
        &mut reader,
        MAX_RESIDENT_JSON_LINE_BYTES,
        "resident back-pressure request preamble",
    )?;
    let error = CliError::from(CalyxError {
        code: BACK_PRESSURE,
        message: "resident supervisor reached its measured native handler capacity".to_string(),
        remediation: "retry after an active resident request completes; do not open idle loopback connections",
    });
    if first_line == RESIDENT_BINARY_MAGIC {
        write_binary_error_before(&mut stream, &error, deadline)
    } else {
        write_json_response_before(&mut stream, &cli_error_value(&error), deadline)
    }
}

fn handle_client(mut stream: TcpStream, supervisor: Arc<Supervisor>) -> CliResult {
    let ingress_deadline = deadline_after(PUBLIC_SOCKET_TIMEOUT)?;
    let mut ingress = stream.try_clone()?;
    let mut reader = BufReader::new(DeadlineStream::new(&mut ingress, ingress_deadline));
    let first_line = match read_bounded_line(
        &mut reader,
        MAX_RESIDENT_JSON_LINE_BYTES,
        "resident public request preamble",
    ) {
        Ok(line) => line,
        Err(error) => {
            return write_json_response(
                &mut stream,
                &error_value(
                    "CALYX_PANEL_RESIDENT_BAD_REQUEST",
                    format!("read resident request preamble: {error}"),
                    "send one complete bounded JSON line or binary request without delaying partial bytes",
                ),
            );
        }
    };
    if first_line == RESIDENT_BINARY_MAGIC {
        return handle_binary(&mut reader, &mut stream, supervisor, ingress_deadline);
    }
    let request = match std::str::from_utf8(&first_line) {
        Ok(line) => match serde_json::from_str::<ResidentRequest>(line) {
            Ok(request) => request,
            Err(error) => {
                return write_json_response(
                    &mut stream,
                    &error_value(
                        "CALYX_PANEL_RESIDENT_BAD_REQUEST",
                        format!("decode resident request JSON line: {error}"),
                        "send one JSON object per connection with op=ready, measure, measure_batch, or shutdown",
                    ),
                );
            }
        },
        Err(error) => {
            return write_json_response(
                &mut stream,
                &error_value(
                    "CALYX_PANEL_RESIDENT_BAD_REQUEST",
                    format!("resident request was not valid UTF-8 JSON: {error}"),
                    "send one JSON object per connection or the resident binary magic line",
                ),
            );
        }
    };
    let class = match validate_public_request(&request) {
        Ok(class) => class,
        Err(error) => return write_json_response(&mut stream, &error),
    };
    if let Err(error) = ensure_before(ingress_deadline, "resident public JSON ingress and decode") {
        return write_json_response(
            &mut stream,
            &error_value(
                "CALYX_PANEL_RESIDENT_BAD_REQUEST",
                error.to_string(),
                "send one bounded request promptly; use the framed binary route for large batches",
            ),
        );
    }
    match class {
        RequestClass::Ready => match supervisor.readiness() {
            Ok(ready) => {
                let ready = serde_json::to_value(ready).map_err(|error| {
                    CliError::runtime(format!("serialize supervisor readiness: {error}"))
                })?;
                write_json_response(&mut stream, &ready)
            }
            Err(error) => write_json_response(&mut stream, &cli_error_value(&error)),
        },
        RequestClass::Shutdown => match supervisor.request_stop() {
            Ok(()) => write_json_response(
                &mut stream,
                &json!({"ok": true, "schema": READY_SCHEMA, "ready": false, "stopping": true}),
            ),
            Err(error) => write_json_response(&mut stream, &cli_error_value(&error)),
        },
        RequestClass::Productive => {
            let modality = request
                .modality
                .expect("productive JSON request validation requires modality");
            if let Err(error) = supervisor
                .source
                .require_applicable_neural_modality(modality)
            {
                return write_json_response(&mut stream, &cli_error_value(&error));
            }
            let mut lease = match supervisor.acquire() {
                Ok(lease) => lease,
                Err(error) => {
                    return write_json_response(&mut stream, &cli_error_value(&error));
                }
            };
            let endpoint = lease.endpoint();
            let request_deadline = deadline_after(endpoint.request_timeout)?;
            let response = match proxy_json(&endpoint, &request, request_deadline, &mut lease) {
                Ok(JsonProxyResponse::Success(response)) => response,
                Ok(JsonProxyResponse::WorkerFailure { response, failure }) => {
                    let cleanup = lease.fail_reported(&failure, RequestOutcome::Failed);
                    let response_deadline = deadline_after(PUBLIC_SOCKET_TIMEOUT)?;
                    return match cleanup {
                        Ok(()) => {
                            write_json_bytes_before(&mut stream, &response, response_deadline)
                        }
                        Err(cleanup_error) => {
                            let value = cli_error_value(&cleanup_error);
                            if let Err(write_error) =
                                write_json_response_before(&mut stream, &value, response_deadline)
                            {
                                eprintln!(
                                    "CALYX_PANEL_RESIDENT_RUNTIME phase=json_cleanup_error_response_failed cleanup_code={} cleanup_message={} write_code={} write_message={}",
                                    cleanup_error.code(),
                                    cleanup_error.message(),
                                    write_error.code(),
                                    write_error.message()
                                );
                            }
                            Err(cleanup_error)
                        }
                    };
                }
                Err(error) => {
                    let cleanup = lease.fail(&error, RequestOutcome::Failed);
                    let value = cli_error_value(cleanup.as_ref().err().unwrap_or(&error));
                    let write = deadline_after(PUBLIC_SOCKET_TIMEOUT)
                        .map_err(CliError::from)
                        .and_then(|deadline| {
                            write_json_response_before(&mut stream, &value, deadline)
                        });
                    if let Err(cleanup_error) = cleanup {
                        if let Err(write_error) = write {
                            eprintln!(
                                "CALYX_PANEL_RESIDENT_RUNTIME phase=json_worker_cleanup_and_response_failed cleanup_code={} cleanup_message={} write_code={} write_message={}",
                                cleanup_error.code(),
                                cleanup_error.message(),
                                write_error.code(),
                                write_error.message()
                            );
                        }
                        return Err(cleanup_error);
                    }
                    write?;
                    return Ok(());
                }
            };
            match write_json_bytes_before(&mut stream, &response, request_deadline) {
                Ok(()) => {
                    lease.advance(RequestStage::PublicFlushComplete)?;
                    lease.complete_success()
                }
                Err(write_error) => {
                    let cancellation = client_aborted_error(
                        endpoint.generation,
                        &write_error,
                        "JSON response flush",
                    );
                    let cleanup = lease.fail(&cancellation, RequestOutcome::Abandoned);
                    cleanup?;
                    Err(write_error)
                }
            }
        }
    }
}

fn loaded_worker_failure(inner: &mut SupervisorInner) -> Option<(u64, CliError)> {
    if !matches!(
        inner.state.phase,
        LifecyclePhase::LoadedIdle | LifecyclePhase::LoadedBusy
    ) {
        return None;
    }
    let generation = inner.state.generation;
    match inner.worker.as_mut() {
        Some(worker) => worker
            .verify_live_exact()
            .err()
            .map(|error| (generation, error)),
        None => Some((
            generation,
            worker_error(
                format!(
                    "resident generation {generation} has loaded lifecycle state without an owned worker"
                ),
                "preserve the lifecycle journal and restart the resident supervisor after the failed generation is reaped",
            ),
        )),
    }
}

fn handle_binary(
    reader: &mut dyn std::io::Read,
    stream: &mut TcpStream,
    supervisor: Arc<Supervisor>,
    ingress_deadline: Instant,
) -> CliResult {
    let payload = match read_frame(reader) {
        Ok(payload) => payload,
        Err(error) => {
            write_binary_error(stream, &CliError::from(error))?;
            return Ok(());
        }
    };
    let decoded_request = match decode_binary_request(&payload) {
        Ok(request) => request,
        Err(error) => {
            write_binary_error(stream, &error)?;
            return Ok(());
        }
    };
    if decoded_request.supervisor_request_id.is_some()
        || decoded_request.supervisor_generation.is_some()
    {
        let error = CliError::from(CalyxError {
            code: "CALYX_PANEL_RESIDENT_BAD_REQUEST",
            message: "public binary request supplied private supervisor request identity"
                .to_string(),
            remediation: "leave supervisor_request_id and supervisor_generation unset; the public supervisor assigns both after admission",
        });
        write_binary_error(stream, &error)?;
        return Ok(());
    }
    if let Err(error) = supervisor
        .source
        .require_applicable_neural_modality(decoded_request.modality)
    {
        write_binary_error(stream, &error)?;
        return Ok(());
    }
    if let Err(error) = ensure_before(
        ingress_deadline,
        "resident public binary ingress and decode",
    ) {
        let error = CliError::from(CalyxError {
            code: "CALYX_PANEL_RESIDENT_BAD_REQUEST",
            message: error.to_string(),
            remediation: "send one bounded binary frame promptly and reduce the batch size if decoding exceeds the public ingress budget",
        });
        write_binary_error(stream, &error)?;
        return Ok(());
    }
    let mut lease = match supervisor.acquire() {
        Ok(lease) => lease,
        Err(error) => {
            write_binary_error(stream, &error)?;
            return Ok(());
        }
    };
    let endpoint = lease.endpoint();
    let request_deadline = deadline_after(endpoint.request_timeout)?;
    match proxy_binary(
        &endpoint,
        &decoded_request,
        stream,
        request_deadline,
        &mut lease,
    ) {
        Ok(()) => {
            lease.advance(RequestStage::PublicFlushComplete)?;
            lease.complete_success()
        }
        Err(BinaryProxyError::Worker(error)) => {
            let cleanup = lease.fail(&error, RequestOutcome::Failed);
            let response_error = cleanup.as_ref().err().unwrap_or(&error);
            if let Ok(error_deadline) = deadline_after(PUBLIC_SOCKET_TIMEOUT) {
                if let Err(write_error) =
                    write_binary_error_before(stream, response_error, error_deadline)
                {
                    eprintln!(
                        "CALYX_PANEL_RESIDENT_RUNTIME phase=binary_worker_error_response_failed worker_code={} worker_message={} write_code={} write_message={}",
                        response_error.code(),
                        response_error.message(),
                        write_error.code(),
                        write_error.message()
                    );
                }
            }
            cleanup?;
            Err(error)
        }
        Err(BinaryProxyError::WorkerReported { failure, frame }) => {
            let cleanup = lease.fail_reported(&failure, RequestOutcome::Failed);
            let response_deadline = deadline_after(PUBLIC_SOCKET_TIMEOUT)?;
            if let Err(cleanup_error) = cleanup {
                if let Err(write_error) =
                    write_binary_error_before(stream, &cleanup_error, response_deadline)
                {
                    eprintln!(
                        "CALYX_PANEL_RESIDENT_RUNTIME phase=binary_cleanup_error_response_failed cleanup_code={} cleanup_message={} write_code={} write_message={}",
                        cleanup_error.code(),
                        cleanup_error.message(),
                        write_error.code(),
                        write_error.message()
                    );
                }
                return Err(cleanup_error);
            }
            write_binary_frame_before(stream, &frame, response_deadline)?;
            Err(failure.supervisor_error)
        }
        Err(BinaryProxyError::Client(error)) => {
            // The supervisor cannot prove that the private worker stopped
            // computing merely because the public client stopped consuming a
            // stream. Reap the generation before releasing its lease.
            let cancellation = client_aborted_error(endpoint.generation, &error, "binary stream");
            let cleanup = lease.fail(&cancellation, RequestOutcome::Abandoned);
            cleanup?;
            Err(error)
        }
    }
}

fn proxy_json(
    endpoint: &WorkerEndpoint,
    request: &ResidentRequest,
    deadline: Instant,
    lease: &mut ProductiveLease,
) -> CliResult<JsonProxyResponse> {
    let bind = endpoint.bind;
    let mut worker = connect_before(&bind, deadline).map_err(|error| {
        worker_error(
            format!("connect loaded resident worker {bind}: {error}"),
            "inspect the recorded worker PID and generation logs",
        )
    })?;
    let mut worker_io = DeadlineStream::new(&mut worker, deadline);
    write_worker_auth_line(&mut worker_io, &endpoint.auth_secret)?;
    let mut worker_request = request.clone();
    worker_request.supervisor_request_id = Some(lease.request_id.clone());
    worker_request.supervisor_generation = Some(endpoint.generation);
    serde_json::to_writer(&mut worker_io, &worker_request)
        .map_err(|error| CliError::runtime(format!("serialize worker request: {error}")))?;
    worker_io.write_all(b"\n")?;
    worker_io.flush()?;
    lease.advance(RequestStage::WorkerRequestFlushed)?;
    let mut worker_reader = BufReader::new(worker_io);
    let response = read_bounded_line(
        &mut worker_reader,
        MAX_RESIDENT_JSON_LINE_BYTES,
        "resident worker JSON response",
    )?;
    let value = serde_json::from_slice::<Value>(&response).map_err(|error| {
        worker_error(
            format!("loaded resident worker {bind} returned invalid JSON: {error}"),
            "preserve the worker response and restart from one native Calyx build",
        )
    })?;
    ensure_before(deadline, "resident worker JSON proxy")?;
    match value.get("ok") {
        Some(Value::Bool(false)) => {
            let failure = worker_reported_json_error(endpoint.bind, &value)?;
            lease.advance(RequestStage::TerminalReceived)?;
            return Ok(JsonProxyResponse::WorkerFailure { response, failure });
        }
        Some(Value::Bool(true)) => {
            if ["code", "message", "remediation"]
                .iter()
                .any(|field| value.get(field).is_some())
            {
                return Err(worker_protocol_error(
                    endpoint.bind,
                    "returned ok=true while also carrying failure-envelope fields",
                ));
            }
        }
        Some(_) => {
            return Err(worker_protocol_error(
                endpoint.bind,
                "returned a non-boolean ok field",
            ));
        }
        None => {
            return Err(worker_protocol_error(
                endpoint.bind,
                "omitted the required boolean ok field",
            ));
        }
    }
    validate_worker_json_success(endpoint, request, &lease.request_id, &value)?;
    lease.advance(RequestStage::GpuSynchronized)?;
    lease.advance(RequestStage::HostMaterialized)?;
    lease.advance(RequestStage::TerminalReceived)?;
    Ok(JsonProxyResponse::Success(response))
}

enum JsonProxyResponse {
    Success(Vec<u8>),
    WorkerFailure {
        response: Vec<u8>,
        failure: WorkerReportedFailure,
    },
}

struct WorkerReportedFailure {
    supervisor_error: CliError,
    lifecycle_error: LifecycleErrorRecord,
}

fn worker_reported_json_error(bind: SocketAddr, value: &Value) -> CliResult<WorkerReportedFailure> {
    let field = |name: &str| {
        value
            .get(name)
            .and_then(Value::as_str)
            .filter(|field| !field.trim().is_empty())
            .ok_or_else(|| {
                worker_protocol_error(
                    bind,
                    format!("returned ok=false but {name} was missing, blank, or not a string"),
                )
            })
    };
    let code = field("code")?;
    let message = field("message")?;
    let remediation = field("remediation")?;
    Ok(reported_worker_error(bind, code, message, remediation))
}

fn validate_worker_json_success(
    endpoint: &WorkerEndpoint,
    request: &ResidentRequest,
    request_id: &str,
    value: &Value,
) -> CliResult {
    match request.op.as_str() {
        "measure" => {
            let response =
                serde_json::from_value::<MeasureResponse>(value.clone()).map_err(|error| {
                    worker_protocol_error(
                        endpoint.bind,
                        format!("measure success did not match its exact schema: {error}"),
                    )
                })?;
            let expected_len = request.input.as_ref().map_or_else(
                || request.input_hex.as_ref().map_or(0, |hex| hex.len() / 2),
                |text| text.len(),
            );
            validate_worker_response_identity(
                endpoint,
                response.schema.as_str(),
                MEASURE_SCHEMA,
                response.ready,
                response.process_id,
                response.template_source.as_str(),
                response.modality,
                request.modality,
            )?;
            if response.input_len != expected_len {
                return Err(worker_protocol_error(
                    endpoint.bind,
                    format!(
                        "measure input_len {} did not match requested byte length {expected_len}",
                        response.input_len
                    ),
                ));
            }
            validate_worker_slots(
                endpoint,
                response.modality,
                response.measured_slot_count,
                response.absent_slot_count,
                &response.slots,
                "measure",
            )?;
            validate_completion(endpoint, request_id, &response.completion)
        }
        "measure_batch" => {
            let response =
                serde_json::from_value::<MeasureBatchResponse>(value.clone()).map_err(|error| {
                    worker_protocol_error(
                        endpoint.bind,
                        format!("measure_batch success did not match its exact schema: {error}"),
                    )
                })?;
            let requested = request.inputs_hex.as_deref().unwrap_or_default();
            validate_worker_response_identity(
                endpoint,
                response.schema.as_str(),
                MEASURE_BATCH_SCHEMA,
                response.ready,
                response.process_id,
                response.template_source.as_str(),
                response.modality,
                request.modality,
            )?;
            if response.input_count != requested.len()
                || response.rows.len() != requested.len()
                || response.runtime_batch_limit != request.runtime_batch_limit
            {
                return Err(worker_protocol_error(
                    endpoint.bind,
                    format!(
                        "measure_batch cardinality/options mismatch: response input_count={} rows={} runtime_batch_limit={:?}; request inputs={} runtime_batch_limit={:?}",
                        response.input_count,
                        response.rows.len(),
                        response.runtime_batch_limit,
                        requested.len(),
                        request.runtime_batch_limit
                    ),
                ));
            }
            for (index, row) in response.rows.iter().enumerate() {
                validate_worker_row(
                    endpoint,
                    response.modality,
                    row,
                    index,
                    requested[index].len() / 2,
                    "measure_batch",
                )?;
            }
            validate_completion(endpoint, request_id, &response.completion)
        }
        other => Err(worker_protocol_error(
            endpoint.bind,
            format!("productive proxy received unsupported operation {other}"),
        )),
    }
}

fn validate_worker_response_identity(
    endpoint: &WorkerEndpoint,
    observed_schema: &str,
    expected_schema: &str,
    ready: bool,
    process_id: u32,
    template_source: &str,
    modality: Modality,
    requested_modality: Option<Modality>,
) -> CliResult {
    if observed_schema != expected_schema
        || !ready
        || process_id != endpoint.process_id
        || template_source != endpoint.template_source
        || Some(modality) != requested_modality
    {
        return Err(worker_protocol_error(
            endpoint.bind,
            format!(
                "response identity mismatch: schema={observed_schema:?} expected={expected_schema:?} ready={ready} process_id={process_id} expected_pid={} template_source={template_source:?} expected_template={:?} modality={modality:?} requested_modality={requested_modality:?}",
                endpoint.process_id, endpoint.template_source
            ),
        ));
    }
    Ok(())
}

fn validate_worker_row(
    endpoint: &WorkerEndpoint,
    modality: Modality,
    row: &ResidentMeasuredInput,
    expected_index: usize,
    expected_input_len: usize,
    context: &str,
) -> CliResult {
    if row.input_index != expected_index || row.input_len != expected_input_len {
        return Err(worker_protocol_error(
            endpoint.bind,
            format!(
                "{context} row identity mismatch: input_index={} expected={expected_index} input_len={} expected={expected_input_len}",
                row.input_index, row.input_len
            ),
        ));
    }
    validate_worker_slots(
        endpoint,
        modality,
        row.measured_slot_count,
        row.absent_slot_count,
        &row.slots,
        context,
    )
}

fn validate_worker_slots(
    endpoint: &WorkerEndpoint,
    modality: Modality,
    measured_slot_count: usize,
    absent_slot_count: usize,
    slots: &[ResidentSlotMeasure],
    context: &str,
) -> CliResult {
    let contracts = &endpoint.slot_contracts;
    if measured_slot_count == 0
        || slots.len() != contracts.len()
        || measured_slot_count.checked_add(absent_slot_count) != Some(contracts.len())
    {
        return Err(worker_protocol_error(
            endpoint.bind,
            format!(
                "{context} slot cardinality invalid: measured={measured_slot_count} absent={absent_slot_count} returned={} frozen_contracts={}",
                slots.len(),
                contracts.len()
            ),
        ));
    }
    let mut observed_measured = 0usize;
    let mut observed_absent = 0usize;
    let mut measured_gpu = 0usize;
    for (slot, contract) in slots.iter().zip(contracts) {
        if slot.slot != contract.slot
            || slot.key != contract.key
            || slot.lens_id != contract.lens_id
            || slot.modality != contract.modality
            || slot.placement != contract.placement
        {
            return Err(worker_protocol_error(
                endpoint.bind,
                format!(
                    "{context} slot contract mismatch at frozen slot {}: returned slot={} key={:?} lens={} modality={:?} placement={:?}; expected key={:?} lens={} modality={:?} placement={:?} state={:?} registered={} retrieval_only={} excluded_from_dedup={}",
                    contract.slot,
                    slot.slot,
                    slot.key,
                    slot.lens_id,
                    slot.modality,
                    slot.placement,
                    contract.key,
                    contract.lens_id,
                    contract.modality,
                    contract.placement,
                    contract.state,
                    contract.registered,
                    contract.retrieval_only,
                    contract.excluded_from_dedup
                ),
            ));
        }
        let expected_absence = if contract.state != SlotState::Active {
            Some(AbsentReason::LensInactive)
        } else if contract.modality != modality {
            Some(AbsentReason::NotApplicable)
        } else if !contract.registered {
            Some(AbsentReason::LensUnavailable)
        } else {
            None
        };
        match expected_absence {
            None if slot.measured && slot.vector.is_some() && slot.absent_reason.is_none() => {
                let vector = slot.vector.as_ref().expect("checked measured vector");
                validate_worker_vector(endpoint.bind, contract, vector, context)?;
                observed_measured += 1;
                if contract.placement == Placement::Gpu {
                    measured_gpu += 1;
                }
            }
            Some(expected)
                if !slot.measured
                    && slot.vector.is_none()
                    && slot.absent_reason.as_ref() == Some(&expected) =>
            {
                observed_absent += 1;
            }
            expected => {
                return Err(worker_protocol_error(
                    endpoint.bind,
                    format!(
                        "{context} slot {} evidence disagrees with frozen state: measured={} vector={} absent_reason={:?}; expected_absence={expected:?} state={:?} registered={} request_modality={modality:?}",
                        slot.slot,
                        slot.measured,
                        slot.vector.is_some(),
                        slot.absent_reason,
                        contract.state,
                        contract.registered
                    ),
                ));
            }
        }
    }
    if observed_measured != measured_slot_count
        || observed_absent != absent_slot_count
        || measured_gpu == 0
    {
        return Err(worker_protocol_error(
            endpoint.bind,
            format!(
                "{context} slot evidence mismatch: declared measured={measured_slot_count} absent={absent_slot_count}; observed measured={observed_measured} absent={observed_absent} measured_gpu={measured_gpu}"
            ),
        ));
    }
    Ok(())
}

fn validate_worker_vector(
    bind: SocketAddr,
    contract: &ResidentSlotContract,
    vector: &SlotVector,
    context: &str,
) -> CliResult {
    vector.validate_schema().map_err(|error| {
        worker_protocol_error(
            bind,
            format!(
                "{context} slot {} vector violates the Calyx vector schema: {}: {}",
                contract.slot, error.code, error.message
            ),
        )
    })?;
    let matches_shape = match (contract.shape, vector) {
        (SlotShape::Dense(expected), SlotVector::Dense { dim, .. }) => expected == *dim,
        (SlotShape::Sparse(expected), SlotVector::Sparse { dim, .. }) => expected == *dim,
        (
            SlotShape::Multi {
                token_dim: expected,
            },
            SlotVector::Multi { token_dim, .. },
        ) => expected == *token_dim,
        _ => false,
    };
    if !matches_shape {
        let observed_shape = match vector {
            SlotVector::Dense { dim, .. } => format!("dense({dim})"),
            SlotVector::Sparse { dim, .. } => format!("sparse({dim})"),
            SlotVector::Multi { token_dim, .. } => format!("multi({token_dim})"),
            SlotVector::Absent { .. } => "absent".to_string(),
        };
        return Err(worker_protocol_error(
            bind,
            format!(
                "{context} slot {} vector shape {observed_shape} does not match frozen shape {:?}",
                contract.slot, contract.shape
            ),
        ));
    }
    Ok(())
}

fn proxy_binary(
    endpoint: &WorkerEndpoint,
    request: &ResidentMeasureBatchBinaryRequest,
    client: &mut TcpStream,
    deadline: Instant,
    lease: &mut ProductiveLease,
) -> Result<(), BinaryProxyError> {
    let bind = endpoint.bind;
    let mut worker = connect_before(&bind, deadline)
        .map_err(|error| {
            worker_error(
                format!("connect loaded resident worker {bind}: {error}"),
                "inspect the recorded worker PID and generation logs",
            )
        })
        .map_err(BinaryProxyError::Worker)?;
    let mut worker_io = DeadlineStream::new(&mut worker, deadline);
    let mut client_io = DeadlineStream::new(client, deadline);
    write_worker_auth_line(&mut worker_io, &endpoint.auth_secret)
        .map_err(BinaryProxyError::Worker)?;
    worker_io
        .write_all(RESIDENT_BINARY_MAGIC)
        .map_err(|error| {
            BinaryProxyError::Worker(worker_transport_error(bind, "send binary magic", error))
        })?;
    let mut worker_request = request.clone();
    worker_request.supervisor_request_id = Some(lease.request_id.clone());
    worker_request.supervisor_generation = Some(endpoint.generation);
    let worker_payload = encode_binary(&worker_request)
        .map_err(CliError::from)
        .map_err(BinaryProxyError::Worker)?;
    write_frame(&mut worker_io, &worker_payload)
        .map_err(CliError::from)
        .map_err(BinaryProxyError::Worker)?;
    worker_io.flush().map_err(|error| {
        BinaryProxyError::Worker(worker_transport_error(bind, "flush binary request", error))
    })?;
    lease
        .advance(RequestStage::WorkerRequestFlushed)
        .map_err(BinaryProxyError::Worker)?;
    let mut saw_header = false;
    let mut row_count = 0usize;
    loop {
        let frame = read_frame(&mut worker_io)
            .map_err(CliError::from)
            .map_err(BinaryProxyError::Worker)?;
        let decoded = decode_binary::<ResidentMeasureBatchStreamFrame>(&frame)
            .map_err(CliError::from)
            .map_err(BinaryProxyError::Worker)?;
        match &decoded {
            ResidentMeasureBatchStreamFrame::Header(header) => {
                if saw_header || row_count != 0 {
                    return Err(BinaryProxyError::Worker(worker_protocol_error(
                        bind,
                        "binary stream repeated its header or emitted it after rows",
                    )));
                }
                validate_binary_header(endpoint, request, header)
                    .map_err(BinaryProxyError::Worker)?;
                saw_header = true;
            }
            ResidentMeasureBatchStreamFrame::Row(row) => {
                if !saw_header || row_count >= request.inputs.len() {
                    return Err(BinaryProxyError::Worker(worker_protocol_error(
                        bind,
                        "binary stream emitted a row before its header or beyond requested cardinality",
                    )));
                }
                validate_worker_row(
                    endpoint,
                    request.modality,
                    row,
                    row_count,
                    request.inputs[row_count].len(),
                    "binary measure_batch",
                )
                .map_err(BinaryProxyError::Worker)?;
                row_count += 1;
            }
            ResidentMeasureBatchStreamFrame::End(_) => {
                let ResidentMeasureBatchStreamFrame::End(end) = &decoded else {
                    unreachable!()
                };
                if !saw_header
                    || row_count != request.inputs.len()
                    || end.row_count != request.inputs.len()
                {
                    return Err(BinaryProxyError::Worker(worker_protocol_error(
                        bind,
                        format!(
                            "binary stream ended without complete evidence: header={saw_header} rows={row_count} end_rows={} requested={}",
                            end.row_count,
                            request.inputs.len()
                        ),
                    )));
                }
                validate_completion(endpoint, &lease.request_id, &end.completion)
                    .map_err(BinaryProxyError::Worker)?;
                lease
                    .advance(RequestStage::GpuSynchronized)
                    .map_err(BinaryProxyError::Worker)?;
                lease
                    .advance(RequestStage::HostMaterialized)
                    .map_err(BinaryProxyError::Worker)?;
                lease
                    .advance(RequestStage::TerminalReceived)
                    .map_err(BinaryProxyError::Worker)?;
            }
            ResidentMeasureBatchStreamFrame::Err {
                code,
                message,
                remediation,
            } => {
                let failure = validate_binary_worker_error(bind, code, message, remediation)
                    .map_err(BinaryProxyError::Worker)?;
                lease
                    .advance(RequestStage::TerminalReceived)
                    .map_err(BinaryProxyError::Worker)?;
                return Err(BinaryProxyError::WorkerReported { failure, frame });
            }
        }
        write_frame(&mut client_io, &frame)
            .map_err(CliError::from)
            .map_err(BinaryProxyError::Client)?;
        if matches!(&decoded, ResidentMeasureBatchStreamFrame::End(_)) {
            client_io
                .flush()
                .map_err(|error| BinaryProxyError::Client(error.into()))?;
            return Ok(());
        }
    }
}

fn validate_binary_worker_error(
    bind: SocketAddr,
    code: &str,
    message: &str,
    remediation: &str,
) -> CliResult<WorkerReportedFailure> {
    for (name, value) in [
        ("code", code),
        ("message", message),
        ("remediation", remediation),
    ] {
        if value.trim().is_empty() {
            return Err(worker_protocol_error(
                bind,
                format!("returned a binary Err frame with blank {name}"),
            ));
        }
    }
    Ok(reported_worker_error(bind, code, message, remediation))
}

fn validate_completion(
    endpoint: &WorkerEndpoint,
    request_id: &str,
    completion: &ResidentCompletionAttestation,
) -> CliResult {
    if completion.schema != COMPLETION_SCHEMA
        || completion.request_id != request_id
        || completion.generation != endpoint.generation
        || !completion.gpu_synchronized
        || !completion.host_materialized
    {
        return Err(worker_protocol_error(
            endpoint.bind,
            format!(
                "completion attestation mismatch: schema={:?} request_id={:?} generation={} gpu_synchronized={} host_materialized={}; expected schema={:?} request_id={request_id:?} generation={}",
                completion.schema,
                completion.request_id,
                completion.generation,
                completion.gpu_synchronized,
                completion.host_materialized,
                COMPLETION_SCHEMA,
                endpoint.generation
            ),
        ));
    }
    Ok(())
}

fn validate_binary_header(
    endpoint: &WorkerEndpoint,
    request: &ResidentMeasureBatchBinaryRequest,
    header: &ResidentMeasureBatchStreamHeader,
) -> CliResult {
    if header.protocol_version != RESIDENT_BINARY_PROTOCOL_VERSION
        || header.schema != MEASURE_BATCH_SCHEMA
        || !header.ready
        || header.process_id != endpoint.process_id
        || header.template_source != endpoint.template_source
        || header.modality != request.modality
        || header.input_count != request.inputs.len()
        || header.runtime_batch_limit != request.runtime_batch_limit
    {
        return Err(worker_protocol_error(
            endpoint.bind,
            format!(
                "binary header mismatch: protocol={} schema={:?} ready={} pid={} template={:?} modality={:?} input_count={} batch_limit={:?}; expected protocol={} schema={:?} pid={} template={:?} modality={:?} input_count={} batch_limit={:?}",
                header.protocol_version,
                header.schema,
                header.ready,
                header.process_id,
                header.template_source,
                header.modality,
                header.input_count,
                header.runtime_batch_limit,
                RESIDENT_BINARY_PROTOCOL_VERSION,
                MEASURE_BATCH_SCHEMA,
                endpoint.process_id,
                endpoint.template_source,
                request.modality,
                request.inputs.len(),
                request.runtime_batch_limit
            ),
        ));
    }
    Ok(())
}

enum BinaryProxyError {
    Worker(CliError),
    WorkerReported {
        failure: WorkerReportedFailure,
        frame: Vec<u8>,
    },
    Client(CliError),
}

fn write_binary_error(stream: &mut TcpStream, error: &CliError) -> CliResult {
    let deadline = deadline_after(PUBLIC_SOCKET_TIMEOUT)?;
    write_binary_error_before(stream, error, deadline)
}

fn write_binary_error_before(
    stream: &mut TcpStream,
    error: &CliError,
    deadline: Instant,
) -> CliResult {
    let mut stream = DeadlineStream::new(stream, deadline);
    write_stream_frame(
        &mut stream,
        &ResidentMeasureBatchStreamFrame::Err {
            code: error.code().to_string(),
            message: error.message().to_string(),
            remediation: error.remediation().to_string(),
        },
    )?;
    stream.flush()?;
    Ok(())
}

fn write_binary_frame_before(stream: &mut TcpStream, frame: &[u8], deadline: Instant) -> CliResult {
    let mut stream = DeadlineStream::new(stream, deadline);
    write_frame(&mut stream, frame)?;
    stream.flush()?;
    Ok(())
}

fn write_json_response(stream: &mut TcpStream, value: &Value) -> CliResult {
    let deadline = deadline_after(PUBLIC_SOCKET_TIMEOUT)?;
    write_json_response_before(stream, value, deadline)
}

fn write_json_response_before(
    stream: &mut TcpStream,
    value: &Value,
    deadline: Instant,
) -> CliResult {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| CliError::runtime(format!("serialize resident response: {error}")))?;
    write_json_bytes_before(stream, &bytes, deadline)
}

fn write_json_bytes_before(stream: &mut TcpStream, bytes: &[u8], deadline: Instant) -> CliResult {
    {
        let mut stream = DeadlineStream::new(stream, deadline);
        stream.write_all(bytes)?;
        if !bytes.ends_with(b"\n") {
            stream.write_all(b"\n")?;
        }
        stream.flush()?;
    }
    let _ = stream.shutdown(Shutdown::Both);
    Ok(())
}

fn clone_cli_error(error: &CliError) -> CliError {
    CliError::from(CalyxError {
        code: error.code(),
        message: error.message().to_string(),
        remediation: error.remediation(),
    })
}

fn prior_fault_cli_error(error: &LifecycleErrorRecord) -> CliError {
    CliError::from(CalyxError {
        code: "CALYX_PANEL_RESIDENT_SHUTDOWN_PRIOR_FAULT",
        message: format!(
            "resident supervisor cannot report a clean shutdown because its exact prior fault was {}: {}; remediation={}",
            error.code, error.message, error.remediation
        ),
        remediation: "resolve the exact prior lifecycle fault recorded in the snapshot before restarting resident GPU work",
    })
}

fn combine_terminal_errors(primary: Option<CliError>, persistence: CliError) -> CliError {
    let Some(primary) = primary else {
        return persistence;
    };
    CliError::from(CalyxError {
        code: "CALYX_PANEL_RESIDENT_SHUTDOWN_PERSIST_FAILED",
        message: format!(
            "resident shutdown fault and its terminal persistence both failed: primary_code={} primary_message={}; persistence_code={} persistence_message={}",
            primary.code(),
            primary.message(),
            persistence.code(),
            persistence.message()
        ),
        remediation: "preserve the lifecycle journal, snapshot, worker PID evidence, and process logs; repair durable storage and prove every recorded worker absent before restart",
    })
}

fn combine_runtime_errors(
    context: &'static str,
    primary: CliError,
    secondary: CliError,
) -> CliError {
    CliError::from(CalyxError {
        code: "CALYX_PANEL_RESIDENT_MULTIPLE_FAILURES",
        message: format!(
            "{context}: primary_code={} primary_message={}; secondary_code={} secondary_message={}",
            primary.code(),
            primary.message(),
            secondary.code(),
            secondary.message()
        ),
        remediation: "preserve the lifecycle source of truth and process logs; resolve every named failure before restarting resident GPU work",
    })
}

fn merge_optional_errors(
    context: &'static str,
    primary: Option<CliError>,
    secondary: Option<CliError>,
) -> Option<CliError> {
    match (primary, secondary) {
        (Some(primary), Some(secondary)) => {
            Some(combine_runtime_errors(context, primary, secondary))
        }
        (Some(error), None) | (None, Some(error)) => Some(error),
        (None, None) => None,
    }
}

fn merge_error(context: &'static str, primary: CliError, secondary: Option<CliError>) -> CliError {
    match secondary {
        Some(secondary) => combine_runtime_errors(context, primary, secondary),
        None => primary,
    }
}

fn worker_error(message: impl Into<String>, remediation: &'static str) -> CliError {
    CliError::from(CalyxError {
        code: WORKER_LOST,
        message: message.into(),
        remediation,
    })
}

fn worker_protocol_error(bind: SocketAddr, detail: impl std::fmt::Display) -> CliError {
    CliError::from(CalyxError {
        code: WORKER_PROTOCOL_INVALID,
        message: format!("loaded resident worker {bind} violated the resident protocol: {detail}"),
        remediation: "preserve the exact worker response and lifecycle journal, then restart the supervisor and worker from the same native Calyx build",
    })
}

fn reported_worker_error(
    bind: SocketAddr,
    code: &str,
    message: &str,
    remediation: &str,
) -> WorkerReportedFailure {
    WorkerReportedFailure {
        supervisor_error: CliError::from(CalyxError {
            code: WORKER_REPORTED_ERROR,
            message: format!(
                "loaded resident worker {bind} reported {code}: {message}; remediation={remediation}"
            ),
            remediation: "fix the reported model or CUDA failure, then retry on the clean generation reaped by the supervisor",
        }),
        lifecycle_error: LifecycleErrorRecord {
            code: code.to_string(),
            message: message.to_string(),
            remediation: remediation.to_string(),
            at_unix_ms: unix_now_ms(),
        },
    }
}

fn client_aborted_error(generation: u64, error: &CliError, operation: &str) -> CliError {
    CliError::from(CalyxError {
        code: CLIENT_ABORTED_GENERATION,
        message: format!(
            "public client transport failed during resident generation {generation} {operation}: {}",
            error.message()
        ),
        remediation: "retry the complete atomic request; the supervisor reaped the interrupted generation before releasing its lease",
    })
}

fn worker_transport_error(bind: SocketAddr, operation: &str, error: std::io::Error) -> CliError {
    worker_error(
        format!("{operation} to loaded resident worker {bind} failed: {error}"),
        "inspect the recorded worker PID and generation logs, then retry on a clean generation",
    )
}

fn stopping_error() -> CliError {
    CliError::from(CalyxError {
        code: STOPPING,
        message: "resident supervisor is stopping and refuses new productive work".to_string(),
        remediation: "wait for the recorded supervisor PID to stop, then start a new resident supervisor",
    })
}
