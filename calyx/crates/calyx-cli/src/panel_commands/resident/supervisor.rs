use std::io::{BufReader, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use calyx_core::CalyxError;
use ulid::Ulid;

use super::codec::{decode_binary, read_frame, write_frame};
use super::deadline::{
    DeadlineStream, connect_before, deadline_after, ensure_before, read_bounded_line,
};
use super::discovery::{
    RESIDENT_DISCOVERY_SCHEMA, ResidentDiscovery, remove_resident_discovery, unix_now_ms,
    write_resident_discovery,
};
use super::dispatch::{RequestClass, validate_request};
use super::lifecycle::{
    LifecycleErrorRecord, LifecyclePhase, LifecycleProjection, LifecycleRequestRecord,
    LifecycleState, LifecycleStore, RequestOutcome, RequestStage,
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
        self.fail_inner(error, outcome)
    }

    fn fail_inner(&self, error: &CliError, outcome: RequestOutcome) -> CliResult {
        let invalidation_error = self
            .supervisor
            .invalidate_generation(self.endpoint.generation, clone_cli_error(error))
            .err();
        let release_error = self
            .supervisor
            .release_failed(self.endpoint.generation, &self.request_id, outcome, error)
            .err();
        match invalidation_error.or(release_error) {
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
        if let Err(cleanup_error) = self.fail_inner(&error, RequestOutcome::Abandoned) {
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
            | (RequestStage::WorkerStarted, RequestStage::GpuSynchronized)
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
    served?;
    stopped?;
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
        let previous = store.last().map(LifecycleProjection::state);
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
        {
            let mut inner = self.lock()?;
            if !self.accepting.load(Ordering::SeqCst) {
                return Err(stopping_error());
            }
            inner.state.queued_requests =
                inner.state.queued_requests.checked_add(1).ok_or_else(|| {
                    CliError::runtime("resident queued request counter overflowed")
                })?;
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
                self.changed.notify_all();
                return Err(error);
            }
            self.changed.notify_all();
        }

        let acquired = self.acquire_queued(&request_id);
        match acquired {
            Ok(endpoint) => Ok(ProductiveLease {
                supervisor: Arc::clone(self),
                endpoint,
                request_id,
                stage: RequestStage::Queued,
                completed: false,
            }),
            Err(error) => {
                let cleanup_error = self.cancel_queued_request(&request_id, &error).err();
                Err(cleanup_error.unwrap_or(error))
            }
        }
    }

    fn acquire_queued(self: &Arc<Self>, request_id: &str) -> CliResult<WorkerEndpoint> {
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
                return Err(cleanup_error.unwrap_or(lock_error));
            }
        };
        if inner.worker_transition != Some(WorkerTransition::Loading(generation))
            || inner.state.generation != generation
        {
            self.changed.notify_all();
            return Err(cleanup_error.unwrap_or(error));
        }
        inner.worker_transition = None;
        inner.worker = None;
        inner.state.worker_pid = None;
        inner.state.worker_descendant_pids.clear();
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
                return Err(CliError::runtime("resident load failure counter exhausted"));
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
                return Err(reap_error);
            }
        }
        self.changed.notify_all();
        Err(persist_error.or(cleanup_error).unwrap_or(error))
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
                inner.state.worker_pid = None;
                inner.state.worker_descendant_pids.clear();
                inner.state.idle_deadline_unix_ms = None;
                inner.idle_deadline = None;
                inner.state.phase = LifecyclePhase::Faulted;
                inner.state.last_error = Some(LifecycleErrorRecord::from_cli_error(
                    cleanup_error.as_ref().unwrap_or(&error),
                ));
            }
        }
        self.changed.notify_all();
        Err(cleanup_error.unwrap_or(error))
    }

    fn cancel_queued_request(&self, request_id: &str, error: &CliError) -> CliResult {
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
                outcome: Some(RequestOutcome::Failed),
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
                inner.state.phase = if self.accepting.load(Ordering::SeqCst) {
                    LifecyclePhase::Unloaded
                } else {
                    LifecyclePhase::Stopping
                };
                inner.state.worker_pid = None;
                inner.state.worker_descendant_pids.clear();
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
                error: Some(LifecycleErrorRecord::from_cli_error(error)),
            },
        );
        self.changed.notify_all();
        persisted
    }

    fn invalidate_generation(&self, generation: u64, error: CliError) -> CliResult {
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
            inner.state.last_error = Some(LifecycleErrorRecord::from_cli_error(&error));
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
        inner.state.worker_pid = None;
        inner.state.worker_descendant_pids.clear();
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
        let reaped_persist_error = if fault_persist_error.is_none() {
            self.persist(&mut inner, "worker_reaped").err()
        } else {
            None
        };
        self.changed.notify_all();
        match fault_persist_error
            .or(cleanup_error)
            .or(counter_error)
            .or(reaped_persist_error)
        {
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
        if inner.worker_transition.is_none() {
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
                Some(CliError::runtime(
                    inner
                        .state
                        .last_error
                        .as_ref()
                        .map_or_else(
                            || "resident supervisor entered shutdown in a faulted state".to_string(),
                            |error| {
                                format!(
                                    "resident supervisor entered shutdown faulted: {}: {}; remediation={}",
                                    error.code, error.message, error.remediation
                                )
                            },
                        ),
                ))
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
        inner.state.worker_pid = None;
        inner.state.worker_descendant_pids.clear();
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
        let mut terminal_error = request_error
            .or(prior_fault)
            .or(unload_started_error)
            .or(cleanup_error)
            .or(counter_error);
        if let Some(error) = &terminal_error {
            inner.state.phase = LifecyclePhase::Faulted;
            inner.state.last_error = Some(LifecycleErrorRecord::from_cli_error(error));
            let _ = self.persist(&mut inner, "shutdown_worker_failed");
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
                Err(_) => return,
            };
            if inner.worker_transition == Some(WorkerTransition::Unloading(generation)) {
                inner.worker_transition = None;
            }
            inner.state.worker_pid = None;
            inner.state.worker_descendant_pids.clear();
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
            let unload_error = started_persist_error.or(cleanup_error).or(counter_error);
            if let Some(error) = &unload_error {
                inner.state.phase = LifecyclePhase::Faulted;
                inner.state.last_error = Some(LifecycleErrorRecord::from_cli_error(error));
                self.accepting.store(false, Ordering::SeqCst);
                let _ = self.persist(&mut inner, "idle_unload_failed");
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
            let _ = supervisor.request_stop();
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
                let _ = supervisor.request_stop();
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
    let class = match validate_request(&request) {
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
                Ok(JsonProxyResponse::WorkerFailure { response, error }) => {
                    let cleanup = lease.fail(&error, RequestOutcome::Failed);
                    let write = deadline_after(PUBLIC_SOCKET_TIMEOUT)
                        .map_err(CliError::from)
                        .and_then(|deadline| {
                            write_json_bytes_before(&mut stream, &response, deadline)
                        });
                    write?;
                    cleanup?;
                    return Ok(());
                }
                Err(error) => {
                    let cleanup = lease.fail(&error, RequestOutcome::Failed);
                    let value = cli_error_value(cleanup.as_ref().err().unwrap_or(&error));
                    let write = deadline_after(PUBLIC_SOCKET_TIMEOUT)
                        .map_err(CliError::from)
                        .and_then(|deadline| {
                            write_json_response_before(&mut stream, &value, deadline)
                        });
                    write?;
                    cleanup?;
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
    match proxy_binary(&endpoint, &payload, stream, request_deadline, &mut lease) {
        Ok(()) => {
            lease.advance(RequestStage::PublicFlushComplete)?;
            lease.complete_success()
        }
        Err(BinaryProxyError::Worker(error)) => {
            let cleanup = lease.fail(&error, RequestOutcome::Failed);
            let response_error = cleanup.as_ref().err().unwrap_or(&error);
            if let Ok(error_deadline) = deadline_after(PUBLIC_SOCKET_TIMEOUT) {
                let _ = write_binary_error_before(stream, response_error, error_deadline);
            }
            cleanup?;
            Err(error)
        }
        Err(BinaryProxyError::WorkerReported(error)) => {
            let cleanup = lease.fail(&error, RequestOutcome::Failed);
            cleanup?;
            Err(error)
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
    serde_json::to_writer(&mut worker_io, request)
        .map_err(|error| CliError::runtime(format!("serialize worker request: {error}")))?;
    worker_io.write_all(b"\n")?;
    worker_io.flush()?;
    lease.advance(RequestStage::WorkerStarted)?;
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
    if value.get("ok").and_then(Value::as_bool) == Some(false) {
        lease.advance(RequestStage::TerminalReceived)?;
        return Ok(JsonProxyResponse::WorkerFailure {
            error: worker_reported_json_error(endpoint.bind, &value),
            response,
        });
    }
    lease.advance(RequestStage::GpuSynchronized)?;
    lease.advance(RequestStage::HostMaterialized)?;
    lease.advance(RequestStage::TerminalReceived)?;
    Ok(JsonProxyResponse::Success(response))
}

enum JsonProxyResponse {
    Success(Vec<u8>),
    WorkerFailure { response: Vec<u8>, error: CliError },
}

fn worker_reported_json_error(bind: SocketAddr, value: &Value) -> CliError {
    let code = value
        .get("code")
        .and_then(Value::as_str)
        .unwrap_or("CALYX_PANEL_RESIDENT_WORKER_MALFORMED_ERROR");
    let message = value
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("worker returned ok=false without a string message");
    let remediation = value
        .get("remediation")
        .and_then(Value::as_str)
        .unwrap_or("preserve the worker response and inspect its structured error envelope");
    worker_error(
        format!(
            "loaded resident worker {bind} reported {code}: {message}; remediation={remediation}"
        ),
        "fix the reported model or CUDA failure, then retry on the clean generation reaped by the supervisor",
    )
}

fn proxy_binary(
    endpoint: &WorkerEndpoint,
    payload: &[u8],
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
    write_frame(&mut worker_io, payload)
        .map_err(CliError::from)
        .map_err(BinaryProxyError::Worker)?;
    worker_io.flush().map_err(|error| {
        BinaryProxyError::Worker(worker_transport_error(bind, "flush binary request", error))
    })?;
    lease
        .advance(RequestStage::WorkerStarted)
        .map_err(BinaryProxyError::Worker)?;
    loop {
        let frame = read_frame(&mut worker_io)
            .map_err(CliError::from)
            .map_err(BinaryProxyError::Worker)?;
        let decoded = decode_binary::<ResidentMeasureBatchStreamFrame>(&frame)
            .map_err(CliError::from)
            .map_err(BinaryProxyError::Worker)?;
        match &decoded {
            ResidentMeasureBatchStreamFrame::End(_) => {
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
            ResidentMeasureBatchStreamFrame::Err { .. } => {
                lease
                    .advance(RequestStage::TerminalReceived)
                    .map_err(BinaryProxyError::Worker)?;
            }
            ResidentMeasureBatchStreamFrame::Header(_)
            | ResidentMeasureBatchStreamFrame::Row(_) => {}
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
        if let ResidentMeasureBatchStreamFrame::Err {
            code,
            message,
            remediation,
        } = decoded
        {
            client_io
                .flush()
                .map_err(|error| BinaryProxyError::Client(error.into()))?;
            return Err(BinaryProxyError::WorkerReported(worker_error(
                format!(
                    "loaded resident worker {bind} reported {code}: {message}; remediation={remediation}"
                ),
                "fix the reported model or CUDA failure, then retry on the clean generation reaped by the supervisor",
            )));
        }
    }
}

enum BinaryProxyError {
    Worker(CliError),
    WorkerReported(CliError),
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

fn worker_error(message: impl Into<String>, remediation: &'static str) -> CliError {
    CliError::from(CalyxError {
        code: WORKER_LOST,
        message: message.into(),
        remediation,
    })
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
