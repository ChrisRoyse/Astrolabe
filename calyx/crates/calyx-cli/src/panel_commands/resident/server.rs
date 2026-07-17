use super::deadline::{DeadlineStream, deadline_after, ensure_before, read_bounded_line};
use super::dispatch::{dispatch_request, readiness};
use super::source::freeze_source;
use super::stream::serve_binary_measure_batch;
use super::*;

const WORKER_AUTH_IO_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_WORKER_AUTH_LINE_BYTES: usize = 128;
const WORKER_UNAUTHORIZED: &str = "CALYX_PANEL_RESIDENT_WORKER_UNAUTHORIZED";

pub(crate) struct ResidentService {
    pub(crate) state: ResidentWarmState,
    pub(crate) bind: SocketAddr,
    pub(crate) started: Instant,
    pub(crate) supervisor_pid: u32,
    pub(crate) generation: u64,
    pub(crate) frozen_panel_fingerprint: String,
    pub(crate) max_request_secs: u64,
    worker_auth_secret: String,
}

pub(crate) fn serve(args: &[String]) -> CliResult {
    #[cfg(windows)]
    {
        return super::supervisor::serve(args);
    }
    #[cfg(not(windows))]
    Err(CliError::runtime(
        "panel resident supervisor is currently supported on native Windows only",
    ))
}

#[cfg(windows)]
pub(crate) fn serve_worker(args: &[String]) -> CliResult {
    // This is deliberately the first operation. It opens the supervisor's
    // nonce-bound named Job Object and proves exact kernel membership before
    // argument parsing, source reads, runtime construction, or CUDA loading.
    let assignment = super::worker::await_assignment_gate()?;
    let mut flags = parse_serve_flags(args)?;
    let bind = flags.bind.unwrap_or(parse_addr(DEFAULT_BIND)?);
    ensure_loopback(bind)?;
    let home = resolve_home(&mut flags)?;
    if flags.template.is_some() == flags.vault.is_some() {
        return Err(CliError::usage(
            "calyx panel resident serve requires exactly one of --template <name-or-id> or --vault <vault>",
        ));
    }
    let frozen_before_load = freeze_source(&home, &flags)?;
    if frozen_before_load.fingerprint != assignment.frozen_fingerprint {
        return Err(CliError::from(CalyxError::lens_frozen_violation(format!(
            "resident worker source fingerprint {} does not match supervisor fingerprint {}",
            frozen_before_load.fingerprint, assignment.frozen_fingerprint
        ))));
    }
    let flags_for_recheck = flags.clone();
    let max_request_secs = flags.max_request_secs.unwrap_or(DEFAULT_MAX_REQUEST_SECS);
    let listener = TcpListener::bind(bind)?;
    let local_addr = listener.local_addr()?;
    let state = load_resident_warm_state(warm_options(home.clone(), flags))?;
    // Warm loading and probing may take minutes. Re-read the source of truth
    // after all model initialization so a mid-load mutation can never be
    // published as the supervisor's frozen generation.
    let frozen_after_probe = freeze_source(&home, &flags_for_recheck)?;
    if frozen_after_probe.fingerprint != assignment.frozen_fingerprint {
        return Err(CliError::from(CalyxError::lens_frozen_violation(format!(
            "resident worker source changed during warm load: before={} after={} supervisor={}",
            frozen_before_load.fingerprint,
            frozen_after_probe.fingerprint,
            assignment.frozen_fingerprint
        ))));
    }
    let worker_auth_secret = assignment.auth_secret().to_string();
    let service = Arc::new(ResidentService {
        state,
        bind: local_addr,
        started: Instant::now(),
        supervisor_pid: assignment.supervisor_pid,
        generation: assignment.generation,
        frozen_panel_fingerprint: frozen_after_probe.fingerprint,
        max_request_secs,
        worker_auth_secret,
    });
    let ready = readiness(&service);
    if let Some(path) = service.state.ready_out.clone() {
        write_json_file(path, &ready)?;
    }
    print_json(&ready)?;
    serve_loop(listener, service)
}

fn resolve_home(flags: &mut ServeFlags) -> CliResult<PathBuf> {
    resolve_home_with(flags.home.take(), calyx_home)
}

pub(crate) fn resolve_home_with(
    provided: Option<PathBuf>,
    fallback: impl FnOnce() -> CliResult<PathBuf>,
) -> CliResult<PathBuf> {
    match provided {
        Some(home) => Ok(home),
        None => fallback(),
    }
}

fn warm_options(home: PathBuf, flags: ServeFlags) -> ResidentWarmOptions {
    ResidentWarmOptions {
        home,
        template: flags.template,
        vault: flags.vault,
        slots: flags.slots,
        modality: flags.modality,
        ready_out: flags.ready_out,
        max_resident_vram_mib: flags
            .max_resident_vram_mib
            .unwrap_or(DEFAULT_MAX_RESIDENT_VRAM_MIB),
        resident_overhead_multiplier_milli: flags
            .resident_overhead_multiplier_milli
            .unwrap_or(DEFAULT_RESIDENT_OVERHEAD_MULTIPLIER_MILLI),
        max_load_secs: flags.max_load_secs.unwrap_or(DEFAULT_MAX_LOAD_SECS),
        load_parallelism: flags.load_parallelism,
        progress_out: flags.progress_out,
    }
}

fn serve_loop(listener: TcpListener, service: Arc<ResidentService>) -> CliResult {
    let running = Arc::new(AtomicBool::new(true));
    while running.load(Ordering::SeqCst) {
        let (stream, peer) = listener.accept()?;
        if !peer.ip().is_loopback() {
            let _ = stream.shutdown(Shutdown::Both);
            continue;
        }
        if let Err(error) = handle_client(stream, Arc::clone(&service), Arc::clone(&running)) {
            eprintln!(
                "CALYX_PANEL_RESIDENT_RUNTIME phase=worker_client_error code={} message={} remediation={}",
                error.code(),
                error.message(),
                error.remediation()
            );
        }
    }
    Ok(())
}

fn handle_client(
    mut stream: TcpStream,
    service: Arc<ResidentService>,
    running: Arc<AtomicBool>,
) -> CliResult {
    let auth_deadline = deadline_after(WORKER_AUTH_IO_TIMEOUT)?;
    let mut ingress = stream.try_clone()?;
    let mut reader = BufReader::new(DeadlineStream::new(&mut ingress, auth_deadline));
    let auth_line = match read_bounded_line(
        &mut reader,
        MAX_WORKER_AUTH_LINE_BYTES,
        "resident worker authentication line",
    ) {
        Ok(line) => line,
        Err(error) => {
            return reject_worker_connection(
                &mut stream,
                format!("read resident worker authentication preamble: {error}"),
                deadline_after(WORKER_AUTH_IO_TIMEOUT)?,
            );
        }
    };
    let expected_auth_line = worker_auth_line(&service.worker_auth_secret)?;
    if !constant_time_eq(&auth_line, &expected_auth_line) {
        return reject_worker_connection(
            &mut stream,
            "resident worker rejected a connection without its exact generation credential",
            deadline_after(WORKER_AUTH_IO_TIMEOUT)?,
        );
    }
    let request_deadline = deadline_after(Duration::from_secs(service.max_request_secs))?;
    reader.get_mut().set_deadline(request_deadline);

    let first_line = read_bounded_line(
        &mut reader,
        MAX_RESIDENT_JSON_LINE_BYTES,
        "resident worker request preamble",
    )?;
    if first_line == RESIDENT_BINARY_MAGIC {
        {
            let mut response_stream = DeadlineStream::new(&mut stream, request_deadline);
            serve_binary_measure_batch(&mut reader, &mut response_stream, &service)?;
            response_stream.flush()?;
        }
        let _ = stream.shutdown(Shutdown::Both);
        return Ok(());
    }

    let response = match String::from_utf8(first_line) {
        Ok(line) => match serde_json::from_str::<ResidentRequest>(&line) {
            Ok(request) => {
                match ensure_before(request_deadline, "resident worker JSON ingress and decode") {
                    Ok(()) => dispatch_request(request, &service, &running),
                    Err(error) => error_value(
                        "CALYX_PANEL_RESIDENT_BAD_REQUEST",
                        error.to_string(),
                        "send one bounded private request promptly through the public supervisor",
                    ),
                }
            }
            Err(error) => error_value(
                "CALYX_PANEL_RESIDENT_BAD_REQUEST",
                format!("decode resident request JSON line: {error}"),
                "send one JSON object per connection with op=ready, measure, or shutdown",
            ),
        },
        Err(error) => error_value(
            "CALYX_PANEL_RESIDENT_BAD_REQUEST",
            format!("resident request was neither binary magic nor valid UTF-8 JSON: {error}"),
            "send one JSON object per connection or the resident binary magic line",
        ),
    };
    write_json_response(&mut stream, &response, request_deadline)
}

fn worker_auth_line(auth_secret: &str) -> CliResult<Vec<u8>> {
    let mut line = Vec::with_capacity(MAX_WORKER_AUTH_LINE_BYTES);
    super::worker::write_worker_auth_line(&mut line, auth_secret)?;
    Ok(line)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let max_len = left.len().max(right.len());
    let mut difference = left.len() ^ right.len();
    for index in 0..max_len {
        difference |= usize::from(
            left.get(index).copied().unwrap_or(0) ^ right.get(index).copied().unwrap_or(0),
        );
    }
    difference == 0
}

fn reject_worker_connection(
    stream: &mut TcpStream,
    message: impl Into<String>,
    deadline: Instant,
) -> CliResult {
    let error = CliError::from(CalyxError {
        code: WORKER_UNAUTHORIZED,
        message: message.into(),
        remediation: "connect through the public resident supervisor; direct worker access is forbidden",
    });
    let response = cli_error_value(&error);
    write_json_response(stream, &response, deadline)?;
    Err(error)
}

fn write_json_response(stream: &mut TcpStream, response: &Value, deadline: Instant) -> CliResult {
    {
        let mut stream = DeadlineStream::new(stream, deadline);
        serde_json::to_writer(&mut stream, response)
            .map_err(|error| CliError::runtime(format!("write resident response JSON: {error}")))?;
        stream.write_all(b"\n")?;
        stream.flush()?;
    }
    let _ = stream.shutdown(Shutdown::Both);
    Ok(())
}
