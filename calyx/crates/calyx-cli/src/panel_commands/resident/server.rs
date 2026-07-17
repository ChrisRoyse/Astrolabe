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
    listener.set_nonblocking(true)?;
    let running = Arc::new(AtomicBool::new(true));
    let expected_auth_line = worker_auth_line(&service.worker_auth_secret)?;
    let handler_limit = std::thread::available_parallelism()
        .map_err(|error| CliError::runtime(format!("measure resident worker capacity: {error}")))?
        .get()
        .saturating_add(1);
    let mut handlers = Vec::new();
    let mut accept_error = None;
    while running.load(Ordering::SeqCst) {
        if let Err(error) = reap_worker_handlers(&mut handlers) {
            accept_error = Some(error);
            running.store(false, Ordering::SeqCst);
            break;
        }
        match listener.accept() {
            Ok((mut stream, peer)) => {
                if !peer.ip().is_loopback() {
                    let _ = stream.shutdown(Shutdown::Both);
                    continue;
                }
                if let Err(error) = authenticate_worker_connection(&mut stream, &expected_auth_line)
                {
                    eprintln!(
                        "CALYX_PANEL_RESIDENT_RUNTIME phase=worker_authentication_error code={} message={} remediation={}",
                        error.code(),
                        error.message(),
                        error.remediation()
                    );
                    continue;
                }
                if let Err(error) = reap_worker_handlers(&mut handlers) {
                    let _ = stream.shutdown(Shutdown::Both);
                    accept_error = Some(error);
                    running.store(false, Ordering::SeqCst);
                    break;
                }
                if handlers.len() >= handler_limit {
                    if let Err(error) =
                        reject_worker_back_pressure(stream, service.max_request_secs)
                    {
                        eprintln!(
                            "CALYX_PANEL_RESIDENT_RUNTIME phase=worker_back_pressure_response_error code={} message={} remediation={}",
                            error.code(),
                            error.message(),
                            error.remediation()
                        );
                    }
                    continue;
                }
                let service = Arc::clone(&service);
                let running = Arc::clone(&running);
                handlers.push(std::thread::spawn(move || {
                    if let Err(error) = handle_client(stream, service, running) {
                        eprintln!(
                            "CALYX_PANEL_RESIDENT_RUNTIME phase=worker_client_error code={} message={} remediation={}",
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
                running.store(false, Ordering::SeqCst);
                break;
            }
        }
    }
    let joined = join_worker_handlers(handlers);
    match accept_error {
        Some(error) => {
            joined?;
            Err(error)
        }
        None => joined,
    }
}

fn reap_worker_handlers(handlers: &mut Vec<std::thread::JoinHandle<()>>) -> CliResult {
    let mut index = 0;
    while index < handlers.len() {
        if handlers[index].is_finished() {
            join_worker_handler(handlers.swap_remove(index))?;
        } else {
            index += 1;
        }
    }
    Ok(())
}

fn join_worker_handlers(handlers: Vec<std::thread::JoinHandle<()>>) -> CliResult {
    let mut first_error = None;
    for handler in handlers {
        if let Err(error) = join_worker_handler(handler)
            && first_error.is_none()
        {
            first_error = Some(error);
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn join_worker_handler(handler: std::thread::JoinHandle<()>) -> CliResult {
    handler.join().map_err(|_| {
        CliError::runtime("resident private worker handler panicked before its socket was released")
    })
}

fn handle_client(
    mut stream: TcpStream,
    service: Arc<ResidentService>,
    running: Arc<AtomicBool>,
) -> CliResult {
    let request_deadline = deadline_after(Duration::from_secs(service.max_request_secs))?;
    let mut ingress = stream.try_clone()?;
    let mut reader = BufReader::new(DeadlineStream::new(&mut ingress, request_deadline));

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

fn authenticate_worker_connection(stream: &mut TcpStream, expected: &[u8]) -> CliResult {
    let deadline = deadline_after(WORKER_AUTH_IO_TIMEOUT)?;
    let observed = match read_worker_auth_line(stream, deadline) {
        Ok(line) => line,
        Err(error) => {
            return reject_worker_connection(
                stream,
                format!("read resident worker authentication preamble: {error}"),
                deadline_after(WORKER_AUTH_IO_TIMEOUT)?,
            );
        }
    };
    if constant_time_eq(&observed, expected) {
        return Ok(());
    }
    reject_worker_connection(
        stream,
        "resident worker rejected a connection without its exact generation credential",
        deadline_after(WORKER_AUTH_IO_TIMEOUT)?,
    )
}

fn read_worker_auth_line(stream: &mut TcpStream, deadline: Instant) -> CliResult<Vec<u8>> {
    let mut stream = DeadlineStream::new(stream, deadline);
    let mut line = Vec::with_capacity(MAX_WORKER_AUTH_LINE_BYTES);
    loop {
        if line.len() >= MAX_WORKER_AUTH_LINE_BYTES {
            return Err(CliError::from(CalyxError {
                code: WORKER_UNAUTHORIZED,
                message: "resident worker authentication line exceeded its exact bound".to_string(),
                remediation: "connect through the public resident supervisor; direct worker access is forbidden",
            }));
        }
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte)?;
        line.push(byte[0]);
        if byte[0] == b'\n' {
            return Ok(line);
        }
    }
}

fn reject_worker_back_pressure(mut stream: TcpStream, max_request_secs: u64) -> CliResult {
    let deadline = deadline_after(Duration::from_secs(max_request_secs))?;
    let mut ingress = stream.try_clone()?;
    let mut reader = BufReader::new(DeadlineStream::new(&mut ingress, deadline));
    let first_line = read_bounded_line(
        &mut reader,
        MAX_RESIDENT_JSON_LINE_BYTES,
        "resident worker back-pressure request preamble",
    )?;
    let error = CliError::from(CalyxError {
        code: PRIVATE_WORKER_BACK_PRESSURE,
        message: "resident private worker reached its authenticated handler capacity".to_string(),
        remediation: "retry the same request within its existing absolute supervisor deadline; the loaded generation remains healthy",
    });
    if first_line == RESIDENT_BINARY_MAGIC {
        let response = (|| -> CliResult {
            let mut output = DeadlineStream::new(&mut stream, deadline);
            super::stream::write_stream_frame(
                &mut output,
                &ResidentMeasureBatchStreamFrame::Err {
                    code: error.code().to_string(),
                    message: error.message().to_string(),
                    remediation: error.remediation().to_string(),
                },
            )?;
            output.flush().map_err(CliError::from)
        })();
        let _ = stream.shutdown(Shutdown::Write);
        let drained = super::codec::discard_frame(&mut reader).map_err(CliError::from);
        let _ = stream.shutdown(Shutdown::Both);
        response?;
        drained
    } else {
        write_json_response(&mut stream, &cli_error_value(&error), deadline)
    }
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
