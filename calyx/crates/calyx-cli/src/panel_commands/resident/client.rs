use super::codec::{decode_binary, encode_binary, read_frame, write_frame};
use super::deadline::{
    DeadlineStream, connect_before, deadline_after, ensure_before, read_bounded_line,
};
use super::*;
use calyx_core::CALYX_ERROR_CODES;
use sha2::{Digest, Sha256};

const REMOTE_RESIDENT_REMEDIATION: &str =
    "follow the remote resident remediation included in the failure message, then retry";
const UNKNOWN_REMOTE_REMEDIATION: &str = "restart the resident service from the same native Calyx build as the client and inspect the remote code included in the failure message";

pub(crate) fn client_command(args: &[String], op: &str) -> CliResult {
    let flags = parse_client_flags(args, op)?;
    if op == "measure-batch" {
        let modality = flags.modality.expect("parsed modality");
        let inputs = flags
            .inputs
            .into_iter()
            .map(|input| client_input_to_core(input, modality))
            .collect::<CliResult<Vec<_>>>()?;
        if flags.summary_only {
            let response =
                measure_batch_summary_at(flags.addr, modality, &inputs, flags.runtime_batch_limit)?;
            if let Some(path) = flags.out {
                write_json_file(path, &response)?;
            }
            return print_json(&response);
        }
        let response = measure_batch_at(flags.addr, modality, &inputs, flags.runtime_batch_limit)?;
        if let Some(path) = flags.out {
            write_json_file(path, &response.response)?;
        }
        return print_json(&response.response);
    }
    let mut request = json!({ "op": op });
    if op == "measure" {
        request["modality"] = serde_json::to_value(flags.modality.expect("parsed modality"))
            .map_err(|error| {
                CliError::runtime(format!("serialize resident measure modality: {error}"))
            })?;
        match flags.input.expect("parsed input") {
            ClientMeasureInput::Utf8(input) => request["input"] = json!(input),
            ClientMeasureInput::Hex(input_hex) => request["input_hex"] = json!(input_hex),
        }
    }
    let timeout = if op == "measure" {
        productive_timeout(flags.addr)?
    } else {
        control_timeout()
    };
    let response = send_request_with_timeout(flags.addr, request, timeout)?;
    if let Some(path) = flags.out {
        write_json_file(path, &response)?;
    }
    print_json(&response)
}

fn client_input_to_core(input: ClientMeasureInput, modality: Modality) -> CliResult<Input> {
    let bytes = match input {
        ClientMeasureInput::Utf8(input) => input.into_bytes(),
        ClientMeasureInput::Hex(input_hex) => hex_decode(&input_hex).map_err(CliError::usage)?,
    };
    Ok(Input {
        modality,
        bytes,
        pointer: None,
    })
}

/// Programmatic readiness probe used by ingest resident-route discovery: one
/// JSON `ready` round-trip returning the raw readiness value.
pub(crate) fn ready_value_at(addr: SocketAddr) -> CliResult<Value> {
    send_request_with_timeout(addr, json!({ "op": "ready" }), control_timeout())
}

fn send_request_with_timeout(
    addr: SocketAddr,
    request: Value,
    timeout: Duration,
) -> CliResult<Value> {
    ensure_loopback(addr)?;
    let deadline = deadline_after(timeout)?;
    let mut stream = connect_before(&addr, deadline).map_err(|error| {
        CliError::from(CalyxError {
            code: "CALYX_PANEL_RESIDENT_UNAVAILABLE",
            message: format!("connect resident service {addr}: {error}"),
            remediation: CLIENT_TIMEOUT_REMEDIATION,
        })
    })?;
    let mut deadline_stream = DeadlineStream::new(&mut stream, deadline);
    serde_json::to_writer(&mut deadline_stream, &request)
        .map_err(|error| CliError::runtime(format!("write resident request to {addr}: {error}")))?;
    deadline_stream.write_all(b"\n")?;
    deadline_stream.flush()?;
    let mut reader = BufReader::new(deadline_stream);
    let response = read_bounded_line(
        &mut reader,
        MAX_RESIDENT_JSON_LINE_BYTES,
        "resident JSON response",
    )?;
    let response = serde_json::from_slice(&response).map_err(|error| {
        CliError::runtime(format!("parse resident response from {addr}: {error}"))
    })?;
    ensure_before(deadline, "resident JSON client round trip")?;
    reject_remote_json_error(addr, response)
}

fn reject_remote_json_error(addr: SocketAddr, response: Value) -> CliResult<Value> {
    let Some(object) = response.as_object() else {
        return Err(remote_schema_error(
            addr,
            "response was not a JSON object with an explicit boolean ok field",
        ));
    };
    let has_error_field = ["code", "message", "remediation"]
        .iter()
        .any(|field| object.contains_key(*field));
    match object.get("ok") {
        Some(Value::Bool(true)) if !has_error_field => return Ok(response),
        Some(Value::Bool(true)) => {
            return Err(remote_schema_error(
                addr,
                "response declared ok=true while also carrying failure-envelope fields",
            ));
        }
        Some(Value::Bool(false)) => {}
        Some(_) => {
            return Err(remote_schema_error(addr, "ok field was not a boolean"));
        }
        None => {
            return Err(remote_schema_error(addr, "required ok field was missing"));
        }
    }

    let field = |name: &str| {
        object
            .get(name)
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| malformed_remote_error(addr, name))
    };
    let code = field("code")?;
    let message = field("message")?;
    let remediation = field("remediation")?;
    Err(remote_error(code, message, remediation))
}

fn malformed_remote_error(addr: SocketAddr, field: &str) -> CliError {
    remote_schema_error(
        addr,
        format!("response declared ok=false but {field} was missing, blank, or not a string"),
    )
}

fn remote_schema_error(addr: SocketAddr, detail: impl std::fmt::Display) -> CliError {
    CliError::from(CalyxError {
        code: "CALYX_PANEL_RESIDENT_SCHEMA_MISMATCH",
        message: format!("resident response from {addr} violated the JSON envelope: {detail}"),
        remediation: "restart the resident supervisor and client from the same native Calyx build; preserve both process logs and the lifecycle journal",
    })
}

pub(crate) fn measure_batch_at(
    addr: SocketAddr,
    modality: Modality,
    inputs: &[Input],
    runtime_batch_limit: Option<usize>,
) -> CliResult<MeasureBatchAtResponse> {
    ensure_loopback(addr)?;
    let timeout = productive_timeout(addr)?;
    let deadline = deadline_after(timeout)?;
    let mut stream = connect_before(&addr, deadline).map_err(|error| {
        CliError::from(CalyxError {
            code: "CALYX_PANEL_RESIDENT_UNAVAILABLE",
            message: format!("connect resident service {addr}: {error}"),
            remediation: CLIENT_TIMEOUT_REMEDIATION,
        })
    })?;
    let mut deadline_stream = DeadlineStream::new(&mut stream, deadline);
    deadline_stream.write_all(RESIDENT_BINARY_MAGIC)?;
    let request_bytes = encode_binary(&ResidentMeasureBatchBinaryRequest {
        protocol_version: RESIDENT_BINARY_PROTOCOL_VERSION,
        modality,
        inputs: inputs
            .iter()
            .map(|input| input.bytes.clone())
            .collect::<Vec<_>>(),
        runtime_batch_limit,
        supervisor_request_id: None,
        supervisor_generation: None,
    })?;
    write_frame(&mut deadline_stream, &request_bytes)?;
    deadline_stream.flush()?;
    let response =
        read_measure_batch_stream(&mut deadline_stream, inputs.len(), request_bytes.len())?;
    ensure_before(deadline, "resident measure_batch client round trip")?;
    Ok(response)
}

fn measure_batch_summary_at(
    addr: SocketAddr,
    modality: Modality,
    inputs: &[Input],
    runtime_batch_limit: Option<usize>,
) -> CliResult<MeasureBatchSummaryResponse> {
    ensure_loopback(addr)?;
    let timeout = productive_timeout(addr)?;
    let deadline = deadline_after(timeout)?;
    let mut stream = connect_before(&addr, deadline).map_err(|error| {
        CliError::from(CalyxError {
            code: "CALYX_PANEL_RESIDENT_UNAVAILABLE",
            message: format!("connect resident service {addr}: {error}"),
            remediation: CLIENT_TIMEOUT_REMEDIATION,
        })
    })?;
    let mut deadline_stream = DeadlineStream::new(&mut stream, deadline);
    deadline_stream.write_all(RESIDENT_BINARY_MAGIC)?;
    let request_bytes = encode_binary(&ResidentMeasureBatchBinaryRequest {
        protocol_version: RESIDENT_BINARY_PROTOCOL_VERSION,
        modality,
        inputs: inputs
            .iter()
            .map(|input| input.bytes.clone())
            .collect::<Vec<_>>(),
        runtime_batch_limit,
        supervisor_request_id: None,
        supervisor_generation: None,
    })?;
    write_frame(&mut deadline_stream, &request_bytes)?;
    deadline_stream.flush()?;
    let response =
        read_measure_batch_summary_stream(&mut deadline_stream, inputs.len(), request_bytes.len())?;
    ensure_before(deadline, "resident measure_batch summary client round trip")?;
    Ok(response)
}

fn control_timeout() -> Duration {
    Duration::from_secs(CLIENT_CONTROL_TIMEOUT_SECS)
}

fn productive_timeout(addr: SocketAddr) -> CliResult<Duration> {
    let ready = ready_value_at(addr)?;
    let max_load_secs = ready
        .get("max_load_secs")
        .and_then(Value::as_u64)
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            CliError::from(CalyxError {
                code: "CALYX_PANEL_RESIDENT_SCHEMA_MISMATCH",
                message: format!(
                    "resident readiness from {addr} has no positive max_load_secs"
                ),
                remediation: "restart the resident supervisor from the same native Calyx build as the client",
            })
        })?;
    let max_request_secs = ready
        .get("max_request_secs")
        .and_then(Value::as_u64)
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            CliError::from(CalyxError {
                code: "CALYX_PANEL_RESIDENT_SCHEMA_MISMATCH",
                message: format!(
                    "resident readiness from {addr} has no positive max_request_secs"
                ),
                remediation: "restart the resident supervisor from the same native Calyx build as the client",
            })
        })?;
    Ok(Duration::from_secs(
        max_load_secs
            .saturating_add(max_request_secs)
            .saturating_add(CLIENT_PRODUCTIVE_MARGIN_SECS),
    ))
}

/// Consume the streamed measure_batch frames: Header, then one Row frame per
/// input, then End. Any Err frame, out-of-order frame, truncated stream, or
/// row/count mismatch fails closed — a partial stream never yields rows.
fn read_measure_batch_stream(
    stream: &mut dyn Read,
    expected_inputs: usize,
    request_bytes: usize,
) -> CliResult<MeasureBatchAtResponse> {
    let mut response_bytes = 0usize;
    let mut next_frame = |stream: &mut dyn Read| -> CliResult<ResidentMeasureBatchStreamFrame> {
        let frame = read_frame(stream)?;
        response_bytes += frame.len();
        Ok(decode_binary::<ResidentMeasureBatchStreamFrame>(&frame)?)
    };
    let header = match next_frame(stream)? {
        ResidentMeasureBatchStreamFrame::Header(header) => header,
        ResidentMeasureBatchStreamFrame::Err {
            code,
            message,
            remediation,
        } => return Err(remote_stream_error(&code, &message, &remediation)),
        other => return Err(unexpected_stream_frame("Header", &other)),
    };
    validate_measure_batch_header(&header)?;
    let mut rows: Vec<ResidentMeasuredInput> = Vec::with_capacity(header.input_count);
    let end = loop {
        match next_frame(stream)? {
            ResidentMeasureBatchStreamFrame::Row(row) => {
                if row.input_index != rows.len() {
                    return Err(CliError::from(CalyxError {
                        code: "CALYX_PANEL_RESIDENT_STREAM_ORDER",
                        message: format!(
                            "resident measure_batch row frame carries input_index {} but {} rows were received",
                            row.input_index,
                            rows.len()
                        ),
                        remediation: "restart the resident service from the same Calyx build as the CLI",
                    }));
                }
                rows.push(*row);
            }
            ResidentMeasureBatchStreamFrame::End(end) => break end,
            ResidentMeasureBatchStreamFrame::Err {
                code,
                message,
                remediation,
            } => return Err(remote_stream_error(&code, &message, &remediation)),
            other => return Err(unexpected_stream_frame("Row or End", &other)),
        }
    };
    if end.row_count != rows.len() || rows.len() != expected_inputs {
        return Err(CliError::from(CalyxError {
            code: "CALYX_PANEL_RESIDENT_STREAM_ORDER",
            message: format!(
                "resident measure_batch stream ended with {} rows (end frame says {}) for {} inputs",
                rows.len(),
                end.row_count,
                expected_inputs
            ),
            remediation: "restart the resident service from the same Calyx build as the CLI",
        }));
    }
    Ok(MeasureBatchAtResponse {
        response: MeasureBatchResponse {
            ok: true,
            schema: header.schema,
            ready: header.ready,
            process_id: header.process_id,
            template_source: header.template_source,
            modality: header.modality,
            input_count: header.input_count,
            elapsed_ms: end.elapsed_ms,
            runtime_batch_limit: header.runtime_batch_limit,
            rows,
            completion: end.completion,
        },
        request_bytes,
        response_bytes,
    })
}

fn read_measure_batch_summary_stream(
    stream: &mut dyn Read,
    expected_inputs: usize,
    request_bytes: usize,
) -> CliResult<MeasureBatchSummaryResponse> {
    let mut response_bytes = 0usize;
    let frame = read_frame(stream)?;
    response_bytes += frame.len();
    let header = match decode_binary::<ResidentMeasureBatchStreamFrame>(&frame)? {
        ResidentMeasureBatchStreamFrame::Header(header) => header,
        ResidentMeasureBatchStreamFrame::Err {
            code,
            message,
            remediation,
        } => return Err(remote_stream_error(&code, &message, &remediation)),
        other => return Err(unexpected_stream_frame("Header", &other)),
    };
    validate_measure_batch_header(&header)?;
    let mut hasher = Sha256::new();
    let mut row_count = 0usize;
    let mut measured_slot_counts = Vec::new();
    let mut absent_slot_counts = Vec::new();
    let end = loop {
        let frame = read_frame(stream)?;
        response_bytes += frame.len();
        match decode_binary::<ResidentMeasureBatchStreamFrame>(&frame)? {
            ResidentMeasureBatchStreamFrame::Row(row) => {
                if row.input_index != row_count {
                    return Err(CliError::from(CalyxError {
                        code: "CALYX_PANEL_RESIDENT_STREAM_ORDER",
                        message: format!(
                            "resident measure_batch row frame carries input_index {} but {} rows were received",
                            row.input_index, row_count
                        ),
                        remediation: "restart the resident service from the same Calyx build as the CLI",
                    }));
                }
                hasher.update(&frame);
                push_unique(&mut measured_slot_counts, row.measured_slot_count);
                push_unique(&mut absent_slot_counts, row.absent_slot_count);
                row_count += 1;
            }
            ResidentMeasureBatchStreamFrame::End(end) => break end,
            ResidentMeasureBatchStreamFrame::Err {
                code,
                message,
                remediation,
            } => return Err(remote_stream_error(&code, &message, &remediation)),
            other => return Err(unexpected_stream_frame("Row or End", &other)),
        }
    };
    if end.row_count != row_count || row_count != expected_inputs {
        return Err(CliError::from(CalyxError {
            code: "CALYX_PANEL_RESIDENT_STREAM_ORDER",
            message: format!(
                "resident measure_batch stream ended with {row_count} rows (end frame says {}) for {expected_inputs} inputs",
                end.row_count
            ),
            remediation: "restart the resident service from the same Calyx build as the CLI",
        }));
    }
    Ok(MeasureBatchSummaryResponse {
        ok: true,
        schema: header.schema,
        ready: header.ready,
        process_id: header.process_id,
        template_source: header.template_source,
        modality: header.modality,
        input_count: header.input_count,
        elapsed_ms: end.elapsed_ms,
        runtime_batch_limit: header.runtime_batch_limit,
        row_count,
        measured_slot_counts,
        absent_slot_counts,
        response_rows_sha256: hex_digest(&hasher.finalize()),
        request_bytes,
        response_bytes,
        completion: end.completion,
    })
}

fn validate_measure_batch_header(header: &ResidentMeasureBatchStreamHeader) -> CliResult {
    if header.protocol_version != RESIDENT_BINARY_PROTOCOL_VERSION {
        return Err(CliError::from(CalyxError {
            code: "CALYX_PANEL_RESIDENT_PROTOCOL_MISMATCH",
            message: format!(
                "resident measure_batch binary protocol {}, expected {}",
                header.protocol_version, RESIDENT_BINARY_PROTOCOL_VERSION
            ),
            remediation: "restart the resident service from the same Calyx build as the CLI",
        }));
    }
    if header.schema != MEASURE_BATCH_SCHEMA {
        return Err(CliError::from(CalyxError {
            code: "CALYX_PANEL_RESIDENT_SCHEMA_MISMATCH",
            message: format!(
                "resident measure_batch schema {}, expected {}",
                header.schema, MEASURE_BATCH_SCHEMA
            ),
            remediation: "restart the resident service from the same Calyx build as the CLI",
        }));
    }
    Ok(())
}

fn push_unique(values: &mut Vec<usize>, value: usize) {
    if !values.contains(&value) {
        values.push(value);
        values.sort_unstable();
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn remote_stream_error(code: &str, message: &str, remediation: &str) -> CliError {
    remote_error(code, message, remediation)
}

fn unexpected_stream_frame(expected: &str, got: &ResidentMeasureBatchStreamFrame) -> CliError {
    let kind = match got {
        ResidentMeasureBatchStreamFrame::Header(_) => "Header",
        ResidentMeasureBatchStreamFrame::Row(_) => "Row",
        ResidentMeasureBatchStreamFrame::End(_) => "End",
        ResidentMeasureBatchStreamFrame::Err { .. } => "Err",
    };
    CliError::from(CalyxError {
        code: "CALYX_PANEL_RESIDENT_STREAM_ORDER",
        message: format!(
            "resident measure_batch stream sent a {kind} frame where {expected} was expected"
        ),
        remediation: "restart the resident service from the same Calyx build as the CLI",
    })
}

fn remote_error(code: &str, message: &str, remediation: &str) -> CliError {
    if let Some(catalog_code) = CALYX_ERROR_CODES
        .iter()
        .find(|catalog_code| catalog_code.code() == code)
    {
        return CliError::from(CalyxError {
            code: catalog_code.code(),
            message: message.to_string(),
            remediation: catalog_code.remediation(),
        });
    }
    if let Some(code) = resident_remote_error_code(code) {
        return CliError::from(CalyxError {
            code,
            message: format!("{message}; remote remediation: {remediation}"),
            remediation: REMOTE_RESIDENT_REMEDIATION,
        });
    }
    CliError::from(CalyxError {
        code: "CALYX_PANEL_RESIDENT_ERROR",
        message: format!(
            "resident returned unknown remote code {code}: {message}; remote remediation: {remediation}"
        ),
        remediation: UNKNOWN_REMOTE_REMEDIATION,
    })
}

fn resident_remote_error_code(remote_code: &str) -> Option<&'static str> {
    Some(match remote_code {
        "CALYX_CLI_IO_ERROR" => "CALYX_CLI_IO_ERROR",
        "CALYX_CLI_RUNTIME_ERROR" => "CALYX_CLI_RUNTIME_ERROR",
        "CALYX_CLI_USAGE_ERROR" => "CALYX_CLI_USAGE_ERROR",
        "CALYX_PANEL_RESIDENT_ALREADY_RUNNING" => "CALYX_PANEL_RESIDENT_ALREADY_RUNNING",
        "CALYX_PANEL_RESIDENT_BACK_PRESSURE" => "CALYX_PANEL_RESIDENT_BACK_PRESSURE",
        "CALYX_PANEL_RESIDENT_BAD_REQUEST" => "CALYX_PANEL_RESIDENT_BAD_REQUEST",
        "CALYX_PANEL_RESIDENT_BINARY_DECODE" => "CALYX_PANEL_RESIDENT_BINARY_DECODE",
        "CALYX_PANEL_RESIDENT_BINARY_ENCODE" => "CALYX_PANEL_RESIDENT_BINARY_ENCODE",
        "CALYX_PANEL_RESIDENT_BINARY_FRAME" => "CALYX_PANEL_RESIDENT_BINARY_FRAME",
        "CALYX_PANEL_RESIDENT_BIND_REFUSED" => "CALYX_PANEL_RESIDENT_BIND_REFUSED",
        "CALYX_PANEL_RESIDENT_CPU_LENS_REFUSED" => "CALYX_PANEL_RESIDENT_CPU_LENS_REFUSED",
        "CALYX_PANEL_RESIDENT_CLIENT_ABORTED_GENERATION" => {
            "CALYX_PANEL_RESIDENT_CLIENT_ABORTED_GENERATION"
        }
        "CALYX_PANEL_RESIDENT_ERROR" => "CALYX_PANEL_RESIDENT_ERROR",
        "CALYX_PANEL_RESIDENT_EXECUTION_UNATTESTED" => "CALYX_PANEL_RESIDENT_EXECUTION_UNATTESTED",
        "CALYX_PANEL_RESIDENT_INPUT_HEX_INVALID" => "CALYX_PANEL_RESIDENT_INPUT_HEX_INVALID",
        "CALYX_PANEL_RESIDENT_JOB_ASSIGN_FAILED" => "CALYX_PANEL_RESIDENT_JOB_ASSIGN_FAILED",
        "CALYX_PANEL_RESIDENT_JOB_CONFIGURE_FAILED" => "CALYX_PANEL_RESIDENT_JOB_CONFIGURE_FAILED",
        "CALYX_PANEL_RESIDENT_JOB_CREATE_FAILED" => "CALYX_PANEL_RESIDENT_JOB_CREATE_FAILED",
        "CALYX_PANEL_RESIDENT_JOB_IDENTITY_INVALID" => "CALYX_PANEL_RESIDENT_JOB_IDENTITY_INVALID",
        "CALYX_PANEL_RESIDENT_JOB_QUERY_FAILED" => "CALYX_PANEL_RESIDENT_JOB_QUERY_FAILED",
        "CALYX_PANEL_RESIDENT_JOB_QUERY_INVALID" => "CALYX_PANEL_RESIDENT_JOB_QUERY_INVALID",
        "CALYX_PANEL_RESIDENT_JOB_TERMINATE_FAILED" => "CALYX_PANEL_RESIDENT_JOB_TERMINATE_FAILED",
        "CALYX_PANEL_RESIDENT_LIFECYCLE_CORRUPT" => "CALYX_PANEL_RESIDENT_LIFECYCLE_CORRUPT",
        "CALYX_PANEL_RESIDENT_LIFECYCLE_DURABILITY" => "CALYX_PANEL_RESIDENT_LIFECYCLE_DURABILITY",
        "CALYX_PANEL_RESIDENT_PROTOCOL_MISMATCH" => "CALYX_PANEL_RESIDENT_PROTOCOL_MISMATCH",
        "CALYX_PANEL_RESIDENT_RUNTIME_MISSING" => "CALYX_PANEL_RESIDENT_RUNTIME_MISSING",
        "CALYX_PANEL_RESIDENT_SCHEMA_MISMATCH" => "CALYX_PANEL_RESIDENT_SCHEMA_MISMATCH",
        "CALYX_PANEL_RESIDENT_SLOT_SCOPE_INVALID" => "CALYX_PANEL_RESIDENT_SLOT_SCOPE_INVALID",
        "CALYX_PANEL_RESIDENT_STOPPING" => "CALYX_PANEL_RESIDENT_STOPPING",
        "CALYX_PANEL_RESIDENT_STREAM_ORDER" => "CALYX_PANEL_RESIDENT_STREAM_ORDER",
        "CALYX_PANEL_RESIDENT_UNAVAILABLE" => "CALYX_PANEL_RESIDENT_UNAVAILABLE",
        "CALYX_PANEL_RESIDENT_UNMANAGED_RUNTIME" => "CALYX_PANEL_RESIDENT_UNMANAGED_RUNTIME",
        "CALYX_PANEL_RESIDENT_WARM_COUNT_MISMATCH" => "CALYX_PANEL_RESIDENT_WARM_COUNT_MISMATCH",
        "CALYX_PANEL_RESIDENT_WORKER_GATE" => "CALYX_PANEL_RESIDENT_WORKER_GATE",
        "CALYX_PANEL_RESIDENT_WORKER_UNAUTHORIZED" => "CALYX_PANEL_RESIDENT_WORKER_UNAUTHORIZED",
        "CALYX_PANEL_RESIDENT_WORKER_LOST" => "CALYX_PANEL_RESIDENT_WORKER_LOST",
        "CALYX_PANEL_RESIDENT_WORKER_PROTOCOL_INVALID" => {
            "CALYX_PANEL_RESIDENT_WORKER_PROTOCOL_INVALID"
        }
        "CALYX_PANEL_RESIDENT_WORKER_REPORTED_ERROR" => {
            "CALYX_PANEL_RESIDENT_WORKER_REPORTED_ERROR"
        }
        "CALYX_PANEL_RESIDENT_WORKER_START_FAILED" => "CALYX_PANEL_RESIDENT_WORKER_START_FAILED",
        "CALYX_PANEL_RESIDENT_WORKER_STOP_FAILED" => "CALYX_PANEL_RESIDENT_WORKER_STOP_FAILED",
        _ => return None,
    })
}
