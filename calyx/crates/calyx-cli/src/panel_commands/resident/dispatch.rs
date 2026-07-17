use super::lifecycle::LifecyclePhase;
use super::server::ResidentService;
use super::*;
use ulid::Ulid;

pub(crate) fn dispatch_request(
    request: ResidentRequest,
    service: &ResidentService,
    running: &AtomicBool,
) -> Value {
    if let Err(error) = validate_request(&request) {
        return error;
    }
    match request.op.as_str() {
        "ready" => json!(readiness(service)),
        "measure" => match productive_completion(
            &request.supervisor_request_id,
            request.supervisor_generation,
            service.generation,
        ) {
            Ok(completion) => dispatch_measure(request, service, completion),
            Err(error) => cli_error_value(&error),
        },
        "measure_batch" => match productive_completion(
            &request.supervisor_request_id,
            request.supervisor_generation,
            service.generation,
        ) {
            Ok(completion) => dispatch_measure_batch(request, service, completion),
            Err(error) => cli_error_value(&error),
        },
        "shutdown" => {
            running.store(false, Ordering::SeqCst);
            json!({"ok": true, "schema": READY_SCHEMA, "ready": false, "stopping": true})
        }
        other => error_value(
            "CALYX_PANEL_RESIDENT_BAD_REQUEST",
            format!("unknown resident op {other}"),
            "send op=ready, measure, measure_batch, or shutdown",
        ),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RequestClass {
    Ready,
    Productive,
    Shutdown,
}

pub(super) fn validate_public_request(request: &ResidentRequest) -> Result<RequestClass, Value> {
    if request.supervisor_request_id.is_some() || request.supervisor_generation.is_some() {
        return Err(error_value(
            "CALYX_PANEL_RESIDENT_BAD_REQUEST",
            "public resident requests must not provide private supervisor request identity",
            "remove supervisor_request_id and supervisor_generation; the public supervisor assigns both after admission",
        ));
    }
    validate_request(request)
}

/// Validate the complete semantic request before a productive request may
/// acquire a GPU-generation lease. Invalid requests must never load or refresh
/// the resident worker.
pub(super) fn validate_request(request: &ResidentRequest) -> Result<RequestClass, Value> {
    match request.op.as_str() {
        "ready" => {
            reject_control_payload(request, "ready")?;
            Ok(RequestClass::Ready)
        }
        "shutdown" => {
            reject_control_payload(request, "shutdown")?;
            Ok(RequestClass::Shutdown)
        }
        "measure" => {
            if request.modality.is_none() {
                return Err(error_value(
                    "CALYX_PANEL_RESIDENT_BAD_REQUEST",
                    "measure requires modality",
                    "send a modality such as text, code, image, audio, protein, or dna",
                ));
            }
            if request.inputs_hex.is_some() || request.runtime_batch_limit.is_some() {
                return Err(error_value(
                    "CALYX_PANEL_RESIDENT_BAD_REQUEST",
                    "measure does not accept inputs_hex or runtime_batch_limit",
                    "send exactly one input or input_hex; use measure_batch for batched inputs",
                ));
            }
            request_input_bytes(&request.input, &request.input_hex)?;
            Ok(RequestClass::Productive)
        }
        "measure_batch" => {
            if request.modality.is_none() {
                return Err(error_value(
                    "CALYX_PANEL_RESIDENT_BAD_REQUEST",
                    "measure_batch requires modality",
                    "send a modality such as text, code, image, audio, protein, or dna",
                ));
            }
            if request.input.is_some() || request.input_hex.is_some() {
                return Err(error_value(
                    "CALYX_PANEL_RESIDENT_BAD_REQUEST",
                    "measure_batch accepts inputs_hex only",
                    "send a non-empty inputs_hex array; use measure for one input",
                ));
            }
            if matches!(request.runtime_batch_limit, Some(0)) {
                return Err(error_value(
                    "CALYX_PANEL_RESIDENT_BAD_REQUEST",
                    "measure_batch runtime_batch_limit must be greater than zero",
                    "omit runtime_batch_limit or send a positive integer",
                ));
            }
            request_inputs_bytes(&request.inputs_hex)?;
            Ok(RequestClass::Productive)
        }
        other => Err(error_value(
            "CALYX_PANEL_RESIDENT_BAD_REQUEST",
            format!("unknown resident op {other}"),
            "send op=ready, measure, measure_batch, or shutdown",
        )),
    }
}

fn reject_control_payload(request: &ResidentRequest, operation: &str) -> Result<(), Value> {
    if request.modality.is_some()
        || request.input.is_some()
        || request.input_hex.is_some()
        || request.inputs_hex.is_some()
        || request.runtime_batch_limit.is_some()
    {
        return Err(error_value(
            "CALYX_PANEL_RESIDENT_BAD_REQUEST",
            format!("{operation} does not accept measurement payload fields"),
            format!("send exactly {{\"op\":\"{operation}\"}}"),
        ));
    }
    Ok(())
}

fn dispatch_measure(
    request: ResidentRequest,
    service: &ResidentService,
    completion: ResidentCompletionAttestation,
) -> Value {
    let Some(modality) = request.modality else {
        return error_value(
            "CALYX_PANEL_RESIDENT_BAD_REQUEST",
            "measure requires modality",
            "send a modality such as text, code, image, audio, protein, or dna",
        );
    };
    let bytes = match request_input_bytes(&request.input, &request.input_hex) {
        Ok(bytes) => bytes,
        Err(error) => return error,
    };
    match measure(service, modality, bytes, completion) {
        Ok(response) => json!(response),
        Err(error) => cli_error_value(&error),
    }
}

fn dispatch_measure_batch(
    request: ResidentRequest,
    service: &ResidentService,
    completion: ResidentCompletionAttestation,
) -> Value {
    let Some(modality) = request.modality else {
        return error_value(
            "CALYX_PANEL_RESIDENT_BAD_REQUEST",
            "measure_batch requires modality",
            "send a modality such as text, code, image, audio, protein, or dna",
        );
    };
    let bytes = match request_inputs_bytes(&request.inputs_hex) {
        Ok(bytes) => bytes,
        Err(error) => return error,
    };
    match measure_batch(
        service,
        modality,
        bytes,
        request.runtime_batch_limit,
        completion,
    ) {
        Ok(response) => json!(response),
        Err(error) => cli_error_value(&error),
    }
}

fn request_input_bytes(
    input: &Option<String>,
    input_hex: &Option<String>,
) -> Result<Vec<u8>, Value> {
    match (input, input_hex) {
        (Some(_), Some(_)) => Err(error_value(
            "CALYX_PANEL_RESIDENT_BAD_REQUEST",
            "measure accepts exactly one of input or input_hex",
            "send UTF-8 text as input or arbitrary bytes as lowercase input_hex",
        )),
        (Some(text), None) if text.is_empty() => Err(error_value(
            "CALYX_PANEL_RESIDENT_BAD_REQUEST",
            "measure input must not be empty",
            "send at least one input byte",
        )),
        (Some(text), None) => Ok(text.as_bytes().to_vec()),
        (None, Some(hex)) => hex_decode(&hex)
            .map_err(|message| {
                error_value(
                    "CALYX_PANEL_RESIDENT_INPUT_HEX_INVALID",
                    message,
                    "send an even-length hexadecimal input_hex string",
                )
            })
            .and_then(|bytes| {
                if bytes.is_empty() {
                    Err(error_value(
                        "CALYX_PANEL_RESIDENT_BAD_REQUEST",
                        "measure input_hex must not encode an empty input",
                        "send at least one hexadecimal byte",
                    ))
                } else {
                    Ok(bytes)
                }
            }),
        (None, None) => Err(error_value(
            "CALYX_PANEL_RESIDENT_BAD_REQUEST",
            "measure requires input or input_hex",
            "send UTF-8 text as input or arbitrary bytes as lowercase input_hex",
        )),
    }
}

fn request_inputs_bytes(inputs_hex: &Option<Vec<String>>) -> Result<Vec<Vec<u8>>, Value> {
    let Some(inputs_hex) = inputs_hex else {
        return Err(error_value(
            "CALYX_PANEL_RESIDENT_BAD_REQUEST",
            "measure_batch requires inputs_hex",
            "send inputs_hex as an array of even-length hexadecimal byte strings",
        ));
    };
    if inputs_hex.is_empty() {
        return Err(error_value(
            "CALYX_PANEL_RESIDENT_BAD_REQUEST",
            "measure_batch inputs_hex must not be empty",
            "send at least one non-empty hexadecimal input",
        ));
    }
    inputs_hex
        .iter()
        .enumerate()
        .map(|(index, hex)| {
            hex_decode(&hex)
                .map_err(|message| {
                    error_value(
                        "CALYX_PANEL_RESIDENT_INPUT_HEX_INVALID",
                        format!("inputs_hex[{index}]: {message}"),
                        "send each inputs_hex item as an even-length hexadecimal byte string",
                    )
                })
                .and_then(|bytes| {
                    if bytes.is_empty() {
                        Err(error_value(
                            "CALYX_PANEL_RESIDENT_BAD_REQUEST",
                            format!("inputs_hex[{index}] encodes an empty input"),
                            "send at least one hexadecimal byte for every input",
                        ))
                    } else {
                        Ok(bytes)
                    }
                })
        })
        .collect()
}

pub(crate) fn readiness(service: &ResidentService) -> ReadyResponse {
    let state = &service.state;
    ReadyResponse {
        ok: true,
        schema: READY_SCHEMA.to_string(),
        ready: true,
        accepting_requests: true,
        warm_ready: true,
        phase: LifecyclePhase::LoadedIdle,
        residency_scope: "generation_scoped_worker".to_string(),
        process_id: std::process::id(),
        supervisor_pid: service.supervisor_pid,
        worker_pid: Some(std::process::id()),
        worker_descendant_pids: vec![std::process::id()],
        generation: service.generation,
        queued_requests: 0,
        in_flight: 0,
        bind: service.bind,
        uptime_ms: service.started.elapsed().as_millis(),
        source_of_truth: state.source_of_truth.clone(),
        home: state.home.clone(),
        template_selector: state.template_selector.clone(),
        template_source: state.template_source.clone(),
        ready_out: state.ready_out.clone(),
        max_resident_vram_mib: state.max_resident_vram_mib,
        declared_template_vram_mib: state.declared_template_vram_mib,
        resident_overhead_multiplier: state.resident_overhead_multiplier,
        estimated_resident_vram_mib: state.estimated_resident_vram_mib,
        max_load_secs: state.max_load_secs,
        max_request_secs: service.max_request_secs,
        idle_ttl_ms: 60_000,
        idle_remaining_ms: None,
        idle_deadline_unix_ms: None,
        load_attempt_count: 1,
        load_success_count: 1,
        load_failure_count: 0,
        unload_count: 0,
        lifecycle_sequence: 0,
        lifecycle_journal: None,
        lifecycle_snapshot: None,
        frozen_panel_fingerprint: service.frozen_panel_fingerprint.clone(),
        last_error: None,
        load_parallelism: state.load_parallelism,
        load_ms: state.load_ms,
        probe_ms: state.probe_ms,
        slot_count: state.build.panel.slots.len(),
        slot_contracts: state
            .build
            .panel
            .slots
            .iter()
            .map(|slot| ResidentSlotContract {
                slot: slot.slot_id.get(),
                key: slot.slot_key.key().to_string(),
                lens_id: slot.lens_id.to_string(),
                shape: slot.shape,
                modality: slot.modality,
                placement: slot.resource.placement,
                state: slot.state,
                registered: state.build.registry.contains(slot.lens_id),
                retrieval_only: slot.retrieval_only,
                excluded_from_dedup: slot.excluded_from_dedup,
            })
            .collect(),
        slot_scope: state.slot_scope.iter().map(|slot| slot.get()).collect(),
        content_lens_count: state.content_lens_count,
        registry_lens_count: state.build.registry.lens_snapshots().len(),
        warmed_lens_count: state.warmed_lens_count,
        warmed_lens_scope: state.warmed_lens_scope.to_string(),
        lens_attestations: state.lens_attestations.clone(),
        #[cfg(windows)]
        onnx_runtime_attestation: state.onnx_runtime_attestation.clone(),
        gpu_content_lens_count: state.gpu_content_lens_count,
        cpu_content_lens_count: state
            .content_lens_count
            .saturating_sub(state.gpu_content_lens_count),
    }
}

fn measure(
    service: &ResidentService,
    modality: Modality,
    bytes: Vec<u8>,
    completion: ResidentCompletionAttestation,
) -> CliResult<MeasureResponse> {
    let started = Instant::now();
    let input = Input::new(modality, bytes);
    // #1153: single-input measure fans out across slots exactly like the
    // batch path — one warm panel walk, all runnable lenses concurrent.
    let measured_by_lens = super::parallel::measure_chunk_lenses(
        service,
        modality,
        std::slice::from_ref(&input),
        None,
    )?;
    let row = super::stream::assemble_row(service, modality, &measured_by_lens, 0, 0, &input)?;
    Ok(MeasureResponse {
        ok: true,
        schema: MEASURE_SCHEMA.to_string(),
        ready: true,
        process_id: std::process::id(),
        template_source: service.state.template_source.clone(),
        modality,
        input_len: row.input_len,
        elapsed_ms: started.elapsed().as_millis(),
        measured_slot_count: row.measured_slot_count,
        absent_slot_count: row.absent_slot_count,
        slots: row.slots,
        completion,
    })
}

fn measure_batch(
    service: &ResidentService,
    modality: Modality,
    input_bytes: Vec<Vec<u8>>,
    runtime_batch_limit: Option<usize>,
    completion: ResidentCompletionAttestation,
) -> CliResult<MeasureBatchResponse> {
    let input_count = input_bytes.len();
    let mut rows = Vec::with_capacity(input_count);
    let elapsed_ms = super::stream::measure_batch_chunked(
        service,
        modality,
        input_bytes,
        runtime_batch_limit,
        &mut |chunk_rows| {
            rows.extend(chunk_rows);
            Ok(())
        },
    )?;
    Ok(MeasureBatchResponse {
        ok: true,
        schema: MEASURE_BATCH_SCHEMA.to_string(),
        ready: true,
        process_id: std::process::id(),
        template_source: service.state.template_source.clone(),
        modality,
        input_count,
        elapsed_ms,
        runtime_batch_limit,
        rows,
        completion,
    })
}

pub(super) fn productive_completion(
    request_id: &Option<String>,
    generation: Option<u64>,
    expected_generation: u64,
) -> CliResult<ResidentCompletionAttestation> {
    let request_id = request_id
        .as_deref()
        .filter(|request_id| {
            request_id
                .parse::<Ulid>()
                .is_ok_and(|parsed| parsed.to_string() == *request_id)
        })
        .ok_or_else(|| {
            CliError::from(CalyxError {
                code: "CALYX_PANEL_RESIDENT_PROTOCOL_MISMATCH",
                message: "private productive request omitted a valid supervisor ULID".to_string(),
                remediation: "route productive work through the public resident supervisor from the same native Calyx build",
            })
        })?;
    if generation != Some(expected_generation) {
        return Err(CliError::from(CalyxError {
            code: "CALYX_PANEL_RESIDENT_PROTOCOL_MISMATCH",
            message: format!(
                "private productive request generation {generation:?} does not match worker generation {expected_generation}"
            ),
            remediation: "reap the mismatched worker generation and retry through the public supervisor",
        }));
    }
    Ok(ResidentCompletionAttestation {
        schema: COMPLETION_SCHEMA.to_string(),
        request_id: request_id.to_string(),
        generation: expected_generation,
        gpu_synchronized: true,
        host_materialized: true,
    })
}

pub(super) fn slot_measure(
    slot: &calyx_core::Slot,
    measured: bool,
    vector: Option<SlotVector>,
    absent_reason: Option<AbsentReason>,
) -> ResidentSlotMeasure {
    ResidentSlotMeasure {
        slot: slot.slot_id.get(),
        key: slot.slot_key.key().to_string(),
        lens_id: slot.lens_id.to_string(),
        modality: slot.modality,
        placement: slot.resource.placement,
        measured,
        vector,
        absent_reason,
    }
}
