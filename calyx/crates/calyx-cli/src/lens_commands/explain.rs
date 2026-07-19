use std::env;
use std::fmt::Write;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use calyx_core::{
    CalyxError, Input, Lens, RuntimeExecutionAttestation, SlotShape, SlotVector, SparseEntry,
};
use calyx_registry::{
    CandleLens, FastembedBgem3Lens, FastembedRerankerLens, FastembedSparseLens,
    LensForgeSourceTensorDtypeProfile, LensRuntime, LensSpec, MultimodalAdapterLens,
    ONNX_COLBERT_RUNTIME_ID, ONNX_CUSTOM_RUNTIME_ID, ONNX_FASTEMBED_RUNTIME_ID, OnnxColbertLens,
    OnnxInt8Attestation, OnnxLens, StaticLookupLens, TeiHttpLens,
    lens_spec_and_onnx_int8_attestation_from_manifest_path,
    validate_cuda_onnx_execution_attestation,
};
#[cfg(windows)]
use calyx_registry::{OnnxRuntimeAttestation, current_runtime_attestation};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::flags::Flags;
use super::support::{
    dim, hex_from_bytes, require_runtime_lens_id, runtime_name, slot_norm, slot_prefix,
    validate_vector_contract,
};
use crate::error::{CliError, CliResult};
use crate::output::print_json;

#[derive(Serialize)]
struct ExplainReport {
    manifest: PathBuf,
    lens_id: String,
    name: String,
    runtime: String,
    runtime_detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_tensor_dtype_profile: Option<LensForgeSourceTensorDtypeProfile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    onnx_int8_attestation: Option<OnnxInt8Attestation>,
    declared_model_dtype: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    local_execution_attestation: Option<LocalExecutionAttestationReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    runtime_execution_attestation: Option<RuntimeExecutionAttestation>,
    #[cfg(windows)]
    #[serde(skip_serializing_if = "Option::is_none")]
    onnx_runtime_attestation: Option<OnnxRuntimeAttestation>,
    gemm_accumulation_dtype: String,
    output_dtype: String,
    shape: ShapeReport,
    dim: u32,
    retrieval_only: bool,
    excluded_from_dedup: bool,
    rows: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_count: Option<usize>,
    norm: f32,
    norm_ok: bool,
    vector_sha256: String,
    first_values: Vec<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sparse_entries: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sparse_top: Option<Vec<SparseEntryReport>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    full_vector: Option<Vec<f32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    full_sparse: Option<Vec<SparseEntryReport>>,
    repeat: usize,
    timing: ExplainTimingReport,
    total_ms: f64,
    ms_per_input: f64,
    artifact_bytes: u64,
    artifact_mib: f32,
}

#[derive(Serialize)]
struct SparseEntryReport {
    idx: u32,
    val: f32,
}

#[derive(Serialize)]
struct ShapeReport {
    kind: &'static str,
    dim: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_dim: Option<u32>,
}

#[derive(Serialize)]
struct LocalExecutionAttestationReport {
    executable_lens_id: String,
    executable_corpus_hash: String,
    loader_target_dtype: String,
    observed_primary_activation_dtype: String,
    observed_execution_device: String,
    evidence_kind: String,
}

#[derive(Serialize)]
struct ExplainTimingReport {
    clock: &'static str,
    repeat: usize,
    end_to_end_total_ms: f64,
    setup_and_attestation_ms: f64,
    measurement_total_ms: f64,
    cold_first_measure_ms: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    steady_measurement: Option<SteadyTimingReport>,
    measurement_samples_ms: Vec<f64>,
}

#[derive(Serialize)]
struct SteadyTimingReport {
    samples: usize,
    total_ms: f64,
    mean_ms: f64,
    min_ms: f64,
    max_ms: f64,
}

struct Measurement {
    vector: SlotVector,
    measure_samples_ms: Vec<f64>,
    source_tensor_dtype_profile: Option<LensForgeSourceTensorDtypeProfile>,
    declared_model_dtype: String,
    local_execution_attestation: Option<LocalExecutionAttestationReport>,
    runtime_execution_attestation: Option<RuntimeExecutionAttestation>,
    gemm_accumulation_dtype: String,
    output_dtype: String,
    rows: Option<u32>,
    artifact_bytes: u64,
    runtime_detail: String,
}

struct RepeatedMeasurement {
    vector: SlotVector,
    samples_ms: Vec<f64>,
}

const UNKNOWN_DTYPE: &str = "unknown";
const NOT_APPLICABLE_DTYPE: &str = "not_applicable";
const GEMM_ACCUMULATION_DTYPE: &str = "f32";
const OUTPUT_DTYPE: &str = "f32";
const ONNX_CPU_FALLBACK_AUDIT_ENV: &str = "CALYX_ONNX_CPU_FALLBACK_AUDIT";
const ONNX_MAX_CPU_NODE_FRACTION_ENV: &str = "CALYX_ONNX_MAX_CPU_NODE_FRACTION";

pub(crate) fn explain(args: &[String]) -> CliResult {
    let flags = Flags::parse(args)?;
    let manifest = flags
        .manifest
        .clone()
        .ok_or_else(|| CliError::usage("calyx lens explain requires --manifest <path>"))?;
    let repeat = flags.repeat.unwrap_or(1);
    if repeat == 0 {
        return Err(CliError::usage("--repeat must be > 0"));
    }
    let (spec, onnx_int8_attestation) =
        lens_spec_and_onnx_int8_attestation_from_manifest_path(&manifest)?;
    configure_onnx_explain_audit(&spec.runtime);
    let input = input_bytes(&flags)?;
    let probe = Input::new(spec.modality, input);
    let started = Instant::now();
    let measurement = measure_runtime(&spec, &probe, repeat)?;
    #[cfg(windows)]
    let onnx_runtime_attestation = explain_onnx_runtime_attestation(&spec.runtime)?;
    let total_ms = started.elapsed().as_secs_f64() * 1000.0;
    let timing = explain_timing(&measurement.measure_samples_ms, total_ms, repeat)?;
    validate_vector_contract(&measurement.vector, spec.output, spec.norm_policy)?;
    let norm = slot_norm(&measurement.vector);
    print_json(&ExplainReport {
        manifest,
        lens_id: spec.lens_id().to_string(),
        name: spec.name,
        runtime: runtime_name(&spec.runtime).to_string(),
        runtime_detail: measurement.runtime_detail,
        source_tensor_dtype_profile: measurement.source_tensor_dtype_profile,
        onnx_int8_attestation,
        declared_model_dtype: measurement.declared_model_dtype,
        local_execution_attestation: measurement.local_execution_attestation,
        runtime_execution_attestation: measurement.runtime_execution_attestation,
        #[cfg(windows)]
        onnx_runtime_attestation,
        gemm_accumulation_dtype: measurement.gemm_accumulation_dtype,
        output_dtype: measurement.output_dtype,
        shape: shape_report(spec.output),
        dim: dim(spec.output),
        retrieval_only: spec.retrieval_only,
        excluded_from_dedup: spec.excluded_from_dedup,
        rows: measurement.rows,
        token_count: token_count(&measurement.vector),
        norm,
        norm_ok: true,
        vector_sha256: vector_sha256(&measurement.vector),
        first_values: slot_prefix(&measurement.vector, 4),
        sparse_entries: sparse_entry_count(&measurement.vector),
        sparse_top: sparse_top(&measurement.vector, 8),
        full_vector: full_vector(&measurement.vector, flags.full_vector)?,
        full_sparse: full_sparse(&measurement.vector, flags.full_vector)?,
        repeat,
        timing,
        total_ms,
        ms_per_input: total_ms / repeat as f64,
        artifact_bytes: measurement.artifact_bytes,
        artifact_mib: measurement.artifact_bytes as f32 / (1024.0 * 1024.0),
    })
}

fn configure_onnx_explain_audit(runtime: &LensRuntime) {
    if !is_in_process_onnx_runtime(runtime) {
        return;
    }
    // `calyx lens explain` is a single-command process and no model/session has
    // been constructed yet. Force the normal ONNX run to produce a placement
    // trace and reject even one CPU compute node under the CUDA-fail-loud policy.
    unsafe {
        env::set_var(ONNX_CPU_FALLBACK_AUDIT_ENV, "fail");
        env::set_var(ONNX_MAX_CPU_NODE_FRACTION_ENV, "0");
    }
}

fn is_in_process_onnx_runtime(runtime: &LensRuntime) -> bool {
    matches!(
        runtime,
        LensRuntime::Onnx { .. }
            | LensRuntime::FastembedDense { .. }
            | LensRuntime::FastembedDensePlaced { .. }
            | LensRuntime::OnnxColbert { .. }
            | LensRuntime::FastembedSparse { .. }
            | LensRuntime::FastembedBgem3 { .. }
            | LensRuntime::FastembedReranker { .. }
            | LensRuntime::FastembedSparsePlaced { .. }
            | LensRuntime::FastembedBgem3Placed { .. }
            | LensRuntime::FastembedRerankerPlaced { .. }
    )
}

fn require_cuda_onnx_execution_attestation(
    lens: &dyn Lens,
    runtime_label: &str,
) -> CliResult<RuntimeExecutionAttestation> {
    let attestation = lens.execution_attestation()?.ok_or_else(|| {
        CliError::from(CalyxError {
            code: "CALYX_LENS_EXPLAIN_ONNX_EXECUTION_UNATTESTED",
            message: format!(
                "{runtime_label} completed inference but retained no runtime provider/node-placement evidence"
            ),
            remediation: "use a Calyx-owned ONNX runtime that retains the fail-closed ORT provider profile; FastEmbed wrappers without execution attestation must not be used to claim GPU placement",
        })
    })?;
    validate_cuda_onnx_execution_attestation(&attestation, runtime_label).map_err(|error| {
        let code = if error.code == "CALYX_ONNX_EXECUTION_PLACEMENT_MISMATCH" {
            "CALYX_LENS_EXPLAIN_ONNX_EXECUTION_PLACEMENT"
        } else {
            "CALYX_LENS_EXPLAIN_ONNX_EXECUTION_UNATTESTED"
        };
        CliError::from(CalyxError {
            code,
            message: format!(
                "{runtime_label} execution attestation failed the current structured contract ({}): {}",
                error.code, error.message
            ),
            remediation: error.remediation,
        })
    })?;
    Ok(attestation)
}

#[cfg(windows)]
fn explain_onnx_runtime_attestation(
    runtime: &LensRuntime,
) -> CliResult<Option<OnnxRuntimeAttestation>> {
    if !is_in_process_onnx_runtime(runtime) {
        return Ok(None);
    }
    let attestation = current_runtime_attestation()?.ok_or_else(|| {
        CliError::from(CalyxError {
            code: "CALYX_LENS_EXPLAIN_ONNX_RUNTIME_UNATTESTED",
            message: "successful ONNX lens explain retained no pinned runtime attestation"
                .to_string(),
            remediation: "terminate the process and rerun through the pinned CUDA 13 runtime boundary; do not infer runtime identity from the lens manifest",
        })
    })?;
    Ok(Some(attestation))
}

fn shape_report(shape: SlotShape) -> ShapeReport {
    match shape {
        SlotShape::Dense(dim) => ShapeReport {
            kind: "dense",
            dim,
            token_dim: None,
        },
        SlotShape::Sparse(dim) => ShapeReport {
            kind: "sparse",
            dim,
            token_dim: None,
        },
        SlotShape::Multi { token_dim } => ShapeReport {
            kind: "multi",
            dim: token_dim,
            token_dim: Some(token_dim),
        },
    }
}

fn sparse_entry_count(vector: &SlotVector) -> Option<usize> {
    match vector {
        SlotVector::Sparse { entries, .. } => Some(entries.len()),
        _ => None,
    }
}

fn sparse_top(vector: &SlotVector, limit: usize) -> Option<Vec<SparseEntryReport>> {
    let SlotVector::Sparse { entries, .. } = vector else {
        return None;
    };
    let mut entries = entries.clone();
    entries.sort_by(|left, right| {
        right
            .val
            .total_cmp(&left.val)
            .then_with(|| left.idx.cmp(&right.idx))
    });
    Some(
        entries
            .into_iter()
            .take(limit)
            .map(|entry| SparseEntryReport {
                idx: entry.idx,
                val: entry.val,
            })
            .collect(),
    )
}

fn sparse_entries_report(entries: &[SparseEntry]) -> Vec<SparseEntryReport> {
    entries
        .iter()
        .map(|entry| SparseEntryReport {
            idx: entry.idx,
            val: entry.val,
        })
        .collect()
}

fn vector_sha256(vector: &SlotVector) -> String {
    let mut hasher = Sha256::new();
    match vector {
        SlotVector::Dense { dim, data } => {
            hasher.update(b"calyx-slot-vector-dense-v1");
            update_u32(&mut hasher, *dim);
            update_u64(&mut hasher, data.len() as u64);
            update_f32s(&mut hasher, data);
        }
        SlotVector::Sparse { dim, entries } => {
            hasher.update(b"calyx-slot-vector-sparse-v1");
            update_u32(&mut hasher, *dim);
            update_u64(&mut hasher, entries.len() as u64);
            for SparseEntry { idx, val } in entries {
                update_u32(&mut hasher, *idx);
                update_f32(&mut hasher, *val);
            }
        }
        SlotVector::Multi { token_dim, tokens } => {
            hasher.update(b"calyx-slot-vector-multi-v1");
            update_u32(&mut hasher, *token_dim);
            update_u64(&mut hasher, tokens.len() as u64);
            for token in tokens {
                update_u64(&mut hasher, token.len() as u64);
                update_f32s(&mut hasher, token);
            }
        }
        SlotVector::Absent { reason } => {
            hasher.update(b"calyx-slot-vector-absent-v1");
            hasher.update(format!("{reason:?}").as_bytes());
        }
    }
    hex_lower(&hasher.finalize())
}

fn update_u32(hasher: &mut Sha256, value: u32) {
    hasher.update(value.to_le_bytes());
}

fn update_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_le_bytes());
}

fn update_f32s(hasher: &mut Sha256, values: &[f32]) {
    for value in values {
        update_f32(hasher, *value);
    }
}

fn update_f32(hasher: &mut Sha256, value: f32) {
    hasher.update(value.to_bits().to_le_bytes());
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut out, "{byte:02x}").expect("hex write");
    }
    out
}

fn token_count(vector: &SlotVector) -> Option<usize> {
    match vector {
        SlotVector::Multi { tokens, .. } => Some(tokens.len()),
        _ => None,
    }
}

fn measure_runtime(spec: &LensSpec, probe: &Input, repeat: usize) -> CliResult<Measurement> {
    match &spec.runtime {
        LensRuntime::StaticLookup { .. } => measure_static_lookup(spec, probe, repeat),
        LensRuntime::TeiHttp { endpoint } => measure_tei(spec, endpoint, probe, repeat),
        LensRuntime::CandleLocal { .. } => measure_candle(spec, probe, repeat),
        LensRuntime::Onnx { .. } | LensRuntime::FastembedDensePlaced { .. } => {
            measure_onnx(spec, probe, repeat)
        }
        LensRuntime::OnnxColbert { .. } => measure_onnx_colbert(spec, probe, repeat),
        LensRuntime::FastembedSparsePlaced { .. } => measure_fastembed_sparse(spec, probe, repeat),
        LensRuntime::FastembedBgem3Placed { .. } => measure_fastembed_bgem3(spec, probe, repeat),
        LensRuntime::FastembedRerankerPlaced { .. } => {
            measure_fastembed_reranker(spec, probe, repeat)
        }
        LensRuntime::FastembedDense { .. }
        | LensRuntime::FastembedSparse { .. }
        | LensRuntime::FastembedBgem3 { .. }
        | LensRuntime::FastembedReranker { .. } => Err(CliError::runtime(
            "CALYX_FASTEMBED_LEGACY_EXECUTION_UNBOUND: recommission this lens with an explicit cuda_fail_loud or cpu_explicit execution policy",
        )),
        LensRuntime::FastembedQwen3 { .. } => measure_fastembed_qwen3(spec, probe, repeat),
        LensRuntime::MultimodalAdapter { .. } => measure_multimodal(spec, probe, repeat),
        other => Err(CliError::usage(format!(
            "calyx lens explain does not support {} runtime measurement",
            runtime_name(other)
        ))),
    }
}

fn full_vector(vector: &SlotVector, enabled: bool) -> CliResult<Option<Vec<f32>>> {
    if !enabled {
        return Ok(None);
    }
    match vector {
        SlotVector::Dense { data, .. } => Ok(Some(data.clone())),
        SlotVector::Sparse { .. } => Ok(None),
        SlotVector::Multi { .. } | SlotVector::Absent { .. } => Err(CliError::usage(
            "--full-vector is supported only for dense or sparse lens explain output",
        )),
    }
}

fn full_sparse(vector: &SlotVector, enabled: bool) -> CliResult<Option<Vec<SparseEntryReport>>> {
    if !enabled {
        return Ok(None);
    }
    match vector {
        SlotVector::Sparse { entries, .. } => Ok(Some(sparse_entries_report(entries))),
        SlotVector::Dense { .. } => Ok(None),
        SlotVector::Multi { .. } | SlotVector::Absent { .. } => Err(CliError::usage(
            "--full-vector is supported only for dense or sparse lens explain output",
        )),
    }
}

fn input_bytes(flags: &Flags) -> CliResult<Vec<u8>> {
    match (&flags.input, &flags.input_file) {
        (Some(_), Some(_)) => Err(CliError::usage(
            "calyx lens explain accepts only one of --input or --input-file",
        )),
        (Some(input), None) => Ok(input.clone().into_bytes()),
        (None, Some(path)) => Ok(fs::read(path)?),
        (None, None) => Ok(b"Calyx lens explain probe".to_vec()),
    }
}

fn measure_static_lookup(spec: &LensSpec, probe: &Input, repeat: usize) -> CliResult<Measurement> {
    let lens = StaticLookupLens::from_lens_spec(spec)?;
    require_runtime_lens_id(spec, &lens)?;
    let repeated = measure_repeated(&lens, probe, repeat)?;
    Ok(Measurement {
        vector: repeated.vector,
        measure_samples_ms: repeated.samples_ms,
        source_tensor_dtype_profile: None,
        declared_model_dtype: lens.dtype().as_str().to_string(),
        local_execution_attestation: None,
        runtime_execution_attestation: None,
        gemm_accumulation_dtype: NOT_APPLICABLE_DTYPE.to_string(),
        output_dtype: OUTPUT_DTYPE.to_string(),
        rows: Some(lens.row_count()),
        artifact_bytes: artifact_files_size(&[
            lens.files().embeddings_file.clone(),
            lens.files().tokenizer.clone(),
        ])?,
        runtime_detail: "static_lookup_mmap".to_string(),
    })
}

fn measure_tei(
    spec: &LensSpec,
    endpoint: &str,
    probe: &Input,
    repeat: usize,
) -> CliResult<Measurement> {
    let lens = TeiHttpLens::new(&spec.name, endpoint, spec.modality, dim(spec.output));
    require_runtime_lens_id(spec, &lens)?;
    let repeated = measure_repeated(&lens, probe, repeat)?;
    Ok(Measurement {
        vector: repeated.vector,
        measure_samples_ms: repeated.samples_ms,
        source_tensor_dtype_profile: None,
        // TEI does not attest model or execution dtype in LensRuntime; #485 owns that contract.
        declared_model_dtype: UNKNOWN_DTYPE.to_string(),
        local_execution_attestation: None,
        runtime_execution_attestation: None,
        gemm_accumulation_dtype: UNKNOWN_DTYPE.to_string(),
        output_dtype: OUTPUT_DTYPE.to_string(),
        rows: None,
        artifact_bytes: 0,
        runtime_detail: endpoint.to_string(),
    })
}

fn measure_candle(spec: &LensSpec, probe: &Input, repeat: usize) -> CliResult<Measurement> {
    let lens = CandleLens::from_lens_spec(spec)?;
    require_runtime_lens_id(spec, &lens)?;
    let repeated = measure_repeated(&lens, probe, repeat)?;
    Ok(Measurement {
        vector: repeated.vector,
        measure_samples_ms: repeated.samples_ms,
        source_tensor_dtype_profile: Some(lens.source_tensor_dtype_profile().clone()),
        declared_model_dtype: match &spec.runtime {
            LensRuntime::CandleLocal { dtype, .. } => dtype.clone(),
            _ => UNKNOWN_DTYPE.to_string(),
        },
        local_execution_attestation: Some(LocalExecutionAttestationReport {
            executable_lens_id: lens.id().to_string(),
            executable_corpus_hash: hex_from_bytes(&lens.contract().corpus_hash()),
            loader_target_dtype: lens.loader_target_dtype().to_string(),
            observed_primary_activation_dtype: lens.observed_primary_activation_dtype().to_string(),
            observed_execution_device: lens.observed_execution_device().to_string(),
            evidence_kind: lens.dtype_attestation_evidence().to_string(),
        }),
        runtime_execution_attestation: None,
        gemm_accumulation_dtype: GEMM_ACCUMULATION_DTYPE.to_string(),
        output_dtype: OUTPUT_DTYPE.to_string(),
        rows: None,
        artifact_bytes: artifact_files_size(&lens.files().artifact_paths())?,
        runtime_detail: lens.device_policy().detail(),
    })
}

fn measure_onnx(spec: &LensSpec, probe: &Input, repeat: usize) -> CliResult<Measurement> {
    let lens = OnnxLens::from_lens_spec(spec)?;
    require_runtime_lens_id(spec, &lens)?;
    let repeated = measure_repeated(&lens, probe, repeat)?;
    let expected_runtime = match &spec.runtime {
        LensRuntime::FastembedDensePlaced { .. } => ONNX_FASTEMBED_RUNTIME_ID,
        LensRuntime::Onnx { .. } => ONNX_CUSTOM_RUNTIME_ID,
        _ => {
            return Err(CliError::from(CalyxError::lens_frozen_violation(
                "measure_onnx received a non-ONNX/non-FastEmbed-dense runtime",
            )));
        }
    };
    let runtime_execution_attestation =
        require_cuda_onnx_execution_attestation(&lens, expected_runtime)?;
    Ok(Measurement {
        vector: repeated.vector,
        measure_samples_ms: repeated.samples_ms,
        source_tensor_dtype_profile: None,
        // ONNX graph and execution dtype are not preserved in LensRuntime; #485 owns that contract.
        declared_model_dtype: UNKNOWN_DTYPE.to_string(),
        local_execution_attestation: None,
        runtime_execution_attestation: Some(runtime_execution_attestation),
        gemm_accumulation_dtype: UNKNOWN_DTYPE.to_string(),
        output_dtype: OUTPUT_DTYPE.to_string(),
        rows: None,
        artifact_bytes: artifact_files_size(&lens.files().artifact_paths())?,
        runtime_detail: format!("{};{}", lens.runtime_name(), lens.provider_policy()),
    })
}

fn measure_onnx_colbert(spec: &LensSpec, probe: &Input, repeat: usize) -> CliResult<Measurement> {
    let lens = OnnxColbertLens::from_lens_spec(spec)?;
    require_runtime_lens_id(spec, &lens)?;
    let repeated = measure_repeated(&lens, probe, repeat)?;
    let runtime_execution_attestation =
        require_cuda_onnx_execution_attestation(&lens, ONNX_COLBERT_RUNTIME_ID)?;
    Ok(Measurement {
        vector: repeated.vector,
        measure_samples_ms: repeated.samples_ms,
        source_tensor_dtype_profile: None,
        declared_model_dtype: UNKNOWN_DTYPE.to_string(),
        local_execution_attestation: None,
        runtime_execution_attestation: Some(runtime_execution_attestation),
        gemm_accumulation_dtype: UNKNOWN_DTYPE.to_string(),
        output_dtype: OUTPUT_DTYPE.to_string(),
        rows: None,
        artifact_bytes: artifact_files_size(&lens.files().artifact_paths())?,
        runtime_detail: format!("onnx-colbert;{}", lens.provider_policy()),
    })
}

fn measure_fastembed_sparse(
    spec: &LensSpec,
    probe: &Input,
    repeat: usize,
) -> CliResult<Measurement> {
    let lens = FastembedSparseLens::from_lens_spec(spec)?;
    require_runtime_lens_id(spec, &lens)?;
    let repeated = measure_repeated(&lens, probe, repeat)?;
    let runtime_execution_attestation =
        require_cuda_onnx_execution_attestation(&lens, ONNX_FASTEMBED_RUNTIME_ID)?;
    Ok(Measurement {
        vector: repeated.vector,
        measure_samples_ms: repeated.samples_ms,
        source_tensor_dtype_profile: None,
        declared_model_dtype: UNKNOWN_DTYPE.to_string(),
        local_execution_attestation: None,
        runtime_execution_attestation: Some(runtime_execution_attestation),
        gemm_accumulation_dtype: UNKNOWN_DTYPE.to_string(),
        output_dtype: OUTPUT_DTYPE.to_string(),
        rows: None,
        artifact_bytes: artifact_files_size(&lens.files().artifact_paths())?,
        runtime_detail: format!("fastembed-sparse;{}", lens.provider_policy()),
    })
}

fn measure_fastembed_bgem3(
    spec: &LensSpec,
    probe: &Input,
    repeat: usize,
) -> CliResult<Measurement> {
    let lens = FastembedBgem3Lens::from_lens_spec(spec)?;
    require_runtime_lens_id(spec, &lens)?;
    let repeated = measure_repeated(&lens, probe, repeat)?;
    let runtime_execution_attestation =
        require_cuda_onnx_execution_attestation(&lens, ONNX_FASTEMBED_RUNTIME_ID)?;
    Ok(Measurement {
        vector: repeated.vector,
        measure_samples_ms: repeated.samples_ms,
        source_tensor_dtype_profile: None,
        declared_model_dtype: UNKNOWN_DTYPE.to_string(),
        local_execution_attestation: None,
        runtime_execution_attestation: Some(runtime_execution_attestation),
        gemm_accumulation_dtype: UNKNOWN_DTYPE.to_string(),
        output_dtype: OUTPUT_DTYPE.to_string(),
        rows: None,
        artifact_bytes: artifact_files_size(&lens.files().artifact_paths())?,
        runtime_detail: format!("{};{}", lens.runtime_name(), lens.provider_policy()),
    })
}

fn measure_fastembed_reranker(
    spec: &LensSpec,
    probe: &Input,
    repeat: usize,
) -> CliResult<Measurement> {
    let lens = FastembedRerankerLens::from_lens_spec(spec)?;
    require_runtime_lens_id(spec, &lens)?;
    let repeated = measure_repeated(&lens, probe, repeat)?;
    let runtime_execution_attestation =
        require_cuda_onnx_execution_attestation(&lens, ONNX_FASTEMBED_RUNTIME_ID)?;
    Ok(Measurement {
        vector: repeated.vector,
        measure_samples_ms: repeated.samples_ms,
        source_tensor_dtype_profile: None,
        declared_model_dtype: UNKNOWN_DTYPE.to_string(),
        local_execution_attestation: None,
        runtime_execution_attestation: Some(runtime_execution_attestation),
        gemm_accumulation_dtype: UNKNOWN_DTYPE.to_string(),
        output_dtype: OUTPUT_DTYPE.to_string(),
        rows: None,
        artifact_bytes: artifact_files_size(&lens.files().artifact_paths())?,
        runtime_detail: format!("fastembed-reranker;{}", lens.provider_policy()),
    })
}

fn measure_fastembed_qwen3(
    spec: &LensSpec,
    probe: &Input,
    repeat: usize,
) -> CliResult<Measurement> {
    let lens = calyx_registry::FastembedQwen3Lens::from_lens_spec(spec)?;
    require_runtime_lens_id(spec, &lens)?;
    let repeated = measure_repeated(&lens, probe, repeat)?;
    Ok(Measurement {
        vector: repeated.vector,
        measure_samples_ms: repeated.samples_ms,
        source_tensor_dtype_profile: Some(lens.source_tensor_dtype_profile().clone()),
        declared_model_dtype: match &spec.runtime {
            LensRuntime::FastembedQwen3 { dtype, .. } => dtype.clone(),
            _ => UNKNOWN_DTYPE.to_string(),
        },
        local_execution_attestation: Some(LocalExecutionAttestationReport {
            executable_lens_id: lens.id().to_string(),
            executable_corpus_hash: hex_from_bytes(&lens.contract().corpus_hash()),
            loader_target_dtype: lens.loader_target_dtype().to_string(),
            observed_primary_activation_dtype: lens.observed_primary_activation_dtype().to_string(),
            observed_execution_device: lens.observed_execution_device().to_string(),
            evidence_kind: lens.dtype_attestation_evidence().to_string(),
        }),
        runtime_execution_attestation: None,
        gemm_accumulation_dtype: GEMM_ACCUMULATION_DTYPE.to_string(),
        output_dtype: OUTPUT_DTYPE.to_string(),
        rows: None,
        artifact_bytes: artifact_files_size(&lens.files().artifact_paths())?,
        runtime_detail: format!(
            "fastembed-qwen3;{};max_tokens={}",
            lens.device_policy().detail(),
            lens.max_tokens()
        ),
    })
}

fn measure_multimodal(spec: &LensSpec, probe: &Input, repeat: usize) -> CliResult<Measurement> {
    let lens = MultimodalAdapterLens::from_lens_spec(spec)?;
    require_runtime_lens_id(spec, &lens)?;
    let repeated = measure_repeated(&lens, probe, repeat)?;
    let artifact_bytes = match &spec.runtime {
        LensRuntime::MultimodalAdapter { files, .. } => artifact_files_size(files)?,
        _ => 0,
    };
    Ok(Measurement {
        vector: repeated.vector,
        measure_samples_ms: repeated.samples_ms,
        source_tensor_dtype_profile: None,
        declared_model_dtype: UNKNOWN_DTYPE.to_string(),
        local_execution_attestation: None,
        runtime_execution_attestation: None,
        gemm_accumulation_dtype: UNKNOWN_DTYPE.to_string(),
        output_dtype: OUTPUT_DTYPE.to_string(),
        rows: None,
        artifact_bytes,
        runtime_detail: format!(
            "multimodal_adapter_onnx_external;{}",
            lens.provider_detail()
        ),
    })
}

fn measure_repeated(
    lens: &dyn Lens,
    probe: &Input,
    repeat: usize,
) -> CliResult<RepeatedMeasurement> {
    let mut last = None;
    let mut samples_ms = Vec::with_capacity(repeat);
    for _ in 0..repeat {
        let started = Instant::now();
        last = Some(lens.measure(probe)?);
        samples_ms.push(started.elapsed().as_secs_f64() * 1000.0);
    }
    let vector = last.ok_or_else(|| CliError::usage("repeat produced no vector"))?;
    Ok(RepeatedMeasurement { vector, samples_ms })
}

fn explain_timing(
    measurement_samples_ms: &[f64],
    end_to_end_total_ms: f64,
    repeat: usize,
) -> CliResult<ExplainTimingReport> {
    const REMEDIATION: &str = "rerun on a host with a working monotonic clock and report the \
         complete CALYX_LENS_EXPLAIN_TIMING_INVALID envelope";

    let invalid = |message: String| {
        CliError::from(CalyxError {
            code: "CALYX_LENS_EXPLAIN_TIMING_INVALID",
            message,
            remediation: REMEDIATION,
        })
    };

    if repeat == 0 || measurement_samples_ms.len() != repeat {
        return Err(invalid(format!(
            "repeat/sample cardinality mismatch: repeat={repeat}, samples={}",
            measurement_samples_ms.len()
        )));
    }
    if !end_to_end_total_ms.is_finite() || end_to_end_total_ms < 0.0 {
        return Err(invalid(format!(
            "end-to-end monotonic duration is invalid: {end_to_end_total_ms}"
        )));
    }
    for (index, sample) in measurement_samples_ms.iter().copied().enumerate() {
        if !sample.is_finite() || sample < 0.0 {
            return Err(invalid(format!(
                "measurement sample {index} is invalid: {sample}"
            )));
        }
    }

    let measurement_total_ms = measurement_samples_ms.iter().sum::<f64>();
    if !measurement_total_ms.is_finite() || measurement_total_ms > end_to_end_total_ms {
        return Err(invalid(format!(
            "nested measurement total {measurement_total_ms} ms exceeds end-to-end total \
             {end_to_end_total_ms} ms"
        )));
    }
    let steady_measurement = if repeat > 1 {
        let steady = &measurement_samples_ms[1..];
        let total_ms = steady.iter().sum::<f64>();
        let min_ms = steady.iter().copied().fold(f64::INFINITY, f64::min);
        let max_ms = steady.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        Some(SteadyTimingReport {
            samples: steady.len(),
            total_ms,
            mean_ms: total_ms / steady.len() as f64,
            min_ms,
            max_ms,
        })
    } else {
        None
    };

    Ok(ExplainTimingReport {
        clock: "std::time::Instant",
        repeat,
        end_to_end_total_ms,
        setup_and_attestation_ms: end_to_end_total_ms - measurement_total_ms,
        measurement_total_ms,
        cold_first_measure_ms: measurement_samples_ms[0],
        steady_measurement,
        measurement_samples_ms: measurement_samples_ms.to_vec(),
    })
}

fn artifact_files_size(files: &[PathBuf]) -> CliResult<u64> {
    files
        .iter()
        .try_fold(0_u64, |acc, path| Ok(acc.saturating_add(path_size(path)?)))
}

fn path_size(path: &Path) -> CliResult<u64> {
    Ok(fs::metadata(path)?.len())
}
