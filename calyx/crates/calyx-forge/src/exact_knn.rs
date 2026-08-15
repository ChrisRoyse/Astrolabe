//! Exact scalar8 cosine kNN with one resident CUDA candidate matrix.
//!
//! The input is the physical signed-byte representation already produced by
//! Sextant's scalar8 codec. At `dim <= 1040`, every dot/norm accumulation has
//! magnitude at most `127^2 * 1040 = 16_774_160 < 2^24`, so every integer
//! partial sum is exactly representable by `f32`. This makes the attested
//! fixed-tree CUDA reduction independent of summation order for this domain.

#[cfg(feature = "cuda")]
use std::sync::{Mutex, MutexGuard, OnceLock};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{BackendKind, CUDA_EXACT_TOPK_MAX_K, ForgeError, Result};

const OPERATION: &str = "scalar8_exact_knn";
const RECEIPT_SCHEMA: &str = "calyx.forge.scalar8_exact_knn.v1";
const OBSERVATION_SCHEMA: &str = "calyx.forge.scalar8_exact_knn.observation.v1";
const FAILURE_CODE: &str = "CALYX_FORGE_SCALAR8_EXACT_KNN_FAILED";
const REMEDIATION: &str = "Preserve the exact Forge error and receipt context, verify the scalar8 shape and CUDA attestation, then rerun without changing backend or input bytes";

/// Largest dimension whose worst-case signed-int8 norm sum is below `2^24`.
pub const SCALAR8_EXACT_KNN_MAX_DIM: usize = 1_040;

/// One canonically ranked exact neighbor. The IEEE-754 bits are stored instead
/// of a float so receipts and parity comparisons remain `Eq`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Scalar8ExactKnnNeighbor {
    pub index: usize,
    pub score_f32_bits: u32,
}

impl Scalar8ExactKnnNeighbor {
    pub fn score(&self) -> f32 {
        f32::from_bits(self.score_f32_bits)
    }
}

/// Stable, persisted subset of one loaded CUDA module attestation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Scalar8ExactKnnKernelReceipt {
    pub module_name: String,
    pub source_sha256: String,
    pub module_sha256: String,
    pub module_bytes: u64,
    pub module_kind: String,
    pub target: String,
    pub fmad: bool,
    pub toolkit_version: String,
    pub policy_record_sha256: String,
}

/// Byte-stable execution receipt suitable for persistence and MCP readback.
/// Volatile free-VRAM readings live in [`Scalar8ExactKnnObservation`] so they
/// cannot perturb a deterministic derived generation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Scalar8ExactKnnReceipt {
    pub schema: &'static str,
    pub provider: &'static str,
    pub executor: BackendKind,
    pub algorithm: &'static str,
    pub input_encoding: &'static str,
    pub input_sha256: String,
    pub output_sha256: String,
    pub rows: usize,
    pub dim: usize,
    pub k: usize,
    pub score_evaluations: u64,
    pub coordinate_products: u64,
    pub candidate_upload_bytes: u64,
    pub query_upload_bytes: u64,
    pub topk_readback_bytes: u64,
    pub device_workspace_bytes: u64,
    pub configured_vram_soft_cap_bytes: Option<u64>,
    pub vram_admission: &'static str,
    pub submission_contract: &'static str,
    pub reduction_contract: &'static str,
    pub ordering_contract: &'static str,
    pub runtime_ordinal: Option<u32>,
    pub driver_ordinal: Option<u32>,
    pub physical_device: Option<String>,
    pub device_name: Option<String>,
    pub compute_capability: Option<(i32, i32)>,
    pub selection_authority: Option<String>,
    pub kernels: Vec<Scalar8ExactKnnKernelReceipt>,
}

/// Volatile physical observations returned to the immediate caller and logs.
/// These prove real admission/release but are deliberately excluded from the
/// byte-stable receipt persisted by Weave.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Scalar8ExactKnnObservation {
    pub schema: &'static str,
    pub executor: BackendKind,
    pub device_free_before_bytes: Option<u64>,
    pub device_free_while_workspace_live_bytes: Option<u64>,
    pub device_free_after_release_bytes: Option<u64>,
    pub reserved_bytes: u64,
    pub forge_allocated_while_reserved_bytes: u64,
    pub forge_allocated_after_release_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Scalar8ExactKnnExecution {
    pub neighbors: Vec<Vec<Scalar8ExactKnnNeighbor>>,
    pub receipt: Scalar8ExactKnnReceipt,
    pub observation: Scalar8ExactKnnObservation,
}

/// Explicit CPU oracle for the exact scalar8 contract. Production never
/// selects it automatically after a CUDA failure.
pub fn scalar8_exact_knn_cpu(
    codes: &[i8],
    rows: usize,
    dim: usize,
    k: usize,
) -> Result<Scalar8ExactKnnExecution> {
    validate_input(codes, rows, dim, k)?;
    let mut neighbors = reserve_rows(rows)?;
    let mut scores = reserve_f32(rows, "cpu_score_row")?;
    for source in 0..rows {
        let query = row(codes, source, dim);
        for (target, score) in scores.iter_mut().enumerate() {
            *score = exact_scalar8_cosine(query, row(codes, target, dim));
        }
        let ranked =
            crate::cpu::topk_f32(&scores, k).map_err(|error| phase_error("cpu_topk", error))?;
        neighbors.push(neighbor_row(&ranked, k, source)?);
    }
    let counts = exact_counts(rows, dim)?;
    let receipt = Scalar8ExactKnnReceipt {
        schema: RECEIPT_SCHEMA,
        provider: "calyx-forge",
        executor: BackendKind::Cpu,
        algorithm: "scalar8_exact_cosine_knn",
        input_encoding: "signed_int8_row_major",
        input_sha256: sha256_i8(codes),
        output_sha256: hash_neighbors(&neighbors)?,
        rows,
        dim,
        k,
        score_evaluations: counts.0,
        coordinate_products: counts.1,
        candidate_upload_bytes: 0,
        query_upload_bytes: 0,
        topk_readback_bytes: 0,
        device_workspace_bytes: 0,
        configured_vram_soft_cap_bytes: None,
        vram_admission: "not_applicable_explicit_cpu_oracle",
        submission_contract: "explicit_cpu_caller_thread",
        reduction_contract: "exact_i64_integer_sum_then_f32_sqrt_divide",
        ordering_contract: "score_descending_index_ascending_self_inclusive",
        runtime_ordinal: None,
        driver_ordinal: None,
        physical_device: None,
        device_name: None,
        compute_capability: None,
        selection_authority: None,
        kernels: Vec::new(),
    };
    Ok(Scalar8ExactKnnExecution {
        neighbors,
        receipt,
        observation: Scalar8ExactKnnObservation {
            schema: OBSERVATION_SCHEMA,
            executor: BackendKind::Cpu,
            device_free_before_bytes: None,
            device_free_while_workspace_live_bytes: None,
            device_free_after_release_bytes: None,
            reserved_bytes: 0,
            forge_allocated_while_reserved_bytes: 0,
            forge_allocated_after_release_bytes: 0,
        },
    })
}

#[cfg(feature = "cuda")]
static SCALAR8_CUDA_CONTEXT: OnceLock<Result<std::sync::Arc<crate::CudaContext>>> = OnceLock::new();
#[cfg(feature = "cuda")]
static SCALAR8_CUDA_SUBMISSION: OnceLock<Mutex<()>> = OnceLock::new();

/// Production CUDA exact-kNN. Candidate bytes cross PCIe once, while one query
/// row and bounded chunk-top-k outputs cross per source. There is no CPU
/// fallback: any context, attestation, admission, allocation, kernel, numeric,
/// readback, or cleanup failure returns an error and no result.
#[cfg(feature = "cuda")]
pub fn scalar8_exact_knn_cuda(
    codes: &[i8],
    rows: usize,
    dim: usize,
    k: usize,
) -> Result<Scalar8ExactKnnExecution> {
    use crate::vram::{CudaVramProbe, VramBudgeter};

    validate_input(codes, rows, dim, k)?;
    let _submission = scalar8_cuda_submission()?;
    let context = scalar8_cuda_context()?;
    context
        .inner()
        .check_err()
        .map_err(|error| phase_error("preflight_deferred_error", driver_error(error)))?;
    context
        .attest_physical_identity()
        .map_err(|error| phase_error("preflight_attestation", error))?;
    crate::cuda::distance::distance_module(&context)
        .map_err(|error| phase_error("preflight_distance_module", error))?;
    crate::cuda::topk::topk_module(&context)
        .map_err(|error| phase_error("preflight_topk_module", error))?;
    stable_kernel_receipts(&context)?;

    let workspace_bytes = cuda_workspace_bytes(rows, dim, k)?;
    let budgeter = VramBudgeter::from_env(CudaVramProbe::new(context.clone()))
        .map_err(|error| phase_error("vram_config", error))?;
    let before = budgeter
        .stats()
        .map_err(|error| phase_error("vram_before", error))?;
    let reservation = budgeter
        .reserve(workspace_bytes)
        .map_err(|error| phase_error("vram_admission", error))?;
    let reserved = budgeter
        .stats()
        .map_err(|error| phase_error("vram_reserved", error))?;

    let run = run_cuda_workspace(&context, codes, rows, dim, k);
    let cleanup = finalize_cuda_workspace(&context);
    let post_attestation = context.attest_physical_identity();
    let while_reserved = budgeter.stats();
    drop(reservation);
    let after_release = budgeter.stats();

    let run = finish_cuda_transaction(
        run,
        cleanup,
        post_attestation,
        while_reserved.as_ref().map(|_| ()).map_err(Clone::clone),
        after_release.as_ref().map(|_| ()).map_err(Clone::clone),
    )?;
    let while_reserved =
        while_reserved.map_err(|error| phase_error("while_reserved_readback", error))?;
    let after_release =
        after_release.map_err(|error| phase_error("after_release_readback", error))?;
    if after_release.allocated_bytes != 0 || after_release.serving_allocated_bytes != 0 {
        return Err(operation_failure(
            "vram_release_readback",
            format!(
                "Forge reservation remained after release: total={} serving={}",
                after_release.allocated_bytes, after_release.serving_allocated_bytes
            ),
        ));
    }

    let kernels = stable_kernel_receipts(&context)?;
    let counts = exact_counts(rows, dim)?;
    let transfer = cuda_transfer_bytes(rows, dim, k)?;
    let receipt = Scalar8ExactKnnReceipt {
        schema: RECEIPT_SCHEMA,
        provider: "calyx-forge",
        executor: BackendKind::Cuda,
        algorithm: "scalar8_exact_cosine_knn",
        input_encoding: "signed_int8_row_major",
        input_sha256: sha256_i8(codes),
        output_sha256: hash_neighbors(&run.neighbors)?,
        rows,
        dim,
        k,
        score_evaluations: counts.0,
        coordinate_products: counts.1,
        candidate_upload_bytes: transfer.0,
        query_upload_bytes: transfer.1,
        topk_readback_bytes: transfer.2,
        device_workspace_bytes: u64_value(workspace_bytes, "device workspace")?,
        configured_vram_soft_cap_bytes: Some(u64_value(
            before.soft_cap_bytes,
            "configured VRAM soft cap",
        )?),
        vram_admission: "live_cuda_mem_get_info_plus_forge_soft_cap",
        submission_contract: "process_serial_attested_context_default_stream",
        reduction_contract: "attested_f32_fixed_tree_exact_signed_int8_domain_dim_le_1040",
        ordering_contract: "score_descending_index_ascending_self_inclusive",
        runtime_ordinal: Some(context.runtime_ordinal()),
        driver_ordinal: Some(context.driver_ordinal()),
        physical_device: Some(context.physical_identity().canonical_execution_token()),
        device_name: Some(context.name().to_string()),
        compute_capability: Some(context.compute_capability()),
        selection_authority: Some(context.selection_authority().to_string()),
        kernels,
    };
    Ok(Scalar8ExactKnnExecution {
        neighbors: run.neighbors,
        receipt,
        observation: Scalar8ExactKnnObservation {
            schema: OBSERVATION_SCHEMA,
            executor: BackendKind::Cuda,
            device_free_before_bytes: Some(u64_value(
                before.device_free_bytes,
                "free VRAM before",
            )?),
            device_free_while_workspace_live_bytes: Some(u64_value(
                run.device_free_while_workspace_live_bytes,
                "free VRAM while CUDA workspace live",
            )?),
            device_free_after_release_bytes: Some(u64_value(
                after_release.device_free_bytes,
                "free VRAM after release",
            )?),
            reserved_bytes: u64_value(reserved.allocated_bytes, "reserved VRAM")?,
            forge_allocated_while_reserved_bytes: u64_value(
                while_reserved.allocated_bytes,
                "Forge allocated VRAM while reserved",
            )?,
            forge_allocated_after_release_bytes: u64_value(
                after_release.allocated_bytes,
                "Forge allocated VRAM after release",
            )?,
        },
    })
}

#[cfg(feature = "cuda")]
fn scalar8_cuda_submission() -> Result<MutexGuard<'static, ()>> {
    SCALAR8_CUDA_SUBMISSION
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|error| {
            operation_failure(
                "submission_admission",
                format!(
                    "process-serial CUDA submission state is poisoned by an earlier panic: {error}"
                ),
            )
        })
}

#[cfg(feature = "cuda")]
fn scalar8_cuda_context() -> Result<std::sync::Arc<crate::CudaContext>> {
    SCALAR8_CUDA_CONTEXT
        .get_or_init(|| {
            let runtime_ordinal = crate::configured_cuda_runtime_ordinal()?;
            let context = crate::init_cuda_native_kernel(runtime_ordinal, true)?;
            context.attest_physical_identity()?;
            Ok(std::sync::Arc::new(context))
        })
        .clone()
        .map_err(|error| phase_error("context_initialize", error))
}

#[cfg(feature = "cuda")]
fn run_cuda_workspace(
    context: &crate::CudaContext,
    codes: &[i8],
    rows: usize,
    dim: usize,
    k: usize,
) -> Result<CudaWorkspaceRun> {
    use crate::cuda::distance::cosine_batch_gpu_validated_scalar8;
    use crate::cuda::topk::CudaTopkWorkspace;

    let stream = context.inner().default_stream();
    let mut values = reserve_f32(codes.len(), "cuda_candidate_staging")?;
    for (target, code) in values.iter_mut().zip(codes) {
        *target = f32::from(*code);
    }
    let candidates = stream.clone_htod(&values).map_err(|error| {
        phase_error(
            "candidate_upload",
            driver_error_with_context(context, error),
        )
    })?;
    drop(values);
    let mut query = stream.alloc_zeros(dim).map_err(|error| {
        phase_error("query_allocate", driver_error_with_context(context, error))
    })?;
    let mut scores = stream.alloc_zeros(rows).map_err(|error| {
        phase_error("score_allocate", driver_error_with_context(context, error))
    })?;
    let mut topk = CudaTopkWorkspace::new(context, rows, k)
        .map_err(|error| phase_error("topk_workspace_allocate", error))?;
    let topk_device_bytes = topk
        .device_bytes()
        .map_err(|error| phase_error("workspace_readback", error))?;
    let expected_workspace = candidates
        .num_bytes()
        .checked_add(query.num_bytes())
        .and_then(|value| value.checked_add(scores.num_bytes()))
        .and_then(|value| value.checked_add(topk_device_bytes))
        .ok_or_else(|| operation_failure("workspace_readback", "workspace byte sum overflow"))?;
    let declared_workspace = cuda_workspace_bytes(rows, dim, k)?;
    if expected_workspace != declared_workspace {
        return Err(operation_failure(
            "workspace_readback",
            format!(
                "allocated workspace differs from admission: observed={expected_workspace} declared={declared_workspace}"
            ),
        ));
    }
    let mut neighbors = reserve_rows(rows)?;
    let mut query_f32 = [0.0_f32; SCALAR8_EXACT_KNN_MAX_DIM];
    for source in 0..rows {
        context
            .attest_execution_identity()
            .map_err(|error| phase_error("query_identity", error))?;
        let query_values = row(codes, source, dim);
        for (target, code) in query_f32[..dim].iter_mut().zip(query_values) {
            *target = f32::from(*code);
        }
        stream
            .memcpy_htod(&query_f32[..dim], &mut query)
            .map_err(|error| {
                phase_error("query_upload", driver_error_with_context(context, error))
            })?;
        cosine_batch_gpu_validated_scalar8(context, &query, &candidates, dim, rows, &mut scores)
            .map_err(|error| phase_error("cosine_dispatch", error))?;
        let ranked = topk
            .select(context, &scores)
            .map_err(|error| phase_error("topk_dispatch_readback", error))?;
        if ranked.is_empty() {
            return Err(operation_failure(
                "topk_readback",
                "non-empty exact-kNN request produced an empty top-k workspace",
            ));
        }
        neighbors.push(neighbor_row(ranked, k, source)?);
    }
    let device_free_while_workspace_live_bytes = context
        .free_device_vram_bytes()
        .map_err(|error| phase_error("workspace_live_vram_readback", error))?;
    Ok(CudaWorkspaceRun {
        neighbors,
        device_free_while_workspace_live_bytes,
    })
}

#[cfg(feature = "cuda")]
struct CudaWorkspaceRun {
    neighbors: Vec<Vec<Scalar8ExactKnnNeighbor>>,
    device_free_while_workspace_live_bytes: usize,
}

#[cfg(feature = "cuda")]
fn finalize_cuda_workspace(context: &crate::CudaContext) -> Result<()> {
    let sync = context.inner().default_stream().synchronize();
    let deferred = context.inner().check_err();
    match (sync, deferred) {
        (Ok(()), Ok(())) => Ok(()),
        (sync, deferred) => Err(operation_failure(
            "workspace_release",
            format!(
                "CUDA workspace cleanup failed: stream_sync={:?} deferred_drop_error={:?}",
                sync.err(),
                deferred.err()
            ),
        )),
    }
}

#[cfg(feature = "cuda")]
fn finish_cuda_transaction(
    run: Result<CudaWorkspaceRun>,
    cleanup: Result<()>,
    post_attestation: Result<()>,
    while_reserved: Result<()>,
    after_release: Result<()>,
) -> Result<CudaWorkspaceRun> {
    let mut failures = Vec::new();
    let completed = match run {
        Ok(completed) => Some(completed),
        Err(error) => {
            failures.push(format!("run[{}]={error}", error.code()));
            None
        }
    };
    for (phase, result) in [
        ("cleanup", cleanup),
        ("post_attestation", post_attestation),
        ("while_reserved_readback", while_reserved),
        ("after_release_readback", after_release),
    ] {
        if let Err(error) = result {
            failures.push(format!("{phase}[{}]={error}", error.code()));
        }
    }
    if !failures.is_empty() {
        return Err(operation_failure(
            "transaction_finalize",
            failures.join(" | "),
        ));
    }
    completed.ok_or_else(|| {
        operation_failure(
            "transaction_finalize",
            "transaction reported no failure and no neighbor result",
        )
    })
}

#[cfg(feature = "cuda")]
fn stable_kernel_receipts(
    context: &crate::CudaContext,
) -> Result<Vec<Scalar8ExactKnnKernelReceipt>> {
    let loaded = context
        .loaded_kernel_modules()
        .map_err(|error| phase_error("kernel_attestation_readback", error))?;
    let mut receipts = Vec::new();
    receipts
        .try_reserve_exact(2)
        .map_err(|error| capacity_error("kernel_receipts", 2, error))?;
    for name in ["distance", "topk"] {
        let module = loaded
            .iter()
            .find(|module| module.module_name == name)
            .ok_or_else(|| {
                operation_failure(
                    "kernel_attestation_readback",
                    format!("required loaded module {name} is absent"),
                )
            })?;
        receipts.push(Scalar8ExactKnnKernelReceipt {
            module_name: module.module_name.to_string(),
            source_sha256: module.source_sha256.to_string(),
            module_sha256: module.module_sha256.to_string(),
            module_bytes: module.module_bytes,
            module_kind: module.module_kind.to_string(),
            target: module.target.to_string(),
            fmad: module.fmad,
            toolkit_version: module.toolkit_version.to_string(),
            policy_record_sha256: module.policy_record_sha256.to_string(),
        });
    }
    Ok(receipts)
}

fn validate_input(codes: &[i8], rows: usize, dim: usize, k: usize) -> Result<()> {
    if rows == 0 || dim == 0 || k == 0 {
        return Err(ForgeError::ShapeMismatch {
            expected: vec![1, 1, 1],
            got: vec![rows, dim, k],
            remediation: "scalar8 exact-kNN requires non-zero rows, dim, and k".to_string(),
        });
    }
    if dim > SCALAR8_EXACT_KNN_MAX_DIM {
        return Err(ForgeError::ShapeMismatch {
            expected: vec![SCALAR8_EXACT_KNN_MAX_DIM],
            got: vec![dim],
            remediation: "use a separately attested wider-accumulator exact-kNN kernel before increasing the scalar8 dimension limit".to_string(),
        });
    }
    if k > rows || k > CUDA_EXACT_TOPK_MAX_K {
        return Err(ForgeError::ShapeMismatch {
            expected: vec![rows.min(CUDA_EXACT_TOPK_MAX_K)],
            got: vec![k],
            remediation: format!(
                "scalar8 exact-kNN requires k <= rows and k <= {CUDA_EXACT_TOPK_MAX_K}"
            ),
        });
    }
    let expected = rows
        .checked_mul(dim)
        .ok_or_else(|| ForgeError::ShapeMismatch {
            expected: vec![rows, dim],
            got: vec![codes.len()],
            remediation: "scalar8 exact-kNN rows*dim overflows usize".to_string(),
        })?;
    if codes.len() != expected {
        return Err(ForgeError::ShapeMismatch {
            expected: vec![expected],
            got: vec![codes.len()],
            remediation: "scalar8 exact-kNN input must contain exactly rows*dim signed bytes"
                .to_string(),
        });
    }
    i32::try_from(rows).map_err(|_| ForgeError::ShapeMismatch {
        expected: vec![i32::MAX as usize],
        got: vec![rows],
        remediation: "scalar8 exact-kNN row count exceeds CUDA kernel index range".to_string(),
    })?;
    for ordinal in 0..rows {
        let norm_sq = row(codes, ordinal, dim)
            .iter()
            .map(|value| i64::from(*value) * i64::from(*value))
            .sum::<i64>();
        if norm_sq == 0 {
            return Err(ForgeError::NumericalInvariant {
                op: OPERATION.to_string(),
                detail: format!("zero-norm scalar8 row at ordinal {ordinal}"),
                remediation: "remove the zero-norm row before candidate generation; never publish a sentinel score".to_string(),
            });
        }
        if norm_sq >= (1_i64 << 24) {
            return Err(ForgeError::NumericalInvariant {
                op: OPERATION.to_string(),
                detail: format!(
                    "scalar8 norm exceeds exact f32 integer domain at ordinal {ordinal}: norm_sq={norm_sq}"
                ),
                remediation: "use a separately attested wider-accumulator exact-kNN kernel for this input domain".to_string(),
            });
        }
    }
    Ok(())
}

fn exact_scalar8_cosine(left: &[i8], right: &[i8]) -> f32 {
    let mut dot = 0_i64;
    let mut left_norm = 0_i64;
    let mut right_norm = 0_i64;
    for (&a, &b) in left.iter().zip(right) {
        dot += i64::from(a) * i64::from(b);
        left_norm += i64::from(a) * i64::from(a);
        right_norm += i64::from(b) * i64::from(b);
    }
    (dot as f32) / ((left_norm as f32).sqrt() * (right_norm as f32).sqrt())
}

fn row(values: &[i8], ordinal: usize, dim: usize) -> &[i8] {
    let start = ordinal * dim;
    &values[start..start + dim]
}

fn neighbor_row(
    ranked: &[(usize, f32)],
    k: usize,
    source: usize,
) -> Result<Vec<Scalar8ExactKnnNeighbor>> {
    if ranked.len() != k {
        return Err(operation_failure(
            "topk_readback",
            format!(
                "source={source} returned {} neighbors, expected {k}",
                ranked.len()
            ),
        ));
    }
    let mut out = Vec::new();
    out.try_reserve_exact(k)
        .map_err(|error| capacity_error("neighbor_row", k, error))?;
    for &(index, score) in ranked {
        if !score.is_finite() {
            return Err(ForgeError::NumericalInvariant {
                op: OPERATION.to_string(),
                detail: format!(
                    "non-finite top-k score for source={source}, target={index}: {score}"
                ),
                remediation: REMEDIATION.to_string(),
            });
        }
        out.push(Scalar8ExactKnnNeighbor {
            index,
            score_f32_bits: score.to_bits(),
        });
    }
    Ok(out)
}

fn reserve_rows(rows: usize) -> Result<Vec<Vec<Scalar8ExactKnnNeighbor>>> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(rows)
        .map_err(|error| capacity_error("neighbor_rows", rows, error))?;
    Ok(result)
}

fn reserve_f32(items: usize, component: &str) -> Result<Vec<f32>> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(items)
        .map_err(|error| capacity_error(component, items, error))?;
    values.resize(items, 0.0);
    Ok(values)
}

fn exact_counts(rows: usize, dim: usize) -> Result<(u64, u64)> {
    let rows = u64_value(rows, "rows")?;
    let dim = u64_value(dim, "dim")?;
    let evaluations = rows.checked_mul(rows).ok_or_else(|| {
        operation_failure("receipt_counts", "score evaluation count overflows u64")
    })?;
    let products = evaluations.checked_mul(dim).ok_or_else(|| {
        operation_failure("receipt_counts", "coordinate product count overflows u64")
    })?;
    Ok((evaluations, products))
}

#[cfg(feature = "cuda")]
fn cuda_workspace_bytes(rows: usize, dim: usize, k: usize) -> Result<usize> {
    let matrix_items = rows
        .checked_mul(dim)
        .ok_or_else(|| operation_failure("workspace_shape", "rows*dim overflows usize"))?;
    let chunks = rows.div_ceil(CUDA_EXACT_TOPK_MAX_K);
    let topk_items = chunks
        .checked_mul(k)
        .ok_or_else(|| operation_failure("workspace_shape", "chunks*k overflows usize"))?;
    let f32_items = matrix_items
        .checked_add(dim)
        .and_then(|value| value.checked_add(rows))
        .and_then(|value| value.checked_add(topk_items))
        .ok_or_else(|| {
            operation_failure("workspace_shape", "f32 workspace items overflow usize")
        })?;
    f32_items
        .checked_mul(std::mem::size_of::<f32>())
        .and_then(|value| {
            topk_items
                .checked_mul(std::mem::size_of::<i32>())
                .and_then(|indices| value.checked_add(indices))
        })
        .ok_or_else(|| operation_failure("workspace_shape", "workspace bytes overflow usize"))
}

#[cfg(feature = "cuda")]
fn cuda_transfer_bytes(rows: usize, dim: usize, k: usize) -> Result<(u64, u64, u64)> {
    let matrix_items = rows
        .checked_mul(dim)
        .ok_or_else(|| operation_failure("transfer_shape", "rows*dim overflows usize"))?;
    let candidate = matrix_items
        .checked_mul(std::mem::size_of::<f32>())
        .ok_or_else(|| operation_failure("transfer_shape", "candidate bytes overflow usize"))?;
    let query = candidate;
    let chunks = rows.div_ceil(CUDA_EXACT_TOPK_MAX_K);
    let per_query = chunks
        .checked_mul(k)
        .and_then(|items| {
            items.checked_mul(std::mem::size_of::<i32>() + std::mem::size_of::<f32>())
        })
        .ok_or_else(|| operation_failure("transfer_shape", "top-k row bytes overflow usize"))?;
    let readback = rows.checked_mul(per_query).ok_or_else(|| {
        operation_failure("transfer_shape", "top-k readback bytes overflow usize")
    })?;
    Ok((
        u64_value(candidate, "candidate upload")?,
        u64_value(query, "query upload")?,
        u64_value(readback, "top-k readback")?,
    ))
}

fn sha256_i8(values: &[i8]) -> String {
    // SAFETY: `i8` and `u8` have identical size/alignment and every bit pattern
    // is valid; the byte slice is immutable and cannot outlive `values`.
    let bytes = unsafe { std::slice::from_raw_parts(values.as_ptr().cast::<u8>(), values.len()) };
    format!("{:x}", Sha256::digest(bytes))
}

fn hash_neighbors(rows: &[Vec<Scalar8ExactKnnNeighbor>]) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(u64_value(rows.len(), "neighbor row count")?.to_be_bytes());
    for row in rows {
        hasher.update(u64_value(row.len(), "neighbor row width")?.to_be_bytes());
        for neighbor in row {
            hasher.update(u64_value(neighbor.index, "neighbor index")?.to_be_bytes());
            hasher.update(neighbor.score_f32_bits.to_be_bytes());
        }
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn u64_value(value: usize, component: &str) -> Result<u64> {
    u64::try_from(value).map_err(|_| {
        operation_failure(
            "receipt_conversion",
            format!("{component} does not fit u64: {value}"),
        )
    })
}

fn capacity_error(
    operation: &str,
    requested_items: usize,
    error: impl std::fmt::Display,
) -> ForgeError {
    ForgeError::CapacityExhausted {
        operation: format!("{OPERATION}.{operation}"),
        detail: format!("requested_items={requested_items}: {error}"),
        remediation: "Free host memory or reduce the exact-kNN pool/breadth before retrying"
            .to_string(),
    }
}

fn phase_error(phase: &'static str, cause: ForgeError) -> ForgeError {
    operation_failure(phase, format!("cause_code={} cause={cause}", cause.code()))
}

fn operation_failure(phase: &'static str, detail: impl Into<String>) -> ForgeError {
    ForgeError::OperationFailure {
        code: FAILURE_CODE,
        operation: OPERATION,
        phase,
        detail: detail.into(),
        remediation: REMEDIATION.to_string(),
    }
}

#[cfg(feature = "cuda")]
fn driver_error(error: cudarc::driver::result::DriverError) -> ForgeError {
    ForgeError::GpuError {
        detail: format!("CUDA driver error: {error}"),
        remediation: REMEDIATION.to_string(),
    }
}

#[cfg(feature = "cuda")]
fn driver_error_with_context(
    context: &crate::CudaContext,
    error: cudarc::driver::result::DriverError,
) -> ForgeError {
    ForgeError::DeviceUnavailable {
        device: context.physical_identity().canonical_execution_token(),
        detail: format!("CUDA driver error: {error}"),
        remediation: REMEDIATION.to_string(),
    }
}
