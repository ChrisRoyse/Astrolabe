use std::sync::Arc;

use cudarc::driver::{CudaModule, CudaSlice, LaunchConfig, PushKernelArg};

use crate::cuda::kernels::{TOPK_CUBIN, load_embedded_cubin};
use crate::{CUDA_EXACT_TOPK_MAX_K, CudaContext, ForgeError, Result};

const TOPK_BLOCK: usize = CUDA_EXACT_TOPK_MAX_K;
const TOPK_REMEDIATION: &str =
    "Reject non-finite scores and keep deterministic score/index ordering";
const DEVICE_REMEDIATION: &str =
    "Check CUDA, the attested embedded topk CUBIN, and the configured sm_120a device";

pub fn topk_gpu(
    ctx: &CudaContext,
    scores: &CudaSlice<f32>,
    k: usize,
    n: usize,
) -> Result<Vec<(usize, f32)>> {
    check_device_len(scores.len(), n)?;
    if k == 0 || n == 0 {
        return Ok(Vec::new());
    }
    let mut workspace = CudaTopkWorkspace::new(ctx, n, k)?;
    let selected = workspace.select(ctx, scores)?;
    let mut result = Vec::new();
    result
        .try_reserve_exact(selected.len())
        .map_err(|error| ForgeError::CapacityExhausted {
            operation: "topk_gpu.result".to_string(),
            detail: format!(
                "cuda top-k result reserve failed: requested_items={}: {error}",
                selected.len()
            ),
            remediation: "Free host memory or reduce the requested top-k breadth".to_string(),
        })?;
    result.extend_from_slice(selected);
    Ok(result)
}

/// Reusable exact top-k device and host workspace for a fixed `(n, k)` shape.
/// The scalar8 exact-kNN path constructs this once and reuses it for every
/// query row, so neither device allocation nor result-buffer allocation occurs
/// inside the corpus-sized query loop.
pub(crate) struct CudaTopkWorkspace {
    n: usize,
    k_eff: usize,
    chunk_k: usize,
    chunks: usize,
    out_indices: CudaSlice<i32>,
    out_scores: CudaSlice<f32>,
    host_indices: Vec<i32>,
    host_scores: Vec<f32>,
    merged: Vec<(usize, f32)>,
}

impl CudaTopkWorkspace {
    pub(crate) fn new(ctx: &CudaContext, n: usize, k: usize) -> Result<Self> {
        let (k_eff, chunks, out_len) = topk_shape(n, k)?;
        let stream = ctx.inner().default_stream();
        let out_indices = stream.alloc_zeros(out_len).map_err(|err| {
            device_unavailable(ctx, format!("topk index allocation failed: {err}"))
        })?;
        let out_scores = stream.alloc_zeros(out_len).map_err(|err| {
            device_unavailable(ctx, format!("topk score allocation failed: {err}"))
        })?;
        let mut host_indices = Vec::new();
        host_indices
            .try_reserve_exact(out_len)
            .map_err(|error| ForgeError::CapacityExhausted {
                operation: "scalar8_exact_knn.topk_host_indices".to_string(),
                detail: format!(
                    "scalar8 exact-kNN topk index readback reserve failed: items={out_len}: {error}"
                ),
                remediation: "Free host memory or reduce the declared exact-kNN candidate breadth"
                    .to_string(),
            })?;
        host_indices.resize(out_len, 0_i32);
        let mut host_scores = Vec::new();
        host_scores
            .try_reserve_exact(out_len)
            .map_err(|error| ForgeError::CapacityExhausted {
                operation: "scalar8_exact_knn.topk_host_scores".to_string(),
                detail: format!(
                    "scalar8 exact-kNN topk score readback reserve failed: items={out_len}: {error}"
                ),
                remediation: "Free host memory or reduce the declared exact-kNN candidate breadth"
                    .to_string(),
            })?;
        host_scores.resize(out_len, 0.0_f32);
        let mut merged = Vec::new();
        merged
            .try_reserve_exact(out_len)
            .map_err(|error| ForgeError::CapacityExhausted {
                operation: "scalar8_exact_knn.topk_merge".to_string(),
                detail: format!(
                    "scalar8 exact-kNN topk merge reserve failed: items={out_len}: {error}"
                ),
                remediation: "Free host memory or reduce the declared exact-kNN candidate breadth"
                    .to_string(),
            })?;
        Ok(Self {
            n,
            k_eff,
            chunk_k: k_eff,
            chunks,
            out_indices,
            out_scores,
            host_indices,
            host_scores,
            merged,
        })
    }

    pub(crate) fn device_bytes(&self) -> Result<usize> {
        self.out_indices
            .num_bytes()
            .checked_add(self.out_scores.num_bytes())
            .ok_or_else(|| ForgeError::ShapeMismatch {
                expected: vec![self.out_indices.num_bytes(), self.out_scores.num_bytes()],
                got: vec![usize::MAX],
                remediation: "cuda topk workspace byte sum overflows usize".to_string(),
            })
    }

    pub(crate) fn select(
        &mut self,
        ctx: &CudaContext,
        scores: &CudaSlice<f32>,
    ) -> Result<&[(usize, f32)]> {
        check_device_len(scores.len(), self.n)?;
        launch_topk(
            ctx,
            scores,
            self.n,
            self.chunk_k,
            self.chunks,
            &mut self.out_indices,
            &mut self.out_scores,
        )?;
        let stream = ctx.inner().default_stream();
        stream
            .memcpy_dtoh(&self.out_indices, self.host_indices.as_mut_slice())
            .map_err(|err| device_unavailable(ctx, format!("topk index readback failed: {err}")))?;
        stream
            .memcpy_dtoh(&self.out_scores, self.host_scores.as_mut_slice())
            .map_err(|err| device_unavailable(ctx, format!("topk score readback failed: {err}")))?;
        merge_chunks(
            ctx,
            &self.host_indices,
            &self.host_scores,
            self.n,
            self.k_eff,
            self.chunk_k,
            &mut self.merged,
        )?;
        Ok(&self.merged)
    }
}

fn topk_shape(n: usize, k: usize) -> Result<(usize, usize, usize)> {
    let k_eff = k.min(n);
    if k_eff == 0 {
        return Err(ForgeError::ShapeMismatch {
            expected: vec![1, n],
            got: vec![k, n],
            remediation: "reusable cuda topk workspace requires non-zero n and k".to_string(),
        });
    }
    if k_eff > TOPK_BLOCK {
        return Err(ForgeError::ShapeMismatch {
            expected: vec![TOPK_BLOCK],
            got: vec![k_eff],
            remediation: format!(
                "cuda topk is exact only for global k <= {CUDA_EXACT_TOPK_MAX_K}; reduce the declared candidate breadth or implement and attest a multi-pass exact CUDA merge"
            ),
        });
    }
    let chunks = n.div_ceil(TOPK_BLOCK);
    let out_len = chunks
        .checked_mul(k_eff)
        .ok_or_else(|| ForgeError::ShapeMismatch {
            expected: vec![chunks, k_eff],
            got: vec![usize::MAX],
            remediation: "cuda topk output shape overflows usize".to_string(),
        })?;
    Ok((k_eff, chunks, out_len))
}

pub fn topk_host(ctx: &CudaContext, scores: &[f32], k: usize) -> Result<Vec<(usize, f32)>> {
    if k == 0 || scores.is_empty() {
        return Ok(Vec::new());
    }
    let stream = ctx.inner().default_stream();
    let scores_dev = stream
        .clone_htod(scores)
        .map_err(|err| device_unavailable(ctx, format!("topk scores copy failed: {err}")))?;
    topk_gpu(ctx, &scores_dev, k, scores.len())
}

fn launch_topk(
    ctx: &CudaContext,
    scores: &CudaSlice<f32>,
    n: usize,
    chunk_k: usize,
    chunks: usize,
    out_indices: &mut CudaSlice<i32>,
    out_scores: &mut CudaSlice<f32>,
) -> Result<()> {
    let n_i32 = to_i32(n, "count")?;
    let k_i32 = to_i32(chunk_k, "k")?;
    let chunks_u32 = u32::try_from(chunks).map_err(|_| ForgeError::ShapeMismatch {
        expected: vec![u32::MAX as usize],
        got: vec![chunks],
        remediation: "cuda topk chunk count exceeds grid dimension limit".to_string(),
    })?;
    let module = topk_module(ctx)?;
    let func = module
        .load_function("bitonic_topk_f32")
        .map_err(|err| device_unavailable(ctx, format!("topk load function failed: {err}")))?;
    let stream = ctx.inner().default_stream();
    let cfg = LaunchConfig {
        grid_dim: (chunks_u32, 1, 1),
        block_dim: (TOPK_BLOCK as u32, 1, 1),
        shared_mem_bytes: 0,
    };
    let mut launch = stream.launch_builder(&func);
    unsafe {
        launch
            .arg(scores)
            .arg(&n_i32)
            .arg(&k_i32)
            .arg(out_indices)
            .arg(out_scores)
            .launch(cfg)
    }
    .map_err(|err| device_unavailable(ctx, format!("topk kernel launch failed: {err}")))?;
    stream
        .synchronize()
        .map_err(|err| device_unavailable(ctx, format!("topk stream sync failed: {err}")))?;
    Ok(())
}

fn merge_chunks(
    ctx: &CudaContext,
    indices: &[i32],
    scores: &[f32],
    n: usize,
    k_eff: usize,
    chunk_k: usize,
    pairs: &mut Vec<(usize, f32)>,
) -> Result<()> {
    pairs.clear();
    for chunk in 0..n.div_ceil(TOPK_BLOCK) {
        let chunk_len = (n - chunk * TOPK_BLOCK).min(TOPK_BLOCK);
        let valid = chunk_len.min(chunk_k);
        for offset in 0..valid {
            let pos = chunk * chunk_k + offset;
            let index = indices[pos];
            let score = scores[pos];
            if index < 0 {
                return Err(numerical(
                    "topk_gpu",
                    "NaN score sentinel returned by kernel".to_string(),
                ));
            }
            if !score.is_finite() {
                return Err(numerical(
                    "topk_gpu",
                    format!("non-finite score at output {pos}: {score}"),
                ));
            }
            let index = index as usize;
            if index >= n {
                return Err(device_unavailable(
                    ctx,
                    format!("topk kernel returned out-of-range index {index}"),
                ));
            }
            pairs.push((index, score));
        }
    }
    pairs.sort_by(|left, right| {
        right
            .1
            .total_cmp(&left.1)
            .then_with(|| left.0.cmp(&right.0))
    });
    pairs.truncate(k_eff);
    Ok(())
}

pub(crate) fn topk_module(ctx: &CudaContext) -> Result<Arc<CudaModule>> {
    load_embedded_cubin(ctx, "topk", TOPK_CUBIN, ctx.topk_module_cache())
}

fn check_device_len(actual: usize, expected: usize) -> Result<()> {
    if actual == expected {
        return Ok(());
    }
    Err(ForgeError::ShapeMismatch {
        expected: vec![expected],
        got: vec![actual],
        remediation: "cuda topk scores length must equal n".to_string(),
    })
}

fn to_i32(value: usize, name: &str) -> Result<i32> {
    i32::try_from(value).map_err(|_| ForgeError::ShapeMismatch {
        expected: vec![i32::MAX as usize],
        got: vec![value],
        remediation: format!("cuda topk {name} exceeds i32 kernel argument limit"),
    })
}

fn numerical(op: &'static str, detail: String) -> ForgeError {
    ForgeError::NumericalInvariant {
        op: op.to_string(),
        detail,
        remediation: TOPK_REMEDIATION.to_string(),
    }
}

fn device_unavailable(ctx: &CudaContext, detail: String) -> ForgeError {
    ForgeError::DeviceUnavailable {
        device: format!("cuda:{}", ctx.device_idx()),
        detail,
        remediation: DEVICE_REMEDIATION.to_string(),
    }
}
