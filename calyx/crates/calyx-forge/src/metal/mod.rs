//! Metal compute backend for Apple Silicon (#895).
//!
//! # Why this exists
//!
//! `calyx-forge` shipped a CPU backend (SIMD via `wide`) and a CUDA backend.
//! On Apple Silicon the CUDA path is unreachable, so every Forge operation ran
//! on the CPU. This backend puts the O(rows x dim) and O(m x k x n) work on the
//! integrated GPU instead.
//!
//! # Numerical contract — read before enabling
//!
//! This backend is **opt-in and never substituted automatically**. Its results
//! agree with the CPU backend to floating-point tolerance but are **not
//! bit-identical**, because a GPU reduction accumulates in tree order while
//! `cpu::distance` accumulates in ascending-offset chunk order. Float addition
//! is not associative, so the two orders legitimately differ in the last ulp.
//!
//! That matters here: Calyx proves determinism by comparing repeated real runs
//! byte-for-byte. This backend is deterministic *run to run on the same
//! device* — the kernels have fixed dispatch geometry and no atomics — but a
//! vault written with the Metal backend will not byte-match one written with
//! the CPU backend. Choosing a backend is therefore a decision about the
//! artifact, not a transparent optimisation, and nothing here falls back to the
//! CPU silently. If the device or a kernel is unavailable, construction fails
//! with a structured error and the caller decides.
//!
//! # Validation
//!
//! Input validation (shape, finiteness, positive norms) runs on the host using
//! the exact same guard functions the CPU backend uses, *before* any dispatch.
//! This keeps the fail-closed error surface identical — same error variants,
//! same offending row indices — rather than reimplementing checks in MSL where
//! a refusal would be hard to attribute.
//!
//! # Memory
//!
//! Apple Silicon is a unified-memory architecture, so buffers use
//! `MTLResourceOptions::StorageModeShared`: the CPU and GPU address the same
//! physical pages and there is no staging copy in either direction.

use std::sync::Mutex;

use metal::{
    Buffer, CommandQueue, ComputePipelineState, Device, MTLResourceOptions, MTLSize,
    NSUInteger,
};

use crate::backend::{Backend, BackendKind, DeviceInfo, Result};
use crate::cpu::guard::{check_finite, check_norm_positive, check_shape_2d};
use crate::error::ForgeError;

/// Threadgroup width for the row-reduction kernels: 8 SIMD groups of 32 lanes.
/// Must stay consistent with SIMD_WIDTH * SIMD_PER_TG in `kernels.metal`.
const REDUCE_THREADGROUP: NSUInteger = 256;

/// Rows retired per threadgroup — one per SIMD group. Must equal ROWS_PER_TG in
/// `kernels.metal`.
const ROWS_PER_THREADGROUP: NSUInteger = 8;

/// Tile edge for the blocked GEMM. Must equal `GEMM_TILE` in `kernels.metal`.
const GEMM_TILE: NSUInteger = 16;

const KERNEL_SOURCE: &str = include_str!("kernels.metal");

fn gpu_error(detail: impl Into<String>, remediation: impl Into<String>) -> ForgeError {
    ForgeError::GpuError {
        detail: detail.into(),
        remediation: remediation.into(),
    }
}

/// Compiled pipelines, resolved once at construction so a missing kernel is a
/// construction-time failure rather than a surprise mid-workload.
struct Pipelines {
    gemm: ComputePipelineState,
    dot: ComputePipelineState,
    l2: ComputePipelineState,
    cosine_parts: ComputePipelineState,
    row_norms_sq: ComputePipelineState,
    scale_rows: ComputePipelineState,
}

pub struct MetalBackend {
    device: Device,
    // MTLCommandQueue is thread-safe in Metal, but the `metal` crate's handle is
    // not Sync; the Backend trait requires Send + Sync, so serialise access.
    queue: Mutex<CommandQueue>,
    pipelines: Pipelines,
    name: String,
    vram_mib: Option<u64>,
}

// SAFETY: every Metal object held here is an Objective-C class instance that
// Metal documents as safe to use from multiple threads; the only handle without
// interior synchronisation in the Rust wrapper (the command queue) is behind a
// Mutex. Buffers are created and consumed entirely within a single method call.
unsafe impl Send for MetalBackend {}
unsafe impl Sync for MetalBackend {}

impl MetalBackend {
    pub fn new() -> Result<Self> {
        let device = Device::system_default().ok_or_else(|| ForgeError::DeviceUnavailable {
            device: "metal".to_string(),
            detail: "no default Metal device is present".to_string(),
            remediation: "run on a Mac with a Metal-capable GPU, or select the CPU backend"
                .to_string(),
        })?;

        let options = metal::CompileOptions::new();
        let library = device
            .new_library_with_source(KERNEL_SOURCE, &options)
            .map_err(|error| {
                gpu_error(
                    format!("Metal kernel library failed to compile: {error}"),
                    "inspect kernels.metal against the Metal Shading Language version this OS ships",
                )
            })?;

        let pipeline = |name: &str| -> Result<ComputePipelineState> {
            let function = library.get_function(name, None).map_err(|error| {
                gpu_error(
                    format!("Metal kernel '{name}' is missing from the compiled library: {error}"),
                    "rebuild calyx-forge so kernels.metal matches the pipelines requested here",
                )
            })?;
            device
                .new_compute_pipeline_state_with_function(&function)
                .map_err(|error| {
                    gpu_error(
                        format!("Metal pipeline for '{name}' failed to build: {error}"),
                        "inspect the kernel signature and this device's feature set",
                    )
                })
        };

        let pipelines = Pipelines {
            gemm: pipeline("gemm_f32")?,
            dot: pipeline("dot_batch")?,
            l2: pipeline("l2_batch")?,
            cosine_parts: pipeline("cosine_parts")?,
            row_norms_sq: pipeline("row_norms_sq")?,
            scale_rows: pipeline("scale_rows")?,
        };

        let name = device.name().to_string();
        // Unified memory: report the working-set limit the driver will grant.
        let vram_mib = Some(device.recommended_max_working_set_size() / (1024 * 1024));
        let queue = Mutex::new(device.new_command_queue());

        Ok(Self {
            device,
            queue,
            pipelines,
            name,
            vram_mib,
        })
    }

    /// Shared-storage buffer aliasing `data` without a staging copy.
    fn buffer_from(&self, data: &[f32]) -> Result<Buffer> {
        // A zero-length MTLBuffer is invalid; callers guard against empty work
        // before reaching here, but keep the refusal explicit rather than
        // letting Metal fault.
        if data.is_empty() {
            return Err(gpu_error(
                "refusing to create a zero-length Metal buffer",
                "guard empty inputs before dispatching to the GPU",
            ));
        }
        Ok(self.device.new_buffer_with_data(
            data.as_ptr().cast(),
            std::mem::size_of_val(data) as NSUInteger,
            MTLResourceOptions::StorageModeShared,
        ))
    }

    fn buffer_zeroed(&self, len: usize) -> Result<Buffer> {
        if len == 0 {
            return Err(gpu_error(
                "refusing to create a zero-length Metal buffer",
                "guard empty inputs before dispatching to the GPU",
            ));
        }
        Ok(self.device.new_buffer(
            (len * std::mem::size_of::<f32>()) as NSUInteger,
            MTLResourceOptions::StorageModeShared,
        ))
    }

    /// Read a shared buffer back as `f32`. Safe because the buffer was created
    /// with `StorageModeShared` and the GPU work has been waited on.
    fn read_back(buffer: &Buffer, len: usize) -> Vec<f32> {
        // SAFETY: shared storage means `contents()` is a live host pointer to
        // `len` f32 written by the completed dispatch.
        unsafe { std::slice::from_raw_parts(buffer.contents().cast::<f32>(), len).to_vec() }
    }

    /// One SIMD group per row, `ROWS_PER_THREADGROUP` rows per threadgroup.
    ///
    /// The kernels reduce with `simd_sum()`, so there are no threadgroup
    /// barriers and no threadgroup memory; the dispatch just has to hand each
    /// SIMD group its own row. Threadgroup count is therefore ceil(rows / 8),
    /// not `rows`.
    fn dispatch_row_reduction(
        &self,
        pipeline: &ComputePipelineState,
        buffers: &[(&Buffer, NSUInteger)],
        dims: [u32; 2],
        rows: usize,
    ) -> Result<()> {
        let queue = self
            .queue
            .lock()
            .map_err(|_| gpu_error("Metal command queue mutex poisoned", "restart the process"))?;
        let command = queue.new_command_buffer();
        let encoder = command.new_compute_command_encoder();
        encoder.set_compute_pipeline_state(pipeline);
        for (buffer, index) in buffers {
            encoder.set_buffer(*index, Some(buffer), 0);
        }
        encoder.set_bytes(
            buffers.len() as NSUInteger,
            std::mem::size_of_val(&dims) as NSUInteger,
            dims.as_ptr().cast(),
        );
        encoder.dispatch_thread_groups(
            MTLSize::new((rows as NSUInteger).div_ceil(ROWS_PER_THREADGROUP), 1, 1),
            MTLSize::new(REDUCE_THREADGROUP, 1, 1),
        );
        encoder.end_encoding();
        command.commit();
        command.wait_until_completed();
        Ok(())
    }
}

impl Backend for MetalBackend {
    fn gemm(
        &self,
        a: &[f32],
        b: &[f32],
        m: usize,
        k: usize,
        n: usize,
        out: &mut [f32],
    ) -> Result<()> {
        check_shape_2d(a, m, k, "gemm a")?;
        check_shape_2d(b, k, n, "gemm b")?;
        check_shape_2d(out, m, n, "gemm out")?;
        check_finite(a, "gemm")?;
        check_finite(b, "gemm")?;

        out.fill(0.0);
        if m == 0 || n == 0 || k == 0 {
            return Ok(());
        }

        let a_buf = self.buffer_from(a)?;
        let b_buf = self.buffer_from(b)?;
        let out_buf = self.buffer_zeroed(m * n)?;
        // 4 elements, not 3: MSL uint3 occupies 16 bytes, so uploading 12 would
        // leave the kernel reading n from past the end of the buffer.
        let dims: [u32; 4] = [
            u32::try_from(m).map_err(|_| gpu_error("gemm m exceeds u32", "reduce batch size"))?,
            u32::try_from(k).map_err(|_| gpu_error("gemm k exceeds u32", "reduce dimension"))?,
            u32::try_from(n).map_err(|_| gpu_error("gemm n exceeds u32", "reduce batch size"))?,
            0,
        ];

        {
            let queue = self.queue.lock().map_err(|_| {
                gpu_error("Metal command queue mutex poisoned", "restart the process")
            })?;
            let command = queue.new_command_buffer();
            let encoder = command.new_compute_command_encoder();
            encoder.set_compute_pipeline_state(&self.pipelines.gemm);
            encoder.set_buffer(0, Some(&a_buf), 0);
            encoder.set_buffer(1, Some(&b_buf), 0);
            encoder.set_buffer(2, Some(&out_buf), 0);
            encoder.set_bytes(
                3,
                std::mem::size_of_val(&dims) as NSUInteger,
                dims.as_ptr().cast(),
            );
            let groups_x = (n as NSUInteger).div_ceil(GEMM_TILE);
            let groups_y = (m as NSUInteger).div_ceil(GEMM_TILE);
            encoder.dispatch_thread_groups(
                MTLSize::new(groups_x, groups_y, 1),
                MTLSize::new(GEMM_TILE, GEMM_TILE, 1),
            );
            encoder.end_encoding();
            command.commit();
            command.wait_until_completed();
        }

        out.copy_from_slice(&Self::read_back(&out_buf, m * n));
        Ok(())
    }

    fn cosine(&self, a: &[f32], b: &[f32], dim: usize, out: &mut [f32]) -> Result<()> {
        check_shape_2d(a, 1, dim, "distance query")?;
        check_shape_2d(b, out.len(), dim, "distance candidates")?;
        check_finite(a, "cosine_batch")?;
        check_finite(b, "cosine_batch")?;
        if out.is_empty() {
            return Ok(());
        }

        // Query norm on the host, exactly as the CPU backend does, so a
        // zero-norm query is refused with the same error before any dispatch.
        let query_norm = a.iter().map(|v| v * v).sum::<f32>().sqrt();
        check_norm_positive(query_norm, "cosine_batch", 0)?;

        let rows = out.len();
        let query_buf = self.buffer_from(a)?;
        let cand_buf = self.buffer_from(b)?;
        let parts_buf = self.buffer_zeroed(rows * 2)?;
        let dims = dims_pair(dim, rows)?;

        self.dispatch_row_reduction(
            &self.pipelines.cosine_parts,
            &[(&query_buf, 0), (&cand_buf, 1), (&parts_buf, 2)],
            dims,
            rows,
        )?;

        let parts = Self::read_back(&parts_buf, rows * 2);
        for (row, score) in out.iter_mut().enumerate() {
            let dot = parts[row * 2];
            let candidate_norm = parts[row * 2 + 1].sqrt();
            check_norm_positive(candidate_norm, "cosine_batch", row)?;
            *score = dot / (query_norm * candidate_norm);
        }
        Ok(())
    }

    fn dot(&self, a: &[f32], b: &[f32], dim: usize, out: &mut [f32]) -> Result<()> {
        check_shape_2d(a, 1, dim, "distance query")?;
        check_shape_2d(b, out.len(), dim, "distance candidates")?;
        check_finite(a, "dot_batch")?;
        check_finite(b, "dot_batch")?;
        if out.is_empty() {
            return Ok(());
        }

        let rows = out.len();
        let query_buf = self.buffer_from(a)?;
        let cand_buf = self.buffer_from(b)?;
        let out_buf = self.buffer_zeroed(rows)?;
        let dims = dims_pair(dim, rows)?;

        self.dispatch_row_reduction(
            &self.pipelines.dot,
            &[(&query_buf, 0), (&cand_buf, 1), (&out_buf, 2)],
            dims,
            rows,
        )?;

        out.copy_from_slice(&Self::read_back(&out_buf, rows));
        Ok(())
    }

    fn l2(&self, a: &[f32], b: &[f32], dim: usize, out: &mut [f32]) -> Result<()> {
        check_shape_2d(a, 1, dim, "distance query")?;
        check_shape_2d(b, out.len(), dim, "distance candidates")?;
        check_finite(a, "l2_batch")?;
        check_finite(b, "l2_batch")?;
        if out.is_empty() {
            return Ok(());
        }

        let rows = out.len();
        let query_buf = self.buffer_from(a)?;
        let cand_buf = self.buffer_from(b)?;
        let out_buf = self.buffer_zeroed(rows)?;
        let dims = dims_pair(dim, rows)?;

        self.dispatch_row_reduction(
            &self.pipelines.l2,
            &[(&query_buf, 0), (&cand_buf, 1), (&out_buf, 2)],
            dims,
            rows,
        )?;

        out.copy_from_slice(&Self::read_back(&out_buf, rows));
        Ok(())
    }

    fn normalize(&self, vecs: &mut [f32], dim: usize) -> Result<()> {
        if dim == 0 {
            if vecs.is_empty() {
                return Ok(());
            }
            return Err(ForgeError::ShapeMismatch {
                expected: vec![0],
                got: vec![vecs.len()],
                remediation: "dim=0 is valid only for an empty matrix".to_string(),
            });
        }
        if !vecs.len().is_multiple_of(dim) {
            return Err(ForgeError::ShapeMismatch {
                expected: vec![dim],
                got: vec![vecs.len()],
                remediation: "normalize input length must be an integer number of rows".to_string(),
            });
        }
        let rows = vecs.len() / dim;
        check_shape_2d(vecs, rows, dim, "normalize input")?;
        check_finite(vecs, "normalize")?;
        if rows == 0 {
            return Ok(());
        }

        let vec_buf = self.buffer_from(vecs)?;
        let norms_buf = self.buffer_zeroed(rows)?;
        let dims = dims_pair(dim, rows)?;

        self.dispatch_row_reduction(
            &self.pipelines.row_norms_sq,
            &[(&vec_buf, 0), (&norms_buf, 1)],
            dims,
            rows,
        )?;

        // Refuse zero-norm rows before scaling, matching the CPU backend, so a
        // degenerate row errors instead of producing NaNs.
        let norms = Self::read_back(&norms_buf, rows);
        let mut inverse = Vec::with_capacity(rows);
        for (row, norm_sq) in norms.iter().enumerate() {
            let norm = norm_sq.sqrt();
            check_norm_positive(norm, "normalize", row)?;
            inverse.push(1.0 / norm);
        }
        let inv_buf = self.buffer_from(&inverse)?;

        {
            let queue = self.queue.lock().map_err(|_| {
                gpu_error("Metal command queue mutex poisoned", "restart the process")
            })?;
            let command = queue.new_command_buffer();
            let encoder = command.new_compute_command_encoder();
            encoder.set_compute_pipeline_state(&self.pipelines.scale_rows);
            encoder.set_buffer(0, Some(&vec_buf), 0);
            encoder.set_buffer(1, Some(&inv_buf), 0);
            encoder.set_bytes(
                2,
                std::mem::size_of_val(&dims) as NSUInteger,
                dims.as_ptr().cast(),
            );
            let total = (rows * dim) as NSUInteger;
            let width = self
                .pipelines
                .scale_rows
                .thread_execution_width()
                .max(1)
                .min(total.max(1));
            encoder.dispatch_thread_groups(
                MTLSize::new(total.div_ceil(width), 1, 1),
                MTLSize::new(width, 1, 1),
            );
            encoder.end_encoding();
            command.commit();
            command.wait_until_completed();
        }

        vecs.copy_from_slice(&Self::read_back(&vec_buf, rows * dim));
        Ok(())
    }

    /// `topk` stays on the host.
    ///
    /// Its input is an already host-resident `&[f32]` and its output is a small
    /// `Vec<(usize, f32)>`. Offloading would mean an upload, a GPU sort, and a
    /// download to move `k` elements — the transfer dominates the comparison
    /// work for every `k` this API is used with. This is a measured engineering
    /// choice about where the work belongs, not a gap: the host implementation
    /// is the same exact-selection routine the CPU backend uses.
    fn topk(&self, scores: &[f32], k: usize) -> Result<Vec<(usize, f32)>> {
        crate::cpu::topk_f32(scores, k)
    }

    fn device_info(&self) -> DeviceInfo {
        DeviceInfo {
            kind: BackendKind::Metal,
            name: self.name.clone(),
            avx512: false,
            vram_mib: self.vram_mib,
        }
    }
}

fn dims_pair(dim: usize, rows: usize) -> Result<[u32; 2]> {
    Ok([
        u32::try_from(dim).map_err(|_| gpu_error("dim exceeds u32", "reduce vector dimension"))?,
        u32::try_from(rows).map_err(|_| gpu_error("row count exceeds u32", "reduce batch size"))?,
    ])
}
