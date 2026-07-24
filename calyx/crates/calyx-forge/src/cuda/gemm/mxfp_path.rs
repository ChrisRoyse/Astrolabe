use std::sync::Arc;

use cudarc::driver::{CudaFunction, CudaModule, CudaSlice, LaunchConfig, PushKernelArg};

use crate::cuda::kernels::{
    CudaKernelRuntimeAttestation, MXFP_GEMM_CUBIN, ensure_kernel_capability, load_embedded_cubin,
};
use crate::{CudaContext, ForgeError, Result};

pub(super) const MXFP_WARP_THREADS: u32 = 32;
pub(super) const MXFP_GEMM_MAX_DIM: usize = 1 << 20;
pub(super) const MXFP_GEMM_MAX_MATRIX_ELEMENTS: usize = 1 << 28;
const MXFP_DEVICE_REMEDIATION: &str = "Run the packed OCP MX kernel on the pinned Blackwell sm_120 device with CUDA 13.3; use the K-axis block layout and do not decode operands or fall back to SGEMM";

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct MxPackedGemmEvidence {
    pub backend: &'static str,
    pub element: &'static str,
    pub kernel: &'static str,
    pub m: usize,
    pub k: usize,
    pub n: usize,
    pub k_blocks: usize,
    pub packed_element_bytes: usize,
    pub scale_bytes: usize,
    pub output_device_bytes: usize,
    pub resident_device_bytes: usize,
    pub module_cache_hit_at_creation: bool,
    pub execution_count: u64,
    pub device: String,
    pub compute_capability: (i32, i32),
    pub device_selection_authority: &'static str,
    pub module: CudaKernelRuntimeAttestation,
}

pub(super) struct PackedPlanStorage {
    pub a_codes: CudaSlice<u8>,
    pub a_scales: CudaSlice<u8>,
    pub b_codes: CudaSlice<u8>,
    pub b_scales: CudaSlice<u8>,
    pub status: CudaSlice<u32>,
    function: CudaFunction,
    element: &'static str,
    kernel: &'static str,
    m: usize,
    k: usize,
    n: usize,
    k_blocks: usize,
    device: String,
    compute_capability: (i32, i32),
    device_selection_authority: &'static str,
    module_attestation: CudaKernelRuntimeAttestation,
    module_cache_hit_at_creation: bool,
    execution_count: u64,
}

impl PackedPlanStorage {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn upload(
        ctx: &CudaContext,
        element: &'static str,
        kernel: &'static str,
        m: usize,
        k: usize,
        n: usize,
        k_blocks: usize,
        a_codes: &[u8],
        a_scales: &[u8],
        b_codes: &[u8],
        b_scales: &[u8],
    ) -> Result<Self> {
        ctx.attest_physical_identity()?;
        ensure_sm120(ctx, element, [m, k, n])?;
        let output_elements = checked_matrix_elements(m, n, element, "output")?;
        let required_bytes = a_codes
            .len()
            .checked_add(a_scales.len())
            .and_then(|total| total.checked_add(b_codes.len()))
            .and_then(|total| total.checked_add(b_scales.len()))
            .and_then(|total| total.checked_add(output_elements.checked_mul(4)?))
            .and_then(|total| total.checked_add(4))
            .ok_or_else(|| {
                packed_shape_error(element, [m, k, n], "resident byte count overflow")
            })?;
        let free_bytes = ctx.free_device_vram_bytes()?;
        if required_bytes > free_bytes {
            return Err(ForgeError::VramBudget {
                detail: format!(
                    "backend=cuda dtype={element} shape=[{m},{k},{n}] requires {required_bytes} resident bytes but only {free_bytes} are currently free"
                ),
                remediation: "Release GPU memory or reduce the packed GEMM shape; never spill or decode MX operands to host F32".to_string(),
            });
        }

        let stream = ctx.inner().default_stream();
        let a_codes = stream.clone_htod(a_codes).map_err(|error| {
            device_error(
                ctx,
                element,
                [m, k, n],
                format!("upload A packed elements failed: {error}"),
            )
        })?;
        let a_scales = stream.clone_htod(a_scales).map_err(|error| {
            device_error(
                ctx,
                element,
                [m, k, n],
                format!("upload A UE8M0 scales failed: {error}"),
            )
        })?;
        let b_codes = stream.clone_htod(b_codes).map_err(|error| {
            device_error(
                ctx,
                element,
                [m, k, n],
                format!("upload B packed elements failed: {error}"),
            )
        })?;
        let b_scales = stream.clone_htod(b_scales).map_err(|error| {
            device_error(
                ctx,
                element,
                [m, k, n],
                format!("upload B UE8M0 scales failed: {error}"),
            )
        })?;
        let status = stream.alloc_zeros(1).map_err(|error| {
            device_error(
                ctx,
                element,
                [m, k, n],
                format!("allocate device validation word failed: {error}"),
            )
        })?;
        let module_cache_hit_at_creation = ctx.mxfp_gemm_module_cache().get().is_some();
        let module = mxfp_module(ctx, element, [m, k, n])?;
        let function = module.load_function(kernel).map_err(|error| {
            device_error(
                ctx,
                element,
                [m, k, n],
                format!("load native kernel {kernel} failed: {error}"),
            )
        })?;
        let module_attestation = ctx.kernel_module_attestation("mxfp_gemm")?.ok_or_else(|| {
            ForgeError::RuntimeBoundary {
                code: "CALYX_FORGE_CUDA_KERNEL_ATTESTATION_MISSING",
                detail: "mxfp_gemm module was loaded but its runtime receipt is absent".to_string(),
                remediation: MXFP_DEVICE_REMEDIATION,
            }
        })?;

        Ok(Self {
            a_codes,
            a_scales,
            b_codes,
            b_scales,
            status,
            function,
            element,
            kernel,
            m,
            k,
            n,
            k_blocks,
            device: ctx.physical_identity().canonical_execution_token(),
            compute_capability: ctx.compute_capability(),
            device_selection_authority: ctx.selection_authority(),
            module_attestation,
            module_cache_hit_at_creation,
            execution_count: 0,
        })
    }

    pub(super) fn execute(&mut self, ctx: &CudaContext, out: &mut CudaSlice<f32>) -> Result<()> {
        ctx.attest_execution_identity()?;
        let current_device = ctx.physical_identity().canonical_execution_token();
        if current_device != self.device {
            return Err(device_error(
                ctx,
                self.element,
                [self.m, self.k, self.n],
                format!(
                    "resident plan belongs to {} but execution requested {}",
                    self.device, current_device
                ),
            ));
        }
        let expected_output = checked_matrix_elements(self.m, self.n, self.element, "output")?;
        if out.len() != expected_output {
            return Err(packed_shape_error(
                self.element,
                [self.m, self.k, self.n],
                format!(
                    "output length mismatch: expected {expected_output}, got {}",
                    out.len()
                ),
            ));
        }

        let stream = ctx.inner().default_stream();
        stream.memset_zeros(&mut self.status).map_err(|error| {
            device_error(
                ctx,
                self.element,
                [self.m, self.k, self.n],
                format!("clear device validation word failed: {error}"),
            )
        })?;
        let grid_x = u32::try_from(self.n.div_ceil(8)).map_err(|_| {
            packed_shape_error(
                self.element,
                [self.m, self.k, self.n],
                "N tile grid exceeds u32",
            )
        })?;
        let grid_y = u32::try_from(self.m.div_ceil(16)).map_err(|_| {
            packed_shape_error(
                self.element,
                [self.m, self.k, self.n],
                "M tile grid exceeds u32",
            )
        })?;
        let m = u32::try_from(self.m).map_err(|_| {
            packed_shape_error(self.element, [self.m, self.k, self.n], "M exceeds u32")
        })?;
        let k = u32::try_from(self.k).map_err(|_| {
            packed_shape_error(self.element, [self.m, self.k, self.n], "K exceeds u32")
        })?;
        let n = u32::try_from(self.n).map_err(|_| {
            packed_shape_error(self.element, [self.m, self.k, self.n], "N exceeds u32")
        })?;
        let k_blocks = u32::try_from(self.k_blocks).map_err(|_| {
            packed_shape_error(
                self.element,
                [self.m, self.k, self.n],
                "K block count exceeds u32",
            )
        })?;
        let config = LaunchConfig {
            grid_dim: (grid_x, grid_y, 1),
            block_dim: (MXFP_WARP_THREADS, 1, 1),
            shared_mem_bytes: 0,
        };
        let mut launch = stream.launch_builder(&self.function);
        unsafe {
            launch
                .arg(&self.a_codes)
                .arg(&self.a_scales)
                .arg(&self.b_codes)
                .arg(&self.b_scales)
                .arg(&m)
                .arg(&k)
                .arg(&n)
                .arg(&k_blocks)
                .arg(out)
                .arg(&mut self.status)
                .launch(config)
        }
        .map_err(|error| {
            device_error(
                ctx,
                self.element,
                [self.m, self.k, self.n],
                format!("launch {} failed: {error}", self.kernel),
            )
        })?;
        stream.synchronize().map_err(|error| {
            device_error(
                ctx,
                self.element,
                [self.m, self.k, self.n],
                format!("synchronize {} failed: {error}", self.kernel),
            )
        })?;
        let status = stream.clone_dtoh(&self.status).map_err(|error| {
            device_error(
                ctx,
                self.element,
                [self.m, self.k, self.n],
                format!("read device validation word failed: {error}"),
            )
        })?[0];
        if status != 0 {
            let detail = if status & 0x8000_0000 != 0 {
                format!(
                    "native kernel produced a non-finite output near column-major index {}",
                    (status & 0x3fff_ffff).saturating_sub(1)
                )
            } else {
                format!(
                    "device-side packed-input validation rejected UE8M0/element block {}",
                    (status & 0x3fff_ffff).saturating_sub(1)
                )
            };
            return Err(ForgeError::NumericalInvariant {
                op: format!("cuda_packed_gemm backend=cuda dtype={} shape=[{},{},{}]", self.element, self.m, self.k, self.n),
                detail,
                remediation: "Reject the output, preserve the packed artifact, and repair/re-encode the reported OCP MX block; do not use the output or fall back to decoded F32".to_string(),
            });
        }
        self.execution_count = self.execution_count.saturating_add(1);
        Ok(())
    }

    pub(super) fn evidence(&self) -> MxPackedGemmEvidence {
        let packed_element_bytes = self.a_codes.len() + self.b_codes.len();
        let scale_bytes = self.a_scales.len() + self.b_scales.len();
        let output_device_bytes = self.m * self.n * size_of::<f32>();
        MxPackedGemmEvidence {
            backend: "cuda",
            element: self.element,
            kernel: self.kernel,
            m: self.m,
            k: self.k,
            n: self.n,
            k_blocks: self.k_blocks,
            packed_element_bytes,
            scale_bytes,
            output_device_bytes,
            resident_device_bytes: packed_element_bytes
                + scale_bytes
                + output_device_bytes
                + size_of::<u32>(),
            module_cache_hit_at_creation: self.module_cache_hit_at_creation,
            execution_count: self.execution_count,
            device: self.device.clone(),
            compute_capability: self.compute_capability,
            device_selection_authority: self.device_selection_authority,
            module: self.module_attestation.clone(),
        }
    }
}

pub(super) fn validate_geometry(
    element: &'static str,
    m: usize,
    k: usize,
    n: usize,
) -> Result<usize> {
    if m == 0 || k == 0 || n == 0 {
        return Err(packed_shape_error(
            element,
            [m, k, n],
            "empty packed GEMM dimensions are not executable",
        ));
    }
    if m > MXFP_GEMM_MAX_DIM || k > MXFP_GEMM_MAX_DIM || n > MXFP_GEMM_MAX_DIM {
        return Err(packed_shape_error(
            element,
            [m, k, n],
            format!("each dimension must be <= {MXFP_GEMM_MAX_DIM}"),
        ));
    }
    checked_matrix_elements(m, k, element, "A")?;
    checked_matrix_elements(k, n, element, "B")?;
    checked_matrix_elements(m, n, element, "output")?;
    Ok(k.div_ceil(32))
}

pub(super) fn check_block_count(
    element: &'static str,
    shape: [usize; 3],
    side: &'static str,
    actual: usize,
    expected: usize,
) -> Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(packed_shape_error(
            element,
            shape,
            format!("{side} K-axis block count mismatch: expected {expected}, got {actual}"),
        ))
    }
}

pub(super) fn checked_matrix_elements(
    rows: usize,
    cols: usize,
    element: &'static str,
    side: &'static str,
) -> Result<usize> {
    let elements = rows.checked_mul(cols).ok_or_else(|| {
        packed_shape_error(
            element,
            [rows, cols, 0],
            format!("{side} element count overflow"),
        )
    })?;
    if elements > MXFP_GEMM_MAX_MATRIX_ELEMENTS {
        return Err(packed_shape_error(
            element,
            [rows, cols, 0],
            format!(
                "{side} has {elements} elements; configured maximum is {MXFP_GEMM_MAX_MATRIX_ELEMENTS}"
            ),
        ));
    }
    Ok(elements)
}

pub(super) fn packed_shape_error(
    element: &'static str,
    shape: [usize; 3],
    detail: impl Into<String>,
) -> ForgeError {
    ForgeError::QuantError {
        op: format!("packed_gemm backend=cuda shape=[{},{},{}]", shape[0], shape[1], shape[2]),
        level: element.to_string(),
        detail: detail.into(),
        remediation: "Supply non-empty dimensions within the configured maximum, exact per-vector K-axis blocks, and a device output of M*N F32 values; no decoded-F32 fallback exists".to_string(),
    }
}

fn ensure_sm120(ctx: &CudaContext, _element: &'static str, _shape: [usize; 3]) -> Result<()> {
    ensure_kernel_capability(ctx, "mxfp_gemm")
}

fn mxfp_module(
    ctx: &CudaContext,
    _element: &'static str,
    _shape: [usize; 3],
) -> Result<Arc<CudaModule>> {
    load_embedded_cubin(
        ctx,
        "mxfp_gemm",
        MXFP_GEMM_CUBIN,
        ctx.mxfp_gemm_module_cache(),
    )
}

fn device_error(
    ctx: &CudaContext,
    element: &'static str,
    shape: [usize; 3],
    detail: impl Into<String>,
) -> ForgeError {
    ForgeError::DeviceUnavailable {
        device: ctx.physical_identity().canonical_execution_token(),
        detail: format!(
            "backend=cuda dtype={element} shape=[{},{},{}]: {}",
            shape[0],
            shape[1],
            shape[2],
            detail.into()
        ),
        remediation: MXFP_DEVICE_REMEDIATION.to_string(),
    }
}
