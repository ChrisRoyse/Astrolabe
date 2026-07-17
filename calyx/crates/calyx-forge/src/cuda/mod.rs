pub mod context;
pub mod distance;
pub mod gemm;
pub mod green_context;
pub mod grouped_gemm;
pub mod kernels;
pub mod ragged_gemm;
pub mod topk;

use crate::{Backend, DeviceInfo, Result};

#[cfg(windows)]
pub use crate::cuda_runtime::{
    CUDA_NO_DEVICE_ATTESTED_CODE, PinnedCudaDeviceAttestation, PinnedCudaModuleAttestation,
    PinnedCudaRuntimeAttestation, attest_pinned_cuda_dependencies,
    attest_pinned_cuda_driver_identity, attest_pinned_cuda_driver_identity_for_native_kernel,
    current_pinned_cuda_device, initialize_pinned_cuda_dependencies,
    initialize_pinned_cuda_runtime_boundary, select_pinned_cuda_device,
    select_pinned_cuda_device_by_identity, select_pinned_cuda_device_for_native_kernel,
};
pub use crate::mxfp4;
pub use context::{
    CudaContext, CudaPrimaryContextStream, attest_cuda_driver_ordinal, attest_cudarc_context,
    driver_ordinal_for_pci_bus_id, init_cuda, init_cuda_by_pci_bus_id, init_cuda_native_kernel,
    query_device_info,
};
pub use distance::{cosine_batch_gpu, dot_batch_gpu, l2_batch_gpu, normalize_rows_gpu};
pub use gemm::{
    MxFp4GemmPlan, MxFp8GemmPlan, MxPackedGemmEvidence, bench_gemm_cublas,
    bench_gemm_reference_cublas, gemm_cublas, gemm_mxfp4_fp32_accum, gemm_mxfp8_fp32_accum,
    pack_mxfp4_a_row_major, pack_mxfp4_b_column_major, pack_mxfp8_a_row_major,
    pack_mxfp8_b_column_major, probe_allocation,
};
pub use green_context::CudaGreenContextStream;
pub use grouped_gemm::{
    AbsentSlotSentinel, GemmProblem, GroupedGemmExecutionMode, GroupedGemmPlan,
    build_grouped_gemm_plan, execute_grouped_gemm, execute_grouped_gemm_strict,
    read_grouped_gemm_output,
};
pub use ragged_gemm::{
    RaggedBatch, build_ragged_batch, build_ragged_batch_from_slabs, extract_ragged_results,
    try_extract_ragged_results,
};
pub use topk::topk_gpu;

#[derive(Clone, Debug)]
pub struct CudaBackend {
    ctx: CudaContext,
}

impl CudaBackend {
    pub fn new() -> Result<Self> {
        init_cuda(crate::configured_cuda_runtime_ordinal()?, false).map(|ctx| Self { ctx })
    }

    pub fn with_context(ctx: CudaContext) -> Self {
        Self { ctx }
    }

    pub fn context(&self) -> &CudaContext {
        &self.ctx
    }

    pub fn grouped_gemm(&self, plan: &mut GroupedGemmPlan) -> Result<()> {
        grouped_gemm::execute_grouped_gemm(&self.ctx, plan)
    }

    pub fn grouped_gemm_strict(&self, plan: &mut GroupedGemmPlan) -> Result<()> {
        grouped_gemm::execute_grouped_gemm_strict(&self.ctx, plan)
    }
}

impl Backend for CudaBackend {
    fn gemm(
        &self,
        a: &[f32],
        b: &[f32],
        m: usize,
        k: usize,
        n: usize,
        out: &mut [f32],
    ) -> Result<()> {
        gemm::gemm_host(&self.ctx, a, b, m, k, n, out)
    }

    fn cosine(&self, a: &[f32], b: &[f32], dim: usize, out: &mut [f32]) -> Result<()> {
        distance::cosine_host(&self.ctx, a, b, dim, out)
    }

    fn dot(&self, a: &[f32], b: &[f32], dim: usize, out: &mut [f32]) -> Result<()> {
        distance::dot_host(&self.ctx, a, b, dim, out)
    }

    fn l2(&self, a: &[f32], b: &[f32], dim: usize, out: &mut [f32]) -> Result<()> {
        distance::l2_host(&self.ctx, a, b, dim, out)
    }

    fn normalize(&self, vecs: &mut [f32], dim: usize) -> Result<()> {
        distance::normalize_host(&self.ctx, vecs, dim)
    }

    fn topk(&self, scores: &[f32], k: usize) -> Result<Vec<(usize, f32)>> {
        topk::topk_host(&self.ctx, scores, k)
    }

    fn device_info(&self) -> DeviceInfo {
        query_device_info(&self.ctx)
    }
}
