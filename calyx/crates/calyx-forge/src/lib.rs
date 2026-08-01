//! Forge math runtime skeleton for CPU, CUDA, and quantized kernels.

/// True when this build compiled the CUDA kernel backend (`cuda` feature).
/// Exported for build-info capability readback (#1130): deploy gates assert
/// this resolved value, not a top-level feature spelling.
pub const CUDA_COMPILED: bool = cfg!(feature = "cuda");

pub mod autotune;
mod backend;
pub mod compression_report;
pub mod cpu;
#[cfg(feature = "cuda")]
pub mod cuda;
#[cfg(all(feature = "metal", target_os = "macos"))]
pub mod metal;
mod cuda_device;
#[cfg(all(windows, feature = "cuda-runtime-boundary"))]
#[path = "cuda/runtime_bundle.rs"]
pub mod cuda_runtime;
#[cfg(all(windows, feature = "cuda-runtime-boundary"))]
#[path = "cuda/system_trust.rs"]
mod cuda_system_trust;
mod error;
#[path = "cuda/mxfp4.rs"]
pub mod mxfp4;
#[path = "cuda/mxfp8.rs"]
pub mod mxfp8;
pub mod quant;
pub mod vram;

pub use autotune::{
    AbHook, AutotuneCache, AutotuneKey, BenchCudaContext, BenchResult, EPSILON, Explorer,
    ExplorerPolicy, MIN_PROMOTE_MARGIN, MIN_PROMOTE_TRIALS, PromotionAction, PromotionEvent,
    autotune, log_promotion, microbench, next_candidate, promote_if_winner, record_trial,
    rollback_promotion, should_promote, should_use_challenger,
};
pub use backend::{
    Backend, BackendKind, BestConfig, CUDA_EXACT_TOPK_MAX_K, DeviceInfo,
    FORGE_DEFERRED_BACKEND_OPS, FORGE_SHIPPED_BACKEND_OPS, Result,
};
pub use compression_report::{
    COMPRESSION_REPORT_SCHEMA_VERSION, CompressionReport, CompressionReportInput,
    CompressionSlotMeasurement, CompressionSlotReport, CompressionTotals, IntelligenceDeltaReport,
    KernelCompressionMeasurement, KernelCompressionReport, compression_report,
};
pub use cpu::{CpuBackend, gemm_mxfp4_packed, gemm_mxfp8_packed};
#[cfg(all(feature = "metal", target_os = "macos"))]
pub use metal::MetalBackend;
#[cfg(feature = "cuda")]
pub use cuda::{
    AbsentSlotSentinel, CUDA_KERNEL_POLICY_JSON, CudaBackend, CudaContext, CudaGreenContextStream,
    CudaKernelBuildAttestation, CudaKernelModuleAttestation, CudaKernelRuntimeAttestation,
    CudaPrimaryContextStream, GemmProblem, GroupedGemmExecutionMode, GroupedGemmPlan,
    MxFp4GemmPlan, MxFp8GemmPlan, MxPackedGemmEvidence, RaggedBatch, attest_cuda_driver_ordinal,
    attest_cudarc_context, build_grouped_gemm_plan, build_ragged_batch,
    build_ragged_batch_from_slabs, cuda_kernel_build_attestation, driver_ordinal_for_pci_bus_id,
    execute_grouped_gemm, execute_grouped_gemm_strict, extract_ragged_results, init_cuda,
    init_cuda_by_pci_bus_id, init_cuda_native_kernel, pack_mxfp4_a_row_major,
    pack_mxfp4_b_column_major, pack_mxfp8_a_row_major, pack_mxfp8_b_column_major,
    query_device_info, read_grouped_gemm_output, try_extract_ragged_results,
};
#[cfg(feature = "cuda-policy-measurement")]
pub use cuda::{CUDA_KERNEL_MEASUREMENT_ARTIFACTS, CudaKernelMeasurementArtifact};
pub use cuda_device::{CUDA_DEVICE_ENV, PinnedCudaDeviceIdentity, configured_cuda_runtime_ordinal};
#[cfg(all(windows, feature = "cuda-runtime-boundary"))]
pub use cuda_runtime::{
    CUDA_NO_DEVICE_ATTESTED_CODE, PinnedCudaDeviceAttestation, PinnedCudaModuleAttestation,
    PinnedCudaRuntimeAttestation, attest_pinned_cuda_dependencies,
    attest_pinned_cuda_driver_dependencies, attest_pinned_cuda_driver_identity,
    attest_pinned_cuda_driver_identity_for_native_kernel, current_pinned_cuda_device,
    initialize_pinned_cuda_dependencies, initialize_pinned_cuda_runtime_boundary,
    revalidate_pinned_cuda_dependencies, select_pinned_cuda_device,
    select_pinned_cuda_device_by_identity, select_pinned_cuda_device_for_native_kernel,
};
pub use error::ForgeError;
pub use mxfp4::{
    MXFP4_BLOCK_BYTES, MXFP4_BLOCK_SIZE, MXFP4_MAX_DIM, MXFP4_PACKED_BYTES, MxFp4Block,
    decode_e2m1, decode_e8m0, decode_mxfp4, decode_mxfp4_block, dot_norm_mxfp4, encode_mxfp4,
    encode_mxfp4_block, nibble_at, validate_mxfp4_blocks,
};
pub use mxfp8::{
    MXFP8_BLOCK_BYTES, MXFP8_BLOCK_SIZE, MXFP8_MAX_DIM, MxFp8Block, decode_e4m3, decode_mxfp8,
    decode_mxfp8_block, dot_norm_mxfp8, encode_mxfp8, encode_mxfp8_block, validate_mxfp8_blocks,
};
pub use quant::{
    AssayQuantSafety, BinaryCodec, CURRENT_SEED_VERSION, MXFP_BODY_ALIGNMENT_BYTES,
    MXFP_FORMAT_HEADER_BYTES, MXFP_FORMAT_VERSION, MxFp4Codec, MxFp8Codec, MxFpStorage,
    QjlResidual, QuantLevel, QuantizedVec, Quantizer, RotationSeed, ScalarInt8Codec, SeedId,
    TURBOQUANT_FORMAT_HEADER_BYTES, TURBOQUANT_FORMAT_VERSION, TURBOQUANT_MAX_DIM, TurboQuantCodec,
    TurboQuantGeometryKind, TurboQuantOwnedCandidate, TurboQuantPreparedQuery, TurboQuantStorage,
    TurboQuantV1MigrationVerifier, TurboQuantValidatedCandidate, apply_inverse_rotation,
    apply_rotation, apply_rotation_batch, binary_prefilter, hamming_dot_estimate, mxfp_payload_len,
    new_seed, seed_id_hex, turboquant_payload_len,
};
#[cfg(feature = "cuda")]
pub use vram::CudaStream;
#[cfg(feature = "cuda")]
pub use vram::CudaVramProbe;
#[cfg(feature = "cuda")]
pub use vram::RawCudaMalloc;
pub use vram::{
    ANNEAL_VRAM_BUDGET_ENV, AdmissionController, AdmissionOutput, AdmitDecision, BlockDeallocator,
    BlockId, BlockKind, Category, CudaAllocError, CudaMalloc, DEFAULT_ANNEAL_THROTTLE_SLEEP,
    DEFAULT_ANNEAL_VRAM_CAP_BYTES, DEFAULT_OOM_MAX_RETRIES, DEFAULT_POWER_BACKOFF_THRESHOLD_W,
    DEFAULT_SOFT_CAP_BYTES, DevicePtr, GpuBlockRegistry, GpuBlockStats,
    LENS_VRAM_BUDGET_REMEDIATION, LensAdmission, LensAdmissionPlacement, LensAdmissionRequest,
    NvmlPowerProbe, OomGuard, OomGuardStats, PowerProbe, QueuedDispatch, RESERVED_HEADROOM_BYTES,
    VRAM_BUDGET_ENV, VRAM_BUDGET_REMEDIATION, VramBudgeter, VramGuard, VramProbe, VramStats,
    YieldPolicy, YieldStats, admit_lens,
};
