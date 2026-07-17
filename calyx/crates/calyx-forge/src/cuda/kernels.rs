pub const DISTANCE_PTX: &[u8] = include_bytes!(env!("FORGE_DISTANCE_PTX_PATH"));
pub const TOPK_PTX: &[u8] = include_bytes!(env!("FORGE_TOPK_PTX_PATH"));
pub const MXFP_GEMM_PTX: &[u8] = include_bytes!(env!("FORGE_MXFP_GEMM_PTX_PATH"));
pub const DISTANCE_CUBIN: &[u8] = include_bytes!(env!("FORGE_DISTANCE_CUBIN_PATH"));
pub const TOPK_CUBIN: &[u8] = include_bytes!(env!("FORGE_TOPK_CUBIN_PATH"));
pub const MXFP_GEMM_CUBIN: &[u8] = include_bytes!(env!("FORGE_MXFP_GEMM_CUBIN_PATH"));

pub const DISTANCE_PTX_PATH: &str = env!("FORGE_DISTANCE_PTX_PATH");
pub const TOPK_PTX_PATH: &str = env!("FORGE_TOPK_PTX_PATH");
pub const MXFP_GEMM_PTX_PATH: &str = env!("FORGE_MXFP_GEMM_PTX_PATH");
pub const DISTANCE_CUBIN_PATH: &str = env!("FORGE_DISTANCE_CUBIN_PATH");
pub const TOPK_CUBIN_PATH: &str = env!("FORGE_TOPK_CUBIN_PATH");
pub const MXFP_GEMM_CUBIN_PATH: &str = env!("FORGE_MXFP_GEMM_CUBIN_PATH");
