use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::ForgeError;

pub type Result<T> = std::result::Result<T, ForgeError>;

/// Backend operations implemented by the Stage 2 `Backend` trait.
pub const FORGE_SHIPPED_BACKEND_OPS: &[&str] = &[
    "gemm",
    "cosine",
    "dot",
    "l2",
    "normalize",
    "topk",
    "device_info",
];

/// PRD-listed Forge operations that are intentionally not part of the Stage 2 trait yet.
pub const FORGE_DEFERRED_BACKEND_OPS: &[&str] = &[
    "knn",
    "histogram_nmi",
    "spmm_sparse_ops",
    "bilinear_cross_term",
    "graph_ops",
    "colbert_maxsim",
];

/// Exact CUDA `topk` is currently guaranteed only for global `k <= 1024`.
pub const CUDA_EXACT_TOPK_MAX_K: usize = 1024;

pub trait Backend: Send + Sync {
    fn gemm(
        &self,
        a: &[f32],
        b: &[f32],
        m: usize,
        k: usize,
        n: usize,
        out: &mut [f32],
    ) -> Result<()>;
    fn cosine(&self, a: &[f32], b: &[f32], dim: usize, out: &mut [f32]) -> Result<()>;
    fn dot(&self, a: &[f32], b: &[f32], dim: usize, out: &mut [f32]) -> Result<()>;
    fn l2(&self, a: &[f32], b: &[f32], dim: usize, out: &mut [f32]) -> Result<()>;
    fn normalize(&self, vecs: &mut [f32], dim: usize) -> Result<()>;
    fn topk(&self, scores: &[f32], k: usize) -> Result<Vec<(usize, f32)>>;
    fn device_info(&self) -> DeviceInfo;
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendKind {
    Cpu,
    Cuda,
}

impl fmt::Display for BackendKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cpu => f.write_str("cpu"),
            Self::Cuda => f.write_str("cuda"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BestConfig {
    pub backend: BackendKind,
    pub tile_m: usize,
    pub tile_n: usize,
    pub tile_k: usize,
    pub extra: HashMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeviceInfo {
    pub kind: BackendKind,
    pub name: String,
    pub avx512: bool,
    pub vram_mib: Option<u64>,
}

impl Default for DeviceInfo {
    fn default() -> Self {
        Self {
            kind: BackendKind::Cpu,
            name: "cpu".to_string(),
            avx512: false,
            vram_mib: None,
        }
    }
}
