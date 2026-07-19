use std::env;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::time::Duration;

use calyx_core::{Asymmetry, CalyxError, LensId, Modality, QuantPolicy, Result, SlotShape};
use serde::{Deserialize, Serialize};

use crate::frozen::{FrozenLensContract, LensDType, NormPolicy};

const LENS_UNREACHABLE: &str = "CALYX_LENS_UNREACHABLE";
#[cfg(not(feature = "candle-cuda"))]
const CANDLE_CUDA_FEATURE_MISSING_REASON: &str =
    "candle CUDA requested but calyx-registry was built without feature `candle-cuda`";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FastembedBgem3Output {
    Dense,
    Sparse,
    Colbert,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LensRuntime {
    Algorithmic {
        kind: String,
    },
    TeiHttp {
        endpoint: String,
    },
    CandleLocal {
        model_id: String,
        files: Vec<PathBuf>,
        device: String,
        dtype: String,
        pooling: String,
    },
    Onnx {
        model_id: String,
        files: Vec<PathBuf>,
    },
    FastembedDense {
        model_id: String,
        files: Vec<PathBuf>,
    },
    OnnxColbert {
        model_id: String,
        files: Vec<PathBuf>,
    },
    FastembedSparse {
        model_id: String,
        files: Vec<PathBuf>,
    },
    FastembedBgem3 {
        model_id: String,
        files: Vec<PathBuf>,
        output: FastembedBgem3Output,
    },
    FastembedReranker {
        model_id: String,
        files: Vec<PathBuf>,
    },
    FastembedQwen3 {
        model_id: String,
        files: Vec<PathBuf>,
        device: String,
        dtype: String,
    },
    StaticLookup {
        embeddings_file: PathBuf,
        tokenizer: PathBuf,
        dim: u32,
    },
    MultimodalAdapter {
        axis: String,
        model_id: String,
        #[serde(default)]
        adapter_config: Option<PathBuf>,
        #[serde(default)]
        files: Vec<PathBuf>,
    },
    ExternalCmd {
        cmd: String,
        args: Vec<String>,
    },
    // Placement-bound successors are appended after every historical variant
    // so the existing bincode discriminants and field layouts remain intact.
    FastembedDensePlaced {
        model_id: String,
        files: Vec<PathBuf>,
        execution: String,
    },
    FastembedSparsePlaced {
        model_id: String,
        files: Vec<PathBuf>,
        execution: String,
    },
    FastembedBgem3Placed {
        model_id: String,
        files: Vec<PathBuf>,
        output: FastembedBgem3Output,
        execution: String,
    },
    FastembedRerankerPlaced {
        model_id: String,
        files: Vec<PathBuf>,
        execution: String,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LensSpec {
    pub name: String,
    pub runtime: LensRuntime,
    pub output: SlotShape,
    pub modality: Modality,
    pub weights_sha256: [u8; 32],
    pub corpus_hash: [u8; 32],
    pub norm_policy: NormPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_batch: Option<usize>,
    pub axis: Option<String>,
    pub asymmetry: Asymmetry,
    #[serde(default = "default_quant_default")]
    pub quant_default: QuantPolicy,
    #[serde(default)]
    pub truncate_dim: Option<u32>,
    #[serde(default = "default_recall_delta")]
    pub recall_delta: f32,
    pub retrieval_only: bool,
    pub excluded_from_dedup: bool,
}

/// Human-readable neural-runtime variant name for fail-closed diagnostics when
/// the `ml-runtime` feature is disabled (#297). Only the neural variants are
/// reachable on the fail-closed path.
#[cfg(not(feature = "ml-runtime"))]
pub(crate) fn ml_runtime_kind(runtime: &LensRuntime) -> &'static str {
    match runtime {
        LensRuntime::CandleLocal { .. } => "candle-local",
        LensRuntime::Onnx { .. } => "onnx",
        LensRuntime::FastembedDense { .. } => "fastembed-dense",
        LensRuntime::FastembedDensePlaced { .. } => "fastembed-dense",
        LensRuntime::FastembedSparsePlaced { .. } => "fastembed-sparse",
        LensRuntime::FastembedBgem3Placed { .. } => "fastembed-bgem3",
        LensRuntime::FastembedRerankerPlaced { .. } => "fastembed-reranker",
        LensRuntime::OnnxColbert { .. } => "onnx-colbert",
        LensRuntime::FastembedSparse { .. } => "fastembed-sparse",
        LensRuntime::FastembedBgem3 { .. } => "fastembed-bgem3",
        LensRuntime::FastembedReranker { .. } => "fastembed-reranker",
        LensRuntime::FastembedQwen3 { .. } => "fastembed-qwen3",
        LensRuntime::StaticLookup { .. } => "static-lookup",
        LensRuntime::Algorithmic { .. }
        | LensRuntime::TeiHttp { .. }
        | LensRuntime::MultimodalAdapter { .. }
        | LensRuntime::ExternalCmd { .. } => "non-neural",
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LensHealth {
    Loaded,
    Cold,
    Failing { code: String, reason: String },
}

impl LensSpec {
    pub fn declared_contract(&self) -> FrozenLensContract {
        FrozenLensContract::new(
            self.name.clone(),
            self.weights_sha256,
            self.corpus_hash,
            self.output,
            self.modality,
            LensDType::F32,
            self.norm_policy,
        )
    }

    pub fn lens_id(&self) -> LensId {
        self.declared_contract().lens_id()
    }

    /// Pre-#570 (legacy v1, modality-blind) LensId this spec would have hashed
    /// to. Used only by the fail-closed legacy-migration diagnostic to detect a
    /// seed/key derived from the historical identity; never a registration path.
    pub fn legacy_v1_lens_id(&self) -> LensId {
        self.declared_contract().legacy_v1_lens_id()
    }

    pub fn health(&self) -> LensHealth {
        match &self.runtime {
            LensRuntime::Algorithmic { .. } => LensHealth::Loaded,
            LensRuntime::MultimodalAdapter {
                adapter_config,
                files,
                ..
            } => multimodal_adapter_health(adapter_config.as_ref(), files),
            LensRuntime::TeiHttp { endpoint } => probe_http(endpoint),
            LensRuntime::CandleLocal { files, device, .. }
            | LensRuntime::FastembedQwen3 { files, device, .. } => {
                candle_local_health(files, device)
            }
            LensRuntime::Onnx { files, .. }
            | LensRuntime::FastembedDense { files, .. }
            | LensRuntime::FastembedDensePlaced { files, .. }
            | LensRuntime::FastembedSparsePlaced { files, .. }
            | LensRuntime::FastembedBgem3Placed { files, .. }
            | LensRuntime::FastembedRerankerPlaced { files, .. }
            | LensRuntime::OnnxColbert { files, .. }
            | LensRuntime::FastembedSparse { files, .. }
            | LensRuntime::FastembedBgem3 { files, .. }
            | LensRuntime::FastembedReranker { files, .. } => files_runtime_health(files),
            LensRuntime::StaticLookup {
                embeddings_file,
                tokenizer,
                ..
            } => {
                if embeddings_file.is_file() && tokenizer.is_file() {
                    LensHealth::Loaded
                } else {
                    LensHealth::Cold
                }
            }
            LensRuntime::ExternalCmd { cmd, .. } => {
                if command_exists(cmd) {
                    LensHealth::Loaded
                } else {
                    LensHealth::Failing {
                        code: LENS_UNREACHABLE.to_string(),
                        reason: format!("external command {cmd} is not executable"),
                    }
                }
            }
        }
    }

    pub fn health_result(&self) -> Result<LensHealth> {
        let health = self.health();
        match &health {
            LensHealth::Failing { reason, .. } => Err(CalyxError::lens_unreachable(reason)),
            _ => Ok(health),
        }
    }
}

pub const fn default_quant_default() -> QuantPolicy {
    QuantPolicy::turboquant_default()
}

/// Shape-aware storage-identity default.
///
/// Dense shapes use the measured TurboQuant candidate, sparse shapes remain
/// exact until a sparse storage contract exists, and multi-vector shapes use
/// the separately versioned ColBERT residual codec.
pub const fn default_quant_for_shape(shape: SlotShape) -> QuantPolicy {
    match shape {
        SlotShape::Dense(_) => QuantPolicy::turboquant_default(),
        SlotShape::Sparse(_) => QuantPolicy::None,
        SlotShape::Multi { .. } => QuantPolicy::ColbertResidual2Bit,
    }
}

pub const fn default_recall_delta() -> f32 {
    0.02
}

fn candle_local_health(files: &[PathBuf], device: &str) -> LensHealth {
    match files_runtime_health(files) {
        LensHealth::Loaded if device == "cpu" => LensHealth::Loaded,
        LensHealth::Loaded => candle_cuda_runtime_health(),
        health => health,
    }
}

fn files_runtime_health(files: &[PathBuf]) -> LensHealth {
    if files.is_empty() {
        return LensHealth::Cold;
    }
    if files.iter().all(|path| path.exists()) {
        LensHealth::Loaded
    } else {
        LensHealth::Cold
    }
}

fn multimodal_adapter_health(adapter_config: Option<&PathBuf>, files: &[PathBuf]) -> LensHealth {
    let Some(adapter_config) = adapter_config else {
        return LensHealth::Cold;
    };
    if !adapter_config.is_file() {
        return LensHealth::Cold;
    }
    files_runtime_health(files)
}

#[cfg(feature = "candle-cuda")]
fn candle_cuda_runtime_health() -> LensHealth {
    LensHealth::Loaded
}

#[cfg(not(feature = "candle-cuda"))]
fn candle_cuda_runtime_health() -> LensHealth {
    LensHealth::Failing {
        code: LENS_UNREACHABLE.to_string(),
        reason: CANDLE_CUDA_FEATURE_MISSING_REASON.to_string(),
    }
}

fn probe_http(endpoint: &str) -> LensHealth {
    let Some(rest) = endpoint.strip_prefix("http://") else {
        return LensHealth::Failing {
            code: LENS_UNREACHABLE.to_string(),
            reason: "endpoint is not http://".to_string(),
        };
    };
    let authority = rest.split('/').next().unwrap_or_default();
    let (host, port) = authority
        .rsplit_once(':')
        .and_then(|(host, port)| port.parse::<u16>().ok().map(|port| (host, port)))
        .unwrap_or((authority, 80));
    let address = match (host, port)
        .to_socket_addrs()
        .ok()
        .and_then(|mut it| it.next())
    {
        Some(address) => address,
        None => {
            return LensHealth::Failing {
                code: LENS_UNREACHABLE.to_string(),
                reason: format!("{endpoint} resolved no socket address"),
            };
        }
    };
    match TcpStream::connect_timeout(&address, Duration::from_millis(250)) {
        Ok(_) => LensHealth::Loaded,
        Err(err) => LensHealth::Failing {
            code: LENS_UNREACHABLE.to_string(),
            reason: format!("connect {endpoint} failed: {err}"),
        },
    }
}

fn command_exists(cmd: &str) -> bool {
    let path = PathBuf::from(cmd);
    if path.components().count() > 1 {
        return path.is_file();
    }
    env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| env::split_paths(&paths).collect::<Vec<_>>())
        .any(|dir| dir.join(cmd).is_file())
}
