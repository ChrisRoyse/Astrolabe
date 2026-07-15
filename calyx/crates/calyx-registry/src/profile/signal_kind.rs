use calyx_core::LensId;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::lens::Registry;
use crate::spec::{LensRuntime, LensSpec};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilitySignalKind {
    #[default]
    Unknown,
    LearnedEncoder,
    DeterministicContentFeature,
    Algorithmic,
    Placeholder,
}

impl CapabilitySignalKind {
    pub fn is_learned_encoder(self) -> bool {
        matches!(self, Self::LearnedEncoder)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::LearnedEncoder => "learned_encoder",
            Self::DeterministicContentFeature => "deterministic_content_feature",
            Self::Algorithmic => "algorithmic",
            Self::Placeholder => "placeholder",
        }
    }
}

pub fn signal_kind_from_spec(spec: &LensSpec) -> CapabilitySignalKind {
    match &spec.runtime {
        LensRuntime::Algorithmic { .. } => CapabilitySignalKind::DeterministicContentFeature,
        LensRuntime::TeiHttp { endpoint } => {
            learned_if(has_hash_provenance(spec) && !endpoint.trim().is_empty())
        }
        LensRuntime::CandleLocal {
            model_id, files, ..
        }
        | LensRuntime::Onnx { model_id, files }
        | LensRuntime::OnnxColbert { model_id, files }
        | LensRuntime::FastembedSparse { model_id, files }
        | LensRuntime::FastembedReranker { model_id, files } => learned_if(
            has_hash_provenance(spec) && has_model_id(model_id) && has_artifact_paths(files),
        ),
        LensRuntime::FastembedBgem3 {
            model_id, files, ..
        }
        | LensRuntime::FastembedQwen3 {
            model_id, files, ..
        } => learned_if(
            has_hash_provenance(spec) && has_model_id(model_id) && has_artifact_paths(files),
        ),
        LensRuntime::StaticLookup {
            embeddings_file,
            tokenizer,
            dim,
        } => learned_if(
            has_hash_provenance(spec)
                && *dim > 0
                && has_path_provenance(embeddings_file)
                && has_path_provenance(tokenizer),
        ),
        LensRuntime::MultimodalAdapter {
            axis,
            model_id,
            adapter_config,
            files,
        } => learned_if(
            has_hash_provenance(spec)
                && !axis.trim().is_empty()
                && has_model_id(model_id)
                && adapter_config.as_deref().is_some_and(has_path_provenance)
                && has_artifact_paths(files),
        ),
        LensRuntime::ExternalCmd { .. } => CapabilitySignalKind::Unknown,
    }
}

pub(super) fn registry_signal_kind(registry: &Registry, lens_id: LensId) -> CapabilitySignalKind {
    registry
        .lens_spec(lens_id)
        .map(signal_kind_from_spec)
        .unwrap_or(CapabilitySignalKind::Unknown)
}

fn learned_if(verified: bool) -> CapabilitySignalKind {
    if verified {
        CapabilitySignalKind::LearnedEncoder
    } else {
        CapabilitySignalKind::Unknown
    }
}

fn has_hash_provenance(spec: &LensSpec) -> bool {
    spec.weights_sha256 != [0; 32] && spec.corpus_hash != [0; 32]
}

fn has_model_id(model_id: &str) -> bool {
    !model_id.trim().is_empty()
}

fn has_artifact_paths(files: &[PathBuf]) -> bool {
    !files.is_empty() && files.iter().all(|path| has_path_provenance(path))
}

fn has_path_provenance(path: &Path) -> bool {
    !path.as_os_str().is_empty()
}
