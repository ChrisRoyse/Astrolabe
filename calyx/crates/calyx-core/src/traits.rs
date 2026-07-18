//! Engine trait boundaries shared by Calyx crates.

use serde::{Deserialize, Serialize};

use crate::{
    Anchor, Constellation, CxId, LensId, Modality, Result, Seq, Signal, SlotShape, SlotVector,
};

/// Raw input presented to a frozen lens.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Input {
    /// Input modality.
    pub modality: Modality,
    /// Raw bytes to measure.
    pub bytes: Vec<u8>,
    /// Optional pointer to retained source bytes.
    pub pointer: Option<String>,
}

impl Input {
    /// Builds an input from modality and bytes.
    pub fn new(modality: Modality, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            modality,
            bytes: bytes.into(),
            pointer: None,
        }
    }

    /// Attaches a source pointer.
    pub fn with_pointer(mut self, pointer: impl Into<String>) -> Self {
        self.pointer = Some(pointer.into());
        self
    }
}

/// Runtime-observed execution facts captured after a real measurement.
///
/// Fields that a backend cannot directly observe stay absent; callers must not
/// substitute frozen declarations for runtime evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeExecutionAttestation {
    /// Runtime implementation that produced the measurement.
    pub runtime: String,
    /// Backend/provider observed during execution.
    pub provider: String,
    /// Device on which execution was observed.
    pub device: String,
    /// Dtype requested when model weights were loaded, when observable.
    pub loader_dtype: Option<String>,
    /// Dtype observed on a primary compute activation, when observable.
    pub compute_dtype: Option<String>,
    /// Evidence mechanism used to observe these facts.
    pub evidence: String,
    /// Compute nodes observed in a provider placement trace, when available.
    pub total_compute_nodes: Option<u64>,
    /// Compute nodes placed on a CPU provider, when available.
    pub cpu_compute_nodes: Option<u64>,
}

/// Exact evidence kind for a fail-loud CUDA ONNX session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OnnxCudaExecutionEvidenceKind {
    /// ORT API 24 committed-session placement plus the first real,
    /// host-materialized, retained-stream-synchronized inference profile.
    #[serde(
        rename = "onnx_api24_committed_session+first_real_host_materialized_retained_stream_synchronized_inference_profile"
    )]
    Api24CommittedSessionAndFirstRealInferenceProfile,
}

/// Physical CUDA stream retained by the exact ONNX session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OnnxRetainedCudaStreamEvidence {
    /// Native stream address observed from the retained session handle.
    pub stream_address: String,
    /// CUDA Driver ordinal bound to the stream.
    pub driver_ordinal: u32,
    /// Canonical PCI + GPU-UUID physical-device identity.
    pub physical_device: String,
}

/// ORT API-24 placement read directly from one committed session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OnnxCommittedSessionPlacementEvidence {
    /// Optimized compute nodes owned by the committed session.
    pub total_compute_nodes: u64,
    /// Nodes assigned to CUDAExecutionProvider.
    pub cuda_compute_nodes: u64,
    /// Nodes assigned to CPUExecutionProvider.
    pub cpu_compute_nodes: u64,
    /// Deterministic provider/count summary.
    pub providers: String,
    /// Deterministic provider/operator summary.
    pub assigned_operators: String,
}

/// Placement observed in the first real synchronized inference profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OnnxFirstInferencePlacementEvidence {
    /// Profiled compute-node events.
    pub total_compute_nodes: u64,
    /// Profiled CUDA compute-node events.
    pub cuda_compute_nodes: u64,
    /// Profiled CPU compute-node events.
    pub cpu_compute_nodes: u64,
    /// Deterministic provider/count summary.
    pub providers: String,
}

/// Structured, versioned CUDA ONNX execution evidence.
///
/// This is serialized into [`RuntimeExecutionAttestation::evidence`] as
/// strict JSON. Consumers deserialize this type instead of matching or
/// searching an opaque status string.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OnnxCudaExecutionEvidence {
    /// Versioned evidence discriminator.
    pub kind: OnnxCudaExecutionEvidenceKind,
    /// Exact retained CUDA stream and physical device.
    pub retained_stream: OnnxRetainedCudaStreamEvidence,
    /// Committed-session API-24 assignment.
    pub committed_session: OnnxCommittedSessionPlacementEvidence,
    /// First-real-inference execution profile.
    pub first_inference_profile: OnnxFirstInferencePlacementEvidence,
    /// Canonical path returned by ORT profiling and independently snapshotted.
    pub profile_path: String,
    /// SHA-256 of the exact snapshotted profile bytes.
    pub profile_sha256: String,
}

/// Implemented by Registry lens runtimes as frozen measurement instruments.
pub trait Lens: Send + Sync {
    /// Stable frozen lens id.
    fn id(&self) -> LensId;

    /// Vector shape this lens emits.
    fn shape(&self) -> SlotShape;

    /// Modality this lens accepts.
    fn modality(&self) -> Modality;

    /// Deterministically measures one input.
    fn measure(&self, input: &Input) -> Result<SlotVector>;

    /// Deterministically measures a batch of inputs.
    fn measure_batch(&self, inputs: &[Input]) -> Result<Vec<SlotVector>> {
        inputs.iter().map(|input| self.measure(input)).collect()
    }

    /// Returns runtime-observed execution evidence after measurement.
    ///
    /// The default is deliberately unattested. Implementations must only
    /// return `Some` for facts retained from actual execution.
    fn execution_attestation(&self) -> Result<Option<RuntimeExecutionAttestation>> {
        Ok(None)
    }
}

/// Implemented by per-slot ANN or inverted indexes.
pub trait Index: Send + Sync {
    /// Inserts or replaces a vector for a constellation.
    fn insert(&mut self, cx: CxId, vector: &SlotVector) -> Result<()>;

    /// Searches for nearest constellations.
    fn search(&self, query: &SlotVector, k: usize, ef: Option<usize>) -> Result<Vec<(CxId, f32)>>;

    /// Rebuilds the index from its source store.
    fn rebuild(&mut self) -> Result<()>;
}

/// Implemented by Aster vault storage.
pub trait VaultStore: Send + Sync {
    /// Persists a constellation through the group-commit path.
    fn put(&self, constellation: Constellation) -> Result<CxId>;

    /// Reads a constellation as of a snapshot sequence.
    fn get(&self, id: CxId, snapshot: Seq) -> Result<Constellation>;

    /// Attaches a grounded anchor to an existing constellation.
    fn anchor(&self, id: CxId, anchor: Anchor) -> Result<()>;

    /// Returns the latest readable snapshot sequence.
    fn snapshot(&self) -> Seq;
}

/// Implemented by Assay signal estimators.
pub trait Estimator: Send + Sync {
    /// Estimates information between slot vectors and anchors.
    fn mi(&self, x: &[SlotVector], y: &[Anchor]) -> Result<Signal>;

    /// Estimates redundancy between two slot-vector samples.
    fn redundancy(&self, a: &[SlotVector], b: &[SlotVector]) -> Result<f32>;
}
