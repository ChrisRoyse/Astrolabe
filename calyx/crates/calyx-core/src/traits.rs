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
    /// Final optimized-graph classification plus ORT API 24 committed-session
    /// placement and the first exact real, host-materialized,
    /// retained-stream-synchronized inference profile.
    #[serde(
        rename = "onnx_optimized_graph_classified_v1+api24_committed_session+first_exact_real_host_materialized_retained_stream_synchronized_inference_profile"
    )]
    OptimizedGraphClassifiedV1Api24AndFirstExactInferenceProfile,
}

/// Categorical role proven for one ONNX node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnnxPlacementNodeRole {
    /// Substantive model computation executed by CUDAExecutionProvider.
    CudaCompute,
    /// Bounded integral/bool shape metadata executed by CPUExecutionProvider.
    CpuShapeMetadata,
}

/// Exact node identity from ORT's committed API-24 assignment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OnnxCommittedNodeEvidence {
    pub name: String,
    pub domain: String,
    pub operator: String,
    pub provider: String,
    pub role: OnnxPlacementNodeRole,
    /// Static aggregate output bound for an authorized CPU metadata node.
    /// CUDA compute nodes carry `None`.
    pub max_output_elements: Option<u64>,
    /// Canonical sorted output dtype set for an authorized CPU metadata node.
    /// CUDA compute nodes carry `None`.
    pub output_dtypes: Option<String>,
}

/// Exact node identity and output facts from the first real ORT profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OnnxProfiledNodeEvidence {
    pub name: String,
    pub operator: String,
    pub provider: String,
    pub role: OnnxPlacementNodeRole,
    pub node_index: u64,
    pub output_size: u64,
    pub output_elements: u64,
    pub output_dtypes: String,
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
    /// Executable nodes in the exact optimized graph.
    pub total_graph_nodes: u64,
    /// Substantive nodes assigned to CUDAExecutionProvider.
    pub cuda_compute_nodes: u64,
    /// Proven bounded shape-metadata nodes assigned to CPUExecutionProvider.
    pub cpu_metadata_nodes: u64,
    /// CPU nodes not proven to be shape metadata. Always zero when admitted.
    pub unclassified_cpu_nodes: u64,
    /// Graph-internal provider transfer nodes. Always zero when admitted.
    pub inter_provider_memcpy_nodes: u64,
    /// Deterministic provider/count summary.
    pub providers: String,
    /// Deterministic provider/operator summary.
    pub assigned_operators: String,
    /// Exact sorted committed node identities and categorical roles.
    pub nodes: Vec<OnnxCommittedNodeEvidence>,
}

/// Placement observed in the first real synchronized inference profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OnnxFirstInferencePlacementEvidence {
    /// Profiled executable-node events.
    pub total_graph_nodes: u64,
    /// Profiled substantive CUDA events.
    pub cuda_compute_nodes: u64,
    /// Profiled, statically authorized CPU shape-metadata events.
    pub cpu_metadata_nodes: u64,
    /// Profiled unclassified CPU events. Always zero when admitted.
    pub unclassified_cpu_nodes: u64,
    /// Profiled transfer events. Always zero when admitted.
    pub inter_provider_memcpy_nodes: u64,
    /// Deterministic provider/count summary.
    pub providers: String,
    /// Exact sorted first-inference node identities and output facts.
    pub nodes: Vec<OnnxProfiledNodeEvidence>,
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
    /// Static classifier implementation bound to this receipt.
    pub classifier_version: String,
    /// Canonical ONNX domain/opset inventory.
    pub opset_inventory: String,
    /// SHA-256 of the length-delimited canonical opset fields.
    pub opset_sha256: String,
    /// Canonical immutable optimized-graph path.
    pub optimized_graph_path: String,
    /// Exact optimized-graph byte length.
    pub optimized_graph_bytes: u64,
    /// SHA-256 of the exact optimized GraphProto bytes.
    pub optimized_graph_sha256: String,
    /// SHA-256 of exact length-delimited API-24 node fields.
    pub assignment_sha256: String,
    /// SHA-256 of exact static CPU metadata proof fields.
    pub cpu_metadata_proof_sha256: String,
    /// SHA-256 binding classifier, graph, opsets, assignment, and proofs.
    pub placement_contract_sha256: String,
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
