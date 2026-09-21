//! Atomic complete kernel-generation publication (#996/#1148).
//!
//! A production kernel is one indivisible serving object: three canonical
//! kernel-artifact rows; the descriptor, binding roster, and HNSW bytes; the
//! real external-query corpus; and its graph-routed recall admission report.
//! This module prepares all eight before mutation, publishes content-addressed
//! generation rows and fixed compatibility aliases in one seq-guarded
//! Ledger-bound group commit, and moves one manifest-bound current pointer in
//! that same commit. Readers resolve the pointer first and reject any generation
//! row or alias that is missing, corrupt, or byte-different.
//!
//! Retention is bounded to current + previous. When a third generation advances,
//! every row of the superseded previous generation is tombstoned atomically with
//! the new current pointer. These rows are regenerable; no asynchronous janitor
//! owns correctness or disk growth. The v3 content address also hashes an
//! explicit predecessor (`genesis` for the first generation), so recurring
//! content (A -> B -> A) never reuses A's immutable manifest key under a
//! different Ledger/retention lineage.

use std::collections::{BTreeMap, BTreeSet};

use astrolabe_ingest::{
    GraphProjectionKind, GraphProjectionManifestIdentity, GraphRoutedQuery,
    GraphRoutedRecallParams, GraphRoutedRecallReport, KernelArtifact, KernelGraph,
    KernelSourceIdentity, PreparedKernelArtifactRows, decode_kernel_artifact_rows,
    graph_routed_kernel_artifact_hash, graph_routed_query_content_hash, graph_routed_query_cx_id,
    graph_routed_query_vector_hash, prepare_kernel_artifact_rows,
    read_graph_projection_manifest_identity_at, validate_graph_routed_recall_report,
};
use astrolabe_panel::{
    FrozenLensContract, NOMIC_EMBED_DIM, NOMIC_TOKEN_TABLE_SHA256, NOMIC_VECTOR_BLOB_SHA256,
    StaticEmbeddingInput, encode_static_embedding_slot, nomic_weights_identity,
    panel_slot_manifest_sha256, shared_default_static_embedding_table, slots_for_version,
};
use calyx_aster::cf::ColumnFamily;
use calyx_aster::mvcc::{is_tombstone_value, tombstone_value};
use calyx_aster::vault::AsterVault;
use calyx_core::{Clock, LedgerRef, SlotVector};
use calyx_ledger::{ActorId, EntryKind, SubjectId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::kernel_index::{
    KernelMemberIndex, KernelMemberIndexDescriptor, LoadedKernelMemberIndex,
    PreparedKernelMemberIndexRows, loaded_from_parts, prepare_kernel_member_index_rows,
    validate_descriptor, verify_source_binding_generations_at,
};
use crate::search::{SLOT_NAME_SEMANTIC, SearchError};
use crate::search_index::split_identifier_tokens;
use crate::slot_source::WeaveSlotBinding;

/// Composite manifest schema.
pub const KERNEL_GENERATION_MANIFEST_SCHEMA: &str = "astrolabe.kernel_generation_manifest.v3";
/// Fixed current-pointer schema.
pub const KERNEL_GENERATION_POINTER_SCHEMA: &str = "astrolabe.kernel_generation_pointer.v3";
/// Ledger payload schema for one complete generation publication.
pub const KERNEL_GENERATION_LEDGER_SCHEMA: &str = "astrolabe.kernel_generation_ledger.v3";
/// Exact point-readable source state bound into a complete generation.
pub const KERNEL_GENERATION_SOURCE_BINDING_SCHEMA: &str =
    "astrolabe.kernel_generation_source_binding.v1";
/// Content-addressed generation-row namespace.
pub const KERNEL_GENERATION_CF_PREFIX: &[u8] = b"astrolabe:kernel-generation:v3:";
/// Fixed per-project/scope current-pointer namespace.
pub const KERNEL_GENERATION_CURRENT_PREFIX: &[u8] = b"astrolabe:kernel-generation-current:v3:";
/// Explicit predecessor identity for a first v3 generation.
pub const KERNEL_GENERATION_GENESIS_PREVIOUS_ID: &str = "genesis";
const LEGACY_KERNEL_GENERATION_CURRENT_PREFIX_V1: &[u8] =
    b"astrolabe:kernel-generation-current:v1:";
const LEGACY_KERNEL_GENERATION_CURRENT_PREFIX_V2: &[u8] =
    b"astrolabe:kernel-generation-current:v2:";
/// The sole actor permitted to publish a production complete kernel generation.
pub const KERNEL_GENERATION_ACTOR: &str = "astrolabe-kernel-generation";
/// Persisted real-query corpus schema bound to graph-routed admission.
pub const KERNEL_RECALL_QUERY_CORPUS_SCHEMA: &str = "astrolabe.kernel_recall_query_corpus.v1";
/// Exact production free-text-to-S20 encoder identity stored with the corpus.
pub const KERNEL_RECALL_QUERY_ENCODER_SCHEMA: &str = "astrolabe.kernel_recall_query_encoder.v1";
/// Input shaping used by the shipping free-text S20 query path.
pub const KERNEL_RECALL_QUERY_INPUT_SEMANTICS: &str =
    "split_identifier_tokens(content);doc=[];name=content;qualified_name=content.v1";
/// Fixed alias namespace for the currently admitted real-query corpus.
pub const KERNEL_RECALL_QUERY_CORPUS_PREFIX: &[u8] = b"astrolabe:kernel-recall-query-corpus:v1:";
/// Fixed alias namespace for the current graph-routed admission report.
pub const KERNEL_GRAPH_ROUTED_REPORT_PREFIX: &[u8] = b"astrolabe:kernel-graph-routed-recall:v1:";

/// A complete generation or its current pointer is malformed or inconsistent.
pub const ASTRO_KERNEL_GENERATION_CORRUPT: &str = "ASTRO_KERNEL_GENERATION_CORRUPT";
/// Complete generation persistence, flush, or independent readback failed.
pub const ASTRO_KERNEL_GENERATION_PERSIST: &str = "ASTRO_KERNEL_GENERATION_PERSIST";
/// Artifact and member-index preparation describe different source/member state.
pub const ASTRO_KERNEL_GENERATION_INCOMPLETE: &str = "ASTRO_KERNEL_GENERATION_INCOMPLETE";
/// A first generation lacks real external queries or their exact S20 contract.
pub const ASTRO_KERNEL_ADMISSION_REQUIRED: &str = "ASTRO_KERNEL_ADMISSION_REQUIRED";

const MANIFEST_LEAF: &[u8] = b"manifest.json";
const CURRENT_LEAF: &[u8] = b"current.json";

const LOGICAL_KERNEL_JSON: &str = "kernel.json";
const LOGICAL_INDEX_JSON: &str = "index.json";
const LOGICAL_MEMBERS_HASH: &str = "members-hash";
const LOGICAL_MEMBER_DESCRIPTOR: &str = "member-descriptor.json";
const LOGICAL_MEMBER_BINDINGS: &str = "member-bindings.json";
const LOGICAL_MEMBER_HNSW: &str = "s20.hnsw";
const LOGICAL_QUERY_CORPUS: &str = "real-query-corpus.json";
const LOGICAL_GRAPH_ROUTED_REPORT: &str = "graph-routed-recall.json";

/// Raw real operator/query-log input accepted by the production admission path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelRecallQueryInput {
    pub stable_id: String,
    pub source: String,
    pub content: String,
}

/// Exact production encoder/table/model identity for every query vector.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelRecallQueryEncoderIdentity {
    pub schema: String,
    pub input_semantics: String,
    pub panel_version: u32,
    pub slot: u16,
    pub lens_id: String,
    pub panel_slot_manifest_sha256: String,
    pub weights_sha256: String,
    pub vector_blob_sha256: String,
    pub token_table_sha256: String,
    pub vector_dimension: u32,
    pub identity_hash: String,
}

/// One free-text query encoded by the exact production S20 path.
///
/// Serving callers compare [`Self::encoder`] with the immutable generation
/// identity before using [`Self::vector`]. This is query execution, not recall
/// evidence construction: only [`build_kernel_recall_query_corpus`] may turn
/// explicitly supplied external query-log rows into admission evidence.
#[derive(Clone, Debug, PartialEq)]
pub struct KernelRecallEncodedQuery {
    pub encoder: KernelRecallQueryEncoderIdentity,
    pub vector: Vec<f32>,
}

/// One real operator/query-log record and its production S20 embedding.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelRecallQueryRecord {
    pub stable_id: String,
    pub source: String,
    pub content: String,
    pub content_sha256: String,
    pub query_cx_id: calyx_core::CxId,
    pub encoder_input_sha256: String,
    pub vector_sha256: String,
    pub vector: Vec<f32>,
}

impl KernelRecallQueryRecord {
    pub fn graph_routed_query(&self) -> GraphRoutedQuery {
        GraphRoutedQuery {
            stable_id: self.stable_id.clone(),
            source: self.source.clone(),
            content: self.content.clone(),
            query_cx_id: self.query_cx_id,
            content_hash: self.content_sha256.clone(),
            vector: self.vector.clone(),
        }
    }
}

/// Canonical authoritative input row retained beside its admission report.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelRecallQueryCorpus {
    pub schema: String,
    pub project: String,
    pub scope_id: String,
    pub panel_version: u32,
    pub slot: u16,
    pub encoder: KernelRecallQueryEncoderIdentity,
    pub queries: Vec<KernelRecallQueryRecord>,
    pub params: GraphRoutedRecallParams,
    pub corpus_hash: String,
}

impl KernelRecallQueryCorpus {
    /// Canonical persisted bytes after exact content/vector/roster/hash checks.
    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>, SearchError> {
        validate_query_corpus(self)?;
        let mut bytes = serde_json::to_vec_pretty(self)
            .map_err(|error| incomplete(format!("stage=query_corpus_encode error={error}")))?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    pub fn graph_routed_queries(&self) -> Vec<GraphRoutedQuery> {
        self.queries
            .iter()
            .map(KernelRecallQueryRecord::graph_routed_query)
            .collect()
    }
}

/// Builds the canonical real-query corpus with the exact shipping S20 query
/// encoder. Input rows are never synthesized or selected from graph members.
pub fn build_kernel_recall_query_corpus(
    project: &str,
    scope_id: &str,
    panel_version: u32,
    inputs: &[KernelRecallQueryInput],
    params: GraphRoutedRecallParams,
) -> Result<KernelRecallQueryCorpus, SearchError> {
    if inputs.is_empty() {
        return Err(admission_required(
            "stage=query_input expected=nonempty_real_external_query_roster observed=empty",
        ));
    }
    let encoder = expected_query_encoder_identity(panel_version)?;
    if params.expected_vector_dimension != encoder.vector_dimension as usize {
        return Err(admission_required(format!(
            "stage=query_params expected_vector_dimension={} observed_vector_dimension={}",
            encoder.vector_dimension, params.expected_vector_dimension
        )));
    }
    let table = shared_default_static_embedding_table().map_err(|error| {
        admission_required(format!(
            "stage=query_encoder_table code={} message={:?} remediation={:?}",
            error.code(),
            error.message(),
            error.remediation()
        ))
    })?;
    let mut queries = Vec::with_capacity(inputs.len());
    for input in inputs {
        let embedding_input = production_query_embedding_input(&input.content);
        let encoded = encode_static_embedding_slot(SLOT_NAME_SEMANTIC, &embedding_input, table)
            .map_err(|error| {
                admission_required(format!(
                    "stage=query_encode stable_id={:?} source={:?} code={} message={:?} remediation={:?}",
                    input.stable_id,
                    input.source,
                    error.code(),
                    error.message(),
                    error.remediation()
                ))
            })?;
        let SlotVector::Dense { dim, data } = encoded else {
            return Err(admission_required(format!(
                "stage=query_encode stable_id={:?} source={:?} expected=dense_s20_vector observed=absent_or_wrong_shape",
                input.stable_id, input.source
            )));
        };
        if dim != encoder.vector_dimension {
            return Err(admission_required(format!(
                "stage=query_encode stable_id={:?} expected_dim={} observed_dim={dim}",
                input.stable_id, encoder.vector_dimension
            )));
        }
        queries.push(KernelRecallQueryRecord {
            stable_id: input.stable_id.clone(),
            source: input.source.clone(),
            content: input.content.clone(),
            content_sha256: graph_routed_query_content_hash(input.content.as_bytes()),
            query_cx_id: graph_routed_query_cx_id(
                &input.stable_id,
                &input.source,
                input.content.as_bytes(),
            ),
            encoder_input_sha256: query_encoder_input_hash(&embedding_input)?,
            vector_sha256: graph_routed_query_vector_hash(&data),
            vector: data,
        });
    }
    queries.sort_by_key(|query| query.query_cx_id);
    let mut corpus = KernelRecallQueryCorpus {
        schema: KERNEL_RECALL_QUERY_CORPUS_SCHEMA.to_string(),
        project: project.to_string(),
        scope_id: scope_id.to_string(),
        panel_version,
        slot: SLOT_NAME_SEMANTIC.get(),
        encoder,
        queries,
        params,
        corpus_hash: String::new(),
    };
    corpus.corpus_hash = compute_query_corpus_hash(&corpus)?;
    validate_query_corpus_encoder(&corpus)?;
    Ok(corpus)
}

/// Recomputes the encoder identity, input frame, and every vector from the real
/// persisted query rows. Reuse is authorized only by exact bit equality.
pub fn validate_kernel_recall_query_corpus_encoder(
    corpus: &KernelRecallQueryCorpus,
) -> Result<(), SearchError> {
    validate_query_corpus_encoder(corpus)
}

/// Returns the exact production S20 encoder identity without encoding a query.
///
/// Shadow no-op admission binds this identity beside the canonical external
/// query roster. A model/table/panel change therefore invalidates the action
/// before an old complete kernel generation can be reported as unchanged.
pub fn kernel_recall_query_encoder_identity(
    panel_version: u32,
) -> Result<KernelRecallQueryEncoderIdentity, SearchError> {
    expected_query_encoder_identity(panel_version)
}

/// Encodes one actual serving query through the same production S20 table,
/// framing, and panel identity used by recall admission.
///
/// This function never manufactures a query-log row or admission claim. It
/// returns only the encoder identity and dense vector for caller-supplied text.
pub fn encode_kernel_recall_query(
    panel_version: u32,
    content: &str,
) -> Result<KernelRecallEncodedQuery, SearchError> {
    if content.trim().is_empty() {
        return Err(admission_required(
            "stage=serving_query expected=nonempty_actual_query observed=empty",
        ));
    }
    let encoder = expected_query_encoder_identity(panel_version)?;
    let table = shared_default_static_embedding_table().map_err(|error| {
        admission_required(format!(
            "stage=serving_query_encoder_table code={} message={:?} remediation={:?}",
            error.code(),
            error.message(),
            error.remediation()
        ))
    })?;
    let input = production_query_embedding_input(content);
    let encoded =
        encode_static_embedding_slot(SLOT_NAME_SEMANTIC, &input, table).map_err(|error| {
            admission_required(format!(
                "stage=serving_query_encode code={} message={:?} remediation={:?}",
                error.code(),
                error.message(),
                error.remediation()
            ))
        })?;
    let SlotVector::Dense { dim, data } = encoded else {
        return Err(admission_required(
            "stage=serving_query_encode expected=dense_s20_vector observed=absent_or_wrong_shape",
        ));
    };
    if dim != encoder.vector_dimension
        || data.len() != encoder.vector_dimension as usize
        || data.iter().any(|value| !value.is_finite())
        || !data.iter().any(|value| *value != 0.0)
    {
        return Err(admission_required(format!(
            "stage=serving_query_encode expected_dim={} observed_dim={dim} observed_len={} finite={} nonzero={}",
            encoder.vector_dimension,
            data.len(),
            data.iter().all(|value| value.is_finite()),
            data.iter().any(|value| *value != 0.0),
        )));
    }
    Ok(KernelRecallEncodedQuery {
        encoder,
        vector: data,
    })
}

fn production_query_embedding_input(content: &str) -> StaticEmbeddingInput {
    StaticEmbeddingInput {
        body_tokens: split_identifier_tokens(content),
        doc_tokens: Vec::new(),
        name: content.to_string(),
        qualified_name: content.to_string(),
    }
}

fn expected_query_encoder_identity(
    panel_version: u32,
) -> Result<KernelRecallQueryEncoderIdentity, SearchError> {
    let slots = slots_for_version(panel_version).map_err(|error| {
        admission_required(format!(
            "stage=query_encoder_identity panel_version={panel_version} code={} message={:?} remediation={:?}",
            error.code(),
            error.message(),
            error.remediation()
        ))
    })?;
    let slot = slots
        .iter()
        .find(|slot| slot.slot_id() == SLOT_NAME_SEMANTIC)
        .ok_or_else(|| {
            admission_required(format!(
                "stage=query_encoder_identity panel_version={panel_version} expected_slot=S{} observed=absent",
                SLOT_NAME_SEMANTIC.get()
            ))
        })?;
    let contract = FrozenLensContract::for_slot_version(slot, panel_version).map_err(|error| {
        admission_required(format!(
            "stage=query_encoder_identity panel_version={panel_version} slot=S{} code={} message={:?} remediation={:?}",
            SLOT_NAME_SEMANTIC.get(),
            error.code(),
            error.message(),
            error.remediation()
        ))
    })?;
    let slot_manifest = panel_slot_manifest_sha256(panel_version).map_err(|error| {
        admission_required(format!(
            "stage=query_encoder_identity panel_version={panel_version} code={} message={:?} remediation={:?}",
            error.code(),
            error.message(),
            error.remediation()
        ))
    })?;
    let vector_dimension = u32::try_from(NOMIC_EMBED_DIM).map_err(|_| {
        admission_required(format!(
            "stage=query_encoder_identity nomic_dimension={NOMIC_EMBED_DIM} exceeds u32"
        ))
    })?;
    let mut identity = KernelRecallQueryEncoderIdentity {
        schema: KERNEL_RECALL_QUERY_ENCODER_SCHEMA.to_string(),
        input_semantics: KERNEL_RECALL_QUERY_INPUT_SEMANTICS.to_string(),
        panel_version,
        slot: SLOT_NAME_SEMANTIC.get(),
        lens_id: contract.lens_id().to_string(),
        panel_slot_manifest_sha256: hex_lower(&slot_manifest),
        weights_sha256: hex_lower(&nomic_weights_identity()),
        vector_blob_sha256: hex_lower(&NOMIC_VECTOR_BLOB_SHA256),
        token_table_sha256: hex_lower(&NOMIC_TOKEN_TABLE_SHA256),
        vector_dimension,
        identity_hash: String::new(),
    };
    identity.identity_hash = compute_query_encoder_identity_hash(&identity);
    Ok(identity)
}

fn compute_query_encoder_identity_hash(identity: &KernelRecallQueryEncoderIdentity) -> String {
    let mut hasher = sha256_identity_hasher(b"astrolabe.kernel_recall.query_encoder.v1\0");
    for part in [
        identity.schema.as_bytes(),
        identity.input_semantics.as_bytes(),
        &identity.panel_version.to_be_bytes(),
        &identity.slot.to_be_bytes(),
        identity.lens_id.as_bytes(),
        identity.panel_slot_manifest_sha256.as_bytes(),
        identity.weights_sha256.as_bytes(),
        identity.vector_blob_sha256.as_bytes(),
        identity.token_table_sha256.as_bytes(),
        &identity.vector_dimension.to_be_bytes(),
    ] {
        sha256_part(&mut hasher, part);
    }
    sha256_finish(hasher)
}

fn query_encoder_input_hash(input: &StaticEmbeddingInput) -> Result<String, SearchError> {
    let mut hasher = sha256_identity_hasher(b"astrolabe.kernel_recall.query_input.v1\0");
    sha256_part(
        &mut hasher,
        &(input.body_tokens.len() as u128).to_be_bytes(),
    );
    for token in &input.body_tokens {
        sha256_part(&mut hasher, token.as_bytes());
    }
    sha256_part(&mut hasher, &(input.doc_tokens.len() as u128).to_be_bytes());
    for token in &input.doc_tokens {
        sha256_part(&mut hasher, token.as_bytes());
    }
    sha256_part(&mut hasher, input.name.as_bytes());
    sha256_part(&mut hasher, input.qualified_name.as_bytes());
    Ok(sha256_finish(hasher))
}

fn compute_query_corpus_hash(corpus: &KernelRecallQueryCorpus) -> Result<String, SearchError> {
    let params = serde_json::to_vec(&corpus.params).map_err(|error| {
        admission_required(format!(
            "stage=query_corpus_hash params_encode_error={error}"
        ))
    })?;
    let encoder = serde_json::to_vec(&corpus.encoder).map_err(|error| {
        admission_required(format!(
            "stage=query_corpus_hash encoder_encode_error={error}"
        ))
    })?;
    let mut hasher = sha256_identity_hasher(b"astrolabe.kernel_recall.query_corpus.v1\0");
    for part in [
        corpus.schema.as_bytes(),
        corpus.project.as_bytes(),
        corpus.scope_id.as_bytes(),
        &corpus.panel_version.to_be_bytes(),
        &corpus.slot.to_be_bytes(),
        encoder.as_slice(),
        params.as_slice(),
        &(corpus.queries.len() as u128).to_be_bytes(),
    ] {
        sha256_part(&mut hasher, part);
    }
    for query in &corpus.queries {
        sha256_part(&mut hasher, query.stable_id.as_bytes());
        sha256_part(&mut hasher, query.source.as_bytes());
        sha256_part(&mut hasher, query.content.as_bytes());
        sha256_part(&mut hasher, query.content_sha256.as_bytes());
        sha256_part(&mut hasher, query.query_cx_id.as_bytes());
        sha256_part(&mut hasher, query.encoder_input_sha256.as_bytes());
        sha256_part(&mut hasher, query.vector_sha256.as_bytes());
        sha256_part(&mut hasher, &(query.vector.len() as u128).to_be_bytes());
        for value in &query.vector {
            sha256_part(&mut hasher, &value.to_bits().to_be_bytes());
        }
    }
    Ok(sha256_finish(hasher))
}

fn validate_query_corpus(corpus: &KernelRecallQueryCorpus) -> Result<(), SearchError> {
    if corpus.schema != KERNEL_RECALL_QUERY_CORPUS_SCHEMA
        || corpus.project.trim().is_empty()
        || corpus.scope_id.trim().is_empty()
        || corpus.panel_version == 0
        || corpus.slot != SLOT_NAME_SEMANTIC.get()
        || corpus.queries.is_empty()
    {
        return Err(admission_required(format!(
            "stage=query_corpus_shape expected_schema={KERNEL_RECALL_QUERY_CORPUS_SCHEMA:?} observed_schema={:?} project={:?} scope={:?} panel_version={} expected_slot={} observed_slot={} query_count={}",
            corpus.schema,
            corpus.project,
            corpus.scope_id,
            corpus.panel_version,
            SLOT_NAME_SEMANTIC.get(),
            corpus.slot,
            corpus.queries.len()
        )));
    }
    let expected_encoder = expected_query_encoder_identity(corpus.panel_version)?;
    if corpus.encoder != expected_encoder
        || corpus.encoder.panel_version != corpus.panel_version
        || corpus.encoder.slot != corpus.slot
        || corpus.params.expected_vector_dimension != corpus.encoder.vector_dimension as usize
    {
        return Err(admission_required(format!(
            "stage=query_encoder_binding expected={expected_encoder:?} observed={:?} params_expected_dimension={}",
            corpus.encoder, corpus.params.expected_vector_dimension
        )));
    }
    require_admission_hash(
        "corpus.encoder.identity_hash",
        &corpus.encoder.identity_hash,
    )?;
    require_admission_hash("corpus.corpus_hash", &corpus.corpus_hash)?;
    let mut stable_ids = BTreeSet::new();
    let mut content_hashes = BTreeSet::new();
    let mut prior_id = None;
    for query in &corpus.queries {
        if query.stable_id.trim().is_empty()
            || query.source.trim().is_empty()
            || query.content.trim().is_empty()
        {
            return Err(admission_required(format!(
                "stage=query_record_identity query_id={} stable_id={:?} source={:?} content_bytes={}",
                query.query_cx_id,
                query.stable_id,
                query.source,
                query.content.len()
            )));
        }
        if prior_id.is_some_and(|prior| prior >= query.query_cx_id) {
            return Err(admission_required(format!(
                "stage=query_roster expected=strictly_ascending_unique observed_query_id={} prior_query_id={prior_id:?}",
                query.query_cx_id
            )));
        }
        prior_id = Some(query.query_cx_id);
        if !stable_ids.insert(query.stable_id.as_str()) {
            return Err(admission_required(format!(
                "stage=query_roster duplicate_stable_id={:?}",
                query.stable_id
            )));
        }
        if !content_hashes.insert(query.content_sha256.as_str()) {
            return Err(admission_required(format!(
                "stage=query_roster duplicate_content_sha256={}",
                query.content_sha256
            )));
        }
        for (label, value) in [
            ("content_sha256", query.content_sha256.as_str()),
            ("encoder_input_sha256", query.encoder_input_sha256.as_str()),
            ("vector_sha256", query.vector_sha256.as_str()),
        ] {
            require_admission_hash(label, value)?;
        }
        let expected_content = graph_routed_query_content_hash(query.content.as_bytes());
        let expected_id =
            graph_routed_query_cx_id(&query.stable_id, &query.source, query.content.as_bytes());
        let expected_input = production_query_embedding_input(&query.content);
        let expected_input_hash = query_encoder_input_hash(&expected_input)?;
        let expected_vector_hash = graph_routed_query_vector_hash(&query.vector);
        if query.content_sha256 != expected_content
            || query.query_cx_id != expected_id
            || query.encoder_input_sha256 != expected_input_hash
            || query.vector_sha256 != expected_vector_hash
            || query.vector.len() != corpus.encoder.vector_dimension as usize
            || query.vector.iter().any(|value| !value.is_finite())
            || !query.vector.iter().any(|value| *value != 0.0)
        {
            return Err(admission_required(format!(
                "stage=query_record_validate stable_id={:?} query_id={} expected_id={} expected_content_hash={} observed_content_hash={} expected_input_hash={} observed_input_hash={} expected_vector_hash={} observed_vector_hash={} expected_dim={} observed_dim={} finite={} nonzero={}",
                query.stable_id,
                query.query_cx_id,
                expected_id,
                expected_content,
                query.content_sha256,
                expected_input_hash,
                query.encoder_input_sha256,
                expected_vector_hash,
                query.vector_sha256,
                corpus.encoder.vector_dimension,
                query.vector.len(),
                query.vector.iter().all(|value| value.is_finite()),
                query.vector.iter().any(|value| *value != 0.0)
            )));
        }
    }
    let expected_corpus_hash = compute_query_corpus_hash(corpus)?;
    if corpus.corpus_hash != expected_corpus_hash {
        return Err(admission_required(format!(
            "stage=query_corpus_hash expected={expected_corpus_hash} observed={}",
            corpus.corpus_hash
        )));
    }
    Ok(())
}

fn validate_query_corpus_encoder(corpus: &KernelRecallQueryCorpus) -> Result<(), SearchError> {
    validate_query_corpus(corpus)?;
    let table = shared_default_static_embedding_table().map_err(|error| {
        admission_required(format!(
            "stage=query_encoder_revalidate code={} message={:?} remediation={:?}",
            error.code(),
            error.message(),
            error.remediation()
        ))
    })?;
    for query in &corpus.queries {
        let input = production_query_embedding_input(&query.content);
        let encoded = encode_static_embedding_slot(SLOT_NAME_SEMANTIC, &input, table).map_err(
            |error| {
                admission_required(format!(
                    "stage=query_encoder_revalidate stable_id={:?} code={} message={:?} remediation={:?}",
                    query.stable_id,
                    error.code(),
                    error.message(),
                    error.remediation()
                ))
            },
        )?;
        let SlotVector::Dense { dim, data } = encoded else {
            return Err(admission_required(format!(
                "stage=query_encoder_revalidate stable_id={:?} expected=dense_s20_vector observed=absent_or_wrong_shape",
                query.stable_id
            )));
        };
        let exact_bits = data
            .iter()
            .map(|value| value.to_bits())
            .eq(query.vector.iter().map(|value| value.to_bits()));
        if dim != corpus.encoder.vector_dimension || !exact_bits {
            return Err(admission_required(format!(
                "stage=query_encoder_revalidate stable_id={:?} expected_dim={} observed_dim={dim} exact_vector_bits={exact_bits} expected_vector_hash={} recomputed_vector_hash={}",
                query.stable_id,
                corpus.encoder.vector_dimension,
                query.vector_sha256,
                graph_routed_query_vector_hash(&data)
            )));
        }
    }
    Ok(())
}

fn validate_recall_admission_join(join: RecallAdmissionJoin<'_>) -> Result<(), SearchError> {
    let RecallAdmissionJoin {
        project,
        scope_id,
        artifact,
        semantic_dim,
        slot,
        panel_version,
        corpus,
        report,
    } = join;
    validate_query_corpus_encoder(corpus)?;
    report.canonical_json_bytes().map_err(|error| {
        admission_required(format!(
            "stage=graph_routed_report_validate code={} message={:?} remediation={:?}",
            error.code(),
            error.message(),
            error.remediation()
        ))
    })?;
    let artifact_members = artifact
        .members
        .iter()
        .map(|member| member.id)
        .collect::<Vec<_>>();
    let corpus_queries = corpus.graph_routed_queries();
    let corpus_query_ids = corpus_queries
        .iter()
        .map(|query| query.query_cx_id)
        .collect::<Vec<_>>();
    let evidence_matches = report.queries.len() == corpus.queries.len()
        && report
            .queries
            .iter()
            .zip(&corpus.queries)
            .all(|(evidence, query)| {
                evidence.query_cx_id == query.query_cx_id
                    && evidence.query_stable_id == query.stable_id
                    && evidence.query_source == query.source
                    && evidence.query_content_hash == query.content_sha256
                    && evidence.query_vector_hash == query.vector_sha256
            });
    if corpus.project != project
        || corpus.scope_id != scope_id
        || corpus.panel_version == 0
        || corpus.slot != SLOT_NAME_SEMANTIC.get()
        || slot != SLOT_NAME_SEMANTIC
        || panel_version != corpus.panel_version
        || semantic_dim != corpus.encoder.vector_dimension
        || corpus.params.expected_vector_dimension != corpus.encoder.vector_dimension as usize
        || report.params != corpus.params
        || report.source_identity != artifact.source_identity
        || report.kernel_artifact_hash != graph_routed_kernel_artifact_hash(artifact)
        || report.node_count != artifact.node_count
        || report.directed_edge_count != artifact.source_identity.edge_count
        || report.vector_dimension != corpus.encoder.vector_dimension as usize
        || report.entry_member_ids != artifact_members
        || report.kernel_member_count != artifact.member_count
        || report.kernel_member_fraction_permille != artifact.compactness.member_fraction_permille
        || report.query_ids != corpus_query_ids
        || !evidence_matches
        || !report.compactness_admitted
        || !report.admitted
    {
        return Err(admission_required(format!(
            "stage=admission_join expected_project={project:?} observed_project={:?} expected_scope={scope_id:?} observed_scope={:?} expected_source={:?} observed_source={:?} expected_artifact_hash={} observed_artifact_hash={} expected_members={artifact_members:?} observed_members={:?} expected_queries={corpus_query_ids:?} observed_queries={:?} expected_panel_version={panel_version} observed_panel_version={} expected_dim={} observed_dim={} report_admitted={} compactness_admitted={} evidence_matches={evidence_matches}",
            corpus.project,
            corpus.scope_id,
            artifact.source_identity,
            report.source_identity,
            graph_routed_kernel_artifact_hash(artifact),
            report.kernel_artifact_hash,
            report.entry_member_ids,
            report.query_ids,
            corpus.panel_version,
            corpus.encoder.vector_dimension,
            report.vector_dimension,
            report.admitted,
            report.compactness_admitted
        )));
    }
    Ok(())
}

fn validate_recall_artifact_join(
    project: &str,
    scope_id: &str,
    artifact: &KernelArtifact,
    manifest: &KernelGenerationManifest,
    corpus: &KernelRecallQueryCorpus,
    report: &GraphRoutedRecallReport,
) -> Result<(), SearchError> {
    validate_recall_admission_join(RecallAdmissionJoin {
        project,
        scope_id,
        artifact,
        semantic_dim: manifest.semantic_dim,
        slot: manifest.source_binding.slot,
        panel_version: manifest.panel_version,
        corpus,
        report,
    })?;
    if manifest.query_encoder_identity_hash != corpus.encoder.identity_hash
        || manifest.query_corpus_hash != corpus.corpus_hash
        || manifest.graph_routed_report_hash != report.report_hash
    {
        return Err(corrupt(format!(
            "stage=admission_manifest expected_encoder_hash={} observed_encoder_hash={} expected_corpus_hash={} observed_corpus_hash={} expected_report_hash={} observed_report_hash={}",
            corpus.encoder.identity_hash,
            manifest.query_encoder_identity_hash,
            corpus.corpus_hash,
            manifest.query_corpus_hash,
            report.report_hash,
            manifest.graph_routed_report_hash
        )));
    }
    Ok(())
}

/// Exact key/hash/count binding for one of the eight logical generation rows.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelGenerationRowBinding {
    pub logical_name: String,
    pub generation_key_hex: String,
    pub fixed_alias_key_hex: String,
    pub bytes: u64,
    pub blake3: String,
}

/// Pointer target retained as current or previous.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelGenerationPointerTarget {
    pub generation_id: String,
    pub manifest_key_hex: String,
    pub manifest_blake3: String,
    pub commit_seq: u64,
    pub ledger_ref: LedgerRef,
}

/// Immutable manifest for one complete content generation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelGenerationManifest {
    pub schema: String,
    pub project: String,
    pub scope_id: String,
    pub generation_id: String,
    /// Stable semantic source identity used to detect an unchanged generation.
    /// It excludes the captured MVCC sequence while binding all graph, anchor,
    /// member, S20 representation, dimension, and index-knob inputs.
    pub source_generation_identity: String,
    pub base_seq: u64,
    pub artifact_source_identity: KernelSourceIdentity,
    pub members_hash: String,
    pub member_count: usize,
    pub binding_count: usize,
    pub indexed_member_count: usize,
    pub semantic_dim: u32,
    pub panel_version: u32,
    pub generation_source_binding: KernelGenerationSourceBinding,
    pub source_binding: WeaveSlotBinding,
    pub query_encoder_identity_hash: String,
    pub query_corpus_hash: String,
    pub graph_routed_report_hash: String,
    pub rows: Vec<KernelGenerationRowBinding>,
    pub ledger_ref: LedgerRef,
    pub ledger_payload_blake3: String,
    /// Exact predecessor content address, or the explicit `genesis` sentinel.
    pub previous_generation_id: String,
    pub retired_generation_id: Option<String>,
    pub retention: String,
}

/// Fixed pointer whose publication is the only visibility transition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelGenerationPointer {
    pub schema: String,
    pub project: String,
    pub scope_id: String,
    pub current: KernelGenerationPointerTarget,
    /// Must equal `previous.generation_id`, or explicit `genesis` when
    /// `previous` is absent.
    pub previous_generation_id: String,
    pub previous: Option<KernelGenerationPointerTarget>,
    pub retained_generation_count: usize,
}

/// Current artifact plus the composite pointer/manifest that selected it.
#[derive(Clone, Debug)]
pub struct CurrentKernelGenerationArtifact {
    pub artifact: KernelArtifact,
    pub query_corpus: KernelRecallQueryCorpus,
    pub graph_routed_report: GraphRoutedRecallReport,
    pub manifest: KernelGenerationManifest,
    pub pointer: KernelGenerationPointer,
    pub rows_verified: usize,
}

/// Current descriptor plus the composite pointer/manifest that selected it.
#[derive(Clone, Debug)]
pub struct CurrentKernelGenerationDescriptor {
    pub descriptor: KernelMemberIndexDescriptor,
    pub manifest: KernelGenerationManifest,
    pub pointer: KernelGenerationPointer,
    pub rows_verified: usize,
}

/// Narrow current-generation header used by external warm-cache guards.
///
/// Resolving this value point-reads only the current pointer, its immutable
/// manifest, and the manifest-bound physical Ledger row. It does not read any
/// artifact, query, member-binding, or HNSW generation row and it does not
/// deep-read the retained predecessor generation.
#[derive(Clone, Debug)]
pub struct CurrentKernelGenerationHeader {
    pub manifest: KernelGenerationManifest,
    pub pointer: KernelGenerationPointer,
}

/// Fully decoded current artifact and checksum-validated member HNSW.
#[derive(Clone, Debug)]
pub struct CurrentKernelGeneration {
    pub artifact: KernelArtifact,
    pub index: LoadedKernelMemberIndex,
    pub query_corpus: KernelRecallQueryCorpus,
    pub graph_routed_report: GraphRoutedRecallReport,
    pub manifest: KernelGenerationManifest,
    pub pointer: KernelGenerationPointer,
    pub rows_verified: usize,
}

/// One independently point-read persisted row included in publication evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelGenerationReadbackRow {
    pub key_hex: String,
    pub bytes: usize,
    pub blake3: String,
    pub tombstoned: bool,
}

/// Full publication/no-op report. Return values are backed by point reads of the
/// pointer, manifest, eight generation rows, eight aliases, and physical Ledger row.
#[derive(Clone, Debug)]
pub struct KernelGenerationPersistReport {
    pub published: bool,
    pub commit_seq: u64,
    pub generation_id: String,
    pub source_generation_identity: String,
    pub artifact: KernelArtifact,
    pub descriptor: KernelMemberIndexDescriptor,
    pub manifest: KernelGenerationManifest,
    pub pointer: KernelGenerationPointer,
    pub ledger_ref: LedgerRef,
    pub ledger_physical_tiers: Vec<String>,
    pub rows_readback_verified: usize,
    pub readback_rows: Vec<KernelGenerationReadbackRow>,
    pub retired_generation_id: Option<String>,
    pub flush_sst_files: usize,
    pub flush_sst_entries: usize,
    pub flush_sst_bytes: u64,
}

#[derive(Clone)]
struct LogicalPreparedRow {
    logical_name: &'static str,
    generation_key: Vec<u8>,
    fixed_alias_key: Vec<u8>,
    value: Vec<u8>,
}

#[derive(Clone)]
struct GenerationHeader {
    pointer: KernelGenerationPointer,
    manifest: KernelGenerationManifest,
}

#[derive(Serialize)]
struct StableSourceIdentity<'a> {
    schema: &'static str,
    project: &'a str,
    scope_id: &'a str,
    artifact_source_identity: &'a KernelSourceIdentity,
    artifact_kernel_blake3: String,
    artifact_index_blake3: String,
    artifact_members_blake3: String,
    members_hash: &'a str,
    member_count: usize,
    bindings_blake3: &'a str,
    binding_count: usize,
    indexed_member_count: usize,
    semantic_dim: u32,
    panel_version: u32,
    source_binding: &'a WeaveSlotBinding,
    generation_source_binding: &'a KernelGenerationSourceBinding,
    knobs: &'a crate::search_index::IndexKnobs,
    query_encoder_identity_hash: &'a str,
    query_corpus_hash: &'a str,
    graph_routed_report_hash: &'a str,
}

/// Exact durable source state that ordinary serving can verify with bounded
/// point reads. Column-family generations are persisted by Aster and therefore
/// remain stable across reopen when a disjoint family advances.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelGenerationSourceBinding {
    pub schema: String,
    pub graph_content_generation: u64,
    pub anchors_content_generation: u64,
    pub anchor_metadata_content_generation: u64,
    pub projection_manifest: GraphProjectionManifestIdentity,
}

/// All immutable inputs to one atomic complete-generation publication.
pub struct KernelGenerationPublishRequest<'a> {
    pub project: &'a str,
    pub scope_id: &'a str,
    pub artifact: &'a KernelArtifact,
    pub index: &'a KernelMemberIndex,
    pub query_corpus: &'a KernelRecallQueryCorpus,
    pub graph_routed_report: &'a GraphRoutedRecallReport,
    pub graph: &'a KernelGraph,
    pub complete_vectors: &'a BTreeMap<calyx_core::CxId, Vec<f32>>,
    pub base_seq: u64,
}

struct RecallAdmissionJoin<'a> {
    project: &'a str,
    scope_id: &'a str,
    artifact: &'a KernelArtifact,
    semantic_dim: u32,
    slot: calyx_core::SlotId,
    panel_version: u32,
    corpus: &'a KernelRecallQueryCorpus,
    report: &'a GraphRoutedRecallReport,
}

struct StableSourceInputs<'a> {
    project: &'a str,
    scope_id: &'a str,
    artifact: &'a PreparedKernelArtifactRows,
    index: &'a PreparedKernelMemberIndexRows,
    semantic_dim: u32,
    panel_version: u32,
    generation_source_binding: &'a KernelGenerationSourceBinding,
    query_encoder_identity_hash: &'a str,
    query_corpus_hash: &'a str,
    graph_routed_report_hash: &'a str,
}

/// Publishes one complete artifact/member-index generation or proves that the
/// current generation already represents the exact same stable source.
///
/// # Cost contract (#1064)
///
/// Against measured production `N=192,873`, `E=328,899`, graph/anchor/FVS work
/// is owned by the caller's single snapshot pass. This function performs
/// `O(B + K*D + Q*D)` byte preparation/readback around the already-built eight
/// rows, plus the caller-owned graph-routed exact comparator `O(Q*N*D)`,
/// one `O(1)` current/previous pointer lookup, one group commit, one flush, and
/// one physical Ledger point read. It performs no Ledger scan and retains only
/// current+previous generation rows. The captured sequence, artifact source
/// identity, member roster, and Slot/Compression binding are invariant from
/// preparation through conditional admission (PC-03/04/07/14/15/28/35/37/38/
/// 41/43).
pub fn persist_complete_kernel_generation<C>(
    vault: &AsterVault<C>,
    request: KernelGenerationPublishRequest<'_>,
) -> Result<KernelGenerationPersistReport, SearchError>
where
    C: Clock,
{
    let KernelGenerationPublishRequest {
        project,
        scope_id,
        artifact,
        index,
        query_corpus,
        graph_routed_report,
        graph,
        complete_vectors,
        base_seq,
    } = request;
    if vault.latest_seq() != base_seq {
        return Err(incomplete(format!(
            "stage=publication_preflight expected_seq={base_seq} observed_seq={}; no rows were prepared or written",
            vault.latest_seq()
        )));
    }
    if artifact.scope_id != scope_id
        || index.members_hash != artifact.members_hash
        || index.member_count != artifact.member_count
    {
        return Err(incomplete(format!(
            "stage=artifact_index_join expected_scope={scope_id:?} observed_scope={:?} artifact_members_hash={} index_members_hash={} artifact_member_count={} index_member_count={}",
            artifact.scope_id,
            artifact.members_hash,
            index.members_hash,
            artifact.member_count,
            index.member_count,
        )));
    }
    let artifact_rows = prepare_kernel_artifact_rows(artifact)
        .map_err(|error| incomplete(format!("stage=artifact_prepare underlying={error}")))?;
    let index_rows = prepare_kernel_member_index_rows(vault, project, scope_id, index, base_seq)?;
    let query_corpus_bytes = query_corpus.canonical_json_bytes()?;
    let graph_routed_report_bytes = graph_routed_report
        .canonical_json_bytes()
        .map_err(|error| incomplete(format!("stage=graph_routed_report_prepare error={error}")))?;
    validate_recall_admission_join(RecallAdmissionJoin {
        project,
        scope_id,
        artifact,
        semantic_dim: index_rows
            .descriptor
            .semantic_dim
            .ok_or_else(|| incomplete("stage=admission_join semantic_dim=absent"))?,
        slot: index_rows.descriptor.slot,
        panel_version: index_rows.descriptor.panel_version,
        query_corpus,
        report: graph_routed_report,
    })?;
    let staged_graph_queries = query_corpus.graph_routed_queries();
    validate_graph_routed_recall_report(
        graph_routed_report,
        graph,
        artifact,
        complete_vectors,
        &staged_graph_queries,
        &query_corpus.params,
    )
    .map_err(|error| {
        admission_required(format!(
            "stage=graph_routed_preflight code={} message={:?} remediation={:?}",
            error.code(),
            error.message(),
            error.remediation()
        ))
    })?;
    let artifact_member_ids = artifact
        .members
        .iter()
        .map(|member| member.id)
        .collect::<Vec<_>>();
    let binding_member_ids = index
        .member_bindings
        .iter()
        .map(|binding| binding.cx_id)
        .collect::<Vec<_>>();
    if artifact_member_ids != binding_member_ids
        || index_rows.descriptor.binding_count != artifact.member_count
        || index_rows.descriptor.indexed_member_count != artifact.member_count
    {
        return Err(incomplete(format!(
            "stage=member_roster expected_count={} observed_binding_count={} observed_indexed_count={} exact_artifact_roster={artifact_member_ids:?} exact_index_roster={binding_member_ids:?}",
            artifact.member_count,
            index_rows.descriptor.binding_count,
            index_rows.descriptor.indexed_member_count,
        )));
    }

    let semantic_dim = index_rows
        .descriptor
        .semantic_dim
        .ok_or_else(|| incomplete("stage=member_roster semantic_dim=absent"))?;
    let generation_source_binding =
        capture_generation_source_binding(vault, base_seq, &artifact.source_identity)?;
    let provisional_rows = logical_rows(
        project,
        scope_id,
        "pending",
        &artifact_rows,
        &index_rows,
        &query_corpus_bytes,
        &graph_routed_report_bytes,
    );
    let source_generation_identity = stable_source_identity(StableSourceInputs {
        project,
        scope_id,
        artifact: &artifact_rows,
        index: &index_rows,
        semantic_dim,
        panel_version: index_rows.descriptor.panel_version,
        generation_source_binding: &generation_source_binding,
        query_encoder_identity_hash: &query_corpus.encoder.identity_hash,
        query_corpus_hash: &query_corpus.corpus_hash,
        graph_routed_report_hash: &graph_routed_report.report_hash,
    })?;
    let existing = read_generation_header_at(vault, base_seq, project, scope_id)?;

    if let Some(existing) = &existing
        && existing.manifest.source_generation_identity == source_generation_identity
    {
        let current = read_current_kernel_generation_at(vault, base_seq, project, scope_id)?
            .ok_or_else(|| corrupt("stage=noop_readback current pointer disappeared"))?;
        if current.artifact != *artifact
            || current.index.descriptor != index_rows.descriptor
            || current.index.bindings != index.member_bindings
            || current.query_corpus != *query_corpus
            || current.graph_routed_report != *graph_routed_report
        {
            return Err(corrupt(format!(
                "stage=noop_equivalence stable_source_identity={} matched but the immutable artifact/descriptor/binding/query/report bytes differ; current_generation={}",
                source_generation_identity, current.manifest.generation_id
            )));
        }
        let current_graph_queries = current.query_corpus.graph_routed_queries();
        validate_graph_routed_recall_report(
            &current.graph_routed_report,
            graph,
            &current.artifact,
            complete_vectors,
            &current_graph_queries,
            &current.query_corpus.params,
        )
        .map_err(|error| {
            corrupt(format!(
                "stage=noop_graph_routed_readback code={} message={:?} remediation={:?}",
                error.code(),
                error.message(),
                error.remediation()
            ))
        })?;
        let (ledger_physical_tiers, _) =
            verify_physical_ledger(vault, project, scope_id, &current.manifest)?;
        verify_retained_previous_at(vault, base_seq, project, scope_id, existing)?;
        return Ok(KernelGenerationPersistReport {
            published: false,
            commit_seq: current.pointer.current.commit_seq,
            generation_id: current.manifest.generation_id.clone(),
            source_generation_identity,
            artifact: current.artifact,
            descriptor: current.index.descriptor,
            manifest: current.manifest.clone(),
            pointer: current.pointer,
            ledger_ref: current.manifest.ledger_ref,
            ledger_physical_tiers,
            rows_readback_verified: current.rows_verified,
            readback_rows: Vec::new(),
            retired_generation_id: None,
            flush_sst_files: 0,
            flush_sst_entries: 0,
            flush_sst_bytes: 0,
        });
    }

    if let Some(existing) = &existing {
        verify_immutable_generation_rows_at(
            vault,
            base_seq,
            project,
            scope_id,
            &existing.manifest,
        )?;
        verify_retained_previous_at(vault, base_seq, project, scope_id, existing)?;
    }

    let previous_target = existing
        .as_ref()
        .map(|header| header.pointer.current.clone());
    let previous_generation_id = previous_target
        .as_ref()
        .map(|target| target.generation_id.clone())
        .unwrap_or_else(|| KERNEL_GENERATION_GENESIS_PREVIOUS_ID.to_string());
    let generation_id = content_generation_id(
        project,
        scope_id,
        &source_generation_identity,
        &previous_generation_id,
        &provisional_rows,
    );
    let logical_rows = logical_rows(
        project,
        scope_id,
        &generation_id,
        &artifact_rows,
        &index_rows,
        &query_corpus_bytes,
        &graph_routed_report_bytes,
    );

    let row_bindings = logical_rows
        .iter()
        .map(|row| {
            let bytes = u64::try_from(row.value.len()).map_err(|_| {
                persist_error(format!(
                    "stage=row_binding logical_name={:?} byte length {} is not representable as u64; no rows were written",
                    row.logical_name,
                    row.value.len(),
                ))
            })?;
            Ok(KernelGenerationRowBinding {
                logical_name: row.logical_name.to_string(),
                generation_key_hex: hex_lower(&row.generation_key),
                fixed_alias_key_hex: hex_lower(&row.fixed_alias_key),
                bytes,
                blake3: blake3_hex(&row.value),
            })
        })
        .collect::<Result<Vec<_>, SearchError>>()?;
    let retired_target = existing
        .as_ref()
        .and_then(|header| header.pointer.previous.clone());
    if let Some(target) = &retired_target {
        // Bind deletion authority to the exact retained manifest before the
        // callback emits any tombstone.
        let _ = read_and_validate_manifest_target(vault, base_seq, project, scope_id, target)?;
    }
    let retired_generation_id = retired_target
        .as_ref()
        .map(|target| target.generation_id.clone());
    let predicted_commit_seq = base_seq.checked_add(1).ok_or_else(|| {
        persist_error("stage=commit_plan expected_seq overflow; no rows were written")
    })?;
    let ledger_payload = serde_json::to_vec(&serde_json::json!({
        "schema": KERNEL_GENERATION_LEDGER_SCHEMA,
        "project": project,
        "scope_id": scope_id,
        "generation_id": generation_id,
        "source_generation_identity": source_generation_identity,
        "base_seq": base_seq,
        "artifact_source_identity": artifact.source_identity,
        "members_hash": artifact.members_hash,
        "member_count": artifact.member_count,
        "binding_count": index_rows.descriptor.binding_count,
        "indexed_member_count": index_rows.descriptor.indexed_member_count,
        "semantic_dim": semantic_dim,
        "panel_version": index_rows.descriptor.panel_version,
        "generation_source_binding": &generation_source_binding,
        "source_binding": index_rows.descriptor.source_binding,
        "query_encoder_identity_hash": query_corpus.encoder.identity_hash,
        "query_corpus_hash": query_corpus.corpus_hash,
        "graph_routed_report_hash": graph_routed_report.report_hash,
        "rows": row_bindings,
        "previous_generation_id": previous_generation_id,
        "retired_generation_id": retired_generation_id,
    }))
    .map_err(|error| persist_error(format!("stage=ledger_payload encode failed: {error}")))?;
    let ledger_payload_blake3 = blake3_hex(&ledger_payload);
    let ledger_subject = generation_subject(project, scope_id, &generation_id);
    let ledger_actor = ActorId::Service(KERNEL_GENERATION_ACTOR.to_string());
    let initial_rows = logical_rows
        .iter()
        .map(|row| {
            (
                ColumnFamily::Kernel,
                row.generation_key.clone(),
                row.value.clone(),
            )
        })
        .collect::<Vec<_>>();

    let callback_rows = logical_rows.clone();
    let callback_project = project.to_string();
    let callback_scope = scope_id.to_string();
    let callback_generation = generation_id.clone();
    let callback_source_generation = source_generation_identity.clone();
    let callback_source_identity = artifact.source_identity.clone();
    let callback_members_hash = artifact.members_hash.clone();
    let callback_generation_source_binding = generation_source_binding.clone();
    let callback_source_binding = index_rows.descriptor.source_binding.clone();
    let callback_panel_version = index_rows.descriptor.panel_version;
    let callback_query_encoder_identity_hash = query_corpus.encoder.identity_hash.clone();
    let callback_query_corpus_hash = query_corpus.corpus_hash.clone();
    let callback_graph_routed_report_hash = graph_routed_report.report_hash.clone();
    let expected_descriptor = index_rows.descriptor.clone();
    let callback_binding_count = index_rows.descriptor.binding_count;
    let callback_indexed_member_count = index_rows.descriptor.indexed_member_count;
    let callback_payload_blake3 = ledger_payload_blake3.clone();
    let callback_previous_generation_id = previous_generation_id.clone();
    let callback_previous = previous_target.clone();
    let callback_retired = retired_target.clone();
    let (commit, (manifest, pointer, retired_keys)) = vault
        .write_cf_batch_with_ledger_entry_with_row_digests_and_derived_if_seq(
            base_seq,
            initial_rows,
            EntryKind::Kernel,
            ledger_subject.clone(),
            ledger_payload.clone(),
            ledger_actor.clone(),
            move |ledger_ref, _source_rows| {
                let mut derived = callback_rows
                    .iter()
                    .map(|row| {
                        (
                            ColumnFamily::Kernel,
                            row.fixed_alias_key.clone(),
                            row.value.clone(),
                        )
                    })
                    .collect::<Vec<_>>();
                let manifest = KernelGenerationManifest {
                    schema: KERNEL_GENERATION_MANIFEST_SCHEMA.to_string(),
                    project: callback_project.clone(),
                    scope_id: callback_scope.clone(),
                    generation_id: callback_generation.clone(),
                    source_generation_identity: callback_source_generation.clone(),
                    base_seq,
                    artifact_source_identity: callback_source_identity.clone(),
                    members_hash: callback_members_hash.clone(),
                    member_count: artifact.member_count,
                    binding_count: callback_binding_count,
                    indexed_member_count: callback_indexed_member_count,
                    semantic_dim,
                    panel_version: callback_panel_version,
                    generation_source_binding: callback_generation_source_binding.clone(),
                    source_binding: callback_source_binding.clone(),
                    query_encoder_identity_hash: callback_query_encoder_identity_hash.clone(),
                    query_corpus_hash: callback_query_corpus_hash.clone(),
                    graph_routed_report_hash: callback_graph_routed_report_hash.clone(),
                    rows: row_bindings.clone(),
                    ledger_ref: ledger_ref.clone(),
                    ledger_payload_blake3: callback_payload_blake3.clone(),
                    previous_generation_id: callback_previous_generation_id.clone(),
                    retired_generation_id: callback_retired
                        .as_ref()
                        .map(|target| target.generation_id.clone()),
                    retention: "bounded_current_plus_previous; superseded rows tombstoned in the pointer commit".to_string(),
                };
                let manifest_bytes = serde_json::to_vec(&manifest).map_err(|error| {
                    calyx_core::CalyxError::ledger_group_commit_failed(format!(
                        "encode complete kernel manifest: {error}"
                    ))
                })?;
                let manifest_key = generation_manifest_key(
                    &callback_project,
                    &callback_scope,
                    &callback_generation,
                );
                let current = KernelGenerationPointerTarget {
                    generation_id: callback_generation.clone(),
                    manifest_key_hex: hex_lower(&manifest_key),
                    manifest_blake3: blake3_hex(&manifest_bytes),
                    commit_seq: predicted_commit_seq,
                    ledger_ref: ledger_ref.clone(),
                };
                let pointer = KernelGenerationPointer {
                    schema: KERNEL_GENERATION_POINTER_SCHEMA.to_string(),
                    project: callback_project.clone(),
                    scope_id: callback_scope.clone(),
                    current,
                    previous_generation_id: callback_previous_generation_id.clone(),
                    previous: callback_previous.clone(),
                    retained_generation_count: usize::from(callback_previous.is_some()) + 1,
                };
                let pointer_bytes = serde_json::to_vec(&pointer).map_err(|error| {
                    calyx_core::CalyxError::ledger_group_commit_failed(format!(
                        "encode complete kernel current pointer: {error}"
                    ))
                })?;
                derived.push((ColumnFamily::Kernel, manifest_key, manifest_bytes));
                derived.push((
                    ColumnFamily::Kernel,
                    generation_current_key(&callback_project, &callback_scope),
                    pointer_bytes,
                ));
                let mut retired_keys = Vec::new();
                if let Some(retired) = &callback_retired
                    && retired.generation_id != callback_generation
                    && callback_previous
                        .as_ref()
                        .is_none_or(|previous| previous.generation_id != retired.generation_id)
                {
                    retired_keys = complete_generation_keys(
                        &callback_project,
                        &callback_scope,
                        &retired.generation_id,
                    );
                    for key in &retired_keys {
                        derived.push((ColumnFamily::Kernel, key.clone(), tombstone_value()));
                    }
                }
                Ok((derived, (manifest, pointer, retired_keys)))
            },
        )
        .map_err(|error| {
            persist_error(format!(
                "stage=atomic_commit expected_seq={base_seq} observed_error_code={} observed_error={:?} remediation={:?}",
                error.code, error.message, error.remediation
            ))
        })?;
    if commit.seq != predicted_commit_seq
        || commit.ledger_ref != manifest.ledger_ref
        || commit.ledger_ref != pointer.current.ledger_ref
    {
        return Err(persist_error(format!(
            "stage=commit_receipt expected_commit_seq={predicted_commit_seq} observed_commit_seq={} expected_ledger_ref={:?} manifest_ledger_ref={:?} pointer_ledger_ref={:?}",
            commit.seq, commit.ledger_ref, manifest.ledger_ref, pointer.current.ledger_ref
        )));
    }

    // Exactly one explicit flush owns publication durability. All subsequent
    // reads are independent point reads; no caller may add a second flush.
    let flush = vault.flush_with_report().map_err(|error| {
        persist_error(format!(
            "stage=flush generation_id={generation_id} underlying_code={} underlying_message={:?} remediation={:?}",
            error.code, error.message, error.remediation
        ))
    })?;
    verify_source_binding_generations_at(
        vault,
        commit.seq,
        &manifest.source_binding,
        "after complete generation commit and flush",
    )?;
    verify_generation_source_binding_at(
        vault,
        commit.seq,
        &manifest.generation_source_binding,
        &manifest.artifact_source_identity,
        "after complete generation commit and flush",
    )?;

    let (readback_rows, rows_readback_verified) =
        verify_commit_row_digests(vault, commit.seq, &commit.data_row_digests)?;
    let current = read_current_kernel_generation_at(vault, commit.seq, project, scope_id)?
        .ok_or_else(|| persist_error("stage=current_readback pointer absent after commit"))?;
    if current.manifest != manifest
        || current.pointer != pointer
        || current.artifact != *artifact
        || current.index.descriptor != expected_descriptor
        || current.index.bindings != index.member_bindings
        || current.query_corpus != *query_corpus
        || current.graph_routed_report != *graph_routed_report
    {
        return Err(persist_error(format!(
            "stage=decoded_readback generation_id={generation_id} current_generation={} artifact_or_index_or_manifest_diff=true",
            current.manifest.generation_id
        )));
    }
    verify_retained_previous_at(
        vault,
        commit.seq,
        project,
        scope_id,
        &GenerationHeader {
            pointer: pointer.clone(),
            manifest: manifest.clone(),
        },
    )?;
    let current_graph_queries = current.query_corpus.graph_routed_queries();
    validate_graph_routed_recall_report(
        &current.graph_routed_report,
        graph,
        &current.artifact,
        complete_vectors,
        &current_graph_queries,
        &current.query_corpus.params,
    )
    .map_err(|error| {
        persist_error(format!(
            "stage=graph_routed_physical_readback code={} message={:?} remediation={:?}",
            error.code(),
            error.message(),
            error.remediation()
        ))
    })?;
    for key in &retired_keys {
        let value = vault
            .read_cf_at(commit.seq, ColumnFamily::Kernel, key)
            .map_err(|error| {
                persist_error(format!(
                    "stage=retention_readback key={} error={error}",
                    hex_lower(key)
                ))
            })?;
        if value.as_deref() != Some(tombstone_value().as_slice()) {
            return Err(persist_error(format!(
                "stage=retention_readback key={} expected=tombstone observed_bytes={}",
                hex_lower(key),
                value.as_ref().map_or(0, Vec::len)
            )));
        }
    }
    let (ledger_physical_tiers, physical_ledger_ref) =
        verify_physical_ledger(vault, project, scope_id, &manifest)?;
    if physical_ledger_ref != commit.ledger_ref {
        return Err(persist_error(
            "stage=physical_ledger_readback returned LedgerRef differs from commit receipt",
        ));
    }

    Ok(KernelGenerationPersistReport {
        published: true,
        commit_seq: commit.seq,
        generation_id,
        source_generation_identity,
        artifact: current.artifact,
        descriptor: current.index.descriptor,
        manifest,
        pointer,
        ledger_ref: commit.ledger_ref,
        ledger_physical_tiers,
        rows_readback_verified,
        readback_rows,
        retired_generation_id,
        flush_sst_files: flush.sst_files(),
        flush_sst_entries: flush.sst_entries(),
        flush_sst_bytes: flush.sst_bytes(),
    })
}

/// Resolves and verifies the current artifact through its composite pointer.
pub fn read_current_kernel_generation_artifact<C>(
    vault: &AsterVault<C>,
    project: &str,
    scope_id: &str,
) -> Result<Option<CurrentKernelGenerationArtifact>, SearchError>
where
    C: Clock,
{
    read_current_kernel_generation_artifact_at(vault, vault.latest_seq(), project, scope_id)
}

/// Resolves and verifies the current member descriptor through its composite
/// pointer. This is the warm-cache generation guard and reads no HNSW bytes.
pub fn read_current_kernel_generation_descriptor<C>(
    vault: &AsterVault<C>,
    project: &str,
    scope_id: &str,
    expected_members_hash: &str,
) -> Result<Option<CurrentKernelGenerationDescriptor>, SearchError>
where
    C: Clock,
{
    let snapshot = vault.latest_seq();
    let Some(header) = read_generation_header_at(vault, snapshot, project, scope_id)? else {
        return Ok(None);
    };
    if header.manifest.members_hash != expected_members_hash {
        return Err(corrupt(format!(
            "stage=descriptor_pointer expected_members_hash={expected_members_hash} observed_members_hash={}",
            header.manifest.members_hash
        )));
    }
    let binding = row_binding(&header.manifest, LOGICAL_MEMBER_DESCRIPTOR)?;
    let bytes = read_bound_row(
        vault,
        snapshot,
        project,
        scope_id,
        &header.manifest,
        binding,
    )?;
    let descriptor: KernelMemberIndexDescriptor = serde_json::from_slice(&bytes)
        .map_err(|error| corrupt(format!("stage=descriptor_decode error={error}")))?;
    validate_descriptor(
        &descriptor,
        snapshot,
        project,
        scope_id,
        expected_members_hash,
    )?;
    if descriptor.source_binding != header.manifest.source_binding
        || descriptor.member_count != header.manifest.member_count
        || descriptor.binding_count != header.manifest.binding_count
        || descriptor.indexed_member_count != header.manifest.indexed_member_count
        || descriptor.semantic_dim != Some(header.manifest.semantic_dim)
        || descriptor.panel_version != header.manifest.panel_version
    {
        return Err(corrupt(
            "stage=descriptor_manifest descriptor source/count/dimension differs from current manifest",
        ));
    }
    verify_generation_source_binding_at(
        vault,
        snapshot,
        &header.manifest.generation_source_binding,
        &header.manifest.artifact_source_identity,
        "current composite descriptor source read",
    )?;
    verify_source_binding_generations_at(
        vault,
        snapshot,
        &descriptor.source_binding,
        "current composite descriptor read",
    )?;
    Ok(Some(CurrentKernelGenerationDescriptor {
        descriptor,
        manifest: header.manifest,
        pointer: header.pointer,
        rows_verified: 4,
    }))
}

/// Resolves and checksum-validates the complete current generation.
pub fn read_current_kernel_generation<C>(
    vault: &AsterVault<C>,
    project: &str,
    scope_id: &str,
) -> Result<Option<CurrentKernelGeneration>, SearchError>
where
    C: Clock,
{
    read_current_kernel_generation_at(vault, vault.latest_seq(), project, scope_id)
}

/// Resolves the narrow current pointer/manifest/Ledger header at one stable
/// latest snapshot. This is the `O(1)` repository-generation guard for a
/// caller that already cold-verified the immutable generation.
pub fn read_current_kernel_generation_header<C>(
    vault: &AsterVault<C>,
    project: &str,
    scope_id: &str,
) -> Result<Option<CurrentKernelGenerationHeader>, SearchError>
where
    C: Clock,
{
    let lease = vault.retain_latest_snapshot();
    let snapshot = lease.seq();
    let header = read_generation_header_at(vault, snapshot, project, scope_id)?;
    lease.record_progress();
    if vault.latest_seq() != snapshot {
        return Err(corrupt(format!(
            "stage=narrow_header_snapshot expected_latest_seq={snapshot} observed_latest_seq={}",
            vault.latest_seq()
        )));
    }
    Ok(header.map(|header| CurrentKernelGenerationHeader {
        manifest: header.manifest,
        pointer: header.pointer,
    }))
}

/// Resolves the current artifact at an already-retained exact snapshot. This is
/// the bounded consumer path for callers that need artifact/query/report rows
/// but do not consume the member HNSW.
pub fn read_current_kernel_generation_artifact_at<C>(
    vault: &AsterVault<C>,
    snapshot: u64,
    project: &str,
    scope_id: &str,
) -> Result<Option<CurrentKernelGenerationArtifact>, SearchError>
where
    C: Clock,
{
    let Some(header) = read_generation_header_at(vault, snapshot, project, scope_id)? else {
        return Ok(None);
    };
    let kernel = read_bound_row(
        vault,
        snapshot,
        project,
        scope_id,
        &header.manifest,
        row_binding(&header.manifest, LOGICAL_KERNEL_JSON)?,
    )?;
    let index = read_bound_row(
        vault,
        snapshot,
        project,
        scope_id,
        &header.manifest,
        row_binding(&header.manifest, LOGICAL_INDEX_JSON)?,
    )?;
    let members = read_bound_row(
        vault,
        snapshot,
        project,
        scope_id,
        &header.manifest,
        row_binding(&header.manifest, LOGICAL_MEMBERS_HASH)?,
    )?;
    let query_corpus_bytes = read_bound_row(
        vault,
        snapshot,
        project,
        scope_id,
        &header.manifest,
        row_binding(&header.manifest, LOGICAL_QUERY_CORPUS)?,
    )?;
    let graph_routed_report_bytes = read_bound_row(
        vault,
        snapshot,
        project,
        scope_id,
        &header.manifest,
        row_binding(&header.manifest, LOGICAL_GRAPH_ROUTED_REPORT)?,
    )?;
    let artifact = decode_kernel_artifact_rows(scope_id, &kernel, &index, &members)
        .map_err(|error| corrupt(format!("stage=artifact_decode underlying={error}")))?;
    if artifact.source_identity != header.manifest.artifact_source_identity
        || artifact.members_hash != header.manifest.members_hash
        || artifact.member_count != header.manifest.member_count
    {
        return Err(corrupt(
            "stage=artifact_manifest artifact source/member identity differs from current manifest",
        ));
    }
    verify_generation_source_binding_at(
        vault,
        snapshot,
        &header.manifest.generation_source_binding,
        &header.manifest.artifact_source_identity,
        "current composite artifact source read",
    )?;
    verify_source_binding_generations_at(
        vault,
        snapshot,
        &header.manifest.source_binding,
        "current composite artifact S20 source read",
    )?;
    let query_corpus: KernelRecallQueryCorpus = serde_json::from_slice(&query_corpus_bytes)
        .map_err(|error| corrupt(format!("stage=query_corpus_decode error={error}")))?;
    let canonical_query_corpus = query_corpus.canonical_json_bytes().map_err(|error| {
        corrupt(format!(
            "stage=query_corpus_decode underlying_code={} underlying_message={:?} underlying_remediation={:?}",
            error.code(),
            error.message(),
            error.remediation()
        ))
    })?;
    if canonical_query_corpus != query_corpus_bytes {
        return Err(corrupt(
            "stage=query_corpus_decode persisted row is not canonical",
        ));
    }
    let graph_routed_report: GraphRoutedRecallReport =
        serde_json::from_slice(&graph_routed_report_bytes)
            .map_err(|error| corrupt(format!("stage=graph_routed_report_decode error={error}")))?;
    let canonical_report = graph_routed_report
        .canonical_json_bytes()
        .map_err(|error| corrupt(format!("stage=graph_routed_report_decode error={error}")))?;
    if canonical_report != graph_routed_report_bytes {
        return Err(corrupt(
            "stage=graph_routed_report_decode persisted row is not canonical",
        ));
    }
    validate_recall_artifact_join(
        project,
        scope_id,
        &artifact,
        &header.manifest,
        &query_corpus,
        &graph_routed_report,
    )
    .map_err(|error| {
        corrupt(format!(
            "stage=admission_composite_read underlying_code={} underlying_message={:?} underlying_remediation={:?}",
            error.code(),
            error.message(),
            error.remediation()
        ))
    })?;
    Ok(Some(CurrentKernelGenerationArtifact {
        artifact,
        query_corpus,
        graph_routed_report,
        manifest: header.manifest,
        pointer: header.pointer,
        rows_verified: 12,
    }))
}

fn read_current_kernel_generation_at<C>(
    vault: &AsterVault<C>,
    snapshot: u64,
    project: &str,
    scope_id: &str,
) -> Result<Option<CurrentKernelGeneration>, SearchError>
where
    C: Clock,
{
    let Some(artifact_read) =
        read_current_kernel_generation_artifact_at(vault, snapshot, project, scope_id)?
    else {
        return Ok(None);
    };
    let descriptor_binding = row_binding(&artifact_read.manifest, LOGICAL_MEMBER_DESCRIPTOR)?;
    let bindings_binding = row_binding(&artifact_read.manifest, LOGICAL_MEMBER_BINDINGS)?;
    let hnsw_binding = row_binding(&artifact_read.manifest, LOGICAL_MEMBER_HNSW)?;
    let descriptor_bytes = read_bound_row(
        vault,
        snapshot,
        project,
        scope_id,
        &artifact_read.manifest,
        descriptor_binding,
    )?;
    let bindings_bytes = read_bound_row(
        vault,
        snapshot,
        project,
        scope_id,
        &artifact_read.manifest,
        bindings_binding,
    )?;
    let hnsw_bytes = read_bound_row(
        vault,
        snapshot,
        project,
        scope_id,
        &artifact_read.manifest,
        hnsw_binding,
    )?;
    let descriptor: KernelMemberIndexDescriptor = serde_json::from_slice(&descriptor_bytes)
        .map_err(|error| corrupt(format!("stage=member_descriptor_decode error={error}")))?;
    validate_descriptor(
        &descriptor,
        snapshot,
        project,
        scope_id,
        &artifact_read.artifact.members_hash,
    )?;
    if descriptor.source_binding != artifact_read.manifest.source_binding
        || descriptor.member_count != artifact_read.manifest.member_count
        || descriptor.binding_count != artifact_read.manifest.binding_count
        || descriptor.indexed_member_count != artifact_read.manifest.indexed_member_count
        || descriptor.semantic_dim != Some(artifact_read.manifest.semantic_dim)
        || descriptor.panel_version != artifact_read.manifest.panel_version
    {
        return Err(corrupt(
            "stage=member_manifest descriptor source/count/dimension differs from current manifest",
        ));
    }
    let loaded = loaded_from_parts(descriptor, bindings_bytes, Some(hnsw_bytes))?;
    Ok(Some(CurrentKernelGeneration {
        artifact: artifact_read.artifact,
        index: loaded,
        query_corpus: artifact_read.query_corpus,
        graph_routed_report: artifact_read.graph_routed_report,
        manifest: artifact_read.manifest,
        pointer: artifact_read.pointer,
        rows_verified: 18,
    }))
}

fn read_generation_header_at<C>(
    vault: &AsterVault<C>,
    snapshot: u64,
    project: &str,
    scope_id: &str,
) -> Result<Option<GenerationHeader>, SearchError>
where
    C: Clock,
{
    let pointer_key = generation_current_key(project, scope_id);
    let Some(pointer_bytes) = vault
        .read_cf_at(snapshot, ColumnFamily::Kernel, &pointer_key)
        .map_err(|error| corrupt(format!("stage=pointer_read error={error}")))?
    else {
        for prefix in [
            LEGACY_KERNEL_GENERATION_CURRENT_PREFIX_V1,
            LEGACY_KERNEL_GENERATION_CURRENT_PREFIX_V2,
        ] {
            let legacy_key = generation_current_key_with_prefix(prefix, project, scope_id);
            if vault
                .read_cf_at(snapshot, ColumnFamily::Kernel, &legacy_key)
                .map_err(|error| corrupt(format!("stage=legacy_pointer_probe error={error}")))?
                .is_some()
            {
                return Err(corrupt(format!(
                    "stage=legacy_pointer_schema project={project:?} scope={scope_id:?} observed_namespace={:?} expected_schema={KERNEL_GENERATION_POINTER_SCHEMA:?}; v1/v2 content addresses omit the predecessor lineage and are never reused or served as v3",
                    String::from_utf8_lossy(prefix),
                )));
            }
        }
        return Ok(None);
    };
    let pointer: KernelGenerationPointer = serde_json::from_slice(&pointer_bytes)
        .map_err(|error| corrupt(format!("stage=pointer_decode error={error}")))?;
    validate_pointer(&pointer, project, scope_id, snapshot)?;
    let manifest =
        read_and_validate_manifest_target(vault, snapshot, project, scope_id, &pointer.current)?;
    verify_physical_ledger(vault, project, scope_id, &manifest).map_err(|error| {
        corrupt(format!(
            "stage=current_ledger_readback generation={} underlying_code={} underlying_message={:?} underlying_remediation={:?}",
            manifest.generation_id,
            error.code(),
            error.message(),
            error.remediation()
        ))
    })?;
    if manifest.previous_generation_id != pointer.previous_generation_id {
        return Err(corrupt(format!(
            "stage=retention_header manifest_previous={:?} pointer_previous={:?}",
            manifest.previous_generation_id, pointer.previous_generation_id,
        )));
    }
    if let Some(previous) = &pointer.previous {
        require_hash("pointer.previous.generation_id", &previous.generation_id)?;
        require_hash(
            "pointer.previous.manifest_blake3",
            &previous.manifest_blake3,
        )?;
        if manifest.previous_generation_id != previous.generation_id
            || previous.generation_id == manifest.generation_id
        {
            return Err(corrupt(format!(
                "stage=retention_header current={} manifest_previous={:?} pointer_previous={} ",
                manifest.generation_id, manifest.previous_generation_id, previous.generation_id
            )));
        }
    } else if manifest.previous_generation_id != KERNEL_GENERATION_GENESIS_PREVIOUS_ID {
        return Err(corrupt(
            "stage=retention_header current pointer has no previous target but does not carry explicit genesis",
        ));
    }
    Ok(Some(GenerationHeader { pointer, manifest }))
}

fn verify_retained_previous_at<C>(
    vault: &AsterVault<C>,
    snapshot: u64,
    project: &str,
    scope_id: &str,
    header: &GenerationHeader,
) -> Result<(), SearchError>
where
    C: Clock,
{
    let Some(previous) = &header.pointer.previous else {
        return Ok(());
    };
    let previous_manifest =
        read_and_validate_manifest_target(vault, snapshot, project, scope_id, previous)?;
    verify_physical_ledger(vault, project, scope_id, &previous_manifest).map_err(|error| {
        corrupt(format!(
            "stage=previous_ledger_readback generation={} underlying_code={} underlying_message={:?} underlying_remediation={:?}",
            previous_manifest.generation_id,
            error.code(),
            error.message(),
            error.remediation()
        ))
    })?;
    verify_immutable_generation_rows_at(vault, snapshot, project, scope_id, &previous_manifest)
}

fn read_and_validate_manifest_target<C>(
    vault: &AsterVault<C>,
    snapshot: u64,
    project: &str,
    scope_id: &str,
    target: &KernelGenerationPointerTarget,
) -> Result<KernelGenerationManifest, SearchError>
where
    C: Clock,
{
    require_hash("target.generation_id", &target.generation_id)?;
    require_hash("target.manifest_blake3", &target.manifest_blake3)?;
    if target.commit_seq == 0 || target.commit_seq > snapshot {
        return Err(corrupt(format!(
            "stage=manifest_target expected_commit_seq<=snapshot({snapshot}) observed_commit_seq={}",
            target.commit_seq
        )));
    }
    let expected_key = generation_manifest_key(project, scope_id, &target.generation_id);
    if target.manifest_key_hex != hex_lower(&expected_key) {
        return Err(corrupt(
            "stage=manifest_target manifest key does not match project/scope/generation",
        ));
    }
    let bytes = vault
        .read_cf_at(snapshot, ColumnFamily::Kernel, &expected_key)
        .map_err(|error| corrupt(format!("stage=manifest_read error={error}")))?
        .ok_or_else(|| corrupt("stage=manifest_read current manifest row is absent"))?;
    if blake3_hex(&bytes) != target.manifest_blake3 {
        return Err(corrupt(
            "stage=manifest_read manifest bytes differ from current pointer hash",
        ));
    }
    let manifest: KernelGenerationManifest = serde_json::from_slice(&bytes)
        .map_err(|error| corrupt(format!("stage=manifest_decode error={error}")))?;
    validate_manifest(&manifest, project, scope_id, target, snapshot)?;
    Ok(manifest)
}

fn validate_pointer(
    pointer: &KernelGenerationPointer,
    project: &str,
    scope_id: &str,
    snapshot: u64,
) -> Result<(), SearchError> {
    if pointer.schema != KERNEL_GENERATION_POINTER_SCHEMA
        || pointer.project != project
        || pointer.scope_id != scope_id
        || !valid_previous_generation_id(&pointer.previous_generation_id)
        || pointer.retained_generation_count != usize::from(pointer.previous.is_some()) + 1
        || pointer.retained_generation_count == 0
        || pointer.retained_generation_count > 2
        || pointer.current.commit_seq > snapshot
        || pointer.current.commit_seq == 0
        || pointer.previous.as_ref().is_some_and(|previous| {
            previous.generation_id == pointer.current.generation_id
                || pointer.previous_generation_id != previous.generation_id
                || previous.commit_seq >= pointer.current.commit_seq
        })
        || (pointer.previous.is_none()
            && pointer.previous_generation_id != KERNEL_GENERATION_GENESIS_PREVIOUS_ID)
    {
        return Err(corrupt(format!(
            "stage=pointer_validate expected_schema={KERNEL_GENERATION_POINTER_SCHEMA:?} observed_schema={:?} expected_project={project:?} observed_project={:?} expected_scope={scope_id:?} observed_scope={:?} retained_count={} snapshot={snapshot} current_commit_seq={}",
            pointer.schema,
            pointer.project,
            pointer.scope_id,
            pointer.retained_generation_count,
            pointer.current.commit_seq,
        )));
    }
    Ok(())
}

fn validate_manifest(
    manifest: &KernelGenerationManifest,
    project: &str,
    scope_id: &str,
    target: &KernelGenerationPointerTarget,
    snapshot: u64,
) -> Result<(), SearchError> {
    let expected_commit_seq = manifest.base_seq.checked_add(1).ok_or_else(|| {
        corrupt(format!(
            "stage=manifest_validate base_seq={} cannot advance",
            manifest.base_seq
        ))
    })?;
    require_hash("manifest.generation_id", &manifest.generation_id)?;
    require_hash(
        "manifest.source_generation_identity",
        &manifest.source_generation_identity,
    )?;
    require_hash(
        "manifest.ledger_payload_blake3",
        &manifest.ledger_payload_blake3,
    )?;
    require_hash(
        "manifest.query_encoder_identity_hash",
        &manifest.query_encoder_identity_hash,
    )?;
    require_hash("manifest.query_corpus_hash", &manifest.query_corpus_hash)?;
    require_hash(
        "manifest.graph_routed_report_hash",
        &manifest.graph_routed_report_hash,
    )?;
    if !valid_previous_generation_id(&manifest.previous_generation_id)
        || manifest.previous_generation_id == manifest.generation_id
    {
        return Err(corrupt(format!(
            "stage=manifest_validate previous_generation_id={:?} is neither a content address nor explicit genesis",
            manifest.previous_generation_id,
        )));
    }
    if let Some(retired) = manifest.retired_generation_id.as_deref() {
        require_hash("manifest.retired_generation_id", retired)?;
        if retired == manifest.generation_id || retired == manifest.previous_generation_id {
            return Err(corrupt(
                "stage=manifest_validate retired generation overlaps current/predecessor",
            ));
        }
    }
    if manifest.schema != KERNEL_GENERATION_MANIFEST_SCHEMA
        || manifest.project != project
        || manifest.scope_id != scope_id
        || manifest.generation_id != target.generation_id
        || manifest.ledger_ref != target.ledger_ref
        || expected_commit_seq != target.commit_seq
        || target.commit_seq > snapshot
        || manifest.member_count == 0
        || manifest.member_count != manifest.binding_count
        || manifest.member_count != manifest.indexed_member_count
        || manifest.semantic_dim == 0
        || manifest.panel_version == 0
        || manifest.rows.len() != 8
    {
        return Err(corrupt(format!(
            "stage=manifest_validate generation={} base_seq={} commit_seq={} snapshot={} member_count={} binding_count={} indexed_count={} semantic_dim={} row_count={}",
            manifest.generation_id,
            manifest.base_seq,
            target.commit_seq,
            snapshot,
            manifest.member_count,
            manifest.binding_count,
            manifest.indexed_member_count,
            manifest.semantic_dim,
            manifest.rows.len(),
        )));
    }
    let expected_names = [
        LOGICAL_KERNEL_JSON,
        LOGICAL_INDEX_JSON,
        LOGICAL_MEMBERS_HASH,
        LOGICAL_MEMBER_DESCRIPTOR,
        LOGICAL_MEMBER_BINDINGS,
        LOGICAL_MEMBER_HNSW,
        LOGICAL_QUERY_CORPUS,
        LOGICAL_GRAPH_ROUTED_REPORT,
    ];
    if manifest
        .rows
        .iter()
        .map(|row| row.logical_name.as_str())
        .ne(expected_names)
    {
        return Err(corrupt(
            "stage=manifest_validate eight-row logical roster/order is invalid",
        ));
    }
    validate_generation_source_binding_shape(
        &manifest.generation_source_binding,
        manifest.base_seq,
        &manifest.artifact_source_identity,
    )?;
    for row in &manifest.rows {
        require_hash("manifest.row.blake3", &row.blake3)?;
        if row.bytes == 0 {
            return Err(corrupt(format!(
                "stage=manifest_validate row {:?} has zero bytes",
                row.logical_name
            )));
        }
    }
    let expected_generation_id = content_generation_id_from_bindings(
        project,
        scope_id,
        &manifest.source_generation_identity,
        &manifest.previous_generation_id,
        &manifest.rows,
    );
    if manifest.generation_id != expected_generation_id {
        return Err(corrupt(format!(
            "stage=manifest_validate expected_content_generation_id={expected_generation_id} observed_generation_id={}",
            manifest.generation_id
        )));
    }
    Ok(())
}

fn row_binding<'a>(
    manifest: &'a KernelGenerationManifest,
    logical_name: &str,
) -> Result<&'a KernelGenerationRowBinding, SearchError> {
    manifest
        .rows
        .iter()
        .find(|row| row.logical_name == logical_name)
        .ok_or_else(|| {
            corrupt(format!(
                "stage=row_binding manifest lacks logical row {logical_name:?}"
            ))
        })
}

fn read_bound_row<C>(
    vault: &AsterVault<C>,
    snapshot: u64,
    project: &str,
    scope_id: &str,
    manifest: &KernelGenerationManifest,
    binding: &KernelGenerationRowBinding,
) -> Result<Vec<u8>, SearchError>
where
    C: Clock,
{
    let generation =
        read_immutable_generation_row_at(vault, snapshot, project, scope_id, manifest, binding)?;
    let expected_alias_key = fixed_alias_key(project, scope_id, &binding.logical_name)?;
    let alias = vault
        .read_cf_at(snapshot, ColumnFamily::Kernel, &expected_alias_key)
        .map_err(|error| corrupt(format!("stage=alias_row_read error={error}")))?
        .ok_or_else(|| {
            corrupt(format!(
                "stage=alias_row_read logical_name={:?} fixed alias absent",
                binding.logical_name
            ))
        })?;
    if generation != alias {
        return Err(corrupt(format!(
            "stage=row_readback logical_name={:?} generation_bytes={} alias_bytes={} expected_bytes={} observed_blake3={} expected_blake3={}",
            binding.logical_name,
            generation.len(),
            alias.len(),
            binding.bytes,
            blake3_hex(&generation),
            binding.blake3,
        )));
    }
    Ok(generation)
}

fn read_immutable_generation_row_at<C>(
    vault: &AsterVault<C>,
    snapshot: u64,
    project: &str,
    scope_id: &str,
    manifest: &KernelGenerationManifest,
    binding: &KernelGenerationRowBinding,
) -> Result<Vec<u8>, SearchError>
where
    C: Clock,
{
    let expected_generation_key = generation_row_key(
        project,
        scope_id,
        &manifest.generation_id,
        binding.logical_name.as_bytes(),
    );
    let expected_alias_key = fixed_alias_key(project, scope_id, &binding.logical_name)?;
    if binding.generation_key_hex != hex_lower(&expected_generation_key)
        || binding.fixed_alias_key_hex != hex_lower(&expected_alias_key)
    {
        return Err(corrupt(format!(
            "stage=row_key logical_name={:?} generation/alias key disagrees with schema",
            binding.logical_name
        )));
    }
    let generation = vault
        .read_cf_at(snapshot, ColumnFamily::Kernel, &expected_generation_key)
        .map_err(|error| corrupt(format!("stage=generation_row_read error={error}")))?
        .ok_or_else(|| {
            corrupt(format!(
                "stage=generation_row_read logical_name={:?} row absent",
                binding.logical_name
            ))
        })?;
    let generation_bytes = u64::try_from(generation.len()).map_err(|_| {
        corrupt(format!(
            "stage=row_readback logical_name={:?} observed byte length {} is not representable as u64",
            binding.logical_name,
            generation.len(),
        ))
    })?;
    let tombstoned = is_tombstone_value(&generation);
    if tombstoned || generation_bytes != binding.bytes || blake3_hex(&generation) != binding.blake3
    {
        return Err(corrupt(format!(
            "stage=immutable_generation_row_readback logical_name={:?} generation_bytes={} expected_bytes={} observed_blake3={} expected_blake3={} tombstoned={tombstoned}",
            binding.logical_name,
            generation.len(),
            binding.bytes,
            blake3_hex(&generation),
            binding.blake3,
        )));
    }
    Ok(generation)
}

fn verify_immutable_generation_rows_at<C>(
    vault: &AsterVault<C>,
    snapshot: u64,
    project: &str,
    scope_id: &str,
    manifest: &KernelGenerationManifest,
) -> Result<(), SearchError>
where
    C: Clock,
{
    for binding in &manifest.rows {
        read_immutable_generation_row_at(vault, snapshot, project, scope_id, manifest, binding)?;
    }
    Ok(())
}

fn verify_commit_row_digests<C>(
    vault: &AsterVault<C>,
    snapshot: u64,
    digests: &[calyx_aster::vault::LedgerBoundRowDigest],
) -> Result<(Vec<KernelGenerationReadbackRow>, usize), SearchError>
where
    C: Clock,
{
    let mut readback = Vec::with_capacity(digests.len());
    for digest in digests {
        if digest.cf != ColumnFamily::Kernel {
            return Err(persist_error(format!(
                "stage=row_digest_readback expected_cf=kernel observed_cf={}",
                digest.cf.name()
            )));
        }
        let value = vault
            .read_cf_at(snapshot, digest.cf, &digest.key)
            .map_err(|error| persist_error(format!("stage=row_digest_readback error={error}")))?
            .ok_or_else(|| {
                persist_error(format!(
                    "stage=row_digest_readback key={} absent",
                    hex_lower(&digest.key)
                ))
            })?;
        let observed_hash = *blake3::hash(&value).as_bytes();
        if observed_hash != digest.value_blake3 || is_tombstone_value(&value) != digest.tombstoned {
            return Err(persist_error(format!(
                "stage=row_digest_readback key={} expected_blake3={} observed_blake3={} expected_tombstoned={} observed_tombstoned={}",
                hex_lower(&digest.key),
                hex_lower(&digest.value_blake3),
                hex_lower(&observed_hash),
                digest.tombstoned,
                is_tombstone_value(&value),
            )));
        }
        readback.push(KernelGenerationReadbackRow {
            key_hex: hex_lower(&digest.key),
            bytes: value.len(),
            blake3: hex_lower(&observed_hash),
            tombstoned: digest.tombstoned,
        });
    }
    Ok((readback, digests.len()))
}

fn verify_physical_ledger<C>(
    vault: &AsterVault<C>,
    project: &str,
    scope_id: &str,
    manifest: &KernelGenerationManifest,
) -> Result<(Vec<String>, LedgerRef), SearchError>
where
    C: Clock,
{
    let wanted = BTreeSet::from([manifest.ledger_ref.seq]);
    let (rows, trace) = vault
        .read_physical_ledger_seqs(&wanted)
        .map_err(|error| persist_error(format!("stage=physical_ledger_read error={error}")))?;
    let row = rows.get(&manifest.ledger_ref.seq).ok_or_else(|| {
        persist_error(format!(
            "stage=physical_ledger_read ledger_seq={} absent",
            manifest.ledger_ref.seq
        ))
    })?;
    let entry = calyx_ledger::decode(&row.bytes)
        .map_err(|error| persist_error(format!("stage=physical_ledger_decode error={error}")))?;
    let expected_payload = serde_json::to_vec(&serde_json::json!({
        "schema": KERNEL_GENERATION_LEDGER_SCHEMA,
        "project": manifest.project,
        "scope_id": manifest.scope_id,
        "generation_id": manifest.generation_id,
        "source_generation_identity": manifest.source_generation_identity,
        "base_seq": manifest.base_seq,
        "artifact_source_identity": manifest.artifact_source_identity,
        "members_hash": manifest.members_hash,
        "member_count": manifest.member_count,
        "binding_count": manifest.binding_count,
        "indexed_member_count": manifest.indexed_member_count,
        "semantic_dim": manifest.semantic_dim,
        "panel_version": manifest.panel_version,
        "generation_source_binding": manifest.generation_source_binding,
        "source_binding": manifest.source_binding,
        "query_encoder_identity_hash": manifest.query_encoder_identity_hash,
        "query_corpus_hash": manifest.query_corpus_hash,
        "graph_routed_report_hash": manifest.graph_routed_report_hash,
        "rows": manifest.rows,
        "previous_generation_id": manifest.previous_generation_id,
        "retired_generation_id": manifest.retired_generation_id,
    }))
    .map_err(|error| {
        persist_error(format!(
            "stage=physical_ledger_expected_payload error={error}"
        ))
    })?;
    if row.seq != manifest.ledger_ref.seq
        || entry.seq != manifest.ledger_ref.seq
        || entry.entry_hash != manifest.ledger_ref.hash
        || !entry.verify()
        || entry.kind != EntryKind::Kernel
        || entry.actor != ActorId::Service(KERNEL_GENERATION_ACTOR.to_string())
        || entry.subject != generation_subject(project, scope_id, &manifest.generation_id)
        || entry.payload != expected_payload
        || blake3_hex(&entry.payload) != manifest.ledger_payload_blake3
    {
        return Err(persist_error(format!(
            "stage=physical_ledger_verify ledger_seq={} expected_hash={} observed_hash={} expected_payload_blake3={} observed_payload_blake3={}",
            manifest.ledger_ref.seq,
            hex_lower(&manifest.ledger_ref.hash),
            hex_lower(&entry.entry_hash),
            manifest.ledger_payload_blake3,
            blake3_hex(&entry.payload),
        )));
    }
    Ok((
        trace
            .tiers
            .into_iter()
            .map(|tier| tier.tier.to_string())
            .collect(),
        LedgerRef {
            seq: entry.seq,
            hash: entry.entry_hash,
        },
    ))
}

fn logical_rows(
    project: &str,
    scope_id: &str,
    generation_id: &str,
    artifact: &PreparedKernelArtifactRows,
    index: &PreparedKernelMemberIndexRows,
    query_corpus_bytes: &[u8],
    graph_routed_report_bytes: &[u8],
) -> Vec<LogicalPreparedRow> {
    vec![
        (
            LOGICAL_KERNEL_JSON,
            artifact.kernel_json.clone(),
            artifact.fixed_kernel_json_key.clone(),
        ),
        (
            LOGICAL_INDEX_JSON,
            artifact.index_json.clone(),
            artifact.fixed_index_json_key.clone(),
        ),
        (
            LOGICAL_MEMBERS_HASH,
            artifact.members_hash.clone(),
            artifact.fixed_members_hash_key.clone(),
        ),
        (
            LOGICAL_MEMBER_DESCRIPTOR,
            index.descriptor_bytes.clone(),
            index.fixed_descriptor_key.clone(),
        ),
        (
            LOGICAL_MEMBER_BINDINGS,
            index.bindings_bytes.clone(),
            index.fixed_bindings_key.clone(),
        ),
        (
            LOGICAL_MEMBER_HNSW,
            index.hnsw_bytes.clone(),
            index.fixed_hnsw_key.clone(),
        ),
        (
            LOGICAL_QUERY_CORPUS,
            query_corpus_bytes.to_vec(),
            recall_query_corpus_alias_key(project, scope_id),
        ),
        (
            LOGICAL_GRAPH_ROUTED_REPORT,
            graph_routed_report_bytes.to_vec(),
            graph_routed_report_alias_key(project, scope_id),
        ),
    ]
    .into_iter()
    .map(
        |(logical_name, value, fixed_alias_key)| LogicalPreparedRow {
            logical_name,
            generation_key: generation_row_key(
                project,
                scope_id,
                generation_id,
                logical_name.as_bytes(),
            ),
            fixed_alias_key,
            value,
        },
    )
    .collect()
}

fn content_generation_id(
    project: &str,
    scope_id: &str,
    source_generation_identity: &str,
    previous_generation_id: &str,
    rows: &[LogicalPreparedRow],
) -> String {
    let mut hasher = blake3::Hasher::new();
    hash_frame(&mut hasher, b"astrolabe.kernel_generation_content.v3");
    hash_frame(&mut hasher, project.as_bytes());
    hash_frame(&mut hasher, scope_id.as_bytes());
    hash_frame(&mut hasher, source_generation_identity.as_bytes());
    hash_frame(&mut hasher, previous_generation_id.as_bytes());
    for row in rows {
        hash_frame(&mut hasher, row.logical_name.as_bytes());
        hash_frame(&mut hasher, &(row.value.len() as u64).to_be_bytes());
        let value_hash = blake3_hex(&row.value);
        hash_frame(&mut hasher, value_hash.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

fn content_generation_id_from_bindings(
    project: &str,
    scope_id: &str,
    source_generation_identity: &str,
    previous_generation_id: &str,
    rows: &[KernelGenerationRowBinding],
) -> String {
    let mut hasher = blake3::Hasher::new();
    hash_frame(&mut hasher, b"astrolabe.kernel_generation_content.v3");
    hash_frame(&mut hasher, project.as_bytes());
    hash_frame(&mut hasher, scope_id.as_bytes());
    hash_frame(&mut hasher, source_generation_identity.as_bytes());
    hash_frame(&mut hasher, previous_generation_id.as_bytes());
    for row in rows {
        hash_frame(&mut hasher, row.logical_name.as_bytes());
        hash_frame(&mut hasher, &row.bytes.to_be_bytes());
        hash_frame(&mut hasher, row.blake3.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

fn stable_source_identity(inputs: StableSourceInputs<'_>) -> Result<String, SearchError> {
    let StableSourceInputs {
        project,
        scope_id,
        artifact,
        index,
        semantic_dim,
        panel_version,
        generation_source_binding,
        query_encoder_identity_hash,
        query_corpus_hash,
        graph_routed_report_hash,
    } = inputs;
    let identity = StableSourceIdentity {
        schema: "astrolabe.kernel_generation_source.v2",
        project,
        scope_id,
        artifact_source_identity: &artifact.artifact.source_identity,
        artifact_kernel_blake3: blake3_hex(&artifact.kernel_json),
        artifact_index_blake3: blake3_hex(&artifact.index_json),
        artifact_members_blake3: blake3_hex(&artifact.members_hash),
        members_hash: &artifact.artifact.members_hash,
        member_count: artifact.artifact.member_count,
        bindings_blake3: &index.descriptor.bindings_blake3,
        binding_count: index.descriptor.binding_count,
        indexed_member_count: index.descriptor.indexed_member_count,
        semantic_dim,
        panel_version,
        source_binding: &index.descriptor.source_binding,
        generation_source_binding,
        knobs: &index.descriptor.knobs,
        query_encoder_identity_hash,
        query_corpus_hash,
        graph_routed_report_hash,
    };
    let bytes = serde_json::to_vec(&identity)
        .map_err(|error| incomplete(format!("stage=source_identity_encode error={error}")))?;
    Ok(blake3_hex(&bytes))
}

fn capture_generation_source_binding<C>(
    vault: &AsterVault<C>,
    snapshot: u64,
    artifact_source_identity: &KernelSourceIdentity,
) -> Result<KernelGenerationSourceBinding, SearchError>
where
    C: Clock,
{
    if vault.latest_seq() != snapshot {
        return Err(incomplete(format!(
            "stage=source_binding_capture expected_latest_seq={snapshot} observed_latest_seq={}",
            vault.latest_seq()
        )));
    }
    let graph_content_generation = vault
        .cf_content_generation(ColumnFamily::Graph)
        .map_err(|error| incomplete(format!("stage=source_binding_graph error={error}")))?;
    let anchors_content_generation = vault
        .cf_content_generation(ColumnFamily::Anchors)
        .map_err(|error| incomplete(format!("stage=source_binding_anchors error={error}")))?;
    let anchor_metadata_content_generation = vault
        .cf_content_generation(ColumnFamily::Kv)
        .map_err(|error| {
            incomplete(format!(
                "stage=source_binding_anchor_metadata error={error}"
            ))
        })?;
    let projection_manifest = read_graph_projection_manifest_identity_at(
        vault,
        GraphProjectionKind::KernelGraph,
        snapshot,
    )
    .map_err(|error| {
        incomplete(format!(
            "stage=source_binding_projection_manifest error={error}"
        ))
    })?
    .ok_or_else(|| {
        incomplete(
            "stage=source_binding_projection_manifest current kernel-graph projection manifest is absent",
        )
    })?;
    let binding = KernelGenerationSourceBinding {
        schema: KERNEL_GENERATION_SOURCE_BINDING_SCHEMA.to_string(),
        graph_content_generation,
        anchors_content_generation,
        anchor_metadata_content_generation,
        projection_manifest,
    };
    validate_generation_source_binding_shape(&binding, snapshot, artifact_source_identity)?;
    if vault.latest_seq() != snapshot {
        return Err(incomplete(format!(
            "stage=source_binding_capture source moved during bounded point reads; expected_latest_seq={snapshot} observed_latest_seq={}",
            vault.latest_seq()
        )));
    }
    Ok(binding)
}

fn validate_generation_source_binding_shape(
    binding: &KernelGenerationSourceBinding,
    snapshot: u64,
    artifact_source_identity: &KernelSourceIdentity,
) -> Result<(), SearchError> {
    require_hash(
        "generation_source_binding.projection.source_fingerprint_blake3",
        &binding.projection_manifest.source_fingerprint_blake3,
    )?;
    require_hash(
        "generation_source_binding.projection.manifest_blake3",
        &binding.projection_manifest.manifest_blake3,
    )?;
    require_hash(
        "generation_source_binding.projection.manifest_sha256",
        &binding.projection_manifest.manifest_sha256,
    )?;
    if binding.schema != KERNEL_GENERATION_SOURCE_BINDING_SCHEMA
        || binding.graph_content_generation > snapshot
        || binding.anchors_content_generation > snapshot
        || binding.anchor_metadata_content_generation > snapshot
        || binding.projection_manifest.projection != GraphProjectionKind::KernelGraph.name()
        || binding.projection_manifest.node_count != artifact_source_identity.node_count
        || binding.projection_manifest.edge_count != artifact_source_identity.edge_count
    {
        return Err(corrupt(format!(
            "stage=source_binding_validate expected_schema={KERNEL_GENERATION_SOURCE_BINDING_SCHEMA:?} observed_schema={:?} snapshot={snapshot} graph_generation={} anchors_generation={} anchor_metadata_generation={} projection={:?} projection_nodes={} artifact_nodes={} projection_edges={} artifact_edges={}",
            binding.schema,
            binding.graph_content_generation,
            binding.anchors_content_generation,
            binding.anchor_metadata_content_generation,
            binding.projection_manifest.projection,
            binding.projection_manifest.node_count,
            artifact_source_identity.node_count,
            binding.projection_manifest.edge_count,
            artifact_source_identity.edge_count,
        )));
    }
    Ok(())
}

fn verify_generation_source_binding_at<C>(
    vault: &AsterVault<C>,
    snapshot: u64,
    binding: &KernelGenerationSourceBinding,
    artifact_source_identity: &KernelSourceIdentity,
    stage: &str,
) -> Result<(), SearchError>
where
    C: Clock,
{
    validate_generation_source_binding_shape(binding, snapshot, artifact_source_identity)?;
    if vault.latest_seq() != snapshot {
        return Err(corrupt(format!(
            "stage={stage} historical source-generation verification is unsupported; expected_latest_seq={snapshot} observed_latest_seq={}",
            vault.latest_seq()
        )));
    }
    let observed_graph = vault
        .cf_content_generation(ColumnFamily::Graph)
        .map_err(|error| corrupt(format!("stage={stage} graph_generation error={error}")))?;
    let observed_anchors = vault
        .cf_content_generation(ColumnFamily::Anchors)
        .map_err(|error| corrupt(format!("stage={stage} anchors_generation error={error}")))?;
    let observed_anchor_metadata =
        vault
            .cf_content_generation(ColumnFamily::Kv)
            .map_err(|error| {
                corrupt(format!(
                    "stage={stage} anchor_metadata_generation error={error}"
                ))
            })?;
    let observed_projection = read_graph_projection_manifest_identity_at(
        vault,
        GraphProjectionKind::KernelGraph,
        snapshot,
    )
    .map_err(|error| corrupt(format!("stage={stage} projection_manifest error={error}")))?
    .ok_or_else(|| corrupt(format!("stage={stage} projection_manifest absent")))?;
    let latest_after = vault.latest_seq();
    if observed_graph != binding.graph_content_generation
        || observed_anchors != binding.anchors_content_generation
        || observed_anchor_metadata != binding.anchor_metadata_content_generation
        || observed_projection != binding.projection_manifest
        || latest_after != snapshot
    {
        return Err(corrupt(format!(
            "stage={stage} source state changed or differs from the retained generation; snapshot={snapshot} latest_after={latest_after} expected_graph_generation={} observed_graph_generation={observed_graph} expected_anchors_generation={} observed_anchors_generation={observed_anchors} expected_anchor_metadata_generation={} observed_anchor_metadata_generation={observed_anchor_metadata} expected_projection={:?} observed_projection={observed_projection:?}",
            binding.graph_content_generation,
            binding.anchors_content_generation,
            binding.anchor_metadata_content_generation,
            binding.projection_manifest,
        )));
    }
    Ok(())
}

fn generation_subject(project: &str, scope_id: &str, generation_id: &str) -> SubjectId {
    SubjectId::Query(format!("kernel-generation:{project}:{scope_id}:{generation_id}").into_bytes())
}

fn generation_row_key(project: &str, scope_id: &str, generation_id: &str, leaf: &[u8]) -> Vec<u8> {
    let mut key = KERNEL_GENERATION_CF_PREFIX.to_vec();
    append_part(&mut key, project.as_bytes());
    append_part(&mut key, scope_id.as_bytes());
    append_part(&mut key, generation_id.as_bytes());
    append_part(&mut key, leaf);
    key
}

fn generation_manifest_key(project: &str, scope_id: &str, generation_id: &str) -> Vec<u8> {
    generation_row_key(project, scope_id, generation_id, MANIFEST_LEAF)
}

fn generation_current_key(project: &str, scope_id: &str) -> Vec<u8> {
    generation_current_key_with_prefix(KERNEL_GENERATION_CURRENT_PREFIX, project, scope_id)
}

fn generation_current_key_with_prefix(prefix: &[u8], project: &str, scope_id: &str) -> Vec<u8> {
    let mut key = prefix.to_vec();
    append_part(&mut key, project.as_bytes());
    append_part(&mut key, scope_id.as_bytes());
    append_part(&mut key, CURRENT_LEAF);
    key
}

fn complete_generation_keys(project: &str, scope_id: &str, generation_id: &str) -> Vec<Vec<u8>> {
    [
        LOGICAL_KERNEL_JSON,
        LOGICAL_INDEX_JSON,
        LOGICAL_MEMBERS_HASH,
        LOGICAL_MEMBER_DESCRIPTOR,
        LOGICAL_MEMBER_BINDINGS,
        LOGICAL_MEMBER_HNSW,
        LOGICAL_QUERY_CORPUS,
        LOGICAL_GRAPH_ROUTED_REPORT,
    ]
    .into_iter()
    .map(|leaf| generation_row_key(project, scope_id, generation_id, leaf.as_bytes()))
    .chain(std::iter::once(generation_manifest_key(
        project,
        scope_id,
        generation_id,
    )))
    .collect()
}

fn fixed_alias_key(
    project: &str,
    scope_id: &str,
    logical_name: &str,
) -> Result<Vec<u8>, SearchError> {
    match logical_name {
        LOGICAL_KERNEL_JSON | LOGICAL_INDEX_JSON | LOGICAL_MEMBERS_HASH => {
            let mut key = astrolabe_ingest::KERNEL_ARTIFACT_CF_PREFIX.to_vec();
            key.extend_from_slice(scope_id.as_bytes());
            key.push(b':');
            key.extend_from_slice(logical_name.as_bytes());
            Ok(key)
        }
        LOGICAL_MEMBER_DESCRIPTOR | LOGICAL_MEMBER_BINDINGS | LOGICAL_MEMBER_HNSW => {
            let suffix = match logical_name {
                LOGICAL_MEMBER_DESCRIPTOR => b"descriptor.json".as_slice(),
                LOGICAL_MEMBER_BINDINGS => b"bindings.json".as_slice(),
                LOGICAL_MEMBER_HNSW => b"s20.hnsw".as_slice(),
                _ => unreachable!(),
            };
            let mut key = crate::KERNEL_MEMBER_INDEX_CF_PREFIX.to_vec();
            append_part(&mut key, project.as_bytes());
            append_part(&mut key, scope_id.as_bytes());
            append_part(&mut key, suffix);
            Ok(key)
        }
        LOGICAL_QUERY_CORPUS => Ok(recall_query_corpus_alias_key(project, scope_id)),
        LOGICAL_GRAPH_ROUTED_REPORT => Ok(graph_routed_report_alias_key(project, scope_id)),
        other => Err(corrupt(format!(
            "stage=fixed_alias_key unknown logical row {other:?}"
        ))),
    }
}

fn recall_query_corpus_alias_key(project: &str, scope_id: &str) -> Vec<u8> {
    let mut key = KERNEL_RECALL_QUERY_CORPUS_PREFIX.to_vec();
    append_part(&mut key, project.as_bytes());
    append_part(&mut key, scope_id.as_bytes());
    key
}

fn graph_routed_report_alias_key(project: &str, scope_id: &str) -> Vec<u8> {
    let mut key = KERNEL_GRAPH_ROUTED_REPORT_PREFIX.to_vec();
    append_part(&mut key, project.as_bytes());
    append_part(&mut key, scope_id.as_bytes());
    key
}

fn append_part(out: &mut Vec<u8>, part: &[u8]) {
    out.extend_from_slice(&(part.len() as u64).to_be_bytes());
    out.extend_from_slice(part);
}

fn hash_frame(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn require_hash(label: &str, value: &str) -> Result<(), SearchError> {
    if value.len() != 64
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(corrupt(format!(
            "stage=hash_validate {label} is not 64 lowercase hexadecimal characters: {value:?}"
        )));
    }
    Ok(())
}

fn valid_previous_generation_id(value: &str) -> bool {
    value == KERNEL_GENERATION_GENESIS_PREVIOUS_ID
        || (value.len() == 64
            && value
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)))
}

fn require_admission_hash(label: &str, value: &str) -> Result<(), SearchError> {
    if value.len() != 64
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(admission_required(format!(
            "stage=query_hash_validate {label} expected=64_lowercase_sha256 observed={value:?}"
        )));
    }
    Ok(())
}

fn sha256_identity_hasher(domain: &[u8]) -> Sha256 {
    let mut hasher = Sha256::new();
    sha256_part(&mut hasher, domain);
    hasher
}

fn sha256_part(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u128).to_be_bytes());
    hasher.update(bytes);
}

fn sha256_finish(hasher: Sha256) -> String {
    hex_lower(&hasher.finalize())
}

fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn corrupt(message: impl Into<String>) -> SearchError {
    SearchError::new(
        ASTRO_KERNEL_GENERATION_CORRUPT,
        message.into(),
        "Preserve the vault, inspect the named current pointer/manifest/generation/alias row and exact hashes, then rebuild one complete generation from a fresh exact source snapshot.",
    )
}

fn persist_error(message: impl Into<String>) -> SearchError {
    SearchError::new(
        ASTRO_KERNEL_GENERATION_PERSIST,
        message.into(),
        "Preserve the prior current pointer and all generation bytes; repair the named commit, flush, Ledger, or readback failure before rebuilding from a new exact snapshot.",
    )
}

fn incomplete(message: impl Into<String>) -> SearchError {
    SearchError::new(
        ASTRO_KERNEL_GENERATION_INCOMPLETE,
        message.into(),
        "Re-read Graph, Anchors, S20 Slot, and Compression at one exact current sequence; rebuild the full artifact and one valid vector/HNSW row per member before any publication.",
    )
}

fn admission_required(message: impl Into<String>) -> SearchError {
    SearchError::new(
        ASTRO_KERNEL_ADMISSION_REQUIRED,
        message.into(),
        "Supply a nonempty persisted real external-query roster {stable_id,source,content} plus every graph-route parameter; let the production S20 encoder derive the vectors, evaluate exact full-corpus recall, and publish only the byte-verified admitted report in the same complete generation.",
    )
}
