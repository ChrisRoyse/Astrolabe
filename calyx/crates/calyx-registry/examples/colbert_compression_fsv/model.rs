use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use calyx_aster::dedup::{DedupPolicy, EpochSecs, IngestInput};
use calyx_aster::stream::{BackpressureGuard, StreamIngester};
use calyx_aster::vault::{AsterVault, VaultOptions};
use calyx_core::{
    Asymmetry, Input, Modality, OnnxCudaExecutionEvidence, QuantPolicy, Slot, SlotId, SlotResource,
    SlotShape, SlotState, SlotVector, SystemClock, VaultId,
};
use calyx_registry::{
    DEFAULT_ANSWERAI_COLBERT_MODEL, MultiVectorCompressionQuery, MultiVectorCompressionRow,
    ONNX_COLBERT_RUNTIME_ID, OnnxColbertLens, OnnxProviderPolicy, Registry,
    validate_cuda_onnx_execution_attestation,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

pub const SLOT_NUMBER: u16 = 75;
pub const PANEL_VERSION: u32 = 575;
pub const VAULT_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FB1";
pub const VAULT_SALT: &[u8] = b"issue-575-real-colbert-vault-salt";

pub type AnyResult<T> = Result<T, Box<dyn Error>>;

pub struct Registered {
    pub registry: Registry,
    pub slot: Slot,
    pub token_dim: u32,
}

pub struct MeasuredCorpus {
    pub events: Vec<IngestInput>,
    pub rows: Vec<MultiVectorCompressionRow>,
    pub queries: Vec<MultiVectorCompressionQuery>,
    pub document_paths: Vec<String>,
    pub token_counts: Vec<usize>,
    pub finiteness_readbacks: Vec<MeasurementFinitenessReadback>,
    pub cuda_execution_readback: ValidatedCudaExecutionReadback,
}

#[derive(Clone, Debug, Serialize)]
pub struct MeasurementFinitenessReadback {
    pub shape_tier: String,
    pub source_path: String,
    pub token_count: usize,
    pub token_dim: u32,
    pub scalar_count: u64,
    pub finite_scalar_count: u64,
    pub non_finite_scalar_count: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ValidatedCudaExecutionReadback {
    pub validator: &'static str,
    pub verdict: &'static str,
    pub expected_runtime: &'static str,
    pub runtime: String,
    pub provider: String,
    pub device: String,
    pub loader_dtype: Option<String>,
    pub compute_dtype: Option<String>,
    pub total_compute_nodes: u64,
    pub cpu_compute_nodes: u64,
    pub serialized_evidence_bytes: u64,
    pub serialized_evidence_sha256: String,
    pub structured_evidence: OnnxCudaExecutionEvidence,
}

struct CorpusDocument {
    path: PathBuf,
    bytes: Vec<u8>,
}

pub fn register_real_colbert(fixture_root: &Path) -> AnyResult<Registered> {
    let cache = fixture_root.join("model-cache");
    fs::create_dir_all(&cache)?;
    let lens = OnnxColbertLens::from_model_id_with_policy(
        "issue575-answerai-colbert",
        DEFAULT_ANSWERAI_COLBERT_MODEL,
        cache,
        OnnxProviderPolicy::CudaFailLoud,
    )?;
    let contract = lens.contract().clone();
    let spec = lens.lens_spec();
    let SlotShape::Multi { token_dim } = spec.output else {
        return Err("real ONNX ColBERT lens did not declare a Multi shape".into());
    };
    let mut registry = Registry::new();
    let lens_id = registry.register_frozen_with_spec(lens, contract, spec)?;
    let slot_id = SlotId::new(SLOT_NUMBER);
    let slot = Slot {
        slot_id,
        slot_key: slot_id.with_key("issue575-real-colbert"),
        lens_id,
        shape: SlotShape::Multi { token_dim },
        modality: Modality::Text,
        asymmetry: Asymmetry::None,
        quant: QuantPolicy::ColbertResidual2Bit,
        resource: SlotResource::default(),
        axis: Some("code-semantics".to_string()),
        retrieval_only: false,
        excluded_from_dedup: false,
        bits_about: BTreeMap::new(),
        state: SlotState::Active,
        added_at_panel_version: PANEL_VERSION,
    };
    Ok(Registered {
        registry,
        slot,
        token_dim,
    })
}

pub fn measure_real_corpus(
    workspace: &Path,
    vault: &AsterVault<SystemClock>,
    registered: &Registered,
) -> AnyResult<MeasuredCorpus> {
    let documents = read_real_documents(workspace)?;
    // Execute the three real source-size tiers independently. A single batch
    // would pad every item to its longest member and therefore could not prove
    // the minimum/ordinary/maximum token-shape paths against reality.
    let mut vectors = Vec::with_capacity(documents.len());
    let mut finiteness_readbacks = Vec::with_capacity(documents.len());
    let shape_tiers = ["minimum", "ordinary", "maximum"];
    for (document_index, document) in documents.iter().enumerate() {
        let shape_tier = shape_tiers
            .get(document_index)
            .ok_or("real ONNX ColBERT corpus contains more than three shape tiers")?;
        let input = Input::new(Modality::Text, document.bytes.clone());
        let measured = registered
            .registry
            .measure_batch(registered.slot.lens_id, &[input])?;
        let [vector] = <[SlotVector; 1]>::try_from(measured).map_err(|measured| {
            format!(
                "real ONNX ColBERT single-document measurement returned {} vectors",
                measured.len()
            )
        })?;
        finiteness_readbacks.push(scan_finite_multivector(
            shape_tier,
            &document.path,
            &vector,
            registered.token_dim,
        )?);
        vectors.push(vector);
    }
    let mut events = Vec::with_capacity(documents.len());
    let mut rows = Vec::with_capacity(documents.len());
    let mut queries = Vec::with_capacity(documents.len());
    let mut document_paths = Vec::with_capacity(documents.len());
    let mut token_counts = Vec::with_capacity(documents.len());
    for (document, vector) in documents.into_iter().zip(vectors) {
        let SlotVector::Multi { token_dim, tokens } = vector else {
            return Err("real ONNX ColBERT measurement was not a Multi vector".into());
        };
        if token_dim != registered.token_dim || tokens.is_empty() {
            return Err(format!(
                "real ONNX ColBERT measurement geometry is invalid: dim={token_dim}, tokens={}",
                tokens.len()
            )
            .into());
        }
        let event = IngestInput::new(document.bytes, PANEL_VERSION, Modality::Text).with_slot(
            registered.slot.slot_id,
            SlotVector::Multi {
                token_dim,
                tokens: tokens.clone(),
            },
        );
        let cx_id = vault.cx_id_for_input(&event.raw_bytes, event.panel_version);
        let mut query_identity = b"issue575-held-out-query:".to_vec();
        query_identity.extend_from_slice(document.path.to_string_lossy().as_bytes());
        let query_id = vault.cx_id_for_input(&query_identity, PANEL_VERSION + 1);
        token_counts.push(tokens.len());
        document_paths.push(document.path.to_string_lossy().to_string());
        rows.push(MultiVectorCompressionRow {
            cx_id,
            tokens: tokens.clone(),
        });
        queries.push(MultiVectorCompressionQuery {
            cx_id: query_id,
            tokens,
        });
        events.push(event);
    }
    let [minimum_tokens, ordinary_tokens, maximum_tokens] =
        <[usize; 3]>::try_from(token_counts.as_slice()).map_err(|_| {
            format!(
                "real ONNX ColBERT shape audit expected three source tiers, observed {}",
                token_counts.len()
            )
        })?;
    if !(minimum_tokens < ordinary_tokens
        && ordinary_tokens < maximum_tokens
        && maximum_tokens == 512)
    {
        return Err(format!(
            "real ONNX ColBERT source tiers did not exercise minimum < ordinary < declared maximum token shapes: {token_counts:?}"
        )
        .into());
    }
    let cuda_execution_readback = read_validated_cuda_execution(registered)?;
    Ok(MeasuredCorpus {
        events,
        rows,
        queries,
        document_paths,
        token_counts,
        finiteness_readbacks,
        cuda_execution_readback,
    })
}

pub fn ingest_real_corpus(
    vault: Arc<AsterVault<SystemClock>>,
    events: Vec<IngestInput>,
) -> AnyResult<()> {
    let expected = events.len();
    let ingester = StreamIngester::new(Arc::clone(&vault), BackpressureGuard::new(expected + 1, 0));
    for (index, event) in events.into_iter().enumerate() {
        ingester.send(event, EpochSecs(5_750 + index as i64))?;
    }
    let stats = ingester.drain_and_close()?;
    if stats.ingested != expected {
        return Err(format!(
            "real stream ingest persisted {} of {expected} documents",
            stats.ingested
        )
        .into());
    }
    vault.flush()?;
    Ok(())
}

pub fn open_vault(fixture_root: &Path, create: bool) -> AnyResult<Arc<AsterVault<SystemClock>>> {
    let vault_dir = fixture_root.join("vault");
    if create {
        fs::create_dir_all(&vault_dir)?;
    } else if !vault_dir.is_dir() {
        return Err(format!("existing FSV vault is absent: {}", vault_dir.display()).into());
    }
    let options = VaultOptions {
        dedup_policy: Some(DedupPolicy::Off),
        ..VaultOptions::default()
    };
    Ok(Arc::new(AsterVault::open(
        &vault_dir,
        VAULT_ID.parse::<VaultId>()?,
        VAULT_SALT.to_vec(),
        options,
    )?))
}

fn read_real_documents(workspace: &Path) -> AnyResult<Vec<CorpusDocument>> {
    let relative = [
        "calyx/crates/calyx-hazard-soak/src/lib.rs",
        "cbm/internal/cbm/grammar_rust.c",
        "calyx/crates/calyx-registry/src/compression/multivector/training.rs",
    ];
    relative
        .into_iter()
        .map(|name| {
            let path = workspace.join(name);
            let bytes = fs::read(&path)?;
            if bytes.is_empty() {
                return Err(format!("real corpus document is empty: {}", path.display()).into());
            }
            Ok(CorpusDocument { path, bytes })
        })
        .collect()
}

fn scan_finite_multivector(
    shape_tier: &str,
    source_path: &Path,
    vector: &SlotVector,
    expected_token_dim: u32,
) -> AnyResult<MeasurementFinitenessReadback> {
    let SlotVector::Multi { token_dim, tokens } = vector else {
        return Err(format!(
            "real ONNX ColBERT measurement for {} was not a Multi vector",
            source_path.display()
        )
        .into());
    };
    if *token_dim != expected_token_dim || tokens.is_empty() {
        return Err(format!(
            "real ONNX ColBERT measurement for {} has invalid geometry: dim={token_dim}, expected_dim={expected_token_dim}, tokens={}",
            source_path.display(),
            tokens.len()
        )
        .into());
    }
    let expected_row_len = usize::try_from(*token_dim)?;
    let mut finite_scalar_count = 0_u64;
    for (token_index, token) in tokens.iter().enumerate() {
        if token.len() != expected_row_len {
            return Err(format!(
                "real ONNX ColBERT measurement for {} has token {token_index} width {}, expected {expected_row_len}",
                source_path.display(),
                token.len()
            )
            .into());
        }
        for (component_index, value) in token.iter().enumerate() {
            if !value.is_finite() {
                return Err(format!(
                    "real ONNX ColBERT measurement for {} contains non-finite component at token={token_index} component={component_index}: {value:?}",
                    source_path.display()
                )
                .into());
            }
            finite_scalar_count = finite_scalar_count
                .checked_add(1)
                .ok_or("real ONNX ColBERT finite-scalar count overflow")?;
        }
    }
    let scalar_count = u64::try_from(tokens.len())?
        .checked_mul(u64::from(*token_dim))
        .ok_or("real ONNX ColBERT scalar-count bound overflow")?;
    if finite_scalar_count != scalar_count {
        return Err(format!(
            "real ONNX ColBERT finiteness scan for {} visited {finite_scalar_count} of {scalar_count} components",
            source_path.display()
        )
        .into());
    }
    let source_path = source_path
        .to_str()
        .ok_or("real ONNX ColBERT source path is not valid UTF-8")?
        .to_string();
    Ok(MeasurementFinitenessReadback {
        shape_tier: shape_tier.to_string(),
        source_path,
        token_count: tokens.len(),
        token_dim: *token_dim,
        scalar_count,
        finite_scalar_count,
        non_finite_scalar_count: 0,
    })
}

fn read_validated_cuda_execution(
    registered: &Registered,
) -> AnyResult<ValidatedCudaExecutionReadback> {
    let attestation = registered
        .registry
        .execution_attestation(registered.slot.lens_id)?
        .ok_or("real ONNX ColBERT lens returned no runtime execution attestation")?;
    let structured_evidence =
        validate_cuda_onnx_execution_attestation(&attestation, ONNX_COLBERT_RUNTIME_ID)?;
    let reserialized_evidence = serde_json::to_string(&structured_evidence)?;
    if reserialized_evidence != attestation.evidence {
        return Err(
            "strictly validated ONNX evidence did not round-trip to the exact attestation bytes"
                .into(),
        );
    }
    let serialized_evidence_bytes = u64::try_from(reserialized_evidence.len())?;
    let serialized_evidence_sha256 =
        format!("{:x}", Sha256::digest(reserialized_evidence.as_bytes()));
    let total_compute_nodes = attestation
        .total_compute_nodes
        .ok_or("validated ONNX execution attestation omitted total compute nodes")?;
    let cpu_compute_nodes = attestation
        .cpu_compute_nodes
        .ok_or("validated ONNX execution attestation omitted CPU compute nodes")?;
    Ok(ValidatedCudaExecutionReadback {
        validator: "calyx_registry::validate_cuda_onnx_execution_attestation",
        verdict: "accepted_after_independent_artifact_reopen_hash_parse_and_reconciliation",
        expected_runtime: ONNX_COLBERT_RUNTIME_ID,
        runtime: attestation.runtime,
        provider: attestation.provider,
        device: attestation.device,
        loader_dtype: attestation.loader_dtype,
        compute_dtype: attestation.compute_dtype,
        total_compute_nodes,
        cpu_compute_nodes,
        serialized_evidence_bytes,
        serialized_evidence_sha256,
        structured_evidence,
    })
}
