use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use calyx_aster::dedup::{DedupPolicy, EpochSecs, IngestInput};
use calyx_aster::stream::{BackpressureGuard, StreamIngester};
use calyx_aster::vault::{AsterVault, VaultOptions};
use calyx_core::{
    Asymmetry, Input, Modality, QuantPolicy, Slot, SlotId, SlotResource, SlotShape, SlotState,
    SlotVector, SystemClock, VaultId,
};
use calyx_registry::{
    DEFAULT_ANSWERAI_COLBERT_MODEL, MultiVectorCompressionQuery, MultiVectorCompressionRow,
    OnnxColbertLens, OnnxProviderPolicy, Registry,
};

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
        OnnxProviderPolicy::CpuExplicit,
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
    let inputs = documents
        .iter()
        .map(|document| Input::new(Modality::Text, document.bytes.clone()))
        .collect::<Vec<_>>();
    let vectors = registered
        .registry
        .measure_batch(registered.slot.lens_id, &inputs)?;
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
    Ok(MeasuredCorpus {
        events,
        rows,
        queries,
        document_paths,
        token_counts,
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
        "calyx/crates/calyx-registry/src/compression/multivector/training.rs",
        "calyx/crates/calyx-registry/src/compression/multivector/index.rs",
        "cbm/internal/cbm/extract_calls.c",
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
