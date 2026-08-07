//! `discover_latent_links` — the L5 latent-association MCP surface (#1009).
//!
//! Serves `astrolabe_kernel::latent` over the persisted composite kernel-graph
//! projection: the associations the graph *implies* through shared intermediaries
//! but never recorded as an edge. Three questions:
//!
//! - `mode="open"` — "what is this symbol implicitly related to?" (seeded)
//! - `mode="closed"` — "why are these two related?" (the linking intermediaries)
//! - `mode="sweep"` — "what implicit relationships does this repo carry?" (ranked)
//!
//! Every served pair is `provisional` by construction: a latent link is a
//! hypothesis about a missing association, never an observed one. The tool fails
//! closed on a missing projection rather than degrading to a partial graph — a
//! latent ranking computed over a subset of the associations would silently
//! misreport exactly the absences it exists to find.

use super::*;

use astrolabe_kernel::{
    LatentConfig, LatentDisclosure, LatentDiscoveryReport, LatentExplanation, LatentIntermediary,
    LatentRelation, latent_closed_discovery, latent_corpus_sweep, latent_discovery_artifact_bytes,
    latent_explanation_artifact_bytes, latent_open_discovery,
};
use calyx_core::{CxId, Seq};

/// Envelope schema for the `discover_latent_links` MCP tool.
pub(crate) const DISCOVER_LATENT_LINKS_SCHEMA: &str = "astrolabe.discover_latent_links.v1";

const ASTRO_LATENT_SHADOW_REQUIRED: &str = "ASTRO_LATENT_SHADOW_REQUIRED";
const ASTRO_LATENT_VAULT_MISSING: &str = "ASTRO_LATENT_VAULT_MISSING";
const ASTRO_LATENT_PROJECTION_MISSING: &str = "ASTRO_LATENT_PROJECTION_MISSING";
const ASTRO_LATENT_MODE_UNSUPPORTED: &str = "ASTRO_LATENT_MODE_UNSUPPORTED";
const ASTRO_LATENT_RELATION_UNSUPPORTED: &str = "ASTRO_LATENT_RELATION_UNSUPPORTED";
const ASTRO_LATENT_SEED_REQUIRED: &str = "ASTRO_LATENT_SEED_REQUIRED";
const ASTRO_LATENT_ENDPOINTS_REQUIRED: &str = "ASTRO_LATENT_ENDPOINTS_REQUIRED";
const ASTRO_LATENT_SYMBOL_UNRESOLVED: &str = "ASTRO_LATENT_SYMBOL_UNRESOLVED";
const ASTRO_LATENT_GATE_INVALID: &str = "ASTRO_LATENT_GATE_INVALID";
const ASTRO_LATENT_COMPOSITE_REQUIRED: &str = "ASTRO_LATENT_COMPOSITE_REQUIRED";
const ASTRO_LATENT_PERSIST_FAILED: &str = "ASTRO_LATENT_PERSIST_FAILED";

const LATENT_PERSISTED_SCHEMA: &str = "astrolabe.latent_persisted.v1";
const LATENT_ARTIFACT_PREFIX: &[u8] = b"astrolabe:latent:v1:";
const LATENT_ACTOR: &str = "astrolabe-latent-discovery";

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct LatentPersistedManifest {
    schema: String,
    project: String,
    request_sha256: String,
    mode: String,
    relation: String,
    max_intermediary_degree: u64,
    min_shared_intermediaries: u64,
    pair_budget: u64,
    top_k: u64,
    listed_intermediaries: u64,
    seed_id: Option<String>,
    endpoint_a_id: Option<String>,
    endpoint_c_id: Option<String>,
    source_projection_fingerprint_blake3: String,
    projection_node_count: u64,
    projection_edge_count: u64,
    projection_association_edge_count: u64,
    composite_similarity_edge_count: u64,
    artifact_schema: String,
    artifact_sha256: String,
    artifact_bytes: u64,
    trust: String,
    freshness: String,
}

struct LatentPersistInput<'a> {
    project: &'a str,
    mode: &'a str,
    relation: LatentRelation,
    config: &'a LatentConfig,
    seed: Option<CxId>,
    endpoint_a: Option<CxId>,
    endpoint_c: Option<CxId>,
    source_seq: Seq,
    csr: &'a astrolabe_ingest::GraphProjectionCsr,
    composite_similarity_edge_count: u64,
    artifact_schema: &'a str,
    artifact_bytes: &'a [u8],
    trust: &'a str,
    freshness: &'a str,
}

fn refused(project: &str, code: &str, message: impl Into<String>, remediation: &str) -> Value {
    json!({
        "schema": DISCOVER_LATENT_LINKS_SCHEMA,
        "project": project,
        "status": "refused",
        "code": code,
        "message": message.into(),
        "remediation": remediation,
        "trust": "provisional",
        "freshness": "fresh",
        "provenance": ["refusal:pre-result:no-latent-link-emitted"],
    })
}

/// Overrides for the registry-default gates. An override outside its declared
/// bounds refuses — it is never clamped, because a clamped gate would serve a
/// ranking the caller did not ask for under a config they think they set.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct LatentGateOverrides {
    pub(crate) max_intermediary_degree: Option<u64>,
    pub(crate) min_shared_intermediaries: Option<u64>,
    pub(crate) pair_budget: Option<u64>,
    pub(crate) top_k: Option<u64>,
    pub(crate) listed_intermediaries: Option<u64>,
}

impl LatentGateOverrides {
    fn apply(self, mut config: LatentConfig) -> LatentConfig {
        if let Some(value) = self.max_intermediary_degree {
            config.max_intermediary_degree = value;
        }
        if let Some(value) = self.min_shared_intermediaries {
            config.min_shared_intermediaries = value;
        }
        if let Some(value) = self.pair_budget {
            config.pair_budget = value;
        }
        if let Some(value) = self.top_k {
            config.top_k = value;
        }
        if let Some(value) = self.listed_intermediaries {
            config.listed_intermediaries = value;
        }
        config
    }
}

fn config_json(config: &LatentConfig) -> Value {
    json!({
        "max_intermediary_degree": config.max_intermediary_degree,
        "min_shared_intermediaries": config.min_shared_intermediaries,
        "pair_budget": config.pair_budget,
        "top_k": config.top_k,
        "listed_intermediaries": config.listed_intermediaries,
    })
}

fn disclosure_json(disclosure: &LatentDisclosure) -> Value {
    json!({
        "intermediaries_considered": disclosure.intermediaries_considered,
        "intermediaries_over_broad": disclosure.intermediaries_over_broad,
        "intermediaries_unshared": disclosure.intermediaries_unshared,
        "pairs_direct_edge": disclosure.pairs_direct_edge,
        "pairs_accumulated": disclosure.pairs_accumulated,
        "pairs_below_min_shared": disclosure.pairs_below_min_shared,
        "pairs_truncated": disclosure.pairs_truncated,
    })
}

fn symbol_json(id: CxId, cx_to_qn: &BTreeMap<CxId, String>) -> Value {
    json!({
        "symbol_id": hex_lower(id.as_bytes()),
        "qualified_name": cx_to_qn.get(&id).cloned(),
    })
}

fn intermediary_json(
    intermediary: &LatentIntermediary,
    cx_to_qn: &BTreeMap<CxId, String>,
) -> Value {
    json!({
        "symbol_id": hex_lower(intermediary.id.as_bytes()),
        "qualified_name": cx_to_qn.get(&intermediary.id).cloned(),
        "degree": intermediary.degree,
        "resource_allocation_micro": intermediary.resource_allocation_micro,
        "adamic_adar_micro": intermediary.adamic_adar_micro,
    })
}

fn discovery_json(
    project: &str,
    report: &LatentDiscoveryReport,
    cx_to_qn: &BTreeMap<CxId, String>,
) -> Value {
    let artifact_bytes = latent_discovery_artifact_bytes(report);
    let pairs: Vec<Value> = report
        .pairs
        .iter()
        .map(|pair| {
            json!({
                "a": symbol_json(pair.a, cx_to_qn),
                "c": symbol_json(pair.c, cx_to_qn),
                "shared_count": pair.shared_count,
                "resource_allocation_micro": pair.resource_allocation_micro,
                "adamic_adar_micro": pair.adamic_adar_micro,
                "intermediaries_listed": pair.intermediaries.len(),
                "intermediaries": pair
                    .intermediaries
                    .iter()
                    .map(|via| intermediary_json(via, cx_to_qn))
                    .collect::<Vec<_>>(),
            })
        })
        .collect();

    json!({
        "schema": report.schema,
        "envelope_schema": DISCOVER_LATENT_LINKS_SCHEMA,
        "project": project,
        "status": "served",
        "mode": report.mode.as_str(),
        "relation": report.relation.as_str(),
        "config": config_json(&report.config),
        "node_count": report.node_count,
        "seed": report.seed.map(|id| symbol_json(id, cx_to_qn)),
        "pair_count": pairs.len(),
        "pairs": pairs,
        "disclosure": disclosure_json(&report.disclosure),
        "artifact_sha256": hex_lower(&Sha256::digest(&artifact_bytes)),
        "artifact_bytes": artifact_bytes.len(),
        // A latent link is an association the graph implies and never recorded.
        // It is a hypothesis, so it is served provisional without exception
        // (HONEST invariants 1 and 2).
        "trust": report.trust,
        "freshness": report.freshness,
        "provenance": [
            "vault:ColumnFamily::Graph".to_string(),
            "projection:kernel_graph".to_string(),
            "astrolabe_kernel::latent".to_string(),
        ],
    })
}

fn explanation_json(
    project: &str,
    explanation: &LatentExplanation,
    cx_to_qn: &BTreeMap<CxId, String>,
) -> Value {
    let artifact_bytes = latent_explanation_artifact_bytes(explanation);
    json!({
        "schema": explanation.schema,
        "envelope_schema": DISCOVER_LATENT_LINKS_SCHEMA,
        "project": project,
        "status": "served",
        "mode": "closed_discovery",
        "relation": explanation.relation.as_str(),
        "config": config_json(&explanation.config),
        "a": symbol_json(explanation.a, cx_to_qn),
        "c": symbol_json(explanation.c, cx_to_qn),
        // When true this explains a *known* association, not a discovery. The
        // caller is told rather than refused: "why are these two related" is a
        // legitimate question about a recorded edge too.
        "direct_edge_present": explanation.direct_edge_present,
        "latent": !explanation.direct_edge_present && explanation.shared_count > 0,
        "shared_count": explanation.shared_count,
        "resource_allocation_micro": explanation.resource_allocation_micro,
        "adamic_adar_micro": explanation.adamic_adar_micro,
        "intermediaries": explanation
            .intermediaries
            .iter()
            .map(|via| intermediary_json(via, cx_to_qn))
            .collect::<Vec<_>>(),
        "disclosure": disclosure_json(&explanation.disclosure),
        "artifact_sha256": hex_lower(&Sha256::digest(&artifact_bytes)),
        "artifact_bytes": artifact_bytes.len(),
        "trust": explanation.trust,
        "freshness": explanation.freshness,
        "provenance": [
            "vault:ColumnFamily::Graph".to_string(),
            "projection:kernel_graph".to_string(),
            "astrolabe_kernel::latent".to_string(),
        ],
    })
}

fn push_hash_part(bytes: &mut Vec<u8>, part: &[u8]) {
    bytes.extend_from_slice(&(part.len() as u64).to_be_bytes());
    bytes.extend_from_slice(part);
}

fn push_optional_cx(bytes: &mut Vec<u8>, id: Option<CxId>) {
    match id {
        Some(id) => {
            bytes.push(1);
            push_hash_part(bytes, id.as_bytes());
        }
        None => bytes.push(0),
    }
}

fn latent_request_sha256(input: &LatentPersistInput<'_>) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(256);
    for part in [
        LATENT_PERSISTED_SCHEMA.as_bytes(),
        input.artifact_schema.as_bytes(),
        input.project.as_bytes(),
        input.mode.as_bytes(),
        input.relation.as_str().as_bytes(),
    ] {
        push_hash_part(&mut bytes, part);
    }
    for knob in [
        input.config.max_intermediary_degree,
        input.config.min_shared_intermediaries,
        input.config.pair_budget,
        input.config.top_k,
        input.config.listed_intermediaries,
    ] {
        bytes.extend_from_slice(&knob.to_be_bytes());
    }
    push_optional_cx(&mut bytes, input.seed);
    push_optional_cx(&mut bytes, input.endpoint_a);
    push_optional_cx(&mut bytes, input.endpoint_c);
    Sha256::digest(bytes).into()
}

fn latent_artifact_key(request_sha256: &[u8; 32], leaf: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(LATENT_ARTIFACT_PREFIX.len() + 64 + 1 + leaf.len());
    key.extend_from_slice(LATENT_ARTIFACT_PREFIX);
    key.extend_from_slice(hex_lower(request_sha256).as_bytes());
    key.push(b':');
    key.extend_from_slice(leaf);
    key
}

fn find_latent_ledger_ref<C: Clock>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    subject_bytes: &[u8],
    manifest_bytes: &[u8],
) -> Result<LedgerRef, DynError> {
    let rows = vault.scan_cf_at(snapshot, ColumnFamily::Ledger)?;
    for (key, bytes) in rows.into_iter().rev() {
        let entry = decode_ledger(&bytes)?;
        if entry.kind != calyx_ledger::EntryKind::Assay
            || !matches!(&entry.actor, ActorId::Service(actor) if actor == LATENT_ACTOR)
            || !matches!(&entry.subject, SubjectId::Kernel(subject) if subject == subject_bytes)
            || entry.payload != manifest_bytes
        {
            continue;
        }
        if !entry.verify() {
            return Err(format!(
                "ASTRO_LATENT_LEDGER_CORRUPT: matching latent-discovery ledger entry {} failed canonical hash verification; remediation: preserve the vault and run verify_chain before retrying",
                entry.seq
            )
            .into());
        }
        if key.as_slice() != entry.seq.to_be_bytes().as_slice() {
            return Err(format!(
                "ASTRO_LATENT_LEDGER_CORRUPT: matching latent-discovery ledger row key {} does not encode entry sequence {}; remediation: preserve the vault and run verify_chain before retrying",
                hex_lower(&key),
                entry.seq
            )
            .into());
        }
        return Ok(LedgerRef {
            seq: entry.seq,
            hash: entry.entry_hash,
        });
    }
    Err(format!(
        "ASTRO_LATENT_LEDGER_UNPAIRED: persisted latent-discovery rows have no matching verified Ledger entry at snapshot {snapshot}; remediation: preserve the vault and inspect the Kernel/Ledger transaction before retrying"
    )
    .into())
}

fn persisted_response(
    state: &str,
    request_sha256: &[u8; 32],
    artifact_key: &[u8],
    manifest_key: &[u8],
    artifact_bytes: &[u8],
    manifest_bytes: &[u8],
    source_fingerprint: &[u8; 32],
    snapshot_seq: Seq,
    ledger_ref: &LedgerRef,
    fsv: Option<&astrolabe_domain::fsv::FsvAck>,
) -> Value {
    json!({
        "schema": LATENT_PERSISTED_SCHEMA,
        "state": state,
        "request_sha256": hex_lower(request_sha256),
        "artifact_key_hex": hex_lower(artifact_key),
        "manifest_key_hex": hex_lower(manifest_key),
        "artifact_sha256": hex_lower(&Sha256::digest(artifact_bytes)),
        "artifact_bytes": artifact_bytes.len(),
        "manifest_sha256": hex_lower(&Sha256::digest(manifest_bytes)),
        "manifest_bytes": manifest_bytes.len(),
        "source_projection_fingerprint_blake3": hex_lower(source_fingerprint),
        "snapshot_seq": snapshot_seq,
        "rows_read_back_verified": 2,
        "ledger_paired": true,
        "ledger_ref": {
            "seq": ledger_ref.seq,
            "hash": hex_lower(&ledger_ref.hash),
        },
        "fsv": fsv,
    })
}

/// Persist one canonical discovery result as an atomic two-row Kernel artifact
/// paired to the append-only Ledger, then independently read it back. The
/// read-only discovery snapshot sequence is the optimistic concurrency token:
/// any mutation between graph read and publication refuses rather than storing
/// a hypothesis over stale associations.
fn persist_latent_result(
    vault_dir: &Path,
    vault_id: &str,
    vault_salt: &str,
    input: &LatentPersistInput<'_>,
) -> Result<Value, DynError> {
    let request_sha256 = latent_request_sha256(input);
    let request_hex = hex_lower(&request_sha256);
    let artifact_sha256 = Sha256::digest(input.artifact_bytes);
    let manifest = LatentPersistedManifest {
        schema: LATENT_PERSISTED_SCHEMA.to_string(),
        project: input.project.to_string(),
        request_sha256: request_hex.clone(),
        mode: input.mode.to_string(),
        relation: input.relation.as_str().to_string(),
        max_intermediary_degree: input.config.max_intermediary_degree,
        min_shared_intermediaries: input.config.min_shared_intermediaries,
        pair_budget: input.config.pair_budget,
        top_k: input.config.top_k,
        listed_intermediaries: input.config.listed_intermediaries,
        seed_id: input.seed.map(|id| hex_lower(id.as_bytes())),
        endpoint_a_id: input.endpoint_a.map(|id| hex_lower(id.as_bytes())),
        endpoint_c_id: input.endpoint_c.map(|id| hex_lower(id.as_bytes())),
        source_projection_fingerprint_blake3: hex_lower(&input.csr.source_fingerprint_blake3),
        projection_node_count: input.csr.nodes.len() as u64,
        projection_edge_count: input.csr.edges.len() as u64,
        projection_association_edge_count: input.csr.association_edge_count as u64,
        composite_similarity_edge_count: input.composite_similarity_edge_count,
        artifact_schema: input.artifact_schema.to_string(),
        artifact_sha256: hex_lower(&artifact_sha256),
        artifact_bytes: input.artifact_bytes.len() as u64,
        trust: input.trust.to_string(),
        freshness: input.freshness.to_string(),
    };
    let manifest_bytes = serde_json::to_vec(&manifest)?;
    let artifact_key = latent_artifact_key(&request_sha256, b"artifact");
    let manifest_key = latent_artifact_key(&request_sha256, b"manifest");
    let actor = ActorId::Service(LATENT_ACTOR.to_string());
    let subject = SubjectId::Kernel(request_sha256.to_vec());

    let vault = open_shadow_vault_writable(vault_dir, vault_id, vault_salt, Vec::new())?;
    let current_seq = vault.latest_seq();
    if current_seq != input.source_seq {
        return Err(format!(
            "ASTRO_LATENT_SOURCE_CHANGED: vault advanced from retained discovery snapshot {} to {} before publication; remediation: rerun discover_latent_links against the new complete projection",
            input.source_seq, current_seq
        )
        .into());
    }

    let existing_artifact = vault.read_cf_at(current_seq, ColumnFamily::Kernel, &artifact_key)?;
    let existing_manifest = vault.read_cf_at(current_seq, ColumnFamily::Kernel, &manifest_key)?;
    match (&existing_artifact, &existing_manifest) {
        (None, None) => {}
        (Some(_), None) | (None, Some(_)) => {
            return Err(format!(
                "ASTRO_LATENT_ARTIFACT_PARTIAL: exactly one persisted row exists for request {request_hex}; remediation: preserve the vault and inspect the interrupted Kernel/Ledger transaction"
            )
            .into());
        }
        (Some(persisted_artifact), Some(persisted_manifest))
            if persisted_artifact == input.artifact_bytes
                && persisted_manifest == &manifest_bytes =>
        {
            let ledger_ref =
                find_latent_ledger_ref(&vault, current_seq, &request_sha256, &manifest_bytes)?;
            return Ok(persisted_response(
                "unchanged",
                &request_sha256,
                &artifact_key,
                &manifest_key,
                persisted_artifact,
                persisted_manifest,
                &input.csr.source_fingerprint_blake3,
                current_seq,
                &ledger_ref,
                None,
            ));
        }
        (Some(_), Some(persisted_manifest)) => {
            let prior: LatentPersistedManifest = serde_json::from_slice(persisted_manifest)
                .map_err(|error| {
                    format!(
                        "ASTRO_LATENT_MANIFEST_CORRUPT: persisted manifest for request {request_hex} is not valid {} JSON ({error}); remediation: preserve the vault and inspect the Kernel row before retrying",
                        LATENT_PERSISTED_SCHEMA
                    )
                })?;
            if prior.request_sha256 != request_hex {
                return Err(format!(
                    "ASTRO_LATENT_REQUEST_COLLISION: persisted manifest request {} occupies key for {request_hex}; remediation: preserve the vault and inspect the content-addressed key collision",
                    prior.request_sha256
                )
                .into());
            }
            if prior.source_projection_fingerprint_blake3
                == manifest.source_projection_fingerprint_blake3
            {
                return Err(format!(
                    "ASTRO_LATENT_NONDETERMINISTIC: request {request_hex} over unchanged source {} produced bytes different from persisted state; remediation: preserve both observations and repair canonical discovery serialization before retrying",
                    manifest.source_projection_fingerprint_blake3
                )
                .into());
            }
        }
    }

    let rows = vec![
        (
            ColumnFamily::Kernel,
            artifact_key.clone(),
            input.artifact_bytes.to_vec(),
        ),
        (
            ColumnFamily::Kernel,
            manifest_key.clone(),
            manifest_bytes.clone(),
        ),
    ];
    let mut plan = astrolabe_ingest::VaultMutationPlan::new(
        format!("latent-discovery:{request_hex}"),
        calyx_ledger::EntryKind::Assay,
        &actor,
        &subject,
    );
    plan.push_content(
        ColumnFamily::Kernel,
        artifact_key.clone(),
        input.artifact_bytes,
    );
    plan.push_content(ColumnFamily::Kernel, manifest_key.clone(), &manifest_bytes);
    let (commit_seq, ledger_ref) = vault.write_cf_batch_with_ledger_entry_if_seq(
        current_seq,
        rows,
        calyx_ledger::EntryKind::Assay,
        subject,
        manifest_bytes.clone(),
        actor,
    )?;
    vault.flush()?;
    let fsv = plan.verify_committed_with_ledger_ref(&vault, commit_seq, &ledger_ref)?;
    Ok(persisted_response(
        "written",
        &request_sha256,
        &artifact_key,
        &manifest_key,
        input.artifact_bytes,
        &manifest_bytes,
        &input.csr.source_fingerprint_blake3,
        commit_seq,
        &ledger_ref,
        Some(&fsv),
    ))
}

fn attach_persistence(mut served: Value, persistence: Value) -> Value {
    let Some(object) = served.as_object_mut() else {
        return served;
    };
    object.insert("persistence".to_string(), persistence);
    if let Some(Value::Array(provenance)) = object.get_mut("provenance") {
        provenance.push(Value::String("vault:ColumnFamily::Kernel".to_string()));
        provenance.push(Value::String("vault:ColumnFamily::Ledger".to_string()));
    }
    served
}

fn persistence_refusal(project: &str, error: &DynError) -> Value {
    let message = error.to_string();
    let code = message
        .split_once(':')
        .map(|(prefix, _)| prefix)
        .filter(|prefix| prefix.starts_with("ASTRO_LATENT_"))
        .unwrap_or(ASTRO_LATENT_PERSIST_FAILED)
        .to_string();
    refused(
        project,
        &code,
        message,
        "preserve the vault and use the named source/readback failure to repair the exact graph or Kernel/Ledger state before retrying; no latent artifact was reported as published",
    )
}

/// Shared core for the `discover_latent_links` MCP tool.
#[allow(clippy::too_many_arguments)]
pub(crate) fn discover_latent_links_json_at(
    cache_dir: &Path,
    project: &str,
    mode: &str,
    relation_name: &str,
    seed: Option<&str>,
    endpoint_a: Option<&str>,
    endpoint_c: Option<&str>,
    overrides: LatentGateOverrides,
) -> Result<Value, DynError> {
    let Some(relation) = LatentRelation::from_wire_name(relation_name) else {
        return Ok(refused(
            project,
            ASTRO_LATENT_RELATION_UNSUPPORTED,
            format!("discover_latent_links relation {relation_name:?} is not supported"),
            "pass relation as \"coupling\" (shared successors), \"co_citation\" (shared predecessors), or \"undirected\"",
        ));
    };
    if !matches!(mode, "open" | "closed" | "sweep") {
        return Ok(refused(
            project,
            ASTRO_LATENT_MODE_UNSUPPORTED,
            format!("discover_latent_links mode {mode:?} is not supported"),
            "pass mode as \"open\" (seeded discovery), \"closed\" (explain a pair), or \"sweep\" (corpus ranking)",
        ));
    }

    let config = overrides.apply(LatentConfig::with_registry_defaults());
    if let Err(error) = config.validate() {
        return Ok(refused(
            project,
            ASTRO_LATENT_GATE_INVALID,
            error.message().to_string(),
            "set every latent gate override within its registered bounds (see get_readiness for the knob registry)",
        ));
    }

    if read_dial_at(cache_dir, project)? != MigrationDial::Shadow {
        return Ok(refused(
            project,
            ASTRO_LATENT_SHADOW_REQUIRED,
            format!("discover_latent_links requires calyx shadow indexing for project {project:?}"),
            "run index_repository with calyx=\"shadow\" for this project before discovering latent links",
        ));
    }

    let (vault_dir, vault_id, vault_salt) = shadow_vault_config_at(cache_dir, project)?;
    if !vault_dir.exists() {
        return Ok(refused(
            project,
            ASTRO_LATENT_VAULT_MISSING,
            format!("shadow vault dir missing: {}", vault_dir.display()),
            "rerun index_repository with calyx=\"shadow\" before discovering latent links",
        ));
    }

    let vault = open_shadow_vault_read_only(
        &vault_dir,
        &vault_id,
        &vault_salt,
        vec![
            ColumnFamily::Graph,
            ColumnFamily::Base,
            ColumnFamily::Kv,
            ColumnFamily::Kernel,
            ColumnFamily::Ledger,
        ],
    )?;
    let source_seq = vault.latest_seq();
    let node_map = astrolabe_ingest::read_node_map_cx_ids(&vault, project)?;
    // Fail closed on an absent projection. A latent ranking computed over a
    // partial association graph would report absences that are really just
    // missing input — the exact failure mode this layer exists to avoid.
    let csr = match astrolabe_ingest::read_graph_projection_csr(
        &vault,
        astrolabe_ingest::GraphProjectionKind::KernelGraph,
    )? {
        Some(csr) => csr,
        None => {
            drop(vault);
            return Ok(refused(
                project,
                ASTRO_LATENT_PROJECTION_MISSING,
                "no persisted kernel_graph projection for this project",
                "run get_kernel with mode=\"build\" (or re-index with calyx=\"shadow\") so the composite association projection is persisted, then retry",
            ));
        }
    };
    let composite_similarity_edge_count = csr
        .edges
        .iter()
        .filter(|edge| {
            edge.etype == astrolabe_domain::EdgeKind::SimilarTo.code()
                || edge.etype == astrolabe_domain::EdgeKind::SemanticallyRelated.code()
        })
        .count() as u64;
    if composite_similarity_edge_count == 0 {
        drop(vault);
        return Ok(refused(
            project,
            ASTRO_LATENT_COMPOSITE_REQUIRED,
            "kernel_graph projection contains no encoded/embedded similarity association edges",
            "complete association reconciliation so KernelGraph contains the typed graph plus learned SIMILAR_TO/SEMANTICALLY_RELATED edges, then retry; structural-only latent mining is refused",
        ));
    }
    drop(vault);

    let graph = astrolabe_ingest::kernel_graph_from_projection_csr(&csr, &BTreeMap::new())?;
    let indexed = graph.compile()?;

    let mut cx_to_qn: BTreeMap<CxId, String> = BTreeMap::new();
    for (qn, cx) in &node_map {
        cx_to_qn.insert(*cx, qn.clone());
    }

    let resolve = |name: &str| -> Option<CxId> { node_map.get(name).copied() };

    match mode {
        "open" => {
            let Some(seed_name) = seed.filter(|name| !name.is_empty()) else {
                return Ok(refused(
                    project,
                    ASTRO_LATENT_SEED_REQUIRED,
                    "discover_latent_links mode=\"open\" requires seed",
                    "pass seed: the qualified name of the symbol whose implicit relationships you want",
                ));
            };
            let Some(seed_cx) = resolve(seed_name) else {
                return Ok(refused(
                    project,
                    ASTRO_LATENT_SYMBOL_UNRESOLVED,
                    format!("seed {seed_name:?} did not resolve to an indexed constellation"),
                    "pass a qualified name present in this project's indexed graph (see search_graph); re-index if the symbol is new",
                ));
            };
            match latent_open_discovery(&indexed, seed_cx, relation, &config) {
                Ok(report) => {
                    let artifact_bytes = latent_discovery_artifact_bytes(&report);
                    let served = discovery_json(project, &report, &cx_to_qn);
                    let input = LatentPersistInput {
                        project,
                        mode,
                        relation,
                        config: &config,
                        seed: Some(seed_cx),
                        endpoint_a: None,
                        endpoint_c: None,
                        source_seq,
                        csr: &csr,
                        composite_similarity_edge_count,
                        artifact_schema: report.schema,
                        artifact_bytes: &artifact_bytes,
                        trust: report.trust,
                        freshness: report.freshness,
                    };
                    match persist_latent_result(&vault_dir, &vault_id, &vault_salt, &input) {
                        Ok(persistence) => Ok(attach_persistence(served, persistence)),
                        Err(error) => Ok(persistence_refusal(project, &error)),
                    }
                }
                Err(error) => Ok(refused(
                    project,
                    error.code(),
                    error.message().to_string(),
                    error.remediation(),
                )),
            }
        }
        "closed" => {
            let (Some(a_name), Some(c_name)) = (
                endpoint_a.filter(|name| !name.is_empty()),
                endpoint_c.filter(|name| !name.is_empty()),
            ) else {
                return Ok(refused(
                    project,
                    ASTRO_LATENT_ENDPOINTS_REQUIRED,
                    "discover_latent_links mode=\"closed\" requires both a and c",
                    "pass a and c: the qualified names of the two symbols whose connection you want explained",
                ));
            };
            let (Some(a_cx), Some(c_cx)) = (resolve(a_name), resolve(c_name)) else {
                let missing = if resolve(a_name).is_none() {
                    a_name
                } else {
                    c_name
                };
                return Ok(refused(
                    project,
                    ASTRO_LATENT_SYMBOL_UNRESOLVED,
                    format!("endpoint {missing:?} did not resolve to an indexed constellation"),
                    "pass qualified names present in this project's indexed graph (see search_graph); re-index if a symbol is new",
                ));
            };
            match latent_closed_discovery(&indexed, a_cx, c_cx, relation, &config) {
                Ok(explanation) => {
                    let artifact_bytes = latent_explanation_artifact_bytes(&explanation);
                    let served = explanation_json(project, &explanation, &cx_to_qn);
                    let input = LatentPersistInput {
                        project,
                        mode,
                        relation,
                        config: &config,
                        seed: None,
                        endpoint_a: Some(a_cx),
                        endpoint_c: Some(c_cx),
                        source_seq,
                        csr: &csr,
                        composite_similarity_edge_count,
                        artifact_schema: explanation.schema,
                        artifact_bytes: &artifact_bytes,
                        trust: explanation.trust,
                        freshness: explanation.freshness,
                    };
                    match persist_latent_result(&vault_dir, &vault_id, &vault_salt, &input) {
                        Ok(persistence) => Ok(attach_persistence(served, persistence)),
                        Err(error) => Ok(persistence_refusal(project, &error)),
                    }
                }
                Err(error) => Ok(refused(
                    project,
                    error.code(),
                    error.message().to_string(),
                    error.remediation(),
                )),
            }
        }
        _ => match latent_corpus_sweep(&indexed, relation, &config) {
            Ok(report) => {
                let artifact_bytes = latent_discovery_artifact_bytes(&report);
                let served = discovery_json(project, &report, &cx_to_qn);
                let input = LatentPersistInput {
                    project,
                    mode,
                    relation,
                    config: &config,
                    seed: None,
                    endpoint_a: None,
                    endpoint_c: None,
                    source_seq,
                    csr: &csr,
                    composite_similarity_edge_count,
                    artifact_schema: report.schema,
                    artifact_bytes: &artifact_bytes,
                    trust: report.trust,
                    freshness: report.freshness,
                };
                match persist_latent_result(&vault_dir, &vault_id, &vault_salt, &input) {
                    Ok(persistence) => Ok(attach_persistence(served, persistence)),
                    Err(error) => Ok(persistence_refusal(project, &error)),
                }
            }
            Err(error) => Ok(refused(
                project,
                error.code(),
                error.message().to_string(),
                error.remediation(),
            )),
        },
    }
}

fn gate_override(args: &Map<String, Value>, key: &str) -> Result<Option<u64>, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(number)) => match number.as_u64() {
            Some(value) => Ok(Some(value)),
            None => Err(format!(
                "discover_latent_links {key} must be a non-negative integer"
            )),
        },
        Some(_) => Err(format!(
            "discover_latent_links {key} must be a non-negative integer"
        )),
    }
}

pub(crate) fn handle_discover_latent_links(args_json: &str) -> Result<String, DynError> {
    let args = serde_json::from_str::<Value>(args_json)?;
    let Some(args_obj) = args.as_object() else {
        return tool_error_result("discover_latent_links arguments must be a JSON object");
    };
    let Some(project) = status_project_from_args(args_obj)? else {
        return tool_error_result("discover_latent_links requires project");
    };
    let mode = string_arg(args_obj, "mode").unwrap_or("open").to_string();
    let relation = string_arg(args_obj, "relation")
        .unwrap_or("coupling")
        .to_string();
    let seed = string_arg(args_obj, "seed")
        .or_else(|| string_arg(args_obj, "symbol"))
        .map(ToOwned::to_owned);
    let endpoint_a = string_arg(args_obj, "a").map(ToOwned::to_owned);
    let endpoint_c = string_arg(args_obj, "c").map(ToOwned::to_owned);

    let mut overrides = LatentGateOverrides::default();
    for (key, slot) in [
        ("max_intermediary_degree", 0_usize),
        ("min_shared_intermediaries", 1),
        ("pair_budget", 2),
        ("top_k", 3),
        ("listed_intermediaries", 4),
    ] {
        let parsed = match gate_override(args_obj, key) {
            Ok(parsed) => parsed,
            Err(message) => return tool_error_result(message),
        };
        match slot {
            0 => overrides.max_intermediary_degree = parsed,
            1 => overrides.min_shared_intermediaries = parsed,
            2 => overrides.pair_budget = parsed,
            3 => overrides.top_k = parsed,
            _ => overrides.listed_intermediaries = parsed,
        }
    }

    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    let value = discover_latent_links_json_at(
        &cache_dir,
        &project,
        &mode,
        &relation,
        seed.as_deref(),
        endpoint_a.as_deref(),
        endpoint_c.as_deref(),
        overrides,
    )?;
    match value.get("status").and_then(Value::as_str) {
        Some("refused") => tool_json_error_result(value),
        _ => tool_json_result(value),
    }
}
