//! Production causal-effect and expected-gain MCP surfaces (#1132).
//!
//! The mutating path publishes exactly one content-addressed generation across
//! Assay + Kernel + Ledger. The read paths reopen only those three column
//! families, point-read every manifested row plus the exact ledger sequence,
//! and rederive all hashes before serving.

use astrolabe_assay::{
    CausalAnalysisConfig, CausalAnalysisInput, CausalEffectArtifact, CausalObservation,
    CausalPairSpec, estimate_causal_effects,
};
use astrolabe_weave::{ExpectedGain, ExpectedGainInput, calculate_expected_gains};
use serde::{Deserialize, Serialize};

use super::*;

const CAUSAL_TOOL_SCHEMA: &str = "astrolabe.causal_analysis.v1";
const CAUSAL_GENERATION_SCHEMA: &str = "astrolabe.causal_generation.v1";
const CAUSAL_KERNEL_SCHEMA: &str = "astrolabe.causal_kernel.v1";
const CAUSAL_MANIFEST_SCHEMA: &str = "astrolabe.causal_manifest.v1";
const CAUSAL_PREFIX: &[u8] = b"astrolabe:causal:v1:";
const CAUSAL_ACTOR: &str = "astrolabe-causal-analysis";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionInput {
    treatment: String,
    outcome: String,
    outcome_value: f64,
    action_cost: f64,
    unit: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareRequest {
    project: String,
    mode: String,
    observations: Vec<CausalObservation>,
    treatments: Vec<String>,
    outcomes: Vec<String>,
    pairs: Vec<CausalPairSpec>,
    assumptions: Vec<astrolabe_assay::CausalAssumption>,
    minimum_propensity: f64,
    minimum_arm_count: usize,
    confidence_level: f64,
    decisions: Vec<DecisionInput>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct CausalGenerationArtifact {
    schema: String,
    project: String,
    request_sha256: String,
    causal: CausalEffectArtifact,
    expected_gains: Vec<ExpectedGain>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct CausalKernel {
    schema: String,
    project: String,
    artifact_sha256: String,
    observation_count: usize,
    pair_count: usize,
    expected_gains: Vec<ExpectedGain>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct PersistedRow {
    cf: String,
    key_hex: String,
    sha256: String,
    bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct CausalManifest {
    schema: String,
    project: String,
    artifact_sha256: String,
    request_sha256: String,
    ledger_seq: u64,
    assay_artifact: PersistedRow,
    kernel: PersistedRow,
}

struct ReadGeneration {
    artifact_sha256: String,
    artifact: CausalGenerationArtifact,
    kernel: CausalKernel,
    persistence: Value,
}

pub(crate) fn handle_causal_analysis(args_json: &str) -> Result<String, DynError> {
    let args: Value = serde_json::from_str(args_json)?;
    let Some(object) = args.as_object() else {
        return tool_fault_json(ToolFault::new(
            "ASTRO_CAUSAL_ARGUMENTS_INVALID",
            "causal_analysis arguments must be a JSON object",
            "pass the strict causal_analysis input schema",
        ));
    };
    let project = object
        .get("project")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            ToolFault::new(
                "ASTRO_CAUSAL_PROJECT_REQUIRED",
                "causal_analysis requires a non-empty project",
                "pass the exact calyx-shadow-indexed project name",
            )
        })?
        .to_string();
    let mode = object
        .get("mode")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ToolFault::new(
                "ASTRO_CAUSAL_MODE_REQUIRED",
                "causal_analysis requires mode",
                "pass mode as prepare or read",
            )
        })?
        .to_string();
    let requested_hash = object
        .get("artifact_sha256")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    let result = match mode.as_str() {
        "prepare" => {
            let request: PrepareRequest = serde_json::from_value(args).map_err(|error| {
                ToolFault::new(
                    "ASTRO_CAUSAL_ARGUMENTS_INVALID",
                    format!("causal_analysis prepare arguments are incomplete or malformed: {error}"),
                    "pass observations, complete treatment/outcome/pair rosters, all assumptions, strict overlap controls, and one decision record per pair",
                )
            })?;
            if request.mode != "prepare" {
                return tool_fault_json(ToolFault::new(
                    "ASTRO_CAUSAL_MODE_MISMATCH",
                    format!("prepare request decoded mode {:?}", request.mode),
                    "pass mode=\"prepare\" for publication",
                ));
            }
            prepare_generation(&cache_dir, request)
        }
        "read" => {
            let prepare_only = [
                "observations",
                "treatments",
                "outcomes",
                "pairs",
                "assumptions",
                "minimum_propensity",
                "minimum_arm_count",
                "confidence_level",
                "decisions",
            ];
            if let Some(name) = prepare_only.iter().find(|name| object.contains_key(**name)) {
                return tool_fault_json(ToolFault::new(
                    "ASTRO_CAUSAL_READ_ARGUMENT_INVALID",
                    format!("causal_analysis read received prepare-only field {name:?}"),
                    "remove prepare-only fields; read accepts project, mode, and optional artifact_sha256",
                ));
            }
            read_generation(&cache_dir, &project, requested_hash.as_deref())
        }
        other => Err(ToolFault::new(
            "ASTRO_CAUSAL_MODE_UNSUPPORTED",
            format!("causal_analysis mode {other:?} is unsupported"),
            "pass mode as prepare or read",
        )
        .into()),
    };
    match result {
        Ok(readback) => tool_json_result(causal_response(&mode, readback)),
        Err(error) => tool_fault_or_error(error),
    }
}

pub(crate) fn handle_expected_gain(args_json: &str) -> Result<String, DynError> {
    let args: Value = serde_json::from_str(args_json)?;
    let Some(object) = args.as_object() else {
        return tool_fault_json(ToolFault::new(
            "ASTRO_EXPECTED_GAIN_ARGUMENTS_INVALID",
            "expected_gain arguments must be a JSON object",
            "pass project and optionally artifact_sha256",
        ));
    };
    let project = object
        .get("project")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            ToolFault::new(
                "ASTRO_EXPECTED_GAIN_PROJECT_REQUIRED",
                "expected_gain requires a non-empty project",
                "pass the exact calyx-shadow-indexed project name",
            )
        })?;
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    match read_generation(
        &cache_dir,
        project,
        object.get("artifact_sha256").and_then(Value::as_str),
    ) {
        Ok(readback) => {
            let freshness = generation_freshness(&readback.persistence);
            tool_json_result(json!({
                "schema": astrolabe_weave::EXPECTED_GAIN_SCHEMA,
                "status": "success",
                "project": project,
                "artifact_sha256": readback.artifact_sha256,
                "observation_count": readback.kernel.observation_count,
                "pair_count": readback.kernel.pair_count,
                "expected_gains": readback.kernel.expected_gains,
                "trust": "verified",
                "freshness": freshness,
                "provenance": ["vault:ColumnFamily::Assay", "vault:ColumnFamily::Kernel", "vault:ColumnFamily::Ledger"],
                "persistence": readback.persistence,
            }))
        }
        Err(error) => tool_fault_or_error(error),
    }
}

fn prepare_generation(
    cache_dir: &Path,
    request: PrepareRequest,
) -> Result<ReadGeneration, DynError> {
    if read_dial_at(cache_dir, &request.project)? != MigrationDial::Shadow {
        return Err(ToolFault::new(
            "ASTRO_CAUSAL_SHADOW_REQUIRED",
            format!(
                "project {:?} is not using Calyx shadow indexing",
                request.project
            ),
            "run index_repository with calyx=\"shadow\" before causal publication",
        )
        .into());
    }
    let causal_input = CausalAnalysisInput {
        observations: request.observations,
        treatments: request.treatments,
        outcomes: request.outcomes,
        pairs: request.pairs,
        assumptions: request.assumptions,
        config: CausalAnalysisConfig {
            minimum_propensity: request.minimum_propensity,
            minimum_arm_count: request.minimum_arm_count,
            confidence_level: request.confidence_level,
        },
    };
    let causal = estimate_causal_effects(&causal_input).map_err(assay_fault)?;
    let expected_gains = decision_gains(&causal, request.decisions)?;
    let request_sha256 = canonical_sha256(&json!({
        "causal": causal,
        "expected_gains": expected_gains,
    }))?;
    let artifact = CausalGenerationArtifact {
        schema: CAUSAL_GENERATION_SCHEMA.to_string(),
        project: request.project.clone(),
        request_sha256: request_sha256.clone(),
        causal,
        expected_gains,
    };
    persist_generation(cache_dir, &request.project, artifact)
}

fn decision_gains(
    causal: &CausalEffectArtifact,
    mut decisions: Vec<DecisionInput>,
) -> Result<Vec<ExpectedGain>, DynError> {
    decisions.sort_by(|left, right| {
        (&left.treatment, &left.outcome).cmp(&(&right.treatment, &right.outcome))
    });
    let effects_by_id = causal
        .effects
        .iter()
        .map(|effect| (effect.effect_id.as_str(), effect))
        .collect::<std::collections::BTreeMap<_, _>>();
    if decisions.len() != causal.effects.len() {
        return Err(ToolFault::new(
            "ASTRO_EXPECTED_GAIN_DECISIONS_INCOMPLETE",
            format!(
                "expected one decision value/cost record per identified effect: expected {}, received {}",
                causal.effects.len(),
                decisions.len()
            ),
            "supply exactly one treatment/outcome decision record for every effect",
        )
        .into());
    }
    let mut inputs = Vec::with_capacity(decisions.len());
    for (ordinal, decision) in decisions.iter().enumerate() {
        let effect_id = format!("{}=>{}", decision.treatment, decision.outcome);
        if !effects_by_id.contains_key(effect_id.as_str())
            || ordinal > 0
                && decisions[ordinal - 1].treatment == decision.treatment
                && decisions[ordinal - 1].outcome == decision.outcome
        {
            return Err(ToolFault::new(
                "ASTRO_EXPECTED_GAIN_DECISIONS_INVALID",
                format!("decision {effect_id:?} is duplicate or outside the identified universe"),
                "supply exactly one decision record for every persisted causal effect",
            )
            .into());
        }
        let effect = effects_by_id
            .get(effect_id.as_str())
            .copied()
            .ok_or_else(|| {
                ToolFault::new(
                    "ASTRO_EXPECTED_GAIN_EFFECT_MISSING",
                    format!("identified effect {effect_id:?} is absent"),
                    "preserve the causal artifact and inspect its complete effect universe",
                )
            })?;
        inputs.push(ExpectedGainInput {
            effect_id,
            treatment: decision.treatment.clone(),
            outcome: decision.outcome.clone(),
            effect: effect.average_treatment_effect,
            effect_lower: effect.confidence_lower,
            effect_upper: effect.confidence_upper,
            outcome_value: decision.outcome_value,
            action_cost: decision.action_cost,
            unit: decision.unit.clone(),
        });
    }
    calculate_expected_gains(&inputs)
        .map_err(|error| ToolFault::new(error.code, error.message, error.remediation).into())
}

fn persist_generation(
    cache_dir: &Path,
    project: &str,
    artifact: CausalGenerationArtifact,
) -> Result<ReadGeneration, DynError> {
    let artifact_bytes = canonical_bytes(&artifact)?;
    let artifact_sha256 = sha256_bytes(&artifact_bytes);
    let kernel = CausalKernel {
        schema: CAUSAL_KERNEL_SCHEMA.to_string(),
        project: project.to_string(),
        artifact_sha256: artifact_sha256.clone(),
        observation_count: artifact.causal.observation_count,
        pair_count: artifact.causal.pair_count,
        expected_gains: artifact.expected_gains.clone(),
    };
    let kernel_bytes = canonical_bytes(&kernel)?;
    let assay_key = generation_key("assay", &artifact_sha256);
    let kernel_key = generation_key("kernel", &artifact_sha256);
    let manifest_key = generation_key("manifest", &artifact_sha256);
    let current_key = current_pointer_key(project);
    let (vault_dir, vault_id, vault_salt) = shadow_vault_config_at(cache_dir, project)?;
    let vault = open_shadow_vault_writable_latest_selected(
        &vault_dir,
        &vault_id,
        &vault_salt,
        vec![
            ColumnFamily::Assay,
            ColumnFamily::Kernel,
            ColumnFamily::Ledger,
            ColumnFamily::TimeIndex,
        ],
    )?;
    let snapshot = vault.latest_seq();
    let existing_assay = vault.read_cf_at(snapshot, ColumnFamily::Assay, &assay_key)?;
    let existing_kernel = vault.read_cf_at(snapshot, ColumnFamily::Kernel, &kernel_key)?;
    let existing_manifest = vault.read_cf_at(snapshot, ColumnFamily::Kernel, &manifest_key)?;
    let existing_current = vault.read_cf_at(snapshot, ColumnFamily::Kernel, &current_key)?;
    let immutable_presence = [
        existing_assay.is_some(),
        existing_kernel.is_some(),
        existing_manifest.is_some(),
    ];
    let any_present = immutable_presence.iter().any(|present| *present);
    let all_present = immutable_presence.iter().all(|present| *present);
    if any_present && !all_present {
        return Err(ToolFault::new(
            "ASTRO_CAUSAL_GENERATION_PARTIAL_OR_DRIFTED",
            format!("generation {artifact_sha256} has a partial physical row set"),
            "preserve the vault and inspect the exact Assay/Kernel generation rows",
        )
        .into());
    }
    if all_present {
        if existing_assay.as_deref() != Some(artifact_bytes.as_slice())
            || existing_kernel.as_deref() != Some(kernel_bytes.as_slice())
        {
            return Err(ToolFault::new(
                "ASTRO_CAUSAL_GENERATION_PARTIAL_OR_DRIFTED",
                format!("generation {artifact_sha256} has byte-different immutable data rows"),
                "preserve the vault and inspect the exact Assay/Kernel generation rows",
            )
            .into());
        }
        if existing_current.as_deref() != Some(artifact_sha256.as_bytes()) {
            return Err(ToolFault::new(
                "ASTRO_CAUSAL_CURRENT_POINTER_MISMATCH",
                "an immutable prior generation exists but is not the current generation",
                "read it by artifact_sha256 or publish a content-distinct causal request; do not silently repoint history",
            )
            .into());
        }
        drop(vault);
        return read_generation(cache_dir, project, Some(&artifact_sha256));
    }

    let ledger_seq =
        calyx_aster::ledger_head::read_head_anchor(&vault_dir)?.map_or(0, |head| head.height);
    let manifest = CausalManifest {
        schema: CAUSAL_MANIFEST_SCHEMA.to_string(),
        project: project.to_string(),
        artifact_sha256: artifact_sha256.clone(),
        request_sha256: artifact.request_sha256.clone(),
        ledger_seq,
        assay_artifact: persisted_row(ColumnFamily::Assay, &assay_key, &artifact_bytes),
        kernel: persisted_row(ColumnFamily::Kernel, &kernel_key, &kernel_bytes),
    };
    let manifest_bytes = canonical_bytes(&manifest)?;

    let actor = ActorId::Service(CAUSAL_ACTOR.to_string());
    let subject = SubjectId::Kernel(artifact_sha256.as_bytes().to_vec());
    let rows = vec![
        (
            ColumnFamily::Assay,
            assay_key.clone(),
            artifact_bytes.clone(),
        ),
        (
            ColumnFamily::Kernel,
            kernel_key.clone(),
            kernel_bytes.clone(),
        ),
        (
            ColumnFamily::Kernel,
            manifest_key.clone(),
            manifest_bytes.clone(),
        ),
        (
            ColumnFamily::Kernel,
            current_key.clone(),
            artifact_sha256.as_bytes().to_vec(),
        ),
    ];
    let mut plan = astrolabe_ingest::VaultMutationPlan::new(
        format!("causal-analysis:{artifact_sha256}"),
        calyx_ledger::EntryKind::Assay,
        &actor,
        &subject,
    );
    for (cf, key, bytes) in &rows {
        plan.push_content(*cf, key.clone(), bytes);
    }
    let (commit_seq, ledger_ref) = vault.write_cf_batch_with_ledger_entry_if_seq(
        snapshot,
        rows,
        calyx_ledger::EntryKind::Assay,
        subject,
        manifest_bytes,
        actor,
    )?;
    if ledger_ref.seq != ledger_seq {
        return Err(ToolFault::new(
            "ASTRO_CAUSAL_LEDGER_SEQUENCE_MISMATCH",
            format!(
                "precommitted ledger sequence {ledger_seq} became {}",
                ledger_ref.seq
            ),
            "preserve the vault and inspect the group-commit concurrency boundary",
        )
        .into());
    }
    vault.flush()?;
    let _fsv = plan.verify_committed_with_ledger_ref(&vault, commit_seq, &ledger_ref)?;
    drop(vault);
    read_generation(cache_dir, project, Some(&artifact_sha256))
}

fn read_generation(
    cache_dir: &Path,
    project: &str,
    requested_hash: Option<&str>,
) -> Result<ReadGeneration, DynError> {
    if read_dial_at(cache_dir, project)? != MigrationDial::Shadow {
        return Err(ToolFault::new(
            "ASTRO_CAUSAL_SHADOW_REQUIRED",
            format!("project {project:?} is not using Calyx shadow indexing"),
            "run index_repository with calyx=\"shadow\" before causal reads",
        )
        .into());
    }
    let (vault_dir, vault_id, vault_salt) = shadow_vault_config_at(cache_dir, project)?;
    let vault = open_shadow_vault_read_only(
        &vault_dir,
        &vault_id,
        &vault_salt,
        vec![
            ColumnFamily::Assay,
            ColumnFamily::Kernel,
            ColumnFamily::Ledger,
        ],
    )?;
    let snapshot = vault.latest_seq();
    let current_key = current_pointer_key(project);
    let current_bytes = vault
        .read_cf_at(snapshot, ColumnFamily::Kernel, &current_key)?
        .ok_or_else(|| {
            ToolFault::new(
                "ASTRO_CAUSAL_CURRENT_MISSING",
                format!("project {project:?} has no current causal generation"),
                "run causal_analysis mode=\"prepare\" with identifiable data first",
            )
        })?;
    let current_hash = String::from_utf8(current_bytes).map_err(|error| {
        ToolFault::new(
            "ASTRO_CAUSAL_CURRENT_CORRUPT",
            format!("current causal pointer is not UTF-8: {error}"),
            "preserve the vault and inspect the Kernel current-pointer row",
        )
    })?;
    let artifact_sha256 = requested_hash.unwrap_or(&current_hash).to_string();
    validate_sha256(&artifact_sha256)?;
    let assay_key = generation_key("assay", &artifact_sha256);
    let kernel_key = generation_key("kernel", &artifact_sha256);
    let manifest_key = generation_key("manifest", &artifact_sha256);
    let artifact_bytes = required_row(
        &vault,
        snapshot,
        ColumnFamily::Assay,
        &assay_key,
        "artifact",
    )?;
    let kernel_bytes = required_row(
        &vault,
        snapshot,
        ColumnFamily::Kernel,
        &kernel_key,
        "kernel",
    )?;
    let manifest_bytes = required_row(
        &vault,
        snapshot,
        ColumnFamily::Kernel,
        &manifest_key,
        "manifest",
    )?;
    let artifact: CausalGenerationArtifact =
        serde_json::from_slice(&artifact_bytes).map_err(|error| {
            ToolFault::new(
                "ASTRO_CAUSAL_ARTIFACT_CORRUPT",
                format!("causal Assay artifact is not valid typed JSON: {error}"),
                "preserve the vault and inspect the exact Assay artifact row",
            )
        })?;
    let kernel: CausalKernel = serde_json::from_slice(&kernel_bytes).map_err(|error| {
        ToolFault::new(
            "ASTRO_CAUSAL_KERNEL_CORRUPT",
            format!("causal Kernel row is not valid typed JSON: {error}"),
            "preserve the vault and inspect the exact compact Kernel row",
        )
    })?;
    let manifest: CausalManifest = serde_json::from_slice(&manifest_bytes).map_err(|error| {
        ToolFault::new(
            "ASTRO_CAUSAL_MANIFEST_CORRUPT",
            format!("causal manifest is not valid typed JSON: {error}"),
            "preserve the vault and inspect the exact Kernel manifest row",
        )
    })?;
    if artifact.schema != CAUSAL_GENERATION_SCHEMA
        || artifact.project != project
        || artifact.causal.schema != astrolabe_assay::CAUSAL_EFFECT_SCHEMA
        || sha256_bytes(&artifact_bytes) != artifact_sha256
        || kernel.schema != CAUSAL_KERNEL_SCHEMA
        || kernel.project != project
        || kernel.artifact_sha256 != artifact_sha256
        || kernel.observation_count != artifact.causal.observation_count
        || kernel.pair_count != artifact.causal.pair_count
        || kernel.expected_gains != artifact.expected_gains
        || manifest.schema != CAUSAL_MANIFEST_SCHEMA
        || manifest.project != project
        || manifest.artifact_sha256 != artifact_sha256
        || manifest.request_sha256 != artifact.request_sha256
        || !row_matches(
            &manifest.assay_artifact,
            ColumnFamily::Assay,
            &assay_key,
            &artifact_bytes,
        )
        || !row_matches(
            &manifest.kernel,
            ColumnFamily::Kernel,
            &kernel_key,
            &kernel_bytes,
        )
    {
        return Err(ToolFault::new(
            "ASTRO_CAUSAL_READBACK_MISMATCH",
            format!("causal generation {artifact_sha256} failed schema, identity, hash, or compact-kernel parity"),
            "preserve the vault and inspect the manifested Assay/Kernel rows",
        )
        .into());
    }
    let ledger_bytes = vault
        .read_cf_at(
            snapshot,
            ColumnFamily::Ledger,
            &ledger_key(manifest.ledger_seq),
        )?
        .ok_or_else(|| {
            ToolFault::new(
                "ASTRO_CAUSAL_LEDGER_UNPAIRED",
                format!(
                    "causal manifest names absent Ledger sequence {}",
                    manifest.ledger_seq
                ),
                "preserve the vault and run verify_chain before serving the generation",
            )
        })?;
    let ledger = decode_ledger(&ledger_bytes)?;
    if !ledger.verify()
        || ledger.seq != manifest.ledger_seq
        || ledger.kind != calyx_ledger::EntryKind::Assay
        || !matches!(&ledger.actor, ActorId::Service(actor) if actor == CAUSAL_ACTOR)
        || !matches!(&ledger.subject, SubjectId::Kernel(subject) if subject == artifact_sha256.as_bytes())
        || ledger.payload != manifest_bytes
    {
        return Err(ToolFault::new(
            "ASTRO_CAUSAL_LEDGER_MISMATCH",
            format!(
                "Ledger sequence {} does not canonically bind causal generation {artifact_sha256}",
                manifest.ledger_seq
            ),
            "preserve the vault and run verify_chain before serving the generation",
        )
        .into());
    }
    let persistence = json!({
        "schema": CAUSAL_MANIFEST_SCHEMA,
        "snapshot_seq": snapshot,
        "current_artifact_sha256": current_hash,
        "requested_is_current": artifact_sha256 == current_hash,
        "rows_read_back_verified": 4,
        "assay_artifact": manifest.assay_artifact,
        "kernel": manifest.kernel,
        "manifest": persisted_row(ColumnFamily::Kernel, &manifest_key, &manifest_bytes),
        "current_pointer": persisted_row(ColumnFamily::Kernel, &current_key, current_hash.as_bytes()),
        "ledger_paired": true,
        "ledger_ref": {"seq": ledger.seq, "hash": hex_lower(&ledger.entry_hash)},
        "source_of_truth": "Calyx Assay + Kernel + Ledger column families",
    });
    Ok(ReadGeneration {
        artifact_sha256,
        artifact,
        kernel,
        persistence,
    })
}

fn causal_response(mode: &str, readback: ReadGeneration) -> Value {
    let freshness = generation_freshness(&readback.persistence);
    json!({
        "schema": CAUSAL_TOOL_SCHEMA,
        "status": "success",
        "mode": mode,
        "project": readback.artifact.project,
        "artifact_sha256": readback.artifact_sha256,
        "artifact": readback.artifact,
        "trust": "verified",
        "freshness": freshness,
        "provenance": ["vault:ColumnFamily::Assay", "vault:ColumnFamily::Kernel", "vault:ColumnFamily::Ledger", "assay:aipw_discrete_strata", "loom:expected_net_gain"],
        "persistence": readback.persistence,
    })
}

fn generation_freshness(persistence: &Value) -> &'static str {
    if persistence["requested_is_current"] == Value::Bool(true) {
        "current"
    } else {
        "retained"
    }
}

fn persisted_row(cf: ColumnFamily, key: &[u8], bytes: &[u8]) -> PersistedRow {
    PersistedRow {
        cf: format!("{cf:?}"),
        key_hex: hex_lower(key),
        sha256: sha256_bytes(bytes),
        bytes: bytes.len(),
    }
}

fn row_matches(row: &PersistedRow, cf: ColumnFamily, key: &[u8], bytes: &[u8]) -> bool {
    row.cf == format!("{cf:?}")
        && row.key_hex == hex_lower(key)
        && row.sha256 == sha256_bytes(bytes)
        && row.bytes == bytes.len()
}

fn generation_key(kind: &str, hash: &str) -> Vec<u8> {
    let mut key = CAUSAL_PREFIX.to_vec();
    key.extend_from_slice(kind.as_bytes());
    key.push(b':');
    key.extend_from_slice(hash.as_bytes());
    key
}

fn current_pointer_key(project: &str) -> Vec<u8> {
    let mut key = CAUSAL_PREFIX.to_vec();
    key.extend_from_slice(b"current:");
    key.extend_from_slice(sha256_bytes(project.as_bytes()).as_bytes());
    key
}

fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, DynError> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn canonical_sha256(value: &Value) -> Result<String, DynError> {
    Ok(sha256_bytes(&canonical_bytes(value)?))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}

fn validate_sha256(value: &str) -> Result<(), DynError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ToolFault::new(
            "ASTRO_CAUSAL_HASH_INVALID",
            "artifact_sha256 must be exactly 64 lowercase hexadecimal characters",
            "copy the exact physical artifact hash returned by causal_analysis",
        )
        .into());
    }
    Ok(())
}

fn required_row<C: Clock>(
    vault: &AsterVault<C>,
    snapshot: u64,
    cf: ColumnFamily,
    key: &[u8],
    name: &str,
) -> Result<Vec<u8>, DynError> {
    vault.read_cf_at(snapshot, cf, key)?.ok_or_else(|| {
        ToolFault::new(
            "ASTRO_CAUSAL_ROW_MISSING",
            format!("causal {name} row {} is absent from {cf:?}", hex_lower(key)),
            "preserve the vault and inspect the interrupted Assay/Kernel/Ledger transaction",
        )
        .into()
    })
}

fn assay_fault(error: astrolabe_assay::AssayError) -> ToolFault {
    ToolFault::new(error.code(), error.message(), error.remediation())
}

fn tool_fault_json(fault: ToolFault) -> Result<String, DynError> {
    tool_json_error_result(fault.envelope())
}

fn tool_fault_or_error(error: DynError) -> Result<String, DynError> {
    if let Some(result) = tool_fault_result_from_error(error.as_ref()) {
        result
    } else if let Some(calyx) = error.downcast_ref::<calyx_core::CalyxError>() {
        ToolFault::new(calyx.code, calyx.message.clone(), calyx.remediation).into_result()
    } else {
        Err(error)
    }
}
