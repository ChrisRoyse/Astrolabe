//! Agent-task Reward anchors and promote-on-resolution (blueprint 06 §2.4, 15 §4).
//!
//! This is the flywheel intake. Every symbol in a served context pack receives a
//! Provisional `Reward` anchor recording whether the agent session succeeded,
//! attributed to the catalog source `agent:<agent>:<session>` at
//! [`AGENT_TASK_REWARD_CONFIDENCE`]. When a *resolved* CI outcome (a `ci:*`
//! `TestPass`) later lands on the same symbols, matching pass evidence promotes
//! the agent Reward anchor to Trusted; an agent-success / CI-failure
//! disagreement is a CONTRADICTION that refuses promotion and is recorded
//! queryably ([`ASTRO_ANCHOR_CONTRADICTION`]), leaving both anchors at their
//! original trust.
//!
//! Persistence mirrors the outcome-anchor contract in [`crate`]: pack manifests,
//! promotions, and contradictions are append-only KV records, each written in
//! one atomic group commit paired with a hash-only `Grounding` ledger entry and
//! independently read-back-verified ([`FsvAck`]). Nothing here is synthetic:
//! promotion is derived from anchors already grounded in real outcomes.

use std::collections::{BTreeMap, BTreeSet};

use astrolabe_domain::fsv::FsvAck;
use astrolabe_ingest::VaultMutationPlan;
use calyx_aster::cf::ColumnFamily;
use calyx_aster::vault::AsterVault;
use calyx_core::{AnchorKind, AnchorValue, CalyxError, Clock, CxId, LedgerRef, Ts, VaultStore};
use calyx_ledger::{ActorId, EntryKind, RedactionPolicy, SubjectId};
use serde::{Deserialize, Serialize};

use crate::{
    AnchorIngestReport, GroundingKind, OutcomeAnchorRequest, OutcomeKind, OutcomeSubject, TrustTag,
    anchor_corrupt, classify_source, hex_lower, ingest_outcome_anchors, ledger_ref_at_commit,
    read_anchor_rows,
};

/// Confidence carried by every agent-task Reward anchor.
///
/// A registry-declared knob (standing invariant 4), not a measurement. Blueprint
/// 06 §2.4 fixes agent self-reports as *proxy* evidence weighted at the exact
/// midpoint of the Provisional interval `(0, 1)`: an unverified agent claim is
/// deliberately less certain than the `0.8`
/// [`crate::DEFAULT_PROVISIONAL_CONFIDENCE`] or the `0.6`
/// [`crate::propagation::PROPAGATION_ANCHOR_CONFIDENCE`], because it is the
/// weakest proxy in the catalog — a bare assertion awaiting CI resolution. It
/// rises to Trusted only through [`promote_on_resolution`], never by re-weighting
/// this seed. Change it only with a blueprint amendment recording the new
/// rationale.
pub const AGENT_TASK_REWARD_CONFIDENCE: f32 = 0.5;

/// Stable failure code: `anchor_outcome{kind:"agent_task"}` named a `pack_id`
/// with no recorded manifest. Refused fail-closed so no orphan anchor is written.
pub const ASTRO_ANCHOR_PACK_UNKNOWN: &str = "ASTRO_ANCHOR_PACK_UNKNOWN";
/// Stable failure code: a pack manifest re-record disagrees with the members
/// already persisted under that `pack_id`.
pub const ASTRO_ANCHOR_PACK_CONFLICT: &str = "ASTRO_ANCHOR_PACK_CONFLICT";
/// Stable failure code: a pack manifest has an empty `pack_id`, empty membership,
/// or a duplicate member.
pub const ASTRO_ANCHOR_PACK_INPUT_INVALID: &str = "ASTRO_ANCHOR_PACK_INPUT_INVALID";
/// Stable failure code recorded when an agent claimed success but a resolved CI
/// outcome failed on the same symbol. Promotion is refused and the pair flagged.
pub const ASTRO_ANCHOR_CONTRADICTION: &str = "ASTRO_ANCHOR_CONTRADICTION";
/// Stable failure code: promotion sources violate the resolution contract (the
/// promoted source must be proxy `agent:*`, the resolving source must be
/// resolved, e.g. `ci:*`).
pub const ASTRO_ANCHOR_PROMOTION_INPUT_INVALID: &str = "ASTRO_ANCHOR_PROMOTION_INPUT_INVALID";

/// Row schema tag for a recorded agent-task context-pack manifest.
pub const SCHEMA_AGENT_TASK_PACK: &str = "astrolabe-agent-task-pack-v1";
/// Row schema tag for a persisted promotion record.
pub const SCHEMA_ANCHOR_PROMOTION: &str = "astrolabe-anchor-promotion-v1";
/// Row schema tag for a persisted contradiction record.
pub const SCHEMA_ANCHOR_CONTRADICTION: &str = "astrolabe-anchor-contradiction-v1";

/// Ledger payload schema for one pack-manifest record commit.
pub const AGENT_TASK_PACK_LEDGER_SCHEMA: &str = "astrolabe.agent_task_pack.v1";
/// Ledger payload schema for one promote-on-resolution reconciliation commit.
pub const ANCHOR_PROMOTION_LEDGER_SCHEMA: &str = "astrolabe.anchor_promotion.v1";
/// Ledger payload schema recorded inside the reconciliation commit for the
/// contradiction tally.
pub const ANCHOR_CONTRADICTION_LEDGER_SCHEMA: &str = "astrolabe.anchor_contradiction.v1";

const AGENT_TASK_PACK_PREFIX: &[u8] = b"astrolabe:agent-task-pack:v1:";
const ANCHOR_PROMOTION_PREFIX: &[u8] = b"astrolabe:anchor-promotion:v1:";
const ANCHOR_CONTRADICTION_PREFIX: &[u8] = b"astrolabe:anchor-contradiction:v1:";

const AGENT_TASK_REMEDIATION: &str =
    "record the served context pack with record_agent_task_pack, then anchor the outcome";

/// A recorded agent-task context-pack manifest: the exact symbol membership a
/// served pack anchored its outcome to. Written by the pack composer (or, until
/// `get_context_pack` lands, `record_agent_task_pack`) and read back to attribute
/// agent-task anchors to *exactly* these members — no more, no less.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentTaskPackManifestV1 {
    /// Always [`SCHEMA_AGENT_TASK_PACK`].
    pub schema: String,
    /// Stable pack identifier the serving surface handed to the agent.
    pub pack_id: String,
    /// Constellation ids of every symbol in the served pack, sorted and unique.
    pub members: Vec<CxId>,
}

/// A persisted promotion: a proxy agent Reward anchor upgraded to Trusted because
/// a resolved outcome confirmed the agent's success on the same symbol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorPromotionV1 {
    /// Always [`SCHEMA_ANCHOR_PROMOTION`].
    pub schema: String,
    /// Symbol whose agent Reward anchor is promoted.
    pub cx_id: CxId,
    /// The proxy `agent:*` source being promoted.
    pub promoted_source: String,
    /// The resolved source (e.g. `ci:*`) that confirmed the outcome.
    pub resolving_source: String,
    /// `observed_at` of the resolving anchor.
    pub resolving_observed_at: Ts,
    /// Server-observed time the promotion was recorded.
    pub promoted_at: Ts,
}

/// A persisted contradiction: an agent claimed success but a resolved outcome
/// failed on the same symbol. Promotion is refused; both anchors are retained.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorContradictionV1 {
    /// Always [`SCHEMA_ANCHOR_CONTRADICTION`].
    pub schema: String,
    /// Always [`ASTRO_ANCHOR_CONTRADICTION`].
    pub code: String,
    /// Symbol on which the agent and the resolved outcome disagree.
    pub cx_id: CxId,
    /// The proxy `agent:*` source that claimed success.
    pub agent_source: String,
    /// The resolved source (e.g. `ci:*`) that reported failure.
    pub resolving_source: String,
    /// `observed_at` of the resolving anchor.
    pub resolving_observed_at: Ts,
    /// Server-observed time the contradiction was detected.
    pub detected_at: Ts,
}

/// Report for one pack-manifest record commit.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentTaskPackReport {
    /// The manifest as persisted (members sorted and deduplicated).
    pub manifest: AgentTaskPackManifestV1,
    /// True when this call wrote a new manifest row; false on idempotent replay.
    pub manifest_written: bool,
    /// Grounding ledger entry paired with this commit.
    pub ledger_ref: LedgerRef,
    /// Full-readback witness when a row was written; `None` on idempotent replay.
    pub fsv: Option<FsvAck>,
}

/// One promoted `(cx_id, agent_source)` pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromotedPair {
    pub cx_id: CxId,
    pub agent_source: String,
    pub resolving_source: String,
}

/// One flagged contradiction pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContradictionPair {
    pub cx_id: CxId,
    pub agent_source: String,
    pub resolving_source: String,
}

/// Report for one promote-on-resolution reconciliation.
#[derive(Debug, Clone, PartialEq)]
pub struct AnchorPromotionReport {
    /// New promotion records written in this commit.
    pub promotions_written: usize,
    /// Promotions already present, skipped idempotently.
    pub promotions_deduplicated: usize,
    /// New contradiction records written in this commit.
    pub contradictions_written: usize,
    /// Contradictions already present, skipped idempotently.
    pub contradictions_deduplicated: usize,
    /// The `(cx, agent, resolving)` pairs promoted in this commit.
    pub promoted: Vec<PromotedPair>,
    /// The `(cx, agent, resolving)` pairs flagged as contradictions in this commit.
    pub contradictions: Vec<ContradictionPair>,
    /// KV rows written or rewritten.
    pub rows_written: usize,
    /// Grounding ledger entry paired with this reconciliation.
    pub ledger_ref: LedgerRef,
    /// Full-readback witness when rows were written; `None` for a ledger-only
    /// reconciliation that changed nothing.
    pub fsv: Option<FsvAck>,
}

fn agent_task_input_error(code: &'static str, message: String) -> CalyxError {
    CalyxError {
        code,
        message,
        remediation: AGENT_TASK_REMEDIATION,
    }
}

fn domain_to_calyx(error: astrolabe_domain::DomainError) -> CalyxError {
    CalyxError {
        code: error.code(),
        message: error.message().to_string(),
        remediation: error.remediation(),
    }
}

/// Reward value for an agent-task outcome: `1.0` success, `0.0` failure.
fn reward_value(success: bool) -> AnchorValue {
    AnchorValue::Number(if success { 1.0 } else { 0.0 })
}

/// True when an anchor value denotes success on its axis: a boolean pass, or a
/// numeric reward at or above the `0.5` midpoint. Any other shape is not a
/// success (fail-closed).
fn anchor_indicates_success(value: &AnchorValue) -> bool {
    match value {
        AnchorValue::Bool(passed) => *passed,
        AnchorValue::Number(reward) => reward.is_finite() && *reward >= 0.5,
        _ => false,
    }
}

fn pack_key(pack_id: &str) -> Vec<u8> {
    let mut key = AGENT_TASK_PACK_PREFIX.to_vec();
    key.extend_from_slice(blake3::hash(pack_id.as_bytes()).as_bytes());
    key
}

fn pair_key(prefix: &[u8], cx_id: CxId, source_a: &str, source_b: &str) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(cx_id.as_bytes());
    hasher.update(&[0]);
    hasher.update(source_a.as_bytes());
    hasher.update(&[0]);
    hasher.update(source_b.as_bytes());
    let mut key = prefix.to_vec();
    key.extend_from_slice(hasher.finalize().as_bytes());
    key
}

/// Records a served context pack's exact symbol membership so agent-task outcomes
/// can be attributed to it. Members are sorted and deduplicated. Re-recording the
/// identical membership is idempotent (no new row); a `pack_id` re-record with
/// *different* members refuses fail-closed ([`ASTRO_ANCHOR_PACK_CONFLICT`]) — a
/// pack's membership is immutable evidence. The row and its hash-only `Grounding`
/// ledger entry land in one atomic group commit.
pub fn record_agent_task_pack<C>(
    vault: &AsterVault<C>,
    pack_id: &str,
    members: &[CxId],
    observed_at: Ts,
    actor: impl Into<String>,
) -> calyx_core::Result<AgentTaskPackReport>
where
    C: Clock,
{
    crate::validate_observed_at(observed_at).map_err(domain_to_calyx)?;
    if pack_id.trim().is_empty() {
        return Err(agent_task_input_error(
            ASTRO_ANCHOR_PACK_INPUT_INVALID,
            "pack_id is empty; a recorded pack manifest requires a stable identifier".to_string(),
        ));
    }
    if members.is_empty() {
        return Err(agent_task_input_error(
            ASTRO_ANCHOR_PACK_INPUT_INVALID,
            format!("pack {pack_id:?} has no members; an empty pack anchors nothing"),
        ));
    }
    let mut sorted: Vec<CxId> = members.to_vec();
    sorted.sort();
    let deduped: Vec<CxId> = {
        let mut seen = BTreeSet::new();
        sorted.iter().copied().filter(|m| seen.insert(*m)).collect()
    };
    if deduped.len() != members.len() {
        return Err(agent_task_input_error(
            ASTRO_ANCHOR_PACK_INPUT_INVALID,
            format!(
                "pack {pack_id:?} membership has duplicate CxIds; each member must appear once"
            ),
        ));
    }

    let manifest = AgentTaskPackManifestV1 {
        schema: SCHEMA_AGENT_TASK_PACK.to_string(),
        pack_id: pack_id.to_string(),
        members: deduped,
    };
    let key = pack_key(pack_id);
    if let Some(existing) = read_agent_task_pack(vault, pack_id)? {
        if existing == manifest {
            let ledger_ref = ledger_only_pack_record(vault, &manifest, observed_at, actor)?;
            return Ok(AgentTaskPackReport {
                manifest,
                manifest_written: false,
                ledger_ref,
                fsv: None,
            });
        }
        return Err(agent_task_input_error(
            ASTRO_ANCHOR_PACK_CONFLICT,
            format!(
                "pack {pack_id:?} already recorded with {} members; refusing conflicting \
                 re-record with {} members",
                existing.members.len(),
                manifest.members.len()
            ),
        ));
    }

    let value = serde_json::to_vec(&manifest)
        .map_err(|error| anchor_corrupt(format!("encode agent-task pack manifest: {error}")))?;
    let payload = pack_ledger_payload(&manifest, observed_at, true)?;
    RedactionPolicy::check_payload(&payload)?;
    let subject = SubjectId::Query(
        format!(
            "astrolabe-agent-task-pack:{}",
            hex_lower(blake3::hash(pack_id.as_bytes()).as_bytes())
        )
        .into_bytes(),
    );
    let actor = ActorId::Service(actor.into());
    let mut fsv_plan = VaultMutationPlan::new(
        "record_agent_task_pack",
        EntryKind::Grounding,
        &actor,
        &subject,
    );
    fsv_plan.push_content(ColumnFamily::Kv, key.clone(), &value);
    let commit_seq = vault.write_cf_batch_with_ledger_entry(
        vec![(ColumnFamily::Kv, key, value)],
        EntryKind::Grounding,
        subject,
        payload,
        actor,
    )?;
    vault.flush()?;
    let fsv = fsv_plan.verify_committed(vault, commit_seq)?;
    Ok(AgentTaskPackReport {
        manifest,
        manifest_written: true,
        ledger_ref: ledger_ref_at_commit(vault, commit_seq)?,
        fsv: Some(fsv),
    })
}

fn ledger_only_pack_record<C>(
    vault: &AsterVault<C>,
    manifest: &AgentTaskPackManifestV1,
    observed_at: Ts,
    actor: impl Into<String>,
) -> calyx_core::Result<LedgerRef>
where
    C: Clock,
{
    let payload = pack_ledger_payload(manifest, observed_at, false)?;
    RedactionPolicy::check_payload(&payload)?;
    let subject = SubjectId::Query(
        format!(
            "astrolabe-agent-task-pack:{}",
            hex_lower(blake3::hash(manifest.pack_id.as_bytes()).as_bytes())
        )
        .into_bytes(),
    );
    let ledger_ref = vault.append_ledger_entry(
        EntryKind::Grounding,
        subject,
        payload,
        ActorId::Service(actor.into()),
    )?;
    vault.flush()?;
    Ok(ledger_ref)
}

fn pack_ledger_payload(
    manifest: &AgentTaskPackManifestV1,
    recorded_at: Ts,
    written: bool,
) -> calyx_core::Result<Vec<u8>> {
    let mut member_hasher = blake3::Hasher::new();
    for member in &manifest.members {
        member_hasher.update(member.as_bytes());
    }
    serde_json::to_vec(&serde_json::json!({
        "schema": AGENT_TASK_PACK_LEDGER_SCHEMA,
        "pack_id_hash": hex_lower(blake3::hash(manifest.pack_id.as_bytes()).as_bytes()),
        "member_count": manifest.members.len(),
        "members_hash": hex_lower(member_hasher.finalize().as_bytes()),
        "recorded_at": recorded_at,
        "manifest_written": written,
    }))
    .map_err(|error| anchor_corrupt(format!("encode agent-task pack ledger payload: {error}")))
}

/// Reads back a recorded pack manifest by `pack_id`, key- and schema-verified.
pub fn read_agent_task_pack<C>(
    vault: &AsterVault<C>,
    pack_id: &str,
) -> calyx_core::Result<Option<AgentTaskPackManifestV1>>
where
    C: Clock,
{
    let key = pack_key(pack_id);
    let Some(bytes) = vault.read_cf_at(vault.snapshot(), ColumnFamily::Kv, &key)? else {
        return Ok(None);
    };
    let manifest = decode_pack_manifest(&key, &bytes)?;
    if manifest.pack_id != pack_id {
        return Err(anchor_corrupt(format!(
            "agent-task pack row {} decodes to pack_id {:?}, not {:?}",
            hex_lower(&key),
            manifest.pack_id,
            pack_id
        )));
    }
    Ok(Some(manifest))
}

/// Reads back every recorded pack manifest, key- and schema-verified.
pub fn read_agent_task_packs<C>(
    vault: &AsterVault<C>,
) -> calyx_core::Result<Vec<AgentTaskPackManifestV1>>
where
    C: Clock,
{
    let snapshot = vault.snapshot();
    let mut manifests = Vec::new();
    for (key, bytes) in vault.scan_cf_at(snapshot, ColumnFamily::Kv)? {
        if !key.starts_with(AGENT_TASK_PACK_PREFIX) {
            continue;
        }
        manifests.push(decode_pack_manifest(&key, &bytes)?);
    }
    manifests.sort_by(|left, right| left.pack_id.cmp(&right.pack_id));
    Ok(manifests)
}

fn decode_pack_manifest(key: &[u8], bytes: &[u8]) -> calyx_core::Result<AgentTaskPackManifestV1> {
    let manifest: AgentTaskPackManifestV1 = serde_json::from_slice(bytes).map_err(|error| {
        anchor_corrupt(format!(
            "decode agent-task pack manifest {}: {error}",
            hex_lower(key)
        ))
    })?;
    if manifest.schema != SCHEMA_AGENT_TASK_PACK {
        return Err(anchor_corrupt(format!(
            "agent-task pack row {} carries schema {:?}",
            hex_lower(key),
            manifest.schema
        )));
    }
    if key != pack_key(&manifest.pack_id) {
        return Err(anchor_corrupt(format!(
            "agent-task pack row {} does not match its pack_id key",
            hex_lower(key)
        )));
    }
    if manifest.members.is_empty() {
        return Err(anchor_corrupt(format!(
            "agent-task pack row {} has no members",
            hex_lower(key)
        )));
    }
    Ok(manifest)
}

/// Builds the `agent_task` outcome request for a recorded pack, attributing a
/// Provisional Reward anchor to *exactly* every member CxId.
///
/// `source` is `agent:<agent>:<session>` (validated as a proxy source). The
/// returned `(request, cx_ids)` feed [`ingest_outcome_anchors`]; the identity
/// `cx_ids` map guarantees no subject is unmapped, so anchors land on the pack's
/// members and nowhere else.
pub fn build_agent_task_request<C>(
    vault: &AsterVault<C>,
    pack_id: &str,
    agent: &str,
    session: &str,
    success: bool,
    observed_at: Ts,
) -> calyx_core::Result<(OutcomeAnchorRequest, BTreeMap<String, CxId>)>
where
    C: Clock,
{
    let manifest = read_agent_task_pack(vault, pack_id)?.ok_or_else(|| {
        agent_task_input_error(
            ASTRO_ANCHOR_PACK_UNKNOWN,
            format!("no recorded pack manifest for pack_id {pack_id:?}"),
        )
    })?;
    let source = format!("agent:{agent}:{session}");
    // Validate the proxy source shape before building any subject.
    let classification = classify_source(&source).map_err(domain_to_calyx)?;
    if classification.grounding_kind != GroundingKind::Proxy {
        return Err(agent_task_input_error(
            ASTRO_ANCHOR_PROMOTION_INPUT_INVALID,
            format!("agent-task source {source:?} did not classify as proxy evidence"),
        ));
    }
    let value = reward_value(success);
    let mut subjects = Vec::with_capacity(manifest.members.len());
    let mut cx_ids = BTreeMap::new();
    for member in &manifest.members {
        let subject_id = member.to_string();
        subjects.push(OutcomeSubject {
            subject_id: subject_id.clone(),
            anchor_kind: AnchorKind::Reward,
            value: value.clone(),
        });
        cx_ids.insert(subject_id, *member);
    }
    let request = OutcomeAnchorRequest::new(
        OutcomeKind::AgentTask,
        source,
        observed_at,
        Some(AGENT_TASK_REWARD_CONFIDENCE),
        subjects,
    )
    .map_err(domain_to_calyx)?;
    Ok((request, cx_ids))
}

/// Records an agent-task outcome against a recorded pack: every member CxId gets
/// a Provisional Reward anchor (`agent:<agent>:<session>`, confidence
/// [`AGENT_TASK_REWARD_CONFIDENCE`]). An unknown `pack_id` refuses fail-closed
/// ([`ASTRO_ANCHOR_PACK_UNKNOWN`]) with no anchor written.
pub fn ingest_agent_task_outcome<C>(
    vault: &AsterVault<C>,
    pack_id: &str,
    agent: &str,
    session: &str,
    success: bool,
    observed_at: Ts,
    actor: impl Into<String>,
) -> calyx_core::Result<AnchorIngestReport>
where
    C: Clock,
{
    let (request, cx_ids) =
        build_agent_task_request(vault, pack_id, agent, session, success, observed_at)?;
    ingest_outcome_anchors(vault, &request, &cx_ids, actor)
}

/// Reconciles proxy agent Reward anchors against a resolved outcome, promoting
/// confirmed successes and flagging contradictions.
///
/// For every symbol carrying *both* an active `agent_source` Reward anchor and an
/// active `resolving_source` `TestPass` anchor:
/// - agent success **and** resolved pass -> a promotion record is written; the
///   agent anchor's effective trust becomes Trusted ([`effective_anchor_trust`]).
/// - agent success **but** resolved failure -> a contradiction record is written
///   ([`ASTRO_ANCHOR_CONTRADICTION`]); promotion is refused and both anchors
///   retain their original trust.
/// - agent failure -> nothing to promote; skipped.
///
/// Symbols the resolving outcome does not cover are never promoted, so an
/// unrelated CI run touches nothing. Promotions and contradictions are
/// append-only and idempotent; the whole reconciliation is one atomic group
/// commit paired with a hash-only `Grounding` ledger entry and read-back FSV.
/// `agent_source` must be proxy and `resolving_source` resolved, else refuse
/// ([`ASTRO_ANCHOR_PROMOTION_INPUT_INVALID`]).
pub fn promote_on_resolution<C>(
    vault: &AsterVault<C>,
    agent_source: &str,
    resolving_source: &str,
    observed_at: Ts,
    actor: impl Into<String>,
) -> calyx_core::Result<AnchorPromotionReport>
where
    C: Clock,
{
    let agent_class = classify_source(agent_source).map_err(domain_to_calyx)?;
    if agent_class.grounding_kind != GroundingKind::Proxy {
        return Err(agent_task_input_error(
            ASTRO_ANCHOR_PROMOTION_INPUT_INVALID,
            format!("promoted source {agent_source:?} must be proxy evidence (e.g. agent:*)"),
        ));
    }
    let resolving_class = classify_source(resolving_source).map_err(domain_to_calyx)?;
    if resolving_class.grounding_kind != GroundingKind::Resolved {
        return Err(agent_task_input_error(
            ASTRO_ANCHOR_PROMOTION_INPUT_INVALID,
            format!("resolving source {resolving_source:?} must be resolved evidence (e.g. ci:*)"),
        ));
    }

    let rows = read_anchor_rows(vault)?;
    // Latest observed agent success and resolved pass per symbol.
    let mut agent_success: BTreeMap<CxId, (bool, Ts)> = BTreeMap::new();
    let mut resolved_pass: BTreeMap<CxId, (bool, Ts)> = BTreeMap::new();
    for persisted in &rows {
        let cx_id = persisted.row.cx_id;
        for anchor in &persisted.row.anchors {
            if persisted.row.kind == AnchorKind::Reward && anchor.source == agent_source {
                update_latest(
                    &mut agent_success,
                    cx_id,
                    anchor_indicates_success(&anchor.value),
                    anchor.observed_at,
                );
            } else if persisted.row.kind == AnchorKind::TestPass
                && anchor.source == resolving_source
            {
                update_latest(
                    &mut resolved_pass,
                    cx_id,
                    anchor_indicates_success(&anchor.value),
                    anchor.observed_at,
                );
            }
        }
    }

    let snapshot = vault.snapshot();
    let mut batch = Vec::new();
    let mut promoted = Vec::new();
    let mut contradictions = Vec::new();
    let mut promotions_deduplicated = 0usize;
    let mut contradictions_deduplicated = 0usize;

    for (&cx_id, &(agent_ok, _)) in &agent_success {
        let Some(&(ci_ok, ci_ts)) = resolved_pass.get(&cx_id) else {
            continue; // resolving outcome did not cover this symbol
        };
        if !agent_ok {
            continue; // agent reported failure: nothing to promote
        }
        if ci_ok {
            let key = pair_key(
                ANCHOR_PROMOTION_PREFIX,
                cx_id,
                agent_source,
                resolving_source,
            );
            if vault
                .read_cf_at(snapshot, ColumnFamily::Kv, &key)?
                .is_some()
            {
                promotions_deduplicated += 1;
                continue;
            }
            let record = AnchorPromotionV1 {
                schema: SCHEMA_ANCHOR_PROMOTION.to_string(),
                cx_id,
                promoted_source: agent_source.to_string(),
                resolving_source: resolving_source.to_string(),
                resolving_observed_at: ci_ts,
                promoted_at: observed_at,
            };
            let value = serde_json::to_vec(&record)
                .map_err(|error| anchor_corrupt(format!("encode promotion record: {error}")))?;
            batch.push((ColumnFamily::Kv, key, value));
            promoted.push(PromotedPair {
                cx_id,
                agent_source: agent_source.to_string(),
                resolving_source: resolving_source.to_string(),
            });
        } else {
            let key = pair_key(
                ANCHOR_CONTRADICTION_PREFIX,
                cx_id,
                agent_source,
                resolving_source,
            );
            if vault
                .read_cf_at(snapshot, ColumnFamily::Kv, &key)?
                .is_some()
            {
                contradictions_deduplicated += 1;
                continue;
            }
            let record = AnchorContradictionV1 {
                schema: SCHEMA_ANCHOR_CONTRADICTION.to_string(),
                code: ASTRO_ANCHOR_CONTRADICTION.to_string(),
                cx_id,
                agent_source: agent_source.to_string(),
                resolving_source: resolving_source.to_string(),
                resolving_observed_at: ci_ts,
                detected_at: observed_at,
            };
            let value = serde_json::to_vec(&record)
                .map_err(|error| anchor_corrupt(format!("encode contradiction record: {error}")))?;
            batch.push((ColumnFamily::Kv, key, value));
            contradictions.push(ContradictionPair {
                cx_id,
                agent_source: agent_source.to_string(),
                resolving_source: resolving_source.to_string(),
            });
        }
    }

    let rows_written = batch.len();
    let payload = serde_json::to_vec(&serde_json::json!({
        "schema": ANCHOR_PROMOTION_LEDGER_SCHEMA,
        "contradiction_schema": ANCHOR_CONTRADICTION_LEDGER_SCHEMA,
        "agent_source_hash": hex_lower(blake3::hash(agent_source.as_bytes()).as_bytes()),
        "resolving_source_hash": hex_lower(blake3::hash(resolving_source.as_bytes()).as_bytes()),
        "promotions_written": promoted.len(),
        "contradictions_written": contradictions.len(),
        "promotions_deduplicated": promotions_deduplicated,
        "contradictions_deduplicated": contradictions_deduplicated,
        "rows_written": rows_written,
        "observed_at": observed_at,
    }))
    .map_err(|error| anchor_corrupt(format!("encode promotion ledger payload: {error}")))?;
    RedactionPolicy::check_payload(&payload)?;

    let subject = SubjectId::Query(
        format!(
            "astrolabe-anchor-promotion:{}:{}",
            hex_lower(blake3::hash(agent_source.as_bytes()).as_bytes()),
            hex_lower(blake3::hash(resolving_source.as_bytes()).as_bytes())
        )
        .into_bytes(),
    );
    let actor = ActorId::Service(actor.into());
    let mut fsv_plan = VaultMutationPlan::new(
        "promote_on_resolution",
        EntryKind::Grounding,
        &actor,
        &subject,
    );
    for (cf, key, value) in &batch {
        fsv_plan.push_content(*cf, key.clone(), value);
    }
    let (ledger_ref, fsv) = if batch.is_empty() {
        (
            vault.append_ledger_entry(EntryKind::Grounding, subject, payload, actor)?,
            None,
        )
    } else {
        let commit_seq = vault.write_cf_batch_with_ledger_entry(
            batch,
            EntryKind::Grounding,
            subject,
            payload,
            actor,
        )?;
        vault.flush()?;
        let fsv = fsv_plan.verify_committed(vault, commit_seq)?;
        (ledger_ref_at_commit(vault, commit_seq)?, Some(fsv))
    };
    if fsv.is_none() {
        vault.flush()?;
    }

    Ok(AnchorPromotionReport {
        promotions_written: promoted.len(),
        promotions_deduplicated,
        contradictions_written: contradictions.len(),
        contradictions_deduplicated,
        promoted,
        contradictions,
        rows_written,
        ledger_ref,
        fsv,
    })
}

fn update_latest(
    map: &mut BTreeMap<CxId, (bool, Ts)>,
    cx_id: CxId,
    success: bool,
    observed_at: Ts,
) {
    map.entry(cx_id)
        .and_modify(|slot| {
            if observed_at >= slot.1 {
                *slot = (success, observed_at);
            }
        })
        .or_insert((success, observed_at));
}

/// Reads back every persisted promotion record, key- and schema-verified.
pub fn read_anchor_promotions<C>(
    vault: &AsterVault<C>,
) -> calyx_core::Result<Vec<AnchorPromotionV1>>
where
    C: Clock,
{
    let snapshot = vault.snapshot();
    let mut records = Vec::new();
    for (key, bytes) in vault.scan_cf_at(snapshot, ColumnFamily::Kv)? {
        if !key.starts_with(ANCHOR_PROMOTION_PREFIX) {
            continue;
        }
        let record: AnchorPromotionV1 = serde_json::from_slice(&bytes).map_err(|error| {
            anchor_corrupt(format!(
                "decode promotion record {}: {error}",
                hex_lower(&key)
            ))
        })?;
        if record.schema != SCHEMA_ANCHOR_PROMOTION
            || key
                != pair_key(
                    ANCHOR_PROMOTION_PREFIX,
                    record.cx_id,
                    &record.promoted_source,
                    &record.resolving_source,
                )
        {
            return Err(anchor_corrupt(format!(
                "promotion record {} disagrees with its key",
                hex_lower(&key)
            )));
        }
        records.push(record);
    }
    records.sort_by(|left, right| {
        (
            left.cx_id.to_string(),
            &left.promoted_source,
            &left.resolving_source,
        )
            .cmp(&(
                right.cx_id.to_string(),
                &right.promoted_source,
                &right.resolving_source,
            ))
    });
    Ok(records)
}

/// Reads back every persisted contradiction record, key- and schema-verified.
pub fn read_anchor_contradictions<C>(
    vault: &AsterVault<C>,
) -> calyx_core::Result<Vec<AnchorContradictionV1>>
where
    C: Clock,
{
    let snapshot = vault.snapshot();
    let mut records = Vec::new();
    for (key, bytes) in vault.scan_cf_at(snapshot, ColumnFamily::Kv)? {
        if !key.starts_with(ANCHOR_CONTRADICTION_PREFIX) {
            continue;
        }
        let record: AnchorContradictionV1 = serde_json::from_slice(&bytes).map_err(|error| {
            anchor_corrupt(format!(
                "decode contradiction record {}: {error}",
                hex_lower(&key)
            ))
        })?;
        if record.schema != SCHEMA_ANCHOR_CONTRADICTION
            || record.code != ASTRO_ANCHOR_CONTRADICTION
            || key
                != pair_key(
                    ANCHOR_CONTRADICTION_PREFIX,
                    record.cx_id,
                    &record.agent_source,
                    &record.resolving_source,
                )
        {
            return Err(anchor_corrupt(format!(
                "contradiction record {} disagrees with its key",
                hex_lower(&key)
            )));
        }
        records.push(record);
    }
    records.sort_by(|left, right| {
        (
            left.cx_id.to_string(),
            &left.agent_source,
            &left.resolving_source,
        )
            .cmp(&(
                right.cx_id.to_string(),
                &right.agent_source,
                &right.resolving_source,
            ))
    });
    Ok(records)
}

/// True when `(cx_id, source)` has a persisted promotion in `promotions`.
pub fn is_anchor_promoted(promotions: &[AnchorPromotionV1], cx_id: CxId, source: &str) -> bool {
    promotions
        .iter()
        .any(|promotion| promotion.cx_id == cx_id && promotion.promoted_source == source)
}

/// Effective trust of an anchor with `source` on `cx_id`: Trusted if a promotion
/// exists, else the catalog trust of its source. Refuses fail-closed on an
/// unknown source prefix.
pub fn effective_anchor_trust(
    cx_id: CxId,
    source: &str,
    promotions: &[AnchorPromotionV1],
) -> calyx_core::Result<TrustTag> {
    if is_anchor_promoted(promotions, cx_id, source) {
        return Ok(TrustTag::Trusted);
    }
    Ok(classify_source(source).map_err(domain_to_calyx)?.trust)
}

/// Rolls up aggregate trust across active anchor rows **honoring promotions**.
///
/// Each active anchor contributes its [`effective_anchor_trust`]: a proxy
/// `agent:*` Reward anchor that a resolved outcome has promoted contributes
/// Trusted, every other anchor contributes its catalog trust. The aggregate is
/// Trusted iff at least one anchor contributes and every contributor is Trusted;
/// empty evidence fails closed to Provisional (via [`crate::rollup_trust`]).
///
/// This is the promotion-aware counterpart of [`crate::rollup_anchor_trust`] and
/// the exact point at which the agent-task flywheel reaches the #29 aggregate
/// trust lifecycle: `rollup_anchor_trust` classifies by catalog source alone, so
/// a promoted `agent:*` anchor stays Provisional there forever; this function
/// lifts the aggregate from Provisional to Trusted once CI has resolved the
/// agent claim, without ever rewriting the anchor's catalog source. Every
/// anchor's persisted confidence is re-validated against its grounding kind
/// first, so a corrupt confidence refuses fail-closed rather than silently
/// rolling up.
///
/// Callers pass the active rows (`crate::read_anchor_rows`, tombstone-excluded)
/// and the persisted promotions (`read_anchor_promotions`); source erasure is
/// therefore honored by construction, because erased anchors are already absent
/// from the active rows the aggregate is computed over.
pub fn rollup_effective_anchor_trust<'a>(
    rows: impl IntoIterator<Item = &'a crate::PersistedAnchorRow>,
    promotions: &[AnchorPromotionV1],
) -> calyx_core::Result<TrustTag> {
    let mut tags = Vec::new();
    for persisted in rows {
        let cx_id = persisted.row.cx_id;
        for anchor in &persisted.row.anchors {
            let classification = classify_source(&anchor.source).map_err(domain_to_calyx)?;
            crate::validate_confidence(classification.grounding_kind, Some(anchor.confidence))
                .map_err(domain_to_calyx)?;
            tags.push(effective_anchor_trust(cx_id, &anchor.source, promotions)?);
        }
    }
    Ok(crate::rollup_trust(tags))
}
