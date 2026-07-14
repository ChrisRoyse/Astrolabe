#![forbid(unsafe_code)]

pub mod kernel_index;
pub mod search;
pub mod search_eval;
pub mod search_index;
pub mod search_production;

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};
use std::error::Error;
use std::fmt;
use std::ops::Range;
use std::thread;

use astrolabe_domain::EdgeKind;
use calyx_assay::AssayStore;
use calyx_aster::cf::{ColumnFamily, XTermKind, xterm_key};
use calyx_aster::vault::AsterVault;
use calyx_core::{CalyxError, Clock, CxId, LedgerRef, SlotId, SlotVector, SparseEntry, VaultStore};
use calyx_ledger::decode as decode_ledger;
use calyx_ledger::{ActorId, EntryKind, RedactionPolicy, SubjectId};
use calyx_loom::agreement_graph::XtermRow;
pub use calyx_loom::reactive::{
    DEFAULT_MAX_AUDIT_ENTRIES as CALYX_REACTIVE_AUDIT_CAP,
    DEFAULT_MAX_QUEUE_DEPTH as CALYX_REACTIVE_QUEUE_CAP,
    DEFAULT_MAX_TRIGGERS as CALYX_REACTIVE_REGISTRY_CAP,
};
pub use calyx_loom::{
    AuditEntry as ReactiveAuditEntry, CALYX_REACTIVE_ROW_CORRUPT,
    CALYX_REACTIVE_SUBSCRIPTION_NOT_FOUND, NoveltyVerdict, ReactiveEngine, ReactiveRowKind,
    ReactiveSignalSet, ReactiveSignals, SeriesStore, SubscriptionId, TriggerCondition,
    TriggerFired, TriggerId, decode_audit_entry, decode_trigger_fired, reactive_row_key,
};
use calyx_loom::{CrossTermKind as LoomCrossTermKind, CrossTermValue as LoomCrossTermValue};
use serde::{Deserialize, Serialize};
use serde_json::Value;

mod ann;
pub mod drift_producer;
mod sim_rows;
mod xterm_rows;

pub use ann::{AnnFamilyReport, QuantScaleMeasurement};
pub use drift_producer::{
    DRIFT_REFERENCE_PAYLOAD_SCHEMA, DriftProductionReport, DriftSlotSamples, load_drift_reference,
    persist_drift_reference, produce_drift_cards, read_slot_samples_from_vault,
    run_index_time_drift,
};
pub use kernel_index::{
    ASTRO_KERNEL_INDEX_ABSENT, ASTRO_KERNEL_INDEX_MEMBER_ABSENT, ASTRO_KERNEL_INDEX_NO_MEMBERS,
    ASTRO_KERNEL_INDEX_STALE, ASTRO_KERNEL_INDEX_VAULT, KERNEL_INDEX_RECALL_GATE_PERMILLE,
    KERNEL_MEMBER_INDEX_SCHEMA, KernelIndexKind, KernelMemberIndex, KernelRecallMeasurement,
    build_kernel_member_index, kernel_scoped_semantic_query, measure_kernel_index_recall,
};
pub use sim_rows::{
    ASTRO_SIM_EDGE_LEDGER_MISSING, ASTRO_SIM_EDGE_ROW_CORRUPT, PersistedSimilarityEdgeRow,
    SCHEMA_SIM_EDGE_ROW, SIM_EDGE_LEDGER_SCHEMA, SIM_EDGE_ROW_PREFIX, SimEdgeGraphRow,
    SimilarityPersistReport, persist_similarity_edges, persist_similarity_edges_delta,
    read_similarity_edge_rows, sim_edge_graph_key,
};
pub use xterm_rows::{
    AGREEMENT_GRAPH_ASPECT_PROVENANCE, AGREEMENT_GRAPH_ASPECT_SCHEMA, ASTRO_XTERM_CX_ID_MISSING,
    ASTRO_XTERM_ROW_CORRUPT, AgreementGraphAspect, EagerCrossTermPersistReport,
    PersistedAgreementEdge, PersistedEagerCrossTermRow, XTERM_EAGER_LEDGER_SCHEMA,
    agreement_graph_aspect, agreement_graph_from_persisted_rows, designed_kind_for_slots,
    eager_xterm_dump_bytes, eager_xterm_key, lazy_agreement, persist_eager_cross_terms,
    persist_eager_cross_terms_delta, read_eager_cross_term_rows,
};

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

pub fn parent_system() -> astrolabe_domain::ParentSystem {
    astrolabe_domain::ParentSystem::Calyx
}

/// A production-path weave persistence outcome that may have changed vault state
/// the lowered SQLite artifact derives from (#225).
///
/// The lowered artifact's content fingerprint moves whenever the vault content
/// it derives from — the persisted Graph/XTerm rows and the ledger head — moves.
/// A weave commit that actually wrote or tombstoned rows (or drained reactive
/// events) is such a change; a no-delta audit re-run that only re-appends an
/// idempotent ledger record is not a content change and must not trigger a
/// regeneration, or every re-run would rewrite the lowered artifact.
pub trait WeaveMutation {
    /// True when this commit changed derived vault content (rows written or
    /// tombstoned, or reactive events acknowledged), false for a no-delta run.
    fn changed_lowered_inputs(&self) -> bool;
}

impl WeaveMutation for SimilarityPersistReport {
    fn changed_lowered_inputs(&self) -> bool {
        self.rows_written > 0 || self.rows_tombstoned > 0
    }
}

impl WeaveMutation for EagerCrossTermPersistReport {
    fn changed_lowered_inputs(&self) -> bool {
        self.rows_written > 0 || self.rows_tombstoned > 0
    }
}

impl WeaveMutation for ReactiveAckReport {
    fn changed_lowered_inputs(&self) -> bool {
        self.acked_count > 0
    }
}

/// Trigger plumbing from a weave mutation path: after a weave persistence commit,
/// ask the lowering coordinator to schedule a debounced lowered-SQLite
/// regeneration — but only when the commit actually changed derived vault
/// content. A no-delta audit re-run never schedules a regeneration.
///
/// Returns whether a regeneration was requested, so callers can surface the
/// scheduling decision. The scheduling itself is debounced by the trigger
/// implementor (`astrolabe-lower`'s `LowerDebouncer`), so N rapid mutations
/// coalesce into one regeneration.
pub fn schedule_lowering_after<M>(
    report: &M,
    trigger: &dyn astrolabe_domain::LoweringTrigger,
) -> bool
where
    M: WeaveMutation + ?Sized,
{
    let changed = report.changed_lowered_inputs();
    if changed {
        trigger.request_regeneration();
    }
    changed
}

pub const SIM_STRUCT_SLOT: SlotId = SlotId::new(1);
pub const SIM_API_SLOT: SlotId = SlotId::new(4);
pub const SIM_SEMANTIC_SLOT: SlotId = SlotId::new(18);
pub const SIM_PROFILE_SLOT: SlotId = SlotId::new(21);

pub const DEFAULT_SIM_STRUCT_MIN_SCORE: f32 = 0.95;
pub const DEFAULT_SIM_SEMANTIC_MIN_SCORE: f32 = 0.80;
pub const DEFAULT_SIM_API_MIN_SCORE: f32 = 0.80;
pub const DEFAULT_SIM_PROFILE_MIN_SCORE: f32 = 0.80;
pub const DEFAULT_SIMILARITY_PER_NODE_CAP: usize = 10;
pub const DEFAULT_SIMILARITY_WORKERS: usize = 1;
pub const DEFAULT_SIMILARITY_EXACT_PAIR_NODE_LIMIT: usize = 50_000;
/// MinHash signature length for LSH banding candidate generation.
///
/// v1 prior carried over from CBM's retained MinHash pipeline (128-permutation
/// signatures behind the 512-hex `fp` fingerprint budget). Annealable later.
pub const DEFAULT_SIMILARITY_LSH_PERMUTATIONS: usize = 128;
/// LSH band count over the MinHash signature (rows per band = permutations / bands).
///
/// v1 derivation from CBM's 0.95-Jaccard admission prior: with 128 permutations
/// and 32 bands (4 rows/band) the banding S-curve crosses 0.5 near Jaccard
/// (1/32)^(1/4) ≈ 0.42, so a pair at the 0.95-Jaccard admission prior is missed
/// with probability (1 − 0.95⁴)³² ≈ 4e-24 — candidate recall at the admission
/// threshold is effectively 1 while pairs far below it stay unprobed.
pub const DEFAULT_SIMILARITY_LSH_BANDS: usize = 32;
/// Deterministic namespace seed for LSH hash derivation and HNSW level draws.
///
/// A fixed identity ("ASTROLAB" as big-endian ASCII), not a tuned quantity: any
/// value yields a valid deterministic plan; changing it changes candidate sets,
/// so it is pinned in config for reproducibility.
pub const DEFAULT_SIMILARITY_ANN_SEED: u64 = u64::from_be_bytes(*b"ASTROLAB");
/// Candidate head-room multiplier for ANN generation.
///
/// Both generators probe `per_node_cap × this` candidates per node (HNSW query
/// k, LSH within-bucket pairing span) so that ownership filtering and exact
/// rescoring still leave `per_node_cap` admissible edges. v1 default 3 is a
/// declared knob (annealable later), not a measurement.
pub const DEFAULT_SIMILARITY_ANN_CANDIDATE_MULTIPLIER: usize = 3;
/// HNSW beam width (`ef`) used for candidate queries.
///
/// v1 prior: 2× the vendored index's own default beam floor (`max_neighbors ×
/// 2 = 64`), a declared knob (annealable later). Raised automatically to the
/// query k when k exceeds it, since the index fails closed on `ef < k`.
pub const DEFAULT_SIMILARITY_HNSW_EF_SEARCH: usize = 128;
/// Squared-L2-norm floor below which a slot/profile vector is treated as a
/// degenerate zero vector and skipped from similarity and cross-term scoring.
///
/// # Scale
/// [`dense_norm`] and [`sparse_norm`] return the **squared** L2 norm (the sum of
/// squares), and `cosine` divides by `norm.sqrt()`. This knob is therefore declared
/// on the *squared* scale so [`zero_norm`] classifies on the same scale as the value
/// it receives. The equivalent *linear* L2-norm floor is `sqrt(f32::MIN_POSITIVE)`
/// ≈ 1.08e-19.
///
/// # Derivation (measured, not a policy magic number)
/// The only legitimate reason to reject a vector here is numerical: `cosine` computes
/// `dot / (left_norm.sqrt() * right_norm.sqrt())`, which is well defined precisely
/// while each squared norm stays within the *normal* (non-subnormal) IEEE-754 binary32
/// range. The floor is thus the smallest normal binary32 value, `f32::MIN_POSITIVE`
/// (≈ 1.1755e-38). Any genuinely non-zero vector — including the ~1e-4-linear-norm
/// vectors (squared ≈ 1e-8) that the previous `norm <= f32::EPSILON` (≈ 1.19e-7) test
/// misclassified as zero — sits far above this floor and is scored normally.
pub const DEFAULT_MIN_VECTOR_SQUARED_NORM: f32 = f32::MIN_POSITIVE;
pub const ASTROLABE_REACTIVE_REGISTRY_CAP: usize = CALYX_REACTIVE_REGISTRY_CAP;
pub const ASTROLABE_REACTIVE_QUEUE_CAP: usize = CALYX_REACTIVE_QUEUE_CAP;
pub const ASTROLABE_REACTIVE_AUDIT_CAP: usize = CALYX_REACTIVE_AUDIT_CAP;
pub const PANEL_SLOT_COUNT_FOR_ABUNDANCE: usize = 22;
pub const PANEL_CROSS_PAIR_COUNT_FOR_ABUNDANCE: usize =
    PANEL_SLOT_COUNT_FOR_ABUNDANCE * (PANEL_SLOT_COUNT_FOR_ABUNDANCE - 1) / 2;
pub const DETECT_ANOMALIES_SCHEMA: &str = "astrolabe.detect_anomalies.v1";
pub const ASTRO_ANOMALY_INVALID_KIND: &str = "ASTRO_ANOMALY_INVALID_KIND";
pub const ASTROLABE_REACTIVE_ACK_TAG: &str = "astrolabe_reactive_ack_v1";
pub const ASSAY_ANOMALY_PAYLOAD_SCHEMA: &str = "astrolabe.assay_anomalies.v1";
/// Schema tag of the delta-invalidation rows the shadow importer co-tenants into
/// `ColumnFamily::Assay` (#348). The live-anomaly reader passes this as an
/// accepted foreign schema to [`calyx_assay::AssayStore::load_from_vault_with_cotenants`]
/// so those rows are skipped (counted) instead of decoded as assay rows —
/// while a genuinely corrupt assay shard still fails closed. This const is the
/// single source of truth: the writer (`invalidation_lane.rs`) references it.
pub const ASSAY_DELTA_INVALIDATION_COTENANT_SCHEMA: &str = "astrolabe.delta_invalidation.v1";
pub const REACTIVE_NEW_REGION_SCORE_POLICY: &str = "policy:reactive_new_region_binary_score:v1";

pub const SLOT_COMPLEXITY: SlotId = SlotId::new(2);
pub const SLOT_GRAPH_POSITION: SlotId = SlotId::new(8);
pub const SLOT_CHURN: SlotId = SlotId::new(10);
pub const SLOT_TEST_COVERAGE: SlotId = SlotId::new(14);
pub const SLOT_ROUTE_MATCH: SlotId = SlotId::new(17);
pub const SLOT_DOC_SEMANTIC: SlotId = SlotId::new(19);
pub const SLOT_NAME_SEMANTIC: SlotId = SlotId::new(20);

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ReactiveCaps {
    pub max_triggers: usize,
    pub max_queue_depth: usize,
    pub max_audit_entries: usize,
}

impl Default for ReactiveCaps {
    fn default() -> Self {
        Self {
            max_triggers: ASTROLABE_REACTIVE_REGISTRY_CAP,
            max_queue_depth: ASTROLABE_REACTIVE_QUEUE_CAP,
            max_audit_entries: ASTROLABE_REACTIVE_AUDIT_CAP,
        }
    }
}

pub fn default_reactive_caps() -> ReactiveCaps {
    ReactiveCaps::default()
}

#[derive(Debug, Clone, PartialEq)]
pub struct RecoveredReactiveState {
    pub subscriptions: Vec<RecoveredReactiveSubscription>,
    pub fired_events: Vec<TriggerFired>,
}

impl RecoveredReactiveState {
    pub fn pending_event_count(&self) -> usize {
        self.subscriptions
            .iter()
            .map(|subscription| subscription.pending_events.len())
            .sum()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RecoveredReactiveSubscription {
    pub subscription_id: SubscriptionId,
    pub trigger_id: TriggerId,
    pub condition: TriggerCondition,
    pub owner: Option<String>,
    pub max_drain_buf: usize,
    pub created_ledger_seq: u64,
    pub pending_events: Vec<TriggerFired>,
    pub overflowed: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ReactiveAckReport {
    pub subscription_id: SubscriptionId,
    pub pending_before: usize,
    pub acked_count: usize,
    pub pending_after: usize,
    pub ledger_ref: Option<LedgerRef>,
    pub acknowledged_events: Vec<TriggerFired>,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
struct ReactiveAckEventRef {
    trigger_id: TriggerId,
    cx_id: CxId,
    ledger_seq: u64,
    ledger_hash: String,
}

impl ReactiveAckEventRef {
    fn from_event(event: &TriggerFired) -> Self {
        Self {
            trigger_id: event.trigger_id,
            cx_id: event.cx_id,
            ledger_seq: event.ledger_ref.seq,
            ledger_hash: hex_lower(&event.ledger_ref.hash),
        }
    }
}

#[derive(Deserialize)]
struct ReactiveSubscriptionLedgerPayload {
    tag: String,
    action: String,
    subscription_id: SubscriptionId,
    trigger_id: TriggerId,
    condition: TriggerCondition,
    owner: Option<String>,
    max_drain_buf: usize,
}

#[derive(Deserialize)]
struct ReactiveAckLedgerPayload {
    tag: String,
    action: String,
    subscription_id: SubscriptionId,
    acknowledged: Vec<ReactiveAckEventRef>,
}

pub fn recover_reactive_state<C>(
    vault: &AsterVault<C>,
) -> calyx_core::Result<RecoveredReactiveState>
where
    C: Clock,
{
    let snapshot = vault.snapshot();
    let mut subscriptions = BTreeMap::<SubscriptionId, RecoveredReactiveSubscription>::new();
    let mut acknowledged = BTreeMap::<SubscriptionId, BTreeSet<ReactiveAckEventRef>>::new();

    for (_key, bytes) in vault.scan_cf_at(snapshot, ColumnFamily::Ledger)? {
        let entry = decode_ledger(&bytes)
            .map_err(|error| reactive_recovery_error(format!("decode Ledger CF row: {error}")))?;
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(&entry.payload) else {
            continue;
        };
        match value.get("tag").and_then(serde_json::Value::as_str) {
            Some("reactive_subscription_v1") => {
                let payload: ReactiveSubscriptionLedgerPayload = serde_json::from_value(value)
                    .map_err(|error| {
                        reactive_recovery_error(format!(
                            "decode reactive subscription ledger payload: {error}"
                        ))
                    })?;
                if payload.tag != "reactive_subscription_v1" {
                    continue;
                }

                match payload.action.as_str() {
                    "SUBSCRIPTION_CREATED" => {
                        subscriptions.insert(
                            payload.subscription_id,
                            RecoveredReactiveSubscription {
                                subscription_id: payload.subscription_id,
                                trigger_id: payload.trigger_id,
                                condition: payload.condition,
                                owner: payload.owner,
                                max_drain_buf: payload.max_drain_buf.max(1),
                                created_ledger_seq: entry.seq,
                                pending_events: Vec::new(),
                                overflowed: false,
                            },
                        );
                    }
                    "SUBSCRIPTION_REMOVED" => {
                        subscriptions.remove(&payload.subscription_id);
                    }
                    other => {
                        return Err(reactive_recovery_error(format!(
                            "unknown reactive subscription action {other}"
                        )));
                    }
                }
            }
            Some(ASTROLABE_REACTIVE_ACK_TAG) => {
                let payload: ReactiveAckLedgerPayload =
                    serde_json::from_value(value).map_err(|error| {
                        reactive_recovery_error(format!(
                            "decode reactive ack ledger payload: {error}"
                        ))
                    })?;
                if payload.tag != ASTROLABE_REACTIVE_ACK_TAG {
                    continue;
                }
                if payload.action != "SUBSCRIPTION_EVENTS_ACKED" {
                    return Err(reactive_recovery_error(format!(
                        "unknown reactive ack action {}",
                        payload.action
                    )));
                }
                acknowledged
                    .entry(payload.subscription_id)
                    .or_default()
                    .extend(payload.acknowledged);
            }
            _ => {}
        }
    }

    let mut fired_events = durable_fired_events(vault, snapshot)?;
    fired_events.sort_by(|left, right| {
        left.ledger_ref
            .seq
            .cmp(&right.ledger_ref.seq)
            .then_with(|| left.trigger_id.cmp(&right.trigger_id))
            .then_with(|| left.cx_id.cmp(&right.cx_id))
    });

    for event in &fired_events {
        for subscription in subscriptions.values_mut() {
            if subscription.trigger_id != event.trigger_id {
                continue;
            }
            if event.ledger_ref.seq < subscription.created_ledger_seq {
                continue;
            }
            if acknowledged
                .get(&subscription.subscription_id)
                .is_some_and(|acked| acked.contains(&ReactiveAckEventRef::from_event(event)))
            {
                continue;
            }
            if subscription.pending_events.len() >= subscription.max_drain_buf {
                subscription.pending_events.remove(0);
                subscription.overflowed = true;
            }
            subscription.pending_events.push(event.clone());
        }
    }

    Ok(RecoveredReactiveState {
        subscriptions: subscriptions.into_values().collect(),
        fired_events,
    })
}

pub fn acknowledge_reactive_subscription<C>(
    vault: &AsterVault<C>,
    subscription_id: SubscriptionId,
    actor: impl Into<String>,
) -> calyx_core::Result<ReactiveAckReport>
where
    C: Clock,
{
    let before = recover_reactive_state(vault)?;
    let subscription = before
        .subscriptions
        .iter()
        .find(|subscription| subscription.subscription_id == subscription_id)
        .ok_or_else(|| reactive_subscription_not_found(subscription_id))?;
    let acknowledged_events = subscription.pending_events.clone();
    let pending_before = acknowledged_events.len();
    let ledger_ref = if acknowledged_events.is_empty() {
        None
    } else {
        Some(append_reactive_ack_ledger(
            vault,
            subscription_id,
            &acknowledged_events,
            actor.into(),
        )?)
    };
    if ledger_ref.is_some() {
        vault.flush()?;
    }
    let after = recover_reactive_state(vault)?;
    let pending_after = after
        .subscriptions
        .iter()
        .find(|subscription| subscription.subscription_id == subscription_id)
        .ok_or_else(|| reactive_subscription_not_found(subscription_id))?
        .pending_events
        .len();

    Ok(ReactiveAckReport {
        subscription_id,
        pending_before,
        acked_count: acknowledged_events.len(),
        pending_after,
        ledger_ref,
        acknowledged_events,
    })
}

fn durable_fired_events<C>(
    vault: &AsterVault<C>,
    snapshot: u64,
) -> calyx_core::Result<Vec<TriggerFired>>
where
    C: Clock,
{
    let mut fired = Vec::new();
    for (key, value) in vault.scan_cf_at(snapshot, ColumnFamily::Reactive)? {
        let parts = reactive_row_key(&key)?;
        if parts.kind == ReactiveRowKind::Fired {
            fired.push(decode_trigger_fired(&value)?);
        }
    }
    Ok(fired)
}

fn append_reactive_ack_ledger<C>(
    vault: &AsterVault<C>,
    subscription_id: SubscriptionId,
    events: &[TriggerFired],
    actor: String,
) -> calyx_core::Result<LedgerRef>
where
    C: Clock,
{
    let acknowledged = events
        .iter()
        .map(ReactiveAckEventRef::from_event)
        .collect::<Vec<_>>();
    let payload = serde_json::to_vec(&serde_json::json!({
        "tag": ASTROLABE_REACTIVE_ACK_TAG,
        "action": "SUBSCRIPTION_EVENTS_ACKED",
        "subscription_id": subscription_id.to_string(),
        "acknowledged_count": acknowledged.len(),
        "acknowledged": acknowledged,
    }))
    .map_err(|error| reactive_recovery_error(format!("encode reactive ack payload: {error}")))?;
    RedactionPolicy::check_payload(&payload)?;
    vault.append_ledger_entry(
        EntryKind::Guard,
        SubjectId::Guard(format!("reactive_ack:{subscription_id}").into_bytes()),
        payload,
        ActorId::Service(actor),
    )
}

fn reactive_recovery_error(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: CALYX_REACTIVE_ROW_CORRUPT,
        message: message.into(),
        remediation: "repair or rebuild reactive Ledger/CF rows before recovering subscriptions",
    }
}

fn reactive_subscription_not_found(subscription_id: SubscriptionId) -> CalyxError {
    CalyxError {
        code: CALYX_REACTIVE_SUBSCRIPTION_NOT_FOUND,
        message: format!("reactive subscription {subscription_id} is not registered"),
        remediation: "use a subscription id from recovered reactive state",
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SimilarityFamily {
    Struct,
    Semantic,
    Api,
    Profile,
}

impl SimilarityFamily {
    pub const ALL: [Self; 4] = [Self::Struct, Self::Semantic, Self::Api, Self::Profile];

    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Struct => "SIM_STRUCT",
            Self::Semantic => "SIM_SEMANTIC",
            Self::Api => "SIM_API",
            Self::Profile => "SIM_PROFILE",
        }
    }

    /// Parses a persisted wire name back into its family.
    pub fn from_wire_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|family| family.wire_name() == name)
    }

    pub const fn slot(self) -> SlotId {
        match self {
            Self::Struct => SIM_STRUCT_SLOT,
            Self::Semantic => SIM_SEMANTIC_SLOT,
            Self::Api => SIM_API_SLOT,
            Self::Profile => SIM_PROFILE_SLOT,
        }
    }

    pub const fn graph_edge_kind(self) -> EdgeKind {
        match self {
            Self::Semantic => EdgeKind::SemanticallyRelated,
            Self::Struct | Self::Api | Self::Profile => EdgeKind::SimilarTo,
        }
    }

    pub const fn threshold_field(self) -> &'static str {
        match self {
            Self::Struct => "sim_struct_min_score",
            Self::Semantic => "sim_semantic_min_score",
            Self::Api => "sim_api_min_score",
            Self::Profile => "sim_profile_min_score",
        }
    }

    pub(crate) const fn sort_index(self) -> u8 {
        match self {
            Self::Struct => 0,
            Self::Semantic => 1,
            Self::Api => 2,
            Self::Profile => 3,
        }
    }
}

impl fmt::Display for SimilarityFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.wire_name())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SimilarityThresholds {
    pub sim_struct_min_score: f32,
    pub sim_semantic_min_score: f32,
    pub sim_api_min_score: f32,
    pub sim_profile_min_score: f32,
}

impl SimilarityThresholds {
    pub fn threshold(&self, family: SimilarityFamily) -> f32 {
        match family {
            SimilarityFamily::Struct => self.sim_struct_min_score,
            SimilarityFamily::Semantic => self.sim_semantic_min_score,
            SimilarityFamily::Api => self.sim_api_min_score,
            SimilarityFamily::Profile => self.sim_profile_min_score,
        }
    }
}

impl Default for SimilarityThresholds {
    fn default() -> Self {
        Self {
            sim_struct_min_score: DEFAULT_SIM_STRUCT_MIN_SCORE,
            sim_semantic_min_score: DEFAULT_SIM_SEMANTIC_MIN_SCORE,
            sim_api_min_score: DEFAULT_SIM_API_MIN_SCORE,
            sim_profile_min_score: DEFAULT_SIM_PROFILE_MIN_SCORE,
        }
    }
}

/// How candidate pairs are generated for one similarity family before exact
/// cosine scoring and admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimilarityCandidateStrategy {
    /// Score every pair (subject to `exact_pair_node_limit`). Exhaustive and
    /// exact; O(n²) evaluations.
    ExactPairs,
    /// ANN candidate generation: MinHash/LSH banding for sparse slot vectors
    /// (S1-style trigram / hashed-set shapes) and a seeded, scalar8-quantized
    /// HNSW for dense slot vectors where LSH does not apply. Admission still
    /// rescores every candidate with the exact cosine.
    Ann,
}

/// Named ANN candidate-generation knobs (see the `DEFAULT_SIMILARITY_*`
/// constants for the documented v1 defaults and their derivations).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnCandidateConfig {
    /// MinHash signature length for LSH banding.
    pub minhash_permutations: usize,
    /// LSH band count; rows per band = `minhash_permutations / lsh_bands`.
    pub lsh_bands: usize,
    /// Deterministic namespace seed for LSH hash derivation and HNSW levels.
    pub seed: u64,
    /// Candidate head-room multiplier (HNSW query k and LSH bucket pair span
    /// are `per_node_cap × this`).
    pub candidate_multiplier: usize,
    /// HNSW beam width for candidate queries (raised to k when k exceeds it).
    pub hnsw_ef_search: usize,
}

impl Default for AnnCandidateConfig {
    fn default() -> Self {
        Self {
            minhash_permutations: DEFAULT_SIMILARITY_LSH_PERMUTATIONS,
            lsh_bands: DEFAULT_SIMILARITY_LSH_BANDS,
            seed: DEFAULT_SIMILARITY_ANN_SEED,
            candidate_multiplier: DEFAULT_SIMILARITY_ANN_CANDIDATE_MULTIPLIER,
            hnsw_ef_search: DEFAULT_SIMILARITY_HNSW_EF_SEARCH,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SimilarityPlannerConfig {
    pub thresholds: SimilarityThresholds,
    pub per_node_cap: usize,
    pub worker_count: usize,
    pub disabled_families: BTreeSet<SimilarityFamily>,
    pub exact_pair_node_limit: Option<usize>,
    /// Per-family candidate generation strategy. Families not present use the
    /// scalable default, [`SimilarityCandidateStrategy::Ann`].
    pub candidate_strategies: BTreeMap<SimilarityFamily, SimilarityCandidateStrategy>,
    /// Named ANN candidate-generation knobs.
    pub ann: AnnCandidateConfig,
}

impl SimilarityPlannerConfig {
    pub fn with_disabled_family(mut self, family: SimilarityFamily) -> Self {
        self.disabled_families.insert(family);
        self
    }

    pub fn with_exact_pair_node_limit(mut self, limit: Option<usize>) -> Self {
        self.exact_pair_node_limit = limit;
        self
    }

    pub fn with_candidate_strategy(
        mut self,
        family: SimilarityFamily,
        strategy: SimilarityCandidateStrategy,
    ) -> Self {
        self.candidate_strategies.insert(family, strategy);
        self
    }

    /// Resolves the candidate strategy for one family (default: `Ann`).
    pub fn candidate_strategy(&self, family: SimilarityFamily) -> SimilarityCandidateStrategy {
        self.candidate_strategies
            .get(&family)
            .copied()
            .unwrap_or(SimilarityCandidateStrategy::Ann)
    }
}

impl Default for SimilarityPlannerConfig {
    fn default() -> Self {
        Self {
            thresholds: SimilarityThresholds::default(),
            per_node_cap: DEFAULT_SIMILARITY_PER_NODE_CAP,
            worker_count: DEFAULT_SIMILARITY_WORKERS,
            disabled_families: BTreeSet::new(),
            exact_pair_node_limit: Some(DEFAULT_SIMILARITY_EXACT_PAIR_NODE_LIMIT),
            candidate_strategies: BTreeMap::new(),
            ann: AnnCandidateConfig::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SimilarityNode {
    pub qualified_name: String,
    pub slots: BTreeMap<SlotId, SlotVector>,
}

impl SimilarityNode {
    pub fn new(qualified_name: impl Into<String>) -> Self {
        Self {
            qualified_name: qualified_name.into(),
            slots: BTreeMap::new(),
        }
    }

    pub fn with_slot(mut self, slot: SlotId, vector: SlotVector) -> Self {
        self.slots.insert(slot, vector);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimilarityMetric {
    Cosine,
}

impl SimilarityMetric {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cosine => "cosine",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SimilarityEdge {
    pub family: SimilarityFamily,
    pub source_qn: String,
    pub target_qn: String,
    pub slot: SlotId,
    pub graph_edge_kind: EdgeKind,
    pub metric: SimilarityMetric,
    pub weight: f32,
    pub threshold: f32,
}

impl SimilarityEdge {
    pub fn graph_properties(&self) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("family".to_string(), self.family.wire_name().to_string()),
            ("metric".to_string(), self.metric.as_str().to_string()),
            ("slot_id".to_string(), self.slot.get().to_string()),
            ("score".to_string(), format_score(self.weight)),
            ("threshold".to_string(), format_score(self.threshold)),
        ])
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SimilarityPlan {
    pub edges: Vec<SimilarityEdge>,
    pub skips: SimilaritySkipReport,
    pub workers_requested: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SimilaritySkipReport {
    pub vector_skips: Vec<SimilarityVectorSkip>,
    pub family_opt_outs: Vec<SimilarityFamilyOptOut>,
    pub pair_counts: BTreeMap<SimilarityFamily, SimilarityPairCounts>,
    /// Per-family ANN candidate-generation accounting (present exactly for the
    /// families planned with [`SimilarityCandidateStrategy::Ann`]).
    pub ann_reports: BTreeMap<SimilarityFamily, AnnFamilyReport>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimilarityVectorSkip {
    pub family: SimilarityFamily,
    pub qualified_name: String,
    pub reason: SimilarityVectorSkipReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimilarityVectorSkipReason {
    MissingSlot,
    AbsentSlot,
    UnsupportedSlotShape { shape: &'static str },
    ZeroNorm,
    InvalidSchema { message: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimilarityFamilyOptOut {
    pub family: SimilarityFamily,
    pub slot: SlotId,
    pub reason: SimilarityFamilyOptOutReason,
    pub node_count: usize,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimilarityFamilyOptOutReason {
    DisabledByConfig,
    ExactCandidateLimitExceeded,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SimilarityPairCounts {
    pub candidate_pairs: usize,
    pub incompatible_shape_pairs: usize,
    pub below_threshold_pairs: usize,
    pub cap_dropped_pairs: usize,
    pub admitted_pairs: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SimilarityPlanError {
    EmptyQualifiedName {
        node_index: usize,
    },
    DuplicateQualifiedName {
        qualified_name: String,
    },
    InvalidPerNodeCap {
        value: usize,
    },
    InvalidWorkerCount {
        value: usize,
    },
    InvalidThreshold {
        field: &'static str,
        value: f32,
    },
    /// An ANN configuration knob is out of its valid domain.
    InvalidAnnConfig {
        field: &'static str,
        value: usize,
        requirement: &'static str,
    },
    /// The ANN candidate generator failed; the plan refuses rather than
    /// silently falling back to another candidate source.
    AnnCandidateFailure {
        family: SimilarityFamily,
        message: String,
    },
}

impl fmt::Display for SimilarityPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyQualifiedName { node_index } => {
                write!(
                    f,
                    "similarity node {node_index} has an empty qualified name"
                )
            }
            Self::DuplicateQualifiedName { qualified_name } => {
                write!(
                    f,
                    "duplicate similarity node qualified name {qualified_name:?}"
                )
            }
            Self::InvalidPerNodeCap { value } => {
                write!(
                    f,
                    "similarity per_node_cap must be greater than zero, got {value}"
                )
            }
            Self::InvalidWorkerCount { value } => {
                write!(
                    f,
                    "similarity worker_count must be greater than zero, got {value}"
                )
            }
            Self::InvalidThreshold { field, value } => {
                write!(
                    f,
                    "similarity threshold {field} must be finite and in [0, 1], got {value}"
                )
            }
            Self::InvalidAnnConfig {
                field,
                value,
                requirement,
            } => {
                write!(
                    f,
                    "similarity ann config {field} = {value} is invalid: {requirement}"
                )
            }
            Self::AnnCandidateFailure { family, message } => {
                write!(f, "ann candidate generation failed for {family}: {message}")
            }
        }
    }
}

impl Error for SimilarityPlanError {}

pub fn plan_similarity_edges(
    nodes: &[SimilarityNode],
    config: &SimilarityPlannerConfig,
) -> Result<SimilarityPlan, SimilarityPlanError> {
    validate_plan_request(nodes, config)?;
    let mut edges = Vec::new();
    let mut skips = SimilaritySkipReport::default();

    for family in SimilarityFamily::ALL {
        if config.disabled_families.contains(&family) {
            skips.family_opt_outs.push(SimilarityFamilyOptOut {
                family,
                slot: family.slot(),
                reason: SimilarityFamilyOptOutReason::DisabledByConfig,
                node_count: 0,
                limit: None,
            });
            continue;
        }

        let vectors = collect_family_vectors(nodes, family, &mut skips);
        let strategy = config.candidate_strategy(family);
        let candidate_lists = match strategy {
            SimilarityCandidateStrategy::ExactPairs => {
                if let Some(limit) = config.exact_pair_node_limit
                    && vectors.len() > limit
                {
                    skips.family_opt_outs.push(SimilarityFamilyOptOut {
                        family,
                        slot: family.slot(),
                        reason: SimilarityFamilyOptOutReason::ExactCandidateLimitExceeded,
                        node_count: vectors.len(),
                        limit: Some(limit),
                    });
                    continue;
                }
                None
            }
            SimilarityCandidateStrategy::Ann => {
                let generated = ann::generate_family_candidates(
                    family,
                    &vectors,
                    &config.ann,
                    config.per_node_cap,
                )?;
                skips.ann_reports.insert(family, generated.report);
                Some(generated.per_source)
            }
        };

        let threshold = config.thresholds.threshold(family);
        let (family_edges, pair_counts) = plan_family_edges(
            family,
            threshold,
            config.per_node_cap,
            &vectors,
            config.worker_count,
            candidate_lists.as_deref(),
        );
        skips.pair_counts.insert(family, pair_counts);
        edges.extend(family_edges);
    }

    edges.sort_by(stable_edge_order);
    Ok(SimilarityPlan {
        edges,
        skips,
        workers_requested: config.worker_count,
    })
}

/// Expands changed symbols into a bounded L2 similarity repair region.
///
/// The region includes two hops of currently persisted SIM neighbors plus the
/// best exact candidates for every changed symbol in each enabled family. The
/// candidate budget is the registry-declared ANN headroom
/// (`per_node_cap * candidate_multiplier`), so work is linear in corpus size
/// per changed symbol and never an all-pairs rebuild.
pub fn expand_similarity_dirty_region(
    nodes: &[SimilarityNode],
    changed: &BTreeSet<String>,
    persisted: &[PersistedSimilarityEdgeRow],
    config: &SimilarityPlannerConfig,
) -> BTreeSet<String> {
    let mut region = changed.clone();
    for _ in 0..2 {
        let frontier = region.clone();
        for edge in persisted {
            if frontier.contains(&edge.row.source_qn) || frontier.contains(&edge.row.target_qn) {
                region.insert(edge.row.source_qn.clone());
                region.insert(edge.row.target_qn.clone());
            }
        }
    }
    let candidate_cap = config
        .per_node_cap
        .saturating_mul(config.ann.candidate_multiplier)
        .max(config.per_node_cap);
    for family in SimilarityFamily::ALL {
        if config.disabled_families.contains(&family) {
            continue;
        }
        let mut skips = SimilaritySkipReport::default();
        let vectors = collect_family_vectors(nodes, family, &mut skips);
        for source in vectors
            .iter()
            .filter(|vector| changed.contains(&vector.qualified_name))
        {
            let mut candidates = vectors
                .iter()
                .filter(|target| target.qualified_name != source.qualified_name)
                .filter_map(|target| {
                    cosine(&source.vector, &target.vector)
                        .map(|score| (score, target.qualified_name.as_str()))
                })
                .collect::<Vec<_>>();
            candidates.sort_by(|left, right| {
                right.0.total_cmp(&left.0).then_with(|| left.1.cmp(right.1))
            });
            region.extend(
                candidates
                    .into_iter()
                    .take(candidate_cap)
                    .map(|(_, qualified_name)| qualified_name.to_string()),
            );
        }
    }
    region
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EagerAgreementKind {
    DocDrift,
    NameTruth,
    CloneTaxonomy,
    ComplexityChurn,
    CentralityCoverage,
    RouteMatch,
}

impl EagerAgreementKind {
    pub const ALL: [Self; 6] = [
        Self::DocDrift,
        Self::NameTruth,
        Self::CloneTaxonomy,
        Self::ComplexityChurn,
        Self::CentralityCoverage,
        Self::RouteMatch,
    ];

    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::DocDrift => "DOC_DRIFT",
            Self::NameTruth => "NAME_TRUTH",
            Self::CloneTaxonomy => "CLONE_TAXONOMY",
            Self::ComplexityChurn => "COMPLEXITY_CHURN",
            Self::CentralityCoverage => "CENTRALITY_COVERAGE",
            Self::RouteMatch => "ROUTE_MATCH",
        }
    }

    pub const fn slots(self) -> (SlotId, SlotId) {
        match self {
            Self::DocDrift => (SLOT_DOC_SEMANTIC, SIM_SEMANTIC_SLOT),
            Self::NameTruth => (SLOT_NAME_SEMANTIC, SIM_API_SLOT),
            Self::CloneTaxonomy => (SIM_SEMANTIC_SLOT, SIM_STRUCT_SLOT),
            Self::ComplexityChurn => (SLOT_COMPLEXITY, SLOT_CHURN),
            Self::CentralityCoverage => (SLOT_GRAPH_POSITION, SLOT_TEST_COVERAGE),
            Self::RouteMatch => (SIM_SEMANTIC_SLOT, SLOT_ROUTE_MATCH),
        }
    }

    const fn comparator(self) -> EagerCrossTermComparator {
        match self {
            // S19 and S18 are embeddings in the same frozen 768-dimensional space.
            Self::DocDrift => EagerCrossTermComparator::DirectAgreement,
            // The other designed pairs have distinct frozen source shapes. Their
            // agreement is the cosine between per-symbol similarity neighborhoods.
            Self::NameTruth
            | Self::CloneTaxonomy
            | Self::ComplexityChurn
            | Self::CentralityCoverage
            | Self::RouteMatch => EagerCrossTermComparator::NeighborhoodAgreement,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EagerCrossTermComparator {
    DirectAgreement,
    NeighborhoodAgreement,
}

impl fmt::Display for EagerAgreementKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.wire_name())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct EagerCrossTermPlan {
    pub rows: Vec<EagerCrossTermRow>,
    pub agreement_graph: Vec<AgreementGraphEdge>,
    pub abundance: CrossTermAbundance,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EagerCrossTermRow {
    pub qualified_name: String,
    pub kind: EagerAgreementKind,
    pub left_slot: SlotId,
    pub right_slot: SlotId,
    pub value: CrossTermValue,
    pub persisted: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CrossTermValue {
    Scalar(f32),
    Absent { reason: CrossTermAbsentReason },
}

impl CrossTermValue {
    pub const fn is_absent(&self) -> bool {
        matches!(self, Self::Absent { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrossTermAbsentReason {
    MissingSlot { slot: SlotId },
    SlotAbsent { slot: SlotId },
    UnsupportedSlotShape { slot: SlotId, shape: &'static str },
    ZeroNorm { slot: SlotId },
    InvalidSchema { slot: SlotId, message: String },
    ShapeMismatch,
    InsufficientNeighborhood { comparable_peer_count: usize },
    ZeroSimilarityProfile { slot: SlotId },
}

#[derive(Debug, Clone, PartialEq)]
pub struct AgreementGraphEdge {
    pub kind: EagerAgreementKind,
    pub left_slot: SlotId,
    pub right_slot: SlotId,
    pub mean_agreement: Option<f32>,
    pub scalar_count: usize,
    pub absent_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossTermAbundance {
    pub symbol_count: usize,
    pub panel_slot_count: usize,
    pub possible_pair_count_per_symbol: usize,
    pub raw_yield: usize,
    pub eager_pair_count_per_symbol: usize,
    pub materialized_count: usize,
    pub scalar_count: usize,
    pub absent_count: usize,
    pub lazy_pair_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AnomalyKind {
    DocDrift,
    NameTruth,
    Drift,
    OodCommit,
    PromptInjection,
    BlindSpot,
}

impl AnomalyKind {
    pub const ALL: [Self; 6] = [
        Self::DocDrift,
        Self::NameTruth,
        Self::Drift,
        Self::OodCommit,
        Self::PromptInjection,
        Self::BlindSpot,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DocDrift => "doc_drift",
            Self::NameTruth => "name_truth",
            Self::Drift => "drift",
            Self::OodCommit => "ood_commit",
            Self::PromptInjection => "prompt_injection",
            Self::BlindSpot => "blind_spot",
        }
    }
}

impl std::str::FromStr for AnomalyKind {
    type Err = astrolabe_domain::DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "doc_drift" => Ok(Self::DocDrift),
            "name_truth" => Ok(Self::NameTruth),
            "drift" => Ok(Self::Drift),
            "ood_commit" => Ok(Self::OodCommit),
            "prompt_injection" => Ok(Self::PromptInjection),
            "blind_spot" => Ok(Self::BlindSpot),
            _ => Err(astrolabe_domain::DomainError::new(
                ASTRO_ANOMALY_INVALID_KIND,
                format!("unknown detect_anomalies kind {value}"),
                "use one of doc_drift, name_truth, drift, ood_commit, prompt_injection, or blind_spot",
            )),
        }
    }
}

impl fmt::Display for AnomalyKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnomalySeverity {
    High,
    Medium,
}

impl AnomalySeverity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
        }
    }

    const fn rank(self) -> u8 {
        match self {
            Self::High => 2,
            Self::Medium => 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnomalyCalibration {
    pub kind: AnomalyKind,
    pub medium_min_score_millipoints: u64,
    pub high_min_score_millipoints: u64,
    pub provenance_ref: String,
}

impl AnomalyCalibration {
    pub fn new(
        kind: AnomalyKind,
        medium_min_score_millipoints: u64,
        high_min_score_millipoints: u64,
        provenance_ref: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            medium_min_score_millipoints,
            high_min_score_millipoints,
            provenance_ref: provenance_ref.into(),
        }
    }

    fn severity_for(&self, score_millipoints: u64) -> Option<AnomalySeverity> {
        if score_millipoints >= self.high_min_score_millipoints {
            Some(AnomalySeverity::High)
        } else if score_millipoints >= self.medium_min_score_millipoints {
            Some(AnomalySeverity::Medium)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnomalySubstrateRow {
    pub kind: AnomalyKind,
    pub subject_id: String,
    pub score_millipoints: u64,
    pub message: String,
    pub substrate_provenance_refs: Vec<String>,
    pub lens_evidence: Vec<String>,
}

impl AnomalySubstrateRow {
    pub fn new(
        kind: AnomalyKind,
        subject_id: impl Into<String>,
        score_millipoints: u64,
        message: impl Into<String>,
        substrate_provenance_refs: impl IntoIterator<Item = impl Into<String>>,
        lens_evidence: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            kind,
            subject_id: subject_id.into(),
            score_millipoints,
            message: message.into(),
            substrate_provenance_refs: substrate_provenance_refs
                .into_iter()
                .map(Into::into)
                .collect(),
            lens_evidence: lens_evidence.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnomalyReport {
    pub schema: &'static str,
    pub kind_filter: Option<AnomalyKind>,
    pub findings: Vec<AnomalyFinding>,
    pub skipped: Vec<SkippedAnomalySubstrate>,
    pub freshness: &'static str,
    pub trust: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnomalyFinding {
    pub kind: AnomalyKind,
    pub subject_id: String,
    pub severity: AnomalySeverity,
    pub score_millipoints: u64,
    pub message: String,
    pub substrate_provenance_refs: Vec<String>,
    pub calibration_provenance_ref: String,
    pub lens_evidence: Vec<String>,
    pub freshness: &'static str,
    pub trust: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedAnomalySubstrate {
    pub kind: AnomalyKind,
    pub subject_id: String,
    pub reason: &'static str,
    pub freshness: &'static str,
    pub trust: &'static str,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LiveAnomalyInputs {
    pub snapshot: u64,
    pub substrates: Vec<AnomalySubstrateRow>,
    pub calibrations: Vec<AnomalyCalibration>,
    pub skipped_rows: usize,
    pub xterm_rows_read: usize,
    pub assay_rows_read: usize,
    pub reactive_rows_read: usize,
    /// Count of shared-CF co-tenant rows (e.g. delta-invalidation rows, #348)
    /// skipped during the Assay CF load — a counted, labeled skip, not an error.
    pub assay_cotenant_rows_skipped: usize,
}

impl LiveAnomalyInputs {
    pub fn has_anomaly_inputs(&self) -> bool {
        !self.substrates.is_empty() || !self.calibrations.is_empty() || self.skipped_rows > 0
    }
}

pub fn anomaly_substrate_row_from_eager_cross_term(
    row: &EagerCrossTermRow,
    substrate_provenance_ref: impl Into<String>,
) -> Option<AnomalySubstrateRow> {
    let kind = match row.kind {
        EagerAgreementKind::DocDrift => AnomalyKind::DocDrift,
        EagerAgreementKind::NameTruth => AnomalyKind::NameTruth,
        _ => return None,
    };
    let CrossTermValue::Scalar(value) = &row.value else {
        return None;
    };
    let agreement_millipoints = agreement_to_millipoints(*value);
    Some(AnomalySubstrateRow::new(
        kind,
        row.qualified_name.clone(),
        1_000_u64.saturating_sub(agreement_millipoints),
        format!(
            "{} agreement={} millipoints",
            row.kind.wire_name(),
            agreement_millipoints
        ),
        [substrate_provenance_ref.into()],
        [format!(
            "{}:{}x{}",
            row.kind.wire_name(),
            row.left_slot.get(),
            row.right_slot.get()
        )],
    ))
}

/// The millipoint scale ceiling for a drift anomaly score.
///
/// A drift score is the permille complement of the MMD permutation p-value:
/// `score = 1000 − p_value_permille`. A p-value of 0 (maximally significant
/// drift) maps to 1000; a p-value of 1000 (no drift) maps to 0. This is the same
/// fixed `[0, 1000]` millipoint scale every other anomaly kind reports on — a
/// unit convention, not a severity threshold (severity is measured per corpus by
/// [`drift_anomaly_calibration`]).
pub const DRIFT_SCORE_MAX_MILLIPOINTS: u64 =
    astrolabe_assay::score_calibration::ASSAY_CALIBRATION_MAX_SCORE_MILLIPOINTS;

/// Converts a single measured MMD [`DriftCard`](astrolabe_assay::DriftCard) into
/// a `Drift` [`AnomalySubstrateRow`], preserving the measured statistics as
/// provenance and per-lens evidence.
///
/// The anomaly score is `1000 − p_value_permille`: a smaller permutation p-value
/// (stronger evidence the new sample drifted from the reference) yields a larger
/// score. Severity tiering is left to a measured [`AnomalyCalibration`] (see
/// [`drift_anomaly_calibration`]); this function never decides an alarm on its
/// own, so a non-significant card simply carries a low score and falls below the
/// calibrated threshold rather than being dropped.
pub fn drift_anomaly_substrate_from_card(
    card: &astrolabe_assay::DriftCard,
    substrate_provenance_ref: impl Into<String>,
) -> AnomalySubstrateRow {
    let score = DRIFT_SCORE_MAX_MILLIPOINTS.saturating_sub(card.p_value_permille);
    AnomalySubstrateRow::new(
        AnomalyKind::Drift,
        format!("slot:{}", card.slot),
        score,
        format!(
            "MMD drift slot={} mmd_squared={:.6} p_value_permille={} detected={} (ref {} vs new {})",
            card.slot,
            card.mmd_squared,
            card.p_value_permille,
            card.drift_detected,
            card.n_reference,
            card.n_sample
        ),
        [substrate_provenance_ref.into()],
        [
            format!("MMD:{}", card.slot),
            format!("mmd_squared={:.6}", card.mmd_squared),
            format!("p_value_permille={}", card.p_value_permille),
            format!("bandwidth={:.6}", card.bandwidth),
            format!("trust={:?}", card.trust),
        ],
    )
}

/// Measures a `Drift` [`AnomalyCalibration`] from a batch of drift cards' own
/// score distribution via the assay calibration substrate — the same measured
/// (never fixed) medium/high thresholds the blind-spot sweep uses.
///
/// Returns `None` when the cards' score spread is below the calibration floor or
/// degenerate (e.g. every card reports no drift, so every score is identical):
/// with no calibration the aggregator honestly reports each drift substrate as a
/// missing-calibration skip instead of tiering it on a fabricated threshold.
pub fn drift_anomaly_calibration(
    cards: &[astrolabe_assay::DriftCard],
    config: &astrolabe_assay::score_calibration::CalibrationConfig,
    provenance_label: &str,
) -> Option<AnomalyCalibration> {
    let scores: Vec<u64> = cards
        .iter()
        .map(|card| DRIFT_SCORE_MAX_MILLIPOINTS.saturating_sub(card.p_value_permille))
        .collect();
    let distribution =
        astrolabe_assay::calibrate_score_distribution(provenance_label, &scores, config).ok()?;
    Some(AnomalyCalibration::new(
        AnomalyKind::Drift,
        distribution.medium_min_score_millipoints,
        distribution.high_min_score_millipoints,
        distribution.provenance_ref,
    ))
}

pub fn live_anomaly_inputs_from_vault<C>(
    vault: &AsterVault<C>,
) -> calyx_core::Result<LiveAnomalyInputs>
where
    C: Clock,
{
    let snapshot = vault.snapshot();
    let mut inputs = LiveAnomalyInputs {
        snapshot,
        ..LiveAnomalyInputs::default()
    };

    for (key, value) in vault.scan_cf_at(snapshot, ColumnFamily::XTerm)? {
        inputs.xterm_rows_read += 1;
        let row: XtermRow = serde_json::from_slice(&value).map_err(|error| {
            CalyxError::aster_corrupt_shard(format!("decode live XTerm anomaly row: {error}"))
        })?;
        let expected_key = xterm_key(
            row.key.cx_id,
            row.key.a,
            row.key.b,
            xterm_kind_from_loom(row.key.kind),
        );
        if key != expected_key {
            return Err(CalyxError::aster_corrupt_shard(
                "live XTerm CF key does not match decoded row key",
            ));
        }
        if let Some(substrate) = anomaly_substrate_row_from_live_xterm(&row, &key) {
            inputs.substrates.push(substrate);
        }
    }

    // ColumnFamily::Assay is shared: the shadow importer co-tenants
    // delta-invalidation rows here (#348). Load co-tenant-aware so those rows
    // are skipped (counted) instead of failing the whole anomaly read with
    // CALYX_ASTER_CORRUPT_SHARD; a genuinely corrupt assay shard still errors.
    let accepted_cotenant_schemas: std::collections::BTreeSet<&str> =
        [ASSAY_DELTA_INVALIDATION_COTENANT_SCHEMA]
            .into_iter()
            .collect();
    let (assay, assay_cotenant_skips) =
        AssayStore::load_from_vault_with_cotenants(vault, &accepted_cotenant_schemas)?;
    inputs.assay_cotenant_rows_skipped = assay_cotenant_skips.skipped_rows;
    for row in assay.rows() {
        inputs.assay_rows_read += 1;
        let Some(payload) = row.payload.as_ref() else {
            continue;
        };
        if payload.get("schema").and_then(Value::as_str) != Some(ASSAY_ANOMALY_PAYLOAD_SCHEMA) {
            continue;
        }
        let provenance = format!(
            "AsterVault:ColumnFamily::Assay:provenance:{}:seq:{}",
            row.provenance, row.written_at_seq
        );
        add_anomaly_payload_inputs(payload, &provenance, &mut inputs);
    }

    for (key, value) in vault.scan_cf_at(snapshot, ColumnFamily::Reactive)? {
        let row_key = reactive_row_key(&key)?;
        if row_key.kind != ReactiveRowKind::Fired {
            continue;
        }
        inputs.reactive_rows_read += 1;
        let event = decode_trigger_fired(&value)?;
        if let Some(substrate) = anomaly_substrate_row_from_reactive_event(&event, &key) {
            inputs.substrates.push(substrate);
        }
    }

    inputs.substrates.sort_by(anomaly_substrate_order);
    inputs.calibrations.sort_by(anomaly_calibration_order);
    Ok(inputs)
}

fn anomaly_substrate_row_from_live_xterm(
    row: &XtermRow,
    key: &[u8],
) -> Option<AnomalySubstrateRow> {
    if row.key.kind != LoomCrossTermKind::Agreement {
        return None;
    }
    let kind = anomaly_kind_for_xterm_pair(row.key.a, row.key.b)?;
    let LoomCrossTermValue::Scalar(value) = row.value else {
        return None;
    };
    let agreement_millipoints = agreement_to_millipoints(value);
    let (left, right, label) = match kind {
        AnomalyKind::DocDrift => (
            SLOT_DOC_SEMANTIC,
            SIM_SEMANTIC_SLOT,
            EagerAgreementKind::DocDrift.wire_name(),
        ),
        AnomalyKind::NameTruth => (
            SLOT_NAME_SEMANTIC,
            SIM_API_SLOT,
            EagerAgreementKind::NameTruth.wire_name(),
        ),
        _ => return None,
    };
    Some(AnomalySubstrateRow::new(
        kind,
        format!("cx:{}", row.key.cx_id),
        1_000_u64.saturating_sub(agreement_millipoints),
        format!("live XTerm {label} agreement={agreement_millipoints} millipoints"),
        [format!(
            "AsterVault:ColumnFamily::XTerm:key:{}",
            hex_lower_bytes(key)
        )],
        [
            format!("live_xterm:{label}:S{}xS{}", left.get(), right.get()),
            format!("xterm_tag:{:?}", row.tag),
        ],
    ))
}

fn anomaly_kind_for_xterm_pair(left: SlotId, right: SlotId) -> Option<AnomalyKind> {
    if same_slot_pair(left, right, SLOT_DOC_SEMANTIC, SIM_SEMANTIC_SLOT) {
        Some(AnomalyKind::DocDrift)
    } else if same_slot_pair(left, right, SLOT_NAME_SEMANTIC, SIM_API_SLOT) {
        Some(AnomalyKind::NameTruth)
    } else {
        None
    }
}

fn same_slot_pair(
    left: SlotId,
    right: SlotId,
    expected_left: SlotId,
    expected_right: SlotId,
) -> bool {
    (left == expected_left && right == expected_right)
        || (left == expected_right && right == expected_left)
}

fn anomaly_substrate_row_from_reactive_event(
    event: &TriggerFired,
    key: &[u8],
) -> Option<AnomalySubstrateRow> {
    let TriggerCondition::NewRegion { .. } = event.condition_snapshot else {
        return None;
    };
    Some(AnomalySubstrateRow::new(
        AnomalyKind::OodCommit,
        format!("cx:{}", event.cx_id),
        1_000,
        format!(
            "NewRegion trigger fired for cx {} at ledger seq {}",
            event.cx_id, event.ledger_ref.seq
        ),
        [
            format!(
                "AsterVault:ColumnFamily::Reactive:key:{}",
                hex_lower_bytes(key)
            ),
            format!("ledger:{}", event.ledger_ref.seq),
        ],
        [
            "NewRegion".to_string(),
            REACTIVE_NEW_REGION_SCORE_POLICY.to_string(),
        ],
    ))
}

fn add_anomaly_payload_inputs(
    payload: &Value,
    row_provenance: &str,
    inputs: &mut LiveAnomalyInputs,
) {
    let mut saw_input = false;
    match payload.get("anomaly_substrates").and_then(Value::as_array) {
        Some(values) => {
            saw_input = true;
            for value in values {
                match anomaly_substrate_from_payload_value(value, row_provenance) {
                    Some(substrate) => inputs.substrates.push(substrate),
                    None => inputs.skipped_rows += 1,
                }
            }
        }
        None => {
            if payload.get("anomaly_substrates").is_some() {
                inputs.skipped_rows += 1;
            }
        }
    }
    match payload
        .get("anomaly_calibrations")
        .and_then(Value::as_array)
    {
        Some(values) => {
            saw_input = true;
            for value in values {
                match anomaly_calibration_from_payload_value(value, row_provenance) {
                    Some(calibration) => inputs.calibrations.push(calibration),
                    None => inputs.skipped_rows += 1,
                }
            }
        }
        None => {
            if payload.get("anomaly_calibrations").is_some() {
                inputs.skipped_rows += 1;
            }
        }
    }
    // Real MMD drift cards (#33's `DriftCard`) are the `drift` kind's substrate:
    // convert each card to a `Drift` substrate row and measure the medium/high
    // thresholds from the batch's own score spread — no fixed drift threshold.
    match payload.get("drift_cards").and_then(Value::as_array) {
        Some(values) => {
            saw_input = true;
            let cards: Vec<astrolabe_assay::DriftCard> = values
                .iter()
                .filter_map(|value| {
                    serde_json::from_value::<astrolabe_assay::DriftCard>(value.clone()).ok()
                })
                .collect();
            inputs.skipped_rows += values.len().saturating_sub(cards.len());
            for card in &cards {
                inputs
                    .substrates
                    .push(drift_anomaly_substrate_from_card(card, row_provenance));
            }
            if let Some(calibration) = drift_anomaly_calibration(
                &cards,
                &astrolabe_assay::score_calibration::CalibrationConfig::default(),
                row_provenance,
            ) {
                inputs.calibrations.push(calibration);
            }
        }
        None => {
            if payload.get("drift_cards").is_some() {
                inputs.skipped_rows += 1;
            }
        }
    }
    if !saw_input {
        inputs.skipped_rows += 1;
    }
}

fn anomaly_substrate_from_payload_value(
    value: &Value,
    row_provenance: &str,
) -> Option<AnomalySubstrateRow> {
    let kind = value.get("kind")?.as_str()?.parse::<AnomalyKind>().ok()?;
    let subject_id = value.get("subject_id")?.as_str()?.trim();
    if subject_id.is_empty() {
        return None;
    }
    let score = value.get("score_millipoints")?.as_u64()?;
    if score > 1_000 {
        return None;
    }
    let message = value.get("message")?.as_str()?.trim();
    if message.is_empty() {
        return None;
    }
    let mut provenance = string_array_value(value, "substrate_provenance_refs");
    provenance.push(row_provenance.to_string());
    if provenance.iter().any(|item| item.trim().is_empty()) {
        return None;
    }
    Some(AnomalySubstrateRow::new(
        kind,
        subject_id.to_string(),
        score,
        message.to_string(),
        provenance,
        string_array_value(value, "lens_evidence"),
    ))
}

fn anomaly_calibration_from_payload_value(
    value: &Value,
    row_provenance: &str,
) -> Option<AnomalyCalibration> {
    let kind = value.get("kind")?.as_str()?.parse::<AnomalyKind>().ok()?;
    let medium = value.get("medium_min_score_millipoints")?.as_u64()?;
    let high = value.get("high_min_score_millipoints")?.as_u64()?;
    if medium > high || high > 1_000 {
        return None;
    }
    let provenance = value
        .get("provenance_ref")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(row_provenance);
    Some(AnomalyCalibration::new(kind, medium, high, provenance))
}

fn string_array_value(value: &Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn xterm_kind_from_loom(kind: LoomCrossTermKind) -> XTermKind {
    match kind {
        LoomCrossTermKind::Concat => XTermKind::Concat,
        LoomCrossTermKind::Interaction => XTermKind::Interaction,
        LoomCrossTermKind::Agreement => XTermKind::Agreement,
        LoomCrossTermKind::Delta => XTermKind::Delta,
    }
}

fn anomaly_substrate_order(left: &AnomalySubstrateRow, right: &AnomalySubstrateRow) -> Ordering {
    left.kind
        .cmp(&right.kind)
        .then_with(|| left.subject_id.cmp(&right.subject_id))
        .then_with(|| right.score_millipoints.cmp(&left.score_millipoints))
}

fn anomaly_calibration_order(left: &AnomalyCalibration, right: &AnomalyCalibration) -> Ordering {
    left.kind
        .cmp(&right.kind)
        .then_with(|| left.provenance_ref.cmp(&right.provenance_ref))
}

fn hex_lower_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

pub fn detect_anomalies(
    rows: &[AnomalySubstrateRow],
    calibrations: &[AnomalyCalibration],
    kind_filter: Option<&str>,
    vault_grounded: bool,
) -> astrolabe_domain::Result<AnomalyReport> {
    let parsed_filter = kind_filter.map(str::parse::<AnomalyKind>).transpose()?;
    let calibration_by_kind = calibrations
        .iter()
        .map(|calibration| (calibration.kind, calibration))
        .collect::<BTreeMap<_, _>>();
    let trust = if vault_grounded {
        "verified"
    } else {
        "provisional"
    };
    let mut findings = Vec::new();
    let mut skipped = Vec::new();

    for row in rows {
        if parsed_filter.is_some_and(|filter| row.kind != filter) {
            continue;
        }
        let Some(calibration) = calibration_by_kind.get(&row.kind) else {
            skipped.push(SkippedAnomalySubstrate {
                kind: row.kind,
                subject_id: row.subject_id.clone(),
                reason: "missing_calibration",
                freshness: "not_evaluated",
                trust: "provisional",
            });
            continue;
        };
        let Some(severity) = calibration.severity_for(row.score_millipoints) else {
            continue;
        };
        findings.push(AnomalyFinding {
            kind: row.kind,
            subject_id: row.subject_id.clone(),
            severity,
            score_millipoints: row.score_millipoints,
            message: row.message.clone(),
            substrate_provenance_refs: row.substrate_provenance_refs.clone(),
            calibration_provenance_ref: calibration.provenance_ref.clone(),
            lens_evidence: row.lens_evidence.clone(),
            freshness: "fresh",
            trust,
        });
    }

    findings.sort_by(anomaly_finding_order);
    skipped.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.subject_id.cmp(&right.subject_id))
    });

    Ok(AnomalyReport {
        schema: DETECT_ANOMALIES_SCHEMA,
        kind_filter: parsed_filter,
        findings,
        skipped,
        freshness: "fresh",
        trust,
    })
}

pub fn anomaly_report_artifact_bytes(report: &AnomalyReport) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("schema=");
    out.push_str(report.schema);
    out.push('\n');
    if let Some(kind_filter) = report.kind_filter {
        out.push_str("kind_filter=");
        out.push_str(kind_filter.as_str());
        out.push('\n');
    }
    out.push_str("trust=");
    out.push_str(report.trust);
    out.push('\n');
    for finding in &report.findings {
        out.push_str("finding\t");
        out.push_str(finding.kind.as_str());
        out.push('\t');
        out.push_str(&finding.subject_id);
        out.push('\t');
        out.push_str(finding.severity.as_str());
        out.push('\t');
        out.push_str(&finding.score_millipoints.to_string());
        out.push('\t');
        out.push_str(&finding.substrate_provenance_refs.join(","));
        out.push('\t');
        out.push_str(&finding.calibration_provenance_ref);
        out.push('\t');
        out.push_str(&finding.lens_evidence.join(","));
        out.push('\n');
    }
    for skipped in &report.skipped {
        out.push_str("skipped\t");
        out.push_str(skipped.kind.as_str());
        out.push('\t');
        out.push_str(&skipped.subject_id);
        out.push('\t');
        out.push_str(skipped.reason);
        out.push('\n');
    }
    out.into_bytes()
}

fn agreement_to_millipoints(value: f32) -> u64 {
    (value.clamp(0.0, 1.0) * 1_000.0).round() as u64
}

fn anomaly_finding_order(left: &AnomalyFinding, right: &AnomalyFinding) -> Ordering {
    right
        .severity
        .rank()
        .cmp(&left.severity.rank())
        .then_with(|| right.score_millipoints.cmp(&left.score_millipoints))
        .then_with(|| left.kind.cmp(&right.kind))
        .then_with(|| left.subject_id.cmp(&right.subject_id))
}

// ---------------------------------------------------------------------------
// Blind-spot sweep (P5.6, #36): calibrated per-lens-pair anomaly detection.
//
// A "blind spot" is a symbol that one lens (the *confident* lens) is confident
// belongs to a cluster, while a second lens (the *neighbor* lens) disagrees
// across that same cluster. CBM's original blind-spot sweep hardcoded one
// comparison; this generalizes it to any pair of similarity families, with the
// medium/high severity thresholds MEASURED per repo from the pair's own gap
// distribution (see `astrolabe-assay`'s calibration substrate) rather than
// fixed. The detector emits `AnomalyKind::BlindSpot` substrate rows that flow
// through the existing `detect_anomalies` severity/trust/provenance path.
// ---------------------------------------------------------------------------

/// Error code: a blind-spot lens pair named the same family for both lenses.
pub const ASTRO_BLIND_SPOT_INVALID_PAIR: &str = "ASTRO_BLIND_SPOT_INVALID_PAIR";
/// Error code: a blind-spot sweep config knob was outside its declared bounds.
pub const ASTRO_BLIND_SPOT_INVALID_CONFIG: &str = "ASTRO_BLIND_SPOT_INVALID_CONFIG";

/// Default number of top confident-lens neighbors that define a symbol's cluster.
///
/// v1 prior carried over from the similarity per-node cap's neighborhood scale
/// (`DEFAULT_SIMILARITY_PER_NODE_CAP` = 10): five neighbors is a compact cluster
/// large enough that one alien member cannot dominate the neighbor-lens mean yet
/// small enough to stay a *local* neighborhood. A declared knob (annealable),
/// not a measurement.
pub const DEFAULT_BLIND_SPOT_NEIGHBOR_CAP: usize = 5;
/// Default minimum comparable neighbors below which a symbol is skipped.
///
/// The neighbor-lens mean is only meaningful across at least two neighbors that
/// both carry the neighbor lens; with fewer than two the "mean" is a single
/// point, so the symbol is skipped as an insufficient neighborhood rather than
/// scored on noise. Declared knob (annealable).
pub const DEFAULT_BLIND_SPOT_MIN_NEIGHBORS: usize = 2;

/// A blind-spot lens pair: the *confident* lens whose top-`k` neighborhood
/// defines a symbol's cluster, and the *neighbor* lens whose agreement across
/// that same cluster is measured against it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlindSpotLensPair {
    /// The lens that is confident about the cluster (defines the neighborhood).
    pub confident: SimilarityFamily,
    /// The lens whose agreement across that neighborhood is measured.
    pub neighbor: SimilarityFamily,
}

impl BlindSpotLensPair {
    /// Builds a lens pair from two similarity families.
    pub const fn new(confident: SimilarityFamily, neighbor: SimilarityFamily) -> Self {
        Self {
            confident,
            neighbor,
        }
    }

    /// The stable pair key (`CONFIDENT_WIRExNEIGHBOR_WIRE`) echoed into provenance.
    pub fn pair_key(&self) -> String {
        format!(
            "{}x{}",
            self.confident.wire_name(),
            self.neighbor.wire_name()
        )
    }
}

/// Configuration for [`blind_spot_sweep`], every field a declared knob value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindSpotConfig {
    /// Number of top confident-lens neighbors that define a symbol's cluster.
    pub neighbor_cap: usize,
    /// Minimum comparable neighbors below which a symbol is skipped.
    pub min_neighbors: usize,
    /// Per-pair threshold calibration knobs (measured from the gap distribution).
    pub calibration: astrolabe_assay::score_calibration::CalibrationConfig,
}

impl Default for BlindSpotConfig {
    fn default() -> Self {
        Self {
            neighbor_cap: DEFAULT_BLIND_SPOT_NEIGHBOR_CAP,
            min_neighbors: DEFAULT_BLIND_SPOT_MIN_NEIGHBORS,
            calibration: astrolabe_assay::score_calibration::CalibrationConfig::default(),
        }
    }
}

/// A per-symbol blind-spot score: how far the confident lens's cluster
/// confidence exceeds the neighbor lens's agreement across that same cluster.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindSpotScore {
    /// The scored symbol's qualified name.
    pub qualified_name: String,
    /// Mean confident-lens cosine over the top-`k` neighbors, in millipoints.
    pub confident_sim_millipoints: u64,
    /// Mean neighbor-lens cosine across the comparable neighbors, in millipoints.
    pub neighbor_mean_millipoints: u64,
    /// The gap `max(0, confident_sim - neighbor_mean)`, in millipoints — the
    /// per-symbol score the calibration and severity tiers are applied to.
    pub gap_millipoints: u64,
    /// Number of comparable neighbors the neighbor mean was taken over.
    pub neighbor_count: usize,
}

/// A symbol excluded from scoring, with the labeled reason (no silent drops).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindSpotSkip {
    /// The skipped symbol's qualified name.
    pub qualified_name: String,
    /// Why it could not be scored.
    pub reason: BlindSpotSkipReason,
}

/// Why a symbol was excluded from the blind-spot sweep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlindSpotSkipReason {
    /// The symbol has no usable confident-lens vector.
    MissingConfidentLens,
    /// The symbol has no usable neighbor-lens vector.
    MissingNeighborLens,
    /// The symbol has no confident-lens neighbor to form a cluster.
    NoConfidentNeighbors,
    /// Fewer than `min_neighbors` of the cluster carry the neighbor lens.
    InsufficientNeighborhood {
        /// How many comparable neighbors were found.
        comparable: usize,
    },
}

impl BlindSpotSkipReason {
    /// A stable wire label for the skip reason.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingConfidentLens => "missing_confident_lens",
            Self::MissingNeighborLens => "missing_neighbor_lens",
            Self::NoConfidentNeighbors => "no_confident_neighbors",
            Self::InsufficientNeighborhood { .. } => "insufficient_neighborhood",
        }
    }
}

/// A labeled calibration deficit: the sweep scored symbols but could not derive
/// a per-pair threshold, so no findings can be tiered (degradation is labeled,
/// never silent).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindSpotDeficit {
    /// The assay calibration error code (below-floor or degenerate/zero-spread).
    pub code: &'static str,
    /// The human-readable calibration refusal message.
    pub message: String,
    /// The number of scored symbols that were available to calibrate on.
    pub n_eff: u64,
}

/// The outcome of a blind-spot sweep over one lens pair.
#[derive(Debug, Clone, PartialEq)]
pub struct BlindSpotSweep {
    /// The lens pair swept.
    pub pair: BlindSpotLensPair,
    /// Per-symbol scores, sorted by qualified name.
    pub scores: Vec<BlindSpotScore>,
    /// The `AnomalyKind::BlindSpot` substrate rows (one per scored symbol),
    /// ready for [`detect_anomalies`], sorted by [`anomaly_substrate_order`].
    pub substrates: Vec<AnomalySubstrateRow>,
    /// The measured per-pair calibration, or `None` when calibration was refused
    /// (see `deficit`).
    pub calibration: Option<AnomalyCalibration>,
    /// The raw measured distribution calibration (present iff `calibration` is).
    pub distribution: Option<astrolabe_assay::DistributionCalibration>,
    /// A labeled calibration deficit, present iff `calibration` is `None`.
    pub deficit: Option<BlindSpotDeficit>,
    /// Symbols excluded from scoring, each with a labeled reason.
    pub skipped: Vec<BlindSpotSkip>,
    /// Number of scored symbols (the effective calibration sample size).
    pub n_eff: u64,
}

impl BlindSpotSweep {
    /// The calibration as a single-element slice for [`detect_anomalies`] (empty
    /// when calibration was refused, so every finding is honestly reported as a
    /// missing-calibration skip rather than silently tiered).
    pub fn calibrations(&self) -> Vec<AnomalyCalibration> {
        self.calibration.clone().into_iter().collect()
    }
}

/// Fail-closed error for a blind-spot sweep with a bad pair or config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindSpotError {
    code: &'static str,
    message: String,
    remediation: &'static str,
}

impl BlindSpotError {
    /// The stable machine-readable error code.
    pub fn code(&self) -> &'static str {
        self.code
    }

    /// The human-readable message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The operator remediation string.
    pub fn remediation(&self) -> &'static str {
        self.remediation
    }
}

impl fmt::Display for BlindSpotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} (remediation: {})",
            self.code, self.message, self.remediation
        )
    }
}

impl Error for BlindSpotError {}

/// Runs the blind-spot sweep over `nodes` for one lens pair.
///
/// For each symbol with a confident-lens vector, the sweep takes its top
/// `neighbor_cap` confident-lens neighbors (its cluster), measures the mean
/// confident-lens similarity to them (cluster confidence) and the mean
/// neighbor-lens similarity across those same neighbors (cross-lens agreement),
/// and scores the symbol by the gap `max(0, confidence − agreement)`. The
/// per-pair medium/high severity thresholds are then MEASURED from the corpus's
/// own gap distribution via `astrolabe-assay`. The whole computation is a pure,
/// deterministic function of `nodes` and the config (worker-count invariant).
///
/// # Errors
/// Returns [`ASTRO_BLIND_SPOT_INVALID_PAIR`] when both lenses are the same
/// family, or [`ASTRO_BLIND_SPOT_INVALID_CONFIG`] when a config knob is invalid.
/// Calibration refusal (too few scores, or a zero-spread distribution) is *not*
/// an error: it is a labeled [`BlindSpotDeficit`] on the returned sweep.
pub fn blind_spot_sweep(
    nodes: &[SimilarityNode],
    pair: BlindSpotLensPair,
    config: &BlindSpotConfig,
) -> Result<BlindSpotSweep, BlindSpotError> {
    if pair.confident == pair.neighbor {
        return Err(BlindSpotError {
            code: ASTRO_BLIND_SPOT_INVALID_PAIR,
            message: format!(
                "blind-spot lens pair uses the same family {} for both lenses",
                pair.confident.wire_name()
            ),
            remediation: "choose two distinct similarity families for the confident and neighbor lenses",
        });
    }
    if config.neighbor_cap == 0 {
        return Err(BlindSpotError {
            code: ASTRO_BLIND_SPOT_INVALID_CONFIG,
            message: "blind-spot neighbor_cap must be greater than zero".to_string(),
            remediation: "set neighbor_cap to at least one confident-lens neighbor",
        });
    }
    if config.min_neighbors == 0 || config.min_neighbors > config.neighbor_cap {
        return Err(BlindSpotError {
            code: ASTRO_BLIND_SPOT_INVALID_CONFIG,
            message: format!(
                "blind-spot min_neighbors {} must be in 1..=neighbor_cap ({})",
                config.min_neighbors, config.neighbor_cap
            ),
            remediation: "set min_neighbors between one and neighbor_cap inclusive",
        });
    }
    if let Err(error) = config.calibration.validate() {
        return Err(BlindSpotError {
            code: ASTRO_BLIND_SPOT_INVALID_CONFIG,
            message: format!("blind-spot calibration config invalid: {}", error.message()),
            remediation: "set every calibration knob inside its declared closed interval",
        });
    }

    let pair_key = pair.pair_key();
    let confident_slot = pair.confident.slot();
    let neighbor_slot = pair.neighbor.slot();

    // Collect each lens's usable vectors (sorted by qualified name), keyed for
    // O(log n) neighbor lookups.
    let mut confident_skips = SimilaritySkipReport::default();
    let confident_vectors = collect_family_vectors(nodes, pair.confident, &mut confident_skips);
    let mut neighbor_skips = SimilaritySkipReport::default();
    let neighbor_vectors = collect_family_vectors(nodes, pair.neighbor, &mut neighbor_skips);
    let neighbor_by_name: BTreeMap<&str, &NormalizedVector> = neighbor_vectors
        .iter()
        .map(|indexed| (indexed.qualified_name.as_str(), &indexed.vector))
        .collect();
    let confident_present: BTreeSet<&str> = confident_vectors
        .iter()
        .map(|indexed| indexed.qualified_name.as_str())
        .collect();

    let mut scores = Vec::new();
    let mut substrates = Vec::new();
    let mut skipped = Vec::new();

    // Any symbol with a neighbor-lens vector but no confident-lens vector cannot
    // be scored — record it so no symbol is silently dropped.
    for indexed in &neighbor_vectors {
        if !confident_present.contains(indexed.qualified_name.as_str()) {
            skipped.push(BlindSpotSkip {
                qualified_name: indexed.qualified_name.clone(),
                reason: BlindSpotSkipReason::MissingConfidentLens,
            });
        }
    }

    for source in &confident_vectors {
        // The source's own neighbor-lens vector is required to measure its
        // agreement with the cluster.
        let Some(source_neighbor_vec) = neighbor_by_name.get(source.qualified_name.as_str()) else {
            skipped.push(BlindSpotSkip {
                qualified_name: source.qualified_name.clone(),
                reason: BlindSpotSkipReason::MissingNeighborLens,
            });
            continue;
        };

        // Rank every other confident-lens symbol by confident-lens cosine.
        let mut candidates: Vec<(f32, &str)> = confident_vectors
            .iter()
            .filter(|target| target.qualified_name != source.qualified_name)
            .filter_map(|target| {
                cosine(&source.vector, &target.vector)
                    .map(|score| (score, target.qualified_name.as_str()))
            })
            .collect();
        candidates
            .sort_by(|left, right| right.0.total_cmp(&left.0).then_with(|| left.1.cmp(right.1)));
        candidates.truncate(config.neighbor_cap);

        if candidates.is_empty() {
            skipped.push(BlindSpotSkip {
                qualified_name: source.qualified_name.clone(),
                reason: BlindSpotSkipReason::NoConfidentNeighbors,
            });
            continue;
        }

        let confident_sum: f32 = candidates.iter().map(|(score, _)| score).sum();
        let confident_sim = confident_sum / candidates.len() as f32;

        // Measure the neighbor lens's agreement across the SAME cluster members.
        let mut neighbor_scores: Vec<f32> = Vec::new();
        for (_, neighbor_qn) in &candidates {
            let Some(neighbor_vec) = neighbor_by_name.get(neighbor_qn) else {
                continue;
            };
            if let Some(score) = cosine(source_neighbor_vec, neighbor_vec) {
                neighbor_scores.push(score);
            }
        }
        if neighbor_scores.len() < config.min_neighbors {
            skipped.push(BlindSpotSkip {
                qualified_name: source.qualified_name.clone(),
                reason: BlindSpotSkipReason::InsufficientNeighborhood {
                    comparable: neighbor_scores.len(),
                },
            });
            continue;
        }
        let neighbor_mean = neighbor_scores.iter().sum::<f32>() / neighbor_scores.len() as f32;

        let confident_sim_millipoints = agreement_to_millipoints(confident_sim);
        let neighbor_mean_millipoints = agreement_to_millipoints(neighbor_mean);
        let gap = (confident_sim - neighbor_mean).max(0.0);
        let gap_millipoints = agreement_to_millipoints(gap);

        scores.push(BlindSpotScore {
            qualified_name: source.qualified_name.clone(),
            confident_sim_millipoints,
            neighbor_mean_millipoints,
            gap_millipoints,
            neighbor_count: neighbor_scores.len(),
        });

        substrates.push(AnomalySubstrateRow::new(
            AnomalyKind::BlindSpot,
            source.qualified_name.clone(),
            gap_millipoints,
            format!(
                "blind_spot {pair_key}: {} confidence {confident_sim_millipoints} vs {} agreement {neighbor_mean_millipoints} (gap {gap_millipoints})",
                pair.confident.wire_name(),
                pair.neighbor.wire_name()
            ),
            [
                format!("blind_spot_sweep:{pair_key}"),
                format!("confident_lens:{}:S{}", pair.confident.wire_name(), confident_slot.get()),
                format!("neighbor_lens:{}:S{}", pair.neighbor.wire_name(), neighbor_slot.get()),
            ],
            [
                format!("{}:confidence={confident_sim_millipoints}", pair.confident.wire_name()),
                format!("{}:neighbor_mean={neighbor_mean_millipoints}", pair.neighbor.wire_name()),
                format!("neighbors={}", neighbor_scores.len()),
            ],
        ));
    }

    scores.sort_by(|left, right| left.qualified_name.cmp(&right.qualified_name));
    substrates.sort_by(anomaly_substrate_order);
    skipped.sort_by(|left, right| left.qualified_name.cmp(&right.qualified_name));
    let n_eff = scores.len() as u64;

    // Measure the per-pair severity thresholds from this corpus's own gap
    // distribution. A below-floor or zero-spread distribution refuses with a
    // labeled deficit rather than fabricating a threshold.
    let gaps: Vec<u64> = scores.iter().map(|score| score.gap_millipoints).collect();
    let (calibration, distribution, deficit) = match astrolabe_assay::calibrate_score_distribution(
        &pair_key,
        &gaps,
        &config.calibration,
    ) {
        Ok(distribution) => {
            let calibration = AnomalyCalibration::new(
                AnomalyKind::BlindSpot,
                distribution.medium_min_score_millipoints,
                distribution.high_min_score_millipoints,
                distribution.provenance_ref.clone(),
            );
            (Some(calibration), Some(distribution), None)
        }
        Err(error) => {
            let deficit = BlindSpotDeficit {
                code: error.code(),
                message: error.message().to_string(),
                n_eff,
            };
            (None, None, Some(deficit))
        }
    };

    Ok(BlindSpotSweep {
        pair,
        scores,
        substrates,
        calibration,
        distribution,
        deficit,
        skipped,
        n_eff,
    })
}

/// Runs [`blind_spot_sweep`] and tiers its findings through [`detect_anomalies`].
///
/// `vault_grounded` controls the trust label exactly as in [`detect_anomalies`]:
/// on an ungrounded (cold-start) vault the sweep still runs and produces
/// findings, but every finding carries provisional trust. When calibration was
/// refused, the report carries no findings and lists every scored symbol as a
/// missing-calibration skip — an honest, labeled degradation.
pub fn blind_spot_report(
    nodes: &[SimilarityNode],
    pair: BlindSpotLensPair,
    config: &BlindSpotConfig,
    vault_grounded: bool,
) -> Result<(BlindSpotSweep, AnomalyReport), BlindSpotError> {
    let sweep = blind_spot_sweep(nodes, pair, config)?;
    let calibrations = sweep.calibrations();
    let report = detect_anomalies(
        &sweep.substrates,
        &calibrations,
        Some(AnomalyKind::BlindSpot.as_str()),
        vault_grounded,
    )
    .expect("blind_spot is a valid detect_anomalies kind");
    Ok((sweep, report))
}

/// The default blind-spot lens pair swept by the live `detect_anomalies` path.
///
/// The *confident* lens (structural, S1) defines each symbol's cluster; the
/// *neighbor* lens (semantic, S18) is measured for agreement across that same
/// cluster. A large gap — a symbol that is structurally like its cluster yet
/// semantically alien to it (the classic "looks like it belongs but means
/// something else" blind spot, e.g. a misleading identifier) — is flagged. Both
/// families read slots the shadow importer persists (S1, S18), so the sweep runs
/// against live vault vectors with no extra substrate.
///
/// One pair, not many: [`detect_anomalies`] keys calibration by [`AnomalyKind`],
/// so two blind-spot pairs would each measure a distinct gap distribution yet
/// collide on the single `BlindSpot` calibration slot. A calibrated
/// multi-pair sweep (per-pair calibration keyed by pair) is tracked as follow-up
/// rather than silently letting one pair's threshold tier another pair's gaps.
pub const DEFAULT_BLIND_SPOT_PAIRS: [BlindSpotLensPair; 1] = [BlindSpotLensPair::new(
    SimilarityFamily::Struct,
    SimilarityFamily::Semantic,
)];

/// The deduplicated, ascending set of slots the given blind-spot `pairs` read —
/// the exact slot column families a caller must load to reconstruct the
/// [`SimilarityNode`]s the sweep scores.
pub fn blind_spot_slots(pairs: &[BlindSpotLensPair]) -> Vec<SlotId> {
    let mut slots = pairs
        .iter()
        .flat_map(|pair| [pair.confident.slot(), pair.neighbor.slot()])
        .collect::<Vec<_>>();
    slots.sort_by_key(|slot| slot.get());
    slots.dedup();
    slots
}

/// A per-pair blind-spot calibration deficit surfaced from a live sweep: the
/// pair scored symbols but could not derive a threshold, so its findings are
/// suppressed — labeled here rather than silently dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindSpotPairDeficit {
    /// The lens pair (`CONFIDENTxNEIGHBOR` wire key) that could not calibrate.
    pub pair_key: String,
    /// The assay calibration refusal code (below-floor or degenerate spread).
    pub code: &'static str,
    /// The human-readable calibration refusal message.
    pub message: String,
    /// The number of scored symbols available to calibrate on.
    pub n_eff: u64,
}

/// The merged blind-spot anomaly inputs across every swept lens pair, ready to
/// fold into a [`LiveAnomalyInputs`] before [`detect_anomalies`].
#[derive(Debug, Clone, Default, PartialEq)]
pub struct BlindSpotAnomalyInputs {
    /// `AnomalyKind::BlindSpot` substrate rows across all pairs, sorted by
    /// [`anomaly_substrate_order`].
    pub substrates: Vec<AnomalySubstrateRow>,
    /// The measured per-pair calibrations (one per pair that calibrated).
    pub calibrations: Vec<AnomalyCalibration>,
    /// Labeled per-pair calibration deficits (pairs that scored but could not
    /// tier), so no degradation is silent.
    pub deficits: Vec<BlindSpotPairDeficit>,
    /// Total symbols scored across all pairs.
    pub scored_symbols: usize,
    /// Total symbols excluded (with labeled reasons) across all pairs.
    pub skipped_symbols: usize,
}

impl BlindSpotAnomalyInputs {
    /// Whether the sweep produced any substrate row, calibration, or deficit —
    /// i.e. whether blind-spot detection contributed anything to fold in.
    pub fn is_empty(&self) -> bool {
        self.substrates.is_empty() && self.calibrations.is_empty() && self.deficits.is_empty()
    }
}

/// Runs [`blind_spot_sweep`] for each lens pair over `nodes` and merges every
/// pair's `BlindSpot` substrate rows and measured calibration into one
/// [`BlindSpotAnomalyInputs`].
///
/// Pure and worker-count invariant: a deterministic function of `nodes`, `pairs`,
/// and `config`. A pair whose calibration is refused contributes its substrate
/// rows (so the scored symbols remain visible) and a labeled
/// [`BlindSpotPairDeficit`]; with no calibration for that pair `detect_anomalies`
/// honestly reports each of its symbols as a missing-calibration skip rather than
/// tiering them on a fabricated threshold.
///
/// # Errors
/// Propagates a [`BlindSpotError`] from the first invalid pair or config knob
/// (same-family pair, or an out-of-bounds config value) — a fail-closed refusal,
/// never a partial merge over an invalid request.
pub fn blind_spot_anomaly_inputs(
    nodes: &[SimilarityNode],
    pairs: &[BlindSpotLensPair],
    config: &BlindSpotConfig,
) -> Result<BlindSpotAnomalyInputs, BlindSpotError> {
    let mut out = BlindSpotAnomalyInputs::default();
    for &pair in pairs {
        let sweep = blind_spot_sweep(nodes, pair, config)?;
        out.scored_symbols += sweep.scores.len();
        out.skipped_symbols += sweep.skipped.len();
        out.substrates.extend(sweep.substrates);
        out.calibrations.extend(sweep.calibration);
        if let Some(deficit) = sweep.deficit {
            out.deficits.push(BlindSpotPairDeficit {
                pair_key: pair.pair_key(),
                code: deficit.code,
                message: deficit.message,
                n_eff: deficit.n_eff,
            });
        }
    }
    out.substrates.sort_by(anomaly_substrate_order);
    out.calibrations.sort_by(anomaly_calibration_order);
    out.deficits
        .sort_by(|left, right| left.pair_key.cmp(&right.pair_key));
    Ok(out)
}

pub fn plan_eager_cross_terms(nodes: &[SimilarityNode]) -> EagerCrossTermPlan {
    plan_eager_cross_terms_selected(nodes, None)
}

/// Plans eager agreements only for the named dirty symbols while retaining the
/// full corpus as neighborhood context.
pub fn plan_eager_cross_terms_for_symbols(
    nodes: &[SimilarityNode],
    qualified_names: &BTreeSet<String>,
) -> EagerCrossTermPlan {
    plan_eager_cross_terms_selected(nodes, Some(qualified_names))
}

fn plan_eager_cross_terms_selected(
    nodes: &[SimilarityNode],
    qualified_names: Option<&BTreeSet<String>>,
) -> EagerCrossTermPlan {
    let selected_indices = nodes
        .iter()
        .enumerate()
        .filter(|(_, node)| {
            qualified_names.is_none_or(|names| names.contains(&node.qualified_name))
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    let mut rows = Vec::with_capacity(selected_indices.len() * EagerAgreementKind::ALL.len());
    // Each kind's value pass is independent of the others, so computing the six
    // kinds on scoped threads cannot change any value (#23); rows are still
    // appended in `EagerAgreementKind::ALL` order and sorted below, keeping the
    // plan byte-identical to the sequential shape.
    let selected = &selected_indices;
    let values_by_kind = std::thread::scope(|scope| {
        EagerAgreementKind::ALL
            .map(|kind| scope.spawn(move || cross_term_values(nodes, kind, selected)))
            .map(|handle| handle.join().expect("cross-term kind worker panicked"))
    });
    for (kind, values) in EagerAgreementKind::ALL.into_iter().zip(values_by_kind) {
        let (left_slot, right_slot) = kind.slots();
        for (&node_index, value) in selected_indices.iter().zip(values) {
            let node = &nodes[node_index];
            rows.push(EagerCrossTermRow {
                qualified_name: node.qualified_name.clone(),
                kind,
                left_slot,
                right_slot,
                value,
                persisted: true,
            });
        }
    }
    rows.sort_by(cross_term_row_order);

    let agreement_graph = agreement_graph_from_cross_terms(&rows);
    let scalar_count = rows
        .iter()
        .filter(|row| matches!(row.value, CrossTermValue::Scalar(_)))
        .count();
    let absent_count = rows.len() - scalar_count;
    let symbol_count = selected_indices.len();
    EagerCrossTermPlan {
        rows,
        agreement_graph,
        abundance: CrossTermAbundance {
            symbol_count,
            panel_slot_count: PANEL_SLOT_COUNT_FOR_ABUNDANCE,
            possible_pair_count_per_symbol: PANEL_CROSS_PAIR_COUNT_FOR_ABUNDANCE,
            raw_yield: symbol_count
                * (PANEL_SLOT_COUNT_FOR_ABUNDANCE + PANEL_CROSS_PAIR_COUNT_FOR_ABUNDANCE + 1),
            eager_pair_count_per_symbol: EagerAgreementKind::ALL.len(),
            materialized_count: symbol_count * EagerAgreementKind::ALL.len(),
            scalar_count,
            absent_count,
            lazy_pair_count: symbol_count
                * (PANEL_CROSS_PAIR_COUNT_FOR_ABUNDANCE - EagerAgreementKind::ALL.len()),
        },
    }
}

fn cross_term_values(
    nodes: &[SimilarityNode],
    kind: EagerAgreementKind,
    selected_indices: &[usize],
) -> Vec<CrossTermValue> {
    let (left_slot, right_slot) = kind.slots();
    let operands = nodes
        .iter()
        .map(|node| {
            (
                cross_term_operand(node, left_slot),
                cross_term_operand(node, right_slot),
            )
        })
        .collect::<Vec<_>>();

    match kind.comparator() {
        EagerCrossTermComparator::DirectAgreement => selected_indices
            .iter()
            .map(|&index| direct_cross_term_value(&operands[index].0, &operands[index].1))
            .collect(),
        EagerCrossTermComparator::NeighborhoodAgreement => selected_indices
            .iter()
            .map(|&node_index| {
                neighborhood_cross_term_value(node_index, left_slot, right_slot, &operands)
            })
            .collect(),
    }
}

fn direct_cross_term_value(
    left: &Result<NormalizedVector, CrossTermAbsentReason>,
    right: &Result<NormalizedVector, CrossTermAbsentReason>,
) -> CrossTermValue {
    let left = match left {
        Ok(value) => value,
        Err(reason) => {
            return CrossTermValue::Absent {
                reason: reason.clone(),
            };
        }
    };
    let right = match right {
        Ok(value) => value,
        Err(reason) => {
            return CrossTermValue::Absent {
                reason: reason.clone(),
            };
        }
    };
    match cosine(left, right) {
        Some(value) => CrossTermValue::Scalar(value),
        None => CrossTermValue::Absent {
            reason: CrossTermAbsentReason::ShapeMismatch,
        },
    }
}

fn neighborhood_cross_term_value(
    node_index: usize,
    left_slot: SlotId,
    right_slot: SlotId,
    operands: &[CrossTermOperandPair],
) -> CrossTermValue {
    let (left, right) = &operands[node_index];
    let left = match left {
        Ok(value) => value,
        Err(reason) => {
            return CrossTermValue::Absent {
                reason: reason.clone(),
            };
        }
    };
    let right = match right {
        Ok(value) => value,
        Err(reason) => {
            return CrossTermValue::Absent {
                reason: reason.clone(),
            };
        }
    };

    let mut left_scores = Vec::with_capacity(operands.len().saturating_sub(1));
    let mut right_scores = Vec::with_capacity(operands.len().saturating_sub(1));
    for (peer_index, (peer_left, peer_right)) in operands.iter().enumerate() {
        if peer_index == node_index {
            continue;
        }
        let (Ok(peer_left), Ok(peer_right)) = (peer_left, peer_right) else {
            continue;
        };
        let (Some(left_score), Some(right_score)) =
            (cosine(left, peer_left), cosine(right, peer_right))
        else {
            continue;
        };
        left_scores.push(left_score);
        right_scores.push(right_score);
    }

    if left_scores.len() < 2 {
        return CrossTermValue::Absent {
            reason: CrossTermAbsentReason::InsufficientNeighborhood {
                comparable_peer_count: left_scores.len(),
            },
        };
    }

    let left_norm = dense_norm(&left_scores);
    if zero_norm(left_norm) {
        return CrossTermValue::Absent {
            reason: CrossTermAbsentReason::ZeroSimilarityProfile { slot: left_slot },
        };
    }
    let right_norm = dense_norm(&right_scores);
    if zero_norm(right_norm) {
        return CrossTermValue::Absent {
            reason: CrossTermAbsentReason::ZeroSimilarityProfile { slot: right_slot },
        };
    }

    let profile_dim = left_scores.len() as u32;
    let left_profile = NormalizedVector::Dense {
        dim: profile_dim,
        data: left_scores,
        norm: left_norm,
    };
    let right_profile = NormalizedVector::Dense {
        dim: profile_dim,
        data: right_scores,
        norm: right_norm,
    };
    direct_cross_term_value(&Ok(left_profile), &Ok(right_profile))
}

/// Computes the direct agreement between two slots of one symbol with the
/// eager planner's absent-aware semantics (used by the lazy on-demand path).
pub(crate) fn lazy_direct_agreement(
    node: &SimilarityNode,
    left_slot: SlotId,
    right_slot: SlotId,
) -> CrossTermValue {
    direct_cross_term_value(
        &cross_term_operand(node, left_slot),
        &cross_term_operand(node, right_slot),
    )
}

fn cross_term_operand(
    node: &SimilarityNode,
    slot: SlotId,
) -> Result<NormalizedVector, CrossTermAbsentReason> {
    let Some(vector) = node.slots.get(&slot) else {
        return Err(CrossTermAbsentReason::MissingSlot { slot });
    };
    match normalized_vector(vector) {
        Ok(vector) => Ok(vector),
        Err(reason) => Err(cross_term_absent_reason(slot, reason)),
    }
}

fn cross_term_absent_reason(
    slot: SlotId,
    reason: SimilarityVectorSkipReason,
) -> CrossTermAbsentReason {
    match reason {
        SimilarityVectorSkipReason::MissingSlot => CrossTermAbsentReason::MissingSlot { slot },
        SimilarityVectorSkipReason::AbsentSlot => CrossTermAbsentReason::SlotAbsent { slot },
        SimilarityVectorSkipReason::UnsupportedSlotShape { shape } => {
            CrossTermAbsentReason::UnsupportedSlotShape { slot, shape }
        }
        SimilarityVectorSkipReason::ZeroNorm => CrossTermAbsentReason::ZeroNorm { slot },
        SimilarityVectorSkipReason::InvalidSchema { message } => {
            CrossTermAbsentReason::InvalidSchema { slot, message }
        }
    }
}

fn cross_term_row_order(left: &EagerCrossTermRow, right: &EagerCrossTermRow) -> Ordering {
    left.qualified_name
        .cmp(&right.qualified_name)
        .then_with(|| left.kind.cmp(&right.kind))
}

fn agreement_graph_from_cross_terms(rows: &[EagerCrossTermRow]) -> Vec<AgreementGraphEdge> {
    let mut sums = BTreeMap::<EagerAgreementKind, (f32, usize, usize)>::new();
    for row in rows {
        let entry = sums.entry(row.kind).or_default();
        match row.value {
            CrossTermValue::Scalar(value) => {
                entry.0 += value;
                entry.1 += 1;
            }
            CrossTermValue::Absent { .. } => entry.2 += 1,
        }
    }

    EagerAgreementKind::ALL
        .into_iter()
        .map(|kind| {
            let (sum, scalar_count, absent_count) = sums.get(&kind).copied().unwrap_or_default();
            let (left_slot, right_slot) = kind.slots();
            AgreementGraphEdge {
                kind,
                left_slot,
                right_slot,
                mean_agreement: (scalar_count > 0).then_some(sum / scalar_count as f32),
                scalar_count,
                absent_count,
            }
        })
        .collect()
}

fn validate_plan_request(
    nodes: &[SimilarityNode],
    config: &SimilarityPlannerConfig,
) -> Result<(), SimilarityPlanError> {
    if config.per_node_cap == 0 {
        return Err(SimilarityPlanError::InvalidPerNodeCap {
            value: config.per_node_cap,
        });
    }
    if config.worker_count == 0 {
        return Err(SimilarityPlanError::InvalidWorkerCount {
            value: config.worker_count,
        });
    }
    validate_ann_config(&config.ann)?;
    for family in SimilarityFamily::ALL {
        let value = config.thresholds.threshold(family);
        if !value.is_finite() || !(0.0..=1.0).contains(&value) {
            return Err(SimilarityPlanError::InvalidThreshold {
                field: family.threshold_field(),
                value,
            });
        }
    }

    let mut seen = BTreeSet::new();
    for (node_index, node) in nodes.iter().enumerate() {
        if node.qualified_name.trim().is_empty() {
            return Err(SimilarityPlanError::EmptyQualifiedName { node_index });
        }
        if !seen.insert(node.qualified_name.clone()) {
            return Err(SimilarityPlanError::DuplicateQualifiedName {
                qualified_name: node.qualified_name.clone(),
            });
        }
    }
    Ok(())
}

fn validate_ann_config(ann: &AnnCandidateConfig) -> Result<(), SimilarityPlanError> {
    if ann.minhash_permutations == 0 {
        return Err(SimilarityPlanError::InvalidAnnConfig {
            field: "minhash_permutations",
            value: ann.minhash_permutations,
            requirement: "must be greater than zero",
        });
    }
    if ann.lsh_bands == 0 {
        return Err(SimilarityPlanError::InvalidAnnConfig {
            field: "lsh_bands",
            value: ann.lsh_bands,
            requirement: "must be greater than zero",
        });
    }
    if ann.lsh_bands > ann.minhash_permutations
        || !ann.minhash_permutations.is_multiple_of(ann.lsh_bands)
    {
        return Err(SimilarityPlanError::InvalidAnnConfig {
            field: "lsh_bands",
            value: ann.lsh_bands,
            requirement: "must divide minhash_permutations exactly",
        });
    }
    if ann.candidate_multiplier == 0 {
        return Err(SimilarityPlanError::InvalidAnnConfig {
            field: "candidate_multiplier",
            value: ann.candidate_multiplier,
            requirement: "must be greater than zero",
        });
    }
    if ann.hnsw_ef_search == 0 {
        return Err(SimilarityPlanError::InvalidAnnConfig {
            field: "hnsw_ef_search",
            value: ann.hnsw_ef_search,
            requirement: "must be greater than zero",
        });
    }
    Ok(())
}

fn collect_family_vectors(
    nodes: &[SimilarityNode],
    family: SimilarityFamily,
    skips: &mut SimilaritySkipReport,
) -> Vec<IndexedVector> {
    let mut out = Vec::new();
    let slot = family.slot();
    for node in nodes {
        let Some(vector) = node.slots.get(&slot) else {
            skips.vector_skips.push(SimilarityVectorSkip {
                family,
                qualified_name: node.qualified_name.clone(),
                reason: SimilarityVectorSkipReason::MissingSlot,
            });
            continue;
        };
        match normalized_vector(vector) {
            Ok(vector) => out.push(IndexedVector {
                qualified_name: node.qualified_name.clone(),
                vector,
            }),
            Err(reason) => skips.vector_skips.push(SimilarityVectorSkip {
                family,
                qualified_name: node.qualified_name.clone(),
                reason,
            }),
        }
    }
    out.sort_by(|left, right| left.qualified_name.cmp(&right.qualified_name));
    out
}

/// Normalizes one slot vector for similarity/cross-term scoring, or attributes an
/// explicit [`SimilarityVectorSkipReason`] when it cannot participate.
///
/// The result is deliberately `Result<NormalizedVector, _>` with no intermediate
/// "absent but not an error" state: every non-degenerate Dense/Sparse vector
/// yields `Ok`, and every other case (invalid schema, zero norm, multi/absent
/// shape) is a counted `Err`. Keeping this total — rather than an
/// `Ok(Option<..>)` whose `None` arm one caller silently dropped and another
/// mapped to a reason — means no caller can lose a vector without recording why.
fn normalized_vector(vector: &SlotVector) -> Result<NormalizedVector, SimilarityVectorSkipReason> {
    if let Err(error) = vector.validate_schema() {
        return Err(SimilarityVectorSkipReason::InvalidSchema {
            message: error.to_string(),
        });
    }

    match vector {
        SlotVector::Dense { dim, data } => {
            let norm = dense_norm(data);
            if zero_norm(norm) {
                return Err(SimilarityVectorSkipReason::ZeroNorm);
            }
            Ok(NormalizedVector::Dense {
                dim: *dim,
                data: data.clone(),
                norm,
            })
        }
        SlotVector::Sparse { dim, entries } => {
            let norm = sparse_norm(entries);
            if zero_norm(norm) {
                return Err(SimilarityVectorSkipReason::ZeroNorm);
            }
            let mut entries = entries.clone();
            entries.sort_by_key(|entry| entry.idx);
            Ok(NormalizedVector::Sparse {
                dim: *dim,
                entries,
                norm,
            })
        }
        SlotVector::Multi { .. } => {
            Err(SimilarityVectorSkipReason::UnsupportedSlotShape { shape: "multi" })
        }
        SlotVector::Absent { .. } => Err(SimilarityVectorSkipReason::AbsentSlot),
    }
}

/// Bounded per-source admission for one similarity family.
///
/// `vectors` is sorted ascending by qualified name (see
/// [`collect_family_vectors`]), so for the pair `(i, j)` with `i < j` the source
/// is always the lexicographically smaller qualified name. Each source therefore
/// keeps at most `per_node_cap` outgoing edges, chosen as the highest-weight
/// targets (ties broken by the smaller target qualified name — the historical
/// admission-order tie-break).
///
/// Rather than buffer every above-threshold candidate and sort the whole set —
/// O(admissible pairs) ≈ O(n²) [`SimilarityEdge`]s, each owning two cloned
/// `String`s, which is infeasible on near-duplicate corpora — this streams a
/// per-source top-`k` [`BinaryHeap`]. Peak intermediate memory is bounded to
/// `per_node_cap` [`AdmissionCandidate`]s at a time plus the O(n · per_node_cap)
/// admitted output, independent of how many pairs clear the threshold. The
/// admitted set and every [`SimilarityPairCounts`] field are byte-for-byte
/// identical to the former sort-then-cap implementation. (Reducing the O(n²)
/// cosine *evaluation* count — as opposed to candidate memory — is the ANN/LSH
/// candidate-generation work tracked in #20.)
fn plan_family_edges(
    family: SimilarityFamily,
    threshold: f32,
    per_node_cap: usize,
    vectors: &[IndexedVector],
    worker_count: usize,
    candidates: Option<&[Vec<usize>]>,
) -> (Vec<SimilarityEdge>, SimilarityPairCounts) {
    // Each source `i` computes its own bounded top-`per_node_cap` outgoing edges
    // against the strictly-greater targets `j > i`, and every
    // [`SimilarityPairCounts`] field is a plain sum over sources. The source
    // ranges therefore partition into independent shards whose per-shard outputs
    // reduce order-invariantly (edge concatenation followed by the total
    // [`stable_edge_order`] sort in the caller; count fields by integer addition).
    // Sharding by source range across `worker_count` workers is the parallel path
    // the planner config exposes; a non-invariant reduction (double-counting at a
    // shard boundary, or splitting one source's per-cap admission across shards)
    // would change the plan, which the worker-invariance test asserts against.
    let source_count = vectors.len();
    let worker_count = worker_count.min(source_count).max(1);
    if worker_count == 1 {
        return plan_source_range(
            family,
            threshold,
            per_node_cap,
            vectors,
            0..source_count,
            candidates,
        );
    }

    let chunk_size = source_count.div_ceil(worker_count);
    let shards = thread::scope(|scope| {
        let mut handles = Vec::new();
        let mut start = 0;
        while start < source_count {
            let end = (start + chunk_size).min(source_count);
            let range = start..end;
            handles.push(scope.spawn(move || {
                plan_source_range(family, threshold, per_node_cap, vectors, range, candidates)
            }));
            start = end;
        }
        handles
            .into_iter()
            .map(|handle| handle.join().expect("similarity planner worker panicked"))
            .collect::<Vec<_>>()
    });

    let mut admitted = Vec::new();
    let mut counts = SimilarityPairCounts::default();
    for (shard_edges, shard_counts) in shards {
        admitted.extend(shard_edges);
        counts.candidate_pairs += shard_counts.candidate_pairs;
        counts.incompatible_shape_pairs += shard_counts.incompatible_shape_pairs;
        counts.below_threshold_pairs += shard_counts.below_threshold_pairs;
        counts.cap_dropped_pairs += shard_counts.cap_dropped_pairs;
    }
    counts.admitted_pairs = admitted.len();
    (admitted, counts)
}

/// Plans the bounded per-source admissions for one shard of source indices.
///
/// `sources` is a contiguous slice of source positions into `vectors`; each
/// source still scans every strictly-greater target `j > i`, so a shard reads all
/// of `vectors` but only emits edges (and counts pairs) for the sources it owns.
/// This keeps each source's per-`per_node_cap` admission wholly inside one shard,
/// which is what makes the sharded plan byte-identical to the serial plan.
fn plan_source_range(
    family: SimilarityFamily,
    threshold: f32,
    per_node_cap: usize,
    vectors: &[IndexedVector],
    sources: Range<usize>,
    candidates: Option<&[Vec<usize>]>,
) -> (Vec<SimilarityEdge>, SimilarityPairCounts) {
    let mut counts = SimilarityPairCounts::default();
    let mut admitted = Vec::new();

    for i in sources {
        let left = &vectors[i];
        // Top-`per_node_cap` targets for this source. The heap's max (`peek`) is
        // the *least preferred* admitted edge (lowest weight, ties broken by the
        // larger target qualified name) — exactly the edge a better candidate
        // evicts. `per_node_cap` is validated as non-zero upstream, so once the
        // heap is full `peek` is always `Some`.
        let mut top: BinaryHeap<AdmissionCandidate> = BinaryHeap::with_capacity(per_node_cap);
        match candidates {
            // Exhaustive scoring: every strictly-greater target is a candidate.
            None => {
                for right in vectors.iter().skip(i + 1) {
                    consider_target(left, right, threshold, per_node_cap, &mut top, &mut counts);
                }
            }
            // ANN scoring: only the generated per-source candidate targets are
            // scored; every list entry is a strictly-greater index (the lower
            // qualified name owns the pair), so ownership and admission are the
            // same discipline as the exhaustive path.
            Some(lists) => {
                for &right_index in &lists[i] {
                    debug_assert!(
                        right_index > i,
                        "candidate lists must hold targets > source"
                    );
                    consider_target(
                        left,
                        &vectors[right_index],
                        threshold,
                        per_node_cap,
                        &mut top,
                        &mut counts,
                    );
                }
            }
        }

        for candidate in top.into_vec() {
            admitted.push(SimilarityEdge {
                family,
                source_qn: left.qualified_name.clone(),
                target_qn: candidate.target_qn,
                slot: family.slot(),
                graph_edge_kind: family.graph_edge_kind(),
                metric: SimilarityMetric::Cosine,
                weight: candidate.weight,
                threshold,
            });
        }
    }

    counts.admitted_pairs = admitted.len();
    (admitted, counts)
}

/// Scores one candidate pair with the exact cosine and applies threshold and
/// streaming per-source cap admission. This is the single admission path for
/// both the exhaustive and the ANN candidate sources; every constant it applies
/// (`threshold`, `per_node_cap`) arrives from [`SimilarityPlannerConfig`].
fn consider_target(
    left: &IndexedVector,
    right: &IndexedVector,
    threshold: f32,
    per_node_cap: usize,
    top: &mut BinaryHeap<AdmissionCandidate>,
    counts: &mut SimilarityPairCounts,
) {
    counts.candidate_pairs += 1;
    let Some(score) = cosine(&left.vector, &right.vector) else {
        counts.incompatible_shape_pairs += 1;
        return;
    };
    if score < threshold {
        counts.below_threshold_pairs += 1;
        return;
    }
    let candidate = AdmissionCandidate {
        weight: score,
        target_qn: right.qualified_name.clone(),
    };
    if top.len() < per_node_cap {
        top.push(candidate);
    } else {
        // The heap is full: exactly one candidate is dropped this step,
        // either the incoming one or the evicted worst admitted edge.
        let outranks_worst = top
            .peek()
            .is_some_and(|worst| candidate.cmp(worst) == Ordering::Less);
        if outranks_worst {
            top.pop();
            top.push(candidate);
        }
        counts.cap_dropped_pairs += 1;
    }
}

/// Heap element for the streaming per-source top-`k` admission in
/// [`plan_family_edges`].
///
/// [`Ord`] is defined so a max-heap surfaces the *least preferred* admitted edge:
/// lowest weight first, and among equal weights the larger target qualified name.
/// That is the reverse of the admission preference (highest weight, then smaller
/// target qualified name), so `candidate.cmp(worst) == Ordering::Less` means the
/// candidate outranks the current worst and should evict it — reproducing the
/// former "sort by (weight desc, target_qn asc), keep the first `per_node_cap`"
/// selection without materializing the full candidate list.
#[derive(Debug)]
struct AdmissionCandidate {
    weight: f32,
    target_qn: String,
}

impl PartialEq for AdmissionCandidate {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for AdmissionCandidate {}

impl PartialOrd for AdmissionCandidate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AdmissionCandidate {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .weight
            .total_cmp(&self.weight)
            .then_with(|| self.target_qn.cmp(&other.target_qn))
    }
}

fn stable_edge_order(left: &SimilarityEdge, right: &SimilarityEdge) -> Ordering {
    left.family
        .sort_index()
        .cmp(&right.family.sort_index())
        .then_with(|| left.source_qn.cmp(&right.source_qn))
        .then_with(|| left.target_qn.cmp(&right.target_qn))
}

#[derive(Debug, Clone)]
pub(crate) struct IndexedVector {
    pub(crate) qualified_name: String,
    pub(crate) vector: NormalizedVector,
}

#[derive(Debug, Clone)]
pub(crate) enum NormalizedVector {
    Dense {
        dim: u32,
        data: Vec<f32>,
        norm: f32,
    },
    Sparse {
        dim: u32,
        entries: Vec<SparseEntry>,
        norm: f32,
    },
}

type CrossTermOperandPair = (
    Result<NormalizedVector, CrossTermAbsentReason>,
    Result<NormalizedVector, CrossTermAbsentReason>,
);

fn cosine(left: &NormalizedVector, right: &NormalizedVector) -> Option<f32> {
    let score = match (left, right) {
        (
            NormalizedVector::Dense {
                dim: left_dim,
                data: left_data,
                norm: left_norm,
            },
            NormalizedVector::Dense {
                dim: right_dim,
                data: right_data,
                norm: right_norm,
            },
        ) if left_dim == right_dim => {
            dense_dot(left_data, right_data) / (left_norm.sqrt() * right_norm.sqrt())
        }
        (
            NormalizedVector::Sparse {
                dim: left_dim,
                entries: left_entries,
                norm: left_norm,
            },
            NormalizedVector::Sparse {
                dim: right_dim,
                entries: right_entries,
                norm: right_norm,
            },
        ) if left_dim == right_dim => {
            sparse_dot(left_entries, right_entries) / (left_norm.sqrt() * right_norm.sqrt())
        }
        _ => return None,
    };
    Some(score.clamp(-1.0, 1.0))
}

fn dense_dot(left: &[f32], right: &[f32]) -> f32 {
    left.iter()
        .zip(right.iter())
        .map(|(left, right)| left * right)
        .sum()
}

fn dense_norm(values: &[f32]) -> f32 {
    values.iter().map(|value| value * value).sum()
}

fn sparse_dot(left: &[SparseEntry], right: &[SparseEntry]) -> f32 {
    let mut i = 0usize;
    let mut j = 0usize;
    let mut dot = 0.0f32;
    while i < left.len() && j < right.len() {
        match left[i].idx.cmp(&right[j].idx) {
            Ordering::Less => i += 1,
            Ordering::Equal => {
                dot += left[i].val * right[j].val;
                i += 1;
                j += 1;
            }
            Ordering::Greater => j += 1,
        }
    }
    dot
}

fn sparse_norm(entries: &[SparseEntry]) -> f32 {
    entries.iter().map(|entry| entry.val * entry.val).sum()
}

fn zero_norm(squared_norm: f32) -> bool {
    // `squared_norm` is the sum of squares produced by `dense_norm`/`sparse_norm`
    // (the *squared* L2 norm), so the guard must compare on the squared scale.
    // A vector is degenerate only when that squared norm underflows out of the
    // normal IEEE-754 binary32 range — below `DEFAULT_MIN_VECTOR_SQUARED_NORM`
    // (`f32::MIN_POSITIVE`) the norm is subnormal or exactly zero and cannot be
    // meaningfully normalized in `cosine`. The previous `<= f32::EPSILON` test
    // compared this squared value against unit-scale float spacing (~1.19e-7),
    // wrongly classifying small-but-real vectors (linear norm ≲ 3.45e-4) as zero.
    squared_norm < DEFAULT_MIN_VECTOR_SQUARED_NORM
}

fn format_score(value: f32) -> String {
    format!("{value:.9}")
}

/// Canonical byte dump of a similarity edge set for determinism probes and
/// ledger content hashing.
///
/// Edges are emitted in [`stable_edge_order`] as one tab-separated line each:
/// family wire name, source and target qualified names, slot, graph edge kind,
/// metric, and the exact IEEE-754 bit patterns (hex) of weight and threshold —
/// so two dumps are byte-identical exactly when the planned edge sets are
/// bit-identical.
pub fn similarity_edge_dump_bytes(edges: &[SimilarityEdge]) -> Vec<u8> {
    let mut sorted: Vec<&SimilarityEdge> = edges.iter().collect();
    sorted.sort_by(|left, right| stable_edge_order(left, right));
    let mut out = String::new();
    for edge in sorted {
        out.push_str(edge.family.wire_name());
        out.push('\t');
        out.push_str(&edge.source_qn);
        out.push('\t');
        out.push_str(&edge.target_qn);
        out.push('\t');
        out.push_str(&edge.slot.get().to_string());
        out.push('\t');
        out.push_str(edge.graph_edge_kind.as_str());
        out.push('\t');
        out.push_str(edge.metric.as_str());
        out.push('\t');
        out.push_str(&format!("{:08x}", edge.weight.to_bits()));
        out.push('\t');
        out.push_str(&format!("{:08x}", edge.threshold.to_bits()));
        out.push('\n');
    }
    out.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

    use astrolabe_domain::SymbolLabel;
    use astrolabe_panel::{FixtureSlotRuntime, PanelDriver, PanelInput};
    use calyx_assay::{
        AssayCacheKey, AssayStore, AssaySubject, EstimatorKind, MiEstimate, TrustTag,
    };
    use calyx_aster::cf::{ColumnFamily, XTermKind, xterm_key};
    use calyx_aster::vault::{AsterVault, VaultOptions};
    use calyx_core::{
        AnchorKind, CxId, FixedClock, LedgerRef, Result as CalyxResult, SparseEntry, SystemClock,
        VaultId, VaultStore,
    };
    use calyx_ledger::{ActorId, EntryKind, SubjectId};
    use calyx_loom::agreement_graph::XtermRow;
    use calyx_loom::{
        CALYX_REACTIVE_QUEUE_FULL, CrossTermKey, CrossTermKind as LoomCrossTermKind,
        CrossTermValue as LoomCrossTermValue, SignalProvenanceTag,
    };
    use serde_json::json;

    static NEXT_REACTIVE_DIR: AtomicU64 = AtomicU64::new(0);
    const REACTIVE_TEST_SALT: &[u8] = b"astrolabe-weave-reactive-fsv";

    // #60 reactive churn coverage, decomposed into two per-test-budget-compliant
    // slices (#280: no single test may exceed 60s). The prior monolithic 10K soak
    // (`durable_reactive_churn_soak_10k_...`, ~227s, deleted in PR #300) is
    // restored here as (1) a bounded-N slice that FSV-reads the persisted reactive
    // CF to prove exact accounting under sustained overflow, and (2) an RSS-bound
    // slice run at the largest event count that stays under the 60s budget.
    //
    // The reactive queue is a bounded evict-oldest ring; the churn property does
    // not depend on the ring being at its production 4096 cap — driving well past
    // a small cap exercises the overflow / evict-oldest path far more times per
    // durable evaluation (the per-event vault write dominates wall clock), so the
    // slices use a small declared cap to soak the ring cheaply. These are declared,
    // annealable knobs, not measurements.
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    const REACTIVE_CHURN_SLICE_QUEUE_CAP: usize = 8;
    /// Bounded-N exact-accounting slice size: enough evaluations to evict the ring
    /// hundreds of times while staying well under the per-test budget.
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    const REACTIVE_CHURN_ACCOUNTING_EVENTS: u64 = 256;
    /// RSS-bound slice size: the largest event count that keeps the durable soak
    /// under the #280 60s per-test budget on the native Windows host (measured;
    /// see the #302 evidence comment).
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    const REACTIVE_CHURN_RSS_EVENTS: u64 = 2_000;
    /// Resident-set growth bound for the churn soak. The ring never exceeds its
    /// cap, so sustained churn far beyond the cap must not grow resident memory.
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    const MAX_REACTIVE_SOAK_RSS_DELTA_BYTES: u64 = 512 * 1024 * 1024;

    #[test]
    fn identifies_calyx_parent() {
        assert_eq!(parent_system(), astrolabe_domain::ParentSystem::Calyx);
    }

    #[test]
    fn family_metadata_uses_calyx_panel_slots_and_named_thresholds() {
        assert_eq!(SimilarityFamily::Struct.wire_name(), "SIM_STRUCT");
        assert_eq!(SimilarityFamily::Semantic.wire_name(), "SIM_SEMANTIC");
        assert_eq!(SimilarityFamily::Api.wire_name(), "SIM_API");
        assert_eq!(SimilarityFamily::Profile.wire_name(), "SIM_PROFILE");

        assert_eq!(SimilarityFamily::Struct.slot(), SlotId::new(1));
        assert_eq!(SimilarityFamily::Api.slot(), SlotId::new(4));
        assert_eq!(SimilarityFamily::Semantic.slot(), SlotId::new(18));
        assert_eq!(SimilarityFamily::Profile.slot(), SlotId::new(21));

        let thresholds = SimilarityThresholds::default();
        assert_eq!(
            thresholds.threshold(SimilarityFamily::Struct),
            DEFAULT_SIM_STRUCT_MIN_SCORE
        );
        assert_eq!(
            thresholds.threshold(SimilarityFamily::Semantic),
            DEFAULT_SIM_SEMANTIC_MIN_SCORE
        );
        assert_eq!(
            thresholds.threshold(SimilarityFamily::Api),
            DEFAULT_SIM_API_MIN_SCORE
        );
        assert_eq!(
            thresholds.threshold(SimilarityFamily::Profile),
            DEFAULT_SIM_PROFILE_MIN_SCORE
        );
    }

    #[test]
    fn reactive_caps_match_calyx_a26_defaults() {
        assert_eq!(
            default_reactive_caps(),
            ReactiveCaps {
                max_triggers: 1024,
                max_queue_depth: 4096,
                max_audit_entries: 65536,
            }
        );
        assert_eq!(
            default_reactive_caps(),
            ReactiveCaps {
                max_triggers: CALYX_REACTIVE_REGISTRY_CAP,
                max_queue_depth: CALYX_REACTIVE_QUEUE_CAP,
                max_audit_entries: CALYX_REACTIVE_AUDIT_CAP,
            }
        );
    }

    #[test]
    fn detect_anomalies_aggregates_remaining_kinds_with_calibrated_severity() {
        let report = detect_anomalies(&anomaly_fixture_rows(), &anomaly_calibrations(), None, true)
            .expect("detect anomalies");

        assert_eq!(report.schema, DETECT_ANOMALIES_SCHEMA);
        assert_eq!(report.kind_filter, None);
        assert_eq!(report.trust, "verified");
        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| (
                    finding.kind.as_str(),
                    finding.subject_id.as_str(),
                    finding.severity.as_str(),
                    finding.score_millipoints
                ))
                .collect::<Vec<_>>(),
            vec![
                ("ood_commit", "commit:alien-1", "high", 950),
                ("doc_drift", "demo.docs.lie", "high", 900),
                ("drift", "slot:S18:week-2026-27", "high", 850),
                ("name_truth", "demo.name.misleads", "medium", 600),
            ]
        );
        assert!(
            report
                .findings
                .iter()
                .all(|finding| !finding.subject_id.contains("clean"))
        );
        let doc = report
            .findings
            .iter()
            .find(|finding| finding.kind == AnomalyKind::DocDrift)
            .expect("doc drift finding");
        assert_eq!(doc.substrate_provenance_refs, vec!["xterm:doc-bad"]);
        assert_eq!(doc.calibration_provenance_ref, "calibration:doc-drift:v1");
        assert!(doc.lens_evidence[0].contains("DOC_DRIFT"));
    }

    #[test]
    fn detect_anomalies_kind_filter_and_invalid_kind_refusal() {
        let report = detect_anomalies(
            &anomaly_fixture_rows(),
            &anomaly_calibrations(),
            Some("doc_drift"),
            true,
        )
        .expect("doc drift filter");

        assert_eq!(report.kind_filter, Some(AnomalyKind::DocDrift));
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].kind, AnomalyKind::DocDrift);
        assert_eq!(
            "prompt_injection".parse::<AnomalyKind>().unwrap(),
            AnomalyKind::PromptInjection
        );

        let err = detect_anomalies(
            &anomaly_fixture_rows(),
            &anomaly_calibrations(),
            Some("supply_chain"),
            true,
        )
        .expect_err("invalid kind refused");
        assert_eq!(err.code(), ASTRO_ANOMALY_INVALID_KIND);
        assert!(err.message().contains("supply_chain"));
    }

    #[test]
    fn detect_anomalies_cold_start_marks_all_findings_provisional() {
        let report = detect_anomalies(
            &anomaly_fixture_rows(),
            &anomaly_calibrations(),
            None,
            false,
        )
        .expect("cold start anomalies");

        assert_eq!(report.trust, "provisional");
        assert!(
            report
                .findings
                .iter()
                .all(|finding| finding.trust == "provisional")
        );
    }

    #[test]
    fn detect_anomalies_reports_missing_calibration_without_silent_fallback() {
        let rows = vec![AnomalySubstrateRow::new(
            AnomalyKind::Drift,
            "slot:S18:week-2026-27",
            850,
            "MMD drift alarm",
            ["assay:mmd:slot18:week27"],
            ["MMD:S18"],
        )];

        let report = detect_anomalies(&rows, &[], None, true).expect("missing calibration report");

        assert!(report.findings.is_empty());
        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].kind, AnomalyKind::Drift);
        assert_eq!(report.skipped[0].reason, "missing_calibration");
    }

    #[test]
    fn detect_anomalies_aggregation_is_deterministic_and_artifact_reads_back() {
        let rows = anomaly_fixture_rows();
        let mut reversed = rows.clone();
        reversed.reverse();
        let first =
            detect_anomalies(&rows, &anomaly_calibrations(), None, true).expect("first report");
        let second = detect_anomalies(&reversed, &anomaly_calibrations(), None, true)
            .expect("second report");
        assert_eq!(first, second);

        let bytes = anomaly_report_artifact_bytes(&first);
        let path = std::env::temp_dir().join(format!(
            "astrolabe-anomalies-{}-{}.txt",
            std::process::id(),
            first.findings.len()
        ));
        std::fs::write(&path, &bytes).expect("write anomaly artifact");
        let readback = std::fs::read(&path).expect("read anomaly artifact");
        std::fs::remove_file(&path).ok();

        assert_eq!(readback, bytes);
        let text = String::from_utf8(readback).expect("utf8 anomaly artifact");
        assert!(text.contains("finding\tdoc_drift\tdemo.docs.lie\thigh\t900\txterm:doc-bad"));
        assert!(text.contains("calibration:doc-drift:v1"));
        assert!(text.contains("finding\tood_commit\tcommit:alien-1\thigh\t950"));
    }

    #[test]
    fn live_anomaly_inputs_read_xterm_assay_and_reactive_cf_rows() {
        let (dir, vault) = reactive_vault("live-anomalies");
        let doc_cx = cx(101);
        let xterm_row = XtermRow {
            key: CrossTermKey {
                cx_id: doc_cx,
                a: SLOT_DOC_SEMANTIC,
                b: SIM_SEMANTIC_SLOT,
                kind: LoomCrossTermKind::Agreement,
            },
            value: LoomCrossTermValue::Scalar(0.10),
            tag: SignalProvenanceTag::Derived,
        };
        let xterm_key = xterm_key(
            doc_cx,
            SLOT_DOC_SEMANTIC,
            SIM_SEMANTIC_SLOT,
            XTermKind::Agreement,
        );
        let xterm_value = serde_json::to_vec(&xterm_row).expect("encode xterm row");
        vault
            .write_cf_batch([(ColumnFamily::XTerm, xterm_key.clone(), xterm_value.clone())])
            .expect("write xterm row");

        let mut assay = AssayStore::default();
        assay.put_with_payload(
            AssayCacheKey::scoped(
                7,
                "week-2026-27",
                reactive_vault_id(),
                AnchorKind::Reward,
            ),
            AssaySubject::Panel,
            MiEstimate::point(1.0, 16, EstimatorKind::PanelSufficiency, TrustTag::Trusted),
            "assay:mmd:slot18:week27",
            vault.snapshot(),
            json!({
                "schema": ASSAY_ANOMALY_PAYLOAD_SCHEMA,
                "anomaly_calibrations": [
                    {"kind":"doc_drift","medium_min_score_millipoints":500,"high_min_score_millipoints":800,"provenance_ref":"calibration:doc-drift:v1"},
                    {"kind":"drift","medium_min_score_millipoints":500,"high_min_score_millipoints":800,"provenance_ref":"calibration:drift:v1"},
                    {"kind":"ood_commit","medium_min_score_millipoints":500,"high_min_score_millipoints":800,"provenance_ref":"calibration:ood-commit:v1"}
                ],
                "anomaly_substrates": [
                    {
                        "kind":"drift",
                        "subject_id":"slot:S18:week-2026-27",
                        "score_millipoints":850,
                        "message":"MMD drift alarm for semantic slot",
                        "substrate_provenance_refs":["assay:mmd:slot18:week27"],
                        "lens_evidence":["MMD:S18","guard_reject_rate:S18"]
                    }
                ]
            }),
        );
        assay.persist_to_vault(&vault).expect("persist assay row");

        let mut engine = ReactiveEngine::new(Arc::new(FixedClock::new(1_786_320_000)));
        engine
            .register(TriggerCondition::NewRegion { tau_override: None }, None)
            .expect("register new-region trigger");
        engine
            .evaluate_post_ingest_durable(
                &vault,
                cx(202),
                lref(42),
                &ScriptedReactiveSignals::with_novelty_and_drift(NoveltyVerdict::NewRegion, 0.0),
            )
            .expect("persist new-region fired row");
        vault.flush().expect("flush live anomaly CF rows");

        let reopened = open_reactive_vault(&dir);
        let raw_xterm = reopened
            .read_cf_at(reopened.snapshot(), ColumnFamily::XTerm, &xterm_key)
            .expect("read xterm CF")
            .expect("xterm row present");
        assert_eq!(raw_xterm, xterm_value);

        let inputs =
            live_anomaly_inputs_from_vault(&reopened).expect("read live anomaly input rows");
        assert!(inputs.has_anomaly_inputs());
        assert_eq!(inputs.xterm_rows_read, 1);
        assert_eq!(inputs.assay_rows_read, 1);
        assert_eq!(inputs.reactive_rows_read, 1);
        assert_eq!(inputs.skipped_rows, 0);

        let report = detect_anomalies(&inputs.substrates, &inputs.calibrations, None, true)
            .expect("detect live anomalies");
        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| (
                    finding.kind.as_str().to_string(),
                    finding.subject_id.clone()
                ))
                .collect::<Vec<_>>(),
            vec![
                ("ood_commit".to_string(), format!("cx:{}", cx(202))),
                ("doc_drift".to_string(), format!("cx:{doc_cx}")),
                ("drift".to_string(), "slot:S18:week-2026-27".to_string()),
            ]
        );
        let doc = report
            .findings
            .iter()
            .find(|finding| finding.kind == AnomalyKind::DocDrift)
            .expect("doc drift finding");
        assert!(doc.substrate_provenance_refs.contains(&format!(
            "AsterVault:ColumnFamily::XTerm:key:{}",
            hex_lower_bytes(&xterm_key)
        )));
        let drift = report
            .findings
            .iter()
            .find(|finding| finding.kind == AnomalyKind::Drift)
            .expect("drift finding");
        assert!(
            drift
                .substrate_provenance_refs
                .iter()
                .any(|source| source.contains("ColumnFamily::Assay"))
        );
        let ood = report
            .findings
            .iter()
            .find(|finding| finding.kind == AnomalyKind::OodCommit)
            .expect("ood finding");
        assert!(
            ood.lens_evidence
                .contains(&REACTIVE_NEW_REGION_SCORE_POLICY.to_string())
        );
        fs::remove_dir_all(dir).ok();
    }

    // #348: a real vault whose ColumnFamily::Assay holds BOTH a genuine assay
    // anomaly row and a co-tenant delta-invalidation row. Before the fix the
    // whole live-anomaly read failed with CALYX_ASTER_CORRUPT_SHARD
    // ("decode assay row: missing field cache_key"); after the fix the anomaly
    // surface is served, the invalidation row is skipped+counted, and a
    // genuinely corrupt assay row still fails closed.
    #[test]
    fn live_anomaly_read_tolerates_delta_invalidation_cotenant_rows() {
        let (dir, vault) = reactive_vault("live-anomalies-cotenant");

        // Genuine assay anomaly row (the same shape the shadow importer writes).
        let mut assay = AssayStore::default();
        assay.put_with_payload(
            AssayCacheKey::scoped(7, "week-2026-27", reactive_vault_id(), AnchorKind::Reward),
            AssaySubject::Panel,
            MiEstimate::point(1.0, 16, EstimatorKind::PanelSufficiency, TrustTag::Trusted),
            "assay:mmd:slot18:week27",
            vault.snapshot(),
            json!({
                "schema": ASSAY_ANOMALY_PAYLOAD_SCHEMA,
                "anomaly_calibrations": [
                    {"kind":"drift","medium_min_score_millipoints":500,"high_min_score_millipoints":800,"provenance_ref":"calibration:drift:v1"}
                ],
                "anomaly_substrates": [
                    {"kind":"drift","subject_id":"slot:S18:week-2026-27","score_millipoints":850,"message":"MMD drift alarm","substrate_provenance_refs":["assay:mmd:slot18:week27"],"lens_evidence":["MMD:S18"]}
                ]
            }),
        );
        assay
            .persist_to_vault(&vault)
            .expect("persist genuine assay row");

        // Plant a delta-invalidation co-tenant row exactly as invalidation_lane.rs
        // writes it: keyed outside the assay keyspace, valued with the
        // delta-invalidation schema tag and no cache_key field.
        let mut inval_key = b"astrolabe:shadow:invalidation:v1\0".to_vec();
        inval_key.extend_from_slice(b"astrolabe\0assay\0");
        inval_key.extend_from_slice(b"crate::foo::bar");
        let inval_value = serde_json::to_vec(&json!({
            "schema": ASSAY_DELTA_INVALIDATION_COTENANT_SCHEMA,
            "kind": "assay_stratum_dirty",
            "project": "astrolabe",
            "qualified_name": "crate::foo::bar",
            "dirty": true,
            "dirty_since_seq": vault.snapshot(),
        }))
        .expect("encode invalidation row");
        vault
            .write_cf_batch([(ColumnFamily::Assay, inval_key.clone(), inval_value.clone())])
            .expect("write invalidation co-tenant row");
        vault.flush().expect("flush shared assay CF");

        let reopened = open_reactive_vault(&dir);

        // The invalidation row is independently readable back (semantics intact).
        let raw_inval = reopened
            .read_cf_at(reopened.snapshot(), ColumnFamily::Assay, &inval_key)
            .expect("read invalidation CF row")
            .expect("invalidation row present");
        assert_eq!(raw_inval, inval_value);

        // The anomaly reader now serves rather than erroring on CORRUPT_SHARD.
        let inputs = live_anomaly_inputs_from_vault(&reopened)
            .expect("live anomaly read must not fail closed");
        assert_eq!(inputs.assay_rows_read, 1, "genuine assay row still read");
        assert_eq!(
            inputs.assay_cotenant_rows_skipped, 1,
            "invalidation co-tenant row skipped and counted"
        );
        let report = detect_anomalies(&inputs.substrates, &inputs.calibrations, None, true)
            .expect("detect anomalies");
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.kind == AnomalyKind::Drift),
            "genuine drift finding still surfaced despite co-tenant row"
        );

        // Negative case: a genuinely corrupt assay row (no schema tag) in the
        // same CF still fails the read closed.
        reopened
            .write_cf_batch([(
                ColumnFamily::Assay,
                b"corrupt-assay-key".to_vec(),
                vec![0xde, 0xad, 0xbe, 0xef],
            )])
            .expect("write corrupt assay row");
        reopened.flush().expect("flush corrupt row");
        let error = live_anomaly_inputs_from_vault(&reopened)
            .expect_err("corrupt assay row must fail closed");
        assert_eq!(error.code, "CALYX_ASTER_CORRUPT_SHARD");

        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn durable_event_recurs_persists_audit_and_fired_rows_once_after_reopen() {
        let (dir, vault) = reactive_vault("event-recurs");
        let series = cx(9);
        let trigger_cx = cx(7);
        let mut engine = ReactiveEngine::new(Arc::new(FixedClock::new(1_786_320_000)));
        let trigger = engine
            .register(
                TriggerCondition::EventRecurs {
                    series,
                    min_occurrences: 3,
                },
                Some("astrolabe-weave".to_string()),
            )
            .expect("register recurring trigger");
        let signals = ScriptedReactiveSignals::grounded();

        assert_eq!(
            engine
                .evaluate_post_ingest_durable(&vault, trigger_cx, lref(1), &signals)
                .expect("first eval"),
            0
        );
        assert_eq!(
            engine
                .evaluate_post_ingest_durable(&vault, trigger_cx, lref(2), &signals)
                .expect("second eval"),
            0
        );
        assert_eq!(
            engine
                .evaluate_post_ingest_durable(&vault, trigger_cx, lref(3), &signals)
                .expect("third eval"),
            1
        );
        assert_eq!(
            engine
                .evaluate_post_ingest_durable(&vault, trigger_cx, lref(4), &signals)
                .expect("fourth eval"),
            0
        );

        let audit = audit_entries(&vault, trigger);
        assert_eq!(
            audit.iter().map(|entry| entry.matched).collect::<Vec<_>>(),
            vec![false, false, true, false]
        );
        let fired = fired_events(&vault);
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].trigger_id, trigger);
        assert_eq!(fired[0].ledger_ref.seq, 3);
        assert_eq!(engine.queue().len(), 1);

        vault.flush().expect("flush durable reactive rows");
        drop(vault);
        let reopened = open_reactive_vault(&dir);
        assert_eq!(
            audit_entries(&reopened, trigger)
                .iter()
                .map(|entry| entry.matched)
                .collect::<Vec<_>>(),
            vec![false, false, true, false]
        );
        let reopened_fired = fired_events(&reopened);
        assert_eq!(reopened_fired.len(), 1);
        assert_eq!(reopened_fired[0].ledger_ref.seq, 3);
        drop(reopened);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn durable_restart_recovery_reads_pending_subscription_and_fired_state() {
        let (dir, vault) = reactive_vault("restart-recovery");
        let mut engine = ReactiveEngine::new(Arc::new(FixedClock::new(1_786_320_250)));
        let subscription = engine
            .subscribe_durable(
                &vault,
                TriggerCondition::NewRegion { tau_override: None },
                Some("astrolabe-weave-restart".to_string()),
            )
            .expect("durable subscription");
        let trigger = engine
            .subscriptions()
            .get(subscription)
            .expect("subscription handle")
            .trigger_id;
        let trigger_cx = cx(44);
        let ingest_ref = vault
            .append_ledger_entry(
                EntryKind::Ingest,
                SubjectId::Cx(trigger_cx),
                b"reactive restart recovery ingest".to_vec(),
                ActorId::Service("astrolabe-weave-test".to_string()),
            )
            .expect("append real ingest ledger entry");
        let signals =
            ScriptedReactiveSignals::with_novelty_and_drift(NoveltyVerdict::NewRegion, 0.0);

        assert_eq!(
            engine
                .evaluate_post_ingest_durable(&vault, trigger_cx, ingest_ref.clone(), &signals)
                .expect("evaluate durable subscription"),
            1
        );
        assert_eq!(engine.queue().len(), 1);
        assert_eq!(
            engine
                .subscriptions()
                .get(subscription)
                .expect("subscription handle")
                .pending_len(),
            1
        );

        vault.flush().expect("flush durable reactive restart state");
        drop(engine);
        drop(vault);
        let reopened = open_reactive_vault(&dir);
        let recovered = recover_reactive_state(&reopened).expect("recover durable reactive state");

        assert_eq!(recovered.fired_events.len(), 1);
        assert_eq!(recovered.fired_events[0].trigger_id, trigger);
        assert_eq!(recovered.fired_events[0].ledger_ref.seq, ingest_ref.seq);
        assert_eq!(recovered.subscriptions.len(), 1);
        let recovered_subscription = &recovered.subscriptions[0];
        assert_eq!(recovered_subscription.subscription_id, subscription);
        assert_eq!(recovered_subscription.trigger_id, trigger);
        assert_eq!(recovered_subscription.pending_events.len(), 1);
        assert!(!recovered_subscription.overflowed);
        assert_eq!(
            recovered_subscription.pending_events[0].ledger_ref.seq,
            ingest_ref.seq
        );
        assert_eq!(recovered.pending_event_count(), 1);
        drop(reopened);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn durable_ack_persists_and_recovery_drains_pending_subscription_after_reopen() {
        let (dir, vault) = reactive_vault("ack-recovery");
        let mut engine = ReactiveEngine::new(Arc::new(FixedClock::new(1_786_320_750)));
        let subscription = engine
            .subscribe_durable(
                &vault,
                TriggerCondition::NewRegion { tau_override: None },
                Some("astrolabe-weave-ack".to_string()),
            )
            .expect("durable subscription");
        let trigger = engine
            .subscriptions()
            .get(subscription)
            .expect("subscription handle")
            .trigger_id;
        let trigger_cx = cx(45);
        let ingest_ref = vault
            .append_ledger_entry(
                EntryKind::Ingest,
                SubjectId::Cx(trigger_cx),
                b"reactive ack ingest".to_vec(),
                ActorId::Service("astrolabe-weave-test".to_string()),
            )
            .expect("append real ingest ledger entry");
        let signals =
            ScriptedReactiveSignals::with_novelty_and_drift(NoveltyVerdict::NewRegion, 0.0);

        assert_eq!(
            engine
                .evaluate_post_ingest_durable(&vault, trigger_cx, ingest_ref.clone(), &signals)
                .expect("evaluate durable subscription"),
            1
        );
        let before = recover_reactive_state(&vault).expect("recover before ack");
        assert_eq!(before.pending_event_count(), 1);

        let ack = acknowledge_reactive_subscription(
            &vault,
            subscription,
            "astrolabe-weave-test".to_string(),
        )
        .expect("ack durable subscription");
        assert_eq!(ack.subscription_id, subscription);
        assert_eq!(ack.pending_before, 1);
        assert_eq!(ack.acked_count, 1);
        assert_eq!(ack.pending_after, 0);
        assert_eq!(ack.acknowledged_events.len(), 1);
        assert_eq!(ack.acknowledged_events[0].trigger_id, trigger);
        assert_eq!(ack.acknowledged_events[0].ledger_ref.seq, ingest_ref.seq);
        assert!(ack.ledger_ref.is_some());

        let ack_payloads = reactive_ack_payloads(&vault);
        assert_eq!(ack_payloads.len(), 1);
        assert_eq!(ack_payloads[0]["tag"], ASTROLABE_REACTIVE_ACK_TAG);
        assert_eq!(ack_payloads[0]["action"], "SUBSCRIPTION_EVENTS_ACKED");
        assert_eq!(ack_payloads[0]["subscription_id"], subscription.to_string());
        assert_eq!(ack_payloads[0]["acknowledged_count"], 1);

        let after = recover_reactive_state(&vault).expect("recover after ack");
        assert_eq!(after.fired_events.len(), 1);
        assert_eq!(after.pending_event_count(), 0);
        vault.flush().expect("flush durable ack state");
        drop(engine);
        drop(vault);

        let reopened = open_reactive_vault(&dir);
        let reopened_state =
            recover_reactive_state(&reopened).expect("recover durable ack state after reopen");
        assert_eq!(reopened_state.fired_events.len(), 1);
        assert_eq!(reopened_state.pending_event_count(), 0);
        assert_eq!(reactive_ack_payloads(&reopened).len(), 1);
        drop(reopened);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn durable_new_region_and_drift_detected_persist_source_rows() {
        let (dir, vault) = reactive_vault("new-region-drift");
        let mut engine = ReactiveEngine::new(Arc::new(FixedClock::new(1_786_320_500)));
        engine
            .register(TriggerCondition::NewRegion { tau_override: None }, None)
            .expect("register new-region trigger");
        engine
            .register(
                TriggerCondition::DriftDetected {
                    slot: SlotId::new(8),
                    drift_threshold: 0.25,
                },
                None,
            )
            .expect("register drift trigger");
        let signals =
            ScriptedReactiveSignals::with_novelty_and_drift(NoveltyVerdict::NewRegion, 0.5);

        assert_eq!(
            engine
                .evaluate_post_ingest_durable(&vault, cx(5), lref(11), &signals)
                .expect("new-region + drift eval"),
            2
        );

        let audits = all_audit_entries(&vault);
        let fired = fired_events(&vault);
        assert_eq!(audits.len(), 2);
        assert!(audits.iter().all(|entry| entry.matched));
        assert_eq!(fired.len(), 2);
        assert!(
            fired.iter().any(|event| matches!(
                event.condition_snapshot,
                TriggerCondition::NewRegion { .. }
            ))
        );
        assert!(fired.iter().any(|event| matches!(
            event.condition_snapshot,
            TriggerCondition::DriftDetected {
                slot,
                drift_threshold
            } if slot == SlotId::new(8) && (drift_threshold - 0.25).abs() <= f32::EPSILON
        )));
        drop(vault);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn durable_queue_overflow_persists_warning_row_and_bounds_queue() {
        let (dir, vault) = reactive_vault("queue-overflow");
        let series = cx(3);
        let mut engine = ReactiveEngine::with_caps(Arc::new(FixedClock::new(55)), 8, 2, 64);
        for _ in 0..3 {
            engine
                .register(
                    TriggerCondition::EventRecurs {
                        series,
                        min_occurrences: 1,
                    },
                    None,
                )
                .expect("register overflow trigger");
        }
        let signals = ScriptedReactiveSignals::grounded();

        let err = engine
            .evaluate_post_ingest_durable(&vault, series, lref(9), &signals)
            .expect_err("third fired event overflows two-item queue");

        assert_eq!(err.code, CALYX_REACTIVE_QUEUE_FULL);
        assert_eq!(engine.queue().len(), 2);
        assert_eq!(
            engine
                .queue()
                .iter()
                .map(|event| event.ledger_ref.seq)
                .collect::<Vec<_>>(),
            vec![9, 9]
        );
        assert_eq!(fired_events(&vault).len(), 3);
        let warnings = all_audit_entries(&vault)
            .into_iter()
            .filter(|entry| entry.code.as_deref() == Some(CALYX_REACTIVE_QUEUE_FULL))
            .collect::<Vec<_>>();
        assert_eq!(warnings.len(), 1);
        drop(vault);
        let _ = fs::remove_dir_all(dir);
    }

    /// Drives `total_evals` durable NewRegion evaluations through `engine`/`vault`,
    /// asserting the queue accepts exactly `cap` events and every subsequent
    /// evaluation fails closed with [`CALYX_REACTIVE_QUEUE_FULL`] (the ring is
    /// never drained here, so once full it stays full). Shared by the two #60
    /// churn slices.
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    fn drive_reactive_churn(
        vault: &AsterVault<SystemClock>,
        engine: &mut ReactiveEngine,
        total_evals: u64,
        cap: u64,
    ) {
        let signals =
            ScriptedReactiveSignals::with_novelty_and_drift(NoveltyVerdict::NewRegion, 0.0);
        let mut ok_count = 0u64;
        let mut overflow_count = 0u64;
        for seq in 1..=total_evals {
            let result = engine.evaluate_post_ingest_durable(vault, cx(12), lref(seq), &signals);
            if seq <= cap {
                assert_eq!(result.expect("queue has capacity below cap"), 1);
                ok_count += 1;
            } else {
                let err = result.expect_err("evaluation beyond queue cap overflows");
                assert_eq!(err.code, CALYX_REACTIVE_QUEUE_FULL);
                overflow_count += 1;
            }
        }
        assert_eq!(ok_count, cap);
        assert_eq!(overflow_count, total_evals - cap);
    }

    /// #60 churn slice 1 of 2 — bounded-N exact accounting. Drives
    /// `REACTIVE_CHURN_ACCOUNTING_EVENTS` durable evaluations past a small ring
    /// cap so the overflow / evict-oldest path runs hundreds of times, then does
    /// an independent readback of the persisted reactive CF and asserts the
    /// accounting is exact: every evaluation matched and was audited, exactly one
    /// QUEUE_FULL warning per overflow, and the in-memory ring holds precisely the
    /// most-recent `cap` events (FIFO evict-oldest). Bounded N keeps it well under
    /// the #280 60s per-test budget; the RSS property is proven by slice 2.
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[test]
    fn durable_reactive_churn_slice_bounded_n_keeps_exact_accounting() {
        let (dir, vault) = reactive_vault("churn-accounting");
        let cap = REACTIVE_CHURN_SLICE_QUEUE_CAP as u64;
        let mut engine = ReactiveEngine::with_caps(
            Arc::new(FixedClock::new(1_786_321_000)),
            4,
            REACTIVE_CHURN_SLICE_QUEUE_CAP,
            1 << 20,
        );
        engine
            .register(TriggerCondition::NewRegion { tau_override: None }, None)
            .expect("register churn accounting trigger");

        let total_evals = REACTIVE_CHURN_ACCOUNTING_EVENTS;
        assert!(
            total_evals > cap,
            "churn slice must drive past the ring cap: total_evals={total_evals} cap={cap}"
        );
        drive_reactive_churn(&vault, &mut engine, total_evals, cap);

        // The ring stays capped and holds exactly the most-recent `cap` events
        // (FIFO evict-oldest): first is total_evals-cap+1, last is total_evals.
        assert_eq!(engine.queue().len(), REACTIVE_CHURN_SLICE_QUEUE_CAP);
        let queued_seqs = engine
            .queue()
            .iter()
            .map(|event| event.ledger_ref.seq)
            .collect::<Vec<_>>();
        assert_eq!(queued_seqs.first().copied(), Some(total_evals - cap + 1));
        assert_eq!(queued_seqs.last().copied(), Some(total_evals));

        // FSV: independent readback of the persisted reactive CF. Every evaluation
        // fired and was audited; exactly one QUEUE_FULL warning per overflow.
        let audits = all_audit_entries(&vault);
        assert_eq!(
            audits.iter().filter(|entry| entry.code.is_none()).count(),
            total_evals as usize
        );
        assert_eq!(
            audits
                .iter()
                .filter(|entry| entry.code.as_deref() == Some(CALYX_REACTIVE_QUEUE_FULL))
                .count(),
            (total_evals - cap) as usize
        );
        assert_eq!(fired_events(&vault).len(), total_evals as usize);
        drop(vault);
        let _ = fs::remove_dir_all(dir);
    }

    /// #60 churn slice 2 of 2 — bounded resident memory under sustained churn.
    /// Drives `REACTIVE_CHURN_RSS_EVENTS` durable evaluations (the largest count
    /// that stays under the #280 60s per-test budget on the native host) against a
    /// full ring, so the overflow / evict-oldest path runs thousands of times, and
    /// asserts resident-set growth stays under the declared bound. Because the ring
    /// never exceeds its cap, sustained churn far beyond the cap must not grow
    /// resident memory. Exact accounting is proven by slice 1.
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[test]
    fn durable_reactive_churn_slice_bounds_rss_under_sustained_churn() {
        let (dir, vault) = reactive_vault("churn-rss");
        let cap = REACTIVE_CHURN_SLICE_QUEUE_CAP as u64;
        let mut engine = ReactiveEngine::with_caps(
            Arc::new(FixedClock::new(1_786_322_000)),
            4,
            REACTIVE_CHURN_SLICE_QUEUE_CAP,
            1 << 20,
        );
        engine
            .register(TriggerCondition::NewRegion { tau_override: None }, None)
            .expect("register churn rss trigger");

        let total_evals = REACTIVE_CHURN_RSS_EVENTS;
        assert!(
            total_evals > cap,
            "churn slice must drive past the ring cap: total_evals={total_evals} cap={cap}"
        );
        let rss_before = resident_set_bytes();
        drive_reactive_churn(&vault, &mut engine, total_evals, cap);
        let rss_after = resident_set_bytes();

        let rss_delta = rss_after.saturating_sub(rss_before);
        assert!(
            rss_delta <= MAX_REACTIVE_SOAK_RSS_DELTA_BYTES,
            "reactive churn soak RSS delta {rss_delta} exceeded cap {MAX_REACTIVE_SOAK_RSS_DELTA_BYTES}"
        );

        // The ring stays capped: bounded footprint under sustained churn.
        assert_eq!(engine.queue().len(), REACTIVE_CHURN_SLICE_QUEUE_CAP);
        drop(vault);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn durable_audit_count_matches_evaluation_count_for_no_match_batch() {
        let (dir, vault) = reactive_vault("audit-count");
        let mut engine = ReactiveEngine::new(Arc::new(FixedClock::new(99)));
        for _ in 0..7 {
            engine
                .register(TriggerCondition::NewRegion { tau_override: None }, None)
                .expect("register no-match trigger");
        }
        let signals = ScriptedReactiveSignals::grounded();

        assert_eq!(
            engine
                .evaluate_post_ingest_durable(&vault, cx(2), lref(14), &signals)
                .expect("no-match eval"),
            0
        );

        let audits = all_audit_entries(&vault);
        assert_eq!(audits.len(), 7);
        assert!(audits.iter().all(|entry| !entry.matched));
        assert!(audits.iter().all(|entry| entry.code.is_none()));
        assert!(fired_events(&vault).is_empty());
        drop(vault);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn golden_knn_admission_uses_lower_qn_owner_and_cap() {
        let mut config = struct_only_config();
        config.per_node_cap = 1;
        config.thresholds.sim_struct_min_score = 0.40;
        let nodes = vec![
            sparse_node("alpha", SimilarityFamily::Struct, 8, &[(0, 1.0), (1, 1.0)]),
            sparse_node("beta", SimilarityFamily::Struct, 8, &[(0, 1.0), (1, 1.0)]),
            sparse_node("gamma", SimilarityFamily::Struct, 8, &[(0, 1.0), (2, 1.0)]),
            sparse_node("omega", SimilarityFamily::Struct, 8, &[(7, 1.0)]),
        ];

        let plan = plan_similarity_edges(&nodes, &config).expect("similarity plan");

        assert_eq!(
            edge_qns(&plan.edges),
            vec![("alpha", "beta"), ("beta", "gamma")]
        );
        assert_eq!(plan.edges[0].family, SimilarityFamily::Struct);
        assert_eq!(plan.edges[0].graph_edge_kind, EdgeKind::SimilarTo);
        assert_eq!(plan.edges[0].weight, 1.0);
        assert_eq!(plan.edges[0].threshold, 0.40);

        let counts = plan
            .skips
            .pair_counts
            .get(&SimilarityFamily::Struct)
            .expect("struct pair counts");
        assert_eq!(counts.candidate_pairs, 6);
        assert_eq!(counts.below_threshold_pairs, 3);
        assert_eq!(counts.cap_dropped_pairs, 1);
        assert_eq!(counts.admitted_pairs, 2);
    }

    #[test]
    fn streaming_top_k_keeps_highest_weight_targets_per_source() {
        // A hub node "a" (smallest qualified name, hence the source of every one
        // of its edges) is above threshold with four targets at strictly
        // distinct cosines; the four leaf nodes have pairwise-disjoint sparse
        // supports so every non-hub pair scores exactly zero. With per_node_cap
        // = 2 the streaming heap must retain the two HIGHEST-weight targets and
        // evict the rest. A bottom-k / broken-eviction rewrite keeps the wrong
        // targets and fails this test.
        let mut config = struct_only_config();
        config.per_node_cap = 2;
        config.thresholds.sim_struct_min_score = 0.10;
        let nodes = vec![
            sparse_node(
                "a",
                SimilarityFamily::Struct,
                8,
                &[(0, 4.0), (1, 3.0), (2, 2.0), (3, 1.0)],
            ),
            sparse_node("b", SimilarityFamily::Struct, 8, &[(0, 1.0)]),
            sparse_node("c", SimilarityFamily::Struct, 8, &[(1, 1.0)]),
            sparse_node("d", SimilarityFamily::Struct, 8, &[(2, 1.0)]),
            sparse_node("e", SimilarityFamily::Struct, 8, &[(3, 1.0)]),
        ];

        let plan = plan_similarity_edges(&nodes, &config).expect("similarity plan");

        // Only the top two targets by weight survive: a-b (4/sqrt30 ≈ 0.7303)
        // and a-c (3/sqrt30 ≈ 0.5477). a-d and a-e are cap-dropped.
        assert_eq!(edge_qns(&plan.edges), vec![("a", "b"), ("a", "c")]);
        let hub_norm = 30.0_f32.sqrt();
        assert!((plan.edges[0].weight - 4.0 / hub_norm).abs() <= f32::EPSILON);
        assert!((plan.edges[1].weight - 3.0 / hub_norm).abs() <= f32::EPSILON);
        // The retained weights are strictly greater than every evicted one,
        // proving top-k (not bottom-k) selection.
        assert!(plan.edges[1].weight > 2.0 / hub_norm);

        let counts = plan
            .skips
            .pair_counts
            .get(&SimilarityFamily::Struct)
            .expect("struct pair counts");
        assert_eq!(counts.candidate_pairs, 10); // C(5,2)
        assert_eq!(counts.below_threshold_pairs, 6); // every disjoint leaf pair
        assert_eq!(counts.incompatible_shape_pairs, 0);
        assert_eq!(counts.cap_dropped_pairs, 2); // a-d, a-e
        assert_eq!(counts.admitted_pairs, 2);
    }

    #[test]
    fn near_duplicate_corpus_admits_bounded_tie_broken_neighbors() {
        // Six identical nodes: every one of the C(6,2)=15 pairs scores exactly
        // 1.0, the O(n^2) near-duplicate case the buffering fix targets. With
        // per_node_cap = 2 each source keeps its two smallest-qualified-name
        // targets (the weight-tie break), giving a closed-form admitted count
        // and cap-drop count that a mis-bounded planner cannot reproduce.
        let mut config = struct_only_config();
        config.per_node_cap = 2;
        config.thresholds.sim_struct_min_score = 0.50;
        let entries = &[(0, 1.0), (1, 1.0)];
        let nodes = vec![
            sparse_node("n0", SimilarityFamily::Struct, 8, entries),
            sparse_node("n1", SimilarityFamily::Struct, 8, entries),
            sparse_node("n2", SimilarityFamily::Struct, 8, entries),
            sparse_node("n3", SimilarityFamily::Struct, 8, entries),
            sparse_node("n4", SimilarityFamily::Struct, 8, entries),
            sparse_node("n5", SimilarityFamily::Struct, 8, entries),
        ];

        let plan = plan_similarity_edges(&nodes, &config).expect("similarity plan");

        // Source n_i keeps targets n_{i+1..=i+2} (smallest qn first):
        // n0->n1,n2 · n1->n2,n3 · n2->n3,n4 · n3->n4,n5 · n4->n5. Total 9.
        assert_eq!(
            edge_qns(&plan.edges),
            vec![
                ("n0", "n1"),
                ("n0", "n2"),
                ("n1", "n2"),
                ("n1", "n3"),
                ("n2", "n3"),
                ("n2", "n4"),
                ("n3", "n4"),
                ("n3", "n5"),
                ("n4", "n5"),
            ]
        );
        assert!(plan.edges.iter().all(|edge| edge.weight == 1.0));

        let counts = plan
            .skips
            .pair_counts
            .get(&SimilarityFamily::Struct)
            .expect("struct pair counts");
        assert_eq!(counts.candidate_pairs, 15); // C(6,2)
        assert_eq!(counts.below_threshold_pairs, 0);
        assert_eq!(counts.admitted_pairs, 9);
        assert_eq!(counts.cap_dropped_pairs, 6); // 15 above-threshold - 9 admitted
    }

    #[test]
    fn dense_semantic_cosine_is_exact_for_golden_pair() {
        let mut config = family_only_config(SimilarityFamily::Semantic);
        config.thresholds.sim_semantic_min_score = 0.50;
        let nodes = vec![
            dense_node("left", SimilarityFamily::Semantic, &[1.0, 0.0]),
            dense_node("right", SimilarityFamily::Semantic, &[0.6, 0.8]),
        ];

        let plan = plan_similarity_edges(&nodes, &config).expect("similarity plan");

        assert_eq!(plan.edges.len(), 1);
        assert_eq!(plan.edges[0].source_qn, "left");
        assert_eq!(plan.edges[0].target_qn, "right");
        assert_eq!(plan.edges[0].graph_edge_kind, EdgeKind::SemanticallyRelated);
        assert!((plan.edges[0].weight - 0.6).abs() <= f32::EPSILON);
        assert_eq!(
            plan.edges[0].graph_properties().get("family"),
            Some(&"SIM_SEMANTIC".to_string())
        );
    }

    #[test]
    fn worker_count_shards_source_loop_without_changing_the_plan() {
        // Enough sources that worker_count > 1 genuinely partitions the source
        // loop into multiple shards (32 sources -> 8 shards of 4 at worker_count=8,
        // uneven shards at worker_count=3). A low threshold plus a small per-node
        // cap forces real above-threshold admission *and* per-source cap eviction,
        // so a shard boundary that split one source's admission or double-counted a
        // pair would produce a different plan than the serial baseline.
        let mut base = struct_only_config();
        base.per_node_cap = 3;
        base.thresholds.sim_struct_min_score = 0.10;
        base.exact_pair_node_limit = None;

        let nodes = (0..32)
            .map(|index| {
                let qualified_name = format!("node-{index:03}");
                // Overlapping sparse support guarantees many above-threshold pairs.
                sparse_node(
                    &qualified_name,
                    SimilarityFamily::Struct,
                    8,
                    &[
                        ((index % 8) as u32, 1.0),
                        (((index + 1) % 8) as u32, 1.0),
                        (((index + 2) % 8) as u32, 1.0),
                    ],
                )
            })
            .collect::<Vec<_>>();

        let mut serial_config = base.clone();
        serial_config.worker_count = 1;
        let serial = plan_similarity_edges(&nodes, &serial_config).expect("serial plan");

        // The baseline must exercise both admission and cap eviction; otherwise the
        // cross-worker equality below would be trivially satisfied by an empty plan.
        assert!(!serial.edges.is_empty(), "baseline must admit edges");
        let struct_counts = serial
            .skips
            .pair_counts
            .get(&SimilarityFamily::Struct)
            .expect("struct pair counts");
        assert!(
            struct_counts.admitted_pairs > 0 && struct_counts.cap_dropped_pairs > 0,
            "baseline must admit and cap-drop pairs: {struct_counts:?}"
        );

        for worker_count in [2usize, 3, 5, 8, 32, 64] {
            let mut config = base.clone();
            config.worker_count = worker_count;
            let sharded = plan_similarity_edges(&nodes, &config)
                .unwrap_or_else(|error| panic!("{worker_count}-worker plan failed: {error:?}"));
            assert_eq!(
                sharded.edges, serial.edges,
                "edges diverged at worker_count={worker_count}"
            );
            assert_eq!(
                sharded.skips, serial.skips,
                "skip report diverged at worker_count={worker_count}"
            );
            assert_eq!(sharded.workers_requested, worker_count);
        }
    }

    #[test]
    fn disabled_family_and_scale_opt_out_are_reported_explicitly() {
        let mut config = family_only_config(SimilarityFamily::Semantic)
            .with_disabled_family(SimilarityFamily::Struct)
            .with_exact_pair_node_limit(Some(2));
        config.thresholds.sim_semantic_min_score = 0.10;

        let nodes = vec![
            dense_node("a", SimilarityFamily::Semantic, &[1.0, 0.0]),
            dense_node("b", SimilarityFamily::Semantic, &[0.9, 0.1]),
            dense_node("c", SimilarityFamily::Semantic, &[0.8, 0.2]),
        ];

        let plan = plan_similarity_edges(&nodes, &config).expect("similarity plan");

        assert!(plan.edges.is_empty());
        assert!(plan.skips.family_opt_outs.iter().any(|skip| {
            skip.family == SimilarityFamily::Struct
                && skip.reason == SimilarityFamilyOptOutReason::DisabledByConfig
        }));
        assert!(plan.skips.family_opt_outs.iter().any(|skip| {
            skip.family == SimilarityFamily::Semantic
                && skip.reason == SimilarityFamilyOptOutReason::ExactCandidateLimitExceeded
                && skip.node_count == 3
                && skip.limit == Some(2)
        }));
    }

    #[test]
    fn ann_lsh_golden_knn_matches_expected_edges_with_cap_and_ownership() {
        // Two identical-support groups: every within-group pair is Jaccard 1,
        // so LSH banding is *guaranteed* to co-bucket them (identical MinHash
        // signatures in every band); cross-group pairs score cosine 0 and can
        // never be admitted even if a band collided. The admitted edge set is
        // therefore an exact golden expectation, not a recall hope.
        let mut config = ann_family_config(SimilarityFamily::Struct);
        config.per_node_cap = 2;
        config.thresholds.sim_struct_min_score = 0.50;
        // Exact-square norms (25 and 100) keep the identical-pair cosine at
        // exactly 1.0 in f32, so the weight assertion is bit-exact.
        let group_a = &[(0, 3.0), (1, 4.0)];
        let group_b = &[(10, 6.0), (11, 8.0)];
        let nodes = vec![
            sparse_node("a1", SimilarityFamily::Struct, 16, group_a),
            sparse_node("a2", SimilarityFamily::Struct, 16, group_a),
            sparse_node("a3", SimilarityFamily::Struct, 16, group_a),
            sparse_node("b1", SimilarityFamily::Struct, 16, group_b),
            sparse_node("b2", SimilarityFamily::Struct, 16, group_b),
        ];

        let plan = plan_similarity_edges(&nodes, &config).expect("lsh similarity plan");

        // Lower QN owns each pair; per-source cap 2 admits both a-group
        // targets for a1.
        assert_eq!(
            edge_qns(&plan.edges),
            vec![("a1", "a2"), ("a1", "a3"), ("a2", "a3"), ("b1", "b2")]
        );
        assert!(plan.edges.iter().all(|edge| edge.weight == 1.0));
        assert!(
            plan.edges
                .iter()
                .all(|edge| edge.family == SimilarityFamily::Struct
                    && edge.graph_edge_kind == EdgeKind::SimilarTo)
        );

        let report = plan
            .skips
            .ann_reports
            .get(&SimilarityFamily::Struct)
            .expect("lsh ann report");
        assert_eq!(report.sparse_pool_nodes, 5);
        assert_eq!(report.dense_pool_nodes, 0);
        assert!(report.lsh_buckets > 0);
        assert!(report.lsh_candidate_pairs >= 4);
        assert_eq!(report.hnsw_candidate_pairs, 0);
        assert_eq!(report.hnsw_dim_groups, 0);

        // Cap boundary: with cap 1, a1 keeps only its smallest-QN tied target
        // and the dropped candidate is accounted, never silently lost.
        let mut capped = config.clone();
        capped.per_node_cap = 1;
        let capped_plan = plan_similarity_edges(&nodes, &capped).expect("capped lsh plan");
        assert_eq!(
            edge_qns(&capped_plan.edges),
            vec![("a1", "a2"), ("a2", "a3"), ("b1", "b2")]
        );
        let counts = capped_plan
            .skips
            .pair_counts
            .get(&SimilarityFamily::Struct)
            .expect("capped struct pair counts");
        assert_eq!(counts.cap_dropped_pairs, 1);
        assert_eq!(counts.admitted_pairs, 3);
    }

    #[test]
    fn ann_hnsw_golden_knn_matches_exact_plan_on_dense_fixture() {
        // Small dense pool: the seeded HNSW is exhaustive at this scale and the
        // query k (cap × multiplier + 1) covers the pool, so the ANN plan must
        // reproduce the exact plan bit-for-bit — including ownership and cap
        // behavior — while candidates come from the quantized index.
        let mut exact = family_only_config(SimilarityFamily::Semantic);
        exact.per_node_cap = 2;
        exact.thresholds.sim_semantic_min_score = 0.60;
        let mut ann = exact.clone();
        ann.candidate_strategies
            .insert(SimilarityFamily::Semantic, SimilarityCandidateStrategy::Ann);

        let nodes = vec![
            dense_node("u1", SimilarityFamily::Semantic, &[1.0, 0.0, 0.0, 0.0]),
            dense_node("u2", SimilarityFamily::Semantic, &[0.9, 0.1, 0.0, 0.0]),
            dense_node("u3", SimilarityFamily::Semantic, &[0.8, 0.2, 0.1, 0.0]),
            dense_node("u4", SimilarityFamily::Semantic, &[0.0, 0.0, 1.0, 0.0]),
            dense_node("u5", SimilarityFamily::Semantic, &[0.0, 0.0, 0.9, 0.2]),
        ];

        let exact_plan = plan_similarity_edges(&nodes, &exact).expect("exact plan");
        let ann_plan = plan_similarity_edges(&nodes, &ann).expect("ann plan");

        assert_eq!(ann_plan.edges, exact_plan.edges);
        assert!(!ann_plan.edges.is_empty(), "fixture must admit edges");
        assert_eq!(
            similarity_edge_dump_bytes(&ann_plan.edges),
            similarity_edge_dump_bytes(&exact_plan.edges)
        );
        assert!(
            ann_plan
                .edges
                .iter()
                .any(|edge| edge.source_qn == "u4" && edge.target_qn == "u5"),
            "second cluster pair must be admitted: {:?}",
            edge_qns(&ann_plan.edges)
        );

        let report = ann_plan
            .skips
            .ann_reports
            .get(&SimilarityFamily::Semantic)
            .expect("hnsw ann report");
        assert_eq!(report.dense_pool_nodes, 5);
        assert_eq!(report.sparse_pool_nodes, 0);
        assert_eq!(report.hnsw_dim_groups, 1);
        assert!(report.hnsw_candidate_pairs >= exact_plan.edges.len());
        assert_eq!(report.quant_scale_measurements.len(), 1);
        let measurement = &report.quant_scale_measurements[0];
        assert_eq!(measurement.dim, 4);
        assert_eq!(measurement.pool_nodes, 5);
        // The scale is measured from the pool (max |component| / 127), not a
        // constant.
        assert_eq!(measurement.scale(), 1.0 / 127.0);
    }

    #[test]
    fn similarity_determinism_probe_three_runs_1_vs_8_workers_byte_identical() {
        // DoD determinism probe (locally runnable; GitHub Actions is banned by
        // owner directive): same mixed sparse+dense corpus, ANN strategies for
        // all families, three runs at 1 worker and three at 8 workers must
        // produce byte-identical canonical edge dumps and identical skip
        // accounting.
        let config = SimilarityPlannerConfig {
            exact_pair_node_limit: None,
            per_node_cap: 3,
            thresholds: SimilarityThresholds {
                sim_struct_min_score: 0.30,
                sim_semantic_min_score: 0.30,
                sim_api_min_score: 0.30,
                sim_profile_min_score: 0.30,
            },
            candidate_strategies: SimilarityFamily::ALL
                .into_iter()
                .map(|family| (family, SimilarityCandidateStrategy::Ann))
                .collect(),
            ..SimilarityPlannerConfig::default()
        };

        let nodes = (0..40)
            .map(|index: u32| {
                let mut node = SimilarityNode::new(format!("probe-{index:03}"));
                // Sparse struct + api supports with heavy overlap.
                for (family, stride) in [
                    (SimilarityFamily::Struct, 1u32),
                    (SimilarityFamily::Api, 3u32),
                ] {
                    node = node.with_slot(
                        family.slot(),
                        SlotVector::Sparse {
                            dim: 16,
                            entries: (0..4)
                                .map(|offset| SparseEntry {
                                    idx: (index * stride + offset * 2) % 16,
                                    val: ((index + offset) % 5 + 1) as f32,
                                })
                                .collect(),
                        },
                    );
                }
                // Dense semantic + profile vectors from exact rationals.
                for (family, salt) in [
                    (SimilarityFamily::Semantic, 7u32),
                    (SimilarityFamily::Profile, 11u32),
                ] {
                    node = node.with_slot(
                        family.slot(),
                        SlotVector::Dense {
                            dim: 6,
                            data: (0..6)
                                .map(|component| {
                                    ((index * salt + component * 5) % 13) as f32 / 13.0
                                })
                                .collect(),
                        },
                    );
                }
                node
            })
            .collect::<Vec<_>>();

        let mut dumps = Vec::new();
        let mut skip_reports = Vec::new();
        for worker_count in [1usize, 8] {
            for _run in 0..3 {
                let mut run_config = config.clone();
                run_config.worker_count = worker_count;
                let plan = plan_similarity_edges(&nodes, &run_config).expect("probe plan");
                assert!(!plan.edges.is_empty(), "probe corpus must admit edges");
                dumps.push(similarity_edge_dump_bytes(&plan.edges));
                skip_reports.push(plan.skips);
            }
        }
        for (index, dump) in dumps.iter().enumerate().skip(1) {
            assert_eq!(
                dump, &dumps[0],
                "edge dump {index} diverged from run 0 (byte compare)"
            );
        }
        for (index, skips) in skip_reports.iter().enumerate().skip(1) {
            assert_eq!(
                skips, &skip_reports[0],
                "skip report {index} diverged from run 0"
            );
        }
        // Every family must have really used the ANN generator.
        for family in SimilarityFamily::ALL {
            assert!(
                skip_reports[0].ann_reports.contains_key(&family),
                "family {family} missing ann accounting"
            );
        }
    }

    #[test]
    fn admission_thresholds_are_config_read_with_no_magic_numbers_in_admission_path() {
        // Named defaults: every per-family admission threshold is a documented
        // config field.
        let thresholds = SimilarityThresholds::default();
        for (family, expected) in [
            (SimilarityFamily::Struct, DEFAULT_SIM_STRUCT_MIN_SCORE),
            (SimilarityFamily::Semantic, DEFAULT_SIM_SEMANTIC_MIN_SCORE),
            (SimilarityFamily::Api, DEFAULT_SIM_API_MIN_SCORE),
            (SimilarityFamily::Profile, DEFAULT_SIM_PROFILE_MIN_SCORE),
        ] {
            assert_eq!(thresholds.threshold(family), expected);
        }
        let config = SimilarityPlannerConfig::default();
        assert_eq!(config.per_node_cap, DEFAULT_SIMILARITY_PER_NODE_CAP);
        assert_eq!(
            config.ann.minhash_permutations,
            DEFAULT_SIMILARITY_LSH_PERMUTATIONS
        );
        assert_eq!(config.ann.lsh_bands, DEFAULT_SIMILARITY_LSH_BANDS);
        assert_eq!(config.ann.seed, DEFAULT_SIMILARITY_ANN_SEED);
        assert_eq!(
            config.ann.candidate_multiplier,
            DEFAULT_SIMILARITY_ANN_CANDIDATE_MULTIPLIER
        );
        assert_eq!(config.ann.hnsw_ef_search, DEFAULT_SIMILARITY_HNSW_EF_SEARCH);

        // A changed config threshold must flow into admission and onto edges.
        let mut tightened = ann_family_config(SimilarityFamily::Semantic);
        tightened.thresholds.sim_semantic_min_score = 0.99;
        let nodes = vec![
            dense_node("left", SimilarityFamily::Semantic, &[1.0, 0.0]),
            dense_node("right", SimilarityFamily::Semantic, &[0.6, 0.8]),
        ];
        let plan = plan_similarity_edges(&nodes, &tightened).expect("tightened plan");
        assert!(
            plan.edges.is_empty(),
            "0.6 cosine must fail a 0.99 threshold"
        );
        let mut loosened = ann_family_config(SimilarityFamily::Semantic);
        loosened.thresholds.sim_semantic_min_score = 0.25;
        let plan = plan_similarity_edges(&nodes, &loosened).expect("loosened plan");
        assert_eq!(plan.edges.len(), 1);
        assert_eq!(plan.edges[0].threshold, 0.25);

        // Grep gate: the admission path (candidate scoring, threshold, cap)
        // must contain no inline float literal — every score-scale constant
        // arrives through SimilarityPlannerConfig.
        let source = include_str!("lib.rs");
        for function in [
            "fn consider_target(",
            "fn plan_source_range(",
            "fn plan_family_edges(",
        ] {
            let body = function_body(source, function);
            if let Some(literal) = first_float_literal(body) {
                panic!("magic float literal {literal:?} found in {function} admission path");
            }
        }

        // Invalid ANN knobs are refused, not defaulted.
        let mut bad = SimilarityPlannerConfig::default();
        bad.ann.lsh_bands = 3; // does not divide 128
        let err = plan_similarity_edges(&[], &bad).expect_err("invalid bands refused");
        assert!(matches!(
            err,
            SimilarityPlanError::InvalidAnnConfig {
                field: "lsh_bands",
                ..
            }
        ));
        let mut bad = SimilarityPlannerConfig::default();
        bad.ann.candidate_multiplier = 0;
        let err = plan_similarity_edges(&[], &bad).expect_err("zero multiplier refused");
        assert!(matches!(
            err,
            SimilarityPlanError::InvalidAnnConfig {
                field: "candidate_multiplier",
                ..
            }
        ));
    }

    /// Returns the body text of `marker`'s function (from its signature line to
    /// the first column-zero closing brace).
    fn function_body<'a>(source: &'a str, marker: &str) -> &'a str {
        let start = source.find(marker).expect("admission function present");
        let rest = &source[start..];
        let end = rest.find("\n}\n").expect("function body terminator");
        &rest[..end]
    }

    /// Finds the first float literal (`<digit>.<digit>`) in a code slice.
    fn first_float_literal(body: &str) -> Option<&str> {
        let bytes = body.as_bytes();
        for index in 1..bytes.len().saturating_sub(1) {
            if bytes[index] == b'.'
                && bytes[index - 1].is_ascii_digit()
                && bytes[index + 1].is_ascii_digit()
            {
                let start = index - 1;
                let end = (index + 2).min(bytes.len());
                return Some(&body[start..end]);
            }
        }
        None
    }

    #[test]
    fn ann_disabled_family_produces_zero_edges_with_accounting() {
        // Scale-control DoD: a family opted out by config yields zero SIM_*
        // edges, an explicit accounted opt-out, and no ANN pass at all.
        let mut config = SimilarityPlannerConfig {
            exact_pair_node_limit: None,
            candidate_strategies: SimilarityFamily::ALL
                .into_iter()
                .map(|family| (family, SimilarityCandidateStrategy::Ann))
                .collect(),
            ..SimilarityPlannerConfig::default()
        }
        .with_disabled_family(SimilarityFamily::Struct);
        config.thresholds.sim_semantic_min_score = 0.10;

        let entries = &[(0, 1.0), (1, 1.0)];
        let nodes = vec![
            sparse_node("s1", SimilarityFamily::Struct, 8, entries)
                .with_slot(SIM_SEMANTIC_SLOT, dense(&[1.0, 0.0])),
            sparse_node("s2", SimilarityFamily::Struct, 8, entries)
                .with_slot(SIM_SEMANTIC_SLOT, dense(&[0.9, 0.1])),
        ];

        let plan = plan_similarity_edges(&nodes, &config).expect("opt-out plan");

        assert!(
            plan.edges
                .iter()
                .all(|edge| edge.family != SimilarityFamily::Struct),
            "opted-out family must produce zero edges"
        );
        assert!(
            plan.edges
                .iter()
                .any(|edge| edge.family == SimilarityFamily::Semantic),
            "enabled family still plans edges"
        );
        assert!(plan.skips.family_opt_outs.iter().any(|skip| {
            skip.family == SimilarityFamily::Struct
                && skip.slot == SIM_STRUCT_SLOT
                && skip.reason == SimilarityFamilyOptOutReason::DisabledByConfig
        }));
        assert!(
            !plan
                .skips
                .ann_reports
                .contains_key(&SimilarityFamily::Struct),
            "opted-out family must not run the ANN generator"
        );
        assert!(
            !plan
                .skips
                .pair_counts
                .contains_key(&SimilarityFamily::Struct)
        );
    }

    #[test]
    fn sim_edges_fsv_readback_is_bit_stable_against_recomputed_plan() {
        // FSV DoD: persist SIM_* rows, reopen the vault, decode the raw Graph
        // CF bytes, and compare weights bit-for-bit (tolerance 0) against an
        // independently recomputed plan from the same inputs, plus the paired
        // ledger entry carrying the canonical dump hash.
        let config = SimilarityPlannerConfig {
            exact_pair_node_limit: None,
            per_node_cap: 2,
            thresholds: SimilarityThresholds {
                sim_struct_min_score: 0.50,
                sim_semantic_min_score: 0.50,
                ..SimilarityThresholds::default()
            },
            candidate_strategies: SimilarityFamily::ALL
                .into_iter()
                .map(|family| (family, SimilarityCandidateStrategy::Ann))
                .collect(),
            ..SimilarityPlannerConfig::default()
        };

        let group = &[(0, 1.0), (1, 2.0), (2, 3.0)];
        let nodes = vec![
            sparse_node("fsv.a", SimilarityFamily::Struct, 8, group)
                .with_slot(SIM_SEMANTIC_SLOT, dense(&[1.0, 0.0, 0.0])),
            sparse_node("fsv.b", SimilarityFamily::Struct, 8, group)
                .with_slot(SIM_SEMANTIC_SLOT, dense(&[0.9, 0.2, 0.1])),
            sparse_node("fsv.c", SimilarityFamily::Struct, 8, group)
                .with_slot(SIM_SEMANTIC_SLOT, dense(&[0.0, 1.0, 0.0])),
        ];
        let plan = plan_similarity_edges(&nodes, &config).expect("fsv plan");
        assert!(
            plan.edges
                .iter()
                .any(|edge| edge.family == SimilarityFamily::Struct)
                && plan
                    .edges
                    .iter()
                    .any(|edge| edge.family == SimilarityFamily::Semantic),
            "fixture must admit edges in both families: {:?}",
            edge_qns(&plan.edges)
        );

        let (dir, vault) = reactive_vault("sim-edges-fsv");
        let report = persist_similarity_edges(&vault, &plan, "astrolabe-weave-test")
            .expect("persist sim edges");
        assert_eq!(report.edge_count, plan.edges.len());
        assert_eq!(report.rows_written, plan.edges.len());
        assert_eq!(report.rows_tombstoned, 0);
        let fsv = report.fsv.as_ref().expect("SIM edge mutation FSV witness");
        assert_eq!(fsv.label(), astrolabe_domain::fsv::FSV_LABEL_VERIFIED);
        assert_eq!(fsv.rows_read_back(), report.rows_written as u64);
        assert_eq!(fsv.ledger_seq(), report.ledger_ref.seq);
        drop(vault);

        // Reopen: everything below reads persisted bytes, not API echoes.
        let reopened = open_reactive_vault(&dir);
        let persisted = read_similarity_edge_rows(&reopened).expect("read sim edge rows");
        assert_eq!(persisted.len(), plan.edges.len());

        // Independent recomputation from the same inputs (same code path must
        // be bit-stable). All fixture QNs share one length, so CF key order
        // (family, source, target) matches the plan's stable edge order and a
        // positional zip is a total comparison.
        let recomputed = plan_similarity_edges(&nodes, &config).expect("recomputed plan");
        assert_eq!(recomputed.edges.len(), persisted.len());
        for (row, edge) in persisted.iter().zip(recomputed.edges.iter()) {
            assert_eq!(row.row.family, edge.family.wire_name());
            assert_eq!(row.row.source_qn, edge.source_qn);
            assert_eq!(row.row.target_qn, edge.target_qn);
            assert_eq!(row.row.slot, edge.slot.get());
            assert_eq!(row.row.etype, edge.graph_edge_kind.code());
            // Tolerance 0: exact bit patterns.
            assert_eq!(row.row.weight_bits, edge.weight.to_bits());
            assert_eq!(row.row.threshold_bits, edge.threshold.to_bits());
            assert_eq!(row.row.props, edge.graph_properties());
            assert_eq!(
                row.key,
                sim_edge_graph_key(edge.family, &edge.source_qn, &edge.target_qn)
            );
        }

        // Ledger pairing: the mutation's ledger entry exists at the reported
        // seq and its payload hash matches the recomputed canonical dump hash.
        let ledger_bytes = reopened
            .read_cf_at(
                reopened.snapshot(),
                ColumnFamily::Ledger,
                &calyx_aster::cf::ledger_key(report.ledger_ref.seq),
            )
            .expect("read ledger row")
            .expect("ledger row present");
        let entry = decode_ledger(&ledger_bytes).expect("decode ledger entry");
        assert_eq!(entry.entry_hash, report.ledger_ref.hash);
        let payload: serde_json::Value =
            serde_json::from_slice(&entry.payload).expect("ledger payload json");
        assert_eq!(payload["schema"], SIM_EDGE_LEDGER_SCHEMA);
        assert_eq!(
            payload["edge_count"].as_u64(),
            Some(plan.edges.len() as u64)
        );
        let expected_hash = hex_lower_bytes(
            blake3::hash(&similarity_edge_dump_bytes(&recomputed.edges)).as_bytes(),
        );
        assert_eq!(payload["edge_dump_hash"], expected_hash);
        assert_eq!(report.edge_dump_hash, expected_hash);

        // Idempotent re-persist: no rewrites, still audited.
        let second = persist_similarity_edges(&reopened, &plan, "astrolabe-weave-test")
            .expect("idempotent persist");
        assert_eq!(second.rows_written, 0);
        assert_eq!(second.rows_unchanged, plan.edges.len());
        assert_eq!(second.rows_tombstoned, 0);
        assert!(
            second.fsv.is_none(),
            "ledger-only replay labels FSV absence"
        );
        assert!(second.ledger_ref.seq > report.ledger_ref.seq);

        // Reconciliation: a tighter plan tombstones stale rows and readback
        // then matches the new plan exactly.
        let mut tighter_config = config.clone();
        tighter_config.thresholds.sim_semantic_min_score = 0.995;
        let tighter = plan_similarity_edges(&nodes, &tighter_config).expect("tighter plan");
        assert!(tighter.edges.len() < plan.edges.len());
        let third = persist_similarity_edges(&reopened, &tighter, "astrolabe-weave-test")
            .expect("reconciling persist");
        assert!(third.rows_tombstoned > 0);
        assert_eq!(
            third
                .fsv
                .as_ref()
                .expect("tombstones earn FSV witness")
                .rows_read_back(),
            (third.rows_written + third.rows_tombstoned) as u64
        );
        let after = read_similarity_edge_rows(&reopened).expect("read reconciled rows");
        assert_eq!(after.len(), tighter.edges.len());
        drop(reopened);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn similarity_delta_tombstones_owned_rows_and_preserves_clean_rows() {
        let mut config = family_only_config(SimilarityFamily::Semantic);
        config.thresholds.sim_semantic_min_score = 0.90;
        let nodes = vec![
            dense_node("dirty.a", SimilarityFamily::Semantic, &[1.0, 0.0]),
            dense_node("dirty.b", SimilarityFamily::Semantic, &[1.0, 0.0]),
            dense_node("clean.c", SimilarityFamily::Semantic, &[0.0, 1.0]),
            dense_node("clean.d", SimilarityFamily::Semantic, &[0.0, 1.0]),
        ];
        let full = plan_similarity_edges(&nodes, &config).expect("full similarity plan");
        assert_eq!(
            edge_qns(&full.edges),
            vec![("clean.c", "clean.d"), ("dirty.a", "dirty.b")]
        );

        let (dir, vault) = reactive_vault("similarity-delta-ownership-fsv");
        persist_similarity_edges(&vault, &full, "astrolabe-weave-test")
            .expect("persist full similarity state");
        let clean_key = sim_edge_graph_key(SimilarityFamily::Semantic, "clean.c", "clean.d");
        let clean_before = vault
            .read_cf_at(vault.snapshot(), ColumnFamily::Graph, &clean_key)
            .expect("read clean row before delta")
            .expect("clean row before delta");

        let empty_delta = SimilarityPlan {
            edges: Vec::new(),
            skips: SimilaritySkipReport::default(),
            workers_requested: config.worker_count,
        };
        let report = persist_similarity_edges_delta(
            &vault,
            &empty_delta,
            &BTreeSet::from(["dirty.a".to_string()]),
            &BTreeSet::new(),
            "astrolabe-weave-test",
        )
        .expect("persist owned similarity delta");
        assert_eq!(report.rows_tombstoned, 1);
        assert_eq!(report.rows_written, 0);

        let persisted = read_similarity_edge_rows(&vault).expect("read similarity delta state");
        assert_eq!(persisted.len(), 1);
        assert_eq!(persisted[0].key, clean_key);
        let clean_after = vault
            .read_cf_at(vault.snapshot(), ColumnFamily::Graph, &clean_key)
            .expect("read clean row after delta")
            .expect("clean row after delta");
        assert_eq!(
            clean_after, clean_before,
            "clean-clean bytes must not change"
        );
        assert!(
            vault
                .read_cf_at(
                    vault.snapshot(),
                    ColumnFamily::Graph,
                    &sim_edge_graph_key(SimilarityFamily::Semantic, "dirty.a", "dirty.b",),
                )
                .expect("read dirty row after delta")
                .is_none()
        );
        drop(vault);
        let _ = fs::remove_dir_all(dir);
    }

    /// Counting [`LoweringTrigger`] double: records how many debounced
    /// regenerations the weave plumbing requested.
    #[derive(Default)]
    struct CountingTrigger {
        requests: std::sync::atomic::AtomicU64,
    }

    impl CountingTrigger {
        fn requests(&self) -> u64 {
            self.requests.load(AtomicOrdering::Relaxed)
        }
    }

    impl astrolabe_domain::LoweringTrigger for CountingTrigger {
        fn request_regeneration(&self) {
            self.requests.fetch_add(1, AtomicOrdering::Relaxed);
        }
    }

    #[test]
    fn weave_mutation_schedules_lowering_but_no_delta_rerun_does_not() {
        // #225 trigger plumbing FSV: a real similarity-edge persistence that
        // writes rows schedules exactly one debounced lowering; a subsequent
        // no-delta re-persist (audited but zero rows changed) schedules none —
        // proven against the persisted SIM_* rows read back from the vault, not
        // the in-memory report alone.
        let config = SimilarityPlannerConfig {
            exact_pair_node_limit: None,
            per_node_cap: 2,
            thresholds: SimilarityThresholds {
                sim_struct_min_score: 0.50,
                sim_semantic_min_score: 0.50,
                ..SimilarityThresholds::default()
            },
            candidate_strategies: SimilarityFamily::ALL
                .into_iter()
                .map(|family| (family, SimilarityCandidateStrategy::Ann))
                .collect(),
            ..SimilarityPlannerConfig::default()
        };
        let group = &[(0, 1.0), (1, 2.0), (2, 3.0)];
        let nodes = vec![
            sparse_node("trig.a", SimilarityFamily::Struct, 8, group)
                .with_slot(SIM_SEMANTIC_SLOT, dense(&[1.0, 0.0, 0.0])),
            sparse_node("trig.b", SimilarityFamily::Struct, 8, group)
                .with_slot(SIM_SEMANTIC_SLOT, dense(&[0.9, 0.2, 0.1])),
        ];
        let plan = plan_similarity_edges(&nodes, &config).expect("trigger plan");
        assert!(
            !plan.edges.is_empty(),
            "fixture must admit at least one edge"
        );

        let (dir, vault) = reactive_vault("lowering-trigger");
        let trigger = CountingTrigger::default();

        // Real mutating commit -> exactly one scheduled regeneration.
        let report = persist_similarity_edges(&vault, &plan, "astrolabe-weave-test")
            .expect("persist sim edges");
        assert!(report.rows_written > 0, "first persist must write rows");
        assert!(report.changed_lowered_inputs());
        let scheduled = schedule_lowering_after(&report, &trigger);
        assert!(scheduled, "a mutating weave commit schedules a lowering");
        assert_eq!(trigger.requests(), 1);
        drop(vault);

        // FSV readback: the persisted SIM_* rows exist independently of the report.
        let reopened = open_reactive_vault(&dir);
        let persisted = read_similarity_edge_rows(&reopened).expect("read persisted sim rows");
        assert_eq!(persisted.len(), plan.edges.len());

        // No-delta re-persist: audited, but zero rows changed -> schedules nothing.
        let rerun = persist_similarity_edges(&reopened, &plan, "astrolabe-weave-test")
            .expect("idempotent persist");
        assert_eq!(rerun.rows_written, 0);
        assert_eq!(rerun.rows_tombstoned, 0);
        assert!(!rerun.changed_lowered_inputs());
        let rescheduled = schedule_lowering_after(&rerun, &trigger);
        assert!(
            !rescheduled,
            "a no-delta audit re-run schedules no lowering"
        );
        assert_eq!(
            trigger.requests(),
            1,
            "trigger count unchanged after no-delta re-run"
        );

        drop(reopened);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn absent_zero_norm_missing_and_bad_shapes_are_not_silent_fallbacks() {
        let config = family_only_config(SimilarityFamily::Semantic);
        let nodes = vec![
            SimilarityNode::new("absent").with_slot(
                SimilarityFamily::Semantic.slot(),
                SlotVector::Absent {
                    reason: calyx_core::AbsentReason::Deferred,
                },
            ),
            SimilarityNode::new("missing"),
            dense_node("zero", SimilarityFamily::Semantic, &[0.0, 0.0]),
            SimilarityNode::new("multi").with_slot(
                SimilarityFamily::Semantic.slot(),
                SlotVector::Multi {
                    token_dim: 2,
                    tokens: vec![vec![1.0, 0.0]],
                },
            ),
        ];

        let plan = plan_similarity_edges(&nodes, &config).expect("similarity plan");

        assert_eq!(plan.edges, Vec::new());
        assert!(has_vector_skip(
            &plan,
            "absent",
            SimilarityVectorSkipReason::AbsentSlot
        ));
        assert!(has_vector_skip(
            &plan,
            "missing",
            SimilarityVectorSkipReason::MissingSlot
        ));
        assert!(has_vector_skip(
            &plan,
            "zero",
            SimilarityVectorSkipReason::ZeroNorm
        ));
        assert!(has_vector_skip(
            &plan,
            "multi",
            SimilarityVectorSkipReason::UnsupportedSlotShape { shape: "multi" }
        ));
    }

    #[test]
    fn zero_norm_knob_is_declared_on_the_squared_scale() {
        // The guard receives the *squared* L2 norm, so the declared floor lives on
        // that scale and equals the smallest normal binary32 value.
        assert_eq!(DEFAULT_MIN_VECTOR_SQUARED_NORM, f32::MIN_POSITIVE);

        // dense_norm / sparse_norm return the sum of squares (the squared norm),
        // which is exactly what zero_norm is fed.
        assert_eq!(dense_norm(&[3.0, 4.0]), 25.0);
        assert_eq!(
            sparse_norm(&[
                SparseEntry { idx: 0, val: 3.0 },
                SparseEntry { idx: 5, val: 4.0 },
            ]),
            25.0
        );
    }

    #[test]
    fn zero_norm_classifies_vectors_at_the_declared_floor_boundary() {
        // Linear-norm floor equivalent to the declared squared-norm knob.
        let floor_norm = DEFAULT_MIN_VECTOR_SQUARED_NORM.sqrt();

        // Just above the floor: squared norm stays a normal f32 -> NOT zero.
        let above = SlotVector::Dense {
            dim: 1,
            data: vec![floor_norm * 2.0],
        };
        let above_sq = dense_norm(&[floor_norm * 2.0]);
        assert!(above_sq >= DEFAULT_MIN_VECTOR_SQUARED_NORM);
        assert!(!zero_norm(above_sq));
        assert!(matches!(
            normalized_vector(&above),
            Ok(NormalizedVector::Dense { .. })
        ));

        // Just below the floor: squared norm underflows to subnormal -> zero.
        let below = SlotVector::Dense {
            dim: 1,
            data: vec![floor_norm * 0.5],
        };
        let below_sq = dense_norm(&[floor_norm * 0.5]);
        assert!(below_sq < DEFAULT_MIN_VECTOR_SQUARED_NORM);
        assert!(zero_norm(below_sq));
        assert!(matches!(
            normalized_vector(&below),
            Err(SimilarityVectorSkipReason::ZeroNorm)
        ));

        // Exactly zero is always degenerate.
        assert!(zero_norm(dense_norm(&[0.0, 0.0])));
        assert!(matches!(
            normalized_vector(&SlotVector::Dense {
                dim: 2,
                data: vec![0.0, 0.0],
            }),
            Err(SimilarityVectorSkipReason::ZeroNorm)
        ));
    }

    #[test]
    fn small_but_real_vector_is_no_longer_zero_classified() {
        // A vector with linear L2 norm 1e-4 (squared 1e-8). This is the exact class
        // of small-but-real vector the audit flagged.
        let data = [1.0e-4_f32];
        let squared = dense_norm(&data);
        assert!((squared - 1.0e-8).abs() <= 1.0e-12);

        // The OLD guard (`squared_norm <= f32::EPSILON`) would have classified this
        // as ZeroNorm — assert that premise so this test is a genuine regression
        // that fails against the pre-fix code.
        assert!(squared <= f32::EPSILON);
        // The FIXED guard, on the correct scale, keeps it.
        assert!(!zero_norm(squared));
        assert!(matches!(
            normalized_vector(&SlotVector::Dense {
                dim: 1,
                data: data.to_vec(),
            }),
            Ok(NormalizedVector::Dense { .. })
        ));
    }

    #[test]
    fn small_but_real_vectors_form_edges_instead_of_zero_norm_skips() {
        // Full-state regression through the real planner: two identical, tiny-norm
        // (~1e-4) vectors must produce a similarity edge (cosine = 1.0), NOT be
        // skipped as ZeroNorm. Under the old `<= f32::EPSILON` guard both nodes were
        // dropped and no edge existed.
        let config = family_only_config(SimilarityFamily::Semantic);
        let nodes = vec![
            dense_node("small_a", SimilarityFamily::Semantic, &[1.0e-4, 2.0e-4]),
            dense_node("small_b", SimilarityFamily::Semantic, &[1.0e-4, 2.0e-4]),
        ];

        let plan = plan_similarity_edges(&nodes, &config).expect("similarity plan");

        assert!(
            !has_vector_skip(&plan, "small_a", SimilarityVectorSkipReason::ZeroNorm),
            "small_a must not be skipped as ZeroNorm"
        );
        assert!(
            !has_vector_skip(&plan, "small_b", SimilarityVectorSkipReason::ZeroNorm),
            "small_b must not be skipped as ZeroNorm"
        );
        assert!(
            plan.edges
                .iter()
                .any(|edge| edge.family == SimilarityFamily::Semantic),
            "expected a semantic similarity edge between the two small-norm nodes"
        );
    }

    #[test]
    fn invalid_config_and_inputs_are_rejected() {
        let nodes = vec![dense_node("n", SimilarityFamily::Semantic, &[1.0, 0.0])];

        let mut config = SimilarityPlannerConfig {
            per_node_cap: 0,
            ..SimilarityPlannerConfig::default()
        };
        assert!(matches!(
            plan_similarity_edges(&nodes, &config),
            Err(SimilarityPlanError::InvalidPerNodeCap { value: 0 })
        ));

        config.per_node_cap = 1;
        config.worker_count = 0;
        assert!(matches!(
            plan_similarity_edges(&nodes, &config),
            Err(SimilarityPlanError::InvalidWorkerCount { value: 0 })
        ));

        config.worker_count = 1;
        config.thresholds.sim_api_min_score = f32::NAN;
        assert!(matches!(
            plan_similarity_edges(&nodes, &config),
            Err(SimilarityPlanError::InvalidThreshold {
                field: "sim_api_min_score",
                ..
            })
        ));

        assert!(matches!(
            plan_similarity_edges(
                &[SimilarityNode::new(" ")],
                &SimilarityPlannerConfig::default()
            ),
            Err(SimilarityPlanError::EmptyQualifiedName { node_index: 0 })
        ));
    }

    #[test]
    fn eager_cross_terms_materialize_exactly_six_designed_pairs_per_symbol() {
        let node = all_dense_cross_term_node("symbol");

        let plan = plan_eager_cross_terms(&[node]);

        assert_eq!(plan.rows.len(), EagerAgreementKind::ALL.len());
        assert_eq!(
            plan.rows.iter().map(|row| row.kind).collect::<Vec<_>>(),
            EagerAgreementKind::ALL
        );
        assert!(plan.rows.iter().all(|row| row.persisted));
        assert_eq!(plan.abundance.symbol_count, 1);
        assert_eq!(plan.abundance.panel_slot_count, 22);
        assert_eq!(plan.abundance.possible_pair_count_per_symbol, 231);
        assert_eq!(plan.abundance.raw_yield, 254);
        assert_eq!(plan.abundance.materialized_count, 6);
        assert_eq!(plan.abundance.lazy_pair_count, 225);
    }

    #[test]
    fn frozen_panel_shapes_produce_all_designed_cross_term_scalars() {
        let nodes = vec![
            frozen_panel_cross_term_node("symbol.alpha", 3),
            frozen_panel_cross_term_node("symbol.beta", 5),
            frozen_panel_cross_term_node("symbol.gamma", 7),
        ];
        assert!(matches!(
            nodes[0].slots.get(&SLOT_NAME_SEMANTIC),
            Some(SlotVector::Dense { dim: 768, .. })
        ));
        assert!(matches!(
            nodes[0].slots.get(&SIM_API_SLOT),
            Some(SlotVector::Sparse { dim: 262_144, .. })
        ));
        assert!(matches!(
            nodes[0].slots.get(&SIM_STRUCT_SLOT),
            Some(SlotVector::Sparse { dim: 65_536, .. })
        ));
        assert!(matches!(
            nodes[0].slots.get(&SLOT_GRAPH_POSITION),
            Some(SlotVector::Dense { dim: 16, .. })
        ));
        assert!(matches!(
            nodes[0].slots.get(&SLOT_TEST_COVERAGE),
            Some(SlotVector::Dense { dim: 4, .. })
        ));
        assert!(matches!(
            nodes[0].slots.get(&SLOT_ROUTE_MATCH),
            Some(SlotVector::Sparse { dim: 4_096, .. })
        ));

        let plan = plan_eager_cross_terms(&nodes);

        for kind in EagerAgreementKind::ALL {
            let rows = plan
                .rows
                .iter()
                .filter(|row| row.kind == kind)
                .collect::<Vec<_>>();
            assert_eq!(rows.len(), nodes.len(), "{kind}");
            assert!(
                rows.iter()
                    .all(|row| matches!(row.value, CrossTermValue::Scalar(_))),
                "{kind} must not be structurally absent"
            );
        }
        assert_eq!(
            plan.abundance.scalar_count,
            nodes.len() * EagerAgreementKind::ALL.len()
        );
        assert_eq!(plan.abundance.absent_count, 0);
        let name_truth = plan
            .rows
            .iter()
            .find(|row| row.kind == EagerAgreementKind::NameTruth)
            .expect("name-truth row");
        assert!(
            anomaly_substrate_row_from_eager_cross_term(name_truth, "xterm:frozen-panel").is_some()
        );
    }

    #[test]
    fn heterogeneous_cross_terms_require_two_comparable_peers() {
        let nodes = vec![
            frozen_panel_cross_term_node("symbol.alpha", 3),
            frozen_panel_cross_term_node("symbol.beta", 5),
        ];

        let plan = plan_eager_cross_terms(&nodes);
        let name_truth = plan
            .rows
            .iter()
            .find(|row| row.kind == EagerAgreementKind::NameTruth)
            .expect("name-truth row");

        assert_eq!(
            name_truth.value,
            CrossTermValue::Absent {
                reason: CrossTermAbsentReason::InsufficientNeighborhood {
                    comparable_peer_count: 1,
                },
            }
        );
    }

    #[test]
    fn name_truth_uses_frozen_shape_peer_similarity_profiles() {
        let aligned = vec![
            name_truth_frozen_node("symbol.alpha", 0, 0),
            name_truth_frozen_node("symbol.beta", 0, 0),
            name_truth_frozen_node("symbol.gamma", 1, 1),
        ];
        let misaligned = vec![
            name_truth_frozen_node("symbol.alpha", 0, 0),
            name_truth_frozen_node("symbol.beta", 0, 1),
            name_truth_frozen_node("symbol.gamma", 1, 0),
        ];

        let aligned_score = named_cross_term_value(&plan_eager_cross_terms(&aligned));
        let misaligned_score = named_cross_term_value(&plan_eager_cross_terms(&misaligned));

        assert_eq!(aligned_score, 1.0);
        assert_eq!(misaligned_score, 0.0);
    }

    #[test]
    fn absent_operand_propagates_instead_of_zero_fallback() {
        let node = SimilarityNode::new("symbol")
            .with_slot(
                SLOT_DOC_SEMANTIC,
                SlotVector::Absent {
                    reason: calyx_core::AbsentReason::LensUnavailable,
                },
            )
            .with_slot(SIM_SEMANTIC_SLOT, dense(&[1.0, 0.0]));

        let plan = plan_eager_cross_terms(&[node]);
        let doc = plan
            .rows
            .iter()
            .find(|row| row.kind == EagerAgreementKind::DocDrift)
            .expect("doc drift row");

        assert_eq!(
            doc.value,
            CrossTermValue::Absent {
                reason: CrossTermAbsentReason::SlotAbsent {
                    slot: SLOT_DOC_SEMANTIC
                }
            }
        );
        assert!(plan.rows.iter().all(|row| row.value.is_absent()));
        assert_eq!(plan.abundance.scalar_count, 0);
        assert_eq!(plan.abundance.absent_count, 6);
    }

    #[test]
    fn agreement_graph_means_scalars_and_counts_absent_rows() {
        let present = all_dense_cross_term_node("present");
        let absent = SimilarityNode::new("absent")
            .with_slot(SLOT_DOC_SEMANTIC, dense(&[1.0, 0.0]))
            .with_slot(
                SIM_SEMANTIC_SLOT,
                SlotVector::Absent {
                    reason: calyx_core::AbsentReason::Deferred,
                },
            );

        let plan = plan_eager_cross_terms(&[present, absent]);
        let graph = plan
            .agreement_graph
            .iter()
            .find(|edge| edge.kind == EagerAgreementKind::DocDrift)
            .expect("doc drift graph edge");

        assert_eq!(graph.mean_agreement, Some(1.0));
        assert_eq!(graph.scalar_count, 1);
        assert_eq!(graph.absent_count, 1);
        assert_eq!(plan.abundance.materialized_count, 12);
        assert_eq!(plan.abundance.raw_yield, 508);
        assert_eq!(plan.abundance.lazy_pair_count, 450);
    }

    #[test]
    fn eager_cross_term_golden_agreements_are_bit_exact() {
        // Hand-computed direct agreements (DocDrift shares the frozen semantic
        // space, so it is plain cosine): [3,4]x[3,4] = 25/(5*5) = 1.0 exactly;
        // [1,0]x[3,4] = 3/(1*5) = 0.6 (the f32 nearest to 3/5, bit-identical
        // to the 0.6f32 literal); orthogonal = 0.0 exactly.
        for (doc, code, expected) in [
            (vec![3.0f32, 4.0], vec![3.0f32, 4.0], 1.0f32),
            (vec![1.0, 0.0], vec![3.0, 4.0], 0.6),
            (vec![1.0, 0.0], vec![0.0, 4.0], 0.0),
        ] {
            let node = SimilarityNode::new("golden")
                .with_slot(SLOT_DOC_SEMANTIC, dense(&doc))
                .with_slot(SIM_SEMANTIC_SLOT, dense(&code));
            let plan = plan_eager_cross_terms(&[node]);
            let row = plan
                .rows
                .iter()
                .find(|row| row.kind == EagerAgreementKind::DocDrift)
                .expect("doc drift row");
            let CrossTermValue::Scalar(value) = row.value else {
                panic!("expected scalar for {doc:?} x {code:?}");
            };
            assert_eq!(
                value.to_bits(),
                expected.to_bits(),
                "agreement for {doc:?} x {code:?} must be bit-exact"
            );
        }

        // The same contract holds for the lazy on-demand (non-designed) path.
        let node = SimilarityNode::new("lazy")
            .with_slot(SLOT_COMPLEXITY, dense(&[1.0, 0.0]))
            .with_slot(SLOT_DOC_SEMANTIC, dense(&[3.0, 4.0]));
        let CrossTermValue::Scalar(value) =
            lazy_agreement(&node, SLOT_COMPLEXITY, SLOT_DOC_SEMANTIC)
        else {
            panic!("expected lazy scalar");
        };
        assert_eq!(value.to_bits(), 0.6f32.to_bits());
        assert!(
            lazy_agreement(&node, SLOT_CHURN, SLOT_DOC_SEMANTIC).is_absent(),
            "missing lazy operand stays absent, never zero"
        );
    }

    #[test]
    fn xterm_cf_materializes_exactly_six_designed_pairs_per_symbol() {
        // Materialization policy DoD: after weave persistence the XTerm CF
        // holds exactly the six designed agreement pairs per symbol — nothing
        // lazy, nothing extra, no Delta/Interaction/Concat rows.
        // Three frozen-panel symbols: the neighborhood comparators need two
        // comparable peers, so all six designed kinds stay scalar.
        let nodes = vec![
            frozen_panel_cross_term_node("mat.alpha", 3),
            frozen_panel_cross_term_node("mat.beta", 5),
            frozen_panel_cross_term_node("mat.gamma", 7),
        ];
        let plan = plan_eager_cross_terms(&nodes);
        assert_eq!(plan.abundance.scalar_count, 18);
        let cx_ids = BTreeMap::from([
            ("mat.alpha".to_string(), cx(31)),
            ("mat.beta".to_string(), cx(32)),
            ("mat.gamma".to_string(), cx(33)),
        ]);

        let (dir, vault) = reactive_vault("xterm-materialization");
        let report = persist_eager_cross_terms(&vault, &plan, &cx_ids, "astrolabe-weave-test")
            .expect("persist eager cross terms");
        assert_eq!(report.symbol_count, 3);
        assert_eq!(report.rows_written, 18);
        let fsv = report.fsv.as_ref().expect("XTerm mutation FSV witness");
        assert_eq!(fsv.label(), astrolabe_domain::fsv::FSV_LABEL_VERIFIED);
        assert_eq!(fsv.rows_read_back(), 18);
        assert_eq!(fsv.ledger_seq(), report.ledger_ref.seq);
        assert_eq!(report.rows_tombstoned, 0);
        assert!(report.absent_by_kind.is_empty());

        // Raw CF scan: exactly symbol_count x 6 rows exist, every one a
        // designed Agreement pair.
        let raw_rows = vault
            .scan_cf_at(vault.snapshot(), ColumnFamily::XTerm)
            .expect("scan xterm cf");
        assert_eq!(raw_rows.len(), 18);
        let persisted = read_eager_cross_term_rows(&vault).expect("read designed rows");
        assert_eq!(persisted.len(), 18);
        for symbol_cx in [cx(31), cx(32), cx(33)] {
            let kinds = persisted
                .iter()
                .filter(|row| row.row.key.cx_id == symbol_cx)
                .map(|row| row.kind)
                .collect::<Vec<_>>();
            assert_eq!(kinds.len(), 6);
            for kind in EagerAgreementKind::ALL {
                assert!(kinds.contains(&kind), "{kind} row missing for {symbol_cx}");
            }
        }
        assert!(
            persisted
                .iter()
                .all(|row| row.row.key.kind == LoomCrossTermKind::Agreement
                    && row.row.tag == SignalProvenanceTag::Derived)
        );

        // The agreement-graph aspect substrate reads the same persisted rows.
        let graph = agreement_graph_from_persisted_rows(&vault).expect("agreement graph");
        assert_eq!(graph.len(), 6);
        for edge in &graph {
            assert_eq!(edge.scalar_count, 3, "{}", edge.kind);
            assert!(edge.mean_agreement.is_some(), "{}", edge.kind);
            assert_eq!(edge.provenance, "AsterVault:ColumnFamily::XTerm:agreement");
        }
        drop(vault);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn xterm_fsv_readback_is_bit_stable_and_ledger_paired() {
        // FSV DoD: persist -> drop -> reopen -> decode raw XTerm CF bytes and
        // compare scalars bit-for-bit against an independently recomputed
        // plan; the paired ledger entry carries the canonical dump hash and
        // the abundance accounting (07 §7 output shape).
        let nodes = vec![
            frozen_panel_cross_term_node("fsv.alpha", 3),
            frozen_panel_cross_term_node("fsv.beta", 5),
            frozen_panel_cross_term_node("fsv.gamma", 7),
        ];
        let plan = plan_eager_cross_terms(&nodes);
        assert_eq!(plan.abundance.scalar_count, 18, "frozen fixture all-scalar");
        let cx_ids = BTreeMap::from([
            ("fsv.alpha".to_string(), cx(41)),
            ("fsv.beta".to_string(), cx(42)),
            ("fsv.gamma".to_string(), cx(43)),
        ]);

        let (dir, vault) = reactive_vault("xterm-fsv");
        let report = persist_eager_cross_terms(&vault, &plan, &cx_ids, "astrolabe-weave-test")
            .expect("persist eager cross terms");
        assert_eq!(report.rows_written, 18);
        drop(vault);

        let reopened = open_reactive_vault(&dir);
        let persisted = read_eager_cross_term_rows(&reopened).expect("read persisted rows");
        assert_eq!(persisted.len(), 18);

        // Independent recomputation (same code path must be bit-stable).
        let recomputed = plan_eager_cross_terms(&nodes);
        let cx_by_qn = |qn: &str| *cx_ids.get(qn).expect("cx id");
        for row in &recomputed.rows {
            let CrossTermValue::Scalar(expected) = &row.value else {
                panic!("frozen fixture must stay all-scalar");
            };
            let key = eager_xterm_key(cx_by_qn(&row.qualified_name), row.kind);
            let persisted_row = persisted
                .iter()
                .find(|candidate| candidate.key == key)
                .unwrap_or_else(|| panic!("persisted row missing for {}", row.kind));
            let LoomCrossTermValue::Scalar(actual) = persisted_row.row.value else {
                panic!("persisted row must be scalar");
            };
            // Tolerance 0: exact bit patterns.
            assert_eq!(actual.to_bits(), expected.to_bits(), "{}", row.kind);
            assert_eq!(persisted_row.row.key.a, row.left_slot);
            assert_eq!(persisted_row.row.key.b, row.right_slot);
        }

        // Ledger pairing + abundance output shape.
        let ledger_bytes = reopened
            .read_cf_at(
                reopened.snapshot(),
                ColumnFamily::Ledger,
                &calyx_aster::cf::ledger_key(report.ledger_ref.seq),
            )
            .expect("read ledger row")
            .expect("ledger row present");
        let entry = decode_ledger(&ledger_bytes).expect("decode ledger entry");
        assert_eq!(entry.entry_hash, report.ledger_ref.hash);
        let payload: serde_json::Value =
            serde_json::from_slice(&entry.payload).expect("ledger payload json");
        assert_eq!(payload["schema"], XTERM_EAGER_LEDGER_SCHEMA);
        let expected_hash = hex_lower_bytes(
            blake3::hash(&eager_xterm_dump_bytes(&recomputed, &cx_ids).expect("recomputed dump"))
                .as_bytes(),
        );
        assert_eq!(payload["xterm_dump_hash"], expected_hash);
        assert_eq!(report.xterm_dump_hash, expected_hash);
        let abundance = &payload["abundance"];
        assert_eq!(abundance["symbol_count"].as_u64(), Some(3));
        assert_eq!(abundance["panel_slot_count"].as_u64(), Some(22));
        assert_eq!(
            abundance["possible_pair_count_per_symbol"].as_u64(),
            Some(231)
        );
        assert_eq!(abundance["raw_yield"].as_u64(), Some(3 * 254));
        assert_eq!(abundance["eager_pair_count_per_symbol"].as_u64(), Some(6));
        assert_eq!(abundance["materialized_count"].as_u64(), Some(18));
        assert_eq!(abundance["scalar_count"].as_u64(), Some(18));
        assert_eq!(abundance["absent_count"].as_u64(), Some(0));
        assert_eq!(abundance["lazy_pair_count"].as_u64(), Some(3 * 225));

        // Idempotent re-persist: no rewrites, still audited.
        let second = persist_eager_cross_terms(&reopened, &plan, &cx_ids, "astrolabe-weave-test")
            .expect("idempotent persist");
        assert_eq!(second.rows_written, 0);
        assert_eq!(second.rows_unchanged, 18);
        assert_eq!(second.rows_tombstoned, 0);
        assert!(second.ledger_ref.seq > report.ledger_ref.seq);

        // Reconciliation: an absent operand tombstones the owned stale row and
        // is counted per kind — never zero-filled, never silently dropped.
        let mut degraded_nodes = nodes.clone();
        degraded_nodes[0].slots.insert(
            SLOT_DOC_SEMANTIC,
            SlotVector::Absent {
                reason: calyx_core::AbsentReason::LensUnavailable,
            },
        );
        let degraded = plan_eager_cross_terms(&degraded_nodes);
        let third =
            persist_eager_cross_terms(&reopened, &degraded, &cx_ids, "astrolabe-weave-test")
                .expect("reconciling persist");
        assert_eq!(third.rows_tombstoned, 1);
        assert_eq!(
            third.absent_by_kind.get(&EagerAgreementKind::DocDrift),
            Some(&1)
        );
        let after = read_eager_cross_term_rows(&reopened).expect("read reconciled rows");
        assert_eq!(after.len(), 17);
        drop(reopened);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn doc_drift_lying_docs_rank_top_from_persisted_state_and_honest_docs_do_not() {
        // P3 exit-gate component: on the pinned fixture corpus, a symbol whose
        // docs lie about its code ranks at the top of doc-drift findings and a
        // well-documented symbol produces no finding — evaluated from
        // persisted XTerm CF state via the live anomaly reader, not from
        // planner echoes.
        let lying = SimilarityNode::new("corpus.docs.lie")
            .with_slot(SLOT_DOC_SEMANTIC, dense(&[1.0, 0.0, 0.0]))
            .with_slot(SIM_SEMANTIC_SLOT, dense(&[0.0, 1.0, 0.0]));
        let drifting = SimilarityNode::new("corpus.docs.stale")
            .with_slot(SLOT_DOC_SEMANTIC, dense(&[1.0, 0.0, 0.0]))
            .with_slot(SIM_SEMANTIC_SLOT, dense(&[3.0, 4.0, 0.0]));
        let honest = SimilarityNode::new("corpus.docs.honest")
            .with_slot(SLOT_DOC_SEMANTIC, dense(&[3.0, 4.0, 0.0]))
            .with_slot(SIM_SEMANTIC_SLOT, dense(&[3.0, 4.0, 0.0]));
        let plan = plan_eager_cross_terms(&[lying, drifting, honest]);
        let cx_ids = BTreeMap::from([
            ("corpus.docs.lie".to_string(), cx(51)),
            ("corpus.docs.stale".to_string(), cx(52)),
            ("corpus.docs.honest".to_string(), cx(53)),
        ]);

        let (dir, vault) = reactive_vault("doc-drift-corpus");
        persist_eager_cross_terms(&vault, &plan, &cx_ids, "astrolabe-weave-test")
            .expect("persist doc drift corpus");
        vault.flush().expect("flush corpus rows");

        let inputs = live_anomaly_inputs_from_vault(&vault).expect("live anomaly inputs");
        let calibrations = vec![AnomalyCalibration::new(
            AnomalyKind::DocDrift,
            300,
            800,
            "calibration:doc-drift:v1",
        )];
        let report = detect_anomalies(&inputs.substrates, &calibrations, Some("doc_drift"), true)
            .expect("doc drift report");

        assert!(!report.findings.is_empty(), "lying docs must be findable");
        // Top finding is the lying symbol (agreement 0 => score 1000, high).
        assert_eq!(report.findings[0].subject_id, format!("cx:{}", cx(51)));
        assert_eq!(report.findings[0].severity, AnomalySeverity::High);
        assert_eq!(report.findings[0].score_millipoints, 1_000);
        // The drifting symbol (agreement 0.6 => score 400) ranks below, medium.
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.subject_id == format!("cx:{}", cx(52))
                    && finding.severity == AnomalySeverity::Medium)
        );
        // The honest symbol (agreement 1.0 => score 0) never appears.
        assert!(
            report
                .findings
                .iter()
                .all(|finding| finding.subject_id != format!("cx:{}", cx(53))),
            "well-documented symbol must not rank as doc drift"
        );
        drop(vault);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn name_truth_misleading_name_ranks_from_persisted_state() {
        // Name-truth half of the sanity gate: a symbol whose name embedding
        // aligns with a different API neighborhood than its peers ranks as a
        // name-truth anomaly from persisted state; consistent peers do not.
        // Two consistent clusters (alpha/beta named-and-calling alike, gamma
        // its own consistent cluster) plus one symbol whose name matches the
        // alpha cluster while its calls match gamma's: its name-similarity and
        // API-similarity peer profiles are orthogonal (agreement 0), while
        // alpha's stay positively aligned.
        let corpus = vec![
            name_truth_frozen_node("corpus.name.alpha", 0, 0),
            name_truth_frozen_node("corpus.name.beta", 0, 0),
            name_truth_frozen_node("corpus.name.gamma", 1, 1),
            name_truth_frozen_node("corpus.name.misleads", 0, 1),
        ];
        let plan = plan_eager_cross_terms(&corpus);
        let cx_ids = BTreeMap::from([
            ("corpus.name.alpha".to_string(), cx(61)),
            ("corpus.name.beta".to_string(), cx(64)),
            ("corpus.name.gamma".to_string(), cx(63)),
            ("corpus.name.misleads".to_string(), cx(62)),
        ]);

        let (dir, vault) = reactive_vault("name-truth-corpus");
        persist_eager_cross_terms(&vault, &plan, &cx_ids, "astrolabe-weave-test")
            .expect("persist name truth corpus");

        let inputs = live_anomaly_inputs_from_vault(&vault).expect("live anomaly inputs");
        let calibrations = vec![AnomalyCalibration::new(
            AnomalyKind::NameTruth,
            500,
            900,
            "calibration:name-truth:v1",
        )];
        let report = detect_anomalies(&inputs.substrates, &calibrations, Some("name_truth"), true)
            .expect("name truth report");

        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.subject_id == format!("cx:{}", cx(62))),
            "misleading name must rank as a name-truth anomaly: {:?}",
            report
                .findings
                .iter()
                .map(|finding| finding.subject_id.clone())
                .collect::<Vec<_>>()
        );
        assert!(
            report
                .findings
                .iter()
                .all(|finding| finding.subject_id != format!("cx:{}", cx(61))),
            "a consistently named symbol must not rank as a name-truth anomaly"
        );
        drop(vault);
        let _ = fs::remove_dir_all(dir);
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(64))]

        /// Absent-propagation DoD: for every designed pair, degrading either
        /// operand slot of one symbol (missing, explicit Absent, unsupported
        /// multi shape, or zero norm) makes that symbol's cross-term Absent —
        /// never a zero-filled scalar — regardless of the surrounding corpus.
        #[test]
        fn any_absent_input_slot_propagates_to_absent_cross_term(
            kind_index in 0usize..EagerAgreementKind::ALL.len(),
            degrade_left in proptest::bool::ANY,
            degrade_mode in 0u8..4,
            peer_seed in 1u32..64,
        ) {
            let kind = EagerAgreementKind::ALL[kind_index];
            let (left_slot, right_slot) = kind.slots();
            let degraded_slot = if degrade_left { left_slot } else { right_slot };

            // A healthy 3-node corpus (peers keep neighborhood kinds scalar).
            let mut nodes = (0u32..3)
                .map(|index| {
                    let mut node = SimilarityNode::new(format!("prop-{index}"));
                    for slot in [
                        SLOT_DOC_SEMANTIC, SIM_SEMANTIC_SLOT, SLOT_NAME_SEMANTIC,
                        SIM_API_SLOT, SIM_STRUCT_SLOT, SLOT_COMPLEXITY, SLOT_CHURN,
                        SLOT_GRAPH_POSITION, SLOT_TEST_COVERAGE, SLOT_ROUTE_MATCH,
                    ] {
                        let component = ((peer_seed + index + u32::from(slot.get())) % 7 + 1) as f32;
                        node = node.with_slot(slot, dense(&[component, 1.0]));
                    }
                    node
                })
                .collect::<Vec<_>>();

            match degrade_mode {
                0 => {
                    nodes[0].slots.remove(&degraded_slot);
                }
                1 => {
                    nodes[0].slots.insert(
                        degraded_slot,
                        SlotVector::Absent { reason: calyx_core::AbsentReason::Deferred },
                    );
                }
                2 => {
                    nodes[0].slots.insert(
                        degraded_slot,
                        SlotVector::Multi { token_dim: 2, tokens: vec![vec![1.0, 0.0]] },
                    );
                }
                _ => {
                    nodes[0].slots.insert(degraded_slot, dense(&[0.0, 0.0]));
                }
            }

            let plan = plan_eager_cross_terms(&nodes);
            let row = plan
                .rows
                .iter()
                .find(|row| row.qualified_name == "prop-0" && row.kind == kind)
                .expect("designed row for degraded symbol");
            proptest::prop_assert!(
                row.value.is_absent(),
                "{kind} must be absent when {degraded_slot:?} is degraded (mode {degrade_mode}), got {:?}",
                row.value
            );
        }
    }

    fn struct_only_config() -> SimilarityPlannerConfig {
        family_only_config(SimilarityFamily::Struct)
    }

    /// Exact-pairs config for one family: these fixtures pin the exhaustive
    /// planner core (candidate universe = all pairs), which the ANN tests use
    /// as their ground truth.
    fn family_only_config(family: SimilarityFamily) -> SimilarityPlannerConfig {
        let disabled_families = SimilarityFamily::ALL
            .into_iter()
            .filter(|candidate| *candidate != family)
            .collect();
        let candidate_strategies = SimilarityFamily::ALL
            .into_iter()
            .map(|family| (family, SimilarityCandidateStrategy::ExactPairs))
            .collect();
        SimilarityPlannerConfig {
            disabled_families,
            exact_pair_node_limit: None,
            candidate_strategies,
            ..SimilarityPlannerConfig::default()
        }
    }

    /// ANN-strategy config for one family (LSH for sparse pools, quantized
    /// HNSW for dense pools).
    fn ann_family_config(family: SimilarityFamily) -> SimilarityPlannerConfig {
        let mut config = family_only_config(family);
        config
            .candidate_strategies
            .insert(family, SimilarityCandidateStrategy::Ann);
        config
    }

    fn dense_node(qn: &str, family: SimilarityFamily, data: &[f32]) -> SimilarityNode {
        SimilarityNode::new(qn).with_slot(
            family.slot(),
            SlotVector::Dense {
                dim: data.len() as u32,
                data: data.to_vec(),
            },
        )
    }

    fn all_dense_cross_term_node(qn: &str) -> SimilarityNode {
        SimilarityNode::new(qn)
            .with_slot(SLOT_DOC_SEMANTIC, dense(&[1.0, 0.0]))
            .with_slot(SIM_SEMANTIC_SLOT, dense(&[1.0, 0.0]))
            .with_slot(SLOT_NAME_SEMANTIC, dense(&[1.0, 0.0]))
            .with_slot(SIM_API_SLOT, dense(&[1.0, 0.0]))
            .with_slot(SIM_STRUCT_SLOT, dense(&[1.0, 0.0]))
            .with_slot(SLOT_COMPLEXITY, dense(&[1.0, 0.0]))
            .with_slot(SLOT_CHURN, dense(&[1.0, 0.0]))
            .with_slot(SLOT_GRAPH_POSITION, dense(&[1.0, 0.0]))
            .with_slot(SLOT_TEST_COVERAGE, dense(&[1.0, 0.0]))
            .with_slot(SLOT_ROUTE_MATCH, dense(&[1.0, 0.0]))
    }

    fn frozen_panel_cross_term_node(qn: &str, source_len: usize) -> SimilarityNode {
        let mut input = PanelInput::fixture(SymbolLabel::Function);
        input.source_bytes = vec![b'x'; source_len];
        let readout = PanelDriver::default()
            .measure(&input, &FixtureSlotRuntime)
            .expect("frozen panel readout");
        SimilarityNode {
            qualified_name: qn.to_string(),
            slots: readout.slots,
        }
    }

    fn name_truth_frozen_node(qn: &str, name_index: usize, api_index: u32) -> SimilarityNode {
        let mut name = vec![0.0; 768];
        name[name_index] = 1.0;
        SimilarityNode::new(qn)
            .with_slot(
                SLOT_NAME_SEMANTIC,
                SlotVector::Dense {
                    dim: 768,
                    data: name,
                },
            )
            .with_slot(
                SIM_API_SLOT,
                SlotVector::Sparse {
                    dim: 262_144,
                    entries: vec![SparseEntry {
                        idx: api_index,
                        val: 1.0,
                    }],
                },
            )
    }

    fn named_cross_term_value(plan: &EagerCrossTermPlan) -> f32 {
        match plan
            .rows
            .iter()
            .find(|row| {
                row.qualified_name == "symbol.alpha" && row.kind == EagerAgreementKind::NameTruth
            })
            .expect("name-truth row")
            .value
        {
            CrossTermValue::Scalar(value) => value,
            CrossTermValue::Absent { ref reason } => panic!("expected scalar, got {reason:?}"),
        }
    }

    fn dense(data: &[f32]) -> SlotVector {
        SlotVector::Dense {
            dim: data.len() as u32,
            data: data.to_vec(),
        }
    }

    fn sparse_node(
        qn: &str,
        family: SimilarityFamily,
        dim: u32,
        entries: &[(u32, f32)],
    ) -> SimilarityNode {
        SimilarityNode::new(qn).with_slot(
            family.slot(),
            SlotVector::Sparse {
                dim,
                entries: entries
                    .iter()
                    .map(|(idx, val)| SparseEntry {
                        idx: *idx,
                        val: *val,
                    })
                    .collect(),
            },
        )
    }

    fn edge_qns(edges: &[SimilarityEdge]) -> Vec<(&str, &str)> {
        edges
            .iter()
            .map(|edge| (edge.source_qn.as_str(), edge.target_qn.as_str()))
            .collect()
    }

    fn anomaly_fixture_rows() -> Vec<AnomalySubstrateRow> {
        let mut rows = Vec::new();
        for (row, provenance) in [
            (
                eager_cross_term_row(
                    "demo.docs.lie",
                    EagerAgreementKind::DocDrift,
                    SLOT_DOC_SEMANTIC,
                    SIM_SEMANTIC_SLOT,
                    0.10,
                ),
                "xterm:doc-bad",
            ),
            (
                eager_cross_term_row(
                    "demo.docs.clean",
                    EagerAgreementKind::DocDrift,
                    SLOT_DOC_SEMANTIC,
                    SIM_SEMANTIC_SLOT,
                    0.95,
                ),
                "xterm:doc-clean",
            ),
            (
                eager_cross_term_row(
                    "demo.name.misleads",
                    EagerAgreementKind::NameTruth,
                    SLOT_NAME_SEMANTIC,
                    SIM_API_SLOT,
                    0.40,
                ),
                "xterm:name-bad",
            ),
            (
                eager_cross_term_row(
                    "demo.name.clean",
                    EagerAgreementKind::NameTruth,
                    SLOT_NAME_SEMANTIC,
                    SIM_API_SLOT,
                    0.96,
                ),
                "xterm:name-clean",
            ),
        ] {
            rows.push(
                anomaly_substrate_row_from_eager_cross_term(&row, provenance)
                    .expect("xterm row converts to anomaly substrate"),
            );
        }
        rows.push(AnomalySubstrateRow::new(
            AnomalyKind::Drift,
            "slot:S18:week-2026-27",
            850,
            "MMD drift alarm for semantic slot",
            ["assay:mmd:slot18:week27"],
            ["MMD:S18", "guard_reject_rate:S18"],
        ));
        rows.push(AnomalySubstrateRow::new(
            AnomalyKind::OodCommit,
            "commit:alien-1",
            950,
            "NewRegion trigger for committed alien code",
            ["reactive:new-region:alien-1", "commit:alien-1"],
            ["NewRegion", "S18"],
        ));
        rows
    }

    fn anomaly_calibrations() -> Vec<AnomalyCalibration> {
        vec![
            AnomalyCalibration::new(AnomalyKind::DocDrift, 500, 800, "calibration:doc-drift:v1"),
            AnomalyCalibration::new(
                AnomalyKind::NameTruth,
                500,
                800,
                "calibration:name-truth:v1",
            ),
            AnomalyCalibration::new(AnomalyKind::Drift, 500, 800, "calibration:drift:v1"),
            AnomalyCalibration::new(
                AnomalyKind::OodCommit,
                500,
                800,
                "calibration:ood-commit:v1",
            ),
        ]
    }

    fn eager_cross_term_row(
        qualified_name: &str,
        kind: EagerAgreementKind,
        left_slot: SlotId,
        right_slot: SlotId,
        value: f32,
    ) -> EagerCrossTermRow {
        EagerCrossTermRow {
            qualified_name: qualified_name.to_string(),
            kind,
            left_slot,
            right_slot,
            value: CrossTermValue::Scalar(value),
            persisted: true,
        }
    }

    fn has_vector_skip(
        plan: &SimilarityPlan,
        qn: &str,
        reason: SimilarityVectorSkipReason,
    ) -> bool {
        plan.skips.vector_skips.iter().any(|skip| {
            skip.qualified_name == qn
                && skip.family == SimilarityFamily::Semantic
                && skip.reason == reason
        })
    }

    struct ScriptedReactiveSignals {
        occurrence: Cell<u64>,
        novelty: NoveltyVerdict,
        drift: f32,
    }

    impl ScriptedReactiveSignals {
        fn grounded() -> Self {
            Self::with_novelty_and_drift(NoveltyVerdict::Grounded, 0.0)
        }

        fn with_novelty_and_drift(novelty: NoveltyVerdict, drift: f32) -> Self {
            Self {
                occurrence: Cell::new(0),
                novelty,
                drift,
            }
        }
    }

    impl ReactiveSignals for ScriptedReactiveSignals {
        fn novelty(&self, _cx_id: CxId, _tau_override: Option<f32>) -> CalyxResult<NoveltyVerdict> {
            Ok(self.novelty)
        }

        fn occurrence_count(&self, _series: CxId) -> CalyxResult<u64> {
            let next = self.occurrence.get() + 1;
            self.occurrence.set(next);
            Ok(next)
        }

        fn slot_drift(&self, _slot: SlotId) -> CalyxResult<f32> {
            Ok(self.drift)
        }
    }

    fn reactive_vault(name: &str) -> (PathBuf, AsterVault<SystemClock>) {
        let dir = std::env::temp_dir().join(format!(
            "astrolabe-weave-reactive-{name}-{}-{}",
            std::process::id(),
            NEXT_REACTIVE_DIR.fetch_add(1, AtomicOrdering::Relaxed)
        ));
        clean_dir(&dir);
        let vault = open_reactive_vault(&dir);
        (dir, vault)
    }

    fn open_reactive_vault(dir: &Path) -> AsterVault<SystemClock> {
        AsterVault::new_durable(
            dir,
            reactive_vault_id(),
            REACTIVE_TEST_SALT.to_vec(),
            VaultOptions::default(),
        )
        .expect("open durable reactive vault")
    }

    fn clean_dir(dir: &Path) {
        let _ = fs::remove_dir_all(dir);
        fs::create_dir_all(dir).expect("create test vault dir");
    }

    fn all_audit_entries(vault: &AsterVault<SystemClock>) -> Vec<ReactiveAuditEntry> {
        reactive_rows(vault)
            .into_iter()
            .filter_map(|(key, value)| {
                let parts = reactive_row_key(&key).expect("reactive row key");
                (parts.kind == ReactiveRowKind::Audit)
                    .then(|| decode_audit_entry(&value).expect("reactive audit row"))
            })
            .collect()
    }

    fn audit_entries(
        vault: &AsterVault<SystemClock>,
        trigger: TriggerId,
    ) -> Vec<ReactiveAuditEntry> {
        all_audit_entries(vault)
            .into_iter()
            .filter(|entry| entry.trigger_id == trigger)
            .collect()
    }

    fn fired_events(vault: &AsterVault<SystemClock>) -> Vec<TriggerFired> {
        reactive_rows(vault)
            .into_iter()
            .filter_map(|(key, value)| {
                let parts = reactive_row_key(&key).expect("reactive row key");
                (parts.kind == ReactiveRowKind::Fired)
                    .then(|| decode_trigger_fired(&value).expect("reactive fired row"))
            })
            .collect()
    }

    fn reactive_rows(vault: &AsterVault<SystemClock>) -> Vec<(Vec<u8>, Vec<u8>)> {
        vault
            .scan_cf_at(vault.snapshot(), ColumnFamily::Reactive)
            .expect("scan reactive CF")
    }

    fn reactive_ack_payloads(vault: &AsterVault<SystemClock>) -> Vec<serde_json::Value> {
        vault
            .scan_cf_at(vault.snapshot(), ColumnFamily::Ledger)
            .expect("scan ledger CF")
            .into_iter()
            .filter_map(|(_key, value)| {
                let entry = calyx_ledger::decode(&value).expect("decode ledger row");
                let payload: serde_json::Value = serde_json::from_slice(&entry.payload).ok()?;
                (payload.get("tag").and_then(serde_json::Value::as_str)
                    == Some(ASTROLABE_REACTIVE_ACK_TAG))
                .then_some(payload)
            })
            .collect()
    }

    #[cfg(target_os = "linux")]
    fn resident_set_bytes() -> u64 {
        let smaps = fs::read_to_string("/proc/self/smaps_rollup").expect("read smaps_rollup");
        smaps
            .lines()
            .find_map(|line| {
                let mut parts = line.split_whitespace();
                match (parts.next(), parts.next(), parts.next()) {
                    (Some("Rss:"), Some(kib), Some("kB")) => {
                        Some(kib.parse::<u64>().expect("parse Rss kB") * 1024)
                    }
                    _ => None,
                }
            })
            .expect("Rss line in smaps_rollup")
    }

    /// Native Windows resident-set probe for the churn soak slice.
    ///
    /// `astrolabe-weave` forbids `unsafe`, so instead of a direct
    /// `GetProcessMemoryInfo` FFI call this shells out to PowerShell for the
    /// process's working set — the Windows analogue of Linux `Rss` — which is
    /// exact enough for the 512 MiB soak delta bound.
    #[cfg(target_os = "windows")]
    fn resident_set_bytes() -> u64 {
        let output = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!("(Get-Process -Id {}).WorkingSet64", std::process::id()),
            ])
            .output()
            .expect("query working set via powershell");
        assert!(
            output.status.success(),
            "powershell working-set query failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("utf8 working set")
            .trim()
            .parse::<u64>()
            .expect("parse working set bytes")
    }

    fn cx(byte: u8) -> CxId {
        CxId::from_bytes([byte; 16])
    }

    fn lref(seq: u64) -> LedgerRef {
        LedgerRef {
            seq,
            hash: [seq as u8; 32],
        }
    }

    fn reactive_vault_id() -> VaultId {
        "01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap()
    }

    // --- Blind-spot sweep (#36) FSV fixtures & tests ----------------------

    fn dense2(x: f32, y: f32) -> SlotVector {
        SlotVector::Dense {
            dim: 2,
            data: vec![x, y],
        }
    }

    /// A symbol carrying a struct (confident) and semantic (neighbor) lens.
    fn blind_spot_node(
        name: &str,
        struct_vec: SlotVector,
        semantic_vec: SlotVector,
    ) -> SimilarityNode {
        SimilarityNode::new(name)
            .with_slot(SIM_STRUCT_SLOT, struct_vec)
            .with_slot(SIM_SEMANTIC_SLOT, semantic_vec)
    }

    /// Eight-member conforming cluster (struct & semantic both [1,0], so cluster
    /// members are structurally AND semantically identical) plus one planted
    /// symbol that is structurally similar to the cluster (struct cosine 0.8) but
    /// semantically alien (semantic cosine 0.0). Hand-computable: every cluster
    /// member scores gap 0; the planted symbol scores gap 800 millipoints.
    fn planted_blind_spot_corpus() -> Vec<SimilarityNode> {
        let mut nodes = Vec::new();
        for i in 0..8 {
            nodes.push(blind_spot_node(
                &format!("cluster.c{i}"),
                dense2(1.0, 0.0),
                dense2(1.0, 0.0),
            ));
        }
        // [0.8, 0.6] has unit norm and cosine 0.8 with [1,0]; [0,1] is orthogonal
        // (cosine 0.0) to the cluster's semantic vector.
        nodes.push(blind_spot_node(
            "planted.alien",
            dense2(0.8, 0.6),
            dense2(0.0, 1.0),
        ));
        nodes
    }

    fn struct_semantic_pair() -> BlindSpotLensPair {
        BlindSpotLensPair::new(SimilarityFamily::Struct, SimilarityFamily::Semantic)
    }

    #[test]
    fn blind_spot_flags_planted_symbol_and_spares_the_clean_cluster() {
        let nodes = planted_blind_spot_corpus();
        let sweep = blind_spot_sweep(&nodes, struct_semantic_pair(), &BlindSpotConfig::default())
            .expect("sweep runs");

        // Hand-computable scores: eight zeros and one 800.
        assert_eq!(sweep.n_eff, 9);
        let planted = sweep
            .scores
            .iter()
            .find(|score| score.qualified_name == "planted.alien")
            .expect("planted scored");
        assert_eq!(planted.confident_sim_millipoints, 800);
        assert_eq!(planted.neighbor_mean_millipoints, 0);
        assert_eq!(planted.gap_millipoints, 800);
        for score in &sweep.scores {
            if score.qualified_name != "planted.alien" {
                assert_eq!(
                    score.gap_millipoints, 0,
                    "{} is clean",
                    score.qualified_name
                );
            }
        }

        // Calibration measured from the corpus's own gap distribution.
        let distribution = sweep.distribution.as_ref().expect("calibrated");
        assert_eq!(distribution.medium_min_score_millipoints, 340);
        assert_eq!(distribution.high_min_score_millipoints, 592);

        // Tiered findings: only the planted symbol, at high severity; FPR = 0.
        let report = detect_anomalies(
            &sweep.substrates,
            &sweep.calibrations(),
            Some("blind_spot"),
            true,
        )
        .expect("tier findings");
        assert_eq!(report.findings.len(), 1);
        let finding = &report.findings[0];
        assert_eq!(finding.subject_id, "planted.alien");
        assert_eq!(finding.severity, AnomalySeverity::High);
        assert!(
            report
                .findings
                .iter()
                .all(|f| !f.subject_id.starts_with("cluster."))
        );
    }

    #[test]
    fn blind_spot_report_carries_severity_evidence_trust_and_provenance() {
        let nodes = planted_blind_spot_corpus();
        let (sweep, report) = blind_spot_report(
            &nodes,
            struct_semantic_pair(),
            &BlindSpotConfig::default(),
            true,
        )
        .expect("report");

        assert_eq!(report.schema, DETECT_ANOMALIES_SCHEMA);
        assert_eq!(report.kind_filter, Some(AnomalyKind::BlindSpot));
        assert_eq!(report.trust, "verified");
        let finding = report
            .findings
            .iter()
            .find(|f| f.subject_id == "planted.alien")
            .expect("planted finding");
        assert_eq!(finding.kind, AnomalyKind::BlindSpot);
        assert_eq!(finding.severity, AnomalySeverity::High);
        // Per-lens evidence names both lenses.
        assert!(
            finding
                .lens_evidence
                .iter()
                .any(|e| e.contains("SIM_STRUCT"))
        );
        assert!(
            finding
                .lens_evidence
                .iter()
                .any(|e| e.contains("SIM_SEMANTIC"))
        );
        // Substrate + calibration provenance are populated.
        assert!(
            finding
                .substrate_provenance_refs
                .iter()
                .any(|p| p.contains("blind_spot_sweep:SIM_STRUCTxSIM_SEMANTIC"))
        );
        assert_eq!(
            finding.calibration_provenance_ref,
            sweep.distribution.as_ref().unwrap().provenance_ref
        );
        assert!(finding.freshness == "fresh");
    }

    #[test]
    fn blind_spot_cold_start_marks_findings_provisional() {
        let nodes = planted_blind_spot_corpus();
        let (_, report) = blind_spot_report(
            &nodes,
            struct_semantic_pair(),
            &BlindSpotConfig::default(),
            false,
        )
        .expect("cold-start report");
        // The sweep still runs and flags the planted symbol, but provisionally.
        assert_eq!(report.trust, "provisional");
        assert!(!report.findings.is_empty());
        assert!(report.findings.iter().all(|f| f.trust == "provisional"));
    }

    #[test]
    fn blind_spot_calibration_differs_across_corpora_with_different_spreads() {
        let wide = planted_blind_spot_corpus();
        // A tighter corpus: the planted symbol is only mildly semantically off
        // ([0.6, 0.8] has cosine 0.6 with [1,0]), so its gap is 800-600=200.
        let mut tight = Vec::new();
        for i in 0..8 {
            tight.push(blind_spot_node(
                &format!("cluster.c{i}"),
                dense2(1.0, 0.0),
                dense2(1.0, 0.0),
            ));
        }
        tight.push(blind_spot_node(
            "planted.alien",
            dense2(0.8, 0.6),
            dense2(0.6, 0.8),
        ));

        let wide_sweep =
            blind_spot_sweep(&wide, struct_semantic_pair(), &BlindSpotConfig::default())
                .expect("wide");
        let tight_sweep =
            blind_spot_sweep(&tight, struct_semantic_pair(), &BlindSpotConfig::default())
                .expect("tight");
        let wide_high = wide_sweep
            .distribution
            .as_ref()
            .unwrap()
            .high_min_score_millipoints;
        let tight_high = tight_sweep
            .distribution
            .as_ref()
            .unwrap()
            .high_min_score_millipoints;
        assert_ne!(
            wide_high, tight_high,
            "distinct gap spreads must yield distinct calibrated thresholds"
        );
    }

    #[test]
    fn blind_spot_sweep_is_deterministic_regardless_of_node_order() {
        let nodes = planted_blind_spot_corpus();
        let mut shuffled = nodes.clone();
        shuffled.reverse();
        shuffled.swap(0, 3);
        let first = blind_spot_sweep(&nodes, struct_semantic_pair(), &BlindSpotConfig::default())
            .expect("first");
        let second = blind_spot_sweep(
            &shuffled,
            struct_semantic_pair(),
            &BlindSpotConfig::default(),
        )
        .expect("second");
        assert_eq!(first, second);
    }

    #[test]
    fn blind_spot_persisted_calibration_and_report_read_back() {
        let nodes = planted_blind_spot_corpus();
        let (sweep, report) = blind_spot_report(
            &nodes,
            struct_semantic_pair(),
            &BlindSpotConfig::default(),
            true,
        )
        .expect("report");

        // Persist the measured calibration, read the bytes back off disk, and
        // confirm they re-parse to the same value (FSV of the calibration).
        let distribution = sweep.distribution.as_ref().expect("calibrated");
        let cal_bytes = astrolabe_assay::calibration_dump_bytes(distribution);
        let cal_path = std::env::temp_dir().join(format!(
            "astrolabe-blindspot-cal-{}.json",
            std::process::id()
        ));
        std::fs::write(&cal_path, &cal_bytes).expect("write calibration");
        let cal_read = std::fs::read(&cal_path).expect("read calibration");
        std::fs::remove_file(&cal_path).ok();
        let reparsed =
            astrolabe_assay::read_calibration_bytes(&cal_read).expect("reparse calibration");
        assert_eq!(&reparsed, distribution);

        // Persist the tiered report artifact and read it back (FSV of the sweep
        // result).
        let report_bytes = anomaly_report_artifact_bytes(&report);
        let report_path = std::env::temp_dir().join(format!(
            "astrolabe-blindspot-report-{}.txt",
            std::process::id()
        ));
        std::fs::write(&report_path, &report_bytes).expect("write report");
        let report_read = std::fs::read(&report_path).expect("read report");
        std::fs::remove_file(&report_path).ok();
        assert_eq!(report_read, report_bytes);
        assert!(
            String::from_utf8(report_read)
                .unwrap()
                .contains("planted.alien")
        );
    }

    #[test]
    fn blind_spot_empty_corpus_refuses_calibration_with_below_floor_deficit() {
        let sweep = blind_spot_sweep(&[], struct_semantic_pair(), &BlindSpotConfig::default())
            .expect("empty sweep runs");
        assert!(sweep.scores.is_empty());
        assert!(sweep.substrates.is_empty());
        assert!(sweep.calibration.is_none());
        let deficit = sweep.deficit.expect("deficit labeled");
        assert_eq!(
            deficit.code,
            astrolabe_assay::error::ASTRO_ASSAY_CALIBRATION_BELOW_FLOOR
        );
        assert_eq!(deficit.n_eff, 0);
    }

    #[test]
    fn blind_spot_single_lens_corpus_skips_every_symbol() {
        // Only the confident (struct) lens is present — no neighbor lens exists.
        let nodes: Vec<SimilarityNode> = (0..9)
            .map(|i| {
                SimilarityNode::new(format!("s{i}")).with_slot(SIM_STRUCT_SLOT, dense2(1.0, 0.0))
            })
            .collect();
        let sweep = blind_spot_sweep(&nodes, struct_semantic_pair(), &BlindSpotConfig::default())
            .expect("single-lens sweep runs");
        assert!(sweep.scores.is_empty());
        assert_eq!(sweep.skipped.len(), 9);
        assert!(
            sweep
                .skipped
                .iter()
                .all(|s| s.reason == BlindSpotSkipReason::MissingNeighborLens)
        );
        assert!(sweep.calibration.is_none());
        assert_eq!(
            sweep.deficit.unwrap().code,
            astrolabe_assay::error::ASTRO_ASSAY_CALIBRATION_BELOW_FLOOR
        );
    }

    #[test]
    fn blind_spot_all_identical_vectors_refuse_as_degenerate_and_flag_nothing() {
        // Ten symbols identical in BOTH lenses: every gap is 0, so the gap
        // distribution has zero spread — the zero-signal negative control.
        let nodes: Vec<SimilarityNode> = (0..10)
            .map(|i| blind_spot_node(&format!("id{i}"), dense2(1.0, 0.0), dense2(1.0, 0.0)))
            .collect();
        let sweep = blind_spot_sweep(&nodes, struct_semantic_pair(), &BlindSpotConfig::default())
            .expect("degenerate sweep runs");
        // Before: every symbol WAS scored (gap 0).
        assert_eq!(sweep.scores.len(), 10);
        assert!(sweep.scores.iter().all(|s| s.gap_millipoints == 0));
        // After: calibration refuses, so nothing is tiered.
        assert!(sweep.calibration.is_none());
        assert_eq!(
            sweep.deficit.as_ref().unwrap().code,
            astrolabe_assay::error::ASTRO_ASSAY_CALIBRATION_DEGENERATE
        );
        let report = detect_anomalies(
            &sweep.substrates,
            &sweep.calibrations(),
            Some("blind_spot"),
            true,
        )
        .expect("tier");
        assert!(report.findings.is_empty());
        assert_eq!(report.skipped.len(), 10);
    }

    #[test]
    fn blind_spot_rejects_same_family_pair_and_bad_config() {
        let nodes = planted_blind_spot_corpus();
        let err = blind_spot_sweep(
            &nodes,
            BlindSpotLensPair::new(SimilarityFamily::Struct, SimilarityFamily::Struct),
            &BlindSpotConfig::default(),
        )
        .expect_err("same-family pair refused");
        assert_eq!(err.code(), ASTRO_BLIND_SPOT_INVALID_PAIR);

        let mut bad = BlindSpotConfig::default();
        bad.min_neighbors = bad.neighbor_cap + 1;
        let err =
            blind_spot_sweep(&nodes, struct_semantic_pair(), &bad).expect_err("bad config refused");
        assert_eq!(err.code(), ASTRO_BLIND_SPOT_INVALID_CONFIG);
    }

    #[test]
    fn blind_spot_anomaly_inputs_flags_planted_alien_via_default_pair_and_is_deterministic() {
        // The live merge path (#36 server clause): the default (Struct-confident,
        // Semantic-neighbor) pair over the planted corpus surfaces the one alien
        // symbol and spares the clean cluster (FPR=0), and the merged inputs are a
        // deterministic function of the corpus regardless of node order.
        let nodes = planted_blind_spot_corpus();
        let merged = blind_spot_anomaly_inputs(
            &nodes,
            &DEFAULT_BLIND_SPOT_PAIRS,
            &BlindSpotConfig::default(),
        )
        .expect("aggregate blind-spot sweep");

        assert_eq!(merged.scored_symbols, 9);
        assert_eq!(
            merged.calibrations.len(),
            1,
            "one calibration for the one pair"
        );
        assert!(
            merged.deficits.is_empty(),
            "calibration succeeded, no deficit"
        );
        let planted = merged
            .substrates
            .iter()
            .find(|substrate| substrate.subject_id == "planted.alien")
            .expect("planted substrate present");
        assert_eq!(planted.kind, AnomalyKind::BlindSpot);
        assert_eq!(planted.score_millipoints, 800);

        // Order invariance: reversing the corpus yields byte-identical inputs.
        let mut reversed = nodes.clone();
        reversed.reverse();
        let merged_reversed = blind_spot_anomaly_inputs(
            &reversed,
            &DEFAULT_BLIND_SPOT_PAIRS,
            &BlindSpotConfig::default(),
        )
        .expect("aggregate blind-spot sweep (reordered)");
        assert_eq!(merged, merged_reversed);

        // Tiered through the shared aggregator: only the planted symbol, no
        // cluster member (false-positive rate zero on the clean cluster).
        let report = detect_anomalies(
            &merged.substrates,
            &merged.calibrations,
            Some("blind_spot"),
            true,
        )
        .expect("tier blind-spot findings");
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].subject_id, "planted.alien");
        assert!(
            report
                .findings
                .iter()
                .all(|finding| !finding.subject_id.starts_with("cluster."))
        );
    }

    #[test]
    fn drift_cards_payload_surfaces_measured_mmd_alarm_and_spares_stable_slots() {
        // #33's real MMD DriftCards, persisted as an Assay CF `drift_cards`
        // payload, flow through the live read path into the `drift` anomaly kind:
        // a planted distribution shift is flagged; slots with identical reference
        // and new samples are not (FPR on the calibrated distribution).
        let cfg = astrolabe_assay::DiffConfig::from_defaults().expect("diff config");
        let reference: Vec<Vec<f64>> = (0..12).map(|i| vec![f64::from(i) * 0.01]).collect();

        let mut cards = Vec::new();
        // Eight stable slots (new sample == reference): no drift, score 0. These
        // also clear the calibration floor so the measured thresholds exist.
        for i in 0..8 {
            let card = astrolabe_assay::measure_drift(
                format!("stable_slot_{i}"),
                &reference,
                &reference,
                3,
                &cfg,
            )
            .expect("stable drift card");
            assert!(!card.drift_detected, "identical samples must not drift");
            cards.push(card);
        }
        // One planted distribution shift: the new sample is translated far away.
        let sample: Vec<Vec<f64>> = (0..12).map(|i| vec![5.0 + f64::from(i) * 0.01]).collect();
        let drifted = astrolabe_assay::measure_drift("S18_semantic", &reference, &sample, 3, &cfg)
            .expect("drifted card");
        assert!(drifted.drift_detected, "planted shift must be detected");
        cards.push(drifted);

        let (dir, vault) = reactive_vault("drift-cards");
        let mut assay = AssayStore::default();
        assay.put_with_payload(
            AssayCacheKey::scoped(9, "week-2026-28", reactive_vault_id(), AnchorKind::Reward),
            AssaySubject::Panel,
            MiEstimate::point(1.0, 16, EstimatorKind::PanelSufficiency, TrustTag::Trusted),
            "assay:mmd:driftcards:week28",
            vault.snapshot(),
            json!({
                "schema": ASSAY_ANOMALY_PAYLOAD_SCHEMA,
                "drift_cards": cards
                    .iter()
                    .map(|card| serde_json::to_value(card).expect("serialize drift card"))
                    .collect::<Vec<_>>(),
            }),
        );
        assay
            .persist_to_vault(&vault)
            .expect("persist drift-card assay row");
        vault.flush().expect("flush drift-card CF rows");

        // Independent readback: reopen the vault and rebuild the report from the
        // persisted Assay bytes.
        let reopened = open_reactive_vault(&dir);
        let inputs = live_anomaly_inputs_from_vault(&reopened).expect("live drift inputs");
        assert_eq!(inputs.skipped_rows, 0, "every drift card parsed");
        // Nine substrate rows (8 stable + 1 drifted) plus one measured calibration.
        assert_eq!(
            inputs
                .substrates
                .iter()
                .filter(|substrate| substrate.kind == AnomalyKind::Drift)
                .count(),
            9
        );
        assert_eq!(
            inputs
                .calibrations
                .iter()
                .filter(|calibration| calibration.kind == AnomalyKind::Drift)
                .count(),
            1
        );

        let report = detect_anomalies(
            &inputs.substrates,
            &inputs.calibrations,
            Some("drift"),
            true,
        )
        .expect("tier drift findings");
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.subject_id == "slot:S18_semantic"),
            "planted-shift slot must surface as a drift finding: {:?}",
            report
                .findings
                .iter()
                .map(|finding| finding.subject_id.clone())
                .collect::<Vec<_>>()
        );
        assert!(
            report
                .findings
                .iter()
                .all(|finding| !finding.subject_id.starts_with("slot:stable_slot_")),
            "stable slots must not be flagged"
        );
        // The finding carries the assay substrate provenance (substrate honesty).
        let finding = report
            .findings
            .iter()
            .find(|finding| finding.subject_id == "slot:S18_semantic")
            .expect("drift finding");
        assert!(
            finding
                .substrate_provenance_refs
                .iter()
                .any(|reference| reference.contains("assay:mmd:driftcards:week28")),
            "drift finding must reference its assay substrate row"
        );

        drop(reopened);
        drop(vault);
        let _ = fs::remove_dir_all(dir);
    }
}
