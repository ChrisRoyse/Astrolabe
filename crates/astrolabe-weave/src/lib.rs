#![forbid(unsafe_code)]

pub mod kernel_index;
pub mod knobs;
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
use calyx_ledger::{ActorId, EntryKind, SubjectId};
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
mod complete_xterms;
pub mod drift_producer;
pub mod signal_cards;
mod sim_rows;
mod xterm_cotenant;
mod xterm_rows;

pub use ann::{AnnFamilyReport, QuantScaleMeasurement};
pub use complete_xterms::{
    ASTRO_XTERM_COMPLETION_CORRUPT, ASTRO_XTERM_COMPLETION_OVERFLOW, ASTRO_XTERM_SOURCE_CORRUPT,
    COMPLETE_PAIR_BLOCK_MAGIC, COMPLETE_PAIR_BLOCK_PREFIX, COMPLETE_PAIR_BLOCK_SCHEMA,
    COMPLETE_WITNESS_PREFIX, COMPLETE_WITNESS_SCHEMA, CompleteAssociationPersistReport,
    CompleteAssociationState, PairMetricCounts, PairReasonCounts, read_complete_association_state,
    read_complete_association_state_vault_path, reconcile_complete_associations,
};
pub use drift_producer::{
    DRIFT_REFERENCE_CHUNK_BUDGET_KNOB, DRIFT_REFERENCE_DEFAULT_CHUNK_BUDGET_BYTES,
    DRIFT_REFERENCE_DEFAULT_SAMPLE_CAP, DRIFT_REFERENCE_KNOB_REGISTRY_VERSION,
    DRIFT_REFERENCE_KNOBS, DRIFT_REFERENCE_MAX_CHUNK_BUDGET_BYTES, DRIFT_REFERENCE_MAX_SAMPLE_CAP,
    DRIFT_REFERENCE_MIN_CHUNK_BUDGET_BYTES, DRIFT_REFERENCE_MIN_SAMPLE_CAP,
    DRIFT_REFERENCE_PAYLOAD_SCHEMA, DRIFT_REFERENCE_SAMPLE_CAP_KNOB, DriftProductionReport,
    DriftReferenceChunkInfo, DriftReferenceSamplingReport, DriftSlotSamples,
    SlotSamplingProvenance, bound_reference_window, drift_reference_chunk_budget_bytes,
    drift_reference_sample_cap, load_drift_reference, load_drift_reference_counted,
    persist_drift_reference, produce_drift_cards, read_slot_samples_from_vault,
    run_index_time_drift,
};
pub use kernel_index::{
    ASTRO_KERNEL_INDEX_ABSENT, ASTRO_KERNEL_INDEX_CORRUPT, ASTRO_KERNEL_INDEX_MEMBER_ABSENT,
    ASTRO_KERNEL_INDEX_NO_MEMBERS, ASTRO_KERNEL_INDEX_PERSIST, ASTRO_KERNEL_INDEX_STALE,
    ASTRO_KERNEL_INDEX_VAULT, ASTRO_KERNEL_QUERY_UNRESOLVED, KERNEL_INDEX_RECALL_GATE_PERMILLE,
    KERNEL_MEMBER_INDEX_CF_PREFIX, KERNEL_MEMBER_INDEX_SCHEMA, KernelIndexKind,
    KernelMemberBinding, KernelMemberIndex, KernelMemberIndexDescriptor,
    KernelMemberIndexPersistReport, KernelQueryMatch, KernelQueryResult, KernelRecallMeasurement,
    LoadedKernelMemberIndex, build_kernel_member_index, kernel_query_loaded_members,
    kernel_query_members, kernel_scoped_semantic_query, measure_kernel_index_recall,
    persist_kernel_member_index, read_persisted_kernel_member_index,
    read_persisted_kernel_member_index_descriptor,
};
pub use signal_cards::{
    SIGNAL_AXIS_STRUCTURAL_DEGREE, SIGNAL_AXIS_SYMBOL_KIND, SignalCardProduction, SymbolAxes,
    derive_symbol_axes, measure_index_time_signal_cards, signal_cards_from_symbol_axes,
};
pub use sim_rows::{
    ASTRO_SIM_EDGE_LEDGER_MISSING, ASTRO_SIM_EDGE_ROW_CORRUPT, PersistedSimilarityEdgeRow,
    SCHEMA_SIM_EDGE_ROW, SIM_EDGE_LEDGER_SCHEMA, SIM_EDGE_ROW_PREFIX, SimEdgeGraphRow,
    SimilarityPersistReport, persist_similarity_edges, persist_similarity_edges_delta,
    read_similarity_edge_rows, sim_edge_graph_key,
};
pub use xterm_cotenant::{
    XTERM_COMPLETE_PAIR_BLOCK_COTENANT_SCHEMA, XTERM_COMPLETE_PAIR_COTENANT_SCHEMA,
    XTERM_PLACEMENT_TRUTH_COTENANT_SCHEMA, accepted_xterm_cotenant_schemas,
    is_accepted_xterm_cotenant, xterm_cotenant_schema_tag,
};
pub use xterm_rows::{
    AGREEMENT_GRAPH_ASPECT_PROVENANCE, AGREEMENT_GRAPH_ASPECT_SCHEMA, ASTRO_XTERM_CX_ID_MISSING,
    ASTRO_XTERM_ROW_CORRUPT, AgreementGraphAspect, EagerCrossTermPersistReport,
    PersistedAgreementEdge, PersistedEagerCrossTermRow, XTERM_EAGER_LEDGER_SCHEMA,
    agreement_graph_aspect, agreement_graph_from_persisted_rows,
    agreement_graph_from_persisted_rows_with_cotenants, designed_kind_for_slots,
    eager_xterm_dump_bytes, eager_xterm_key, persist_eager_cross_terms,
    persist_eager_cross_terms_delta, read_eager_cross_term_rows,
    read_eager_cross_term_rows_with_cotenants,
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
/// Superseded by the registry-declared `weave_similarity_workers` knob (#433):
/// [`SimilarityPlannerConfig::default`] now resolves the worker count via
/// [`crate::knobs::weave_similarity_workers`] (host parallelism), not this bare
/// `1`. Retained only as the explicit single-shard reference an operator may pin
/// for a reproducible serial bench.
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
/// Stable failure code when a cross-term plan is asked to account for a panel
/// roster that cannot host the designed eager pairs, or when a symbol carries a
/// slot outside the declared roster (#522). The abundance report must describe
/// the panel that was physically persisted, never a compiled-in constant.
pub const ASTRO_XTERM_PANEL_ROSTER_INVALID: &str = "ASTRO_XTERM_PANEL_ROSTER_INVALID";
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
pub const ASSAY_DELTA_INVALIDATION_COTENANT_SCHEMA: &str = "astrolabe.delta_invalidation.v2";
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
            // #433: resolve to the measured host parallelism instead of the bare
            // serial `1` (registry-declared `weave_similarity_workers` knob). The
            // exact-cosine rescoring shards are proven byte-identical to the serial
            // plan (worker-count invariant), so this changes only wall-clock — the
            // largest weave sub-stage (`similarity_plan`) no longer runs serial on a
            // many-core host.
            worker_count: crate::knobs::weave_similarity_workers(),
            disabled_families: BTreeSet::new(),
            exact_pair_node_limit: Some(DEFAULT_SIMILARITY_EXACT_PAIR_NODE_LIMIT),
            candidate_strategies: BTreeMap::new(),
            ann: AnnCandidateConfig::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SimilarityNode {
    /// Stable source-atom identity. This is the planner/persistence key; qualified
    /// names are deliberately non-unique display metadata.
    pub symbol_id: String,
    pub qualified_name: String,
    pub slots: BTreeMap<SlotId, SlotVector>,
}

impl SimilarityNode {
    pub fn new(symbol_id: impl Into<String>, qualified_name: impl Into<String>) -> Self {
        Self {
            symbol_id: symbol_id.into(),
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
    pub source_id: String,
    pub target_id: String,
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
            ("source_atom_id".to_string(), self.source_id.clone()),
            ("target_atom_id".to_string(), self.target_id.clone()),
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
    /// #433 permanent labeled per-stage wall-clock attribution: one
    /// `(stage.family, ms)` entry per planned family for the ANN candidate
    /// generation (`ann_generate.<family>`) and the exact-cosine rescoring
    /// (`rescore.<family>`), so cold-index weave cost is attributable to a real
    /// sub-stage instead of guessed. Telemetry only — never part of the persisted
    /// edge set.
    pub timing_ms: Vec<(String, u64)>,
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
    pub symbol_id: String,
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
    EmptySymbolId {
        node_index: usize,
    },
    EmptyQualifiedName {
        node_index: usize,
    },
    DuplicateSymbolId {
        symbol_id: String,
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
            Self::EmptySymbolId { node_index } => {
                write!(
                    f,
                    "similarity node {node_index} has an empty stable symbol id"
                )
            }
            Self::EmptyQualifiedName { node_index } => {
                write!(
                    f,
                    "similarity node {node_index} has an empty qualified name"
                )
            }
            Self::DuplicateSymbolId { symbol_id } => {
                write!(
                    f,
                    "duplicate similarity node stable symbol id {symbol_id:?}"
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
    let mut timing_ms: Vec<(String, u64)> = Vec::new();

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
        let t_generate = std::time::Instant::now();
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
        timing_ms.push((
            format!("ann_generate.{family}"),
            t_generate.elapsed().as_millis() as u64,
        ));

        let threshold = config.thresholds.threshold(family);
        let t_rescore = std::time::Instant::now();
        let (family_edges, pair_counts) = plan_family_edges(
            family,
            threshold,
            config.per_node_cap,
            &vectors,
            config.worker_count,
            candidate_lists.as_deref(),
        );
        timing_ms.push((
            format!("rescore.{family}"),
            t_rescore.elapsed().as_millis() as u64,
        ));
        skips.pair_counts.insert(family, pair_counts);
        edges.extend(family_edges);
    }

    edges.sort_by(stable_edge_order);
    Ok(SimilarityPlan {
        edges,
        skips,
        workers_requested: config.worker_count,
        timing_ms,
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
            if frontier.contains(&edge.row.source_id) || frontier.contains(&edge.row.target_id) {
                region.insert(edge.row.source_id.clone());
                region.insert(edge.row.target_id.clone());
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
            .filter(|vector| changed.contains(&vector.symbol_id))
        {
            let mut candidates = vectors
                .iter()
                .filter(|target| target.symbol_id != source.symbol_id)
                .filter_map(|target| {
                    cosine(&source.vector, &target.vector)
                        .map(|score| (score, target.symbol_id.as_str()))
                })
                .collect::<Vec<_>>();
            candidates.sort_by(|left, right| {
                right.0.total_cmp(&left.0).then_with(|| left.1.cmp(right.1))
            });
            region.extend(
                candidates
                    .into_iter()
                    .take(candidate_cap)
                    .map(|(_, symbol_id)| symbol_id.to_string()),
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
    /// #433 neighborhood peer sample-cap accounting. `neighborhood_sample_cap` is
    /// the applied `weave_neighborhood_sample_cap` knob value;
    /// `neighborhood_capped_evaluations` counts the (symbol, kind) neighborhood
    /// agreements whose profile was scored over a seeded peer subsample of the cap
    /// rather than every comparable peer (loud disclosure of the labeled
    /// degradation — invariant 3). Zero when the corpus has no more comparable
    /// peers than the cap, in which case the plan is byte-identical to the
    /// uncapped path.
    pub neighborhood_sample_cap: usize,
    pub neighborhood_capped_evaluations: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EagerCrossTermRow {
    pub symbol_id: String,
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
    /// The declared specialized comparators this plan actually evaluates.
    pub designed_pair_count_per_symbol: usize,
    pub materialized_count: usize,
    pub scalar_count: usize,
    pub absent_count: usize,
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
    /// The per-pair calibration discriminator. `Some(pair_key)` for kinds whose
    /// thresholds are measured per lens-pair (`BlindSpot`, one distribution per
    /// [`BlindSpotLensPair`]); `None` for kinds with a single global calibration
    /// slot (drift, doc-drift, name-truth, ood-commit, prompt-injection) and for
    /// legacy persisted rows that predate per-pair keying. The composite
    /// `(kind, pair_key)` is the true calibration key, so two blind-spot pairs
    /// with distinct measured distributions never collide on the single
    /// `BlindSpot` kind (see [`Self::calibration_key`]).
    pub pair_key: Option<String>,
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
            pair_key: None,
            medium_min_score_millipoints,
            high_min_score_millipoints,
            provenance_ref: provenance_ref.into(),
        }
    }

    /// Tags this calibration with the blind-spot lens pair it was measured for.
    ///
    /// Consumed-builder form so per-pair calibrations read as
    /// `AnomalyCalibration::new(..).with_pair_key(pair.pair_key())`. A pair-keyed
    /// calibration only tiers substrate rows carrying the same pair key.
    #[must_use]
    pub fn with_pair_key(mut self, pair_key: impl Into<String>) -> Self {
        self.pair_key = Some(pair_key.into());
        self
    }

    /// The composite calibration key `(kind, pair_key)`. Blind-spot pairs each
    /// key on their own pair, so one pair's threshold can never tier another
    /// pair's gaps; every other kind keys on `(kind, None)` exactly as before.
    pub fn calibration_key(&self) -> (AnomalyKind, Option<&str>) {
        (self.kind, self.pair_key.as_deref())
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
    /// The per-pair calibration discriminator this row is tiered under — mirrors
    /// [`AnomalyCalibration::pair_key`]. `Some(pair_key)` for a blind-spot row
    /// produced by a specific [`BlindSpotLensPair`]; `None` for every other kind
    /// and for legacy persisted rows. A row only tiers against the calibration
    /// sharing its `(kind, pair_key)` composite key (see [`Self::calibration_key`]).
    pub pair_key: Option<String>,
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
            pair_key: None,
        }
    }

    /// Tags this substrate row with the blind-spot lens pair that produced it, so
    /// it tiers only against that pair's measured calibration.
    #[must_use]
    pub fn with_pair_key(mut self, pair_key: impl Into<String>) -> Self {
        self.pair_key = Some(pair_key.into());
        self
    }

    /// The composite calibration key `(kind, pair_key)` this row tiers under —
    /// the exact key an [`AnomalyCalibration`] must expose to tier it.
    pub fn calibration_key(&self) -> (AnomalyKind, Option<&str>) {
        (self.kind, self.pair_key.as_deref())
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
    /// Count of shared `ColumnFamily::XTerm` co-tenant rows (layout
    /// `placement_truth` rows, #369) skipped during the live XTerm scan — a
    /// counted, labeled skip, not an error.
    pub xterm_cotenant_rows_skipped: usize,
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
        row.symbol_id.clone(),
        1_000_u64.saturating_sub(agreement_millipoints),
        format!(
            "{} symbol={:?} agreement={} millipoints",
            row.kind.wire_name(),
            row.qualified_name,
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

    // ColumnFamily::XTerm is shared: the shadow importer's layout lane
    // co-tenants `placement_truth` cross-term rows here (#369). Those rows are
    // line-based text (`schema=...`), not loom-row JSON, so strict-decoding every
    // row failed the whole live-anomaly read with CALYX_ASTER_CORRUPT_SHARD on a
    // real corpus. Classify co-tenant-aware: an accepted co-tenant schema is a
    // counted skip; a genuinely corrupt xterm row still fails closed.
    let accepted_xterm_cotenants = accepted_xterm_cotenant_schemas();
    for (key, value) in vault.scan_cf_at(snapshot, ColumnFamily::XTerm)? {
        let row: XtermRow = match serde_json::from_slice(&value) {
            Ok(row) => row,
            Err(error) => {
                if is_accepted_xterm_cotenant(&value, &accepted_xterm_cotenants) {
                    inputs.xterm_cotenant_rows_skipped += 1;
                    continue;
                }
                return Err(CalyxError::aster_corrupt_shard(format!(
                    "decode live XTerm anomaly row: {error}"
                )));
            }
        };
        inputs.xterm_rows_read += 1;
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

/// Migration-safe decode of the optional per-pair calibration key from a
/// persisted payload value.
///
/// Returns `Ok(None)` when the field is absent or JSON `null` — the documented
/// default for legacy rows written before per-pair keying, which decode as the
/// single pair-agnostic calibration slot (byte-compatible single-pair behavior).
/// Fails closed (`Err`) when the field is present but is not a non-empty string,
/// so a malformed `pair_key` is refused rather than silently reinterpreted as
/// "no pair".
fn pair_key_from_payload_value(value: &Value) -> Result<Option<String>, ()> {
    match value.get("pair_key") {
        None | Some(Value::Null) => Ok(None),
        Some(raw) => {
            let text = raw.as_str().ok_or(())?.trim();
            if text.is_empty() {
                return Err(());
            }
            Ok(Some(text.to_string()))
        }
    }
}

fn anomaly_substrate_from_payload_value(
    value: &Value,
    row_provenance: &str,
) -> Option<AnomalySubstrateRow> {
    let kind = value.get("kind")?.as_str()?.parse::<AnomalyKind>().ok()?;
    let pair_key = pair_key_from_payload_value(value).ok()?;
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
    let mut row = AnomalySubstrateRow::new(
        kind,
        subject_id.to_string(),
        score,
        message.to_string(),
        provenance,
        string_array_value(value, "lens_evidence"),
    );
    if let Some(pair_key) = pair_key {
        row = row.with_pair_key(pair_key);
    }
    Some(row)
}

fn anomaly_calibration_from_payload_value(
    value: &Value,
    row_provenance: &str,
) -> Option<AnomalyCalibration> {
    let kind = value.get("kind")?.as_str()?.parse::<AnomalyKind>().ok()?;
    let pair_key = pair_key_from_payload_value(value).ok()?;
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
    let mut calibration = AnomalyCalibration::new(kind, medium, high, provenance);
    if let Some(pair_key) = pair_key {
        calibration = calibration.with_pair_key(pair_key);
    }
    Some(calibration)
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
        .then_with(|| left.pair_key.cmp(&right.pair_key))
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
    // Key calibrations by the composite (kind, pair_key), not kind alone: two
    // blind-spot lens pairs each carry their own measured gap distribution under
    // the single `BlindSpot` kind, so keying on kind would let the second pair's
    // threshold silently overwrite the first's. Every non-per-pair kind keys on
    // (kind, None) exactly as before, so single-pair/legacy behavior is
    // byte-identical.
    let calibration_by_key = calibrations
        .iter()
        .map(|calibration| (calibration.calibration_key(), calibration))
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
        let Some(calibration) = calibration_by_key.get(&row.calibration_key()) else {
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
    /// Stable source-atom identity of the scored symbol.
    pub symbol_id: String,
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
    /// Stable source-atom identity of the skipped symbol.
    pub symbol_id: String,
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
    let neighbor_by_id: BTreeMap<&str, &NormalizedVector> = neighbor_vectors
        .iter()
        .map(|indexed| (indexed.symbol_id.as_str(), &indexed.vector))
        .collect();
    let confident_present: BTreeSet<&str> = confident_vectors
        .iter()
        .map(|indexed| indexed.symbol_id.as_str())
        .collect();

    let mut scores = Vec::new();
    let mut substrates = Vec::new();
    let mut skipped = Vec::new();

    // Any symbol with a neighbor-lens vector but no confident-lens vector cannot
    // be scored — record it so no symbol is silently dropped.
    for indexed in &neighbor_vectors {
        if !confident_present.contains(indexed.symbol_id.as_str()) {
            skipped.push(BlindSpotSkip {
                symbol_id: indexed.symbol_id.clone(),
                qualified_name: indexed.qualified_name.clone(),
                reason: BlindSpotSkipReason::MissingConfidentLens,
            });
        }
    }

    for source in &confident_vectors {
        // The source's own neighbor-lens vector is required to measure its
        // agreement with the cluster.
        let Some(source_neighbor_vec) = neighbor_by_id.get(source.symbol_id.as_str()) else {
            skipped.push(BlindSpotSkip {
                symbol_id: source.symbol_id.clone(),
                qualified_name: source.qualified_name.clone(),
                reason: BlindSpotSkipReason::MissingNeighborLens,
            });
            continue;
        };

        // Rank every other confident-lens symbol by confident-lens cosine.
        let mut candidates: Vec<(f32, &str)> = confident_vectors
            .iter()
            .filter(|target| target.symbol_id != source.symbol_id)
            .filter_map(|target| {
                cosine(&source.vector, &target.vector)
                    .map(|score| (score, target.symbol_id.as_str()))
            })
            .collect();
        candidates
            .sort_by(|left, right| right.0.total_cmp(&left.0).then_with(|| left.1.cmp(right.1)));
        candidates.truncate(config.neighbor_cap);

        if candidates.is_empty() {
            skipped.push(BlindSpotSkip {
                symbol_id: source.symbol_id.clone(),
                qualified_name: source.qualified_name.clone(),
                reason: BlindSpotSkipReason::NoConfidentNeighbors,
            });
            continue;
        }

        let confident_sum: f32 = candidates.iter().map(|(score, _)| score).sum();
        let confident_sim = confident_sum / candidates.len() as f32;

        // Measure the neighbor lens's agreement across the SAME cluster members.
        let mut neighbor_scores: Vec<f32> = Vec::new();
        for (_, neighbor_id) in &candidates {
            let Some(neighbor_vec) = neighbor_by_id.get(neighbor_id) else {
                continue;
            };
            if let Some(score) = cosine(source_neighbor_vec, neighbor_vec) {
                neighbor_scores.push(score);
            }
        }
        if neighbor_scores.len() < config.min_neighbors {
            skipped.push(BlindSpotSkip {
                symbol_id: source.symbol_id.clone(),
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
            symbol_id: source.symbol_id.clone(),
            qualified_name: source.qualified_name.clone(),
            confident_sim_millipoints,
            neighbor_mean_millipoints,
            gap_millipoints,
            neighbor_count: neighbor_scores.len(),
        });

        substrates.push(AnomalySubstrateRow::new(
            AnomalyKind::BlindSpot,
            source.symbol_id.clone(),
            gap_millipoints,
            format!(
                "blind_spot {pair_key} symbol={:?}: {} confidence {confident_sim_millipoints} vs {} agreement {neighbor_mean_millipoints} (gap {gap_millipoints})",
                source.qualified_name,
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
        ).with_pair_key(pair_key.clone()));
    }

    scores.sort_by(|left, right| left.symbol_id.cmp(&right.symbol_id));
    substrates.sort_by(anomaly_substrate_order);
    skipped.sort_by(|left, right| left.symbol_id.cmp(&right.symbol_id));
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
            )
            .with_pair_key(pair_key.clone());
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

pub fn plan_eager_cross_terms(
    nodes: &[SimilarityNode],
    active_slot_count: usize,
) -> calyx_core::Result<EagerCrossTermPlan> {
    plan_eager_cross_terms_selected(nodes, None, active_slot_count)
}

/// Plans eager agreements only for the named dirty symbols while retaining the
/// full corpus as neighborhood context.
pub fn plan_eager_cross_terms_for_symbols(
    nodes: &[SimilarityNode],
    symbol_ids: &BTreeSet<String>,
    active_slot_count: usize,
) -> calyx_core::Result<EagerCrossTermPlan> {
    plan_eager_cross_terms_selected(nodes, Some(symbol_ids), active_slot_count)
}

/// Largest panel slot id referenced by any designed eager agreement pair.
///
/// The persisted panel roster must physically host every designed pair, so a
/// roster whose active slot count does not cover this id cannot describe the
/// materialized eager cross-terms and is rejected fail-closed (#522).
fn max_designed_eager_slot() -> u16 {
    EagerAgreementKind::ALL
        .into_iter()
        .flat_map(|kind| {
            let (left, right) = kind.slots();
            [left.get(), right.get()]
        })
        .max()
        .expect("EagerAgreementKind::ALL is non-empty")
}

fn xterm_panel_roster_invalid(message: String) -> calyx_core::CalyxError {
    calyx_core::CalyxError {
        code: ASTRO_XTERM_PANEL_ROSTER_INVALID,
        message,
        remediation: "Derive the active slot count from the persisted panel roster \
             (astrolabe_panel::slots_for_version) so abundance describes the panel that \
             was physically persisted; re-index if the persisted panel version is stale.",
    }
}

/// Validates that `active_slot_count` — the number of slots S0..S(N-1) in the
/// persisted panel roster — can host every designed eager pair and covers every
/// slot the given symbols physically carry (#522). Slot ids are 0-indexed, so a
/// roster of `N` slots hosts ids `0..=N-1`.
fn validate_active_roster(
    nodes: &[SimilarityNode],
    active_slot_count: usize,
) -> calyx_core::Result<()> {
    let max_designed = max_designed_eager_slot();
    if active_slot_count == 0 || usize::from(max_designed) >= active_slot_count {
        return Err(xterm_panel_roster_invalid(format!(
            "panel roster of {active_slot_count} active slots cannot host the designed eager \
             pairs (largest designed slot id is S{max_designed}, which requires at least \
             {} active slots)",
            usize::from(max_designed) + 1
        )));
    }
    for node in nodes {
        for slot in node.slots.keys() {
            if usize::from(slot.get()) >= active_slot_count {
                return Err(xterm_panel_roster_invalid(format!(
                    "symbol {:?} carries slot S{} outside the declared {active_slot_count}-slot \
                     panel roster; the persisted panel version disagrees with the abundance roster",
                    node.qualified_name,
                    slot.get()
                )));
            }
        }
    }
    Ok(())
}

fn plan_eager_cross_terms_selected(
    nodes: &[SimilarityNode],
    symbol_ids: Option<&BTreeSet<String>>,
    active_slot_count: usize,
) -> calyx_core::Result<EagerCrossTermPlan> {
    validate_active_roster(nodes, active_slot_count)?;
    let selected_indices = nodes
        .iter()
        .enumerate()
        .filter(|(_, node)| symbol_ids.is_none_or(|ids| ids.contains(&node.symbol_id)))
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    let mut rows = Vec::with_capacity(selected_indices.len() * EagerAgreementKind::ALL.len());
    // #433 neighborhood peer sample-cap: the five NeighborhoodAgreement kinds score
    // each symbol's agreement as the cosine between its two per-slot similarity
    // neighborhood profiles, each built against every comparable peer — an O(n²)
    // per-kind pass that measurement shows re-dominating the cold index at monorepo
    // scale. Capping the peer set to a seeded without-replacement subsample bounds
    // it to O(n·cap); a corpus with no more comparable peers than the cap is scored
    // whole (byte-identical to the uncapped plan).
    let sample_cap = crate::knobs::weave_neighborhood_sample_cap();
    let sample_seed = crate::knobs::WEAVE_NEIGHBORHOOD_SAMPLE_SEED;
    // Each kind's value pass is independent of the others, so computing the six
    // kinds on scoped threads cannot change any value (#23); rows are still
    // appended in `EagerAgreementKind::ALL` order and sorted below, keeping the
    // plan byte-identical to the sequential shape.
    let selected = &selected_indices;
    let counted_values_by_kind = std::thread::scope(|scope| {
        EagerAgreementKind::ALL
            .map(|kind| {
                scope.spawn(move || {
                    cross_term_values(nodes, kind, selected, sample_cap, sample_seed)
                })
            })
            .map(|handle| handle.join().expect("cross-term kind worker panicked"))
    });
    let mut neighborhood_capped_evaluations = 0usize;
    for (kind, (values, capped)) in EagerAgreementKind::ALL
        .into_iter()
        .zip(counted_values_by_kind)
    {
        neighborhood_capped_evaluations += capped;
        let (left_slot, right_slot) = kind.slots();
        for (&node_index, value) in selected_indices.iter().zip(values) {
            let node = &nodes[node_index];
            rows.push(EagerCrossTermRow {
                symbol_id: node.symbol_id.clone(),
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
    // This is deliberately a specialized-comparator report, not an active-panel
    // abundance claim. Exhaustive applicable-roster counts and the strict
    // computed+typed-incompatible equation are owned by complete_xterms (#522).
    let eager = EagerAgreementKind::ALL.len();
    Ok(EagerCrossTermPlan {
        rows,
        agreement_graph,
        abundance: CrossTermAbundance {
            symbol_count,
            designed_pair_count_per_symbol: eager,
            materialized_count: symbol_count * eager,
            scalar_count,
            absent_count,
        },
        neighborhood_sample_cap: sample_cap,
        neighborhood_capped_evaluations,
    })
}

/// Computes one kind's cross-term values for the selected symbols, returning the
/// values plus the count of neighborhood evaluations that scored over a capped
/// peer subsample (#433; always zero for the DirectAgreement kind and for any
/// corpus with no more comparable peers than `sample_cap`).
fn cross_term_values(
    nodes: &[SimilarityNode],
    kind: EagerAgreementKind,
    selected_indices: &[usize],
    sample_cap: usize,
    sample_seed: u64,
) -> (Vec<CrossTermValue>, usize) {
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
        EagerCrossTermComparator::DirectAgreement => (
            selected_indices
                .iter()
                .map(|&index| direct_cross_term_value(&operands[index].0, &operands[index].1))
                .collect(),
            0,
        ),
        EagerCrossTermComparator::NeighborhoodAgreement => {
            // #433: a peer contributes to a source's neighborhood profile iff BOTH
            // its operand vectors match the source's shapes exactly (`cosine` is
            // Some only for equal-kind, equal-dim pairs). Grouping the measurable
            // pool by that (left, right) shape signature — once per kind — makes
            // each source's group the *exact* contributor domain of the uncapped
            // peer loop. Sampling from the source's own group therefore preserves
            // the contributing-peer count at min(cap, group-1): capping can never
            // flip a symbol to `InsufficientNeighborhood` that the uncapped path
            // would have scored, so the persisted scalar-row set is count-preserved
            // and only the profile membership (values within Monte-Carlo noise)
            // changes.
            let mut sig_groups: BTreeMap<(VectorSig, VectorSig), Vec<usize>> = BTreeMap::new();
            for (index, (left, right)) in operands.iter().enumerate() {
                if let (Ok(left), Ok(right)) = (left, right) {
                    sig_groups
                        .entry((vector_sig(left), vector_sig(right)))
                        .or_default()
                        .push(index);
                }
            }
            let mut capped = 0usize;
            let values = selected_indices
                .iter()
                .map(|&node_index| {
                    let group = match &operands[node_index] {
                        (Ok(left), Ok(right)) => sig_groups
                            .get(&(vector_sig(left), vector_sig(right)))
                            .map(Vec::as_slice)
                            .unwrap_or(&[]),
                        _ => &[],
                    };
                    neighborhood_cross_term_value(
                        node_index,
                        &nodes[node_index].symbol_id,
                        kind,
                        &operands,
                        group,
                        sample_cap,
                        sample_seed,
                        &mut capped,
                    )
                })
                .collect();
            (values, capped)
        }
    }
}

/// Shape signature deciding pairwise [`cosine`] comparability: two vectors score
/// `Some` iff their signatures are equal (same kind, same dim).
type VectorSig = (bool, u32);

fn vector_sig(vector: &NormalizedVector) -> VectorSig {
    match vector {
        NormalizedVector::Dense { dim, .. } => (true, *dim),
        NormalizedVector::Sparse { dim, .. } => (false, *dim),
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

/// Seeded without-replacement subsample of `cap` peer indices from `[0, n)` (#433).
///
/// A partial Fisher–Yates shuffle keyed by a [`DeterministicRng`] labeled with the
/// source symbol's identity, then sorted so the chosen peers are visited in index
/// order (a stable readback independent of shuffle order). This mirrors the #422
/// estimator sample-cap subsample exactly; it is a pure function of
/// `(seed, label, n, cap)`, so a byte-identical corpus yields byte-identical
/// sampled profiles. Callers invoke it only when `n - 1 > cap`.
fn seeded_peer_indices(n: usize, cap: usize, seed: u64, label: &str) -> Vec<usize> {
    let m = cap.min(n);
    let mut rng = astrolabe_assay::rng::DeterministicRng::from_u64_labeled(seed, label);
    let mut indices: Vec<usize> = (0..n).collect();
    for i in 0..m {
        let j = i + (rng.next_u64() % (n - i) as u64) as usize;
        indices.swap(i, j);
    }
    let mut chosen = indices[..m].to_vec();
    chosen.sort_unstable();
    chosen
}

#[allow(clippy::too_many_arguments)]
fn neighborhood_cross_term_value(
    node_index: usize,
    source_qualified_name: &str,
    kind: EagerAgreementKind,
    operands: &[CrossTermOperandPair],
    comparable_pool: &[usize],
    sample_cap: usize,
    sample_seed: u64,
    capped: &mut usize,
) -> CrossTermValue {
    let (left_slot, right_slot) = kind.slots();
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

    // #433: bound the O(n) per-symbol peer scan to a seeded without-replacement
    // subsample of the cap when the source's shape-signature group holds more
    // comparable peers than the cap. `comparable_pool` is the source's OWN
    // signature group — the exact contributor domain of the uncapped peer loop
    // (every member scores `Some` on both slots) — so a capped profile always
    // scores exactly min(cap, group-1) contributing peers and the scalar-row set
    // is count-preserved. The profile cosine is a Monte-Carlo estimate whose
    // variance is O(1/m); at the declared cap it is pinned within its noise band,
    // so further peers buy no accuracy while costing O(n). A group at or below
    // the cap is scored whole and is byte-identical to the uncapped path.
    let comparable_peers =
        comparable_pool.len() - usize::from(comparable_pool.binary_search(&node_index).is_ok());
    let sampled;
    let peer_positions: &[usize] = if comparable_peers > sample_cap {
        *capped += 1;
        sampled = seeded_peer_indices(
            comparable_pool.len(),
            sample_cap,
            sample_seed,
            &format!("{kind}:{source_qualified_name}:{}", comparable_pool.len()),
        );
        &sampled
    } else {
        sampled = (0..comparable_pool.len()).collect();
        &sampled
    };

    let mut left_scores = Vec::with_capacity(peer_positions.len());
    let mut right_scores = Vec::with_capacity(peer_positions.len());
    for &pool_position in peer_positions {
        let peer_index = comparable_pool[pool_position];
        if peer_index == node_index {
            continue;
        }
        let (peer_left, peer_right) = &operands[peer_index];
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
    left.symbol_id
        .cmp(&right.symbol_id)
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

    let mut seen_ids = BTreeSet::new();
    for (node_index, node) in nodes.iter().enumerate() {
        if node.symbol_id.trim().is_empty() {
            return Err(SimilarityPlanError::EmptySymbolId { node_index });
        }
        if node.qualified_name.trim().is_empty() {
            return Err(SimilarityPlanError::EmptyQualifiedName { node_index });
        }
        if !seen_ids.insert(node.symbol_id.clone()) {
            return Err(SimilarityPlanError::DuplicateSymbolId {
                symbol_id: node.symbol_id.clone(),
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
                symbol_id: node.symbol_id.clone(),
                qualified_name: node.qualified_name.clone(),
                reason: SimilarityVectorSkipReason::MissingSlot,
            });
            continue;
        };
        match normalized_vector(vector) {
            Ok(vector) => out.push(IndexedVector {
                symbol_id: node.symbol_id.clone(),
                qualified_name: node.qualified_name.clone(),
                vector,
            }),
            Err(reason) => skips.vector_skips.push(SimilarityVectorSkip {
                family,
                symbol_id: node.symbol_id.clone(),
                qualified_name: node.qualified_name.clone(),
                reason,
            }),
        }
    }
    out.sort_by(|left, right| left.symbol_id.cmp(&right.symbol_id));
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
                source_id: left.symbol_id.clone(),
                target_id: candidate.target_id,
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
        target_id: right.symbol_id.clone(),
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
    target_id: String,
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
            .then_with(|| self.target_id.cmp(&other.target_id))
    }
}

fn stable_edge_order(left: &SimilarityEdge, right: &SimilarityEdge) -> Ordering {
    left.family
        .sort_index()
        .cmp(&right.family.sort_index())
        .then_with(|| left.source_id.cmp(&right.source_id))
        .then_with(|| left.target_id.cmp(&right.target_id))
}

#[derive(Debug, Clone)]
pub(crate) struct IndexedVector {
    pub(crate) symbol_id: String,
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
/// family wire name, stable source/target ids, display qualified names, slot, graph edge kind,
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
        out.push_str(&edge.source_id);
        out.push('\t');
        out.push_str(&edge.target_id);
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
