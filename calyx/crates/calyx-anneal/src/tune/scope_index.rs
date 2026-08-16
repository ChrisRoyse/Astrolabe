mod types;
mod writer;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use calyx_core::{CalyxError, Result, SlotId};
use calyx_forge::AutotuneCache;

use crate::{
    AssayMetrics, BanditPolicy, ComponentHealth, ComponentKind, ConfigBandit, DegradeRegistry,
    HealthStorage, SignalSample, shape_key_hash,
};

use types::metrics_are_valid;
pub use types::{
    DEFAULT_INDEX_RECALL_TARGET, DEFAULT_INDEX_VRAM_BUDGET_BYTES, IndexArtifactActivation,
    IndexArtifactPromotionRequest, IndexConfig, IndexPromotionRecord, IndexTuneDecision,
    IndexTuneSkip, MAX_INDEX_CANDIDATES, MIN_BITS_PER_ANCHOR, QuantPromotionEvidence,
    candidate_configs, decode_index_config, encode_index_config, index_slot_label, quant_win_check,
    slot_autotune_key, validate_index_artifact_activation, validate_index_config,
    validate_quant_promotion_evidence,
};
pub use writer::{
    IndexBanditPersistence, IndexPromotionWriter, NoopIndexBanditStore, NoopIndexPromotionWriter,
};

pub const CALYX_INDEX_CACHE_WRITE_FAIL: &str = "CALYX_INDEX_CACHE_WRITE_FAIL";
pub const CALYX_INDEX_SCOPE_INVALID_CONFIG: &str = "CALYX_INDEX_SCOPE_INVALID_CONFIG";
pub const CALYX_INDEX_ARTIFACT_ACTIVATION_REQUIRED: &str =
    "CALYX_INDEX_ARTIFACT_ACTIVATION_REQUIRED";

const NEXT_CHANGE_ID_START: u64 = 414_000;
const RECALL_EPSILON: f64 = 1e-12;

struct PromotionMetrics {
    latency_before_ns: u64,
    latency_after_ns: u64,
    recall_before: f64,
    recall_after: f64,
    bits_before: f64,
    bits_after: f64,
    quant_evidence: Option<QuantPromotionEvidence>,
}

pub trait IndexSlotHealth {
    fn is_slot_parked(&self, slot_id: SlotId) -> bool;
}

/// Serving owner for a prepared physical index artifact. Implementations must
/// atomically move the active pointer, reopen the pointer and artifact bytes,
/// and return that observation. `rollback` must restore and reread the prior
/// pointer if a later cache/ledger mutation fails.
pub trait IndexArtifactActivator {
    fn activate(
        &mut self,
        request: &IndexArtifactPromotionRequest,
    ) -> Result<IndexArtifactActivation>;

    fn rollback(&mut self, activation: &IndexArtifactActivation) -> Result<()>;
}

#[derive(Clone, Copy, Default)]
pub struct RefuseIndexArtifactActivator;

impl IndexArtifactActivator for RefuseIndexArtifactActivator {
    fn activate(
        &mut self,
        _request: &IndexArtifactPromotionRequest,
    ) -> Result<IndexArtifactActivation> {
        Err(CalyxError {
            code: CALYX_INDEX_ARTIFACT_ACTIVATION_REQUIRED,
            message: "quantization promotion has no physical serving-artifact activator".into(),
            remediation: "stage the measured candidate index artifact and configure an activator that atomically swaps and rereads the served pointer",
        })
    }

    fn rollback(&mut self, _activation: &IndexArtifactActivation) -> Result<()> {
        Err(CalyxError {
            code: CALYX_INDEX_ARTIFACT_ACTIVATION_REQUIRED,
            message:
                "cannot roll back a quantization promotion without a serving-artifact activator"
                    .into(),
            remediation: "repair the serving-artifact activator and restore the last independently verified pointer",
        })
    }
}

#[derive(Clone, Copy, Default)]
pub struct NoopIndexSlotHealth;

impl IndexSlotHealth for NoopIndexSlotHealth {
    fn is_slot_parked(&self, _slot_id: SlotId) -> bool {
        false
    }
}

impl<S> IndexSlotHealth for DegradeRegistry<S>
where
    S: HealthStorage,
{
    fn is_slot_parked(&self, slot_id: SlotId) -> bool {
        matches!(
            self.health(&ComponentKind::ann_index(slot_id)),
            ComponentHealth::Parked { .. }
        )
    }
}

impl<T> IndexSlotHealth for &T
where
    T: IndexSlotHealth + ?Sized,
{
    fn is_slot_parked(&self, slot_id: SlotId) -> bool {
        (**self).is_slot_parked(slot_id)
    }
}

#[derive(Default)]
pub struct NoopIndexAssayMetrics;

impl AssayMetrics for NoopIndexAssayMetrics {
    fn signal_samples(&self) -> Result<Vec<SignalSample>> {
        Ok(Vec::new())
    }
}

pub struct IndexScopeTuner<
    W = NoopIndexPromotionWriter,
    B = NoopIndexBanditStore,
    H = NoopIndexSlotHealth,
    A = RefuseIndexArtifactActivator,
> where
    W: IndexPromotionWriter,
    B: IndexBanditPersistence,
    H: IndexSlotHealth,
    A: IndexArtifactActivator,
{
    pub bandits: HashMap<SlotId, ConfigBandit>,
    pub assay: Arc<dyn AssayMetrics>,
    pub cache: Arc<Mutex<AutotuneCache>>,
    promotion_writer: W,
    bandit_store: B,
    health: H,
    artifact_activator: A,
    pending_arms: HashMap<SlotId, usize>,
    incumbent_latency_ns: HashMap<SlotId, u64>,
    incumbent_recall: HashMap<SlotId, f64>,
    incumbent_bits: HashMap<SlotId, f64>,
    recall_target: f32,
    next_change_id: u64,
    promotions: Vec<IndexPromotionRecord>,
}

impl IndexScopeTuner {
    pub fn new(cache: AutotuneCache) -> Self {
        Self::with_parts(
            cache,
            NoopIndexPromotionWriter,
            NoopIndexBanditStore,
            NoopIndexSlotHealth,
        )
    }
}

impl<W, B, H> IndexScopeTuner<W, B, H, RefuseIndexArtifactActivator>
where
    W: IndexPromotionWriter,
    B: IndexBanditPersistence,
    H: IndexSlotHealth,
{
    pub fn with_parts(
        cache: AutotuneCache,
        promotion_writer: W,
        bandit_store: B,
        health: H,
    ) -> Self {
        Self::with_assay_parts(
            cache,
            Arc::new(NoopIndexAssayMetrics),
            promotion_writer,
            bandit_store,
            health,
        )
    }

    pub fn with_assay_parts(
        cache: AutotuneCache,
        assay: Arc<dyn AssayMetrics>,
        promotion_writer: W,
        bandit_store: B,
        health: H,
    ) -> Self {
        Self::with_assay_artifact_parts(
            cache,
            assay,
            promotion_writer,
            bandit_store,
            health,
            RefuseIndexArtifactActivator,
        )
    }
}

impl<W, B, H, A> IndexScopeTuner<W, B, H, A>
where
    W: IndexPromotionWriter,
    B: IndexBanditPersistence,
    H: IndexSlotHealth,
    A: IndexArtifactActivator,
{
    pub fn with_artifact_parts(
        cache: AutotuneCache,
        promotion_writer: W,
        bandit_store: B,
        health: H,
        artifact_activator: A,
    ) -> Self {
        Self::with_assay_artifact_parts(
            cache,
            Arc::new(NoopIndexAssayMetrics),
            promotion_writer,
            bandit_store,
            health,
            artifact_activator,
        )
    }

    pub fn with_assay_artifact_parts(
        cache: AutotuneCache,
        assay: Arc<dyn AssayMetrics>,
        promotion_writer: W,
        bandit_store: B,
        health: H,
        artifact_activator: A,
    ) -> Self {
        Self {
            bandits: HashMap::new(),
            assay,
            cache: Arc::new(Mutex::new(cache)),
            promotion_writer,
            bandit_store,
            health,
            artifact_activator,
            pending_arms: HashMap::new(),
            incumbent_latency_ns: HashMap::new(),
            incumbent_recall: HashMap::new(),
            incumbent_bits: HashMap::new(),
            recall_target: DEFAULT_INDEX_RECALL_TARGET,
            next_change_id: NEXT_CHANGE_ID_START,
            promotions: Vec::new(),
        }
    }

    pub fn on_search(
        &mut self,
        slot_id: SlotId,
        p99_ns: u64,
        recall_k: f64,
        bits_per_anchor: f64,
    ) -> Result<IndexTuneDecision> {
        if self.health.is_slot_parked(slot_id) {
            return self.parked_decision(slot_id);
        }
        self.ensure_bandit(slot_id)?;
        let arm = self
            .pending_arms
            .remove(&slot_id)
            .unwrap_or(self.bandits[&slot_id].incumbent_idx);
        self.on_search_for_arm(slot_id, arm, p99_ns, recall_k, bits_per_anchor)
    }

    pub fn on_search_for_arm(
        &mut self,
        slot_id: SlotId,
        arm_idx: usize,
        p99_ns: u64,
        recall_k: f64,
        bits_per_anchor: f64,
    ) -> Result<IndexTuneDecision> {
        self.on_search_for_arm_with_quant_evidence(
            slot_id,
            arm_idx,
            p99_ns,
            recall_k,
            bits_per_anchor,
            None,
        )
    }

    pub fn on_search_for_arm_with_quant_evidence(
        &mut self,
        slot_id: SlotId,
        arm_idx: usize,
        p99_ns: u64,
        recall_k: f64,
        bits_per_anchor: f64,
        quant_evidence: Option<QuantPromotionEvidence>,
    ) -> Result<IndexTuneDecision> {
        if self.health.is_slot_parked(slot_id) {
            return self.parked_decision(slot_id);
        }
        self.ensure_bandit(slot_id)?;
        let prior_idx = self.bandits[&slot_id].incumbent_idx;
        let prior_config = self.config_for_arm(slot_id, prior_idx)?;
        let prior_bandit = self.bandits[&slot_id].clone();
        let won = self.arm_won(
            slot_id,
            arm_idx,
            p99_ns,
            recall_k,
            bits_per_anchor,
            quant_evidence.as_ref(),
        )?;
        self.bandits
            .get_mut(&slot_id)
            .expect("bandit ensured")
            .record_result(arm_idx, won)?;
        let new_idx = self.bandits[&slot_id].incumbent_idx;
        let shadow_arm = match self
            .bandits
            .get_mut(&slot_id)
            .expect("bandit ensured")
            .select_arm()
        {
            Ok(arm) => arm,
            Err(error) => {
                self.bandits.insert(slot_id, prior_bandit);
                return Err(error);
            }
        };
        let shadow_candidate = match (shadow_arm != new_idx)
            .then(|| self.config_for_arm(slot_id, shadow_arm))
            .transpose()
        {
            Ok(candidate) => candidate,
            Err(error) => {
                self.bandits.insert(slot_id, prior_bandit);
                return Err(error);
            }
        };
        if let Err(error) = self.save_bandit(slot_id) {
            self.bandits.insert(slot_id, prior_bandit);
            return Err(error);
        }

        let promoted = if new_idx != prior_idx {
            let new_config = self.config_for_arm(slot_id, new_idx)?;
            let metrics = PromotionMetrics {
                latency_before_ns: self
                    .incumbent_latency_ns
                    .get(&slot_id)
                    .copied()
                    .unwrap_or(p99_ns),
                latency_after_ns: p99_ns,
                recall_before: self
                    .incumbent_recall
                    .get(&slot_id)
                    .copied()
                    .unwrap_or(recall_k),
                recall_after: recall_k,
                bits_before: self
                    .incumbent_bits
                    .get(&slot_id)
                    .copied()
                    .unwrap_or(bits_per_anchor),
                bits_after: bits_per_anchor,
                quant_evidence,
            };
            match self.promote_with_metrics(slot_id, prior_config, new_config, metrics) {
                Ok(record) => {
                    self.record_incumbent_metrics(slot_id, p99_ns, recall_k, bits_per_anchor);
                    Some(record)
                }
                Err(error) => {
                    self.bandits.insert(slot_id, prior_bandit);
                    if let Err(restore_error) = self.save_bandit(slot_id) {
                        return Err(invalid_config(format!(
                            "index promotion failed ({}) and restoring the prior bandit failed ({})",
                            error.message, restore_error.message
                        )));
                    }
                    return Err(error);
                }
            }
        } else {
            if arm_idx == prior_idx && metrics_are_valid(recall_k, bits_per_anchor) {
                self.record_incumbent_metrics(slot_id, p99_ns, recall_k, bits_per_anchor);
            }
            None
        };

        self.pending_arms.insert(slot_id, shadow_arm);

        Ok(IndexTuneDecision {
            evaluated_arm: arm_idx,
            won,
            incumbent: self.get_incumbent_config(slot_id)?,
            promoted,
            shadow_arm: Some(shadow_arm),
            shadow_candidate,
            skipped: None,
        })
    }

    pub fn install_candidates(&mut self, slot_id: SlotId, configs: Vec<IndexConfig>) -> Result<()> {
        if configs.is_empty() || configs.len() > MAX_INDEX_CANDIDATES {
            return Err(invalid_config(
                "Index candidate set must contain 1..=8 configs",
            ));
        }
        let mut bandit = ConfigBandit::new(BanditPolicy::Thompson, types::seed_for_slot(slot_id));
        for config in configs {
            validate_index_config(&config)?;
            bandit.add_arm(encode_index_config(&config)?);
        }
        let key_hash = shape_key_hash(&index_slot_label(slot_id));
        self.bandit_store.save_bandit(key_hash, &bandit)?;
        self.bandits.insert(slot_id, bandit);
        Ok(())
    }

    pub fn get_incumbent_config(&self, slot_id: SlotId) -> Result<IndexConfig> {
        if let Some(bandit) = self.bandits.get(&slot_id)
            && !bandit.arms.is_empty()
        {
            return decode_index_config(&bandit.incumbent()?.config);
        }
        let cache = self
            .cache
            .lock()
            .map_err(|_| invalid_config("autotune cache lock poisoned"))?;
        match cache
            .get(&slot_autotune_key(slot_id, self.recall_target))
            .map_err(cache_write_fail)?
        {
            Some(config) => IndexConfig::from_best_config(config),
            None => Err(invalid_config(format!(
                "no measured index incumbent exists for slot {}; install and persist an explicitly evaluated bandit/config before serving it",
                slot_id.get()
            ))),
        }
    }

    pub fn promotions(&self) -> &[IndexPromotionRecord] {
        &self.promotions
    }

    fn parked_decision(&self, slot_id: SlotId) -> Result<IndexTuneDecision> {
        Ok(IndexTuneDecision {
            evaluated_arm: self.pending_arms.get(&slot_id).copied().unwrap_or(0),
            won: false,
            incumbent: self.get_incumbent_config(slot_id)?,
            promoted: None,
            shadow_arm: None,
            shadow_candidate: None,
            skipped: Some(IndexTuneSkip::ParkedSlot),
        })
    }

    fn ensure_bandit(&mut self, slot_id: SlotId) -> Result<()> {
        if self.bandits.contains_key(&slot_id) {
            return Ok(());
        }
        let key_hash = shape_key_hash(&index_slot_label(slot_id));
        let bandit = match self.bandit_store.load_bandit(key_hash)? {
            Some(bandit) => bandit,
            None => {
                let mut bandit =
                    ConfigBandit::new(BanditPolicy::Thompson, types::seed_for_slot(slot_id));
                for config in candidate_configs(slot_id)? {
                    bandit.add_arm(encode_index_config(&config)?);
                }
                self.bandit_store.save_bandit(key_hash, &bandit)?;
                bandit
            }
        };
        self.bandits.insert(slot_id, bandit);
        Ok(())
    }

    fn arm_won(
        &self,
        slot_id: SlotId,
        arm_idx: usize,
        p99_ns: u64,
        recall_k: f64,
        bits_per_anchor: f64,
        quant_evidence: Option<&QuantPromotionEvidence>,
    ) -> Result<bool> {
        if !metrics_are_valid(recall_k, bits_per_anchor) {
            return Ok(false);
        }
        let Some(bandit) = self.bandits.get(&slot_id) else {
            return Ok(false);
        };
        if arm_idx == bandit.incumbent_idx {
            return Ok(true);
        }
        let candidate = self.config_for_arm(slot_id, arm_idx)?;
        let incumbent = self.config_for_arm(slot_id, bandit.incumbent_idx)?;
        let baseline_latency = self
            .incumbent_latency_ns
            .get(&slot_id)
            .copied()
            .unwrap_or(p99_ns);
        let baseline_recall = self
            .incumbent_recall
            .get(&slot_id)
            .copied()
            .unwrap_or(recall_k);
        let baseline_bits = self
            .incumbent_bits
            .get(&slot_id)
            .copied()
            .unwrap_or(bits_per_anchor);
        let latency_ok = p99_ns < baseline_latency;
        let recall_ok = recall_k + RECALL_EPSILON >= baseline_recall;
        let bits_ok = quant_win_check(&candidate, &incumbent, baseline_bits, bits_per_anchor);
        if !(latency_ok && recall_ok && bits_ok) {
            return Ok(false);
        }
        if candidate.quant_bits != incumbent.quant_bits {
            validate_quant_promotion_evidence(quant_evidence.ok_or_else(|| {
                invalid_config("quant promotion requires measured cosine/FAR evidence")
            })?)?;
        }
        Ok(true)
    }

    fn promote_with_metrics(
        &mut self,
        slot_id: SlotId,
        old_config: IndexConfig,
        new_config: IndexConfig,
        metrics: PromotionMetrics,
    ) -> Result<IndexPromotionRecord> {
        let change_id = crate::ChangeId(self.next_change_id);
        self.next_change_id = self.next_change_id.saturating_add(1);
        let old_bytes = encode_index_config(&old_config)?;
        let new_bytes = encode_index_config(&new_config)?;
        let old_config_hash = *blake3::hash(&old_bytes).as_bytes();
        let new_config_hash = *blake3::hash(&new_bytes).as_bytes();
        let activation = if old_config.quant_bits != new_config.quant_bits {
            let request = IndexArtifactPromotionRequest {
                slot_id,
                prior_config_hash: old_config_hash,
                candidate_config_hash: new_config_hash,
                prior_quant_bits: old_config.quant_bits,
                candidate_quant_bits: new_config.quant_bits,
            };
            let activation = self.artifact_activator.activate(&request)?;
            if let Err(error) = validate_index_artifact_activation(&request, &activation) {
                if let Err(rollback_error) = self.artifact_activator.rollback(&activation) {
                    return Err(invalid_config(format!(
                        "served artifact activation was invalid ({}) and rollback failed ({})",
                        error.message, rollback_error.message
                    )));
                }
                return Err(error);
            }
            Some(activation)
        } else {
            None
        };
        let record = IndexPromotionRecord {
            slot_id,
            change_id,
            old_config,
            new_config,
            latency_before_ns: metrics.latency_before_ns,
            latency_after_ns: metrics.latency_after_ns,
            recall_before: metrics.recall_before,
            recall_after: metrics.recall_after,
            bits_before: metrics.bits_before,
            bits_after: metrics.bits_after,
            slot_key_hash: shape_key_hash(&index_slot_label(slot_id)),
            old_config_hash,
            new_config_hash,
            quant_evidence: metrics.quant_evidence,
            served_artifact: activation,
        };
        if let Err(error) = self.write_cache(&record) {
            self.rollback_activation_and_cache(&record, &error)?;
            return Err(error);
        }
        if let Err(error) = self.promotion_writer.write_autotune_promote(&record) {
            self.rollback_activation_and_cache(&record, &error)?;
            return Err(error);
        }
        self.promotions.push(record.clone());
        Ok(record)
    }

    fn rollback_activation_and_cache(
        &mut self,
        record: &IndexPromotionRecord,
        cause: &CalyxError,
    ) -> Result<()> {
        if let Some(activation) = &record.served_artifact
            && let Err(error) = self.artifact_activator.rollback(activation)
        {
            return Err(invalid_config(format!(
                "promotion mutation failed ({}) and served artifact rollback failed ({})",
                cause.message, error.message
            )));
        }
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| invalid_config("autotune cache lock poisoned during rollback"))?;
        cache
            .apply_and_persist(
                slot_autotune_key(record.slot_id, self.recall_target),
                record.old_config.to_best_config(record.slot_id),
            )
            .map(|_| ())
            .map_err(cache_write_fail)
    }

    fn write_cache(&self, record: &IndexPromotionRecord) -> Result<()> {
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| invalid_config("autotune cache lock poisoned"))?;
        cache
            .apply_and_persist(
                slot_autotune_key(record.slot_id, self.recall_target),
                record.new_config.to_best_config(record.slot_id),
            )
            .map(|_| ())
            .map_err(cache_write_fail)
    }

    fn save_bandit(&self, slot_id: SlotId) -> Result<()> {
        let key_hash = shape_key_hash(&index_slot_label(slot_id));
        self.bandit_store
            .save_bandit(key_hash, &self.bandits[&slot_id])
    }

    fn config_for_arm(&self, slot_id: SlotId, arm_idx: usize) -> Result<IndexConfig> {
        let bandit = self
            .bandits
            .get(&slot_id)
            .ok_or_else(|| invalid_config("missing Index bandit"))?;
        let arm = bandit
            .arms
            .get(arm_idx)
            .ok_or_else(|| invalid_config(format!("Index arm {arm_idx} out of range")))?;
        decode_index_config(&arm.config)
    }

    fn record_incumbent_metrics(
        &mut self,
        slot_id: SlotId,
        p99_ns: u64,
        recall_k: f64,
        bits_per_anchor: f64,
    ) {
        self.incumbent_latency_ns
            .entry(slot_id)
            .and_modify(|value| *value = (*value).min(p99_ns))
            .or_insert(p99_ns);
        self.incumbent_recall.entry(slot_id).or_insert(recall_k);
        self.incumbent_bits
            .entry(slot_id)
            .or_insert(bits_per_anchor);
    }
}

pub(super) fn invalid_config(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: CALYX_INDEX_SCOPE_INVALID_CONFIG,
        message: message.into(),
        remediation: "repair Index scope autotune slot/config metadata before promotion",
    }
}

fn cache_write_fail(error: calyx_forge::ForgeError) -> CalyxError {
    CalyxError {
        code: CALYX_INDEX_CACHE_WRITE_FAIL,
        message: format!("Index autotune cache access failed: {error}"),
        remediation: "repair and reopen the PH16 autotune cache before reading or persisting an Index promotion",
    }
}
