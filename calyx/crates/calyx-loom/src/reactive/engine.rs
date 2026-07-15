//! The reactive engine: registry + bounded fired-event queue + audit log, with
//! a single [`ReactiveEngine::evaluate_post_ingest`] entry point invoked after
//! each ingest completes.

use std::collections::HashMap;
use std::sync::Arc;

use calyx_core::{Clock, CxId, LedgerRef, Result};
use uuid::Uuid;

use super::{
    AuditEntry, AuditLog, BoundedQueue, DEFAULT_MAX_AUDIT_ENTRIES, DEFAULT_MAX_QUEUE_DEPTH,
    DEFAULT_MAX_TRIGGERS, NoveltyVerdict, ReactiveSignals, SubscriptionStore, TriggerCondition,
    TriggerDef, TriggerFired, TriggerId, TriggerRegistry, queue_full_error,
};

/// A bounded, audited reactive trigger engine. Holds the registry of trigger
/// definitions, a depth-capped queue of fired events, and a ring audit log.
pub struct ReactiveEngine {
    pub(crate) registry: TriggerRegistry,
    pub(crate) queue: BoundedQueue<TriggerFired>,
    pub(crate) audit_log: AuditLog,
    pub(crate) clock: Arc<dyn Clock>,
    /// Last observed occurrence count per `EventRecurs` trigger, so a fire is
    /// raised only on the ingest that *increments* the count past the bar.
    pub(crate) last_count: HashMap<TriggerId, u64>,
    pub(crate) subscriptions: SubscriptionStore,
}

impl ReactiveEngine {
    /// Creates an engine with the default A26 caps.
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self::with_caps(
            clock,
            DEFAULT_MAX_TRIGGERS,
            DEFAULT_MAX_QUEUE_DEPTH,
            DEFAULT_MAX_AUDIT_ENTRIES,
        )
    }

    /// Creates an engine with explicit caps (all clamped to ≥ 1).
    pub fn with_caps(
        clock: Arc<dyn Clock>,
        max_triggers: usize,
        max_queue_depth: usize,
        max_audit_entries: usize,
    ) -> Self {
        Self {
            registry: TriggerRegistry::new(max_triggers),
            queue: BoundedQueue::new(max_queue_depth),
            audit_log: AuditLog::new(max_audit_entries),
            clock,
            last_count: HashMap::new(),
            subscriptions: SubscriptionStore::default(),
        }
    }

    /// Registers `condition` (owned by `owner`), assigning a fresh UUID v7 id and
    /// the current engine-clock `created_at`. Fails closed with
    /// [`crate::CALYX_REACTIVE_REGISTRY_FULL`] when the registry is full.
    pub fn register(
        &mut self,
        condition: TriggerCondition,
        owner: Option<String>,
    ) -> Result<TriggerId> {
        let def = TriggerDef {
            id: Uuid::now_v7(),
            condition,
            created_at: self.clock.now(),
            owner,
        };
        self.registry.register(def)
    }

    /// Removes the trigger with `id` and forgets its recurrence cursor.
    pub fn deregister(&mut self, id: TriggerId) -> bool {
        self.last_count.remove(&id);
        self.registry.deregister(id)
    }

    /// Evaluates every registered trigger against the post-ingest state exposed
    /// by `signals`, for the constellation `cx_id` whose ingest is recorded at
    /// `ingest_ledger_ref`. Appends exactly one [`AuditEntry`] per trigger
    /// (match or no-match) and enqueues a [`TriggerFired`] for each match.
    ///
    /// Returns the number of triggers that fired. Fails closed:
    /// - a signal-source error (e.g. an ungrounded constellation on `NewRegion`)
    ///   propagates and no fire is recorded for that trigger;
    /// - a queue overflow discards the oldest event, writes a
    ///   [`crate::CALYX_REACTIVE_QUEUE_FULL`] audit warning, and returns that
    ///   error after the batch.
    pub fn evaluate_post_ingest<S: ReactiveSignals>(
        &mut self,
        cx_id: CxId,
        ingest_ledger_ref: LedgerRef,
        signals: &S,
    ) -> Result<usize> {
        let now = self.clock.now();
        let mut fired = 0usize;
        let mut overflow: Option<calyx_core::CalyxError> = None;

        // Snapshot the defs so we can mutate queue/audit/cursor while iterating.
        for def in self.registry.defs().to_vec() {
            let matched = self.evaluate_condition(&def, cx_id, signals)?;
            self.audit_log.append(AuditEntry {
                eval_id: Uuid::now_v7(),
                trigger_id: def.id,
                cx_id,
                matched,
                ts: now,
                ledger_ref: ingest_ledger_ref.clone(),
                code: None,
            });
            if !matched {
                continue;
            }
            fired += 1;
            let event = TriggerFired {
                trigger_id: def.id,
                cx_id,
                fired_at: now,
                ledger_ref: ingest_ledger_ref.clone(),
                condition_snapshot: def.condition.clone(),
            };
            self.dispatch_to_subscriptions(&event);
            if let Some(dropped) = self.queue.push(event) {
                // A26: oldest event discarded — record the loss to the audit log
                // (the immutable warning the FSV reads) and remember to fail.
                self.audit_log.append(AuditEntry {
                    eval_id: Uuid::now_v7(),
                    trigger_id: def.id,
                    cx_id,
                    matched: true,
                    ts: now,
                    ledger_ref: ingest_ledger_ref.clone(),
                    code: Some(crate::CALYX_REACTIVE_QUEUE_FULL.to_string()),
                });
                overflow.get_or_insert_with(|| queue_full_error(&dropped));
            }
        }

        match overflow {
            Some(err) => Err(err),
            None => Ok(fired),
        }
    }

    /// Evaluates one condition. Returns `Ok(true)` on match, `Ok(false)` on
    /// no-match, and propagates any signal-source error (fail closed).
    pub(crate) fn evaluate_condition<S: ReactiveSignals>(
        &mut self,
        def: &TriggerDef,
        cx_id: CxId,
        signals: &S,
    ) -> Result<bool> {
        match &def.condition {
            TriggerCondition::NewRegion { tau_override } => {
                Ok(signals.novelty(cx_id, *tau_override)? == NoveltyVerdict::NewRegion)
            }
            TriggerCondition::EventRecurs {
                series,
                min_occurrences,
            } => {
                let current = signals.occurrence_count(*series)?;
                let last = self.last_count.insert(def.id, current).unwrap_or(0);
                let threshold = u64::from(*min_occurrences).max(1);
                Ok(current > last && last < threshold && current >= threshold)
            }
            TriggerCondition::DriftDetected {
                slot,
                drift_threshold,
            } => {
                let drift = signals.slot_drift(*slot)?;
                Ok(drift >= *drift_threshold)
            }
        }
    }

    /// Removes and returns all queued fired events, oldest first.
    pub fn drain_fired(&mut self) -> Vec<TriggerFired> {
        let mut out = Vec::with_capacity(self.queue.len());
        while let Some(event) = self.queue.pop() {
            out.push(event);
        }
        out
    }

    /// Read-only view of the registry.
    pub fn registry(&self) -> &TriggerRegistry {
        &self.registry
    }

    /// Read-only view of the fired-event queue.
    pub fn queue(&self) -> &BoundedQueue<TriggerFired> {
        &self.queue
    }

    /// Read-only view of the audit log (the engine's source of truth).
    pub fn audit_log(&self) -> &AuditLog {
        &self.audit_log
    }
}
