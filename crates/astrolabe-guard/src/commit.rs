//! Commit out-of-distribution (OOD) scoring for the watcher (P7.4, blueprint
//! `10_GUARD.md` §5, capability 6.8).
//!
//! When the watcher observes a new commit it scores each of the commit's changed
//! symbols through the guard in the background. A symbol that does not conform to
//! its trusted region (any verdict other than `accept`) makes the commit
//! **out-of-distribution**, and the guard raises a `NewRegion` reactive trigger
//! carrying the **commit ref** so the review surface can ground it. A commit whose
//! symbols all conform raises no trigger — the watcher stays quiet on ordinary
//! in-distribution changes.
//!
//! This module owns the pure scoring: it consumes measured symbols + their
//! enclosing-scope exemplars (the watcher supplies these from the real panel over
//! the indexed corpus) and produces the trigger payloads. The lock decision per
//! symbol is honored so a private symbol's signature drift does not masquerade as
//! a breaking-change identity breach.

use crate::calibration::CalibrationError;
use crate::check::{Exemplar, check_candidate_with_lock, resolve_region};
use crate::profile::{GuardProfile, GuardVerdict};

/// Schema tag for a commit-OOD reactive trigger surfaced to the review queue.
pub const COMMIT_OOD_SCHEMA: &str = "astro.guard.commit_ood.v1";

/// The reactive trigger kind raised for an OOD commit symbol (a `NewRegion`
/// reactive trigger to the review surface).
pub const COMMIT_OOD_TRIGGER_KIND: &str = "new_region";

/// One changed symbol in a commit, measured through the guard instrument, with
/// the trusted exemplars of its enclosing scope and its identity-lock status.
#[derive(Debug, Clone, PartialEq)]
pub struct CommitSymbol {
    /// Hex CxId of the changed symbol (the trigger subject).
    pub cx_id_hex: String,
    /// Whether the symbol is identity-locked (exported/public).
    pub identity_locked: bool,
    /// The candidate measured through the shared guard instrument.
    pub candidate: crate::check::MeasuredSymbol,
    /// The enclosing scope's trusted exemplars (kernel-near first).
    pub exemplars: Vec<Exemplar>,
}

/// A reactive trigger for one OOD symbol in a commit.
#[derive(Debug, Clone, PartialEq)]
pub struct CommitOodTrigger {
    pub schema: &'static str,
    /// The reactive trigger kind (`new_region`).
    pub trigger: &'static str,
    /// The commit ref that introduced the drift (carried to the review surface).
    pub commit_ref: String,
    /// The changed symbol's CxId hex.
    pub subject_cx_hex: String,
    /// The guard verdict that made the symbol OOD (`refuse`/`quarantine`/
    /// `new_region`).
    pub verdict: GuardVerdict,
    /// The comparison region tier the symbol was scored against.
    pub region_class: &'static str,
    /// The per-slot reason for the OOD routing.
    pub reason: String,
}

impl CommitOodTrigger {
    /// Canonical UTF-8 JSON bytes (stable key order) for ledger/readback.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        format!(
            "{{\"schema\":\"{}\",\"trigger\":\"{}\",\"commit_ref\":\"{}\",\"subject_cx\":\"{}\",\
             \"verdict\":\"{}\",\"region_class\":\"{}\",\"reason\":\"{}\"}}",
            COMMIT_OOD_SCHEMA,
            self.trigger,
            json_escape(&self.commit_ref),
            json_escape(&self.subject_cx_hex),
            self.verdict.as_str(),
            self.region_class,
            json_escape(&self.reason),
        )
        .into_bytes()
    }
}

/// The result of scoring a whole commit: how many symbols were scored, whether
/// the commit is OOD, and the reactive triggers for its non-conforming symbols.
#[derive(Debug, Clone, PartialEq)]
pub struct CommitOodReport {
    pub schema: &'static str,
    pub commit_ref: String,
    pub scored: usize,
    /// `true` iff at least one symbol did not conform (raised a trigger).
    pub ood: bool,
    pub triggers: Vec<CommitOodTrigger>,
}

/// Score every changed symbol in a commit against `profile`. A symbol whose
/// verdict is anything other than `accept` raises a `NewRegion` reactive trigger
/// carrying `commit_ref`; a commit whose symbols all accept raises none.
///
/// Fails closed: a symbol with an empty comparison region, a missing guard slot,
/// or a degenerate vector surfaces the underlying [`CalibrationError`] rather than
/// silently dropping the symbol (an unscored change is never treated as
/// conforming).
pub fn score_commit(
    commit_ref: &str,
    symbols: &[CommitSymbol],
    profile: &GuardProfile,
) -> Result<CommitOodReport, CalibrationError> {
    let mut triggers = Vec::new();
    for symbol in symbols {
        let region = resolve_region(&symbol.exemplars)?;
        let report =
            check_candidate_with_lock(&symbol.candidate, profile, &region, symbol.identity_locked)?;
        if report.combined.verdict != GuardVerdict::Accept {
            triggers.push(CommitOodTrigger {
                schema: COMMIT_OOD_SCHEMA,
                trigger: COMMIT_OOD_TRIGGER_KIND,
                commit_ref: commit_ref.to_string(),
                subject_cx_hex: symbol.cx_id_hex.clone(),
                verdict: report.combined.verdict,
                region_class: report.region_class.as_str(),
                reason: report.combined.reason.clone(),
            });
        }
    }
    Ok(CommitOodReport {
        schema: COMMIT_OOD_SCHEMA,
        commit_ref: commit_ref.to_string(),
        scored: symbols.len(),
        ood: !triggers.is_empty(),
        triggers,
    })
}

/// Minimal JSON string escaping for the hand-built canonical bytes.
fn json_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calibration::{CalibrationDomain, CalibrationLanguage};
    use crate::check::{MeasuredSymbol, SlotFeature, SymbolSlotInput, measure_symbol_slots};
    use crate::profile::{GuardProfile, GuardSlot, SlotCalibration, default_content_policy};

    fn domain() -> CalibrationDomain {
        CalibrationDomain::new(CalibrationLanguage::Rust, "core").expect("valid domain")
    }

    fn symbol_input(seed: f32, dim: usize) -> SymbolSlotInput {
        let slots = GuardSlot::ALL
            .iter()
            .enumerate()
            .map(|(ordinal, slot)| {
                let vector: Vec<f32> = (0..dim)
                    .map(|i| (seed * (i as f32 + 1.0) + ordinal as f32 * 0.001).sin())
                    .collect();
                SlotFeature {
                    slot: *slot,
                    vector,
                }
            })
            .collect();
        SymbolSlotInput { slots }
    }

    fn measured(seed: f32, dim: usize) -> MeasuredSymbol {
        measure_symbol_slots(&symbol_input(seed, dim)).expect("measures")
    }

    fn exemplar(seed: f32, dim: usize, cx: &str) -> Exemplar {
        Exemplar {
            cx_id_hex: cx.to_string(),
            kernel_near: true,
            measured: measured(seed, dim),
        }
    }

    fn profile_with_tau(tau: f32) -> GuardProfile {
        let slots: Vec<SlotCalibration> = GuardSlot::ALL
            .iter()
            .map(|slot| {
                let mut cal = SlotCalibration::cold_start(*slot);
                cal.tau = tau;
                cal.provisional = false;
                cal.achieved_far = 0.02;
                cal
            })
            .collect();
        GuardProfile {
            domain: domain(),
            slots,
            content_policy: default_content_policy(),
            provisional: false,
            corpus_hash: [0u8; 32],
            calibrated_ledger_seq: Some(1),
        }
    }

    // -- DoD #3: watcher OOD trigger with commit ref, conforming => none ------

    #[test]
    fn alien_commit_raises_new_region_trigger_with_commit_ref() {
        let dim = 16;
        // Trusted region around seed 0.5; the changed symbol is alien (seed 2.3).
        let symbols = vec![CommitSymbol {
            cx_id_hex: "cx:changed".to_string(),
            identity_locked: true,
            candidate: measured(2.3, dim),
            exemplars: vec![exemplar(0.5, dim, "cx:kernel")],
        }];
        // Strict taus force the alien symbol OOD.
        let report = score_commit("commit:abc123", &symbols, &profile_with_tau(0.999)).unwrap();
        assert!(report.ood, "an alien commit symbol makes the commit OOD");
        assert_eq!(report.scored, 1);
        assert_eq!(report.triggers.len(), 1);
        let trigger = &report.triggers[0];
        assert_eq!(trigger.trigger, COMMIT_OOD_TRIGGER_KIND);
        assert_eq!(
            trigger.commit_ref, "commit:abc123",
            "the trigger carries the commit ref"
        );
        assert_eq!(trigger.subject_cx_hex, "cx:changed");
        assert_ne!(trigger.verdict, GuardVerdict::Accept);
    }

    #[test]
    fn conforming_commit_raises_no_trigger() {
        let dim = 16;
        // The changed symbol is identical to the trusted exemplar (cosine ~1.0),
        // so it conforms on every slot against a permissive tau.
        let symbols = vec![CommitSymbol {
            cx_id_hex: "cx:changed".to_string(),
            identity_locked: true,
            candidate: measured(0.5, dim),
            exemplars: vec![exemplar(0.5, dim, "cx:kernel")],
        }];
        let report = score_commit("commit:def456", &symbols, &profile_with_tau(0.8)).unwrap();
        assert!(!report.ood, "a conforming commit is not OOD");
        assert_eq!(report.scored, 1);
        assert!(
            report.triggers.is_empty(),
            "no trigger for a conforming commit"
        );
    }

    #[test]
    fn empty_region_fails_closed_never_silently_conforming() {
        let symbols = vec![CommitSymbol {
            cx_id_hex: "cx:changed".to_string(),
            identity_locked: false,
            candidate: measured(0.5, 8),
            exemplars: vec![], // no trusted exemplars => unscored
        }];
        let err = score_commit("commit:xyz", &symbols, &profile_with_tau(0.8))
            .expect_err("an unscored symbol must fail closed, not be treated as conforming");
        assert_eq!(err.code(), "ASTRO_GUARD_CHECK_NO_REGION");
    }

    #[test]
    fn commit_ood_trigger_bytes_reparse_with_commit_ref() {
        let symbols = vec![CommitSymbol {
            cx_id_hex: "cx:c".to_string(),
            identity_locked: true,
            candidate: measured(2.3, 16),
            exemplars: vec![exemplar(0.5, 16, "cx:kernel")],
        }];
        let report = score_commit("commit:HEAD~1", &symbols, &profile_with_tau(0.999)).unwrap();
        let value: serde_json::Value =
            serde_json::from_slice(&report.triggers[0].canonical_bytes()).expect("valid JSON");
        assert_eq!(value["schema"], COMMIT_OOD_SCHEMA);
        assert_eq!(value["trigger"], COMMIT_OOD_TRIGGER_KIND);
        assert_eq!(value["commit_ref"], "commit:HEAD~1");
        assert_eq!(value["subject_cx"], "cx:c");
    }
}
