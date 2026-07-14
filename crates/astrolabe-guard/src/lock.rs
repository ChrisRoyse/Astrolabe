//! Identity-lock inventory for public APIs (P7.4, blueprint `10_GUARD.md` §4,
//! capabilities 6.5/6.8/6.9).
//!
//! Exported/public API symbols are **identity-locked**: their public-API
//! signature slot ([`crate::profile::GuardSlot::PublicApiSignature`], S5+S17) is
//! enforced `AllRequired` at the identity FAR (0.01) so breaking-change drift on
//! a locked surface refuses. A non-exported symbol is not identity-locked; the
//! same drift is handled as content-class (see
//! [`crate::profile::combine_verdicts_with_lock`]).
//!
//! The **lock inventory** is derived directly from extraction's export/public
//! flags: the set of locked symbols is exactly the set of exported symbols
//! (parity, proven by test). The inventory serializes to canonical, deterministic
//! bytes so a lock decision is auditably paired with its ledger entry (HONEST
//! invariant 5), and lock/unlock is **reversible** — an unlock returns the
//! inventory byte-for-byte to its pre-lock state (proven by readback).
//!
//! # Fail-closed
//!
//! Locking a symbol that extraction did not flag exported/public refuses
//! (`ASTRO_GUARD_LOCK_NOT_EXPORTED`) rather than locking a private symbol that
//! has no public surface to protect. Re-locking an already-locked symbol is
//! idempotent (no duplicate entry). Unlocking a symbol that is not locked
//! refuses (`ASTRO_GUARD_LOCK_NOT_LOCKED`).

use std::collections::BTreeMap;

use crate::calibration::CalibrationError;

/// Schema tag for the canonical lock-inventory serialization.
pub const LOCK_INVENTORY_SCHEMA: &str = "astro.guard.lock_inventory.v1";

/// Schema tag for a per-target lock decision (ledgered with a `guard_check`
/// verdict so the identity-lock routing is auditable).
pub const LOCK_DECISION_SCHEMA: &str = "astro.guard.lock_decision.v1";

/// A symbol as surfaced by extraction, carrying the export/public flag that
/// decides whether its public-API signature slot is identity-locked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockCandidate {
    /// Hex CxId of the symbol.
    pub cx_id_hex: String,
    /// Fully-qualified symbol name (for the surfaced inventory / provenance).
    pub qualified_name: String,
    /// `true` iff extraction flagged the symbol exported/public. This is the
    /// sole determinant of identity-lock membership (parity invariant).
    pub exported: bool,
}

/// The before/after result of a lock or unlock mutation, carrying the inventory's
/// canonical bytes so an independent readback can confirm the persisted state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockChange {
    pub cx_id_hex: String,
    /// Lock membership before the mutation.
    pub was_locked: bool,
    /// Lock membership after the mutation.
    pub now_locked: bool,
    /// `true` when a lock request found the symbol already locked (idempotent
    /// re-lock) or an unlock request found it already absent — a no-op.
    pub idempotent: bool,
    /// Canonical inventory bytes after the mutation (the persisted image).
    pub inventory_bytes: Vec<u8>,
}

/// The per-target identity-lock routing decision consumed by `guard_check` and
/// paired with the verdict ledger entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockDecision {
    pub schema: &'static str,
    pub subject_cx_hex: String,
    /// `true` when the target is identity-locked (exported/public); its
    /// public-API signature slot is enforced `AllRequired` at the identity FAR.
    pub identity_locked: bool,
}

impl LockDecision {
    /// Canonical UTF-8 JSON bytes of the lock decision (stable key order) so the
    /// server can hash it and read it back byte-for-byte.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        format!(
            "{{\"schema\":\"{}\",\"subject_cx\":\"{}\",\"identity_locked\":{}}}",
            LOCK_DECISION_SCHEMA,
            json_escape(&self.subject_cx_hex),
            self.identity_locked
        )
        .into_bytes()
    }
}

/// The identity-lock inventory: the set of locked (exported/public) symbols,
/// keyed by CxId hex, each with its qualified name for the surfaced inventory.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LockInventory {
    /// cx_id_hex -> qualified_name, kept sorted by key via `BTreeMap` so the
    /// canonical serialization is deterministic regardless of insertion order.
    locked: BTreeMap<String, String>,
}

impl LockInventory {
    /// An empty inventory.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build the inventory directly from extraction flags: the locked set is
    /// exactly the exported/public symbols (parity invariant, proven by test).
    pub fn from_extraction(symbols: &[LockCandidate]) -> Self {
        let mut locked = BTreeMap::new();
        for symbol in symbols {
            if symbol.exported {
                locked.insert(symbol.cx_id_hex.clone(), symbol.qualified_name.clone());
            }
        }
        Self { locked }
    }

    /// Whether `cx_id_hex` is identity-locked.
    pub fn is_locked(&self, cx_id_hex: &str) -> bool {
        self.locked.contains_key(cx_id_hex)
    }

    /// The number of locked symbols.
    pub fn len(&self) -> usize {
        self.locked.len()
    }

    /// Whether the inventory is empty.
    pub fn is_empty(&self) -> bool {
        self.locked.is_empty()
    }

    /// The locked CxIds, in canonical (sorted) order.
    pub fn locked_cx_ids(&self) -> impl Iterator<Item = &str> {
        self.locked.keys().map(String::as_str)
    }

    /// The per-target lock decision for `cx_id_hex` (identity-locked iff present).
    pub fn decision_for(&self, cx_id_hex: &str) -> LockDecision {
        LockDecision {
            schema: LOCK_DECISION_SCHEMA,
            subject_cx_hex: cx_id_hex.to_string(),
            identity_locked: self.is_locked(cx_id_hex),
        }
    }

    /// Lock a candidate's public API. **Fails closed** if extraction did not flag
    /// the candidate exported/public — a private symbol has no public surface to
    /// breaking-change-protect, so it cannot be identity-locked. Re-locking an
    /// already-locked symbol is idempotent (no duplicate entry).
    pub fn lock(&mut self, candidate: &LockCandidate) -> Result<LockChange, CalibrationError> {
        if !candidate.exported {
            return Err(CalibrationError::new(
                "ASTRO_GUARD_LOCK_NOT_EXPORTED",
                format!(
                    "symbol `{}` ({}) is not flagged exported/public; only public API symbols can \
                     be identity-locked",
                    candidate.qualified_name, candidate.cx_id_hex
                ),
                "Identity-lock only exported/public symbols; a private symbol has no public \
                 surface to protect.",
            ));
        }
        let was_locked = self.is_locked(&candidate.cx_id_hex);
        self.locked.insert(
            candidate.cx_id_hex.clone(),
            candidate.qualified_name.clone(),
        );
        Ok(LockChange {
            cx_id_hex: candidate.cx_id_hex.clone(),
            was_locked,
            now_locked: true,
            idempotent: was_locked,
            inventory_bytes: self.canonical_bytes(),
        })
    }

    /// Unlock a symbol (reversible). **Fails closed** if the symbol is not
    /// currently locked. A successful unlock returns the inventory to the state
    /// it held before the corresponding lock (proven by canonical-byte readback).
    pub fn unlock(&mut self, cx_id_hex: &str) -> Result<LockChange, CalibrationError> {
        if !self.is_locked(cx_id_hex) {
            return Err(CalibrationError::new(
                "ASTRO_GUARD_LOCK_NOT_LOCKED",
                format!("symbol `{cx_id_hex}` is not identity-locked; nothing to unlock"),
                "Unlock only a currently locked symbol.",
            ));
        }
        self.locked.remove(cx_id_hex);
        Ok(LockChange {
            cx_id_hex: cx_id_hex.to_string(),
            was_locked: true,
            now_locked: false,
            idempotent: false,
            inventory_bytes: self.canonical_bytes(),
        })
    }

    /// Canonical, deterministic UTF-8 JSON bytes of the inventory (locked symbols
    /// in sorted CxId order). Two inventories with the same locked set produce
    /// byte-identical output regardless of insertion order.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = String::new();
        out.push('{');
        out.push_str(&format!("\"schema\":\"{LOCK_INVENTORY_SCHEMA}\","));
        out.push_str(&format!("\"locked_count\":{},", self.locked.len()));
        out.push_str("\"locked\":[");
        for (index, (cx, name)) in self.locked.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            out.push_str(&format!(
                "{{\"cx\":\"{}\",\"qualified_name\":\"{}\"}}",
                json_escape(cx),
                json_escape(name)
            ));
        }
        out.push_str("]}");
        out.into_bytes()
    }
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

    fn candidate(cx: &str, name: &str, exported: bool) -> LockCandidate {
        LockCandidate {
            cx_id_hex: cx.to_string(),
            qualified_name: name.to_string(),
            exported,
        }
    }

    // -- DoD #5: lock inventory correctness (parity with extraction flags) ----

    #[test]
    fn inventory_locked_set_equals_exported_set() {
        let symbols = vec![
            candidate("cx:a", "mod::public_a", true),
            candidate("cx:b", "mod::private_b", false),
            candidate("cx:c", "mod::public_c", true),
            candidate("cx:d", "mod::private_d", false),
            candidate("cx:e", "mod::public_e", true),
        ];
        let inventory = LockInventory::from_extraction(&symbols);

        // The locked set is exactly the exported/public symbols — no more, no less.
        let locked: Vec<&str> = inventory.locked_cx_ids().collect();
        assert_eq!(locked, vec!["cx:a", "cx:c", "cx:e"]);
        assert_eq!(inventory.len(), 3);

        for symbol in &symbols {
            assert_eq!(
                inventory.is_locked(&symbol.cx_id_hex),
                symbol.exported,
                "lock membership must match the extraction exported flag for {}",
                symbol.cx_id_hex
            );
        }
    }

    #[test]
    fn canonical_bytes_are_deterministic_and_insertion_order_independent() {
        let forward = LockInventory::from_extraction(&[
            candidate("cx:a", "a", true),
            candidate("cx:b", "b", true),
            candidate("cx:c", "c", true),
        ]);
        let reversed = LockInventory::from_extraction(&[
            candidate("cx:c", "c", true),
            candidate("cx:b", "b", true),
            candidate("cx:a", "a", true),
        ]);
        assert_eq!(
            forward.canonical_bytes(),
            reversed.canonical_bytes(),
            "canonical bytes must be sorted-key stable regardless of insertion order"
        );
        // Valid, reparsable JSON carrying the locked set.
        let text = String::from_utf8(forward.canonical_bytes()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
        assert_eq!(value["schema"], LOCK_INVENTORY_SCHEMA);
        assert_eq!(value["locked_count"], 3);
        assert_eq!(value["locked"].as_array().unwrap().len(), 3);
    }

    // -- Edge case: lock a nonexistent / non-exported API fails closed --------

    #[test]
    fn locking_a_non_exported_symbol_fails_closed() {
        let mut inventory = LockInventory::new();
        let err = inventory
            .lock(&candidate("cx:priv", "mod::private", false))
            .expect_err("locking a private symbol must refuse");
        assert_eq!(err.code(), "ASTRO_GUARD_LOCK_NOT_EXPORTED");
        assert!(!err.remediation().is_empty());
        // The refusal persisted nothing.
        assert!(inventory.is_empty());
    }

    #[test]
    fn unlocking_an_unlocked_symbol_fails_closed() {
        let mut inventory = LockInventory::new();
        let err = inventory
            .unlock("cx:absent")
            .expect_err("unlocking an absent symbol must refuse");
        assert_eq!(err.code(), "ASTRO_GUARD_LOCK_NOT_LOCKED");
    }

    // -- Edge case: double-lock is idempotent (no duplicate) ------------------

    #[test]
    fn double_lock_is_idempotent_with_stable_bytes() {
        let mut inventory = LockInventory::new();
        let cand = candidate("cx:pub", "mod::public", true);

        let first = inventory.lock(&cand).expect("first lock");
        assert!(!first.was_locked);
        assert!(first.now_locked);
        assert!(!first.idempotent);

        let second = inventory.lock(&cand).expect("second lock idempotent");
        assert!(second.was_locked);
        assert!(second.now_locked);
        assert!(second.idempotent, "re-locking must be idempotent");

        // No duplicate entry; the inventory holds exactly one lock and the bytes
        // are unchanged across the idempotent re-lock.
        assert_eq!(inventory.len(), 1);
        assert_eq!(
            first.inventory_bytes, second.inventory_bytes,
            "idempotent re-lock must not change the persisted image"
        );
    }

    // -- Reversibility: unlock returns to the exact pre-lock state ------------

    #[test]
    fn lock_then_unlock_is_reversible_by_readback() {
        let mut inventory = LockInventory::from_extraction(&[candidate("cx:base", "base", true)]);
        let before = inventory.canonical_bytes();

        let cand = candidate("cx:pub", "mod::public", true);
        inventory.lock(&cand).expect("lock");
        assert!(inventory.is_locked("cx:pub"));
        assert_ne!(
            inventory.canonical_bytes(),
            before,
            "lock changed the image"
        );

        let change = inventory.unlock("cx:pub").expect("unlock");
        assert!(change.was_locked && !change.now_locked);
        assert!(!inventory.is_locked("cx:pub"));
        // Independent readback: the post-unlock canonical bytes equal the exact
        // pre-lock bytes — the mutation is fully reversible.
        assert_eq!(
            inventory.canonical_bytes(),
            before,
            "unlock must return the inventory byte-for-byte to its pre-lock state"
        );
        assert_eq!(change.inventory_bytes, before);
    }

    #[test]
    fn lock_decision_bytes_reflect_membership_and_reparse() {
        let inventory = LockInventory::from_extraction(&[candidate("cx:pub", "public", true)]);
        let locked = inventory.decision_for("cx:pub");
        assert!(locked.identity_locked);
        let unlocked = inventory.decision_for("cx:other");
        assert!(!unlocked.identity_locked);

        let value: serde_json::Value =
            serde_json::from_slice(&locked.canonical_bytes()).expect("valid JSON");
        assert_eq!(value["schema"], LOCK_DECISION_SCHEMA);
        assert_eq!(value["subject_cx"], "cx:pub");
        assert_eq!(value["identity_locked"], true);
    }
}
