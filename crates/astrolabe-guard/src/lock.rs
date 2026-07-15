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
