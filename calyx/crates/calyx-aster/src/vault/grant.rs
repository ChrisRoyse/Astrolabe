//! Cross-vault grant model with default-deny semantics (PH60 · T03).
//!
//! [`GrantStore`] is the third layer of the defense-in-depth tenant-isolation
//! stack (key + keyspace + **grant** — PRD `30 §3`), above [`super::key`] and
//! [`super::keyspace`]. One vault = one tenant boundary. A cross-vault read is
//! **denied by default**: it requires an explicit, non-expired [`GrantEntry`],
//! and *every* decision — grant, deny, revoke — is recorded in an immutable
//! audit ring (the stub Ledger until PH36 is wired in PH61).
//!
//! This mirrors the established cross-tenant pattern: deny unless an explicit
//! grant says otherwise, and log every access decision for accountability.
//! A denied check **fails closed** with [`CALYX_VAULT_ACCESS_DENIED`] (A16) —
//! even when the caller already knows the target vault's id.

use calyx_core::{CalyxError, Result, Ts, VaultId};
use calyx_ledger::ActorId;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

/// Maximum events retained in the audit ring (capacity-bounded, A26). The
/// oldest event is dropped once this is exceeded.
pub const AUDIT_RING_CAPACITY: usize = 1024;

/// An explicit permission for `actor` to read from `dst_vault` while operating
/// in `src_vault`. Absence of a matching active entry means **denied**.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantEntry {
    /// Vault the actor is operating in (the reader's home vault).
    pub src_vault: VaultId,
    /// Vault being read across into.
    pub dst_vault: VaultId,
    /// Principal the grant is issued to.
    pub actor: ActorId,
    /// When the grant was issued (Unix millis).
    pub granted_at: Ts,
    /// Optional expiry (Unix millis); `None` = never expires.
    pub expires_at: Option<Ts>,
    /// Reserved for write-grant support; cross-vault is read-only today.
    pub read_only: bool,
}

impl GrantEntry {
    /// True iff this entry authorizes `(src, dst, actor)` and has not expired at
    /// `now`. Expiry is exclusive: a grant with `expires_at = e` is active while
    /// `now < e` and expired at `now == e` (no off-by-one — see expiry test).
    fn authorizes(&self, src: VaultId, dst: VaultId, actor: &ActorId, now: Ts) -> bool {
        self.src_vault == src
            && self.dst_vault == dst
            && &self.actor == actor
            && self.expires_at.is_none_or(|e| now < e)
    }

    /// True iff this entry has the same identity tuple `(src, dst, actor)` —
    /// used for idempotent add and for revoke.
    fn same_principal(&self, src: VaultId, dst: VaultId, actor: &ActorId) -> bool {
        self.src_vault == src && self.dst_vault == dst && &self.actor == actor
    }
}

/// An immutable record of a single access-control decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AuditEvent {
    /// A grant was added (or replaced).
    Granted {
        src_vault: VaultId,
        dst_vault: VaultId,
        actor: ActorId,
        at: Ts,
    },
    /// A cross-vault read was denied (default-deny or expired/absent grant).
    Denied {
        src_vault: VaultId,
        dst_vault: VaultId,
        actor: ActorId,
        at: Ts,
    },
    /// A grant was revoked.
    Revoked {
        src_vault: VaultId,
        dst_vault: VaultId,
        actor: ActorId,
        at: Ts,
    },
}

/// Default-deny cross-vault grant table with a bounded immutable audit ring.
#[derive(Debug, Default)]
pub struct GrantStore {
    grants: Vec<GrantEntry>,
    audit_ring: Arc<Mutex<VecDeque<AuditEvent>>>,
}

impl GrantStore {
    /// Builds an empty store: no grants, fresh audit ring.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a grant, idempotent by `(src, dst, actor)`: an existing entry for the
    /// same principal is **replaced** (re-issuing updates expiry, never
    /// duplicates). Writes an [`AuditEvent::Granted`].
    pub fn add_grant(&mut self, entry: GrantEntry) {
        let at = entry.granted_at;
        let (src, dst, actor) = (entry.src_vault, entry.dst_vault, entry.actor.clone());
        if let Some(existing) = self
            .grants
            .iter_mut()
            .find(|g| g.same_principal(src, dst, &actor))
        {
            *existing = entry;
        } else {
            self.grants.push(entry);
        }
        self.push_audit(AuditEvent::Granted {
            src_vault: src,
            dst_vault: dst,
            actor,
            at,
        });
    }

    /// Removes any grant for `(src, dst, actor)` and writes an
    /// [`AuditEvent::Revoked`] at `now`. A revoke of a non-existent grant is a
    /// no-op on the table but is still audited (the intent is recorded).
    pub fn revoke_grant(&mut self, src: VaultId, dst: VaultId, actor: ActorId, now: Ts) {
        self.grants.retain(|g| !g.same_principal(src, dst, &actor));
        self.push_audit(AuditEvent::Revoked {
            src_vault: src,
            dst_vault: dst,
            actor,
            at: now,
        });
    }

    /// Default-deny authorization check for a cross-vault read.
    ///
    /// Returns `Ok(())` iff `src == dst` (a vault always reads itself) **or** a
    /// matching non-expired [`GrantEntry`] exists. Otherwise records an
    /// [`AuditEvent::Denied`] and returns [`CALYX_VAULT_ACCESS_DENIED`].
    /// Never panics on an unknown principal — fail closed (A16).
    pub fn check_grant(&self, src: VaultId, dst: VaultId, actor: ActorId, now: Ts) -> Result<()> {
        // A vault reading its own keyspace needs no grant.
        if src == dst {
            return Ok(());
        }
        let authorized = self
            .grants
            .iter()
            .any(|g| g.authorizes(src, dst, &actor, now));
        if authorized {
            return Ok(());
        }
        self.push_audit(AuditEvent::Denied {
            src_vault: src,
            dst_vault: dst,
            actor: actor.clone(),
            at: now,
        });
        Err(CalyxError::vault_access_denied(format!(
            "no active grant for {actor:?} reading {src} -> {dst} at t={now}"
        )))
    }

    /// Returns up to `last_n` most-recent audit events, oldest-first, for FSV
    /// inspection. Reading the ring is a separate operation from the decision
    /// that wrote it (the Source-of-Truth read).
    pub fn audit_events(&self, last_n: usize) -> Vec<AuditEvent> {
        let ring = self.lock_ring();
        let start = ring.len().saturating_sub(last_n);
        ring.iter().skip(start).cloned().collect()
    }

    /// Number of active grant entries currently in the table.
    pub fn grant_count(&self) -> usize {
        self.grants.len()
    }

    /// Total events currently retained in the audit ring.
    pub fn audit_len(&self) -> usize {
        self.lock_ring().len()
    }

    fn push_audit(&self, event: AuditEvent) {
        let mut ring = self.lock_ring();
        if ring.len() >= AUDIT_RING_CAPACITY {
            ring.pop_front();
        }
        ring.push_back(event);
    }

    /// Locks the ring, recovering from poisoning (a panic while holding the lock
    /// must not wedge audit; the ring carries no cross-entry invariant).
    fn lock_ring(&self) -> std::sync::MutexGuard<'_, VecDeque<AuditEvent>> {
        self.audit_ring
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}
