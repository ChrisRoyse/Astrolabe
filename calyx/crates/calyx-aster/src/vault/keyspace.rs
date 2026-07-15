//! Per-vault keyspace isolation (PH60 · T02).
//!
//! [`KeyspaceGuard`] enforces that every CF key a vault writes or reads is
//! prefixed with that vault's unique 16-byte `VaultId`, so one vault's read
//! path **cannot structurally reach** another vault's key range. This is the
//! second layer of the defense-in-depth tenant-isolation stack (key +
//! **keyspace** + grant — PRD `30 §2`), sitting above [`super::key::VaultKey`].
//!
//! ## Why a 16-byte prefix (not 8)
//!
//! A `VaultId` wraps a 128-bit ULID. The task card sketched an 8-byte
//! (`as_u64`) prefix, but truncating a 128-bit identifier to 64 bits is **not
//! collision-free** — two distinct vaults could share a prefix and alias into
//! each other's keyspace, the exact failure tenant isolation must rule out
//! (prefix aliasing — see PR notes). We therefore use the **full ULID** as the
//! prefix: distinct `VaultId` ⟺ distinct prefix, with zero collision risk.
//! Every decode re-verifies the full prefix and fails closed on mismatch (A16).
//!
//! ## Why the write lock is a separate type
//!
//! [`KeyspaceGuard`] is a `Copy`, stateless key codec. A per-vault write lock
//! must be a **single shared** `Mutex` — if every `KeyspaceGuard::new` minted
//! its own mutex, two guards for the same vault would not actually exclude each
//! other. So the lock lives in [`VaultWriteLock`], constructed once per vault
//! and shared, rather than inside the copyable codec.

use crate::cf::ColumnFamily;
use calyx_core::{CalyxError, Result, VaultId};
use std::sync::{Mutex, MutexGuard};

/// A CF key presented to a vault guard did not carry that vault's keyspace
/// prefix (or was too short / malformed to carry one).
pub const CALYX_VAULT_KEYSPACE_MISMATCH: &str = "CALYX_VAULT_KEYSPACE_MISMATCH";

/// Width of the vault keyspace prefix: the full 16-byte ULID.
pub const PREFIX_LEN: usize = 16;

/// Returns the deterministic, collision-free keyspace prefix for `vault_id`:
/// the full 16 bytes of its ULID, in ULID byte order.
pub fn vault_prefix(vault_id: &VaultId) -> [u8; PREFIX_LEN] {
    vault_id.as_ulid().to_bytes()
}

/// Stateless per-vault CF-key codec enforcing keyspace isolation.
///
/// Holds no secret material, so it is `Copy`. The only path that produces a
/// storable, vault-scoped CF key is [`KeyspaceGuard::encode_key`]; the only
/// path that reads one back is [`KeyspaceGuard::decode_key`], which fails
/// closed if the key belongs to another vault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyspaceGuard {
    vault_id: VaultId,
    prefix: [u8; PREFIX_LEN],
}

impl KeyspaceGuard {
    /// Builds a guard for `vault_id`, deriving its keyspace prefix.
    pub fn new(vault_id: VaultId) -> Self {
        Self {
            vault_id,
            prefix: vault_prefix(&vault_id),
        }
    }

    /// The vault this guard scopes keys to.
    pub fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    /// The 16-byte keyspace prefix every key for this vault carries.
    pub fn prefix(&self) -> &[u8; PREFIX_LEN] {
        &self.prefix
    }

    /// Encodes a storable CF key: `prefix ‖ cf_tag ‖ user_key`.
    ///
    /// This is the only path that produces a CF key for a vault-scoped
    /// operation. The `cf` tag round-trips exactly through [`decode_key`].
    pub fn encode_key(&self, cf: ColumnFamily, user_key: &[u8]) -> Vec<u8> {
        let tag = cf.keyspace_tag();
        let mut out = Vec::with_capacity(PREFIX_LEN + tag.len() + user_key.len());
        out.extend_from_slice(&self.prefix);
        out.extend_from_slice(&tag);
        out.extend_from_slice(user_key);
        out
    }

    /// Fast prefix check without allocating — used in range-scan filters.
    /// Returns `true` iff `raw` begins with this vault's full prefix.
    pub fn owns_key(&self, raw: &[u8]) -> bool {
        raw.get(..PREFIX_LEN) == Some(&self.prefix[..])
    }

    /// Decodes a raw CF key back into `(ColumnFamily, user_key)`, verifying it
    /// belongs to this vault.
    ///
    /// # Errors
    /// [`CALYX_VAULT_KEYSPACE_MISMATCH`] if the leading 16 bytes are not this
    /// vault's prefix, the key is shorter than the prefix, or the CF tag is
    /// malformed. Never returns another vault's key bytes (fail closed, A16).
    pub fn decode_key<'a>(&self, raw: &'a [u8]) -> Result<(ColumnFamily, &'a [u8])> {
        if !self.owns_key(raw) {
            return Err(keyspace_mismatch(format!(
                "key prefix does not match vault {} (got {} leading bytes)",
                self.vault_id,
                raw.len().min(PREFIX_LEN),
            )));
        }
        let rest = &raw[PREFIX_LEN..];
        ColumnFamily::parse_keyspace_tag(rest)
            .ok_or_else(|| keyspace_mismatch("malformed column-family tag after vault prefix"))
    }
}

/// Single-instance, per-vault write lock guarding WAL group-commit ordering so
/// concurrent cross-vault mutations cannot interleave a vault's keys.
///
/// Construct exactly one per vault and share it; cloning the lock would defeat
/// the mutual exclusion it exists to provide.
#[derive(Debug, Default)]
pub struct VaultWriteLock {
    inner: Mutex<()>,
}

impl VaultWriteLock {
    /// Creates an unlocked per-vault write lock.
    pub fn new() -> Self {
        Self::default()
    }

    /// Acquires the lock, blocking until available. Released on guard drop.
    ///
    /// Recovers from poisoning (a panic while held does not wedge the vault):
    /// the lock protects ordering, not invariant-bearing data.
    pub fn lock(&self) -> VaultWriteLockGuard<'_> {
        let guard = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        VaultWriteLockGuard { _inner: guard }
    }

    /// Attempts to acquire without blocking; `None` if already held.
    pub fn try_lock(&self) -> Option<VaultWriteLockGuard<'_>> {
        match self.inner.try_lock() {
            Ok(guard) => Some(VaultWriteLockGuard { _inner: guard }),
            Err(std::sync::TryLockError::WouldBlock) => None,
            Err(std::sync::TryLockError::Poisoned(poisoned)) => Some(VaultWriteLockGuard {
                _inner: poisoned.into_inner(),
            }),
        }
    }
}

/// RAII guard releasing the [`VaultWriteLock`] on drop.
#[derive(Debug)]
pub struct VaultWriteLockGuard<'a> {
    _inner: MutexGuard<'a, ()>,
}

fn keyspace_mismatch(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: CALYX_VAULT_KEYSPACE_MISMATCH,
        message: message.into(),
        remediation: "read/write keys only through the owning vault's KeyspaceGuard",
    }
}
