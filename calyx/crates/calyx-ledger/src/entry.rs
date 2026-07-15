//! Canonical ledger entry structure and hash framing.

use calyx_core::{CalyxError, CxId, LensId, Result};
use serde::{Deserialize, Serialize};

use crate::kind::EntryKind;

pub(crate) const HASH_BYTES: usize = 32;
pub(crate) const TAG_CX: u8 = 0;
pub(crate) const TAG_LENS: u8 = 1;
pub(crate) const TAG_KERNEL: u8 = 2;
pub(crate) const TAG_GUARD: u8 = 3;
pub(crate) const TAG_QUERY: u8 = 4;
pub(crate) const TAG_AGENT: u8 = 0;
pub(crate) const TAG_SERVICE: u8 = 1;
pub(crate) const TAG_SYSTEM: u8 = 2;
const MAX_ACTOR_ID_BYTES: usize = 64;

/// Tagged subject identifier for the ledger entry's primary object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubjectId {
    Cx(CxId),
    Lens(LensId),
    Kernel(Vec<u8>),
    Guard(Vec<u8>),
    Query(Vec<u8>),
}

impl SubjectId {
    pub(crate) fn wire_tag(&self) -> u8 {
        match self {
            Self::Cx(_) => TAG_CX,
            Self::Lens(_) => TAG_LENS,
            Self::Kernel(_) => TAG_KERNEL,
            Self::Guard(_) => TAG_GUARD,
            Self::Query(_) => TAG_QUERY,
        }
    }

    pub(crate) fn wire_bytes(&self) -> Vec<u8> {
        match self {
            Self::Cx(id) => id.as_bytes().to_vec(),
            Self::Lens(id) => id.as_bytes().to_vec(),
            Self::Kernel(bytes) | Self::Guard(bytes) | Self::Query(bytes) => bytes.clone(),
        }
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        tagged_slice(self.wire_tag(), &self.wire_bytes())
    }
}

/// Tagged actor identifier for the service or agent that caused an entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActorId {
    Agent(String),
    Service(String),
    System,
}

impl ActorId {
    pub(crate) fn wire_tag(&self) -> u8 {
        match self {
            Self::Agent(_) => TAG_AGENT,
            Self::Service(_) => TAG_SERVICE,
            Self::System => TAG_SYSTEM,
        }
    }

    pub(crate) fn wire_bytes(&self) -> &[u8] {
        match self {
            Self::Agent(value) | Self::Service(value) => value.as_bytes(),
            Self::System => &[],
        }
    }

    pub fn validate(&self) -> Result<()> {
        let len = self.wire_bytes().len();
        if len <= MAX_ACTOR_ID_BYTES {
            Ok(())
        } else {
            Err(CalyxError::ledger_actor_too_long(format!(
                "actor id has {len} UTF-8 bytes, max {MAX_ACTOR_ID_BYTES}"
            )))
        }
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        tagged_var(self.wire_tag(), self.wire_bytes())
    }
}

/// Canonical append-only ledger entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub seq: u64,
    pub prev_hash: [u8; HASH_BYTES],
    pub kind: EntryKind,
    pub subject: SubjectId,
    pub payload: Vec<u8>,
    pub actor: ActorId,
    pub ts: u64,
    pub entry_hash: [u8; HASH_BYTES],
}

impl LedgerEntry {
    /// Builds an entry and computes its canonical BLAKE3 hash.
    pub fn new(
        seq: u64,
        prev_hash: [u8; HASH_BYTES],
        kind: EntryKind,
        subject: SubjectId,
        payload: Vec<u8>,
        actor: ActorId,
        ts: u64,
    ) -> Self {
        let entry_hash = compute_entry_hash(seq, &prev_hash, kind, &subject, &payload, &actor, ts);
        Self {
            seq,
            prev_hash,
            kind,
            subject,
            payload,
            actor,
            ts,
            entry_hash,
        }
    }

    /// Recomputes and compares the canonical entry hash.
    pub fn verify(&self) -> bool {
        self.entry_hash
            == compute_entry_hash(
                self.seq,
                &self.prev_hash,
                self.kind,
                &self.subject,
                &self.payload,
                &self.actor,
                self.ts,
            )
    }
}

/// Computes the canonical BLAKE3 ledger entry hash.
pub fn compute_entry_hash(
    seq: u64,
    prev_hash: &[u8; HASH_BYTES],
    kind: EntryKind,
    subject: &SubjectId,
    payload: &[u8],
    actor: &ActorId,
    ts: u64,
) -> [u8; HASH_BYTES] {
    let mut hasher = blake3::Hasher::new();
    frame(&mut hasher, &seq.to_be_bytes());
    frame(&mut hasher, prev_hash);
    frame(&mut hasher, &[kind.wire_code()]);
    frame(&mut hasher, &subject.canonical_bytes());
    frame(&mut hasher, payload);
    frame(&mut hasher, &actor.canonical_bytes());
    frame(&mut hasher, &ts.to_be_bytes());
    *hasher.finalize().as_bytes()
}

fn frame(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn tagged_slice(tag: u8, bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + bytes.len());
    out.push(tag);
    out.extend_from_slice(bytes);
    out
}

fn tagged_var(tag: u8, bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 8 + bytes.len());
    out.push(tag);
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
    out
}
