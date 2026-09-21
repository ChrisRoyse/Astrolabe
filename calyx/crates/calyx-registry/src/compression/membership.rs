use std::collections::BTreeMap;

use calyx_core::{CxId, Result};
use sha2::{Digest, Sha256};

use super::{CALYX_VECTOR_COMPRESSION_EMPTY, CALYX_VECTOR_COMPRESSION_INVALID, compression_error};

pub(super) const COMPRESSION_MEMBERSHIP_VERSION: u8 = 1;

const PROOF_MAGIC: &[u8; 4] = b"CSMP";
const PROOF_PREFIX_BYTES: usize = 68;
const PROOF_DIGEST_BYTES: usize = 32;
const LEAF_DOMAIN: &[u8] = b"calyx-registry-compression-membership-leaf-v1";
const NODE_DOMAIN: &[u8] = b"calyx-registry-compression-membership-node-v1";
const PROOF_DIGEST_DOMAIN: &[u8] = b"calyx-registry-compression-membership-proof-v1";

pub(super) struct BuiltMembership {
    pub(super) root: [u8; 32],
    pub(super) proofs: BTreeMap<CxId, Vec<u8>>,
}

struct MembershipProof {
    cx_id: CxId,
    root: [u8; 32],
    leaf_count: u32,
    leaf_index: u32,
    siblings: Vec<[u8; 32]>,
}

pub(super) fn build_membership<'a>(
    rows: impl IntoIterator<Item = (CxId, &'a [u8])>,
) -> Result<BuiltMembership> {
    let mut rows = rows.into_iter().collect::<Vec<_>>();
    rows.sort_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
    if rows.is_empty() {
        return Err(compression_error(
            CALYX_VECTOR_COMPRESSION_EMPTY,
            "compressed membership generation requires at least one row",
        ));
    }
    if rows
        .windows(2)
        .any(|pair| pair[0].0.as_bytes() == pair[1].0.as_bytes())
    {
        return Err(invalid(
            "compressed membership generation contains duplicate CxIds",
        ));
    }
    let leaf_count = u32::try_from(rows.len())
        .map_err(|_| invalid("compressed membership leaf count exceeds u32"))?;
    let leaves = rows
        .iter()
        .map(|(cx_id, stored)| membership_leaf_hash(*cx_id, stored))
        .collect::<Vec<_>>();
    let levels = membership_levels(leaves)?;
    let root = levels
        .last()
        .and_then(|level| level.first())
        .copied()
        .ok_or_else(|| invalid("compressed membership tree has no root"))?;
    let depth = expected_proof_depth(leaf_count);
    let mut proofs = BTreeMap::new();
    for (leaf_index, (cx_id, _)) in rows.iter().enumerate() {
        let mut index = leaf_index;
        let mut siblings = Vec::with_capacity(depth);
        for level in levels.iter().take(levels.len().saturating_sub(1)) {
            let sibling_index = if index.is_multiple_of(2) {
                (index + 1).min(level.len() - 1)
            } else {
                index - 1
            };
            siblings.push(level[sibling_index]);
            index /= 2;
        }
        let leaf_index = u32::try_from(leaf_index)
            .map_err(|_| invalid("compressed membership leaf index exceeds u32"))?;
        let bytes = encode_proof(MembershipProof {
            cx_id: *cx_id,
            root,
            leaf_count,
            leaf_index,
            siblings,
        })?;
        if proofs.insert(*cx_id, bytes).is_some() {
            return Err(invalid(
                "compressed membership proof map contains duplicate CxIds",
            ));
        }
    }
    Ok(BuiltMembership { root, proofs })
}

pub(super) fn verify_membership_proof(
    bytes: &[u8],
    expected_root: [u8; 32],
    expected_version: u8,
    expected_rows: u32,
    expected_cx_id: CxId,
    stored: &[u8],
) -> Result<[u8; 32]> {
    if expected_version != COMPRESSION_MEMBERSHIP_VERSION {
        return Err(invalid(format!(
            "unsupported compressed membership version {expected_version}; expected {COMPRESSION_MEMBERSHIP_VERSION}"
        )));
    }
    let proof = parse_proof(bytes)?;
    if proof.cx_id != expected_cx_id {
        return Err(invalid(format!(
            "compressed membership proof CxId {} does not match requested CF key {expected_cx_id}",
            proof.cx_id
        )));
    }
    if proof.root != expected_root {
        return Err(invalid(
            "compressed membership proof root does not match its generation manifest",
        ));
    }
    if proof.leaf_count != expected_rows {
        return Err(invalid(format!(
            "compressed membership proof leaf count {} does not match manifest rows {expected_rows}",
            proof.leaf_count
        )));
    }
    let leaf = membership_leaf_hash(expected_cx_id, stored);
    let mut current = leaf;
    let mut index = proof.leaf_index as usize;
    let mut width = proof.leaf_count as usize;
    for sibling in proof.siblings {
        if index.is_multiple_of(2) {
            if index + 1 >= width && sibling != current {
                return Err(invalid(
                    "compressed membership proof has a non-canonical sibling for an unpaired leaf",
                ));
            }
            current = membership_node_hash(current, sibling);
        } else {
            current = membership_node_hash(sibling, current);
        }
        index /= 2;
        width = width / 2 + width % 2;
    }
    if width != 1 || index != 0 || current != expected_root {
        return Err(invalid(
            "compressed row membership proof does not resolve to the manifest root",
        ));
    }
    Ok(leaf)
}

pub(super) fn membership_root_from_leaf_hashes(
    mut leaves: Vec<(CxId, [u8; 32])>,
    expected_rows: u32,
) -> Result<[u8; 32]> {
    leaves.sort_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
    if leaves.len() != expected_rows as usize {
        return Err(invalid(format!(
            "compressed membership leaf count mismatch: manifest={expected_rows} actual={}",
            leaves.len()
        )));
    }
    if leaves
        .windows(2)
        .any(|pair| pair[0].0.as_bytes() == pair[1].0.as_bytes())
    {
        return Err(invalid(
            "compressed membership leaves contain duplicate CxIds",
        ));
    }
    membership_levels(leaves.into_iter().map(|(_, hash)| hash).collect())?
        .last()
        .and_then(|level| level.first())
        .copied()
        .ok_or_else(|| invalid("compressed membership generation has no leaves"))
}

fn membership_levels(leaves: Vec<[u8; 32]>) -> Result<Vec<Vec<[u8; 32]>>> {
    if leaves.is_empty() {
        return Err(compression_error(
            CALYX_VECTOR_COMPRESSION_EMPTY,
            "compressed membership generation has no leaves",
        ));
    }
    let mut levels = vec![leaves];
    while levels.last().is_some_and(|level| level.len() > 1) {
        let current = levels
            .last()
            .ok_or_else(|| invalid("compressed membership tree lost its current level"))?;
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        for pair in current.chunks(2) {
            let left = pair[0];
            let right = pair.get(1).copied().unwrap_or(left);
            next.push(membership_node_hash(left, right));
        }
        levels.push(next);
    }
    Ok(levels)
}

fn membership_leaf_hash(cx_id: CxId, stored: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(LEAF_DOMAIN);
    hasher.update([COMPRESSION_MEMBERSHIP_VERSION]);
    hasher.update(cx_id.as_bytes());
    hasher.update((stored.len() as u64).to_be_bytes());
    hasher.update(stored);
    hasher.finalize().into()
}

fn membership_node_hash(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(NODE_DOMAIN);
    hasher.update([COMPRESSION_MEMBERSHIP_VERSION]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn encode_proof(proof: MembershipProof) -> Result<Vec<u8>> {
    let sibling_count = u8::try_from(proof.siblings.len())
        .map_err(|_| invalid("compressed membership proof depth exceeds u8"))?;
    if proof.siblings.len() != expected_proof_depth(proof.leaf_count) {
        return Err(invalid(
            "compressed membership proof has a non-canonical depth",
        ));
    }
    let capacity = proof
        .siblings
        .len()
        .checked_mul(32)
        .and_then(|bytes| bytes.checked_add(PROOF_PREFIX_BYTES + PROOF_DIGEST_BYTES))
        .ok_or_else(|| invalid("compressed membership proof length overflow"))?;
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(PROOF_MAGIC);
    bytes.push(COMPRESSION_MEMBERSHIP_VERSION);
    bytes.extend_from_slice(&[0; 3]);
    bytes.extend_from_slice(proof.cx_id.as_bytes());
    bytes.extend_from_slice(&proof.root);
    bytes.extend_from_slice(&proof.leaf_count.to_be_bytes());
    bytes.extend_from_slice(&proof.leaf_index.to_be_bytes());
    bytes.push(sibling_count);
    bytes.extend_from_slice(&[0; 3]);
    if bytes.len() != PROOF_PREFIX_BYTES {
        return Err(invalid(
            "internal compressed membership proof prefix mismatch",
        ));
    }
    for sibling in proof.siblings {
        bytes.extend_from_slice(&sibling);
    }
    let digest = proof_digest(&bytes);
    bytes.extend_from_slice(&digest);
    Ok(bytes)
}

fn parse_proof(bytes: &[u8]) -> Result<MembershipProof> {
    if bytes.len() < PROOF_PREFIX_BYTES + PROOF_DIGEST_BYTES {
        return Err(invalid(format!(
            "compressed membership proof is too short: got {} bytes",
            bytes.len()
        )));
    }
    if &bytes[..4] != PROOF_MAGIC {
        return Err(invalid("compressed membership proof magic mismatch"));
    }
    if bytes[4] != COMPRESSION_MEMBERSHIP_VERSION {
        return Err(invalid(format!(
            "unsupported compressed membership proof version {}; expected {COMPRESSION_MEMBERSHIP_VERSION}",
            bytes[4]
        )));
    }
    if bytes[5..8].iter().any(|byte| *byte != 0) || bytes[65..68].iter().any(|byte| *byte != 0) {
        return Err(invalid(
            "compressed membership proof reserved bytes must be zero",
        ));
    }
    let mut cx_bytes = [0_u8; 16];
    cx_bytes.copy_from_slice(&bytes[8..24]);
    let cx_id = CxId::from_bytes(cx_bytes);
    let mut root = [0_u8; 32];
    root.copy_from_slice(&bytes[24..56]);
    let leaf_count = u32::from_be_bytes(
        bytes[56..60]
            .try_into()
            .map_err(|_| invalid("compressed membership proof leaf-count field is malformed"))?,
    );
    let leaf_index = u32::from_be_bytes(
        bytes[60..64]
            .try_into()
            .map_err(|_| invalid("compressed membership proof leaf-index field is malformed"))?,
    );
    if leaf_count == 0 || leaf_index >= leaf_count {
        return Err(invalid(format!(
            "compressed membership proof has invalid leaf index {leaf_index} for count {leaf_count}"
        )));
    }
    let sibling_count = bytes[64] as usize;
    let expected_depth = expected_proof_depth(leaf_count);
    if sibling_count != expected_depth {
        return Err(invalid(format!(
            "compressed membership proof depth mismatch: encoded={sibling_count} expected={expected_depth} rows={leaf_count}"
        )));
    }
    let sibling_bytes = sibling_count
        .checked_mul(32)
        .ok_or_else(|| invalid("compressed membership sibling byte count overflow"))?;
    let digest_offset = PROOF_PREFIX_BYTES
        .checked_add(sibling_bytes)
        .ok_or_else(|| invalid("compressed membership proof digest offset overflow"))?;
    let expected_len = digest_offset
        .checked_add(PROOF_DIGEST_BYTES)
        .ok_or_else(|| invalid("compressed membership proof length overflow"))?;
    if bytes.len() != expected_len {
        return Err(invalid(format!(
            "compressed membership proof length mismatch: encoded_depth={sibling_count} expected={expected_len} actual={}",
            bytes.len()
        )));
    }
    let computed = proof_digest(&bytes[..digest_offset]);
    if bytes[digest_offset..] != computed {
        return Err(invalid("compressed membership proof SHA-256 mismatch"));
    }
    let siblings = bytes[PROOF_PREFIX_BYTES..digest_offset]
        .chunks_exact(32)
        .map(|chunk| {
            let mut sibling = [0_u8; 32];
            sibling.copy_from_slice(chunk);
            sibling
        })
        .collect();
    Ok(MembershipProof {
        cx_id,
        root,
        leaf_count,
        leaf_index,
        siblings,
    })
}

fn expected_proof_depth(mut width: u32) -> usize {
    let mut depth = 0;
    while width > 1 {
        width = width / 2 + width % 2;
        depth += 1;
    }
    depth
}

fn proof_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PROOF_DIGEST_DOMAIN);
    hasher.update(bytes);
    hasher.finalize().into()
}

fn invalid(message: impl Into<String>) -> calyx_core::CalyxError {
    compression_error(CALYX_VECTOR_COMPRESSION_INVALID, message)
}
