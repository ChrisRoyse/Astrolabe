use std::collections::{BTreeMap, BTreeSet};

use calyx_aster::cf::{
    ColumnFamily, base_key, compression_lifecycle_key, compression_manifest_key,
};
use calyx_aster::compression_lifecycle::GenerationLifecycleRecord;
use calyx_aster::vault::{AsterVault, encode};
use calyx_core::{Clock, CxId, Result, Seq, Slot, SlotVector};

use super::codec::{
    compute_generation_root, compute_raw_generation_root, prepare_maxsim_query,
    score_prepared_maxsim, validate_token_matrix,
};
use super::{
    CALYX_MULTIVECTOR_CONTEXT_MISMATCH, CALYX_MULTIVECTOR_PACK_INVALID,
    MultiVectorCompressionQuery, PackedMaxSimScratch, PackedMultiVectorHit,
    PackedMultiVectorManifest, ParsedPackedMultiVectorRow, multivector_error,
    parse_packed_multivector_manifest, parse_packed_multivector_row, validate_multivector_context,
};
use crate::spec::LensSpec;

/// Reusable, context-bound view of one residual-packed Multi slot.
pub struct PackedMultiVectorIndex<'a, C: Clock> {
    vault: &'a AsterVault<C>,
    slot: &'a Slot,
    lens: &'a LensSpec,
    manifest: PackedMultiVectorManifest,
    opened_at: Seq,
}

impl<'a, C: Clock> PackedMultiVectorIndex<'a, C> {
    /// Opens and fully verifies the latest manifested generation.
    pub fn open(vault: &'a AsterVault<C>, slot: &'a Slot, lens: &'a LensSpec) -> Result<Self> {
        validate_multivector_context(slot, lens)?;
        let opened_at = vault.latest_seq();
        let manifest = read_manifest(vault, slot, lens, opened_at)?;
        let index = Self {
            vault,
            slot,
            lens,
            manifest,
            opened_at,
        };
        index.verify_at(opened_at)?;
        Ok(index)
    }

    pub fn manifest(&self) -> &PackedMultiVectorManifest {
        &self.manifest
    }

    pub fn opened_at(&self) -> Seq {
        self.opened_at
    }

    /// Recomputes row/raw roots, Base bindings, token counts, checksums, and the
    /// lifecycle witness from independently read persisted bytes.
    pub fn verify_at(&self, at: Seq) -> Result<()> {
        let manifest = read_manifest(self.vault, self.slot, self.lens, at)?;
        let rows = read_and_verify_rows(self.vault, self.slot, &manifest, at)?;
        if rows.len() != manifest.generation_rows as usize {
            return Err(invalid(format!(
                "manifest declares {} rows but persisted generation has {}",
                manifest.generation_rows,
                rows.len()
            )));
        }
        let total_tokens = rows.iter().try_fold(0_u64, |sum, (_, parsed, _)| {
            sum.checked_add(u64::from(parsed.token_count()))
                .ok_or_else(|| invalid("verified token count overflow"))
        })?;
        if total_tokens != manifest.total_tokens {
            return Err(invalid(format!(
                "manifest total_tokens {} != persisted {total_tokens}",
                manifest.total_tokens
            )));
        }
        let generation_root = compute_generation_root(
            manifest.codec_context_id,
            manifest.generation_rows,
            rows.iter()
                .map(|(cx_id, parsed, _)| (*cx_id, parsed.token_count(), parsed.payload())),
        );
        let raw_root = compute_raw_generation_root(
            manifest.codec_context_id,
            manifest.generation_rows,
            rows.iter().map(|(cx_id, _, raw)| (*cx_id, raw.as_slice())),
        );
        if generation_root != manifest.generation_root || raw_root != manifest.raw_generation_root {
            return Err(invalid(
                "persisted packed/raw generation roots do not match the manifest",
            ));
        }
        let lifecycle_bytes = self
            .vault
            .read_cf_at(
                at,
                ColumnFamily::Compression,
                &compression_lifecycle_key(self.slot.slot_id, manifest.generation_seq),
            )?
            .ok_or_else(|| {
                invalid(format!(
                    "generation has no lifecycle witness for prior_seq {}",
                    manifest.generation_seq
                ))
            })?;
        let lifecycle = GenerationLifecycleRecord::parse(&lifecycle_bytes)?;
        if lifecycle.slot_id != self.slot.slot_id.get()
            || lifecycle.prior_seq != manifest.generation_seq
            || lifecycle.generation_rows != manifest.generation_rows
            || lifecycle.generation_root_sha256 != hex(&manifest.generation_root)
            || lifecycle.raw_generation_root_sha256 != hex(&manifest.raw_generation_root)
        {
            return Err(invalid(
                "generation lifecycle witness does not match manifest geometry/roots",
            ));
        }
        Ok(())
    }

    /// Reads and parses one packed primary row at the opened snapshot.
    pub fn read(&self, cx_id: CxId) -> Result<Option<ParsedPackedMultiVectorRow>> {
        self.require_current_opened_snapshot()?;
        let key = cx_id.as_bytes();
        self.vault
            .read_cf_at(self.opened_at, ColumnFamily::slot(self.slot.slot_id), key)?
            .map(|bytes| parse_packed_multivector_row(&bytes, &self.manifest, cx_id))
            .transpose()
    }

    /// Directly searches packed rows with SSE2 and bounded scratch.
    pub fn search(
        &self,
        query: &MultiVectorCompressionQuery,
        k: usize,
        scratch: &mut PackedMaxSimScratch,
    ) -> Result<Vec<PackedMultiVectorHit>> {
        self.require_current_opened_snapshot()?;
        if k == 0 || k > self.manifest.generation_rows as usize {
            return Err(invalid(format!(
                "search k {k} is outside 1..={} generation rows",
                self.manifest.generation_rows
            )));
        }
        prepare_maxsim_query(&query.tokens, &self.manifest, scratch)?;
        let stored = self
            .vault
            .scan_cf_at(self.opened_at, ColumnFamily::slot(self.slot.slot_id))?;
        let mut hits = Vec::with_capacity(stored.len());
        for (key, bytes) in stored {
            let cx_id = cx_id_from_key(&key)?;
            let row = parse_packed_multivector_row(&bytes, &self.manifest, cx_id)?;
            let score = score_prepared_maxsim(&row, &self.manifest, scratch)?;
            hits.push(PackedMultiVectorHit { cx_id, score });
        }
        hits.sort_by(|left, right| {
            right
                .score
                .total_cmp(&left.score)
                .then_with(|| left.cx_id.cmp(&right.cx_id))
        });
        hits.truncate(k);
        Ok(hits)
    }

    fn require_current_opened_snapshot(&self) -> Result<()> {
        let current = self.vault.latest_seq();
        if current != self.opened_at {
            return Err(multivector_error(
                CALYX_MULTIVECTOR_CONTEXT_MISMATCH,
                format!(
                    "packed index opened at seq {} but vault advanced to {current}; reopen the index so no generation is mixed",
                    self.opened_at
                ),
            ));
        }
        Ok(())
    }
}

fn read_manifest<C: Clock>(
    vault: &AsterVault<C>,
    slot: &Slot,
    lens: &LensSpec,
    at: Seq,
) -> Result<PackedMultiVectorManifest> {
    let bytes = vault
        .read_cf_at(
            at,
            ColumnFamily::Compression,
            &compression_manifest_key(slot.slot_id),
        )?
        .ok_or_else(|| {
            invalid(format!(
                "slot {} has no packed generation manifest at seq={at}",
                slot.slot_id.get()
            ))
        })?;
    let manifest = parse_packed_multivector_manifest(&bytes)?;
    if manifest.slot_id != slot.slot_id.get()
        || manifest.lens_id != lens.lens_id()
        || manifest.token_dim
            != match slot.shape {
                calyx_core::SlotShape::Multi { token_dim } => token_dim,
                _ => 0,
            }
    {
        return Err(multivector_error(
            CALYX_MULTIVECTOR_CONTEXT_MISMATCH,
            "packed generation manifest does not match requested slot/lens/shape",
        ));
    }
    Ok(manifest)
}

type VerifiedRow = (CxId, ParsedPackedMultiVectorRow, Vec<u8>);

fn read_and_verify_rows<C: Clock>(
    vault: &AsterVault<C>,
    slot: &Slot,
    manifest: &PackedMultiVectorManifest,
    at: Seq,
) -> Result<Vec<VerifiedRow>> {
    let primary = vault.scan_cf_at(at, ColumnFamily::slot(slot.slot_id))?;
    let raw = vault
        .scan_cf_at(at, ColumnFamily::slot_raw(slot.slot_id))?
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    let primary_keys = primary
        .iter()
        .map(|(key, _)| key.clone())
        .collect::<BTreeSet<_>>();
    if primary_keys.is_empty() || primary_keys != raw.keys().cloned().collect() {
        return Err(invalid(
            "packed primary/raw sidecar keysets are empty or divergent",
        ));
    }
    let mut rows = Vec::with_capacity(primary.len());
    for (key, packed_bytes) in primary {
        let cx_id = cx_id_from_key(&key)?;
        let parsed = parse_packed_multivector_row(&packed_bytes, manifest, cx_id)?;
        let raw_bytes = raw
            .get(&key)
            .ok_or_else(|| invalid("packed row has no raw sidecar"))?
            .clone();
        let SlotVector::Multi { token_dim, tokens } = encode::decode_slot_vector(&raw_bytes)?
        else {
            return Err(invalid(format!(
                "raw sidecar for {cx_id} is not a Multi SlotVector"
            )));
        };
        if token_dim != manifest.token_dim || tokens.len() != parsed.token_count() as usize {
            return Err(invalid(format!(
                "raw sidecar for {cx_id} does not match packed token geometry"
            )));
        }
        validate_token_matrix(
            &tokens,
            manifest.token_dim,
            manifest.config.max_tokens,
            "raw sidecar",
        )?;
        verify_base_binding(vault, slot, at, cx_id, &raw_bytes)?;
        rows.push((cx_id, parsed, raw_bytes));
    }
    Ok(rows)
}

fn verify_base_binding<C: Clock>(
    vault: &AsterVault<C>,
    slot: &Slot,
    at: Seq,
    cx_id: CxId,
    raw_bytes: &[u8],
) -> Result<()> {
    let base = vault
        .read_cf_at(at, ColumnFamily::Base, &base_key(cx_id))?
        .ok_or_else(|| invalid(format!("packed row {cx_id} has no Base constellation")))?;
    let identity = encode::decode_constellation_base_identity(&base)?;
    let expected = identity.slot_hashes.get(&slot.slot_id).ok_or_else(|| {
        invalid(format!(
            "Base constellation {cx_id} does not declare slot {}",
            slot.slot_id.get()
        ))
    })?;
    if identity.cx_id != cx_id || blake3::hash(raw_bytes).as_bytes() != expected {
        return Err(invalid(format!(
            "packed raw sidecar {cx_id} does not match immutable Base slot hash"
        )));
    }
    Ok(())
}

fn cx_id_from_key(key: &[u8]) -> Result<CxId> {
    let bytes: [u8; 16] = key.try_into().map_err(|_| {
        invalid(format!(
            "packed slot key length {} is not a 16-byte CxId",
            key.len()
        ))
    })?;
    Ok(CxId::from_bytes(bytes))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn invalid(message: impl Into<String>) -> calyx_core::CalyxError {
    multivector_error(CALYX_MULTIVECTOR_PACK_INVALID, message)
}
