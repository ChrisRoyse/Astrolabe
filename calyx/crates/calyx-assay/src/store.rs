//! In-memory Assay result CF/cache with provenance.

use std::collections::{BTreeMap, BTreeSet};

use calyx_aster::cf::{CfRouter, ColumnFamily};
use calyx_aster::vault::AsterVault;
use calyx_core::{AnchorKind, CalyxError, Clock, Result, SlotId, VaultId, VaultStore};
use serde::{Deserialize, Serialize};

use crate::estimate::MiEstimate;

type AsterAssayRow = (ColumnFamily, Vec<u8>, Vec<u8>);

/// Summary of co-tenant rows skipped during a co-tenant-aware Assay CF load.
///
/// `ColumnFamily::Assay` is a *shared* column family: besides genuine
/// [`AssayRow`] entries, other subsystems (e.g. Astrolabe's delta-invalidation
/// lane) route rows here that carry a self-declaring top-level `schema` string
/// outside the assay row schema. A co-tenant-aware load skips those rows
/// instead of failing closed on them, but every skip is *counted and labeled*
/// here (invariant 3: no silent skips) so the reader can surface the
/// degradation-free co-tenancy in its provenance. A row that is neither a valid
/// `AssayRow` nor a declared, *accepted* foreign schema still fails closed with
/// `CALYX_ASTER_CORRUPT_SHARD` — real corruption is never masked (invariant 5).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AssayCotenantSkips {
    /// Total co-tenant rows skipped across all accepted foreign schemas.
    pub skipped_rows: usize,
    /// Per-schema skip counts, keyed by the row's declared `schema` string.
    pub skipped_schemas: BTreeMap<String, usize>,
}

/// Classification of one raw Assay CF `(key, value)` pair during load.
enum AssayRowClass {
    /// A genuine assay row, decoded and key-verified.
    Assay(Box<AssayRow>),
    /// A co-tenant row that positively declares an *accepted* foreign top-level
    /// `schema` tag; carries that schema string for counting.
    Foreign(String),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AssayCacheKey {
    #[serde(default)]
    pub vault_id: Option<VaultId>,
    #[serde(default = "default_anchor")]
    pub anchor: AnchorKind,
    pub panel_version: u32,
    pub corpus_shard: String,
}

impl AssayCacheKey {
    /// Compatibility constructor for legacy tests and unscoped probes.
    #[deprecated(note = "Assay CF rows must use AssayCacheKey::scoped before persistence")]
    pub fn new(panel_version: u32, corpus_shard: impl Into<String>) -> Self {
        Self {
            vault_id: None,
            anchor: default_anchor(),
            panel_version,
            corpus_shard: corpus_shard.into(),
        }
    }

    pub fn scoped(
        panel_version: u32,
        corpus_shard: impl Into<String>,
        vault_id: VaultId,
        anchor: AnchorKind,
    ) -> Self {
        Self {
            vault_id: Some(vault_id),
            anchor,
            panel_version,
            corpus_shard: corpus_shard.into(),
        }
    }

    pub fn require_scoped(&self) -> Result<()> {
        if self.vault_id.is_none() {
            return Err(CalyxError::vault_access_denied(
                "assay cache key must include explicit vault scope",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssaySubject {
    Lens { slot: SlotId },
    Pair { a: SlotId, b: SlotId },
    Panel,
    OutcomeEntropy,
    EnsembleCard,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AssayRow {
    pub cache_key: AssayCacheKey,
    pub subject: AssaySubject,
    pub estimate: MiEstimate,
    pub provenance: String,
    pub written_at_seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct AssayStore {
    rows: BTreeMap<(AssayCacheKey, AssaySubject), AssayRow>,
}

impl AssayStore {
    pub fn put(
        &mut self,
        cache_key: AssayCacheKey,
        subject: AssaySubject,
        estimate: MiEstimate,
        provenance: impl Into<String>,
        written_at_seq: u64,
    ) {
        let row = AssayRow {
            cache_key: cache_key.clone(),
            subject: subject.clone(),
            estimate,
            provenance: provenance.into(),
            written_at_seq,
            payload: None,
        };
        self.rows.insert((cache_key, subject), row);
    }

    pub fn put_with_payload(
        &mut self,
        cache_key: AssayCacheKey,
        subject: AssaySubject,
        estimate: MiEstimate,
        provenance: impl Into<String>,
        written_at_seq: u64,
        payload: serde_json::Value,
    ) {
        let row = AssayRow {
            cache_key: cache_key.clone(),
            subject: subject.clone(),
            estimate,
            provenance: provenance.into(),
            written_at_seq,
            payload: Some(payload),
        };
        self.rows.insert((cache_key, subject), row);
    }

    pub fn get(&self, cache_key: &AssayCacheKey, subject: &AssaySubject) -> Option<&AssayRow> {
        self.rows.get(&(cache_key.clone(), subject.clone()))
    }

    pub fn cache_hit(&self, cache_key: &AssayCacheKey, subject: &AssaySubject) -> bool {
        self.get(cache_key, subject).is_some()
    }

    pub fn invalidate_panel(&mut self, panel_version: u32) -> usize {
        let before = self.rows.len();
        self.rows
            .retain(|(key, _), _| key.panel_version != panel_version);
        before - self.rows.len()
    }

    pub fn rows(&self) -> Vec<AssayRow> {
        self.rows.values().cloned().collect()
    }

    pub fn persist_to_aster(&self, router: &mut CfRouter) -> Result<usize> {
        for (_, key, value) in self.aster_rows()? {
            router.put(ColumnFamily::Assay, &key, &value)?;
        }
        router.flush_cf(ColumnFamily::Assay)?;
        Ok(self.rows.len())
    }

    pub fn persist_to_vault<C>(&self, vault: &AsterVault<C>) -> Result<usize>
    where
        C: Clock,
    {
        vault.write_cf_batch(self.aster_rows()?)?;
        vault.flush()?;
        Ok(self.rows.len())
    }

    pub fn load_from_aster(router: &CfRouter) -> Result<Self> {
        let mut store = Self::default();
        for entry in router.iter_cf(ColumnFamily::Assay)? {
            store.insert_aster_row(entry.key, entry.value)?;
        }
        Ok(store)
    }

    pub fn load_from_vault<C>(vault: &AsterVault<C>) -> Result<Self>
    where
        C: Clock,
    {
        let mut store = Self::default();
        for (key, value) in vault.scan_cf_at(vault.snapshot(), ColumnFamily::Assay)? {
            store.insert_aster_row(key, value)?;
        }
        Ok(store)
    }

    /// Loads assay rows from a vault whose `ColumnFamily::Assay` is shared with
    /// co-tenant writers.
    ///
    /// `accepted_foreign_schemas` is the allowlist of top-level `schema` tags
    /// whose rows are *not* assay rows and must be skipped rather than decoded.
    /// Each such row is counted in the returned [`AssayCotenantSkips`]. A row
    /// that neither decodes as a valid [`AssayRow`] nor positively declares an
    /// **accepted** foreign schema still fails closed with
    /// `CALYX_ASTER_CORRUPT_SHARD` — this is the invariant-3-vs-5 seam: a
    /// foreign-schema co-tenant row is a counted skip, a genuinely corrupt assay
    /// shard is a hard error, and the two are distinguished by a *positive*
    /// schema-tag match, never by "decode failed → skip".
    ///
    /// Pure-Calyx callers with no co-tenants use [`load_from_vault`] /
    /// [`load_from_aster`] (empty allowlist), preserving strict fail-closed
    /// semantics unchanged.
    pub fn load_from_vault_with_cotenants<C>(
        vault: &AsterVault<C>,
        accepted_foreign_schemas: &BTreeSet<&str>,
    ) -> Result<(Self, AssayCotenantSkips)>
    where
        C: Clock,
    {
        let mut store = Self::default();
        let mut skips = AssayCotenantSkips::default();
        for (key, value) in vault.scan_cf_at(vault.snapshot(), ColumnFamily::Assay)? {
            match classify_aster_row(&key, &value, accepted_foreign_schemas)? {
                AssayRowClass::Assay(row) => {
                    store
                        .rows
                        .insert((row.cache_key.clone(), row.subject.clone()), *row);
                }
                AssayRowClass::Foreign(schema) => {
                    skips.skipped_rows += 1;
                    *skips.skipped_schemas.entry(schema).or_default() += 1;
                }
            }
        }
        Ok((store, skips))
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    fn aster_rows(&self) -> Result<Vec<AsterAssayRow>> {
        let mut out = Vec::with_capacity(self.rows.len());
        for row in self.rows.values() {
            row.cache_key.require_scoped()?;
            let key = assay_key(&row.cache_key, &row.subject);
            let value = serde_json::to_vec(row)
                .map_err(|error| CalyxError::disk_pressure(format!("encode assay row: {error}")))?;
            out.push((ColumnFamily::Assay, key, value));
        }
        Ok(out)
    }

    fn insert_aster_row(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
        // Strict load: no accepted co-tenant schemas, so any row that is not a
        // valid, key-matching AssayRow fails closed (unchanged behavior).
        match classify_aster_row(&key, &value, &BTreeSet::new())? {
            AssayRowClass::Assay(row) => {
                self.rows
                    .insert((row.cache_key.clone(), row.subject.clone()), *row);
                Ok(())
            }
            // Unreachable with an empty allowlist: a foreign row can only be
            // classified as such when its schema is in the accepted set.
            AssayRowClass::Foreign(schema) => Err(CalyxError::aster_corrupt_shard(format!(
                "unexpected foreign assay co-tenant schema {schema} in strict load"
            ))),
        }
    }
}

/// Classifies one raw `ColumnFamily::Assay` row as a genuine [`AssayRow`] or an
/// accepted foreign co-tenant row.
///
/// A genuine `AssayRow` is decoded first: if it deserializes, its scope is
/// re-checked and its stored key is verified against the recomputed
/// [`assay_key`] (a mismatch is corruption). Only when the `AssayRow` decode
/// *fails* is the value inspected for a co-tenant marker: a top-level `schema`
/// string that is present in `accepted_foreign_schemas` yields
/// [`AssayRowClass::Foreign`]; anything else (invalid JSON, no `schema`, or an
/// unaccepted `schema`) fails closed with `CALYX_ASTER_CORRUPT_SHARD`. Decoding
/// the concrete `AssayRow` first guarantees a real assay row is never
/// misclassified as foreign even if it happened to carry a `schema`-named field.
fn classify_aster_row(
    key: &[u8],
    value: &[u8],
    accepted_foreign_schemas: &BTreeSet<&str>,
) -> Result<AssayRowClass> {
    match serde_json::from_slice::<AssayRow>(value) {
        Ok(row) => {
            row.cache_key.require_scoped()?;
            let expected = assay_key(&row.cache_key, &row.subject);
            if key != expected {
                return Err(CalyxError::aster_corrupt_shard(
                    "assay CF key does not match row subject",
                ));
            }
            Ok(AssayRowClass::Assay(Box::new(row)))
        }
        Err(decode_error) => {
            if let Ok(serde_json::Value::Object(map)) =
                serde_json::from_slice::<serde_json::Value>(value)
                && let Some(serde_json::Value::String(schema)) = map.get("schema")
                && accepted_foreign_schemas.contains(schema.as_str())
            {
                return Ok(AssayRowClass::Foreign(schema.clone()));
            }
            Err(CalyxError::aster_corrupt_shard(format!(
                "decode assay row: {decode_error}"
            )))
        }
    }
}

fn assay_key(cache_key: &AssayCacheKey, subject: &AssaySubject) -> Vec<u8> {
    let vault = cache_key
        .vault_id
        .expect("assay cache key scope validated before encoding")
        .to_string();
    let shard = cache_key.corpus_shard.as_bytes();
    let anchor = serde_json::to_vec(&cache_key.anchor).expect("anchor kind serializes");
    let mut key = Vec::with_capacity(48 + vault.len() + anchor.len() + shard.len());
    key.extend_from_slice(&cache_key.panel_version.to_be_bytes());
    push_len_prefixed(&mut key, vault.as_bytes());
    push_len_prefixed(&mut key, &anchor);
    push_len_prefixed(&mut key, shard);
    match subject {
        AssaySubject::Lens { slot } => {
            key.push(0);
            key.extend_from_slice(&slot.get().to_be_bytes());
        }
        AssaySubject::Pair { a, b } => {
            key.push(1);
            key.extend_from_slice(&a.get().to_be_bytes());
            key.extend_from_slice(&b.get().to_be_bytes());
        }
        AssaySubject::Panel => key.push(2),
        AssaySubject::OutcomeEntropy => key.push(3),
        AssaySubject::EnsembleCard => key.push(4),
    }
    key
}

fn push_len_prefixed(key: &mut Vec<u8>, value: &[u8]) {
    key.extend_from_slice(&(value.len() as u32).to_be_bytes());
    key.extend_from_slice(value);
}

fn default_anchor() -> AnchorKind {
    AnchorKind::Reward
}
