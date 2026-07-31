//! Manifest-bound durable-SST handoff for the live column-family router.
//!
//! Durable vault commits first stage rows in bounded router memtables and in
//! the checkpoint queue. Once the manifest covers the checkpoint SSTs, those
//! immutable files are the authoritative current and historical home. This
//! module reconciles only the affected router levels, proves that clearing the
//! mutable/flush copies cannot change the latest view, swaps the verified
//! levels, and then removes only commit-watermarked flush files covered by the
//! manifest. Legacy router files remain preserving because they have no commit
//! watermark.

use super::ColumnFamily;
use super::router::CfRouter;
use super::router_load::{list_sst_files, sort_ssts_by_sequence};
use crate::memtable::Memtable;
use crate::sst::level::SstLevel;
use crate::sst::{SstReader, SstSummary};
use crate::storage_names::{SstName, SstOrderKey, classify_sst, parse_cf_dir_name, sst_order_key};
use calyx_core::{CalyxError, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) const CALYX_ASTER_ROUTER_HANDOFF_MISMATCH: &str = "CALYX_ASTER_ROUTER_HANDOFF_MISMATCH";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RouterManifestHandoffReport {
    pub full_inventory: bool,
    pub column_families: usize,
    pub candidate_sst_files: usize,
    pub durable_sst_files_attached: usize,
    pub memtable_rows_verified: usize,
    pub flush_sst_files_verified: usize,
    pub flush_sst_entries_verified: usize,
    pub flush_sst_bytes_verified: u64,
    pub flush_sst_files_retired: usize,
    pub flush_sst_bytes_retired: u64,
    pub covered_flush_debt_files_after: usize,
    pub covered_flush_debt_bytes_after: u64,
}

#[derive(Clone)]
struct CandidateRow {
    order: SstOrderKey,
    digest: [u8; 32],
}

impl CfRouter {
    pub(crate) fn handoff_manifested_ssts(
        &mut self,
        durable_seq: u64,
        full_inventory: bool,
        durable_ssts: &[SstSummary],
    ) -> Result<RouterManifestHandoffReport> {
        let refresh = durable_ssts
            .iter()
            .map(|summary| summary.path.clone())
            .collect::<BTreeSet<_>>();
        let mut selected_cfs = if full_inventory {
            self.inventory_column_families()?
        } else {
            BTreeSet::new()
        };
        for summary in durable_ssts {
            selected_cfs.insert(cf_from_sst_path(&summary.path)?);
        }
        for (cf, table) in &self.memtables {
            if !table.is_empty() {
                selected_cfs.insert(*cf);
            }
        }
        for (cf, level) in &self.levels {
            if level.paths().any(|path| {
                matches!(
                    classify_sst(path),
                    Ok(Some(SstName::Flush { watermark, .. })) if watermark <= durable_seq
                )
            }) {
                selected_cfs.insert(*cf);
            }
        }

        let mut report = RouterManifestHandoffReport {
            full_inventory,
            column_families: selected_cfs.len(),
            durable_sst_files_attached: durable_ssts.len(),
            ..RouterManifestHandoffReport::default()
        };
        if selected_cfs.is_empty() {
            return Ok(report);
        }

        let mut candidate_levels = BTreeMap::<ColumnFamily, SstLevel>::new();
        let mut candidate_max_order = BTreeMap::<ColumnFamily, SstOrderKey>::new();
        let mut retired_paths = Vec::<PathBuf>::new();
        let mut retired_latest = BTreeMap::<(ColumnFamily, Vec<u8>), CandidateRow>::new();
        for cf in &selected_cfs {
            let mut all_paths = self.inventory_cf_ssts(*cf)?;
            sort_ssts_by_sequence(&mut all_paths)?;
            let mut candidate_paths = Vec::with_capacity(all_paths.len());
            for path in all_paths {
                match classify_sst(&path)? {
                    Some(SstName::Flush { watermark, .. }) if watermark <= durable_seq => {
                        let order = required_order(&path)?;
                        let bytes = fs::metadata(&path)
                            .map_err(|error| {
                                handoff_storage_error("stat covered router flush", &path, error)
                            })?
                            .len();
                        let rows = SstReader::open(&path)?.iter()?;
                        report.flush_sst_files_verified += 1;
                        report.flush_sst_entries_verified += rows.len();
                        report.flush_sst_bytes_verified =
                            report.flush_sst_bytes_verified.saturating_add(bytes);
                        for row in rows {
                            let key = (*cf, row.key);
                            let candidate = CandidateRow {
                                order,
                                digest: *blake3::hash(&row.value).as_bytes(),
                            };
                            if retired_latest
                                .get(&key)
                                .is_none_or(|existing| candidate.order > existing.order)
                            {
                                retired_latest.insert(key, candidate);
                            }
                        }
                        retired_paths.push(path);
                    }
                    Some(_) => {
                        let order = required_order(&path)?;
                        candidate_max_order
                            .entry(*cf)
                            .and_modify(|current| *current = (*current).max(order))
                            .or_insert(order);
                        candidate_paths.push(path);
                    }
                    None => {}
                }
            }
            report.candidate_sst_files += candidate_paths.len();
            let current = self.levels.get(cf).cloned().unwrap_or_default();
            candidate_levels.insert(
                *cf,
                current.reconcile_oldest_first_with_lookup(candidate_paths, &refresh)?,
            );
        }

        let mut recent_durable = BTreeMap::<(ColumnFamily, Vec<u8>), CandidateRow>::new();
        for summary in durable_ssts {
            let cf = cf_from_sst_path(&summary.path)?;
            let order = required_order(&summary.path)?;
            let rows = SstReader::open(&summary.path)?.iter()?;
            if rows.len() != summary.entries {
                return Err(handoff_mismatch(format!(
                    "durable handoff summary for {} declared {} row(s), physical readback found {}",
                    summary.path.display(),
                    summary.entries,
                    rows.len()
                )));
            }
            let physical_bytes = fs::metadata(&summary.path)
                .map_err(|error| {
                    handoff_storage_error("stat durable handoff SST", &summary.path, error)
                })?
                .len();
            if physical_bytes != summary.bytes {
                return Err(handoff_mismatch(format!(
                    "durable handoff summary for {} declared {} byte(s), physical readback found {physical_bytes}",
                    summary.path.display(),
                    summary.bytes
                )));
            }
            for row in rows {
                let key = (cf, row.key);
                let candidate = CandidateRow {
                    order,
                    digest: *blake3::hash(&row.value).as_bytes(),
                };
                if recent_durable
                    .get(&key)
                    .is_none_or(|existing| candidate.order > existing.order)
                {
                    recent_durable.insert(key, candidate);
                }
            }
        }

        for cf in &selected_cfs {
            let Some(table) = self.memtables.get(cf) else {
                continue;
            };
            for (key, value) in table.iter() {
                let candidate = candidate_for(
                    *cf,
                    &key,
                    &recent_durable,
                    &candidate_max_order,
                    candidate_levels.get(cf),
                )?
                .ok_or_else(|| {
                    handoff_mismatch(format!(
                        "manifest durable_seq {durable_seq} has no immutable home for active {} memtable key {}",
                        cf.name(),
                        hex_prefix(&key)
                    ))
                })?;
                let expected = *blake3::hash(&value).as_bytes();
                if candidate.digest != expected {
                    return Err(handoff_mismatch(format!(
                        "manifest durable_seq {durable_seq} resolves different bytes for active {} memtable key {}",
                        cf.name(),
                        hex_prefix(&key)
                    )));
                }
                report.memtable_rows_verified += 1;
            }
        }

        for ((cf, key), retired) in &retired_latest {
            let candidate = candidate_for(
                *cf,
                key,
                &recent_durable,
                &candidate_max_order,
                candidate_levels.get(cf),
            )?
            .ok_or_else(|| {
                handoff_mismatch(format!(
                    "covered router flush key {}:{} has no manifest-covered immutable home at durable_seq {durable_seq}",
                    cf.name(),
                    hex_prefix(key)
                ))
            })?;
            if candidate.order < retired.order && candidate.digest != retired.digest {
                return Err(handoff_mismatch(format!(
                    "retiring router flush would change newest bytes for {} key {}: candidate order {:?}, flush order {:?}",
                    cf.name(),
                    hex_prefix(key),
                    candidate.order,
                    retired.order
                )));
            }
        }

        // The candidate levels and fresh empty memtables become visible under
        // the router write lock held by the caller before any covered path is
        // removed. A crash before this point leaves the old router/files; a
        // crash after it reopens from the manifest-covered durable files.
        for (cf, level) in candidate_levels {
            self.levels.insert(cf, level);
            self.memtables
                .insert(cf, Memtable::new(self.memtable_byte_cap));
        }

        let mut synced_parents = BTreeSet::new();
        for path in &retired_paths {
            let bytes = fs::metadata(path)
                .map_err(|error| handoff_storage_error("restat covered router flush", path, error))?
                .len();
            fs::remove_file(path).map_err(|error| {
                handoff_storage_error("remove covered router flush", path, error)
            })?;
            if path.try_exists().map_err(|error| {
                handoff_storage_error("read back retired router flush", path, error)
            })? {
                return Err(handoff_mismatch(format!(
                    "covered router flush {} remained present after removal",
                    path.display()
                )));
            }
            if let Some(parent) = path.parent() {
                synced_parents.insert(parent.to_path_buf());
            }
            report.flush_sst_files_retired += 1;
            report.flush_sst_bytes_retired = report.flush_sst_bytes_retired.saturating_add(bytes);
        }
        for parent in synced_parents {
            crate::fsync::sync_dir(&parent, "router handoff")?;
        }

        for cf in &selected_cfs {
            for path in self.inventory_cf_ssts(*cf)? {
                if matches!(
                    classify_sst(&path)?,
                    Some(SstName::Flush { watermark, .. }) if watermark <= durable_seq
                ) {
                    report.covered_flush_debt_files_after += 1;
                    report.covered_flush_debt_bytes_after =
                        report.covered_flush_debt_bytes_after.saturating_add(
                            fs::metadata(&path)
                                .map_err(|error| {
                                    handoff_storage_error(
                                        "stat remaining router debt",
                                        &path,
                                        error,
                                    )
                                })?
                                .len(),
                        );
                }
            }
        }
        if report.covered_flush_debt_files_after != 0 {
            return Err(handoff_mismatch(format!(
                "manifest-bound handoff left {} covered router flush file(s) / {} byte(s) after durable_seq {durable_seq}",
                report.covered_flush_debt_files_after, report.covered_flush_debt_bytes_after
            )));
        }
        Ok(report)
    }

    fn inventory_column_families(&self) -> Result<BTreeSet<ColumnFamily>> {
        let mut cfs = BTreeSet::new();
        for root in self.cf_roots() {
            if !root.exists() {
                continue;
            }
            for entry in fs::read_dir(&root)
                .map_err(|error| handoff_storage_error("read router CF root", &root, error))?
            {
                let entry = entry
                    .map_err(|error| handoff_storage_error("read router CF entry", &root, error))?;
                if !entry
                    .file_type()
                    .map_err(|error| {
                        handoff_storage_error("stat router CF entry", &entry.path(), error)
                    })?
                    .is_dir()
                {
                    continue;
                }
                let name = entry.file_name().into_string().map_err(|value| {
                    handoff_mismatch(format!(
                        "router CF directory name is not Unicode: {value:?}"
                    ))
                })?;
                cfs.insert(parse_cf_dir_name(&name)?);
            }
        }
        Ok(cfs)
    }

    fn inventory_cf_ssts(&self, cf: ColumnFamily) -> Result<Vec<PathBuf>> {
        let mut paths = Vec::new();
        for root in self.cf_roots() {
            let dir = root.join(cf.name());
            if dir.exists() {
                paths.extend(list_sst_files(&dir)?);
            }
        }
        paths.sort();
        paths.dedup();
        Ok(paths)
    }
}

fn candidate_for(
    cf: ColumnFamily,
    key: &[u8],
    recent: &BTreeMap<(ColumnFamily, Vec<u8>), CandidateRow>,
    candidate_max_order: &BTreeMap<ColumnFamily, SstOrderKey>,
    level: Option<&SstLevel>,
) -> Result<Option<CandidateRow>> {
    if let Some(candidate) = recent.get(&(cf, key.to_vec()))
        && candidate_max_order
            .get(&cf)
            .is_none_or(|maximum| candidate.order >= *maximum)
    {
        return Ok(Some(candidate.clone()));
    }
    let Some((value, path)) = level.map_or(Ok(None), |level| level.get_with_source(key))? else {
        return Ok(None);
    };
    Ok(Some(CandidateRow {
        order: required_order(&path)?,
        digest: *blake3::hash(&value).as_bytes(),
    }))
}

fn cf_from_sst_path(path: &Path) -> Result<ColumnFamily> {
    let parent = path.parent().ok_or_else(|| {
        handoff_mismatch(format!(
            "SST {} has no column-family parent",
            path.display()
        ))
    })?;
    let name = parent
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            handoff_mismatch(format!(
                "SST column-family parent {} has no Unicode name",
                parent.display()
            ))
        })?;
    parse_cf_dir_name(name)
}

fn required_order(path: &Path) -> Result<SstOrderKey> {
    sst_order_key(path)?.ok_or_else(|| {
        handoff_mismatch(format!(
            "router handoff received non-SST path {}",
            path.display()
        ))
    })
}

fn handoff_mismatch(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: CALYX_ASTER_ROUTER_HANDOFF_MISMATCH,
        message: message.into(),
        remediation: "preserve the vault, run a deep physical SST/manifest verification, and retry the manifest-bound handoff only after the reported identity or byte mismatch is corrected",
    }
}

fn handoff_storage_error(context: &str, path: &Path, error: std::io::Error) -> CalyxError {
    CalyxError {
        code: CALYX_ASTER_ROUTER_HANDOFF_MISMATCH,
        message: format!("{context} {}: {error}", path.display()),
        remediation: "preserve the vault and correct the reported filesystem state before retrying the manifest-bound handoff",
    }
}

fn hex_prefix(bytes: &[u8]) -> String {
    let mut value = String::new();
    for byte in bytes.iter().take(12) {
        value.push_str(&format!("{byte:02x}"));
    }
    if bytes.len() > 12 {
        value.push_str("...");
    }
    value
}
