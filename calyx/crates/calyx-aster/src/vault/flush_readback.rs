use std::collections::BTreeMap;
use std::ffi::OsStr;

use super::{VaultFlushReport, encode};
use crate::cf::{ColumnFamily, base_key};
use crate::sst::SstReader;
use calyx_core::{CalyxError, CxId, Result, Seq};

impl VaultFlushReport {
    /// Reopens only the durable Base SSTs owned by `commit_seq` in this flush receipt
    /// and byte-compares their complete row set with the commit's exact Base
    /// records. It does not walk WAL history, manifests, or unrelated CF data.
    pub fn verify_commit_base_records(
        &self,
        commit_seq: Option<Seq>,
        expected: &BTreeMap<CxId, encode::BaseRecord>,
    ) -> Result<()> {
        let expected = expected
            .iter()
            .map(|(cx_id, record)| Ok((base_key(*cx_id), record.encode()?)))
            .collect::<Result<BTreeMap<_, _>>>()?;
        if !self.router_ssts.is_empty() {
            return Err(CalyxError::aster_corrupt_shard(
                "commit-owned Base readback requires a durable flush receipt; router flush files may coalesce multiple commit sequences",
            ));
        }
        let Some(commit_seq) = commit_seq else {
            if !expected.is_empty() {
                return Err(CalyxError::aster_corrupt_shard(
                    "Base flush readback expected changed rows for a no-op commit",
                ));
            }
            return Ok(());
        };

        let file_prefix = format!("{commit_seq:020}-");
        let base_cf_name = ColumnFamily::Base.name();
        let mut observed = BTreeMap::new();
        for summary in &self.durable_ssts {
            if summary
                .path
                .parent()
                .and_then(|path| path.file_name())
                .and_then(OsStr::to_str)
                != Some(base_cf_name.as_str())
                || !summary
                    .path
                    .file_name()
                    .and_then(OsStr::to_str)
                    .is_some_and(|name| name.starts_with(&file_prefix))
            {
                continue;
            }
            let reader = SstReader::open(&summary.path)?;
            for row in reader.iter()? {
                if observed.insert(row.key.clone(), row.value).is_some() {
                    return Err(CalyxError::aster_corrupt_shard(format!(
                        "flush published duplicate Base key {} across its commit-owned SSTs",
                        hex_prefix(&row.key)
                    )));
                }
            }
        }
        if observed != expected {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "flush Base SST readback mismatch: expected_rows={} observed_rows={} expected_keys=[{}] observed_keys=[{}]",
                expected.len(),
                observed.len(),
                key_sample(expected.keys()),
                key_sample(observed.keys())
            )));
        }
        Ok(())
    }
}

fn key_sample<'a>(keys: impl IntoIterator<Item = &'a Vec<u8>>) -> String {
    keys.into_iter()
        .take(8)
        .map(|key| hex_prefix(key))
        .collect::<Vec<_>>()
        .join(",")
}

fn hex_prefix(bytes: &[u8]) -> String {
    let mut out = String::new();
    for byte in bytes.iter().take(16) {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    if bytes.len() > 16 {
        out.push_str("...");
    }
    out
}
