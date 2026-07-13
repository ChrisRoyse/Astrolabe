//! End-to-end FSV for the issue #23 defect: an atomic durable commit whose
//! encoded write batch exceeds the 64 MiB WAL record cap.
//!
//! Before multi-record framing this commit died in
//! `encode_write_batch -> DurableVault::append_batch -> wal::record::encode`
//! with `CALYX_DISK_PRESSURE: WAL payload exceeds max record size 67108864`.
//! The source of truth here is the WAL bytes on disk: after the commit the
//! vault is dropped and the batch is independently recovered by replaying the
//! WAL, then every row is compared byte-for-byte.

use super::durable::{DurableVault, VaultOptions};
use super::encode::{WriteRow, encode_write_batch};
use crate::cf::ColumnFamily;
use crate::wal::{Wal, WalOptions};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

const RECORD_CAP: usize = 64 * 1024 * 1024;

fn value_of(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_add(seed)).collect()
}

#[test]
fn oversized_durable_commit_replays_rows_byte_exact() {
    let dir = test_dir("durable-oversized-commit");
    let options = VaultOptions::default();
    let durable = DurableVault::open_after(&dir, &options, 0).expect("open durable vault");

    // Two ~34 MiB rows: the encoded batch is ~68 MiB, comfortably past the
    // 64 MiB per-record cap that used to fail this commit closed.
    let rows = vec![
        WriteRow {
            cf: ColumnFamily::Base,
            key: b"alpha".to_vec(),
            value: value_of(34 * 1024 * 1024, 0x11),
        },
        WriteRow {
            cf: ColumnFamily::Base,
            key: b"bravo".to_vec(),
            value: value_of(34 * 1024 * 1024, 0x77),
        },
    ];
    let encoded_len = encode_write_batch(&rows).expect("encode batch").len();
    assert!(
        encoded_len > RECORD_CAP,
        "test batch ({encoded_len} bytes) must exceed the record cap to exercise framing"
    );

    let seq = durable
        .append_batch(&rows)
        .expect("oversized durable commit must succeed");
    durable.flush().expect("flush durable");
    drop(durable);

    // The WAL physically split the commit into multiple records...
    let mut wal =
        Wal::open(dir.join("wal"), WalOptions::default()).expect("open wal for inventory");
    let physical_records: usize = wal
        .segment_inventory()
        .expect("inventory")
        .iter()
        .map(|segment| segment.record_count)
        .sum();
    drop(wal);
    assert!(
        physical_records >= 2,
        "oversized commit must span multiple WAL records, got {physical_records}"
    );

    // ...but recovery reassembles it into exactly one atomic batch whose rows
    // are byte-exact with what was committed.
    let recovered =
        DurableVault::recover_batches(&dir, &options).expect("recover batches from WAL replay");
    assert_eq!(recovered.batches.len(), 1, "one atomic commit recovered");
    assert_eq!(recovered.batches[0].seq, seq);
    assert_eq!(recovered.last_recovered_seq, seq);
    assert_eq!(
        recovered.batches[0].rows, rows,
        "recovered rows must be byte-exact"
    );
    assert_eq!(recovered.torn_tail, None);

    cleanup(dir);
}

fn test_dir(name: &str) -> PathBuf {
    let id = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("calyx-aster-{name}-{}-{id}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create test dir");
    dir
}

fn cleanup(dir: PathBuf) {
    let _ = fs::remove_dir_all(dir);
}
