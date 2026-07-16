//! #444 group-commit lever measurement harness (NOT a test; no assertions).
//!
//! Opens a real durable AsterVault on disk and commits one large ledger-paired
//! batch through `write_cf_batch_with_ledger_entry` — the exact `group_commit`
//! path #433/#444 profiled (WAL serialize + page-write + fsync, ledger-head
//! anchor, MVCC/router apply, checkpoint stage). Rows are spread across many CFs
//! with ~200-byte values, mirroring an import write set, so the per-row
//! `ensure_cf` path (the lever site) is exercised for every row. Run with
//! `CALYX_COMMIT_TIMING=1` to get the per-phase stderr breakdown.
//!
//! Usage: cargo run -p calyx-aster --example bench_group_commit --release -- <rows> <vault_dir>

use std::time::Instant;

use calyx_aster::cf::ColumnFamily;
use calyx_aster::vault::{AsterVault, VaultOptions};
use calyx_core::{FixedClock, VaultId};
use calyx_ledger::{ActorId, EntryKind, SubjectId};

const VAULT_ID: &str = "00000000000000000000000000";

fn main() {
    let mut args = std::env::args().skip(1);
    let rows: usize = args
        .next()
        .and_then(|value| value.parse().ok())
        .unwrap_or(16_746);
    let vault_dir = args
        .next()
        .unwrap_or_else(|| std::env::temp_dir().join("bench_group_commit").display().to_string());
    // Fresh vault each run so the measured commit is a first write, matching a
    // fresh import; determinism across runs is checked by the caller comparing
    // the persisted Base/ledger readback of two runs into two dirs.
    let _ = std::fs::remove_dir_all(&vault_dir);
    std::fs::create_dir_all(&vault_dir).expect("create vault dir");

    let vault = AsterVault::open_with_clock(
        &vault_dir,
        VAULT_ID.parse::<VaultId>().expect("vault id"),
        b"bench-group-commit".to_vec(),
        VaultOptions::default(),
        FixedClock::new(1_785_400_000),
    )
    .expect("open durable vault");

    // A spread of non-Base CFs (Base rows require a valid encoded constellation;
    // these plain-byte CFs exercise the same per-row router/ensure_cf path).
    let cfs = [
        ColumnFamily::Kv,
        ColumnFamily::Collections,
        ColumnFamily::Relational,
        ColumnFamily::Document,
        ColumnFamily::Blob,
        ColumnFamily::XTerm,
        ColumnFamily::Scalars,
        ColumnFamily::Anchors,
        ColumnFamily::Assay,
        ColumnFamily::Kernel,
        ColumnFamily::Guard,
        ColumnFamily::Online,
        ColumnFamily::Reactive,
    ];

    let value_template = vec![b'x'; 200];
    let mut write_set = Vec::with_capacity(rows);
    for index in 0..rows {
        let cf = cfs[index % cfs.len()];
        let mut key = b"bench:group-commit:".to_vec();
        key.extend_from_slice(&(index as u64).to_be_bytes());
        let mut value = value_template.clone();
        value[..8].copy_from_slice(&(index as u64).to_le_bytes());
        write_set.push((cf, key, value));
    }

    let start = Instant::now();
    let seq = vault
        .write_cf_batch_with_ledger_entry(
            write_set,
            EntryKind::Ingest,
            SubjectId::Query(b"bench".to_vec()),
            br#"{"schema":"bench-group-commit-v1"}"#.to_vec(),
            ActorId::Service("astrolabe-bench".to_string()),
        )
        .expect("group commit");
    let elapsed = start.elapsed();

    let per_row_us = elapsed.as_micros() as f64 / rows as f64;
    println!("rows        : {rows}");
    println!("committed_seq: {seq}");
    println!("group_commit: {elapsed:?}");
    println!("per_row     : {per_row_us:.2} us/row");
    println!("throughput  : {:.0} rows/s", rows as f64 / elapsed.as_secs_f64());
    println!("vault_dir   : {vault_dir}");
}
