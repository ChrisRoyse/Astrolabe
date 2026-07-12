//! Measures the engine-native FSV write-ack overhead (#178, non-goal clause).
//!
//! Readback verification must be *measured*, not asserted to be cheap. This
//! bench builds an in-memory vault, commits a batch of registry-shaped rows, and
//! then times the post-commit readback verification pass (re-read every
//! persisted row + the paired ledger entry + content-hash compare) against the
//! commit itself, reporting the per-row and relative overhead.
//!
//! Usage: `cargo run -p astrolabe-ingest --example bench_fsv_readback [rows] [reps]`
//!
//! The number printed is the FSV verification cost the ingest path pays per
//! mutation; declare it in the phase gate rather than assuming it is free.

use std::time::Instant;

use astrolabe_ingest::VaultMutationPlan;
use calyx_aster::cf::ColumnFamily;
use calyx_aster::vault::AsterVault;
use calyx_core::{FixedClock, VaultId};
use calyx_ledger::{ActorId, EntryKind, SubjectId};

const VAULT_ID: &str = "00000000000000000000000000";

fn main() {
    let mut args = std::env::args().skip(1);
    let rows: usize = args
        .next()
        .and_then(|value| value.parse().ok())
        .unwrap_or(20_000);
    let reps: usize = args
        .next()
        .and_then(|value| value.parse().ok())
        .unwrap_or(20);

    let vault = AsterVault::with_clock(
        VAULT_ID.parse::<VaultId>().expect("vault id"),
        b"bench-fsv".to_vec(),
        FixedClock::new(1_785_400_000),
    );

    // Build a realistic registry-shaped write set: 200-byte JSON-ish values.
    let value_template = vec![b'x'; 200];
    let mut write_set = Vec::with_capacity(rows);
    let mut plan = VaultMutationPlan::new(
        "bench_fsv_readback",
        EntryKind::Ingest,
        &ActorId::Service("astrolabe-registry".to_string()),
        &SubjectId::Query(b"bench".to_vec()),
    );
    for index in 0..rows {
        let mut key = b"astrolabe:series-registry:v2:series:".to_vec();
        key.extend_from_slice(&(index as u64).to_be_bytes());
        let mut value = value_template.clone();
        value[..8].copy_from_slice(&(index as u64).to_le_bytes());
        plan.push_content(ColumnFamily::Kv, key.clone(), &value);
        write_set.push((ColumnFamily::Kv, key, value));
    }

    // Time the commit (group commit + ledger entry).
    let commit_start = Instant::now();
    vault
        .write_cf_batch_with_ledger_entry(
            write_set,
            EntryKind::Ingest,
            SubjectId::Query(b"bench".to_vec()),
            br#"{"schema":"bench-fsv-v1"}"#.to_vec(),
            ActorId::Service("astrolabe-registry".to_string()),
        )
        .expect("commit");
    let commit_elapsed = commit_start.elapsed();

    // Time the FSV readback verification, averaged over `reps` passes.
    let commit_seq = vault.latest_seq();
    let verify_start = Instant::now();
    let mut acked_rows = 0_u64;
    for _ in 0..reps {
        let ack = plan
            .verify_committed(&vault, commit_seq)
            .expect("verified readback");
        acked_rows = ack.rows_read_back();
        assert_eq!(ack.label(), "fsv:verified");
    }
    let verify_elapsed = verify_start.elapsed();

    let per_verify = verify_elapsed / reps as u32;
    let per_row_ns = per_verify.as_nanos() as f64 / rows as f64;
    let rows_per_sec = rows as f64 / per_verify.as_secs_f64();
    let overhead_pct = per_verify.as_secs_f64() / commit_elapsed.as_secs_f64() * 100.0;

    println!("rows                : {rows}");
    println!("rows_read_back      : {acked_rows}");
    println!("commit              : {commit_elapsed:?}");
    println!("fsv_readback (avg)  : {per_verify:?} over {reps} reps");
    println!("fsv per-row         : {per_row_ns:.1} ns/row");
    println!("fsv throughput      : {rows_per_sec:.0} rows/s");
    println!("fsv overhead vs commit: {overhead_pct:.1}%");
}
