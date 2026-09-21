//! Manual native ordered-SST read-session FSV for Astrolabe #874.
//!
//! This real-artifact driver writes durable vaults, reopens their immutable
//! SST generations, exercises ordered multi-get behavior, and emits a report
//! whose claims can be checked independently against the stored bytes.

use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use calyx_aster::cf::{ColumnFamily, ledger_key, slot_key};
use calyx_aster::mvcc::{OrderedReadbackMetrics, is_tombstone_value, tombstone_value};
use calyx_aster::sst::SstReader;
use calyx_aster::storage_names::classify_sst;
use calyx_aster::vault::encode::{decode_slot_vector, encode_slot_vector};
use calyx_aster::vault::{AsterVault, OrderedCfRead, VaultOptions};
use calyx_core::{CalyxError, Clock, CxId, SlotId, SlotVector, VaultId};
use calyx_ledger::{ActorId, EntryKind, SubjectId, decode as decode_ledger};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[cfg(windows)]
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessHandleCount};

const HAPPY_SALT: &[u8] = b"astrolabe-issue-874-happy";
const LEASE_SALT: &[u8] = b"astrolabe-issue-874-lease";
const CORRUPT_SALT: &[u8] = b"astrolabe-issue-874-corrupt";
const FSV_SLOT: SlotId = SlotId::new(17);
const REPEATED_BATCHES: usize = 128;

#[derive(Clone, Debug)]
struct MutableClock(Arc<AtomicU64>);

impl MutableClock {
    fn new(now: u64) -> Self {
        Self(Arc::new(AtomicU64::new(now)))
    }

    fn advance(&self, delta_ms: u64) {
        self.0.fetch_add(delta_ms, Ordering::SeqCst);
    }
}

impl Clock for MutableClock {
    fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

fn main() {
    let mut args = std::env::args_os().skip(1);
    let first = args
        .next()
        .expect("usage: sst_read_session_fsv <fresh-root> <report-path> | readback <root> <source-report> <readback-report>");
    if first == "readback" {
        let root = PathBuf::from(args.next().expect("missing readback root"));
        let source_report = PathBuf::from(args.next().expect("missing source report"));
        let readback_report = PathBuf::from(args.next().expect("missing readback report"));
        assert!(args.next().is_none(), "unexpected extra readback argument");
        readback(&root, &source_report, &readback_report);
        return;
    }
    let root = PathBuf::from(first);
    let report_path = PathBuf::from(args.next().expect("missing report path"));
    assert!(args.next().is_none(), "unexpected extra argument");
    assert!(!root.exists(), "FSV root must be absent before execution");
    fs::create_dir_all(&root).expect("create FSV root");

    let before = physical_state(&root);
    println!("SST_SESSION_BEFORE={before}");
    let happy = happy_and_boundaries(&root.join("happy"));
    let lease_expiry = lease_expiry(&root.join("lease-expiry"));
    let corruption = corruption_atomicity(&root.join("corruption"));
    let after = physical_state(&root);
    println!("SST_SESSION_AFTER={after}");

    let report = json!({
        "schema": "calyx.issue874.sst-read-session-fsv.v1",
        "status": "verified",
        "source_of_truth": "durable WAL/SST/MANIFEST bytes plus independent report readback",
        "before": before,
        "happy_and_boundaries": happy,
        "lease_expiry": lease_expiry,
        "corruption_atomicity": corruption,
        "after": after,
    });
    fs::write(
        &report_path,
        serde_json::to_vec_pretty(&report).expect("encode FSV report"),
    )
    .expect("write FSV report");
    println!("{}", serde_json::to_string(&report).expect("print report"));
    println!("REPORT_PATH={}", report_path.display());
}

fn readback(root: &Path, source_report: &Path, output: &Path) {
    assert!(root.is_dir(), "readback root must exist");
    let source_bytes = fs::read(source_report).expect("read source FSV report");
    let source: Value = serde_json::from_slice(&source_bytes).expect("parse source FSV report");
    assert_eq!(source["status"], "verified");

    let happy_root = root.join("happy");
    let kv_ssts = sst_files_in(&happy_root.join("cf").join(ColumnFamily::Kv.name()));
    assert_eq!(kv_ssts.len(), 1);
    let reader = SstReader::open(&kv_ssts[0]).expect("open compacted KV SST directly");
    let physical_alpha = reader.get(b"alpha").expect("read physical alpha");
    let physical_bravo = reader.get(b"bravo").expect("read physical bravo");
    let physical_tomb = reader.get(b"tomb").expect("read physical tomb");
    assert_eq!(physical_alpha, Some(b"value-alpha".to_vec()));
    assert_eq!(physical_bravo, Some(b"value-bravo".to_vec()));
    assert_eq!(physical_tomb, None);

    let slot_key = fsv_slot_key();
    let slot_ssts = sst_files_in(
        &happy_root
            .join("cf")
            .join(ColumnFamily::slot(FSV_SLOT).name()),
    );
    assert_eq!(slot_ssts.len(), 1);
    let slot_reader = SstReader::open(&slot_ssts[0]).expect("open Slot-CF SST directly");
    let physical_slot = slot_reader
        .get(&slot_key)
        .expect("read physical encoded slot")
        .expect("encoded slot row must exist");
    assert_eq!(physical_slot, fsv_slot_bytes());
    assert_eq!(
        decode_slot_vector(&physical_slot).expect("decode physical slot"),
        fsv_slot_vector()
    );

    let ledger_ssts = sst_files_in(&happy_root.join("cf").join(ColumnFamily::Ledger.name()));
    assert_eq!(ledger_ssts.len(), 1);
    let ledger_reader = SstReader::open(&ledger_ssts[0]).expect("open Ledger-CF SST directly");
    let ledger_rows = ledger_reader.iter().expect("read physical ledger SST rows");
    assert_eq!(ledger_rows.len(), 1);
    let ledger_key = ledger_rows[0].key.clone();
    let physical_ledger = ledger_rows[0].value.clone();
    let decoded_ledger = decode_ledger(&physical_ledger).expect("decode physical ledger entry");
    assert!(decoded_ledger.verify());
    assert_eq!(decoded_ledger.kind, EntryKind::Assay);
    assert_eq!(decoded_ledger.subject, SubjectId::Cx(fsv_cx_id()));
    assert_eq!(decoded_ledger.payload, b"issue-874-ledger-row".to_vec());
    assert_eq!(decoded_ledger.actor, ActorId::System);

    let happy = open_read_only(
        &happy_root,
        vault_id("01ARZ3NDEKTSV4RRFFQ69G5F10"),
        HAPPY_SALT,
        MutableClock::new(4_000_000),
    );
    let happy_seq = happy.latest_seq();
    let logical_alpha = happy
        .read_cf_at(happy_seq, ColumnFamily::Kv, b"alpha")
        .expect("logical alpha readback");
    let logical_bravo = happy
        .read_cf_at(happy_seq, ColumnFamily::Kv, b"bravo")
        .expect("logical bravo readback");
    let logical_tomb = happy
        .read_cf_at(happy_seq, ColumnFamily::Kv, b"tomb")
        .expect("logical tomb readback");
    let logical_slot = happy
        .read_cf_at(happy_seq, ColumnFamily::slot(FSV_SLOT), &slot_key)
        .expect("logical slot readback");
    let logical_ledger = happy
        .read_cf_at(happy_seq, ColumnFamily::Ledger, &ledger_key)
        .expect("logical ledger readback");
    assert_eq!(logical_alpha, physical_alpha);
    assert_eq!(logical_bravo, physical_bravo);
    assert_eq!(logical_tomb, physical_tomb);
    assert_eq!(logical_slot.as_deref(), Some(physical_slot.as_slice()));
    assert_eq!(logical_ledger.as_deref(), Some(physical_ledger.as_slice()));
    drop(happy);

    let lease_root = root.join("lease-expiry");
    let lease = open_read_only(
        &lease_root,
        vault_id("01ARZ3NDEKTSV4RRFFQ69G5F11"),
        LEASE_SALT,
        MutableClock::new(4_000_000),
    );
    let lease_value = lease
        .read_cf_at(lease.latest_seq(), ColumnFamily::Kv, b"lease-key")
        .expect("lease fixture readback");
    assert_eq!(lease_value, Some(b"lease-value".to_vec()));
    drop(lease);

    assert_eq!(
        source["happy_and_boundaries"]["invalid_ordinal"]["callbacks"],
        0
    );
    assert_eq!(source["lease_expiry"]["callbacks"], 0);
    assert_eq!(source["corruption_atomicity"]["callbacks"], 0);
    assert_eq!(
        source["corruption_atomicity"]["before"]["tree_blake3"],
        source["corruption_atomicity"]["after"]["tree_blake3"]
    );

    let current_name = fs::read_to_string(happy_root.join("CURRENT"))
        .expect("read CURRENT")
        .trim()
        .to_string();
    let manifest_path = happy_root.join(&current_name);
    let report = json!({
        "schema": "calyx.issue874.sst-read-session-readback.v1",
        "status": "verified",
        "source_report": {
            "path": source_report.to_string_lossy(),
            "bytes": source_bytes.len(),
            "sha256": sha256_bytes(&source_bytes),
        },
        "physical_state": physical_state(root),
        "compacted_kv_sst": {
            "path": kv_ssts[0].strip_prefix(root).expect("relative KV SST").to_string_lossy().replace('\\', "/"),
            "bytes": fs::metadata(&kv_ssts[0]).expect("stat compacted KV SST").len(),
            "sha256": sha256_file(&kv_ssts[0]),
            "alpha": physical_alpha.map(|value| String::from_utf8_lossy(&value).to_string()),
            "bravo": physical_bravo.map(|value| String::from_utf8_lossy(&value).to_string()),
            "tomb": physical_tomb.map(|value| String::from_utf8_lossy(&value).to_string()),
        },
        "slot_sst": {
            "path": slot_ssts[0].strip_prefix(root).expect("relative Slot SST").to_string_lossy().replace('\\', "/"),
            "bytes": fs::metadata(&slot_ssts[0]).expect("stat Slot SST").len(),
            "sha256": sha256_file(&slot_ssts[0]),
            "key_sha256": sha256_bytes(&slot_key),
            "value_sha256": sha256_bytes(&physical_slot),
            "decoded": slot_vector_json(&decode_slot_vector(&physical_slot).expect("decode readback slot")),
        },
        "ledger_sst": {
            "path": ledger_ssts[0].strip_prefix(root).expect("relative Ledger SST").to_string_lossy().replace('\\', "/"),
            "bytes": fs::metadata(&ledger_ssts[0]).expect("stat Ledger SST").len(),
            "sha256": sha256_file(&ledger_ssts[0]),
            "key_sha256": sha256_bytes(&ledger_key),
            "value_sha256": sha256_bytes(&physical_ledger),
            "decoded": {
                "seq": decoded_ledger.seq,
                "kind": decoded_ledger.kind.as_str(),
                "subject_matches": decoded_ledger.subject == SubjectId::Cx(fsv_cx_id()),
                "payload": String::from_utf8_lossy(&decoded_ledger.payload).to_string(),
                "actor_is_system": decoded_ledger.actor == ActorId::System,
                "hash_verified": decoded_ledger.verify(),
            },
        },
        "logical_reopen": {
            "seq": happy_seq,
            "alpha": logical_alpha.map(|value| String::from_utf8_lossy(&value).to_string()),
            "bravo": logical_bravo.map(|value| String::from_utf8_lossy(&value).to_string()),
            "tomb": logical_tomb.map(|value| String::from_utf8_lossy(&value).to_string()),
            "slot_value_sha256": logical_slot.as_deref().map(sha256_bytes),
            "ledger_value_sha256": logical_ledger.as_deref().map(sha256_bytes),
            "lease_value": lease_value.map(|value| String::from_utf8_lossy(&value).to_string()),
        },
        "current_manifest": {
            "path": manifest_path.strip_prefix(root).expect("relative manifest").to_string_lossy().replace('\\', "/"),
            "bytes": fs::metadata(&manifest_path).expect("stat manifest").len(),
            "sha256": sha256_file(&manifest_path),
        },
        "edge_callback_readback": {
            "invalid_ordinal": source["happy_and_boundaries"]["invalid_ordinal"]["callbacks"],
            "expired_lease": source["lease_expiry"]["callbacks"],
            "changed_generation": source["corruption_atomicity"]["callbacks"],
        },
    });
    fs::write(
        output,
        serde_json::to_vec_pretty(&report).expect("encode readback report"),
    )
    .expect("write readback report");
    println!(
        "{}",
        serde_json::to_string(&report).expect("print readback report")
    );
    println!("READBACK_REPORT_PATH={}", output.display());
}

fn happy_and_boundaries(root: &Path) -> Value {
    fs::create_dir_all(root).expect("create happy vault root");
    let before_seed = physical_state(root);
    println!("HAPPY_BEFORE={before_seed}");
    let clock = MutableClock::new(1_000_000);
    let vault = open_latest(
        root,
        vault_id("01ARZ3NDEKTSV4RRFFQ69G5F10"),
        HAPPY_SALT,
        clock,
    );

    let seq_alpha = write_and_flush(&vault, b"alpha", b"value-alpha");
    let seq_bravo = write_and_flush(&vault, b"bravo", b"value-bravo");
    let _seq_tomb_live = write_and_flush(&vault, b"tomb", b"value-before-delete");
    let seq_tombstone = write_and_flush(&vault, b"tomb", &tombstone_value());
    let slot_key = fsv_slot_key();
    let slot_bytes = fsv_slot_bytes();
    let seq_slot = write_cf_and_flush(&vault, ColumnFamily::slot(FSV_SLOT), &slot_key, &slot_bytes);
    let ledger_ref = vault
        .append_ledger_entry(
            EntryKind::Assay,
            SubjectId::Cx(fsv_cx_id()),
            b"issue-874-ledger-row".to_vec(),
            ActorId::System,
        )
        .expect("append canonical FSV ledger row");
    let ledger_key = ledger_key(ledger_ref.seq);
    let ledger_flush = vault
        .flush_with_report()
        .expect("flush canonical FSV ledger row");
    assert!(!ledger_flush.durable_ssts.is_empty());
    let seq_ledger = vault.latest_seq();
    assert!(
        seq_alpha < seq_bravo
            && seq_bravo < seq_tombstone
            && seq_tombstone < seq_slot
            && seq_slot < seq_ledger
    );
    let seeded = physical_state(root);
    println!("HAPPY_SEEDED={seeded}");

    let session = vault.sst_read_session().expect("open retained SST session");
    assert_eq!(session.snapshot_seq(), seq_ledger);
    let plan = [
        (ColumnFamily::Kv, b"bravo".to_vec()),
        (ColumnFamily::Kv, b"missing".to_vec()),
        (ColumnFamily::Kv, b"alpha".to_vec()),
        (ColumnFamily::Kv, b"alpha".to_vec()),
        (ColumnFamily::Kv, b"tomb".to_vec()),
        (ColumnFamily::slot(FSV_SLOT), slot_key.clone()),
        (ColumnFamily::Ledger, ledger_key.clone()),
    ];
    let point_rows = plan
        .iter()
        .map(|(cf, key)| {
            vault
                .read_cf_at(seq_ledger, *cf, key)
                .expect("point read before ordered batch")
        })
        .collect::<Vec<_>>();
    let reads = plan
        .iter()
        .enumerate()
        .map(|(ordinal, (cf, key))| OrderedCfRead::new(ordinal, *cf, key))
        .collect::<Vec<_>>();
    let mut rows = vec![None; reads.len()];
    let metrics = session
        .visit_ordered_cf_plan::<CalyxError, _>(&reads, |ordinal, cf, key, value| {
            assert_eq!(cf, plan[ordinal].0);
            assert_eq!(key, plan[ordinal].1.as_slice());
            rows[ordinal] = value.map(<[u8]>::to_vec);
            Ok(())
        })
        .expect("ordered multi-get");
    assert_eq!(rows[0].as_deref(), Some(b"value-bravo".as_slice()));
    assert_eq!(rows[1], None);
    assert_eq!(rows[2].as_deref(), Some(b"value-alpha".as_slice()));
    assert_eq!(rows[3].as_deref(), Some(b"value-alpha".as_slice()));
    assert!(rows[4].as_deref().is_some_and(is_tombstone_value));
    assert_eq!(rows[5].as_deref(), Some(slot_bytes.as_slice()));
    let decoded_batch_ledger = decode_ledger(rows[6].as_deref().expect("batch ledger row"))
        .expect("decode batch ledger row");
    assert!(decoded_batch_ledger.verify());
    assert_eq!(decoded_batch_ledger.payload, b"issue-874-ledger-row");
    for ordinal in [0_usize, 1, 2, 3, 5, 6] {
        assert_eq!(rows[ordinal], point_rows[ordinal]);
    }
    assert_eq!(point_rows[4], None);
    assert_eq!(metrics.requested_keys, 7);
    assert_eq!(metrics.rows_read_back, 7);
    assert_eq!(metrics.sst_files_opened, metrics.unique_sst_generations);
    assert!(metrics.sst_files_opened >= 4);
    assert!(metrics.sst_key_probes >= 6);
    assert!(metrics.sst_map_reuses >= 1);

    let handles_before = process_handle_count();
    let mut handles_max_after_batch = handles_before;
    let mut repeated_metrics = OrderedReadbackMetrics {
        session_snapshot_seq: seq_ledger,
        ..OrderedReadbackMetrics::default()
    };
    for _ in 0..REPEATED_BATCHES {
        let mut repeated_rows = vec![None; reads.len()];
        let batch_metrics = session
            .visit_ordered_cf_plan::<CalyxError, _>(&reads, |ordinal, _, _, value| {
                repeated_rows[ordinal] = value.map(<[u8]>::to_vec);
                Ok(())
            })
            .expect("repeated ordered multi-get");
        assert_eq!(repeated_rows, rows);
        assert_eq!(
            batch_metrics.sst_files_opened,
            batch_metrics.unique_sst_generations
        );
        repeated_metrics
            .checked_merge(batch_metrics)
            .expect("merge repeated read metrics");
        handles_max_after_batch = handles_max_after_batch.max(process_handle_count());
    }
    let handles_after = process_handle_count();
    assert_eq!(handles_after, handles_before);
    assert_eq!(handles_max_after_batch, handles_before);

    let mut empty_callbacks = 0_u64;
    let empty_metrics = session
        .visit_ordered_cf_plan::<CalyxError, _>(&[], |_, _, _, _| {
            empty_callbacks += 1;
            Ok(())
        })
        .expect("empty ordered plan");
    assert_eq!(empty_callbacks, 0);
    assert_eq!(empty_metrics.requested_keys, 0);
    assert_eq!(empty_metrics.sst_files_opened, 0);

    let invalid_before = physical_state(root);
    println!("INVALID_ORDINAL_BEFORE={invalid_before}");
    let mut invalid_callbacks = 0_u64;
    let invalid = session
        .visit_ordered_cf_plan::<CalyxError, _>(
            &[OrderedCfRead::new(7, ColumnFamily::Kv, b"alpha")],
            |_, _, _, _| {
                invalid_callbacks += 1;
                Ok(())
            },
        )
        .expect_err("invalid ordinal must fail closed");
    assert_eq!(invalid.code, "CALYX_ASTER_CORRUPT_SHARD");
    assert_eq!(invalid_callbacks, 0);
    let invalid_after = physical_state(root);
    println!("INVALID_ORDINAL_AFTER={invalid_after}");
    assert_eq!(invalid_before, invalid_after);

    let kv_inputs = sst_files_in(&root.join("cf").join(ColumnFamily::Kv.name()));
    assert!(kv_inputs.len() >= 2);
    drop(session);
    let before_compaction = physical_state(root);
    println!("COMPACTION_BEFORE={before_compaction}");
    vault
        .purge_tombstoned_cfs(&[ColumnFamily::Kv])
        .expect("compact KV after read session release");
    let after_compaction = physical_state(root);
    println!("COMPACTION_AFTER={after_compaction}");
    assert!(kv_inputs.iter().all(|path| !path.exists()));
    let kv_outputs = sst_files_in(&root.join("cf").join(ColumnFamily::Kv.name()));
    assert_eq!(kv_outputs.len(), 1);
    assert!(
        classify_sst(&kv_outputs[0])
            .expect("classify compacted adoption output")
            .is_some()
    );
    drop(vault);

    let reopened = open_full(
        root,
        vault_id("01ARZ3NDEKTSV4RRFFQ69G5F10"),
        HAPPY_SALT,
        MutableClock::new(1_010_000),
    );
    let reopened_seq = reopened.latest_seq();
    assert_eq!(reopened_seq, seq_ledger);
    assert_eq!(
        reopened
            .read_cf_at(reopened_seq, ColumnFamily::Kv, b"alpha")
            .expect("reopen alpha"),
        Some(b"value-alpha".to_vec())
    );
    assert_eq!(
        reopened
            .read_cf_at(reopened_seq, ColumnFamily::Kv, b"bravo")
            .expect("reopen bravo"),
        Some(b"value-bravo".to_vec())
    );
    assert_eq!(
        reopened
            .read_cf_at(reopened_seq, ColumnFamily::Kv, b"tomb")
            .expect("reopen tombstone"),
        None
    );
    assert_eq!(
        reopened
            .read_cf_at(reopened_seq, ColumnFamily::slot(FSV_SLOT), &slot_key)
            .expect("reopen encoded slot"),
        Some(slot_bytes.clone())
    );
    assert_eq!(
        reopened
            .read_cf_at(reopened_seq, ColumnFamily::Ledger, &ledger_key)
            .expect("reopen ledger"),
        point_rows[6].clone()
    );
    drop(reopened);
    let terminal = physical_state(root);
    println!("HAPPY_TERMINAL={terminal}");

    json!({
        "before_seed": before_seed,
        "seeded": seeded,
        "snapshot_seq": seq_ledger,
        "ordered_rows": rows.iter().map(|row| row.as_ref().map(|bytes| json!({
            "bytes": bytes.len(),
            "sha256": sha256_bytes(bytes),
            "utf8_lossy": String::from_utf8_lossy(bytes).to_string(),
        }))).collect::<Vec<_>>(),
        "metrics": metrics_json(metrics),
        "point_batch_byte_identity": {
            "ordinals_compared": [0, 1, 2, 3, 5, 6],
            "equal": true,
            "tombstone_point_hidden": point_rows[4].is_none(),
            "tombstone_physical_present": rows[4].as_deref().is_some_and(is_tombstone_value),
        },
        "repeated_batches": {
            "count": REPEATED_BATCHES,
            "handles_before": handles_before,
            "handles_max_after_batch": handles_max_after_batch,
            "handles_after": handles_after,
            "metrics": metrics_json(repeated_metrics),
        },
        "empty_plan": {
            "callbacks": empty_callbacks,
            "metrics": metrics_json(empty_metrics),
        },
        "invalid_ordinal": {
            "before": invalid_before,
            "error": error_json(&invalid),
            "callbacks": invalid_callbacks,
            "after": invalid_after,
        },
        "compaction": {
            "before": before_compaction,
            "after": after_compaction,
            "input_ssts": relative_paths(root, &kv_inputs),
            "input_ssts_absent": kv_inputs.iter().all(|path| !path.exists()),
            "output_ssts": relative_paths(root, &kv_outputs),
        },
        "reopen": {
            "seq": reopened_seq,
            "alpha": "value-alpha",
            "bravo": "value-bravo",
            "tomb": null,
            "slot_value_sha256": sha256_bytes(&slot_bytes),
            "ledger_value_sha256": sha256_bytes(rows[6].as_deref().expect("ledger row for report")),
            "ledger_hash_verified": decoded_batch_ledger.verify(),
        },
        "terminal": terminal,
    })
}

fn lease_expiry(root: &Path) -> Value {
    fs::create_dir_all(root).expect("create lease-expiry vault root");
    let clock = MutableClock::new(2_000_000);
    let vault = open_latest(
        root,
        vault_id("01ARZ3NDEKTSV4RRFFQ69G5F11"),
        LEASE_SALT,
        clock.clone(),
    );
    let seq = write_and_flush(&vault, b"lease-key", b"lease-value");
    let session = vault.sst_read_session().expect("open expiring session");
    assert_eq!(session.snapshot_seq(), seq);
    clock.advance(5_001);
    let before = physical_state(root);
    println!("LEASE_EXPIRY_BEFORE={before}");
    let mut callbacks = 0_u64;
    let error = session
        .visit_ordered_cf_plan::<CalyxError, _>(
            &[OrderedCfRead::new(0, ColumnFamily::Kv, b"lease-key")],
            |_, _, _, _| {
                callbacks += 1;
                Ok(())
            },
        )
        .expect_err("expired session must fail closed");
    assert_eq!(error.code, "CALYX_READER_LEASE_EXPIRED");
    assert_eq!(callbacks, 0);
    let after = physical_state(root);
    println!("LEASE_EXPIRY_AFTER={after}");
    assert_eq!(before, after);
    json!({
        "before": before,
        "action": "advance deterministic real-vault clock by 5001 ms, then read",
        "error": error_json(&error),
        "callbacks": callbacks,
        "after": after,
    })
}

fn corruption_atomicity(root: &Path) -> Value {
    fs::create_dir_all(root).expect("create corruption vault root");
    let clock = MutableClock::new(3_000_000);
    let vault_id = vault_id("01ARZ3NDEKTSV4RRFFQ69G5F12");
    let corrupt_slot_key = slot_key(CxId::from_input(
        b"astrolabe-issue-874-corrupt-slot",
        1,
        CORRUPT_SALT,
    ));
    {
        let vault = open_latest(root, vault_id, CORRUPT_SALT, clock.clone());
        vault
            .write_cf(
                ColumnFamily::Kv,
                b"corrupt-alpha".to_vec(),
                b"corrupt-value-alpha".to_vec(),
            )
            .expect("write valid earlier-CF corruption seed");
        vault.flush().expect("flush valid earlier-CF seed");
        vault
            .write_cf(
                ColumnFamily::slot(FSV_SLOT),
                corrupt_slot_key.clone(),
                fsv_slot_bytes(),
            )
            .expect("write later-CF corruption seed");
        vault.flush().expect("flush later-CF corruption seed");
    }
    let vault = open_latest(root, vault_id, CORRUPT_SALT, clock);
    let target = find_sst_with_key(root, ColumnFamily::slot(FSV_SLOT), &corrupt_slot_key);
    let session = vault.sst_read_session().expect("open corruption session");
    std::thread::sleep(Duration::from_millis(20));
    flip_last_byte(&target);
    let before = physical_state(root);
    println!("CORRUPTION_BEFORE_READ={before}");
    let mut callbacks = 0_u64;
    let reads = [
        OrderedCfRead::new(0, ColumnFamily::Kv, b"corrupt-alpha"),
        OrderedCfRead::new(1, ColumnFamily::slot(FSV_SLOT), &corrupt_slot_key),
    ];
    let error = session
        .visit_ordered_cf_plan::<CalyxError, _>(&reads, |_, _, _, _| {
            callbacks += 1;
            Ok(())
        })
        .expect_err("changed SST generation must fail closed");
    assert_eq!(error.code, "CALYX_ASTER_CORRUPT_SHARD");
    assert_eq!(callbacks, 0);
    let after = physical_state(root);
    println!("CORRUPTION_AFTER_READ={after}");
    assert_eq!(before, after);
    json!({
        "corrupted_sst": target.strip_prefix(root).expect("relative corrupt SST").to_string_lossy().replace('\\', "/"),
        "before": before,
        "action": "ordered cross-CF read where valid KV precedes a length-stable changed Slot generation",
        "error": error_json(&error),
        "callbacks": callbacks,
        "after": after,
    })
}

fn write_and_flush<C: Clock>(vault: &AsterVault<C>, key: &[u8], value: &[u8]) -> u64 {
    write_cf_and_flush(vault, ColumnFamily::Kv, key, value)
}

fn write_cf_and_flush<C: Clock>(
    vault: &AsterVault<C>,
    cf: ColumnFamily,
    key: &[u8],
    value: &[u8],
) -> u64 {
    let seq = vault
        .write_cf(cf, key.to_vec(), value.to_vec())
        .expect("write durable FSV row");
    let report = vault.flush_with_report().expect("flush durable FSV row");
    assert!(!report.durable_ssts.is_empty());
    assert!(report.router_handoff.is_some());
    seq
}

fn open_latest(
    root: &Path,
    vault_id: VaultId,
    salt: &[u8],
    clock: MutableClock,
) -> AsterVault<MutableClock> {
    AsterVault::new_durable_with_clock(
        root,
        vault_id,
        salt.to_vec(),
        VaultOptions {
            memtable_byte_cap: 1_024,
            restore_mvcc_rows: false,
            ..VaultOptions::default()
        },
        clock,
    )
    .expect("open latest-only durable FSV vault")
}

fn open_full(
    root: &Path,
    vault_id: VaultId,
    salt: &[u8],
    clock: MutableClock,
) -> AsterVault<MutableClock> {
    AsterVault::new_durable_with_clock(
        root,
        vault_id,
        salt.to_vec(),
        VaultOptions {
            memtable_byte_cap: 1_024,
            ..VaultOptions::default()
        },
        clock,
    )
    .expect("open full-MVCC durable FSV vault")
}

fn open_read_only(
    root: &Path,
    vault_id: VaultId,
    salt: &[u8],
    clock: MutableClock,
) -> AsterVault<MutableClock> {
    AsterVault::new_durable_with_clock(
        root,
        vault_id,
        salt.to_vec(),
        VaultOptions {
            memtable_byte_cap: 1_024,
            read_only: true,
            restore_ledger_hook: false,
            ..VaultOptions::default()
        },
        clock,
    )
    .expect("open read-only durable FSV vault")
}

fn vault_id(value: &str) -> VaultId {
    value.parse().expect("valid FSV vault id")
}

fn fsv_slot_vector() -> SlotVector {
    SlotVector::Dense {
        dim: 3,
        data: vec![0.25, -0.5, 0.75],
    }
}

fn fsv_slot_bytes() -> Vec<u8> {
    encode_slot_vector(&fsv_slot_vector()).expect("encode deterministic FSV slot")
}

fn fsv_slot_key() -> Vec<u8> {
    slot_key(fsv_cx_id())
}

fn fsv_cx_id() -> CxId {
    CxId::from_input(b"astrolabe-issue-874-constellation", 1, HAPPY_SALT)
}

fn slot_vector_json(vector: &SlotVector) -> Value {
    serde_json::to_value(vector).expect("serialize decoded slot vector")
}

#[cfg(windows)]
fn process_handle_count() -> u32 {
    let mut handles = 0_u32;
    // SAFETY: GetCurrentProcess returns a process-lifetime pseudo-handle and
    // `handles` is a valid writable u32 for the duration of the call.
    let success = unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut handles) };
    assert_ne!(success, 0, "GetProcessHandleCount must succeed");
    handles
}

#[cfg(not(windows))]
fn process_handle_count() -> u32 {
    0
}

fn find_sst_with_key(root: &Path, cf: ColumnFamily, key: &[u8]) -> PathBuf {
    sst_files_in(&root.join("cf").join(cf.name()))
        .into_iter()
        .find(|path| {
            SstReader::open(path)
                .expect("open candidate SST")
                .get(key)
                .expect("probe candidate SST")
                .is_some()
        })
        .expect("find SST containing corruption key")
}

fn flip_last_byte(path: &Path) {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .expect("open SST for controlled corruption");
    let len = file.metadata().expect("stat corruption SST").len();
    assert!(len > 0);
    file.seek(SeekFrom::Start(len - 1))
        .expect("seek corruption byte");
    let mut byte = [0_u8; 1];
    file.read_exact(&mut byte).expect("read corruption byte");
    byte[0] ^= 0x5a;
    file.seek(SeekFrom::Start(len - 1))
        .expect("rewind corruption byte");
    file.write_all(&byte).expect("write corruption byte");
    file.sync_all().expect("sync corrupted SST");
}

fn error_json(error: &CalyxError) -> Value {
    json!({
        "code": error.code,
        "message": error.message,
        "remediation": error.remediation,
    })
}

fn sha256_file(path: &Path) -> String {
    sha256_bytes(&fs::read(path).expect("read file for SHA-256"))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn metrics_json(metrics: OrderedReadbackMetrics) -> Value {
    json!({
        "session_snapshot_seq": metrics.session_snapshot_seq,
        "requested_keys": metrics.requested_keys,
        "rows_read_back": metrics.rows_read_back,
        "bytes_read_back": metrics.bytes_read_back,
        "read_batches": metrics.read_batches,
        "source_read_operations": metrics.source_read_operations,
        "sst_files_opened": metrics.sst_files_opened,
        "unique_sst_generations": metrics.unique_sst_generations,
        "sst_key_probes": metrics.sst_key_probes,
        "sst_map_reuses": metrics.sst_map_reuses,
        "plan_index_bytes": metrics.plan_index_bytes,
        "max_readback_batch_bytes": metrics.max_readback_batch_bytes,
    })
}

fn physical_state(root: &Path) -> Value {
    let files = files(root);
    json!({
        "files": files.len(),
        "bytes": files.iter().map(|path| fs::metadata(path).expect("stat state file").len()).sum::<u64>(),
        "sst_files": files.iter().filter(|path| path.extension().and_then(|value| value.to_str()) == Some("sst")).count(),
        "tree_blake3": tree_hash(root),
        "current": fs::read_to_string(root.join("CURRENT")).ok().map(|value| value.trim().to_string()),
        "router_handoff_present": root.join("ROUTER_HANDOFF").is_file(),
    })
}

fn sst_files_in(root: &Path) -> Vec<PathBuf> {
    files(root)
        .into_iter()
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("sst"))
        .collect()
}

fn relative_paths(root: &Path, paths: &[PathBuf]) -> Vec<String> {
    paths
        .iter()
        .map(|path| {
            path.strip_prefix(root)
                .expect("relative state path")
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect()
}

fn tree_hash(root: &Path) -> String {
    let mut hasher = blake3::Hasher::new();
    for path in files(root) {
        let relative = path.strip_prefix(root).expect("relative state path");
        hasher.update(relative.to_string_lossy().replace('\\', "/").as_bytes());
        hasher.update(&[0]);
        hasher.update(&fs::read(&path).expect("read state file"));
        hasher.update(&[0xff]);
    }
    hasher.finalize().to_hex().to_string()
}

fn files(root: &Path) -> Vec<PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(path) = pending.pop() {
        if !path.exists() {
            continue;
        }
        if path.is_file() {
            files.push(path);
            continue;
        }
        for entry in fs::read_dir(&path).expect("read state directory") {
            pending.push(entry.expect("read state entry").path());
        }
    }
    files.sort();
    files
}
