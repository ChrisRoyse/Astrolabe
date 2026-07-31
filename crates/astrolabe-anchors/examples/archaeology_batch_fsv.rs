//! Manual native FSV for ordered anchor batching and manifest-bound router
//! handoff (#858).
//!
//! The caller supplies an empty evidence root. This real artifact creates
//! durable vaults beneath it, exercises happy/incremental/no-op and refusal
//! paths, independently reopens persisted state, and writes one JSON receipt.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use astrolabe_anchors::{
    ASTRO_ANCHOR_BATCH_EMPTY, OutcomeAnchorBatchItem, OutcomeAnchorRequest, OutcomeKind,
    OutcomeSubject, ingest_outcome_anchor_batch, read_anchor_rows,
};
use calyx_aster::cf::ColumnFamily;
use calyx_aster::vault::{AsterVault, VaultFlushReport, VaultOptions};
use calyx_core::{AnchorKind, AnchorValue, CxId, VaultId, VaultStore};
use serde_json::{Value, json};

const SALT: &[u8] = b"astrolabe-issue-858-fsv";

fn main() {
    let root = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .expect("usage: archaeology_batch_fsv <empty-evidence-root>");
    fs::create_dir_all(&root).expect("create evidence root");
    assert!(
        fs::read_dir(&root)
            .expect("read evidence root")
            .next()
            .is_none(),
        "evidence root must be empty"
    );

    let handoff = handoff_happy_incremental_noop(&root.join("handoff"));
    let anchors = ordered_anchor_boundaries(&root.join("anchors"));
    let empty = empty_batch_refusal(&root.join("empty"));
    let invalid = invalid_marker_refusal(&root.join("invalid-marker"));
    let isolation = project_isolation(&root.join("project-a"), &root.join("project-b"));
    let report = json!({
        "schema": "astrolabe.issue858.manual-fsv.v1",
        "status": "verified",
        "handoff": handoff,
        "anchors": anchors,
        "empty_batch": empty,
        "invalid_marker": invalid,
        "project_isolation": isolation,
    });
    let report_path = root.join("issue858-fsv.json");
    fs::write(
        &report_path,
        serde_json::to_vec_pretty(&report).expect("encode report"),
    )
    .expect("write report");
    println!("{}", serde_json::to_string(&report).expect("print report"));
    println!("REPORT_PATH={}", report_path.display());
}

fn handoff_happy_incremental_noop(root: &Path) -> Value {
    let vault = open_vault(root, vault_id(1), 4_096);
    let before = physical_state(root);
    println!("HANDOFF_HAPPY_BEFORE={before}");
    let initial_rows = (0u8..12)
        .map(|index| {
            (
                ColumnFamily::Kv,
                format!("issue858-key-{index:02}").into_bytes(),
                vec![index; 1_400],
            )
        })
        .collect::<Vec<_>>();
    let initial_seq = vault.write_cf_batch(initial_rows).expect("initial commit");
    let initial_flush = vault.flush_with_report().expect("initial handoff");
    require_handoff(&initial_flush, true, 1);
    for index in 0u8..12 {
        let value = vault
            .read_cf_at(
                initial_seq,
                ColumnFamily::Kv,
                format!("issue858-key-{index:02}").as_bytes(),
            )
            .expect("read initial row")
            .expect("initial row present");
        assert_eq!(value, vec![index; 1_400]);
    }
    let after_initial = physical_state(root);
    println!("HANDOFF_HAPPY_AFTER={after_initial}");

    let update = vec![
        (
            ColumnFamily::Kv,
            b"issue858-key-00".to_vec(),
            vec![200; 1_400],
        ),
        (
            ColumnFamily::Kv,
            b"issue858-key-12".to_vec(),
            vec![12; 1_400],
        ),
    ];
    let incremental_seq = vault.write_cf_batch(update).expect("incremental commit");
    let incremental_flush = vault.flush_with_report().expect("incremental handoff");
    require_handoff(&incremental_flush, false, 0);
    assert_eq!(
        vault
            .read_cf_at(incremental_seq, ColumnFamily::Kv, b"issue858-key-00")
            .expect("read updated row")
            .expect("updated row present"),
        vec![200; 1_400]
    );
    let after_incremental = physical_state(root);
    println!("HANDOFF_INCREMENTAL_AFTER={after_incremental}");

    let no_op_before = tree_hash(root);
    let no_op_flush = vault.flush_with_report().expect("no-op handoff");
    let no_op_after = tree_hash(root);
    assert_eq!(
        no_op_before, no_op_after,
        "no-op flush changed persisted bytes"
    );
    assert!(no_op_flush.durable_ssts.is_empty());
    assert!(no_op_flush.router_ssts.is_empty());
    require_handoff(&no_op_flush, false, 0);
    drop(vault);

    let reopened = open_vault(root, vault_id(1), 4_096);
    assert_eq!(reopened.latest_seq(), incremental_seq);
    assert_eq!(
        reopened
            .read_cf_at(initial_seq, ColumnFamily::Kv, b"issue858-key-00")
            .expect("historical reopen read")
            .expect("historical row present"),
        vec![0; 1_400]
    );
    assert_eq!(
        reopened
            .read_cf_at(incremental_seq, ColumnFamily::Kv, b"issue858-key-00")
            .expect("latest reopen read")
            .expect("latest row present"),
        vec![200; 1_400]
    );
    let reopened_rows = reopened
        .scan_cf_at(incremental_seq, ColumnFamily::Kv)
        .expect("scan reopened rows");
    assert_eq!(reopened_rows.len(), 13);
    let terminal = physical_state(root);
    println!("HANDOFF_REOPENED_AFTER={terminal}");
    json!({
        "before": before,
        "after_initial": after_initial,
        "after_incremental": after_incremental,
        "terminal": terminal,
        "initial_seq": initial_seq,
        "incremental_seq": incremental_seq,
        "reopened_rows": reopened_rows.len(),
        "initial_flush": flush_json(&initial_flush),
        "incremental_flush": flush_json(&incremental_flush),
        "no_op_flush": flush_json(&no_op_flush),
        "no_op_tree_hash_equal": no_op_before == no_op_after,
    })
}

fn ordered_anchor_boundaries(root: &Path) -> Value {
    let vault = open_vault(root, vault_id(2), 8 * 1024 * 1024);
    let cx_id = CxId::from_bytes([7; 16]);
    let mapping = BTreeMap::from([("shared-symbol".to_string(), cx_id)]);
    let exact_requests = requests(0, 4);
    let exact_items = exact_requests
        .iter()
        .map(|request| OutcomeAnchorBatchItem::new(request, &mapping))
        .collect::<Vec<_>>();
    let before = physical_state(root);
    println!("ANCHOR_EXACT_BEFORE={before}");
    let exact = ingest_outcome_anchor_batch(&vault, &exact_items, "issue858-fsv")
        .expect("exact-boundary anchor batch");
    assert_eq!(exact.items.len(), 4);
    assert_eq!(exact.ledger_refs_verified, 4);
    assert_eq!(exact.rows_written, 1);
    assert_eq!(
        read_anchor_rows(&vault).expect("read exact anchors")[0]
            .row
            .anchors
            .len(),
        4
    );
    let after_exact = physical_state(root);
    println!("ANCHOR_EXACT_AFTER={after_exact}");

    let dedup = ingest_outcome_anchor_batch(&vault, &exact_items, "issue858-fsv")
        .expect("dedup-only anchor batch");
    assert_eq!(dedup.items.len(), 4);
    assert_eq!(dedup.ledger_refs_verified, 4);
    assert_eq!(dedup.rows_written, 0);
    assert!(dedup.items.iter().all(|item| item.anchors_written == 0));
    assert!(
        dedup
            .items
            .iter()
            .all(|item| item.anchors_deduplicated == 1)
    );
    assert_eq!(
        read_anchor_rows(&vault).expect("read dedup anchors")[0]
            .row
            .anchors
            .len(),
        4
    );
    let after_dedup = physical_state(root);
    println!("ANCHOR_DEDUP_AFTER={after_dedup}");

    let plus_requests = requests(4, 5);
    let plus_items = plus_requests
        .iter()
        .map(|request| OutcomeAnchorBatchItem::new(request, &mapping))
        .collect::<Vec<_>>();
    let plus = ingest_outcome_anchor_batch(&vault, &plus_items, "issue858-fsv")
        .expect("boundary-plus-one anchor batch");
    assert_eq!(plus.items.len(), 5);
    assert_eq!(plus.ledger_refs_verified, 5);
    assert_eq!(plus.rows_written, 1);
    let persisted = read_anchor_rows(&vault).expect("read plus-one anchors");
    assert_eq!(persisted.len(), 1);
    assert_eq!(persisted[0].row.anchors.len(), 9);
    let ledger_rows = vault
        .scan_cf_at(vault.snapshot(), ColumnFamily::Ledger)
        .expect("scan exact ledger");
    assert_eq!(ledger_rows.len(), 13);
    let terminal = physical_state(root);
    println!("ANCHOR_PLUS_ONE_AFTER={terminal}");
    json!({
        "before": before,
        "after_exact": after_exact,
        "after_dedup": after_dedup,
        "terminal": terminal,
        "exact_items": exact.items.len(),
        "exact_rows_written": exact.rows_written,
        "exact_ledger_refs": exact.ledger_refs_verified,
        "dedup_items": dedup.items.len(),
        "dedup_rows_written": dedup.rows_written,
        "dedup_ledger_refs": dedup.ledger_refs_verified,
        "plus_one_items": plus.items.len(),
        "plus_one_rows_written": plus.rows_written,
        "plus_one_ledger_refs": plus.ledger_refs_verified,
        "final_anchor_values": persisted[0].row.anchors.len(),
        "final_ledger_rows": ledger_rows.len(),
        "exact_flush": flush_json(&exact.flush),
        "dedup_flush": flush_json(&dedup.flush),
        "plus_one_flush": flush_json(&plus.flush),
    })
}

fn empty_batch_refusal(root: &Path) -> Value {
    let vault = open_vault(root, vault_id(3), 8 * 1024 * 1024);
    let before = physical_state(root);
    let before_hash = tree_hash(root);
    println!("EMPTY_BATCH_BEFORE={before}");
    let error = ingest_outcome_anchor_batch(&vault, &[], "issue858-fsv")
        .expect_err("empty batch must refuse");
    let after_hash = tree_hash(root);
    let after = physical_state(root);
    println!("EMPTY_BATCH_AFTER={after}");
    assert_eq!(error.code, ASTRO_ANCHOR_BATCH_EMPTY);
    assert_eq!(before_hash, after_hash);
    json!({
        "before": before,
        "after": after,
        "error_code": error.code,
        "tree_hash_equal": before_hash == after_hash,
    })
}

fn invalid_marker_refusal(root: &Path) -> Value {
    let vault = open_vault(root, vault_id(4), 8 * 1024 * 1024);
    vault
        .write_cf(
            ColumnFamily::Kv,
            b"marker-key".to_vec(),
            b"marker-value".to_vec(),
        )
        .expect("marker seed commit");
    vault.flush().expect("marker seed flush");
    drop(vault);
    let marker = root.join("ROUTER_HANDOFF");
    fs::write(&marker, b"{not-json").expect("corrupt marker fixture");
    let reopened = open_vault(root, vault_id(4), 8 * 1024 * 1024);
    let before = physical_state(root);
    let before_hash = tree_hash(root);
    println!("INVALID_MARKER_BEFORE={before}");
    let error = reopened
        .flush_with_report()
        .expect_err("malformed marker must refuse");
    let after_hash = tree_hash(root);
    let after = physical_state(root);
    println!("INVALID_MARKER_AFTER={after}");
    assert_eq!(error.code, "CALYX_ASTER_ROUTER_HANDOFF_STATE_INVALID");
    assert_eq!(before_hash, after_hash);
    json!({
        "before": before,
        "after": after,
        "error_code": error.code,
        "tree_hash_equal": before_hash == after_hash,
    })
}

fn project_isolation(a_root: &Path, b_root: &Path) -> Value {
    let a = open_vault(a_root, vault_id(5), 8 * 1024 * 1024);
    let b = open_vault(b_root, vault_id(6), 8 * 1024 * 1024);
    a.write_cf(
        ColumnFamily::Kv,
        b"same-key".to_vec(),
        b"project-a-v1".to_vec(),
    )
    .expect("project A seed");
    a.flush().expect("project A seed flush");
    b.write_cf(
        ColumnFamily::Kv,
        b"same-key".to_vec(),
        b"project-b-v1".to_vec(),
    )
    .expect("project B seed");
    b.flush().expect("project B seed flush");
    let b_before = physical_state(b_root);
    let b_hash_before = tree_hash(b_root);
    println!("PROJECT_B_BEFORE_A_UPDATE={b_before}");
    a.write_cf(
        ColumnFamily::Kv,
        b"same-key".to_vec(),
        b"project-a-v2".to_vec(),
    )
    .expect("project A update");
    a.flush().expect("project A update flush");
    let b_hash_after = tree_hash(b_root);
    let b_after = physical_state(b_root);
    println!("PROJECT_B_AFTER_A_UPDATE={b_after}");
    assert_eq!(b_hash_before, b_hash_after);
    assert_eq!(
        b.read_cf_at(b.snapshot(), ColumnFamily::Kv, b"same-key")
            .expect("read B")
            .expect("B row present"),
        b"project-b-v1"
    );
    assert_eq!(
        a.read_cf_at(a.snapshot(), ColumnFamily::Kv, b"same-key")
            .expect("read A")
            .expect("A row present"),
        b"project-a-v2"
    );
    json!({
        "project_b_before": b_before,
        "project_b_after": b_after,
        "project_b_tree_hash_equal": b_hash_before == b_hash_after,
        "project_a_value": "project-a-v2",
        "project_b_value": "project-b-v1",
    })
}

fn requests(start: u64, count: usize) -> Vec<OutcomeAnchorRequest> {
    (0..count)
        .map(|offset| {
            let ordinal = start + offset as u64;
            OutcomeAnchorRequest::new(
                OutcomeKind::GitArchaeology,
                format!("git:revert:issue858-{ordinal}"),
                10_000 + ordinal,
                None,
                vec![OutcomeSubject {
                    subject_id: "shared-symbol".to_string(),
                    anchor_kind: AnchorKind::TestPass,
                    value: AnchorValue::Bool(ordinal % 2 == 0),
                }],
            )
            .expect("valid request")
        })
        .collect()
}

fn require_handoff(flush: &VaultFlushReport, full_inventory: bool, minimum_retired: usize) {
    assert!(flush.router_ssts.is_empty());
    let handoff = flush
        .router_handoff
        .as_ref()
        .expect("durable handoff receipt");
    assert_eq!(handoff.full_inventory, full_inventory);
    assert_eq!(handoff.covered_flush_debt_files_after, 0);
    assert_eq!(handoff.covered_flush_debt_bytes_after, 0);
    assert!(handoff.flush_sst_files_retired >= minimum_retired);
}

fn flush_json(flush: &VaultFlushReport) -> Value {
    let handoff = flush.router_handoff.as_ref().expect("durable handoff");
    json!({
        "durable_sst_files": flush.durable_ssts.len(),
        "durable_sst_entries": flush.durable_ssts.iter().map(|summary| summary.entries).sum::<usize>(),
        "durable_sst_bytes": flush.durable_ssts.iter().map(|summary| summary.bytes).sum::<u64>(),
        "router_sst_files": flush.router_ssts.len(),
        "manifest_seq": handoff.manifest_seq,
        "durable_seq": handoff.durable_seq,
        "full_inventory": handoff.full_inventory,
        "candidate_sst_files": handoff.candidate_sst_files,
        "memtable_rows_verified": handoff.memtable_rows_verified,
        "flush_sst_files_verified": handoff.flush_sst_files_verified,
        "flush_sst_entries_verified": handoff.flush_sst_entries_verified,
        "flush_sst_files_retired": handoff.flush_sst_files_retired,
        "flush_sst_bytes_retired": handoff.flush_sst_bytes_retired,
        "covered_flush_debt_files_after": handoff.covered_flush_debt_files_after,
        "covered_flush_debt_bytes_after": handoff.covered_flush_debt_bytes_after,
        "state_path": handoff.state_path,
    })
}

fn open_vault(root: &Path, id: VaultId, memtable_byte_cap: usize) -> AsterVault {
    AsterVault::open(
        root,
        id,
        SALT.to_vec(),
        VaultOptions {
            memtable_byte_cap,
            ..VaultOptions::default()
        },
    )
    .expect("open durable vault")
}

fn vault_id(ordinal: u8) -> VaultId {
    format!("01ARZ3NDEKTSV4RRFFQ69G5F{ordinal:02}")
        .parse()
        .expect("vault id")
}

fn physical_state(root: &Path) -> Value {
    let files = files(root);
    let ssts = files
        .iter()
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("sst"))
        .count();
    let flush_ssts = files
        .iter()
        .filter(|path| {
            path.file_name()
                .and_then(|value| value.to_str())
                .is_some_and(|name| name.starts_with("flush-") && name.ends_with(".sst"))
        })
        .count();
    let bytes = files
        .iter()
        .map(|path| fs::metadata(path).expect("stat physical state").len())
        .sum::<u64>();
    json!({
        "files": files.len(),
        "bytes": bytes,
        "sst_files": ssts,
        "flush_sst_files": flush_ssts,
        "tree_blake3": tree_hash(root),
        "current": fs::read_to_string(root.join("CURRENT")).ok().map(|value| value.trim().to_string()),
        "router_handoff_present": root.join("ROUTER_HANDOFF").is_file(),
    })
}

fn tree_hash(root: &Path) -> String {
    let mut hasher = blake3::Hasher::new();
    for path in files(root) {
        let relative = path.strip_prefix(root).expect("relative path");
        hasher.update(relative.to_string_lossy().replace('\\', "/").as_bytes());
        hasher.update(&[0]);
        hasher.update(&fs::read(&path).expect("read physical file"));
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
        for entry in fs::read_dir(&path).expect("read physical directory") {
            pending.push(entry.expect("read physical entry").path());
        }
    }
    files.sort();
    files
}
