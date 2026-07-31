//! Manual native WAL-tail recovery FSV for Astrolabe #858.
//!
//! This is a real-artifact driver, not a test. An external supervisor runs the
//! three modes in order. `crash` is compiled with `crash-fsv`, parks after the
//! WAL and MVCC commit but before checkpoint staging, and is terminated only
//! after its marker is read back. `recover` then proves the tail through the
//! live read path, publishes its durable SST, reopens, and proves history.

use std::fs;
use std::path::{Path, PathBuf};

use calyx_aster::cf::ColumnFamily;
use calyx_aster::vault::{AsterVault, VaultFlushReport, VaultOptions};
use calyx_core::VaultId;
use serde_json::{Value, json};

const SALT: &[u8] = b"astrolabe-issue-858-wal-tail-fsv";
const KEY: &[u8] = b"issue858-wal-key";
const TAIL_KEY: &[u8] = b"issue858-tail-only";
const BEFORE_VALUE: &[u8] = b"baseline-before-crash";
const AFTER_VALUE: &[u8] = b"baseline-after-recovery";
const TAIL_VALUE: &[u8] = b"wal-tail-recovered";

fn main() {
    let mut args = std::env::args_os().skip(1);
    let mode = args
        .next()
        .expect("usage: wal_tail_fsv <seed|crash|recover> ...");
    let root = PathBuf::from(args.next().expect("missing durable vault root"));
    match mode.to_str() {
        Some("seed") => seed(&root, output_path(&mut args)),
        Some("crash") => crash_writer(&root),
        Some("recover") => recover(&root, output_path(&mut args)),
        _ => panic!("mode must be seed, crash, or recover"),
    }
}

fn output_path(args: &mut impl Iterator<Item = std::ffi::OsString>) -> PathBuf {
    PathBuf::from(args.next().expect("missing report output path"))
}

fn seed(root: &Path, output: PathBuf) {
    fs::create_dir_all(root).expect("create WAL-tail vault root");
    assert!(
        fs::read_dir(root)
            .expect("read WAL-tail vault root")
            .next()
            .is_none(),
        "seed requires an empty durable vault root"
    );
    let before = physical_state(root);
    println!("WAL_TAIL_SEED_BEFORE={before}");
    let vault = open_latest(root);
    let seq = vault
        .write_cf(ColumnFamily::Kv, KEY.to_vec(), BEFORE_VALUE.to_vec())
        .expect("commit baseline row");
    assert_eq!(seq, 1);
    let flush = vault.flush_with_report().expect("flush baseline row");
    // The explicit KV row and its mandatory time-index row are both covered.
    require_handoff(&flush, 1, 2, true);
    assert_eq!(
        vault
            .read_cf_at(seq, ColumnFamily::Kv, KEY)
            .expect("read baseline row")
            .expect("baseline row present"),
        BEFORE_VALUE
    );
    let after = physical_state(root);
    println!("WAL_TAIL_SEED_AFTER={after}");
    write_report(
        &output,
        json!({
            "schema": "calyx.issue858.wal-tail-seed.v1",
            "status": "verified",
            "before": before,
            "after": after,
            "seq": seq,
            "flush": flush_json(&flush),
        }),
    );
}

fn crash_writer(root: &Path) {
    let marker = std::env::var_os("CALYX_ASTER_CRASH_FSV_AFTER_MVCC_COMMIT_MARKER")
        .expect("crash mode requires the post-MVCC marker environment variable");
    assert!(!Path::new(&marker).exists(), "crash marker already exists");
    let vault = open_latest(root);
    assert_eq!(vault.latest_seq(), 1);
    assert_eq!(
        vault
            .read_cf_at(1, ColumnFamily::Kv, KEY)
            .expect("read pre-crash baseline")
            .expect("pre-crash baseline present"),
        BEFORE_VALUE
    );
    let _never_returns = vault
        .write_cf_batch(vec![
            (ColumnFamily::Kv, KEY.to_vec(), AFTER_VALUE.to_vec()),
            (ColumnFamily::Kv, TAIL_KEY.to_vec(), TAIL_VALUE.to_vec()),
        ])
        .expect("post-MVCC crash failpoint did not park");
    panic!("post-MVCC crash failpoint returned unexpectedly");
}

fn recover(root: &Path, output: PathBuf) {
    let before_open = physical_state(root);
    println!("WAL_TAIL_RECOVERY_BEFORE={before_open}");
    let vault = open_latest(root);
    assert_eq!(vault.recovery_report().last_recovered_seq, 2);
    assert!(vault.recovery_report().torn_tail.is_none());
    assert_eq!(vault.latest_seq(), 2);
    assert_eq!(
        vault
            .read_cf_at(2, ColumnFamily::Kv, KEY)
            .expect("read replayed update")
            .expect("replayed update present"),
        AFTER_VALUE
    );
    assert_eq!(
        vault
            .read_cf_at(2, ColumnFamily::Kv, TAIL_KEY)
            .expect("read replayed tail")
            .expect("replayed tail present"),
        TAIL_VALUE
    );
    let after_open = physical_state(root);
    println!("WAL_TAIL_RECOVERY_AFTER_OPEN={after_open}");

    let flush = vault
        .flush_with_report()
        .expect("checkpoint and hand off recovered WAL tail");
    // Latest-only recovery overlays the WAL tail in the version table while the
    // staged checkpoint publishes those rows directly as durable SSTs; there is
    // no second router memtable copy to verify or retire on this path.
    require_handoff(&flush, 2, 0, false);
    let after_flush = physical_state(root);
    println!("WAL_TAIL_RECOVERY_AFTER_FLUSH={after_flush}");
    drop(vault);

    let reopened = open(root);
    assert_eq!(reopened.latest_seq(), 2);
    assert_eq!(
        reopened
            .read_cf_at(1, ColumnFamily::Kv, KEY)
            .expect("reopen historical baseline")
            .expect("reopen historical baseline present"),
        BEFORE_VALUE
    );
    assert_eq!(
        reopened
            .read_cf_at(2, ColumnFamily::Kv, KEY)
            .expect("reopen latest update")
            .expect("reopen latest update present"),
        AFTER_VALUE
    );
    assert_eq!(
        reopened
            .read_cf_at(2, ColumnFamily::Kv, TAIL_KEY)
            .expect("reopen tail row")
            .expect("reopen tail row present"),
        TAIL_VALUE
    );
    let terminal = physical_state(root);
    println!("WAL_TAIL_RECOVERY_TERMINAL={terminal}");
    write_report(
        &output,
        json!({
            "schema": "calyx.issue858.wal-tail-recovery.v1",
            "status": "verified",
            "before_open": before_open,
            "after_open": after_open,
            "after_flush": after_flush,
            "terminal": terminal,
            "recovered_seq": 2,
            "historical_value": String::from_utf8_lossy(BEFORE_VALUE),
            "latest_value": String::from_utf8_lossy(AFTER_VALUE),
            "tail_value": String::from_utf8_lossy(TAIL_VALUE),
            "flush": flush_json(&flush),
        }),
    );
}

fn open(root: &Path) -> AsterVault {
    AsterVault::open(
        root,
        vault_id(),
        SALT.to_vec(),
        VaultOptions {
            memtable_byte_cap: 4_096,
            ..VaultOptions::default()
        },
    )
    .expect("open durable WAL-tail vault")
}

fn open_latest(root: &Path) -> AsterVault {
    AsterVault::open(
        root,
        vault_id(),
        SALT.to_vec(),
        VaultOptions {
            memtable_byte_cap: 4_096,
            restore_mvcc_rows: false,
            ..VaultOptions::default()
        },
    )
    .expect("open latest-only durable WAL-tail vault")
}

fn vault_id() -> VaultId {
    "01ARZ3NDEKTSV4RRFFQ69G5F07"
        .parse()
        .expect("valid WAL-tail vault id")
}

fn require_handoff(
    flush: &VaultFlushReport,
    manifest_seq: u64,
    memtable_rows: usize,
    full_inventory: bool,
) {
    assert!(flush.router_ssts.is_empty());
    let handoff = flush
        .router_handoff
        .as_ref()
        .expect("router handoff receipt");
    assert_eq!(handoff.manifest_seq, manifest_seq);
    assert_eq!(handoff.durable_seq, manifest_seq);
    assert_eq!(handoff.memtable_rows_verified, memtable_rows);
    assert_eq!(handoff.full_inventory, full_inventory);
    assert_eq!(handoff.covered_flush_debt_files_after, 0);
    assert_eq!(handoff.covered_flush_debt_bytes_after, 0);
}

fn flush_json(flush: &VaultFlushReport) -> Value {
    let handoff = flush
        .router_handoff
        .as_ref()
        .expect("router handoff receipt");
    json!({
        "durable_sst_files": flush.durable_ssts.len(),
        "durable_sst_entries": flush.sst_entries(),
        "durable_sst_bytes": flush.sst_bytes(),
        "router_sst_files": flush.router_ssts.len(),
        "manifest_seq": handoff.manifest_seq,
        "durable_seq": handoff.durable_seq,
        "full_inventory": handoff.full_inventory,
        "memtable_rows_verified": handoff.memtable_rows_verified,
        "covered_flush_debt_files_after": handoff.covered_flush_debt_files_after,
        "covered_flush_debt_bytes_after": handoff.covered_flush_debt_bytes_after,
    })
}

fn physical_state(root: &Path) -> Value {
    let files = files(root);
    let sst_files = files
        .iter()
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("sst"))
        .count();
    let flush_sst_files = files
        .iter()
        .filter(|path| {
            path.file_name()
                .and_then(|value| value.to_str())
                .is_some_and(|name| name.starts_with("flush-") && name.ends_with(".sst"))
        })
        .count();
    json!({
        "files": files.len(),
        "bytes": files.iter().map(|path| fs::metadata(path).expect("stat state file").len()).sum::<u64>(),
        "sst_files": sst_files,
        "flush_sst_files": flush_sst_files,
        "tree_blake3": tree_hash(root),
        "current": fs::read_to_string(root.join("CURRENT")).ok().map(|value| value.trim().to_string()),
        "router_handoff_present": root.join("ROUTER_HANDOFF").is_file(),
    })
}

fn write_report(path: &Path, report: Value) {
    fs::write(
        path,
        serde_json::to_vec_pretty(&report).expect("encode report"),
    )
    .expect("write report");
    println!("{}", serde_json::to_string(&report).expect("print report"));
    println!("REPORT_PATH={}", path.display());
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
