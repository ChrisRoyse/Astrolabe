use std::cell::{Cell, RefCell};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use astrolabe_bridge::{BridgeError, CbmToolRunner, CbmWatcher, ErrorEnvelope};
use astrolabe_weave::{
    NoveltyVerdict, ReactiveAuditEntry, ReactiveEngine, ReactiveRowKind, ReactiveSignals,
    TriggerCondition, TriggerFired, TriggerId, decode_audit_entry, decode_trigger_fired,
    reactive_row_key,
};
use calyx_aster::cf::ColumnFamily;
use calyx_aster::vault::{AsterVault, VaultOptions};
use calyx_core::{
    CalyxError, CxId, FixedClock, LedgerRef, Result as CalyxResult, SlotId, VaultId, VaultStore,
};

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

#[test]
fn watcher_detects_tracked_file_touch_reindexes_and_feeds_reactive_eval() {
    let project = format!(
        "astrolabe-watch-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    );
    let root = temp_path(&project);
    let vault_dir = temp_path(&format!("{project}-vault"));
    clean_dir(&root);
    clean_dir(&vault_dir);
    init_git_fixture(&root);

    let runner = Rc::new(CbmToolRunner::new(":memory:").expect("create CBM runner"));
    let mut engine = ReactiveEngine::new(Arc::new(FixedClock::new(1_786_400_000)));
    let trigger = engine
        .register(
            TriggerCondition::NewRegion { tau_override: None },
            Some("astrolabe-bridge-watcher".to_string()),
        )
        .expect("register reactive trigger");
    let engine = Rc::new(RefCell::new(engine));
    let vault = Rc::new(open_vault(&vault_dir));
    let next_seq = Rc::new(Cell::new(0_u64));
    let callbacks = Rc::new(RefCell::new(Vec::<(String, String)>::new()));

    let runner_for_callback = Rc::clone(&runner);
    let engine_for_callback = Rc::clone(&engine);
    let vault_for_callback = Rc::clone(&vault);
    let next_seq_for_callback = Rc::clone(&next_seq);
    let callbacks_for_callback = Rc::clone(&callbacks);
    let project_for_callback = project.clone();
    let mut watcher = CbmWatcher::new_for_polling(move |project_name, root_path| {
        callbacks_for_callback
            .borrow_mut()
            .push((project_name.to_string(), root_path.to_string()));

        let index_args = serde_json::json!({
            "repo_path": root_path,
            "mode": "fast",
            "name": project_for_callback,
        })
        .to_string();
        let response = runner_for_callback.handle_tool("index_repository", &index_args)?;
        let status = response
            .value
            .get("structuredContent")
            .and_then(|content| content.get("status"))
            .and_then(serde_json::Value::as_str);
        if !matches!(status, Some("indexed" | "degraded")) {
            return Err(BridgeError::new(
                ErrorEnvelope::new(
                    "ASTRO_TEST_INDEX_STATUS",
                    format!("index_repository returned unexpected status {status:?}"),
                    "Inspect the CBM tool response captured in the test stderr.",
                )
                .with_stderr(response.raw_json),
            ));
        }

        let seq = next_seq_for_callback.get() + 1;
        next_seq_for_callback.set(seq);
        engine_for_callback
            .borrow_mut()
            .evaluate_post_ingest_durable(
                vault_for_callback.as_ref(),
                CxId::from_bytes([42; 16]),
                ledger_ref(seq),
                &NewRegionSignals,
            )
            .map_err(bridge_error_from_calyx)?;
        Ok(())
    })
    .expect("create watcher");

    watcher
        .watch(&project, root.to_str().expect("UTF-8 temp path"))
        .expect("watch temp repo");
    assert_eq!(watcher.watch_count().expect("watch count"), 1);
    assert_eq!(watcher.poll_once().expect("baseline poll"), 0);
    assert!(callbacks.borrow().is_empty());

    fs::write(
        root.join("main.c"),
        "int helper(void) { return 2; }\nint main(void) { return helper(); }\n",
    )
    .expect("modify tracked file");
    watcher.touch(&project).expect("force immediate poll");
    assert_eq!(watcher.poll_once().expect("change poll"), 1);

    assert_eq!(
        callbacks.borrow().as_slice(),
        &[(project.clone(), root.to_string_lossy().to_string())]
    );
    assert_eq!(next_seq.get(), 1);
    assert_reactive_rows(vault.as_ref(), trigger, 1);

    vault.flush().expect("flush reactive watcher vault");
    let _ = runner.handle_tool(
        "delete_project",
        &serde_json::json!({ "project": project }).to_string(),
    );
    drop(watcher);
    drop(vault);

    let reopened = open_vault(&vault_dir);
    assert_reactive_rows(&reopened, trigger, 1);
    drop(reopened);
    let _ = fs::remove_dir_all(root);
    let _ = fs::remove_dir_all(vault_dir);
}

struct NewRegionSignals;

impl ReactiveSignals for NewRegionSignals {
    fn novelty(&self, _cx_id: CxId, _tau_override: Option<f32>) -> CalyxResult<NoveltyVerdict> {
        Ok(NoveltyVerdict::NewRegion)
    }

    fn occurrence_count(&self, _series: CxId) -> CalyxResult<u64> {
        Ok(0)
    }

    fn slot_drift(&self, _slot: SlotId) -> CalyxResult<f32> {
        Ok(0.0)
    }
}

fn bridge_error_from_calyx(err: CalyxError) -> BridgeError {
    BridgeError::new(ErrorEnvelope::new(err.code, err.message, err.remediation))
}

fn assert_reactive_rows(vault: &AsterVault<FixedClock>, trigger: TriggerId, seq: u64) {
    let audits = audit_entries(vault);
    assert_eq!(audits.len(), 1);
    assert_eq!(audits[0].trigger_id, trigger);
    assert!(audits[0].matched);
    assert_eq!(audits[0].ledger_ref.seq, seq);

    let fired = fired_events(vault);
    assert_eq!(fired.len(), 1);
    assert_eq!(fired[0].trigger_id, trigger);
    assert_eq!(fired[0].ledger_ref.seq, seq);
    assert!(matches!(
        fired[0].condition_snapshot,
        TriggerCondition::NewRegion { .. }
    ));
}

fn audit_entries(vault: &AsterVault<FixedClock>) -> Vec<ReactiveAuditEntry> {
    reactive_rows(vault)
        .into_iter()
        .filter_map(|(key, value)| {
            let parts = reactive_row_key(&key).expect("reactive row key");
            (parts.kind == ReactiveRowKind::Audit)
                .then(|| decode_audit_entry(&value).expect("decode audit entry"))
        })
        .collect()
}

fn fired_events(vault: &AsterVault<FixedClock>) -> Vec<TriggerFired> {
    reactive_rows(vault)
        .into_iter()
        .filter_map(|(key, value)| {
            let parts = reactive_row_key(&key).expect("reactive row key");
            (parts.kind == ReactiveRowKind::Fired)
                .then(|| decode_trigger_fired(&value).expect("decode fired event"))
        })
        .collect()
}

fn reactive_rows(vault: &AsterVault<FixedClock>) -> Vec<(Vec<u8>, Vec<u8>)> {
    vault
        .scan_cf_at(vault.snapshot(), ColumnFamily::Reactive)
        .expect("scan reactive CF")
}

fn open_vault(dir: &Path) -> AsterVault<FixedClock> {
    AsterVault::new_durable_with_clock(
        dir,
        vault_id(),
        b"astrolabe-bridge-reactive-watcher".to_vec(),
        VaultOptions::default(),
        FixedClock::new(1_786_400_001),
    )
    .expect("open durable watcher vault")
}

fn vault_id() -> VaultId {
    "01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap()
}

fn ledger_ref(seq: u64) -> LedgerRef {
    LedgerRef {
        seq,
        hash: [seq as u8; 32],
    }
}

fn temp_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(name)
}

fn clean_dir(dir: &Path) {
    let _ = fs::remove_dir_all(dir);
    fs::create_dir_all(dir).expect("create temp dir");
}

fn init_git_fixture(root: &Path) {
    run(Command::new("git")
        .arg("-C")
        .arg(root)
        .arg("init")
        .arg("-q"));
    run(Command::new("git").arg("-C").arg(root).args([
        "config",
        "user.email",
        "astrolabe@example.invalid",
    ]));
    run(Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["config", "user.name", "Astrolabe Test"]));
    run(Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["config", "commit.gpgsign", "false"]));
    fs::write(
        root.join("main.c"),
        "int helper(void) { return 1; }\nint main(void) { return helper(); }\n",
    )
    .expect("write C fixture");
    run(Command::new("git").arg("-C").arg(root).args(["add", "."]));
    run(Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["commit", "-q", "-m", "init"]));
}

fn run(command: &mut Command) {
    let output = command.output().expect("run command");
    assert!(
        output.status.success(),
        "command failed: {:?}\nstdout:\n{}\nstderr:\n{}",
        command,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
