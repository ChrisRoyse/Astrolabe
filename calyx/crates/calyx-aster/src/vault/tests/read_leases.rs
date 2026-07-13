use super::*;
use std::sync::Arc;

// NOTE (#287 Tranche 1, candidate 6): upstream f8fa97d0's second regression,
// `seq_paged_scan_pins_versions_until_every_page_completes`, exercises the
// seq-parameterized `AsterVault::scan_cf_pages_at` whole-CF streaming API, which
// was introduced by upstream #1350 (`Stream Aster CF scans for Oracle`,
// d7c34d63) — a commit our owned base has NOT adopted (out of Tranche-1 scope).
// Our base carries only the range-paged variants (`scan_cf_range_page_at` /
// `_snapshot`). That test is therefore intentionally NOT ported here; adopting
// #1350 is tracked separately. The lease-scoping conversion candidate 6 makes to
// every seq read our base *does* have (read_cf_at / scan_cf_at /
// scan_cf_range_at / scan_cf_range_keys_at / scan_cf_range_page_at /
// seq_for_key_at) is proven by the no-regression full lib suite plus the
// explicit-lease bound below.

#[derive(Clone, Debug)]
struct MutableClock {
    now: Arc<AtomicU64>,
}

impl MutableClock {
    fn new(ts: u64) -> Self {
        Self {
            now: Arc::new(AtomicU64::new(ts)),
        }
    }

    fn set(&self, ts: u64) {
        self.now.store(ts, Ordering::Release);
    }
}

impl Clock for MutableClock {
    fn now(&self) -> u64 {
        self.now.load(Ordering::Acquire)
    }
}

#[test]
fn pinned_snapshot_cf_reads_honor_explicit_lease_bound() {
    let clock = MutableClock::new(1_000);
    let vault = AsterVault::with_clock(vault_id(), b"salt".to_vec(), clock.clone());
    vault
        .write_cf(ColumnFamily::Base, b"k".to_vec(), b"v".to_vec())
        .expect("write physical Base CF row");
    let snapshot = vault.pin_reader(Freshness::FreshDerived, 60_000);
    let lease_id = snapshot.lease().id();
    let before = vault
        .scan_cf_snapshot(snapshot, ColumnFamily::Base)
        .expect("scan Base CF before clock advance");

    clock.set(6_001);
    let after_old_internal_window = vault
        .read_cf_snapshot(snapshot, ColumnFamily::Base, b"k")
        .expect("explicit 60s snapshot remains live after old 5s window");

    clock.set(snapshot.lease().expires_at());
    let expired = vault
        .read_cf_snapshot(snapshot, ColumnFamily::Base, b"k")
        .expect_err("explicit snapshot expires at its own bound");

    println!(
        "ASTER_PINNED_SNAPSHOT_FSV {}",
        serde_json::json!({
            "source_of_truth": "Aster Base CF rows read through one explicit Snapshot lease",
            "lease_id": lease_id,
            "pinned_seq": snapshot.seq(),
            "issued_at": snapshot.lease().issued_at(),
            "expires_at": snapshot.lease().expires_at(),
            "before_base_rows": before.len(),
            "after_old_internal_window_value": after_old_internal_window.as_deref(),
            "expired_error_code": expired.code,
        })
    );
    assert_eq!(before, vec![(b"k".to_vec(), b"v".to_vec())]);
    assert_eq!(after_old_internal_window, Some(b"v".to_vec()));
    assert_eq!(expired.code, "CALYX_READER_LEASE_EXPIRED");
    assert!(
        !vault.release_reader(lease_id),
        "expired read should abort the registered lease"
    );
}
