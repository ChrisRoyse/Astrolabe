//! #349 — deterministic reproduction / exoneration of
//! `AsterVault::scan_cf_range_keys_at` on vaults opened with **selected CFs**.
//!
//! The #23 perf session left an in-code note in
//! `astrolabe-ingest/src/sqlite_import.rs` claiming a keys-only range scan
//! "access-violates on vaults opened with selected CFs", and #349 lists the
//! function as *unexonerated*. This test opens a real durable vault read-only
//! with a strict CF subset — exactly `open_shadow_vault_read_only`'s options —
//! over multiple on-disk SST files per CF (the `rayon` `par_iter` multi-file
//! keys path) and asserts `scan_cf_range_keys_at` returns byte-exact keys with
//! no crash. It is the read-side twin of `scan_cf_range_at` (the rows path that
//! was always green), so any divergence would convict the keys path.

use calyx_aster::cf::{ColumnFamily, KeyRange, prefix_range};
use calyx_aster::vault::{AsterVault, VaultOptions};
use calyx_core::{VaultId, VaultStore};

fn temp_root(tag: &str) -> std::path::PathBuf {
    let unique = format!(
        "calyx-issue349-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let dir = std::env::temp_dir().join(unique);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn vault_id() -> VaultId {
    "01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap()
}

const SALT: &[u8] = b"issue349-selected-cf-salt";

/// Base CF key `i` as a fixed-width, lexicographically ordered raw key.
fn base_key(i: u32) -> Vec<u8> {
    let mut key = b"base:".to_vec();
    key.extend_from_slice(&i.to_be_bytes());
    key
}

#[test]
fn scan_cf_range_keys_at_on_selected_cf_vault_reads_back_byte_exact_keys() {
    let root = temp_root("selected-cf-keys");
    let vault_dir = root.join("vault");

    // Write across several CFs so the read-only handle selects a strict subset.
    // Flush TWICE so each CF has multiple on-disk SST files: that is what drives
    // the `SstLevel::range_keys_until` -> `par_iter` multi-file merge, the exact
    // path the note fingered.
    let mut expected_base_keys: Vec<Vec<u8>> = Vec::new();
    {
        let vault = AsterVault::new_durable(
            &vault_dir,
            vault_id(),
            SALT.to_vec(),
            VaultOptions::default(),
        )
        .expect("open writable durable vault");

        for i in 0..64u32 {
            let key = base_key(i);
            vault
                .write_cf(
                    ColumnFamily::Base,
                    key.clone(),
                    format!("v{i}").into_bytes(),
                )
                .expect("write Base row");
            expected_base_keys.push(key);
            // Populate an unrelated large CF that the read handle will NOT select.
            vault
                .write_cf(ColumnFamily::Graph, base_key(i), b"graph".to_vec())
                .expect("write Graph row");
        }
        vault.flush().expect("flush -> first SST generation");

        for i in 64..128u32 {
            let key = base_key(i);
            vault
                .write_cf(
                    ColumnFamily::Base,
                    key.clone(),
                    format!("v{i}").into_bytes(),
                )
                .expect("write Base row (second generation)");
            expected_base_keys.push(key);
        }
        vault.flush().expect("flush -> second SST generation");
    }
    expected_base_keys.sort();

    // Reopen read-only with a strict CF subset — identical to
    // `open_shadow_vault_read_only` (read_only + restore_ledger_hook=false +
    // selected_cfs). Base is selected; Graph is deliberately excluded.
    let options = VaultOptions {
        read_only: true,
        restore_ledger_hook: false,
        selected_cfs: Some(vec![ColumnFamily::Base]),
        ..VaultOptions::default()
    };
    let vault = AsterVault::open(&vault_dir, vault_id(), SALT.to_vec(), options)
        .expect("reopen read-only selected-CF vault");
    let snapshot = vault.snapshot();

    // Full unbounded range.
    let full = KeyRange {
        start: Vec::new(),
        end: None,
    };
    let keys_full = vault
        .scan_cf_range_keys_at(snapshot, ColumnFamily::Base, &full)
        .expect("scan_cf_range_keys_at must not access-violate on a selected-CF vault");

    // Prefix range (the shape `read_cbm_graph_snapshot` would use).
    let prefix = prefix_range(b"base:");
    let keys_prefix = vault
        .scan_cf_range_keys_at(snapshot, ColumnFamily::Base, &prefix)
        .expect("prefix keys scan");

    // The rows-path twin that was always green: its key projection must match.
    let rows_keys = vault
        .scan_cf_range_at(snapshot, ColumnFamily::Base, &full)
        .expect("scan_cf_range_at (rows path)")
        .into_iter()
        .map(|(key, _)| key)
        .collect::<Vec<_>>();

    println!(
        "ASTER_ISSUE349_SELECTED_CF_KEYS_FSV {}",
        serde_json::json!({
            "source_of_truth": "durable Aster Base CF, read-only selected_cfs=[Base], 2 SST generations",
            "expected_base_keys": expected_base_keys.len(),
            "scan_cf_range_keys_at_full": keys_full.len(),
            "scan_cf_range_keys_at_prefix": keys_prefix.len(),
            "scan_cf_range_at_rows_keys": rows_keys.len(),
        })
    );

    assert_eq!(keys_full, expected_base_keys, "full-range keys byte-exact");
    assert_eq!(
        keys_prefix, expected_base_keys,
        "prefix-range keys byte-exact"
    );
    assert_eq!(
        keys_full, rows_keys,
        "keys path agrees with the always-green rows path"
    );

    drop(vault);
    let _ = std::fs::remove_dir_all(&root);
}
