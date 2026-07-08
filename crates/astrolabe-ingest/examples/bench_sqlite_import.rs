use std::env;
use std::error::Error;
use std::path::PathBuf;
use std::time::Instant;

use astrolabe_ingest::{SqliteImportOptions, import_sqlite_to_vault};
use astrolabe_panel::FixtureSlotRuntime;
use calyx_aster::vault::{AsterVault, VaultOptions};
use calyx_core::VaultId;
use serde_json::json;

const DEFAULT_VAULT_ID: &str = "00000000000000000000000000";
const DEFAULT_PANEL_VERSION: u32 = 7;
const DEFAULT_TARGET_SECONDS: f64 = 300.0;

fn main() -> Result<(), Box<dyn Error>> {
    let args = env::args().collect::<Vec<_>>();
    if args.len() < 3 {
        eprintln!(
            "usage: {} <cbm.sqlite> <project> [commit] [panel-version]",
            args.first()
                .map(String::as_str)
                .unwrap_or("bench_sqlite_import")
        );
        std::process::exit(2);
    }

    let sqlite_path = PathBuf::from(&args[1]);
    let project = &args[2];
    let commit = args
        .get(3)
        .cloned()
        .unwrap_or_else(|| "lscale-bench".to_string());
    let panel_version = args
        .get(4)
        .map(|value| value.parse::<u32>())
        .transpose()?
        .unwrap_or(DEFAULT_PANEL_VERSION);
    let workers = env::var("ASTROLABE_LSCALE_WORKERS")
        .ok()
        .map(|value| value.parse::<usize>())
        .transpose()?
        .unwrap_or(8);
    let target_seconds = env::var("ASTROLABE_LSCALE_TARGET_SECONDS")
        .ok()
        .map(|value| value.parse::<f64>())
        .transpose()?
        .unwrap_or(DEFAULT_TARGET_SECONDS);

    let vault_id = DEFAULT_VAULT_ID.parse::<VaultId>()?;
    let salt = format!("astrolabe-lscale-bench:{project}").into_bytes();
    let vault = if let Ok(dir) = env::var("ASTROLABE_LSCALE_VAULT_DIR") {
        AsterVault::new_durable(PathBuf::from(dir), vault_id, salt, VaultOptions::default())?
    } else {
        AsterVault::new(vault_id, salt)
    };
    let options = SqliteImportOptions::new(project, commit, panel_version).with_workers(workers);

    let started = Instant::now();
    let report = import_sqlite_to_vault(&sqlite_path, &vault, &FixtureSlotRuntime, &options)?;
    let elapsed = started.elapsed().as_secs_f64();
    let passed = elapsed <= target_seconds;

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema": "astrolabe-ingest-lscale-bench-v1",
            "status": if passed { "passed" } else { "failed" },
            "elapsed_seconds": elapsed,
            "target_seconds": target_seconds,
            "workers": workers,
            "sqlite_nodes": report.sqlite_nodes,
            "sqlite_node_vectors": report.sqlite_node_vectors,
            "sqlite_edges": report.sqlite_edges,
            "constellation_inputs": report.constellation_inputs,
            "structural_only": report.structural_only,
            "new_cx_ids": report.new_cx_ids,
            "reused_cx_ids": report.reused_cx_ids,
            "graph_rows_written": report.graph_rows_written,
            "edge_rows_written": report.edge_rows_written,
            "edge_dangling_skipped": report.edge_skips.dangling,
            "readback_base_rows_verified": report.readback.base_rows_verified,
            "readback_slot_rows_verified": report.readback.slot_rows_verified,
            "readback_graph_rows_verified": report.readback.graph_rows_verified,
            "readback_edge_rows_verified": report.readback.edge_rows_verified,
        }))?
    );

    if passed {
        Ok(())
    } else {
        std::process::exit(1);
    }
}
