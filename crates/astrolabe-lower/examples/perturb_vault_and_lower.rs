//! L2 shadow-parity fault-injection helper (#19).
//!
//! Opens a REAL durable Aster vault (the shadow vault the harness's own
//! `index_repository` runs produced), deliberately perturbs one persisted
//! node-map row's properties through the normal ledger-paired batch path, and
//! re-lowers the perturbed vault to a SQLite artifact. The harness then
//! byte-compares that artifact against the native CBM database and must fail
//! naming the exact qualified name and field this program reports — proving
//! the parity gate bites on genuine vault-state divergence, not only on
//! SQLite-side tampering.

use std::env;
use std::error::Error;
use std::path::PathBuf;

use astrolabe_ingest::inject_node_property_fault;
use astrolabe_lower::{LowerSqliteOptions, lower_cbm_sqlite};
use calyx_aster::vault::{AsterVault, VaultOptions};
use calyx_core::VaultId;
use serde_json::json;

fn main() -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 6 {
        return Err(format!(
            "usage: {} <vault-dir> <vault-id> <vault-salt> <project> <output.sqlite>",
            args.first()
                .map(String::as_str)
                .unwrap_or("perturb_vault_and_lower")
        )
        .into());
    }

    let vault_dir = PathBuf::from(&args[1]);
    let vault_id = args[2].parse::<VaultId>()?;
    let vault_salt = args[3].as_bytes().to_vec();
    let project = &args[4];
    let output = PathBuf::from(&args[5]);

    let vault = AsterVault::open(&vault_dir, vault_id, vault_salt, VaultOptions::default())?;
    let fault = inject_node_property_fault(&vault, project)?;
    vault.flush()?;
    let lower = lower_cbm_sqlite(&vault, &output, &LowerSqliteOptions::new(project))?;

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema": "astrolabe-vault-fault-example-v1",
            "vault_dir": vault_dir,
            "project": project,
            "qualified_name": fault.qualified_name,
            "field": fault.field,
            "properties_json": fault.properties_json,
            "output": output,
            "lowered_artifact_sha256": lower.artifact_sha256,
            "lowered_nodes": lower.node_count,
            "lowered_edges": lower.edge_count,
        }))?
    );
    Ok(())
}
