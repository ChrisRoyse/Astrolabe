use std::env;
use std::error::Error;
use std::path::PathBuf;

use astrolabe_ingest::{SqliteImportOptions, import_sqlite_to_vault};
use astrolabe_lower::{LowerSqliteOptions, lower_cbm_sqlite};
use astrolabe_panel::FixtureSlotRuntime;
use calyx_aster::vault::AsterVault;
use calyx_core::VaultId;
use serde_json::json;

fn main() -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        return Err(format!(
            "usage: {} <cbm.sqlite> <project> <output.sqlite>",
            args.first()
                .map(String::as_str)
                .unwrap_or("lower_cbm_sqlite")
        )
        .into());
    }

    let source = PathBuf::from(&args[1]);
    let project = &args[2];
    let output = PathBuf::from(&args[3]);
    let vault = AsterVault::new(
        "01ARZ3NDEKTSV4RRFFQ69G5FAV".parse::<VaultId>()?,
        format!("astrolabe-lower-example:{project}").into_bytes(),
    );
    let import = import_sqlite_to_vault(
        &source,
        &vault,
        &FixtureSlotRuntime,
        &SqliteImportOptions::new(project, "lower-cbm-sqlite-example", 1),
    )?;
    let lower = lower_cbm_sqlite(&vault, &output, &LowerSqliteOptions::new(project))?;

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema": "astrolabe-lower-example-v1",
            "project": project,
            "source": source,
            "output": output,
            "import": {
                "sqlite_nodes": import.sqlite_nodes,
                "sqlite_edges": import.sqlite_edges,
                "sqlite_fingerprint_sha256": hex_lower(&import.sqlite_fingerprint_sha256),
                "ledger_seq": import.ledger_seq,
            },
            "lower": lower,
        }))?
    );
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
