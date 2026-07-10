use std::env;
use std::error::Error;
use std::path::PathBuf;

use astrolabe_ingest::{SqliteImportOptions, import_sqlite_to_vault};
use astrolabe_lower::{LowerSqliteOptions, lower_cbm_sqlite};
use astrolabe_panel::FixtureSlotRuntime;
use calyx_aster::vault::AsterVault;
use calyx_core::VaultId;
use serde_json::{Value, json};

fn main() -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 && args.len() != 5 {
        return Err(format!(
            "usage: {} <cbm.sqlite> <project> <output.sqlite> [determinism-output.sqlite]",
            args.first()
                .map(String::as_str)
                .unwrap_or("lower_cbm_sqlite")
        )
        .into());
    }

    let source = PathBuf::from(&args[1]);
    let project = &args[2];
    let output = PathBuf::from(&args[3]);
    let determinism_output = args.get(4).map(PathBuf::from);
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
    let original_cx_ids = sorted_cx_ids(&import.cx_ids);
    let determinism = match determinism_output {
        Some(path) => {
            let second = lower_cbm_sqlite(&vault, &path, &LowerSqliteOptions::new(project))?;
            let first_bytes = std::fs::read(&output)?;
            let second_bytes = std::fs::read(&path)?;
            let byte_identical = first_bytes == second_bytes;
            let artifact_sha256_matches = lower.artifact_sha256 == second.artifact_sha256;
            if !byte_identical || !artifact_sha256_matches {
                return Err(
                    "lowering the same vault twice did not produce byte-identical artifacts".into(),
                );
            }
            json!({
                "output": path,
                "artifact_sha256": second.artifact_sha256,
                "byte_identical": byte_identical,
                "artifact_sha256_matches": artifact_sha256_matches,
            })
        }
        None => Value::Null,
    };
    let roundtrip_vault = AsterVault::new(
        "01ARZ3NDEKTSV4RRFFQ69G5FAV".parse::<VaultId>()?,
        format!("astrolabe-lower-example-roundtrip:{project}").into_bytes(),
    );
    let roundtrip = import_sqlite_to_vault(
        &output,
        &roundtrip_vault,
        &FixtureSlotRuntime,
        &SqliteImportOptions::new(project, "lower-cbm-sqlite-roundtrip", 1),
    )?;
    let roundtrip_cx_ids = sorted_cx_ids(&roundtrip.cx_ids);
    if original_cx_ids != roundtrip_cx_ids {
        return Err("lowered SQLite roundtrip changed the imported CxId set".into());
    }

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
                "cx_ids": original_cx_ids,
            },
            "lower": lower,
            "determinism": determinism,
            "roundtrip": {
                "sqlite_nodes": roundtrip.sqlite_nodes,
                "sqlite_edges": roundtrip.sqlite_edges,
                "sqlite_fingerprint_sha256": hex_lower(&roundtrip.sqlite_fingerprint_sha256),
                "ledger_seq": roundtrip.ledger_seq,
                "cx_ids": roundtrip_cx_ids,
                "matches_original_cx_ids": true,
            },
        }))?
    );
    Ok(())
}

fn sorted_cx_ids(ids: &[calyx_core::CxId]) -> Vec<String> {
    let mut ids = ids.iter().map(ToString::to_string).collect::<Vec<_>>();
    ids.sort();
    ids
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
