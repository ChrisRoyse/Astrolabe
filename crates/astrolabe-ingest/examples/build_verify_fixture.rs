use std::env;
use std::error::Error;

use calyx_aster::cf::ColumnFamily;
use calyx_aster::vault::{AsterVault, VaultOptions};
use calyx_core::VaultId;
use calyx_ledger::{ActorId, EntryKind, SubjectId};

fn main() -> Result<(), Box<dyn Error>> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 3 {
        return Err("usage: build_verify_fixture <vault-dir> <vault-id> <vault-salt>".into());
    }
    let vault = AsterVault::new_durable(
        &args[0],
        args[1].parse::<VaultId>()?,
        args[2].as_bytes().to_vec(),
        VaultOptions::default(),
    )?;
    vault.write_cf_batch_with_ledger_entry(
        [(
            ColumnFamily::Kv,
            b"astrolabe:verify-fixture:v1".to_vec(),
            b"verified".to_vec(),
        )],
        EntryKind::Ingest,
        SubjectId::Query(b"astrolabe-verify-chain-fixture".to_vec()),
        br#"{"schema":"astrolabe-verify-fixture-v1","input_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#.to_vec(),
        ActorId::Service("astrolabe-ci".to_string()),
    )?;
    vault.flush()?;
    println!("vault={} seq={}", args[0], vault.latest_seq());
    Ok(())
}
