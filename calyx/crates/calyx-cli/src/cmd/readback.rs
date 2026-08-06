use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use calyx_aster::cf::ColumnFamily;
use calyx_aster::sst::SstReader;
use calyx_aster::vault::encode::decode_write_batch;
use calyx_aster::wal::{replay_dir_read_only_after, replay_segment_read_only};
use calyx_core::CalyxError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::cf_read::{hex_bytes, latest_cf_rows_for_keys, list_sst_files};
use crate::error::{CliError, CliResult};
use crate::output::{WriteLineResult, print_hex_dump, print_json, print_line_result};
use crate::readback_vault::ensure_native_aster_vault;
use crate::{ops, vault_tree};

#[derive(Clone, Debug, PartialEq, Eq)]
enum ReadbackCommand {
    Hex(PathBuf),
    VaultTree(PathBuf),
    CfRow {
        vault: PathBuf,
        cf: String,
        key_hex: String,
    },
    CfRows {
        vault: PathBuf,
        cf: String,
        keys_file: PathBuf,
    },
    WalSegment(PathBuf),
    Ledger {
        vault: PathBuf,
        seq: u64,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CfRowsKeysFile {
    schema: String,
    keys_hex: Vec<String>,
}

#[derive(Debug, Serialize)]
struct CfRowsReadback {
    schema: &'static str,
    vault: String,
    cf: String,
    rows: Vec<CfRowsReadbackRow>,
}

#[derive(Debug, Serialize)]
struct CfRowsReadbackRow {
    key_hex: String,
    value_len: usize,
    value_sha256: String,
    value_hex: String,
}

pub(crate) fn try_run(args: &[String]) -> Option<CliResult> {
    if args.first().map(String::as_str) != Some("readback") {
        return None;
    }
    if !owns_form(args) {
        return None;
    }
    Some(parse(args).and_then(run))
}

fn owns_form(args: &[String]) -> bool {
    matches!(
        args.get(1).map(String::as_str),
        Some("--hex" | "--vault-tree" | "--cf-row" | "--cf-rows" | "--ledger")
    ) || matches!(args.get(1).map(String::as_str), Some("--wal")) && args.len() == 3
}

fn parse(args: &[String]) -> CliResult<ReadbackCommand> {
    match args {
        [_, flag, path] if flag == "--hex" => Ok(ReadbackCommand::Hex(path.into())),
        [_, flag, path] if flag == "--vault-tree" => Ok(ReadbackCommand::VaultTree(path.into())),
        [_, flag, path] if flag == "--wal" => Ok(ReadbackCommand::WalSegment(path.into())),
        [_, flag, vault, cf_flag, cf, key_flag, key]
            if flag == "--cf-row" && cf_flag == "--cf" && key_flag == "--key" =>
        {
            Ok(ReadbackCommand::CfRow {
                vault: vault.into(),
                cf: cf.clone(),
                key_hex: key.clone(),
            })
        }
        [_, flag, vault, cf_flag, cf, keys_flag, keys_file]
            if flag == "--cf-rows" && cf_flag == "--cf" && keys_flag == "--keys-file" =>
        {
            Ok(ReadbackCommand::CfRows {
                vault: vault.into(),
                cf: cf.clone(),
                keys_file: keys_file.into(),
            })
        }
        [_, flag, vault, seq_flag, seq] if flag == "--ledger" && seq_flag == "--seq" => {
            Ok(ReadbackCommand::Ledger {
                vault: vault.into(),
                seq: parse_seq(seq)?,
            })
        }
        _ => Err(CliError::usage(
            "usage: calyx readback (--hex <file> | --vault-tree <dir> | --cf-row <vault> --cf <cf-name> --key <hex-key> | --cf-rows <vault> --cf <cf-name> --keys-file <json> | --wal <segment-path> | --ledger <vault> --seq <n>)",
        )),
    }
}

fn run(command: ReadbackCommand) -> CliResult {
    match command {
        ReadbackCommand::Hex(path) => readback_hex(&path),
        ReadbackCommand::VaultTree(path) => vault_tree::readback_vault_tree(&path),
        ReadbackCommand::CfRow { vault, cf, key_hex } => readback_cf_row(&vault, &cf, &key_hex),
        ReadbackCommand::CfRows {
            vault,
            cf,
            keys_file,
        } => readback_cf_rows(&vault, &cf, &keys_file),
        ReadbackCommand::WalSegment(path) => readback_wal_segment(&path),
        ReadbackCommand::Ledger { vault, seq } => readback_ledger(&vault, seq),
    }
}

fn readback_hex(path: &Path) -> CliResult {
    let bytes = fs::read(path)?;
    print_hex_dump(0, &bytes).map(|_| ())
}

fn readback_cf_row(vault: &Path, cf_name: &str, key_hex: &str) -> CliResult {
    ensure_manifested_vault(vault)?;
    let cf = ops::parse_cf(cf_name).map_err(CliError::usage)?;
    let key = parse_hex_bytes(key_hex, "--key")?;
    let value = latest_cf_row(vault, cf, &key)?.ok_or_else(|| {
        CalyxError::aster_corrupt_shard(format!(
            "CF {} row key {} not found",
            cf.name(),
            hex_bytes(&key)
        ))
    })?;
    print_hex_dump(0, &value).map(|_| ())
}

fn readback_cf_rows(vault: &Path, cf_name: &str, keys_file: &Path) -> CliResult {
    ensure_manifested_vault(vault)?;
    let cf = ops::parse_cf(cf_name).map_err(CliError::usage)?;
    let metadata = fs::metadata(keys_file).map_err(|error| {
        CliError::io(format!(
            "read --keys-file metadata {}: {error}",
            keys_file.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(CliError::usage(format!(
            "--keys-file must name a regular file: {}",
            keys_file.display()
        )));
    }
    let input_bytes = fs::read(keys_file).map_err(|error| {
        CliError::io(format!("read --keys-file {}: {error}", keys_file.display()))
    })?;
    let input: CfRowsKeysFile = serde_json::from_slice(&input_bytes).map_err(|error| {
        CliError::usage(format!(
            "decode --keys-file {} as strict JSON: {error}",
            keys_file.display()
        ))
    })?;
    if input.schema != "calyx.cf-read-keys.v1" {
        return Err(CliError::usage(format!(
            "--keys-file schema must be calyx.cf-read-keys.v1, got {:?}",
            input.schema
        )));
    }
    if input.keys_hex.is_empty() {
        return Err(CliError::usage(
            "--keys-file keys_hex must contain at least one key",
        ));
    }
    let mut unique = BTreeSet::new();
    for (index, key_hex) in input.keys_hex.iter().enumerate() {
        let key = parse_hex_bytes(key_hex, &format!("--keys-file keys_hex[{index}]"))?;
        if !unique.insert(key) {
            return Err(CliError::usage(format!(
                "--keys-file contains a duplicate key at keys_hex[{index}]"
            )));
        }
    }
    let keys = unique.into_iter().collect::<Vec<_>>();
    let stored = latest_cf_rows_for_keys(vault, cf, &keys)?;
    let mut rows = Vec::with_capacity(stored.len());
    for (key, value) in stored {
        let value = value.ok_or_else(|| {
            CalyxError::aster_corrupt_shard(format!(
                "CF {} row key {} not found",
                cf.name(),
                hex_bytes(&key)
            ))
        })?;
        rows.push(CfRowsReadbackRow {
            key_hex: hex_bytes(&key),
            value_len: value.len(),
            value_sha256: hex_bytes(&Sha256::digest(&value)),
            value_hex: hex_bytes(&value),
        });
    }
    print_json(&CfRowsReadback {
        schema: "calyx.cf-rows-readback.v1",
        vault: vault.display().to_string(),
        cf: cf.name().to_string(),
        rows,
    })
}

fn readback_ledger(vault: &Path, seq: u64) -> CliResult {
    ensure_manifested_vault(vault)?;
    let key = seq.to_be_bytes();
    let bytes = latest_cf_row(vault, ColumnFamily::Ledger, &key)?.ok_or_else(|| {
        CalyxError::vault_access_denied(format!("ledger seq {seq} does not exist"))
    })?;
    let entry = calyx_ledger::decode(&bytes)?;
    if print_line_result(&format!(
        "LEDGER seq={} prev_hash={} entry_hash={} kind={}",
        entry.seq,
        hex_bytes(&entry.prev_hash),
        hex_bytes(&entry.entry_hash),
        entry.kind
    ))? == WriteLineResult::ClosedPipe
    {
        return Ok(());
    }
    print_hex_dump(0, &bytes).map(|_| ())
}

fn readback_wal_segment(path: &Path) -> CliResult {
    let outcome = replay_segment_read_only(path)?;
    for record in outcome.records {
        if print_line_result(&format!(
            "WAL seq={} logical=1 len={} start={} end={}",
            record.seq,
            record.payload.len(),
            record.start_offset,
            record.end_offset
        ))? == WriteLineResult::ClosedPipe
        {
            return Ok(());
        }
        if print_hex_dump(0, &record.payload)? == WriteLineResult::ClosedPipe {
            return Ok(());
        }
    }
    if let Some(torn) = outcome.torn_tail {
        print_line_result(&format!(
            "TORN_TAIL seq=unknown offset={} code={} message={}",
            torn.offset, torn.code, torn.message
        ))?;
    }
    Ok(())
}

fn latest_cf_row(vault: &Path, cf: ColumnFamily, key: &[u8]) -> CliResult<Option<Vec<u8>>> {
    let mut value = None;
    for file in list_sst_files(&vault.join("cf").join(cf.name()))? {
        let reader = SstReader::open(&file)?;
        if let Some(bytes) = reader.get(key)? {
            value = Some(bytes);
        }
    }
    for record in replay_dir_read_only_after(vault.join("wal"), 0)?.records {
        for row in decode_write_batch(&record.payload)? {
            if row.cf == cf && row.key == key {
                value = Some(row.value);
            }
        }
    }
    Ok(value)
}

fn ensure_manifested_vault(vault: &Path) -> CliResult {
    ensure_native_aster_vault(vault)
}

fn parse_seq(value: &str) -> CliResult<u64> {
    value
        .parse::<u64>()
        .map_err(|error| CliError::usage(format!("invalid --seq {value}: {error}")))
}

fn parse_hex_bytes(value: &str, label: &str) -> CliResult<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return Err(CliError::usage(format!(
            "{label} must contain an even number of hex digits"
        )));
    }
    let mut out = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks(2) {
        let high = hex_value(pair[0])
            .ok_or_else(|| CliError::usage(format!("{label} contains non-hex digit")))?;
        let low = hex_value(pair[1])
            .ok_or_else(|| CliError::usage(format!("{label} contains non-hex digit")))?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
