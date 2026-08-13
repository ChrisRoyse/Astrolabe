use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use calyx_aster::cf::{ColumnFamily, KeyRange};
use calyx_aster::ledger_view::LedgerPointReadTrace;
use calyx_aster::manifest::VaultManifest;
use calyx_aster::sst::SstReader;
use calyx_aster::storage_names::parse_cf_dir_name;
use calyx_aster::vault::encode::decode_write_batch;
use calyx_aster::vault::{AsterVault, VaultOptions};
use calyx_aster::wal::{replay_dir_read_only_after, replay_segment_read_only};
use calyx_core::{CalyxError, VaultId};
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
        historical: Option<HistoricalCfRow>,
    },
    CfRows {
        vault: PathBuf,
        cf: String,
        keys_file: PathBuf,
    },
    MvccCfProbe {
        vault: PathBuf,
        selected_cf: String,
        read_cf: String,
        key_hex: Option<String>,
        seq: u64,
        vault_id: String,
        vault_salt: String,
    },
    MvccAllCfStreams {
        vault: PathBuf,
        seq: AllCfStreamSequence,
        vault_id: String,
        vault_salt: String,
        page_rows: usize,
    },
    WalSegment(PathBuf),
    Ledger {
        vault: PathBuf,
        seq: u64,
    },
    PhysicalLedger {
        vault: PathBuf,
        seqs_file: PathBuf,
        vault_id: String,
        vault_salt: String,
        handle: PhysicalLedgerHandle,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PhysicalLedgerHandle {
    ReadOnly,
    Writable,
    Volatile,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AllCfStreamSequence {
    Latest,
    Exact(u64),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HistoricalCfRow {
    seq: u64,
    vault_id: String,
    vault_salt: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CfRowsKeysFile {
    schema: String,
    keys_hex: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PhysicalLedgerSeqsFile {
    schema: String,
    seqs: Vec<u64>,
}

#[derive(Debug, Serialize)]
struct PhysicalLedgerReadback {
    schema: &'static str,
    source_of_truth: &'static str,
    vault: String,
    handle: &'static str,
    requested_seqs: Vec<u64>,
    resolved_count: usize,
    missing_seqs: Vec<u64>,
    rows: Vec<PhysicalLedgerRowReadback>,
    head: Option<PhysicalLedgerHeadReadback>,
    trace: LedgerPointReadTrace,
}

#[derive(Debug, Serialize)]
struct PhysicalLedgerRowReadback {
    seq: u64,
    value_len: usize,
    value_sha256: String,
    value_hex: String,
    decoded_seq: u64,
    prev_hash: String,
    entry_hash: String,
    kind: String,
}

#[derive(Debug, Serialize)]
struct PhysicalLedgerHeadReadback {
    height: u64,
    tip_hash: String,
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

#[derive(Debug, Serialize)]
struct MvccCfProbeReadback {
    schema: &'static str,
    vault: String,
    selected_cf: String,
    read_cf: String,
    seq: u64,
    operation: &'static str,
    found: Option<bool>,
    row_count: Option<usize>,
    value_len: Option<usize>,
    value_sha256: Option<String>,
    value_hex: Option<String>,
    row_stream_sha256: Option<String>,
}

#[derive(Debug, Serialize)]
struct MvccAllCfStreamsReadback {
    schema: &'static str,
    source_of_truth: &'static str,
    vault: String,
    requested_seq_selector: &'static str,
    requested_seq: u64,
    recovered_latest_seq: u64,
    current_manifest: String,
    manifest_seq: u64,
    manifest_durable_seq: u64,
    manifest_sha256: String,
    page_rows: usize,
    cf_count: usize,
    roster_sha256: String,
    aggregate_sha256: String,
    streams: Vec<MvccCfStreamReadback>,
}

#[derive(Debug, Serialize)]
struct MvccCfStreamReadback {
    cf: String,
    row_count: usize,
    row_stream_sha256: String,
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
        Some(
            "--hex"
                | "--vault-tree"
                | "--cf-row"
                | "--cf-rows"
                | "--mvcc-cf-probe"
                | "--mvcc-all-cf-streams"
                | "--ledger"
                | "--physical-ledger",
        )
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
                historical: None,
            })
        }
        [
            _,
            flag,
            vault,
            cf_flag,
            cf,
            key_flag,
            key,
            seq_flag,
            seq,
            vault_id_flag,
            vault_id,
            vault_salt_flag,
            vault_salt,
        ] if flag == "--cf-row"
            && cf_flag == "--cf"
            && key_flag == "--key"
            && seq_flag == "--seq"
            && vault_id_flag == "--vault-id"
            && vault_salt_flag == "--vault-salt" =>
        {
            Ok(ReadbackCommand::CfRow {
                vault: vault.into(),
                cf: cf.clone(),
                key_hex: key.clone(),
                historical: Some(HistoricalCfRow {
                    seq: parse_seq(seq)?,
                    vault_id: vault_id.clone(),
                    vault_salt: vault_salt.clone(),
                }),
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
        [
            _,
            flag,
            vault,
            selected_flag,
            selected_cf,
            read_flag,
            read_cf,
            seq_flag,
            seq,
            vault_id_flag,
            vault_id,
            vault_salt_flag,
            vault_salt,
        ] if flag == "--mvcc-cf-probe"
            && selected_flag == "--selected-cf"
            && read_flag == "--read-cf"
            && seq_flag == "--seq"
            && vault_id_flag == "--vault-id"
            && vault_salt_flag == "--vault-salt" =>
        {
            Ok(ReadbackCommand::MvccCfProbe {
                vault: vault.into(),
                selected_cf: selected_cf.clone(),
                read_cf: read_cf.clone(),
                key_hex: None,
                seq: parse_seq(seq)?,
                vault_id: vault_id.clone(),
                vault_salt: vault_salt.clone(),
            })
        }
        [
            _,
            flag,
            vault,
            seq_flag,
            seq,
            vault_id_flag,
            vault_id,
            vault_salt_flag,
            vault_salt,
            page_rows_flag,
            page_rows,
        ] if flag == "--mvcc-all-cf-streams"
            && seq_flag == "--seq"
            && vault_id_flag == "--vault-id"
            && vault_salt_flag == "--vault-salt"
            && page_rows_flag == "--page-rows" =>
        {
            Ok(ReadbackCommand::MvccAllCfStreams {
                vault: vault.into(),
                seq: parse_all_cf_stream_sequence(seq)?,
                vault_id: vault_id.clone(),
                vault_salt: vault_salt.clone(),
                page_rows: parse_nonzero_usize(page_rows, "--page-rows")?,
            })
        }
        [
            _,
            flag,
            vault,
            selected_flag,
            selected_cf,
            read_flag,
            read_cf,
            key_flag,
            key,
            seq_flag,
            seq,
            vault_id_flag,
            vault_id,
            vault_salt_flag,
            vault_salt,
        ] if flag == "--mvcc-cf-probe"
            && selected_flag == "--selected-cf"
            && read_flag == "--read-cf"
            && key_flag == "--key"
            && seq_flag == "--seq"
            && vault_id_flag == "--vault-id"
            && vault_salt_flag == "--vault-salt" =>
        {
            Ok(ReadbackCommand::MvccCfProbe {
                vault: vault.into(),
                selected_cf: selected_cf.clone(),
                read_cf: read_cf.clone(),
                key_hex: Some(key.clone()),
                seq: parse_seq(seq)?,
                vault_id: vault_id.clone(),
                vault_salt: vault_salt.clone(),
            })
        }
        [_, flag, vault, seq_flag, seq] if flag == "--ledger" && seq_flag == "--seq" => {
            Ok(ReadbackCommand::Ledger {
                vault: vault.into(),
                seq: parse_seq(seq)?,
            })
        }
        [
            _,
            flag,
            vault,
            seqs_flag,
            seqs_file,
            vault_id_flag,
            vault_id,
            vault_salt_flag,
            vault_salt,
            handle_flag,
            handle,
        ] if flag == "--physical-ledger"
            && seqs_flag == "--seqs-file"
            && vault_id_flag == "--vault-id"
            && vault_salt_flag == "--vault-salt"
            && handle_flag == "--handle" =>
        {
            Ok(ReadbackCommand::PhysicalLedger {
                vault: vault.into(),
                seqs_file: seqs_file.into(),
                vault_id: vault_id.clone(),
                vault_salt: vault_salt.clone(),
                handle: parse_physical_ledger_handle(handle)?,
            })
        }
        _ => Err(CliError::usage(
            "usage: calyx readback (--hex <file> | --vault-tree <dir> | --cf-row <vault> --cf <cf-name> --key <hex-key> [--seq <n> --vault-id <id> --vault-salt <salt>] | --cf-rows <vault> --cf <cf-name> --keys-file <json> | --mvcc-cf-probe <vault> --selected-cf <cf-name> --read-cf <cf-name> [--key <hex-key>] --seq <n> --vault-id <id> --vault-salt <salt> | --mvcc-all-cf-streams <vault> --seq <n> --vault-id <id> --vault-salt <salt> --page-rows <positive-n> | --wal <segment-path> | --ledger <vault> --seq <n> | --physical-ledger <vault> --seqs-file <json> --vault-id <id> --vault-salt <salt> --handle <read-only|writable|volatile>)",
        )),
    }
}

fn run(command: ReadbackCommand) -> CliResult {
    match command {
        ReadbackCommand::Hex(path) => readback_hex(&path),
        ReadbackCommand::VaultTree(path) => vault_tree::readback_vault_tree(&path),
        ReadbackCommand::CfRow {
            vault,
            cf,
            key_hex,
            historical,
        } => readback_cf_row(&vault, &cf, &key_hex, historical.as_ref()),
        ReadbackCommand::CfRows {
            vault,
            cf,
            keys_file,
        } => readback_cf_rows(&vault, &cf, &keys_file),
        ReadbackCommand::MvccCfProbe {
            vault,
            selected_cf,
            read_cf,
            key_hex,
            seq,
            vault_id,
            vault_salt,
        } => mvcc_cf_probe(
            &vault,
            &selected_cf,
            &read_cf,
            key_hex.as_deref(),
            seq,
            &vault_id,
            &vault_salt,
        ),
        ReadbackCommand::MvccAllCfStreams {
            vault,
            seq,
            vault_id,
            vault_salt,
            page_rows,
        } => mvcc_all_cf_streams(&vault, seq, &vault_id, &vault_salt, page_rows),
        ReadbackCommand::WalSegment(path) => readback_wal_segment(&path),
        ReadbackCommand::Ledger { vault, seq } => readback_ledger(&vault, seq),
        ReadbackCommand::PhysicalLedger {
            vault,
            seqs_file,
            vault_id,
            vault_salt,
            handle,
        } => readback_physical_ledger(&vault, &seqs_file, &vault_id, &vault_salt, handle),
    }
}

fn readback_hex(path: &Path) -> CliResult {
    let bytes = fs::read(path)?;
    print_hex_dump(0, &bytes).map(|_| ())
}

fn readback_cf_row(
    vault: &Path,
    cf_name: &str,
    key_hex: &str,
    historical: Option<&HistoricalCfRow>,
) -> CliResult {
    ensure_manifested_vault(vault)?;
    let cf = ops::parse_cf(cf_name).map_err(CliError::usage)?;
    let key = parse_hex_bytes(key_hex, "--key")?;
    let value = match historical {
        Some(historical) => historical_cf_row(vault, cf, &key, historical)?,
        None => latest_cf_row(vault, cf, &key)?,
    }
    .ok_or_else(|| {
        CalyxError::aster_corrupt_shard(format!(
            "CF {} row key {} not found{}",
            cf.name(),
            hex_bytes(&key),
            historical
                .map(|historical| format!(" at MVCC sequence {}", historical.seq))
                .unwrap_or_default(),
        ))
    })?;
    print_hex_dump(0, &value).map(|_| ())
}

fn historical_cf_row(
    vault: &Path,
    cf: ColumnFamily,
    key: &[u8],
    historical: &HistoricalCfRow,
) -> CliResult<Option<Vec<u8>>> {
    let vault_id = historical
        .vault_id
        .parse::<calyx_core::VaultId>()
        .map_err(|error| CliError::usage(format!("invalid --vault-id: {error}")))?;
    let store = AsterVault::open(
        vault,
        vault_id,
        historical.vault_salt.as_bytes().to_vec(),
        VaultOptions {
            restore_mvcc_rows: true,
            restore_ledger_hook: false,
            read_only: true,
            selected_cfs: Some(vec![cf]),
            ..VaultOptions::default()
        },
    )?;
    Ok(store.read_cf_at(historical.seq, cf, key)?)
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

fn mvcc_cf_probe(
    vault: &Path,
    selected_cf_name: &str,
    read_cf_name: &str,
    key_hex: Option<&str>,
    seq: u64,
    vault_id: &str,
    vault_salt: &str,
) -> CliResult {
    ensure_manifested_vault(vault)?;
    let selected_cf = ops::parse_cf(selected_cf_name).map_err(CliError::usage)?;
    let read_cf = ops::parse_cf(read_cf_name).map_err(CliError::usage)?;
    let vault_id = vault_id
        .parse::<calyx_core::VaultId>()
        .map_err(|error| CliError::usage(format!("invalid --vault-id: {error}")))?;
    let store = AsterVault::open(
        vault,
        vault_id,
        vault_salt.as_bytes().to_vec(),
        VaultOptions {
            restore_mvcc_rows: true,
            restore_ledger_hook: false,
            read_only: true,
            selected_cfs: Some(vec![selected_cf]),
            ..VaultOptions::default()
        },
    )?;

    let mut report = MvccCfProbeReadback {
        schema: "calyx.mvcc-cf-probe.v1",
        vault: vault.display().to_string(),
        selected_cf: selected_cf.name().to_string(),
        read_cf: read_cf.name().to_string(),
        seq,
        operation: if key_hex.is_some() { "point" } else { "scan" },
        found: None,
        row_count: None,
        value_len: None,
        value_sha256: None,
        value_hex: None,
        row_stream_sha256: None,
    };

    if let Some(key_hex) = key_hex {
        let key = parse_hex_bytes(key_hex, "--key")?;
        let value = store.read_cf_at(seq, read_cf, &key)?;
        report.found = Some(value.is_some());
        if let Some(value) = value {
            report.value_len = Some(value.len());
            report.value_sha256 = Some(hex_bytes(&Sha256::digest(&value)));
            report.value_hex = Some(hex_bytes(&value));
        }
    } else {
        let rows = store.scan_cf_at(seq, read_cf)?;
        let mut hasher = Sha256::new();
        for (key, value) in &rows {
            hasher.update((key.len() as u64).to_be_bytes());
            hasher.update(key);
            hasher.update((value.len() as u64).to_be_bytes());
            hasher.update(value);
        }
        report.row_count = Some(rows.len());
        report.row_stream_sha256 = Some(hex_bytes(&hasher.finalize()));
    }

    print_json(&report)
}

fn mvcc_all_cf_streams(
    vault: &Path,
    seq_request: AllCfStreamSequence,
    vault_id: &str,
    vault_salt: &str,
    page_rows: usize,
) -> CliResult {
    ensure_manifested_vault(vault)?;
    let roster = physical_cf_roster(vault)?;
    let vault_id = vault_id
        .parse::<VaultId>()
        .map_err(|error| CliError::usage(format!("invalid --vault-id: {error}")))?;
    let selected_cfs = roster.iter().map(|(_, cf)| *cf).collect::<Vec<_>>();
    let store = AsterVault::open(
        vault,
        vault_id,
        vault_salt.as_bytes().to_vec(),
        VaultOptions {
            restore_mvcc_rows: false,
            restore_ledger_hook: false,
            read_only: true,
            selected_cfs: Some(selected_cfs),
            ..VaultOptions::default()
        },
    )?;
    let recovered_latest_seq = store.latest_seq();
    let seq = match seq_request {
        AllCfStreamSequence::Latest => recovered_latest_seq,
        AllCfStreamSequence::Exact(seq) if seq == recovered_latest_seq => seq,
        AllCfStreamSequence::Exact(seq) => {
            return Err(CalyxError {
                code: "CALYX_READBACK_SEQUENCE_NOT_LATEST",
                message: format!(
                    "--mvcc-all-cf-streams requested sequence {seq}, but the one-open latest-only vault recovered sequence {recovered_latest_seq}; no CF was scanned"
                ),
                remediation: "pass `latest`, the vault's exact recovered latest sequence, or use --mvcc-cf-probe for one explicitly historical CF read",
            }
            .into());
        }
    };
    let manifest = read_manifest_receipt(vault)?;

    let roster_sha256 = digest_cf_roster(&roster)?;
    let mut aggregate = Sha256::new();
    update_length_framed(&mut aggregate, b"calyx.mvcc-all-cf-streams.v1")?;
    aggregate.update(seq.to_be_bytes());
    aggregate.update(manifest.sha256);
    aggregate.update(roster_sha256);
    let mut streams = Vec::with_capacity(roster.len());
    let full_key_range = KeyRange {
        start: Vec::new(),
        end: None,
    };
    for (cf_name, cf) in &roster {
        let mut row_stream = Sha256::new();
        let mut row_count = 0usize;
        store.scan_cf_range_pages_at(
            seq,
            *cf,
            &full_key_range,
            page_rows,
            |rows| -> CliResult {
                row_count = row_count.checked_add(rows.len()).ok_or_else(|| {
                    CalyxError::aster_corrupt_shard(format!(
                        "CF {cf_name} row count overflowed during readback"
                    ))
                })?;
                for (key, value) in &rows {
                    update_length_framed(&mut row_stream, key)?;
                    update_length_framed(&mut row_stream, value)?;
                }
                Ok(())
            },
        )?;
        let row_count_u64 = u64::try_from(row_count).map_err(|_| {
            CalyxError::aster_corrupt_shard(format!(
                "CF {cf_name} row count {row_count} does not fit the readback receipt"
            ))
        })?;
        let row_stream_sha256 = row_stream.finalize();
        update_length_framed(&mut aggregate, cf_name.as_bytes())?;
        aggregate.update(row_count_u64.to_be_bytes());
        aggregate.update(&row_stream_sha256);
        streams.push(MvccCfStreamReadback {
            cf: cf_name.clone(),
            row_count,
            row_stream_sha256: hex_bytes(&row_stream_sha256),
        });
    }

    print_json(&MvccAllCfStreamsReadback {
        schema: "calyx.mvcc-all-cf-streams.v1",
        source_of_truth: "one read-only latest-router open over the exact physical cf/ roster; MANIFEST SHA-256 covers the byte-equal mirror/current immutable manifest; roster SHA-256 frames each canonical CF name; each row-stream SHA-256 frames ordered key then value bytes; aggregate SHA-256 frames schema, sequence, raw manifest and roster digests, and each CF name, row count, and raw row-stream digest",
        vault: vault.display().to_string(),
        requested_seq_selector: match seq_request {
            AllCfStreamSequence::Latest => "latest",
            AllCfStreamSequence::Exact(_) => "exact",
        },
        requested_seq: seq,
        recovered_latest_seq,
        current_manifest: manifest.current_name,
        manifest_seq: manifest.manifest_seq,
        manifest_durable_seq: manifest.durable_seq,
        manifest_sha256: hex_bytes(&manifest.sha256),
        page_rows,
        cf_count: streams.len(),
        roster_sha256: hex_bytes(&roster_sha256),
        aggregate_sha256: hex_bytes(&aggregate.finalize()),
        streams,
    })
}

fn parse_all_cf_stream_sequence(value: &str) -> CliResult<AllCfStreamSequence> {
    if value == "latest" {
        Ok(AllCfStreamSequence::Latest)
    } else {
        parse_seq(value).map(AllCfStreamSequence::Exact)
    }
}

struct ManifestReceipt {
    current_name: String,
    manifest_seq: u64,
    durable_seq: u64,
    sha256: [u8; 32],
}

fn read_manifest_receipt(vault: &Path) -> CliResult<ManifestReceipt> {
    let current_path = vault.join("CURRENT");
    let current_bytes = fs::read(&current_path).map_err(|error| {
        CliError::io(format!(
            "read manifest pointer {}: {error}",
            current_path.display()
        ))
    })?;
    let current_name = std::str::from_utf8(&current_bytes)
        .map_err(|error| {
            CalyxError::aster_corrupt_shard(format!(
                "manifest pointer {} is not UTF-8: {error}",
                current_path.display()
            ))
        })?
        .trim()
        .to_string();
    let immutable_path = vault.join(&current_name);
    let immutable_bytes = fs::read(&immutable_path).map_err(|error| {
        CliError::io(format!(
            "read current immutable manifest {}: {error}",
            immutable_path.display()
        ))
    })?;
    let mirror_path = vault.join("MANIFEST");
    let mirror_bytes = fs::read(&mirror_path).map_err(|error| {
        CliError::io(format!(
            "read manifest mirror {}: {error}",
            mirror_path.display()
        ))
    })?;
    if mirror_bytes != immutable_bytes {
        return Err(CalyxError::aster_corrupt_shard(format!(
            "manifest mirror {} differs from current immutable manifest {}",
            mirror_path.display(),
            immutable_path.display()
        ))
        .into());
    }
    let decoded: VaultManifest = serde_json::from_slice(&immutable_bytes).map_err(|error| {
        CalyxError::aster_corrupt_shard(format!(
            "decode current immutable manifest {}: {error}",
            immutable_path.display()
        ))
    })?;
    Ok(ManifestReceipt {
        current_name,
        manifest_seq: decoded.manifest_seq,
        durable_seq: decoded.durable_seq,
        sha256: Sha256::digest(&immutable_bytes).into(),
    })
}

fn physical_cf_roster(vault: &Path) -> CliResult<Vec<(String, ColumnFamily)>> {
    let cf_root = vault.join("cf");
    let metadata = fs::metadata(&cf_root).map_err(|error| {
        CliError::io(format!(
            "stat physical CF root {}: {error}",
            cf_root.display()
        ))
    })?;
    if !metadata.is_dir() {
        return Err(CalyxError::aster_corrupt_shard(format!(
            "physical CF root {} is not a directory",
            cf_root.display()
        ))
        .into());
    }
    let entries = fs::read_dir(&cf_root).map_err(|error| {
        CliError::io(format!(
            "enumerate physical CF root {}: {error}",
            cf_root.display()
        ))
    })?;
    let mut roster = Vec::new();
    let mut seen = BTreeSet::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            CliError::io(format!(
                "read entry from physical CF root {}: {error}",
                cf_root.display()
            ))
        })?;
        let name = entry.file_name().into_string().map_err(|name| {
            CalyxError::aster_corrupt_shard(format!(
                "physical CF root {} contains a non-UTF-8 name {:?}",
                cf_root.display(),
                name
            ))
        })?;
        let file_type = entry.file_type().map_err(|error| {
            CliError::io(format!(
                "read type for physical CF entry {}: {error}",
                entry.path().display()
            ))
        })?;
        if !file_type.is_dir() {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "physical CF entry {} is not a directory",
                entry.path().display()
            ))
            .into());
        }
        let cf = parse_cf_dir_name(&name)?;
        if !seen.insert(cf) {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "physical CF roster contains duplicate declared family {name}"
            ))
            .into());
        }
        roster.push((name, cf));
    }
    if roster.is_empty() {
        return Err(CalyxError::aster_corrupt_shard(format!(
            "physical CF roster {} is empty",
            cf_root.display()
        ))
        .into());
    }
    roster.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    Ok(roster)
}

fn digest_cf_roster(roster: &[(String, ColumnFamily)]) -> CliResult<[u8; 32]> {
    let mut hasher = Sha256::new();
    for (name, _) in roster {
        update_length_framed(&mut hasher, name.as_bytes())?;
    }
    Ok(hasher.finalize().into())
}

fn update_length_framed(hasher: &mut Sha256, bytes: &[u8]) -> CliResult {
    let length = u64::try_from(bytes.len()).map_err(|_| {
        CalyxError::aster_corrupt_shard(format!(
            "readback value length {} does not fit its canonical frame",
            bytes.len()
        ))
    })?;
    hasher.update(length.to_be_bytes());
    hasher.update(bytes);
    Ok(())
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

fn readback_physical_ledger(
    vault: &Path,
    seqs_file: &Path,
    vault_id: &str,
    vault_salt: &str,
    handle: PhysicalLedgerHandle,
) -> CliResult {
    ensure_manifested_vault(vault)?;
    let seqs = read_physical_ledger_seqs_file(seqs_file)?;
    let vault_id = VaultId::from_str(vault_id)
        .map_err(|error| CliError::usage(format!("invalid --vault-id: {error}")))?;

    match handle {
        PhysicalLedgerHandle::ReadOnly => {
            let store = AsterVault::open(
                vault,
                vault_id,
                vault_salt.as_bytes().to_vec(),
                VaultOptions {
                    restore_mvcc_rows: false,
                    restore_ledger_hook: false,
                    read_only: true,
                    selected_cfs: Some(vec![ColumnFamily::Ledger]),
                    ..VaultOptions::default()
                },
            )?;
            let (physical_rows, trace) = store.read_physical_ledger_seqs(&seqs)?;
            let resolved_seqs = physical_rows.keys().copied().collect::<BTreeSet<_>>();
            let head =
                store
                    .retained_read_only_ledger_head()?
                    .map(|head| PhysicalLedgerHeadReadback {
                        height: head.height,
                        tip_hash: hex_bytes(&head.tip_hash),
                    });
            let mut rows = Vec::with_capacity(physical_rows.len());
            for (seq, row) in physical_rows {
                let entry = calyx_ledger::decode(&row.bytes)?;
                if entry.seq != seq || row.seq != seq {
                    return Err(CalyxError::ledger_corrupt(format!(
                        "physical Ledger key seq {seq} decoded as row {} / entry {}",
                        row.seq, entry.seq
                    ))
                    .into());
                }
                rows.push(PhysicalLedgerRowReadback {
                    seq,
                    value_len: row.bytes.len(),
                    value_sha256: hex_bytes(&Sha256::digest(&row.bytes)),
                    value_hex: hex_bytes(&row.bytes),
                    decoded_seq: entry.seq,
                    prev_hash: hex_bytes(&entry.prev_hash),
                    entry_hash: hex_bytes(&entry.entry_hash),
                    kind: entry.kind.to_string(),
                });
            }
            let missing_seqs = seqs
                .iter()
                .filter(|seq| !resolved_seqs.contains(seq))
                .copied()
                .collect::<Vec<_>>();
            print_json(&PhysicalLedgerReadback {
                schema: "calyx.physical-ledger-readback.v1",
                source_of_truth: "retained read-only Aster snapshot over manifest/SST/WAL bytes and ledger_head/current.json",
                vault: vault.display().to_string(),
                handle: "read-only",
                requested_seqs: seqs.iter().copied().collect(),
                resolved_count: rows.len(),
                missing_seqs,
                rows,
                head,
                trace,
            })
        }
        PhysicalLedgerHandle::Writable => {
            let store = AsterVault::open(
                vault,
                vault_id,
                vault_salt.as_bytes().to_vec(),
                VaultOptions::default(),
            )?;
            let _ = store.retained_read_only_ledger_head()?;
            Err(CalyxError {
                code: "CALYX_RETAINED_LEDGER_SNAPSHOT_INVARIANT",
                message: "write-capable handle unexpectedly supplied a retained read-only Ledger snapshot"
                    .to_string(),
                remediation: "preserve the vault and repair the retained-snapshot capability check",
            }
            .into())
        }
        PhysicalLedgerHandle::Volatile => {
            let store = AsterVault::new(vault_id, vault_salt.as_bytes().to_vec());
            let _ = store.retained_read_only_ledger_head()?;
            Err(CalyxError {
                code: "CALYX_RETAINED_LEDGER_SNAPSHOT_INVARIANT",
                message: "volatile handle unexpectedly supplied a retained read-only Ledger snapshot"
                    .to_string(),
                remediation: "preserve the process state and repair the retained-snapshot capability check",
            }
            .into())
        }
    }
}

fn read_physical_ledger_seqs_file(path: &Path) -> CliResult<BTreeSet<u64>> {
    const MAX_SEQS_FILE_BYTES: u64 = 1024 * 1024;
    let metadata = fs::metadata(path).map_err(|error| {
        CliError::io(format!(
            "read --seqs-file metadata {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(CliError::usage(format!(
            "--seqs-file must name a regular file: {}",
            path.display()
        )));
    }
    if metadata.len() > MAX_SEQS_FILE_BYTES {
        return Err(CliError::usage(format!(
            "--seqs-file is {} bytes; maximum is {MAX_SEQS_FILE_BYTES}",
            metadata.len()
        )));
    }
    let bytes = fs::read(path)
        .map_err(|error| CliError::io(format!("read --seqs-file {}: {error}", path.display())))?;
    let input: PhysicalLedgerSeqsFile = serde_json::from_slice(&bytes).map_err(|error| {
        CliError::usage(format!(
            "decode --seqs-file {} as strict JSON: {error}",
            path.display()
        ))
    })?;
    if input.schema != "calyx.physical-ledger-seqs.v1" {
        return Err(CliError::usage(format!(
            "--seqs-file schema must be calyx.physical-ledger-seqs.v1, got {:?}",
            input.schema
        )));
    }
    let seqs = input.seqs.iter().copied().collect::<BTreeSet<_>>();
    if seqs.len() != input.seqs.len() {
        return Err(CliError::usage(
            "--seqs-file contains a duplicate Ledger sequence",
        ));
    }
    Ok(seqs)
}

fn parse_physical_ledger_handle(value: &str) -> CliResult<PhysicalLedgerHandle> {
    match value {
        "read-only" => Ok(PhysicalLedgerHandle::ReadOnly),
        "writable" => Ok(PhysicalLedgerHandle::Writable),
        "volatile" => Ok(PhysicalLedgerHandle::Volatile),
        _ => Err(CliError::usage(format!(
            "invalid --handle {value:?}; expected read-only, writable, or volatile"
        ))),
    }
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

fn parse_nonzero_usize(value: &str, label: &str) -> CliResult<usize> {
    let parsed = value
        .parse::<usize>()
        .map_err(|error| CliError::usage(format!("invalid {label} {value}: {error}")))?;
    if parsed == 0 {
        return Err(CliError::usage(format!("{label} must be positive")));
    }
    Ok(parsed)
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
