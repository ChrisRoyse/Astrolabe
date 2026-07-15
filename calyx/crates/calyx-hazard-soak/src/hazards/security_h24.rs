use calyx_aster::cf::{ColumnFamily, base_key};
use calyx_core::{
    Anchor, AnchorKind, AnchorValue, Constellation, CxFlags, CxId, InputRef, LedgerRef, Modality,
    SlotId, SlotVector, VaultStore,
};
use calyxd::verify::{VerifyRestoreReport, verify_restore};
use serde::Serialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

use super::resource::ProbeResult;
use super::resource_support::{case_dir, err, open_vault};
use super::security_support::{MEMTABLE_BYTES, START_TS, hash_hex, hex_bytes, vault_id};

const RESTORE_PROGRAM_ENV: &str = "CALYX_PH59_DR_RESTORE_PROGRAM";
const RESTORE_ARGS_ENV: &str = "CALYX_PH59_DR_RESTORE_ARGS_JSON";
const SOURCE_MARKER: &[u8] = b"h24 byte exact";

pub(super) fn probe_h24_whole_host_loss(root: &Path) -> ProbeResult {
    let dir = case_dir(root, "h24_whole_host_loss")?;
    let source_vault = dir.join("source_vault");
    let restored_vault = dir.join("restore_target").join("vault");
    let vault = open_vault(
        &source_vault,
        START_TS + 24,
        b"ph59-h24",
        MEMTABLE_BYTES,
        None,
    )?;
    let cx = h24_constellation();
    let cx_id = cx.cx_id;
    vault.put(cx).map_err(err)?;
    vault.flush().map_err(err)?;
    let source_base = vault
        .read_cf_at(vault.latest_seq(), ColumnFamily::Base, &base_key(cx_id))
        .map_err(err)?
        .unwrap_or_default();
    drop(vault);

    let source_report = verify_restore_json(&source_vault)?;
    let source_files = file_hashes(&source_vault)?;
    let restore_run = match restore_command() {
        Ok(command) => run_restore_command(&command, &source_vault, &restored_vault),
        Err(error) => RestoreRun::not_started(error, env::var_os(RESTORE_PROGRAM_ENV).is_some()),
    };
    let (restored_report, restored_files) = if restore_run.error.is_none() {
        if restored_vault.is_dir() {
            let report = verify_restore_json(&restored_vault)?;
            let files = file_hashes(&restored_vault)?;
            (Some(report), files)
        } else {
            (None, Vec::<FileHash>::new())
        }
    } else {
        (None, Vec::<FileHash>::new())
    };
    let source_success = source_report.success();
    let restored_success = restored_report
        .as_ref()
        .is_some_and(VerifyRestoreReport::success);
    let file_hashes_match = !restored_files.is_empty() && source_files == restored_files;
    let dr_restore_verified = source_success && restored_success && file_hashes_match;
    let passed = source_base_contains_marker(&source_base) && dr_restore_verified;

    Ok((
        passed,
        json!({
            "trigger": "write real durable Aster vault, run explicit DR restore command into an isolated target, then verify restored bytes read-only",
            "expected": {
                "source_base_contains_marker": true,
                "source_verify_restore_success": true,
                "restored_verify_restore_success": true,
                "source_restored_file_hashes_match": true,
                "dr_restore_verified": true
            },
            "actual": {
                "source_base_hex": hex_bytes(&source_base),
                "source_base_contains_marker": source_base_contains_marker(&source_base),
                "restore_program_env": RESTORE_PROGRAM_ENV,
                "restore_args_env": RESTORE_ARGS_ENV,
                "restore_command_configured": restore_run.configured,
                "restore_run": restore_run,
                "source_verify_restore": source_report,
                "restored_verify_restore": restored_report,
                "source_file_count": source_files.len(),
                "restored_file_count": restored_files.len(),
                "source_file_hashes": source_files,
                "restored_file_hashes": restored_files,
                "source_restored_file_hashes_match": file_hashes_match,
                "dr_restore_verified": dr_restore_verified,
                "panic_free": true
            },
            "metrics_text": format!(
                "calyx_dr_restore_verified{{vault=\"ph59-h24\"}} {}\ncalyx_dr_restore_required{{vault=\"ph59-h24\"}} 1\n",
                usize::from(dr_restore_verified)
            )
        }),
    ))
}

fn h24_constellation() -> Constellation {
    Constellation {
        cx_id: CxId::from_bytes([24; 16]),
        vault_id: vault_id(),
        panel_version: 24,
        created_at: START_TS + 24,
        input_ref: InputRef {
            hash: [24; 32],
            pointer: Some("synthetic://ph59/h24/whole-host-loss".to_string()),
            redacted: false,
        },
        modality: Modality::Text,
        slots: BTreeMap::from([(
            SlotId::new(24),
            SlotVector::Dense {
                dim: 4,
                data: vec![24.0, 25.0, 26.0, 27.0],
            },
        )]),
        scalars: BTreeMap::from([("h24_marker_bytes".to_string(), SOURCE_MARKER.len() as f64)]),
        metadata: BTreeMap::from([(
            "dr_marker".to_string(),
            String::from_utf8_lossy(SOURCE_MARKER).to_string(),
        )]),
        anchors: vec![Anchor {
            kind: AnchorKind::TestPass,
            value: AnchorValue::Bool(true),
            source: "ph59-h24-dr-source".to_string(),
            observed_at: START_TS + 24,
            confidence: 1.0,
        }],
        provenance: LedgerRef {
            seq: 0,
            hash: [0; 32],
        },
        flags: CxFlags::default(),
    }
}

#[derive(Debug)]
struct RestoreCommand {
    program: String,
    args: Vec<String>,
}

#[derive(Debug, Serialize)]
struct RestoreRun {
    configured: bool,
    program: Option<String>,
    args: Vec<String>,
    status_code: Option<i32>,
    stdout: String,
    stderr: String,
    error: Option<String>,
}

impl RestoreRun {
    fn not_started(error: String, configured: bool) -> Self {
        Self {
            configured,
            program: None,
            args: Vec::new(),
            status_code: None,
            stdout: String::new(),
            stderr: String::new(),
            error: Some(error),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct FileHash {
    path: String,
    bytes: u64,
    blake3: String,
}

fn restore_command() -> Result<RestoreCommand, String> {
    let program = env::var(RESTORE_PROGRAM_ENV)
        .map_err(|_| format!("{RESTORE_PROGRAM_ENV} is required for H24 DR verification"))?;
    if program.trim().is_empty() {
        return Err(format!("{RESTORE_PROGRAM_ENV} must not be empty"));
    }
    let args = match env::var(RESTORE_ARGS_ENV) {
        Ok(text) => serde_json::from_str::<Vec<String>>(&text)
            .map_err(|error| format!("parse {RESTORE_ARGS_ENV}: {error}"))?,
        Err(env::VarError::NotPresent) => vec!["{source}".to_string(), "{restore}".to_string()],
        Err(error) => return Err(format!("read {RESTORE_ARGS_ENV}: {error}")),
    };
    if args.is_empty() {
        return Err(format!(
            "{RESTORE_ARGS_ENV} must not be an empty argument array"
        ));
    }
    if !args.iter().any(|arg| arg.contains("{source}"))
        || !args.iter().any(|arg| arg.contains("{restore}"))
    {
        return Err(format!(
            "{RESTORE_ARGS_ENV} must include both {{source}} and {{restore}} placeholders"
        ));
    }
    Ok(RestoreCommand { program, args })
}

fn run_restore_command(
    command: &RestoreCommand,
    source_vault: &Path,
    restored_vault: &Path,
) -> RestoreRun {
    if restored_vault.exists() {
        return RestoreRun::not_started(
            format!(
                "restore target {} already exists before DR command",
                restored_vault.display()
            ),
            true,
        );
    }
    let Some(parent) = restored_vault.parent() else {
        return RestoreRun::not_started(
            format!("restore target {} has no parent", restored_vault.display()),
            true,
        );
    };
    if let Err(error) = fs::create_dir_all(parent) {
        return RestoreRun::not_started(format!("create restore parent: {error}"), true);
    }
    let args = command
        .args
        .iter()
        .map(|arg| {
            arg.replace("{source}", &source_vault.display().to_string())
                .replace("{restore}", &restored_vault.display().to_string())
        })
        .collect::<Vec<_>>();
    let output = match Command::new(&command.program).args(&args).output() {
        Ok(output) => output,
        Err(error) => {
            return RestoreRun {
                configured: true,
                program: Some(command.program.clone()),
                args,
                status_code: None,
                stdout: String::new(),
                stderr: String::new(),
                error: Some(format!("launch H24 DR restore command: {error}")),
            };
        }
    };
    let mut run = RestoreRun {
        configured: true,
        program: Some(command.program.clone()),
        args,
        status_code: output.status.code(),
        stdout: bounded_text(&output.stdout),
        stderr: bounded_text(&output.stderr),
        error: (!output.status.success()).then(|| {
            format!(
                "H24 DR restore command exited with status {:?}",
                output.status.code()
            )
        }),
    };
    if run.error.is_none() && !restored_vault.is_dir() {
        run.error = Some(format!(
            "H24 DR restore command did not create restored vault {}",
            restored_vault.display()
        ));
    }
    run
}

fn verify_restore_json(vault: &Path) -> Result<VerifyRestoreReport, String> {
    verify_restore(vault).map_err(err)
}

fn file_hashes(root: &Path) -> Result<Vec<FileHash>, String> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in
            fs::read_dir(&dir).map_err(|error| format!("read dir {}: {error}", dir.display()))?
        {
            let path = entry.map_err(err)?.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let bytes = fs::read(&path)
                    .map_err(|error| format!("read file {}: {error}", path.display()))?;
                files.push(FileHash {
                    path: path
                        .strip_prefix(root)
                        .unwrap_or(&path)
                        .display()
                        .to_string(),
                    bytes: bytes.len() as u64,
                    blake3: hash_hex(&bytes),
                });
            }
        }
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(files)
}

fn source_base_contains_marker(base: &[u8]) -> bool {
    base.windows(SOURCE_MARKER.len())
        .any(|window| window == SOURCE_MARKER)
}

fn bounded_text(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    text.chars().take(4096).collect()
}
