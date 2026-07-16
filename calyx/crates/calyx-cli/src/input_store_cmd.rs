//! `input-read` / `input-write` CLI verbs for the content-addressed input store
//! (issue #446).
//!
//! `input-read` resolves a stored input either directly by `--hash` or via a
//! constellation's `--cx` (base record -> `input_ref.hash`), then reassembles
//! and verifies the bytes through [`calyx_aster::vault::input_store`], printing
//! the raw bytes (default) or a JSON metadata record (`--meta`).
//!
//! `input-write` commits arbitrary raw bytes from `--file` into the input store
//! as a standalone atomic batch, printing the derived hash and typed pointer.
//! It exercises the real persisted store path for inputs (invalid UTF-8, empty,
//! multi-chunk) that the text-ingest surface cannot express as a `String`.

use std::fs;
use std::io::Write;
use std::path::Path;

use calyx_aster::cf::{ColumnFamily, base_key};
use calyx_aster::vault::encode::decode_constellation_base;
use calyx_aster::vault::input_store::{self, InputManifest};
use calyx_aster::vault::{AsterVault, VaultOptions};
use calyx_core::CxId;

use crate::cmd::vault::{home_dir, vault_salt};
use crate::error::{CliError, CliResult};

/// Opens the named vault (resolved through `CALYX_HOME`) for input-store access.
fn open_named_vault(vault_name: &str) -> CliResult<AsterVault> {
    let home = home_dir()?;
    let resolved = crate::cmd::vault::resolve_vault_info(&home, vault_name)?;
    Ok(AsterVault::open(
        &resolved.path,
        resolved.vault_id,
        vault_salt(resolved.vault_id, &resolved.name),
        VaultOptions::default(),
    )?)
}

fn parse_hash_hex(raw: &str) -> CliResult<[u8; 32]> {
    let raw = raw.trim();
    if raw.len() != 64 {
        return Err(CliError::usage(format!(
            "--hash must be 64 hex chars (32 bytes), got {}",
            raw.len()
        )));
    }
    let mut out = [0_u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&raw[i * 2..i * 2 + 2], 16)
            .map_err(|error| CliError::usage(format!("--hash is not valid hex: {error}")))?;
    }
    Ok(out)
}

fn input_hash_from_cx(vault: &AsterVault, cx_hex: &str) -> CliResult<[u8; 32]> {
    let cx_id = cx_hex
        .parse::<CxId>()
        .map_err(|error| CliError::usage(format!("parse --cx {cx_hex}: {error}")))?;
    let base = vault
        .read_cf_at(vault.snapshot(), ColumnFamily::Base, &base_key(cx_id))?
        .ok_or_else(|| {
            CliError::runtime(format!("cx_id {cx_hex} has no base record in this vault"))
        })?;
    let constellation = decode_constellation_base(&base)?;
    Ok(constellation.input_ref.hash)
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn print_meta(input_hash: &[u8; 32], manifest: &InputManifest, redacted: bool) -> CliResult {
    let json = format!(
        "{{\"input_hash\":\"{}\",\"pointer\":\"{}\",\"total_len\":{},\"chunk_count\":{},\"content_hash\":\"{}\",\"redacted\":{}}}",
        hex(input_hash),
        input_store::input_pointer(input_hash),
        manifest.total_len,
        manifest.chunk_count,
        hex(&manifest.content_hash),
        redacted,
    );
    println!("{json}");
    Ok(())
}

/// `input-read --vault <name> (--cx <hex> | --hash <hex>) [--meta]`.
pub(crate) fn run_input_read(
    vault_name: &str,
    selector_flag: &str,
    selector_value: &str,
    meta: bool,
) -> CliResult {
    let vault = open_named_vault(vault_name)?;
    let input_hash = match selector_flag {
        "--hash" => parse_hash_hex(selector_value)?,
        "--cx" => input_hash_from_cx(&vault, selector_value)?,
        other => {
            return Err(CliError::usage(format!(
                "input-read selector must be --cx or --hash, got {other}"
            )));
        }
    };
    if meta {
        let manifest = input_store::input_manifest(&vault, &input_hash)?.ok_or_else(|| {
            CliError::from(calyx_core::CalyxError {
                code: input_store::CALYX_INPUT_STORE_MISSING,
                message: format!("no input-store manifest for input_hash {}", hex(&input_hash)),
                remediation: "ingest with input_retention=persist, or read a persisted hash",
            })
        })?;
        // Reassemble to prove the stored bytes verify, then report metadata.
        let _bytes = input_store::read_input_bytes(&vault, &input_hash)?;
        return print_meta(&input_hash, &manifest, false);
    }
    let bytes = input_store::read_input_bytes(&vault, &input_hash)?;
    std::io::stdout()
        .write_all(&bytes)
        .map_err(|error| CliError::runtime(format!("write input bytes to stdout: {error}")))?;
    Ok(())
}

/// `input-write --vault <name> --file <path>`: commit raw file bytes into the
/// content-addressed input store and print the derived hash + pointer.
pub(crate) fn run_input_write(vault_name: &str, file: &Path) -> CliResult {
    let bytes = fs::read(file)
        .map_err(|error| CliError::runtime(format!("read {}: {error}", file.display())))?;
    let vault = open_named_vault(vault_name)?;
    let input_hash = *blake3::hash(&bytes).as_bytes();
    let seq = vault.commit_input_bytes(&input_hash, &bytes)?;
    vault.flush()?;
    // Read the persisted bytes straight back and byte-compare before reporting.
    let readback = input_store::read_input_bytes(&vault, &input_hash)?;
    if readback != bytes {
        return Err(CliError::from(calyx_core::CalyxError {
            code: input_store::CALYX_INPUT_STORE_CORRUPT,
            message: "post-write readback of input bytes did not byte-match the source".to_string(),
            remediation: "the input store write path is inconsistent; do not trust this vault",
        }));
    }
    let json = format!(
        "{{\"input_hash\":\"{}\",\"pointer\":\"{}\",\"total_len\":{},\"chunk_count\":{},\"commit_seq\":{}}}",
        hex(&input_hash),
        input_store::input_pointer(&input_hash),
        bytes.len(),
        input_store::chunk_count_for(bytes.len()),
        seq,
    );
    println!("{json}");
    Ok(())
}
