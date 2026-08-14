//! Manual Full State Verification for #885's append-only Assay ledger.
//!
//! This executable drives the production `CardLedger` API against a real file.
//! It prints the physical ledger state before and after each action so the
//! caller can independently read and hash the file after the process exits.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use astrolabe_assay::{
    AssayCardAppendRequest, CardLedger, SignalRankingCard,
    error::{ASTRO_ASSAY_INPUT_FINGERPRINT_COLLISION, ASTRO_ASSAY_INPUT_FINGERPRINT_INVALID},
};
use serde_json::json;

type AnyResult<T> = Result<T, Box<dyn Error + Send + Sync + 'static>>;

fn physical_state(path: &Path) -> AnyResult<serde_json::Value> {
    match fs::read(path) {
        Ok(bytes) => Ok(json!({
            "exists": true,
            "bytes": bytes.len(),
            "blake3": blake3::hash(&bytes).to_hex().to_string(),
        })),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(json!({
            "exists": false,
            "bytes": 0,
            "blake3": null,
        })),
        Err(error) => Err(error.into()),
    }
}

fn print_state(case: &str, phase: &str, path: &Path) -> AnyResult<()> {
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case": case,
            "phase": phase,
            "ledger": physical_state(path)?,
        }))?
    );
    Ok(())
}

fn request(fingerprint: String) -> AssayCardAppendRequest {
    AssayCardAppendRequest {
        card: SignalRankingCard {
            axis: "issue_885_known_axis".to_string(),
            signals: Vec::new(),
        },
        seed: 885,
        input_fingerprint: fingerprint,
    }
}

fn expect_code<T>(result: astrolabe_assay::Result<T>, expected: &str) -> AnyResult<String> {
    let error = result
        .err()
        .ok_or_else(|| format!("expected {expected}, but the action succeeded"))?;
    if error.code() != expected {
        return Err(format!("expected {expected}, observed {}: {error}", error.code()).into());
    }
    Ok(error.to_string())
}

fn run(root: PathBuf) -> AnyResult<()> {
    if !root.is_dir() {
        return Err(format!("FSV root must already exist: {}", root.display()).into());
    }
    let path = root.join("signal-cards.ndjson");
    if path.exists() {
        return Err(format!("FSV ledger must begin absent: {}", path.display()).into());
    }
    let ledger = CardLedger::open(&path)?;

    print_state("invalid_fingerprint", "before", &path)?;
    let invalid = expect_code(
        ledger.prepare_batch(&[request("not-a-fingerprint".to_string())]),
        ASTRO_ASSAY_INPUT_FINGERPRINT_INVALID,
    )?;
    print_state("invalid_fingerprint", "after", &path)?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case": "invalid_fingerprint",
            "outcome": "refused",
            "error": invalid,
        }))?
    );
    if path.exists() {
        return Err("invalid fingerprint materialized the ledger path".into());
    }

    let duplicate_request = request("11".repeat(32));
    print_state("duplicate_batch_identity", "before", &path)?;
    let collision = expect_code(
        ledger.prepare_batch(&[duplicate_request.clone(), duplicate_request]),
        ASTRO_ASSAY_INPUT_FINGERPRINT_COLLISION,
    )?;
    print_state("duplicate_batch_identity", "after", &path)?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case": "duplicate_batch_identity",
            "outcome": "refused",
            "error": collision,
        }))?
    );
    if path.exists() {
        return Err("duplicate batch identity materialized the ledger path".into());
    }

    let valid_request = request("22".repeat(32));
    print_state("append_and_readback", "before", &path)?;
    let receipt = ledger
        .prepare_batch(std::slice::from_ref(&valid_request))?
        .publish()?;
    print_state("append_and_readback", "after", &path)?;
    let entries = CardLedger::open(&path)?.read_all()?;
    if entries != receipt.entries || entries.len() != 1 {
        return Err("separate ledger readback did not equal the published entry".into());
    }
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case": "append_and_readback",
            "outcome": "committed",
            "receipt": receipt,
            "readback": entries,
        }))?
    );

    let before_replay = physical_state(&path)?;
    let replay = ledger.prepare_batch(&[valid_request])?.publish()?;
    let after_replay = physical_state(&path)?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case": "idempotent_replay",
            "phase": "before",
            "ledger": before_replay,
        }))?
    );
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case": "idempotent_replay",
            "phase": "after",
            "ledger": after_replay,
            "receipt": replay,
        }))?
    );
    if !replay.idempotent_replay || before_replay != after_replay {
        return Err("idempotent replay changed the physical ledger".into());
    }

    Ok(())
}

fn inspect(root: PathBuf) -> AnyResult<()> {
    let path = root.join("signal-cards.ndjson");
    let entries = CardLedger::open(&path)?.read_all()?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "ledger": physical_state(&path)?,
            "entries": entries,
        }))?
    );
    Ok(())
}

fn main() -> AnyResult<()> {
    let mut args = std::env::args().skip(1);
    let operation = args
        .next()
        .ok_or("usage: issue_885_ledger_fsv <run|inspect> <existing-root>")?;
    let root = PathBuf::from(
        args.next()
            .ok_or("usage: issue_885_ledger_fsv <run|inspect> <existing-root>")?,
    );
    if args.next().is_some() {
        return Err("unexpected extra argument".into());
    }
    match operation.as_str() {
        "run" => run(root),
        "inspect" => inspect(root),
        _ => Err(format!("unknown operation {operation:?}; expected run or inspect").into()),
    }
}
