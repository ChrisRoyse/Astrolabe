//! Manual Full State Verification driver for index-time Assay signal-card input identity.
//!
//! This is an executable reality probe, not a test: it writes a durable Aster vault,
//! reopens and independently reads its Slot-CF bytes, produces real Assay cards through
//! the Weave alignment path, persists them in the real card ledger, and records explicit
//! before/action/after state for replay and refusal boundaries.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use astrolabe_assay::CardLedger;
use astrolabe_weave::{SymbolAxes, signal_cards_from_symbol_axes};
use calyx_aster::cf::{ColumnFamily, slot_key};
use calyx_aster::vault::encode::encode_slot_vector;
use calyx_aster::vault::{AsterVault, VaultOptions};
use calyx_core::{CxId, SlotId, SlotVector, VaultId};
use serde_json::{Value, json};

const SEED: u64 = 0x5165_A15C_A5D5_EED1;
const SYMBOL_COUNT: usize = 50;

type AnyResult<T> = Result<T, Box<dyn Error + Send + Sync + 'static>>;

fn bytes_blake3(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn card_state(card: &astrolabe_weave::ProducedSignalCard) -> AnyResult<Value> {
    let card_bytes = serde_json::to_vec(&card.card)?;
    Ok(json!({
        "axis": card.card.axis,
        "input_fingerprint": card.input_fingerprint,
        "input_fingerprint_is_lower_hex_256": card.input_fingerprint.len() == 64
            && card.input_fingerprint.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "card_blake3": bytes_blake3(&card_bytes),
        "card_bytes": card_bytes.len(),
        "signal_count": card.card.signals.len(),
        "signals": card.card.signals,
    }))
}

fn ledger_state(path: &Path, ledger: &CardLedger) -> AnyResult<Value> {
    let raw = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(error.into()),
    };
    let entries = ledger.read_all()?;
    Ok(json!({
        "exists": path.is_file(),
        "bytes": raw.len(),
        "blake3": bytes_blake3(&raw),
        "entries": entries.len(),
        "entry_hashes": entries.iter().map(|entry| entry.entry_hash.clone()).collect::<Vec<_>>(),
        "input_fingerprints": entries.iter().map(|entry| entry.input_fingerprint.clone()).collect::<Vec<_>>(),
    }))
}

fn expect_ledger_error(
    result: astrolabe_assay::Result<astrolabe_assay::AssayCardEntry>,
    expected_code: &str,
) -> AnyResult<Value> {
    match result {
        Ok(entry) => Err(format!(
            "expected {expected_code}, but ledger appended/returned seq {}",
            entry.seq
        )
        .into()),
        Err(error) if error.code() == expected_code => Ok(json!({
            "code": error.code(),
            "message": error.message(),
            "remediation": error.remediation(),
        })),
        Err(error) => Err(format!(
            "expected {expected_code}, observed {}: {}",
            error.code(),
            error
        )
        .into()),
    }
}

fn main() -> AnyResult<()> {
    let payload = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("usage: signal_card_repro_fsv <absent-payload-directory>")?;
    if payload.exists() {
        return Err(format!("payload path already exists: {}", payload.display()).into());
    }
    fs::create_dir_all(&payload)?;

    let vault_dir = payload.join("vault");
    let vault_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV".parse::<VaultId>()?;
    let vault_salt = b"issue-1007-real-fsv-v1".to_vec();
    let slot = SlotId::new(1);
    let mismatch_slot = SlotId::new(2);
    let symbols = (0..SYMBOL_COUNT)
        .map(|index| SymbolAxes {
            cx_id: CxId::from_bytes(((index + 1) as u128).to_be_bytes()),
            kind_class: (index % 2) as i64,
            degree: index as f64,
        })
        .collect::<Vec<_>>();

    let expected_rows = symbols
        .iter()
        .enumerate()
        .map(|(index, symbol)| {
            let vector = SlotVector::Dense {
                dim: 2,
                data: vec![(index % 2) as f32, index as f32],
            };
            Ok((
                ColumnFamily::slot(slot),
                slot_key(symbol.cx_id),
                encode_slot_vector(&vector)?,
            ))
        })
        .collect::<calyx_core::Result<Vec<_>>>()?;

    let vault = AsterVault::new_durable(
        &vault_dir,
        vault_id,
        vault_salt.clone(),
        VaultOptions::default(),
    )?;
    let commit_seq = vault.write_cf_batch(expected_rows.clone())?;
    vault.flush()?;
    drop(vault);

    // Independent source-of-truth read: reopen the durable vault and compare every
    // exact key/value byte before using those rows for measurement.
    let vault = AsterVault::open(&vault_dir, vault_id, vault_salt, VaultOptions::default())?;
    let at_seq = vault.latest_seq();
    if at_seq < commit_seq {
        return Err(format!("reopened vault seq {at_seq} precedes commit {commit_seq}").into());
    }
    let mut physical_preimage = Vec::new();
    let mut rows_read_back = 0usize;
    for (cf, key, expected) in &expected_rows {
        let observed = vault
            .read_cf_at(at_seq, *cf, key)?
            .ok_or_else(|| format!("slot row missing after reopen: {}", bytes_blake3(key)))?;
        if observed != *expected {
            return Err(
                format!("slot row bytes changed after reopen: {}", bytes_blake3(key)).into(),
            );
        }
        physical_preimage.extend_from_slice(&(key.len() as u64).to_be_bytes());
        physical_preimage.extend_from_slice(key);
        physical_preimage.extend_from_slice(&(observed.len() as u64).to_be_bytes());
        physical_preimage.extend_from_slice(&observed);
        rows_read_back += 1;
    }

    let ledger_path = payload.join("signal-cards.ndjson");
    let ledger = CardLedger::open(&ledger_path)?;
    let initial = ledger_state(&ledger_path, &ledger)?;

    let first = signal_cards_from_symbol_axes(&vault, &symbols, &[slot], SEED)?;
    if first.cards.len() != 2 || first.symbols_measured != SYMBOL_COUNT {
        return Err(format!(
            "expected two cards over {SYMBOL_COUNT} symbols, observed cards={} symbols={}",
            first.cards.len(),
            first.symbols_measured
        )
        .into());
    }
    for produced in &first.cards {
        ledger.append(&produced.card, SEED, &produced.input_fingerprint)?;
    }
    let happy_after = ledger_state(&ledger_path, &ledger)?;

    // Exact replay: both produced cards and the physical ledger must be byte-identical.
    let replay_before = fs::read(&ledger_path)?;
    let replay = signal_cards_from_symbol_axes(&vault, &symbols, &[slot], SEED)?;
    if replay != first {
        return Err("byte-identical signal-card inputs produced a different result".into());
    }
    for produced in &replay.cards {
        ledger.append(&produced.card, SEED, &produced.input_fingerprint)?;
    }
    let replay_after = fs::read(&ledger_path)?;
    if replay_after != replay_before {
        return Err("idempotent replay mutated signal-cards.ndjson".into());
    }
    let replay_state = ledger_state(&ledger_path, &ledger)?;

    // Changed source axis: the content identity must change before a new entry is admitted.
    let mut changed_symbols = symbols.clone();
    changed_symbols
        .last_mut()
        .ok_or("missing last symbol")?
        .degree += 7.0;
    let changed_before = ledger_state(&ledger_path, &ledger)?;
    let changed = signal_cards_from_symbol_axes(&vault, &changed_symbols, &[slot], SEED)?;
    if changed.cards.len() != first.cards.len()
        || changed
            .cards
            .iter()
            .zip(&first.cards)
            .any(|(left, right)| left.input_fingerprint == right.input_fingerprint)
    {
        return Err("changed canonical source axes did not change every card fingerprint".into());
    }
    for produced in &changed.cards {
        ledger.append(&produced.card, SEED, &produced.input_fingerprint)?;
    }
    let changed_after = ledger_state(&ledger_path, &ledger)?;

    // Edge 1: same identity plus different payload must return a coded collision and
    // leave the physical ledger byte-identical.
    let collision_before = ledger_state(&ledger_path, &ledger)?;
    let mut conflicting_card = first.cards[0].card.clone();
    conflicting_card.signals[0].interval.lo += 0.125;
    let collision_error = expect_ledger_error(
        ledger.append(&conflicting_card, SEED, &first.cards[0].input_fingerprint),
        "ASTRO_ASSAY_INPUT_FINGERPRINT_COLLISION",
    )?;
    let collision_after = ledger_state(&ledger_path, &ledger)?;
    if collision_before != collision_after {
        return Err("collision refusal mutated the ledger".into());
    }

    // Edge 2: a provenance label is not a content identity.
    let invalid_before = ledger_state(&ledger_path, &ledger)?;
    let invalid_error = expect_ledger_error(
        ledger.append(&first.cards[0].card, SEED, "project:axis:seed"),
        "ASTRO_ASSAY_INPUT_FINGERPRINT_INVALID",
    )?;
    let invalid_after = ledger_state(&ledger_path, &ledger)?;
    if invalid_before != invalid_after {
        return Err("invalid fingerprint refusal mutated the ledger".into());
    }

    // Edge 3: empty inputs are an explicit no-card state and cannot mutate the ledger.
    let empty_before = ledger_state(&ledger_path, &ledger)?;
    let empty = signal_cards_from_symbol_axes(&vault, &[], &[], SEED)?;
    let empty_after = ledger_state(&ledger_path, &ledger)?;
    if !empty.cards.is_empty() || empty.axes_skipped_degenerate != 2 || empty_before != empty_after
    {
        return Err("empty-input boundary was not a mutation-free labeled absence".into());
    }

    // Additional identity edge: duplicate canonical symbols fail before any slot read/write.
    let duplicate_before = ledger_state(&ledger_path, &ledger)?;
    let duplicate_symbols = vec![symbols[0].clone(), symbols[0].clone()];
    let duplicate_error =
        match signal_cards_from_symbol_axes(&vault, &duplicate_symbols, &[slot], SEED) {
            Ok(_) => return Err("duplicate canonical symbols were accepted".into()),
            Err(error) if error.code == "ASTRO_WEAVE_SIGNAL_CARD_INPUT_INVALID" => json!({
                "code": error.code,
                "message": error.message,
                "remediation": error.remediation,
            }),
            Err(error) => return Err(format!("unexpected duplicate-symbol error: {error}").into()),
        };
    let duplicate_after = ledger_state(&ledger_path, &ledger)?;
    if duplicate_before != duplicate_after {
        return Err("duplicate-symbol refusal mutated the ledger".into());
    }

    // Additional shape edge: two individually valid dense rows with different widths
    // must fail closed instead of silently dropping one from the aligned matrix.
    let mismatch_rows = [
        (
            ColumnFamily::slot(mismatch_slot),
            slot_key(symbols[0].cx_id),
            encode_slot_vector(&SlotVector::Dense {
                dim: 1,
                data: vec![0.0],
            })?,
        ),
        (
            ColumnFamily::slot(mismatch_slot),
            slot_key(symbols[1].cx_id),
            encode_slot_vector(&SlotVector::Dense {
                dim: 2,
                data: vec![1.0, 1.0],
            })?,
        ),
    ];
    vault.write_cf_batch(mismatch_rows)?;
    vault.flush()?;
    let mismatch_before = ledger_state(&ledger_path, &ledger)?;
    let mismatch_error =
        match signal_cards_from_symbol_axes(&vault, &symbols, &[mismatch_slot], SEED) {
            Ok(_) => return Err("mixed dense widths were silently accepted".into()),
            Err(error) if error.code == "CALYX_LENS_DIM_MISMATCH" => json!({
                "code": error.code,
                "message": error.message,
                "remediation": error.remediation,
            }),
            Err(error) => return Err(format!("unexpected dense-width error: {error}").into()),
        };
    let mismatch_after = ledger_state(&ledger_path, &ledger)?;
    if mismatch_before != mismatch_after {
        return Err("dense-width refusal mutated the ledger".into());
    }

    let report = json!({
        "schema": "astrolabe.signal-card-reproduce-fsv.v1",
        "rayon_threads": rayon::current_num_threads(),
        "source_of_truth": {
            "vault_dir": vault_dir,
            "slot_cf": format!("S{}", slot.get()),
            "snapshot_seq": at_seq,
            "rows_expected": expected_rows.len(),
            "rows_read_back": rows_read_back,
            "exact_key_value_preimage_blake3": bytes_blake3(&physical_preimage),
            "ledger_path": ledger_path,
        },
        "initial": initial,
        "happy": {
            "after": happy_after,
            "cards": first.cards.iter().map(card_state).collect::<AnyResult<Vec<_>>>()?,
        },
        "exact_replay": {
            "before_blake3": bytes_blake3(&replay_before),
            "after_blake3": bytes_blake3(&replay_after),
            "state": replay_state,
            "production_equal": replay == first,
        },
        "changed_input": {
            "before": changed_before,
            "after": changed_after,
            "cards": changed.cards.iter().map(card_state).collect::<AnyResult<Vec<_>>>()?,
        },
        "edges": {
            "collision": {"before": collision_before, "action": collision_error, "after": collision_after},
            "invalid_fingerprint": {"before": invalid_before, "action": invalid_error, "after": invalid_after},
            "empty_input": {
                "before": empty_before,
                "action": {"cards": empty.cards.len(), "axes_skipped_degenerate": empty.axes_skipped_degenerate},
                "after": empty_after,
            },
            "duplicate_symbol": {"before": duplicate_before, "action": duplicate_error, "after": duplicate_after},
            "dense_width_mismatch": {"before": mismatch_before, "action": mismatch_error, "after": mismatch_after},
        },
        "final_ledger": ledger_state(&ledger_path, &ledger)?,
    });
    let report_bytes = serde_json::to_vec_pretty(&report)?;
    fs::write(payload.join("report.json"), &report_bytes)?;
    let report_readback = fs::read(payload.join("report.json"))?;
    if report_readback != report_bytes {
        return Err("report.json did not read back byte-identically".into());
    }
    println!("{}", String::from_utf8(report_readback)?);
    Ok(())
}
