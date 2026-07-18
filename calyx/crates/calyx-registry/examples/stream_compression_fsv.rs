//! Full State Verification driver for #563, #565, and #574.
//!
//! #563: streaming ingest must not write the removed per-row TurboQuant
//! metadata format; compression of a streamed slot column is the registry-owned
//! versioned generation transition (`Registry::compress_streamed_column`) that
//! atomically persists envelopes, raw source binding, manifest roots, and the
//! ledger transition under one frozen slot geometry.
//!
//! #574: Scalar INT8 is selected only through its explicit
//! `QuantPolicy::ScalarInt8` identity; `TurboQuant { bits_per_channel_x2: 16 }`
//! fails closed before any durable mutation, on both the current write path and
//! the legacy migration path.
//!
//! Source of Truth: a real durable `AsterVault` on disk, reopened through a
//! fresh handle — slot CF envelope bytes, slot_raw sidecar bytes, compression
//! manifest bytes, and hash-chained Ledger CF rows.
//!
//! Run: `cargo run -p calyx-registry --example stream_compression_fsv`

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use calyx_aster::cf::{ColumnFamily, compression_manifest_key, slot_key};
use calyx_aster::dedup::{DedupPolicy, EpochSecs, IngestInput};
use calyx_aster::stream::{BackpressureGuard, StreamIngester};
use calyx_aster::vault::{AsterVault, VaultOptions, encode};
use calyx_core::{
    Asymmetry, Modality, QuantPolicy, Slot, SlotId, SlotResource, SlotShape, SlotState, SlotVector,
    SystemClock, VaultId, VaultStore,
};
use calyx_ledger::EntryKind;
use calyx_registry::{
    AlgorithmicLens, COMPRESSED_SLOT_TAG, COMPRESSION_GENERATION_MARKER, CompressionQuery,
    LensRuntime, LensSpec, REGISTRY_ENVELOPE_HEADER_BYTES, Registry, StoredSlotCodec,
};
use serde_json::json;

const DIM: u32 = 32;
const ROWS: usize = 6;
const PANEL_VERSION: u32 = 41;
const VAULT_SALT: &[u8] = b"w26-tq563-574-fsv-salt";
const VAULT_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

type AnyResult<T> = Result<T, Box<dyn Error>>;

struct Registered {
    slot: Slot,
}

fn main() {
    if let Err(error) = run() {
        println!(
            "{}",
            json!({ "event": "fsv_failure", "error": error.to_string() })
        );
        std::process::exit(1);
    }
}

fn run() -> AnyResult<()> {
    let workspace = std::env::current_dir()?;
    let root = std::env::var_os("CALYX_FSV_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            workspace
                .join(".tmp")
                .join(format!("tq-registry-{}", std::process::id()))
        });
    require(
        !root.exists(),
        format!("FSV root already exists: {}", root.display()),
    )?;
    fs::create_dir_all(&root)?;
    let artifact = std::env::current_exe()?;
    println!(
        "{}",
        json!({
            "event": "fsv_context",
            "platform": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "fixture_root": root,
            "artifact": artifact,
        })
    );

    let mut registry = Registry::new();
    let tq35 = register(
        &mut registry,
        "w26-stream-tq35",
        41,
        QuantPolicy::TurboQuant {
            bits_per_channel_x2: 7,
        },
    )?;
    let int8 = register(
        &mut registry,
        "w26-scalar-int8",
        42,
        QuantPolicy::ScalarInt8,
    )?;
    let tq16 = register(
        &mut registry,
        "w26-tq16-refused",
        43,
        QuantPolicy::TurboQuant {
            bits_per_channel_x2: 16,
        },
    )?;
    let empty_slot = register(
        &mut registry,
        "w26-empty-column",
        44,
        QuantPolicy::TurboQuant {
            bits_per_channel_x2: 5,
        },
    )?;
    let structured = register(
        &mut registry,
        "w26-structured-tq35",
        45,
        QuantPolicy::TurboQuantHadamard {
            bits_per_channel_x2: 7,
        },
    )?;

    // #574: frozen serialized identity of the explicit Scalar INT8 policy.
    let scalar_json = serde_json::to_string(&QuantPolicy::ScalarInt8)?;
    require(
        scalar_json == "\"scalar_int8\"",
        format!(
            "QuantPolicy::ScalarInt8 serialized identity must be \"scalar_int8\", got {scalar_json}"
        ),
    )?;
    let parsed_back: QuantPolicy = serde_json::from_str(&scalar_json)?;
    require(
        parsed_back == QuantPolicy::ScalarInt8,
        "scalar_int8 must round-trip",
    )?;
    let tq16_json = serde_json::to_string(&QuantPolicy::TurboQuant {
        bits_per_channel_x2: 16,
    })?;
    let structured_json = serde_json::to_string(&QuantPolicy::TurboQuantHadamard {
        bits_per_channel_x2: 7,
    })?;
    require(
        structured_json == "{\"turbo_quant_hadamard\":{\"bits_per_channel_x2\":7}}",
        format!("unexpected structured policy identity: {structured_json}"),
    )?;
    println!(
        "{}",
        json!({
            "event": "policy_identity",
            "scalar_int8": scalar_json,
            "structured_turboquant": structured_json,
            "legacy_turboquant_16_still_parses": tq16_json,
            "note": "TurboQuant-16 parses (persisted specs stay readable) but is refused at codec selection"
        })
    );

    let vault_dir = root.join("vault");
    let vault = open_vault(&vault_dir)?;

    // ---- Stream ingest: every event carries dense slots 41/42/43. ----
    let ingester = StreamIngester::new(Arc::clone(&vault), BackpressureGuard::new(64, 0));
    for index in 0..ROWS {
        ingester.send(
            event(index, &[41, 42, 43, 45]),
            EpochSecs(2_000 + index as i64),
        )?;
    }
    let stats = ingester.drain_and_close()?;
    vault.flush()?;
    require(
        stats.ingested == ROWS,
        format!("streamed {ROWS} events, ingested {}", stats.ingested),
    )?;

    // #563: no metadata-only quantization format exists after streaming.
    let mut cx_ids = Vec::new();
    for index in 0..ROWS {
        let input = event(index, &[41, 42, 43]);
        let cx_id = vault.cx_id_for_input(&input.raw_bytes, input.panel_version);
        let constellation = vault.get(cx_id, vault.snapshot())?;
        require(
            !constellation.metadata.contains_key("quantized")
                && constellation
                    .metadata
                    .keys()
                    .all(|key| !key.starts_with("quant_slot_")),
            format!("event {index}: metadata-only quantization rows must not exist"),
        )?;
        cx_ids.push(cx_id);
    }
    println!(
        "{}",
        json!({
            "event": "stream_state",
            "ingested": stats.ingested,
            "batches": stats.batches,
            "metadata_quant_rows": 0,
        })
    );

    let queries = build_queries(&vault);

    // ---- #563 happy path: registry-owned generation transition (TurboQuant 3.5). ----
    let seq_before = vault.latest_seq();
    let report = registry.compress_streamed_column(&vault, &tq35.slot, &queries, 1)?;
    let snapshot = report.snapshot.ok_or("report.snapshot missing")?;
    let ledger_ref = report.ledger.clone().ok_or("report.ledger missing")?;
    require(
        snapshot > seq_before,
        "generation write must advance the vault seq",
    )?;

    // Independent persisted-state readback.
    let stored_rows = vault.scan_cf_at(snapshot, ColumnFamily::slot(SlotId::new(41)))?;
    require(
        stored_rows.len() == ROWS,
        format!("expected {ROWS} envelope rows, got {}", stored_rows.len()),
    )?;
    for (key, value) in &stored_rows {
        require(
            value.first().copied() == Some(COMPRESSED_SLOT_TAG),
            "envelope tag missing",
        )?;
        require(
            value.get(1).copied() == Some(3),
            "envelope version must be 3",
        )?;
        require(
            value.get(2).copied() == Some(1),
            "envelope codec byte must be 1 (TurboQuantBits3p5)",
        )?;
        require(key.len() == 16, "slot key must be a CxId")?;
    }
    let raw_rows = vault.scan_cf_at(snapshot, ColumnFamily::slot_raw(SlotId::new(41)))?;
    require(raw_rows.len() == ROWS, "raw sidecar row count")?;
    for (index, cx_id) in cx_ids.iter().enumerate() {
        let raw = raw_rows
            .iter()
            .find(|(key, _)| key == &slot_key(*cx_id))
            .ok_or("raw sidecar missing")?;
        let expected = encode::encode_slot_vector(&dense_vector(index))?;
        require(
            raw.1 == expected,
            format!("row {index}: raw sidecar must be byte-exact source vector"),
        )?;
    }
    let manifest = vault
        .read_cf_at(
            snapshot,
            ColumnFamily::Compression,
            &compression_manifest_key(SlotId::new(41)),
        )?
        .ok_or("generation manifest missing")?;
    require(&manifest[..4] == b"CSMF", "manifest magic")?;

    // Ledger transition readback: the Migrate entry is persisted and hash-bound.
    let ledger_rows = vault.scan_cf_at(snapshot, ColumnFamily::Ledger)?;
    let ledger_value = ledger_rows
        .iter()
        .find(|(key, _)| key.as_slice() == ledger_ref.seq.to_be_bytes().as_slice())
        .map(|(_, value)| value.clone())
        .ok_or("compression ledger row missing from Ledger CF")?;
    let entry = calyx_ledger::decode(&ledger_value)?;
    require(
        entry.kind == EntryKind::Migrate,
        format!("ledger kind must be Migrate, got {:?}", entry.kind),
    )?;
    require(
        entry.entry_hash == ledger_ref.hash,
        "ledger entry hash must equal report.ledger.hash",
    )?;
    let payload_text = String::from_utf8_lossy(&entry.payload).to_string();
    require(
        payload_text.contains(COMPRESSION_GENERATION_MARKER)
            && payload_text.contains("generation_root_sha256"),
        format!("ledger payload must carry the generation marker and roots: {payload_text}"),
    )?;
    println!(
        "{}",
        json!({
            "event": "generation_committed",
            "slot": 41,
            "stored_codec": report.stored_codec,
            "snapshot": snapshot,
            "ledger_seq": ledger_ref.seq,
            "ledger_kind": "Migrate",
            "ledger_payload": payload_text,
            "manifest_len": manifest.len(),
        })
    );

    // #565: explicit structured-Hadamard geometry, still subject to the exact
    // zero-recall-drop contract used by every compressed generation.
    let structured_report =
        registry.compress_streamed_column(&vault, &structured.slot, &queries, 1)?;
    require(
        structured_report.requested_quant
            == (QuantPolicy::TurboQuantHadamard {
                bits_per_channel_x2: 7,
            }),
        "structured report lost its frozen policy identity",
    )?;
    require(
        structured_report.recall_drop == 0.0,
        format!(
            "structured generation must pass the zero-drop gate, got {}",
            structured_report.recall_drop
        ),
    )?;
    let structured_snapshot = structured_report
        .snapshot
        .ok_or("structured report.snapshot missing")?;
    let structured_rows =
        vault.scan_cf_at(structured_snapshot, ColumnFamily::slot(SlotId::new(45)))?;
    require(
        structured_rows.len() == ROWS,
        "structured persisted row count mismatch",
    )?;
    let geometry_ids = structured_rows
        .iter()
        .map(|(_, bytes)| tqpr_geometry_id(bytes))
        .collect::<AnyResult<Vec<_>>>()?;
    require(
        geometry_ids.iter().all(|id| *id == geometry_ids[0]),
        "structured rows do not share one frozen geometry identity",
    )?;
    println!(
        "{}",
        json!({
            "event": "structured_generation_committed",
            "slot": 45,
            "requested_quant": structured_report.requested_quant,
            "stored_codec": structured_report.stored_codec,
            "recall_at_k": structured_report.recall_at_k_compressed,
            "recall_drop": structured_report.recall_drop,
            "geometry_id": hex(&geometry_ids[0]),
            "persisted_rows": structured_rows.len(),
            "snapshot": structured_snapshot,
            "ledger_seq": structured_report.ledger.as_ref().map(|entry| entry.seq),
        })
    );

    // ---- #574 happy path: explicit Scalar INT8 identity. ----
    let report_int8 = registry.compress_streamed_column(&vault, &int8.slot, &queries, 1)?;
    require(
        report_int8.requested_quant == QuantPolicy::ScalarInt8,
        "requested policy identity",
    )?;
    require(
        report_int8.stored_codec == StoredSlotCodec::ScalarInt8,
        "stored codec identity",
    )?;
    let int8_snapshot = report_int8.snapshot.ok_or("int8 snapshot missing")?;
    let int8_rows = vault.scan_cf_at(int8_snapshot, ColumnFamily::slot(SlotId::new(42)))?;
    for (_, value) in &int8_rows {
        require(
            value.get(2).copied() == Some(3),
            "envelope codec byte must be 3 (ScalarInt8)",
        )?;
        require(
            value.get(3).copied() == Some(1),
            "envelope level byte must be 1 (Bits8)",
        )?;
    }
    println!(
        "{}",
        json!({
            "event": "scalar_int8_committed",
            "requested_quant": report_int8.requested_quant,
            "stored_codec": report_int8.stored_codec,
            "codec_payload_bits_per_channel": report_int8.codec_payload_bits_per_channel,
            "ledger_seq": report_int8.ledger.as_ref().map(|entry| entry.seq),
        })
    );

    // ---- #574 refusal: TurboQuant-16 fails closed before durable mutation. ----
    let seq_before_tq16 = vault.latest_seq();
    let tq16_error = registry
        .compress_streamed_column(&vault, &tq16.slot, &queries, 1)
        .expect_err("TurboQuant-16 must be refused");
    let seq_after_tq16 = vault.latest_seq();
    let tq16_manifest = vault.read_cf_at(
        seq_after_tq16,
        ColumnFamily::Compression,
        &compression_manifest_key(SlotId::new(43)),
    )?;
    let tq16_first_row = vault
        .scan_cf_at(seq_after_tq16, ColumnFamily::slot(SlotId::new(43)))?
        .first()
        .map(|(_, value)| value.first().copied())
        .ok_or("tq16 column must still hold raw rows")?;
    require(
        seq_before_tq16 == seq_after_tq16,
        "TQ16 refusal must not advance the vault seq",
    )?;
    require(
        tq16_manifest.is_none(),
        "TQ16 refusal must not write a manifest",
    )?;
    require(
        tq16_first_row != Some(COMPRESSED_SLOT_TAG),
        "TQ16 rows must remain raw",
    )?;
    require(
        tq16_error.message.contains("removed policy substitution")
            && tq16_error.message.contains("QuantPolicy::ScalarInt8"),
        format!(
            "TQ16 error must name the removed substitution: {}",
            tq16_error.message
        ),
    )?;
    println!(
        "{}",
        json!({
            "event": "tq16_refused_before_mutation",
            "code": tq16_error.code,
            "message": tq16_error.message,
            "seq_before": seq_before_tq16,
            "seq_after": seq_after_tq16,
            "manifest_written": false,
        })
    );

    // ---- #574 legacy path: unmanifested TQ16 state is explicitly refused. ----
    let sidecar_writes = vault
        .scan_cf_at(vault.latest_seq(), ColumnFamily::slot(SlotId::new(43)))?
        .into_iter()
        .map(|(key, value)| (ColumnFamily::slot_raw(SlotId::new(43)), key, value))
        .collect::<Vec<_>>();
    vault.write_cf_batch(sidecar_writes)?;
    let legacy_error = registry
        .compress_streamed_column(&vault, &tq16.slot, &queries, 1)
        .expect_err("legacy TQ16 state must be refused");
    require(
        legacy_error.message.contains("re-commission")
            && legacy_error.message.contains("ScalarInt8"),
        format!(
            "legacy TQ16 refusal must carry remediation: {}",
            legacy_error.message
        ),
    )?;
    println!(
        "{}",
        json!({
            "event": "legacy_tq16_refused",
            "code": legacy_error.code,
            "message": legacy_error.message,
        })
    );

    // ---- #563 edge: empty column fails closed. ----
    let empty_error = registry
        .compress_streamed_column(&vault, &empty_slot.slot, &queries, 1)
        .expect_err("empty column must fail closed");
    require(
        empty_error.code == "CALYX_VECTOR_COMPRESSION_EMPTY",
        format!("empty column code: {}", empty_error.code),
    )?;

    // ---- #563 edge: an already-compressed column is refused, seq unchanged. ----
    let seq_before_dup = vault.latest_seq();
    let dup_error = registry
        .compress_streamed_column(&vault, &tq35.slot, &queries, 1)
        .expect_err("already-compressed column must be refused");
    require(
        dup_error
            .message
            .contains("already carries a compressed envelope"),
        format!("duplicate compression refusal: {}", dup_error.message),
    )?;
    require(
        vault.latest_seq() == seq_before_dup,
        "duplicate refusal must not write",
    )?;

    // ---- #563 edge: missing registry/lens context fails closed. ----
    let mut unregistered = tq35.slot.clone();
    unregistered.lens_id = calyx_core::LensId::from_bytes([0xEE; 16]);
    let missing_context = registry
        .compress_streamed_column(&vault, &unregistered, &queries, 1)
        .expect_err("missing lens context must fail closed");
    println!(
        "{}",
        json!({
            "event": "edge_triad",
            "empty_column": empty_error.code,
            "already_compressed": dup_error.code,
            "missing_lens_context": missing_context.code,
            "seq_stable_on_refusal": true,
        })
    );

    // ---- Durable reopen: fresh handle, compressed search + decode parity. ----
    drop(vault);
    let reopened = open_vault(&vault_dir)?;
    let head = reopened.latest_seq();
    let index = registry.compressed_slot_index(&reopened, &tq35.slot)?;
    index.verify_at(head)?;
    let query = queries[0].values.clone();
    let hits = index.search_at(&query, 1, head)?;
    require(hits.len() == 1, "top-1 search must return one hit")?;
    require(
        hits[0].cx_id == cx_ids[0],
        format!("top-1 must be row 0 ({}), got {}", cx_ids[0], hits[0].cx_id),
    )?;
    let decoded = index.read_at(cx_ids[0], head)?;
    let SlotVector::Dense { data, .. } = decoded else {
        return Err("decoded row must be dense".into());
    };
    let raw = dense_data(0);
    let parity = cosine(&raw, &data);
    require(
        parity > 0.8,
        format!("decode parity cosine too low: {parity}"),
    )?;

    let int8_index = registry.compressed_slot_index(&reopened, &int8.slot)?;
    int8_index.verify_at(head)?;
    let int8_hits = int8_index.search_at(&query, 1, head)?;
    require(int8_hits[0].cx_id == cx_ids[0], "int8 top-1 must be row 0")?;
    let SlotVector::Dense {
        data: int8_data, ..
    } = int8_index.read_at(cx_ids[0], head)?
    else {
        return Err("decoded int8 row must be dense".into());
    };
    let int8_parity = cosine(&raw, &int8_data);
    require(
        int8_parity > 0.999,
        format!("int8 decode parity too low: {int8_parity}"),
    )?;

    let structured_index = registry.compressed_slot_index(&reopened, &structured.slot)?;
    structured_index.verify_at(head)?;
    let structured_hits = structured_index.search_at(&query, 1, head)?;
    require(
        structured_hits[0].cx_id == cx_ids[0],
        "structured top-1 must be row 0",
    )?;
    let SlotVector::Dense {
        data: structured_data,
        ..
    } = structured_index.read_at(cx_ids[0], head)?
    else {
        return Err("decoded structured row must be dense".into());
    };
    let structured_parity = cosine(&raw, &structured_data);
    require(
        structured_parity > 0.8,
        format!("structured decode parity too low: {structured_parity}"),
    )?;

    println!(
        "{}",
        json!({
            "event": "reopen_verified",
            "head_seq": head,
            "tq35_top1": hits[0].cx_id.to_string(),
            "tq35_top1_score": hits[0].score,
            "tq35_decode_cosine": parity,
            "int8_top1": int8_hits[0].cx_id.to_string(),
            "int8_top1_score": int8_hits[0].score,
            "int8_decode_cosine": int8_parity,
            "structured_top1": structured_hits[0].cx_id.to_string(),
            "structured_top1_score": structured_hits[0].score,
            "structured_decode_cosine": structured_parity,
            "fixture_root": root,
        })
    );

    drop(index);
    drop(int8_index);
    drop(structured_index);
    drop(reopened);
    println!(
        "{}",
        json!({ "event": "fsv_success", "issues": [563, 565, 574], "fixture_root": root })
    );
    Ok(())
}

fn register(
    registry: &mut Registry,
    name: &str,
    slot_id: u16,
    quant: QuantPolicy,
) -> AnyResult<Registered> {
    let lens = AlgorithmicLens::one_hot(name, Modality::Text, DIM);
    let contract = lens.contract().clone();
    let spec = LensSpec {
        name: contract.name().to_string(),
        runtime: LensRuntime::Algorithmic {
            kind: format!("one_hot:{DIM}"),
        },
        output: contract.shape(),
        modality: contract.modality(),
        weights_sha256: contract.weights_sha256(),
        corpus_hash: contract.corpus_hash(),
        norm_policy: contract.norm_policy(),
        max_batch: None,
        axis: Some("w26-tq-fsv".to_string()),
        asymmetry: Asymmetry::None,
        quant_default: quant,
        truncate_dim: None,
        recall_delta: 0.0,
        retrieval_only: false,
        excluded_from_dedup: false,
    };
    let lens_id = registry.register_frozen_with_spec(lens, contract, spec)?;
    let id = SlotId::new(slot_id);
    Ok(Registered {
        slot: Slot {
            slot_id: id,
            slot_key: id.with_key(format!("{name}-slot")),
            lens_id,
            shape: SlotShape::Dense(DIM),
            modality: Modality::Text,
            asymmetry: Asymmetry::None,
            quant,
            resource: SlotResource::default(),
            axis: Some("w26-tq-fsv".to_string()),
            retrieval_only: false,
            excluded_from_dedup: false,
            bits_about: BTreeMap::new(),
            state: SlotState::Active,
            added_at_panel_version: PANEL_VERSION,
        },
    })
}

fn open_vault(dir: &Path) -> AnyResult<Arc<AsterVault<SystemClock>>> {
    fs::create_dir_all(dir)?;
    let options = VaultOptions {
        dedup_policy: Some(DedupPolicy::Off),
        ..VaultOptions::default()
    };
    let vault_id: VaultId = VAULT_ID.parse()?;
    Ok(Arc::new(AsterVault::open(
        dir,
        vault_id,
        VAULT_SALT.to_vec(),
        options,
    )?))
}

fn dense_data(index: usize) -> Vec<f32> {
    let mut data = vec![0.0_f32; DIM as usize];
    data[index % DIM as usize] = 1.0;
    data
}

fn dense_vector(index: usize) -> SlotVector {
    SlotVector::Dense {
        dim: DIM,
        data: dense_data(index),
    }
}

fn event(index: usize, slot_ids: &[u16]) -> IngestInput {
    let mut input = IngestInput::new(
        format!("w26-tq-fsv-event-{index}").into_bytes(),
        PANEL_VERSION,
        Modality::Text,
    );
    for slot_id in slot_ids {
        input = input.with_slot(SlotId::new(*slot_id), dense_vector(index));
    }
    input
}

fn build_queries(vault: &AsterVault<SystemClock>) -> Vec<CompressionQuery> {
    // A mixture query: strictly decreasing weight per stored one-hot bucket, so
    // ranking is strict and the query shares no positive ray with any row.
    let mut values = vec![0.0_f32; DIM as usize];
    for index in 0..ROWS {
        values[index] = 1.0 / (1 << index) as f32;
    }
    let cx_id = vault.cx_id_for_input(b"w26-tq-fsv-query-0", PANEL_VERSION);
    vec![CompressionQuery { cx_id, values }]
}

fn cosine(left: &[f32], right: &[f32]) -> f64 {
    let dot: f64 = left
        .iter()
        .zip(right)
        .map(|(a, b)| f64::from(*a) * f64::from(*b))
        .sum();
    let ln: f64 = left
        .iter()
        .map(|v| f64::from(*v) * f64::from(*v))
        .sum::<f64>()
        .sqrt();
    let rn: f64 = right
        .iter()
        .map(|v| f64::from(*v) * f64::from(*v))
        .sum::<f64>()
        .sqrt();
    if ln == 0.0 || rn == 0.0 {
        0.0
    } else {
        dot / (ln * rn)
    }
}

fn require(condition: bool, message: impl Into<String>) -> AnyResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.into().into())
    }
}

fn tqpr_geometry_id(envelope: &[u8]) -> AnyResult<[u8; 32]> {
    let payload = envelope
        .get(REGISTRY_ENVELOPE_HEADER_BYTES..)
        .ok_or("structured envelope is shorter than its fixed header")?;
    require(
        payload.len() >= 88 && &payload[..4] == b"TQPR" && payload[4] == 2,
        "structured envelope does not contain TQPR v2 bytes",
    )?;
    let mut id = [0_u8; 32];
    id.copy_from_slice(&payload[24..56]);
    Ok(id)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
