use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use calyx_assay::{
    AssayCacheKey, AssayStore, AssaySubject, ksg_mi_continuous_discrete_with_anchor,
};
use calyx_aster::cf::{ColumnFamily, compression_manifest_key};
use calyx_aster::vault::{AsterVault, VaultOptions, encode};
use calyx_core::{
    Anchor, AnchorKind, AnchorValue, Asymmetry, Constellation, CxFlags, CxId, FixedClock, Input,
    InputRef, LedgerRef, Lens, LensId, Modality, QuantPolicy, Result as CalyxResult, Slot, SlotId,
    SlotResource, SlotShape, SlotState, SlotVector, VaultId, VaultStore,
};
use calyx_forge::{
    AssayQuantSafety, MXFP_FORMAT_HEADER_BYTES, MxFp4Codec, QuantLevel, QuantizedVec, Quantizer,
    decode_mxfp4, encode_mxfp4,
};
use calyx_registry::frozen::{FrozenLensContract, LensDType, NormPolicy, sha256_digest};
use calyx_registry::{
    CompressionQuery, LensRuntime, LensSpec, REGISTRY_ENVELOPE_HEADER_BYTES, Registry,
    StoredSlotCodec, inspect_unbound_stored_slot_envelope, load_mxfp4_assay_evidence,
    persist_mxfp4_assay_evidence,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const FIXED_TS: u64 = 1_784_164_800_000;
const PANEL_VERSION: u32 = 1;
const DIM: usize = 64;
const ROWS: usize = 64;
const SLOT_ID: u16 = 52;
const VAULT_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAW";
const VAULT_SALT: &[u8] = b"issue-552-ocp-mx-registry-fsv-v1";

type AnyResult<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Debug)]
struct FsvFailure {
    message: String,
}

impl fmt::Display for FsvFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "ASTRO_FSV_INVARIANT_FAILED: {}; remediation: inspect the emitted vault CF/file state and repair the first violated invariant",
            self.message
        )
    }
}

impl Error for FsvFailure {}

#[derive(Clone)]
struct KnownPatternLens {
    id: LensId,
}

impl KnownPatternLens {
    fn contract() -> FrozenLensContract {
        FrozenLensContract::new(
            "issue552-known-ocp-pattern-v1",
            sha256_digest(&[b"issue552-known-ocp-pattern-implementation-v1"]),
            sha256_digest(&[b"manual-fsv-known-ordinal-corpus-0-through-63"]),
            SlotShape::Dense(DIM as u32),
            Modality::Structured,
            LensDType::F32,
            NormPolicy::Finite,
        )
    }

    fn new() -> Self {
        Self {
            id: Self::contract().lens_id(),
        }
    }
}

impl Lens for KnownPatternLens {
    fn id(&self) -> LensId {
        self.id
    }

    fn shape(&self) -> SlotShape {
        SlotShape::Dense(DIM as u32)
    }

    fn modality(&self) -> Modality {
        Modality::Structured
    }

    fn measure(&self, input: &Input) -> CalyxResult<SlotVector> {
        if input.modality != Modality::Structured || input.bytes.len() != 1 || input.bytes[0] >= 64
        {
            return Err(calyx_core::CalyxError::lens_dim_mismatch(
                "issue552 known-pattern lens requires one structured ordinal byte in 0..64",
            ));
        }
        let ordinal = input.bytes[0] as usize;
        let mut data = vec![0.0_f32; DIM];
        data[0] = if ordinal < 32 { -1.0 } else { 1.0 };
        data[32] = 2.0_f32.powi(-((ordinal % 32) as i32 + 1));
        Ok(SlotVector::Dense {
            dim: DIM as u32,
            data,
        })
    }
}

struct Fixture {
    registry: Registry,
    slot: Slot,
    lens_id: LensId,
    rows: Vec<(CxId, Vec<f32>)>,
    labels: Vec<usize>,
    anchor: Anchor,
    query: CompressionQuery,
}

fn main() {
    if let Err(error) = run() {
        println!(
            "{}",
            json!({
                "event": "mxfp_registry_fsv_failure",
                "error": error.to_string(),
            })
        );
        std::process::exit(1);
    }
}

fn run() -> AnyResult<()> {
    let root = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or_else(|| failure("usage: mxfp_registry_fsv <output-directory>"))?;
    if root.exists() {
        fs::remove_dir_all(&root)?;
    }
    fs::create_dir_all(&root)?;
    let vault_dir = root.join("vault");
    let mut fixture = register_fixture()?;
    let vault = open_writer(&vault_dir)?;
    populate_source(&vault, &mut fixture)?;

    let source_state = logical_state(&vault, &fixture.slot)?;
    let no_evidence_error = fixture
        .registry
        .write_compressed_slot_batch(
            &vault,
            &fixture.slot,
            &fixture.rows,
            std::slice::from_ref(&fixture.query),
            1,
        )
        .unwrap_err();
    let no_evidence_after = logical_state(&vault, &fixture.slot)?;
    require(
        source_state == no_evidence_after,
        "missing-evidence attempt mutated the vault",
    )?;

    let (estimate, safety, quantized_rows) = measured_assay(&fixture)?;
    let cache_key = AssayCacheKey::scoped(
        PANEL_VERSION,
        "issue552-known-pattern-corpus-v1",
        vault.vault_id(),
        AnchorKind::TestPass,
    );
    let first_assay_seq = persist_mxfp4_assay_evidence(
        &vault,
        &fixture.slot,
        fixture
            .registry
            .lens_spec(fixture.lens_id)
            .ok_or_else(|| failure("registered lens spec is missing"))?,
        cache_key.clone(),
        estimate.clone(),
        safety.clone(),
    )?;
    let stale_evidence = load_mxfp4_assay_evidence(
        &vault,
        &fixture.slot,
        fixture
            .registry
            .lens_spec(fixture.lens_id)
            .ok_or_else(|| failure("registered lens spec is missing"))?,
    )?;

    vault.write_cf_batch(vec![(
        ColumnFamily::Assay,
        b"astrolabe:issue552:cotenant-proof".to_vec(),
        serde_json::to_vec(&json!({
            "schema": "astrolabe.manual_fsv.cotenant.v1",
            "purpose": "prove disjoint Assay CF rows are counted and cannot forge MXFP4 evidence"
        }))?,
    )])?;
    let stale_before = logical_state(&vault, &fixture.slot)?;
    let stale_error = fixture
        .registry
        .write_compressed_slot_batch_with_assay_evidence(
            &vault,
            &fixture.slot,
            &fixture.rows,
            std::slice::from_ref(&fixture.query),
            1,
            Some(&stale_evidence),
        )
        .unwrap_err();
    let stale_after = logical_state(&vault, &fixture.slot)?;
    require(
        stale_before == stale_after,
        "stale-evidence attempt mutated the vault",
    )?;

    let fresh_assay_seq = persist_mxfp4_assay_evidence(
        &vault,
        &fixture.slot,
        fixture
            .registry
            .lens_spec(fixture.lens_id)
            .ok_or_else(|| failure("registered lens spec is missing"))?,
        cache_key.clone(),
        estimate.clone(),
        safety.clone(),
    )?;
    let fresh_evidence = load_mxfp4_assay_evidence(
        &vault,
        &fixture.slot,
        fixture
            .registry
            .lens_spec(fixture.lens_id)
            .ok_or_else(|| failure("registered lens spec is missing"))?,
    )?;

    let partial_before = logical_state(&vault, &fixture.slot)?;
    let partial_error = fixture
        .registry
        .write_compressed_slot_batch_with_assay_evidence(
            &vault,
            &fixture.slot,
            &fixture.rows[..ROWS - 1],
            std::slice::from_ref(&fixture.query),
            1,
            Some(&fresh_evidence),
        )
        .unwrap_err();
    let partial_after = logical_state(&vault, &fixture.slot)?;
    require(
        partial_before == partial_after,
        "partial-column attempt mutated the vault",
    )?;

    let absent_before = logical_state(&vault, &fixture.slot)?;
    let absent_error = fixture
        .registry
        .write_compressed_slot_batch_with_assay_evidence(
            &vault,
            &fixture.slot,
            &fixture.rows,
            std::slice::from_ref(&fixture.query),
            1,
            None,
        )
        .unwrap_err();
    let absent_after = logical_state(&vault, &fixture.slot)?;
    require(
        absent_before == absent_after,
        "explicitly absent evidence attempt mutated the vault",
    )?;

    let report = fixture.registry.write_compressed_slot_batch(
        &vault,
        &fixture.slot,
        &fixture.rows,
        std::slice::from_ref(&fixture.query),
        1,
    )?;
    vault.flush()?;
    let committed_state = logical_state(&vault, &fixture.slot)?;
    let committed_seq = vault.latest_seq();
    drop(vault);

    let physical_before_reopen = physical_state(&vault_dir)?;
    let reader = open_reader(&vault_dir)?;
    let readback = inspect_reopened(
        &reader,
        &fixture,
        &quantized_rows,
        report
            .snapshot
            .ok_or_else(|| failure("compression report has no committed snapshot"))?,
    )?;
    drop(reader);
    let physical_after_reopen = physical_state(&vault_dir)?;
    require(
        physical_before_reopen == physical_after_reopen,
        "read-only reopen changed physical vault bytes",
    )?;

    let assay_reader = open_reader(&vault_dir)?;
    let assay_rows = AssayStore::read_row_from_vault_at(
        &assay_reader,
        committed_seq,
        &cache_key,
        &AssaySubject::Lens {
            slot: fixture.slot.slot_id,
        },
    )?
    .ok_or_else(|| failure("persisted MXFP4 Assay row is absent after independent reopen"))?;
    drop(assay_reader);
    let report_summary = json!({
        "slot_id": report.slot_id,
        "slot_key": report.slot_key,
        "requested_quant": report.requested_quant,
        "stored_codec": report.stored_codec,
        "fallback_reason": report.fallback_reason,
        "rows": report.rows.len(),
        "raw_bytes_total": report.raw_bytes_total,
        "stored_bytes_total": report.stored_bytes_total,
        "codec_payload_bytes_total": report.codec_payload_bytes_total,
        "registry_envelope_bytes_total": report.registry_envelope_bytes_total,
        "generation_manifest_bytes_total": report.generation_manifest_bytes_total,
        "codec_header_bytes_total": report.codec_header_bytes_total,
        "logical_data_bits_total": report.logical_data_bits_total,
        "written_value_bytes_total": report.written_value_bytes_total,
        "logical_data_bits_per_channel": report.logical_data_bits_per_channel,
        "codec_payload_bits_per_channel": report.codec_payload_bits_per_channel,
        "written_value_bits_per_channel": report.written_value_bits_per_channel,
        "recall_at_k_raw": report.recall_at_k_raw,
        "recall_at_k_compressed": report.recall_at_k_compressed,
        "recall_drop": report.recall_drop,
        "manifest_sha256": sha256_hex(&report.generation_manifest_bytes),
        "snapshot": report.snapshot,
    });

    let final_report = json!({
        "schema": "astrolabe.issue552.mxfp_registry_fsv.v1",
        "execution": {
            "platform": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "tree_head": std::env::var("ASTRO_FSV_TREE_HEAD").unwrap_or_else(|_| "unset".to_string()),
            "tree_state_sha256": std::env::var("ASTRO_FSV_TREE_STATE_SHA256").unwrap_or_else(|_| "unset".to_string()),
            "artifact": std::env::current_exe()?,
            "artifact_sha256": sha256_file(&std::env::current_exe()?)?,
        },
        "source_of_truth": "durable Aster Base/Anchors/Assay/slot_52/slot_52.raw/compression CF rows plus independently hashed WAL/SST/manifest files",
        "known_corpus": {
            "rows": ROWS,
            "dim": DIM,
            "lens_id": fixture.lens_id.to_string(),
            "slot_id": fixture.slot.slot_id.get(),
            "exact_pattern": "lane0=-1 for ordinals 0..31 and +1 for 32..63; lane32=2^(-(ordinal%32+1)); all remaining lanes +0",
            "grounded_anchor": fixture.anchor,
        },
        "assay": {
            "raw_estimate": estimate,
            "safety": safety,
            "first_persisted_seq": first_assay_seq,
            "fresh_persisted_seq": fresh_assay_seq,
            "readback_written_at_seq": assay_rows.written_at_seq,
            "readback_provenance": assay_rows.provenance,
            "readback_payload": assay_rows.payload,
        },
        "edges": {
            "missing_persisted_evidence": {
                "before": source_state,
                "error": calyx_error_json(&no_evidence_error),
                "after": no_evidence_after,
            },
            "stale_evidence_after_cotenant_commit": {
                "before": stale_before,
                "error": calyx_error_json(&stale_error),
                "after": stale_after,
            },
            "partial_column": {
                "before": partial_before,
                "error": calyx_error_json(&partial_error),
                "after": partial_after,
            },
            "explicitly_absent_evidence": {
                "before": absent_before,
                "error": calyx_error_json(&absent_error),
                "after": absent_after,
            },
        },
        "commit": {
            "seq": committed_seq,
            "state": committed_state,
            "report": report_summary,
        },
        "independent_readback": readback,
        "physical_vault": physical_after_reopen,
    });
    let report_bytes = serde_json::to_vec_pretty(&final_report)?;
    let report_path = root.join("report.json");
    fs::write(&report_path, &report_bytes)?;
    require(
        fs::read(&report_path)? == report_bytes,
        "registry FSV report readback differs from written bytes",
    )?;
    println!("{}", String::from_utf8(fs::read(report_path)?)?);
    Ok(())
}

fn register_fixture() -> AnyResult<Fixture> {
    let lens = KnownPatternLens::new();
    let contract = KnownPatternLens::contract();
    let lens_id = contract.lens_id();
    let spec = LensSpec {
        name: contract.name().to_string(),
        runtime: LensRuntime::Algorithmic {
            kind: "issue552-known-ocp-pattern-v1".to_string(),
        },
        output: contract.shape(),
        modality: contract.modality(),
        weights_sha256: contract.weights_sha256(),
        corpus_hash: contract.corpus_hash(),
        norm_policy: contract.norm_policy(),
        max_batch: Some(ROWS),
        axis: Some("issue552-known-outcome".to_string()),
        asymmetry: Asymmetry::None,
        quant_default: QuantPolicy::MxFp4,
        truncate_dim: None,
        recall_delta: 0.0,
        retrieval_only: false,
        excluded_from_dedup: false,
    };
    let mut registry = Registry::new();
    let registered_id = registry.register_frozen_with_spec(lens, contract, spec)?;
    require(registered_id == lens_id, "registered lens identity drifted")?;
    let slot_id = SlotId::new(SLOT_ID);
    let slot = Slot {
        slot_id,
        slot_key: slot_id.with_key("issue552-mxfp4-known-pattern"),
        lens_id,
        shape: SlotShape::Dense(DIM as u32),
        modality: Modality::Structured,
        asymmetry: Asymmetry::None,
        quant: QuantPolicy::MxFp4,
        resource: SlotResource::default(),
        axis: Some("issue552-known-outcome".to_string()),
        retrieval_only: false,
        excluded_from_dedup: false,
        bits_about: BTreeMap::new(),
        state: SlotState::Active,
        added_at_panel_version: PANEL_VERSION,
    };
    let anchor = Anchor {
        kind: AnchorKind::TestPass,
        value: AnchorValue::Bool(true),
        source: "manual-fsv:issue552:known-ordinal-threshold".to_string(),
        observed_at: FIXED_TS,
        confidence: 1.0,
    };
    Ok(Fixture {
        registry,
        slot,
        lens_id,
        rows: Vec::new(),
        labels: Vec::new(),
        anchor,
        query: CompressionQuery {
            cx_id: CxId::from_bytes([0xff; 16]),
            values: Vec::new(),
        },
    })
}

fn populate_source(vault: &AsterVault<FixedClock>, fixture: &mut Fixture) -> AnyResult<()> {
    for ordinal in 0..ROWS {
        let input_bytes = vec![ordinal as u8];
        let input = Input::new(Modality::Structured, input_bytes.clone());
        let measured = fixture.registry.measure(fixture.lens_id, &input)?;
        let values = measured
            .as_dense()
            .ok_or_else(|| failure("known-pattern lens emitted a non-dense vector"))?
            .to_vec();
        let label = ordinal >= 32;
        require(
            values[0] == if label { 1.0 } else { -1.0 },
            "known label does not match measured lane zero",
        )?;
        let cx_id = vault.cx_id_for_input(&input_bytes, PANEL_VERSION);
        let anchor = Anchor {
            kind: AnchorKind::TestPass,
            value: AnchorValue::Bool(label),
            source: "manual-fsv:issue552:known-ordinal-threshold".to_string(),
            observed_at: FIXED_TS,
            confidence: 1.0,
        };
        let stored = vault.put(Constellation {
            cx_id,
            vault_id: vault.vault_id(),
            panel_version: PANEL_VERSION,
            created_at: FIXED_TS,
            input_ref: InputRef {
                hash: Sha256::digest(&input_bytes).into(),
                pointer: Some(format!("manual-fsv://issue552/ordinal/{ordinal}")),
                redacted: false,
            },
            modality: Modality::Structured,
            slots: BTreeMap::from([(
                fixture.slot.slot_id,
                SlotVector::Dense {
                    dim: DIM as u32,
                    data: values.clone(),
                },
            )]),
            scalars: BTreeMap::from([("ordinal".to_string(), ordinal as f64)]),
            metadata: BTreeMap::from([(
                "fixture".to_string(),
                "issue552-real-known-pattern".to_string(),
            )]),
            anchors: vec![anchor],
            provenance: LedgerRef {
                seq: 0,
                hash: [0; 32],
            },
            flags: CxFlags::default(),
        })?;
        require(stored == cx_id, "vault returned the wrong CxId")?;
        fixture.rows.push((cx_id, values));
        fixture.labels.push(label as usize);
    }
    let query_primary = fixture
        .rows
        .get(32)
        .ok_or_else(|| failure("known positive query source is missing"))?;
    let query_secondary = fixture
        .rows
        .get(33)
        .ok_or_else(|| failure("known secondary query source is missing"))?;
    let mut query_values = query_primary
        .1
        .iter()
        .zip(&query_secondary.1)
        .map(|(&primary, &secondary)| 4.0 * primary + secondary)
        .collect::<Vec<_>>();
    let query_norm = query_values
        .iter()
        .map(|value| f64::from(*value).powi(2))
        .sum::<f64>()
        .sqrt();
    require(query_norm > 0.0, "known mixed query has zero norm")?;
    for value in &mut query_values {
        *value = (f64::from(*value) / query_norm) as f32;
    }
    fixture.query = CompressionQuery {
        cx_id: vault.cx_id_for_input(b"issue552-disjoint-query", PANEL_VERSION),
        values: query_values,
    };
    let raw_ranked = ranked(
        fixture
            .rows
            .iter()
            .map(|(cx_id, values)| (*cx_id, values.as_slice())),
        &fixture.query.values,
        2,
    )?;
    require(
        raw_ranked.first() == Some(&fixture.rows[32].0)
            && raw_ranked.get(1) == Some(&fixture.rows[33].0),
        "known directionally distinct query did not rank rows 32 then 33",
    )?;
    vault.flush()?;
    Ok(())
}

fn measured_assay(
    fixture: &Fixture,
) -> AnyResult<(calyx_assay::MiEstimate, AssayQuantSafety, Vec<Vec<f32>>)> {
    let raw = fixture
        .rows
        .iter()
        .map(|(_, values)| values.clone())
        .collect::<Vec<_>>();
    let quantized = raw
        .iter()
        .map(|values| decode_mxfp4(&encode_mxfp4(values)?, DIM))
        .collect::<calyx_forge::Result<Vec<_>>>()?;
    require(
        raw == quantized,
        "known exact OCP corpus did not round-trip bit-for-bit",
    )?;
    let raw_estimate =
        ksg_mi_continuous_discrete_with_anchor(&raw, &fixture.labels, 3, &fixture.anchor)?;
    let quantized_estimate =
        ksg_mi_continuous_discrete_with_anchor(&quantized, &fixture.labels, 3, &fixture.anchor)?;
    require(
        raw_estimate.trust == calyx_assay::TrustTag::Trusted
            && quantized_estimate.trust == calyx_assay::TrustTag::Trusted,
        "grounded Assay estimates are not trusted",
    )?;
    require(
        raw_estimate.bits.to_bits() == quantized_estimate.bits.to_bits(),
        "exact OCP round-trip changed measured Assay bits",
    )?;
    let safety = AssayQuantSafety {
        baseline_bits: raw_estimate.bits,
        quantized_bits: quantized_estimate.bits,
        cosine: corpus_cosine(&raw, &quantized)?,
        far_delta: recall_delta(&fixture.rows, &quantized, &fixture.query.values, 8)?,
    };
    require(safety.passes(), "measured OCP safety card did not pass")?;
    Ok((quantized_estimate, safety, quantized))
}

fn inspect_reopened(
    vault: &AsterVault<FixedClock>,
    fixture: &Fixture,
    quantized_rows: &[Vec<f32>],
    expected_snapshot: u64,
) -> AnyResult<Value> {
    let snapshot = vault.latest_seq();
    require(
        snapshot == expected_snapshot,
        "reopened snapshot differs from committed report",
    )?;
    let base = vault.scan_cf_at(snapshot, ColumnFamily::Base)?;
    let anchors = vault.scan_cf_at(snapshot, ColumnFamily::Anchors)?;
    let assay = vault.scan_cf_at(snapshot, ColumnFamily::Assay)?;
    let primary = vault.scan_cf_at(snapshot, ColumnFamily::slot(fixture.slot.slot_id))?;
    let raw = vault.scan_cf_at(snapshot, ColumnFamily::slot_raw(fixture.slot.slot_id))?;
    let manifest = vault
        .read_cf_at(
            snapshot,
            ColumnFamily::Compression,
            &compression_manifest_key(fixture.slot.slot_id),
        )?
        .ok_or_else(|| failure("compression manifest is absent after reopen"))?;
    require(base.len() == ROWS, "Base row count mismatch after reopen")?;
    require(
        anchors.len() == ROWS,
        "Anchor row count mismatch after reopen",
    )?;
    require(
        assay.len() == 2,
        "Assay row count should contain evidence plus one co-tenant",
    )?;
    require(
        primary.len() == ROWS,
        "compressed primary row count mismatch",
    )?;
    require(raw.len() == ROWS, "raw sidecar row count mismatch")?;
    require(
        &manifest[..4] == b"CSMF",
        "compression manifest magic mismatch",
    )?;

    let expected_by_id = fixture
        .rows
        .iter()
        .enumerate()
        .map(|(index, (cx_id, values))| (*cx_id, (index, values)))
        .collect::<BTreeMap<_, _>>();
    let raw_by_key = raw.into_iter().collect::<BTreeMap<_, _>>();
    let mut inspected = Vec::with_capacity(ROWS);
    for (key, bytes) in &primary {
        let cx_id = cx_id_from_key(key)?;
        let (index, expected) = expected_by_id
            .get(&cx_id)
            .ok_or_else(|| failure("persisted compressed row has an unknown CxId"))?;
        let envelope = inspect_unbound_stored_slot_envelope(bytes)?;
        require(
            envelope.codec == StoredSlotCodec::MxFp4,
            "persisted codec is not MXFP4",
        )?;
        require(
            envelope.cx_id == cx_id,
            "outer envelope CxId differs from CF key",
        )?;
        require(
            bytes.len() == REGISTRY_ENVELOPE_HEADER_BYTES + envelope.payload_bytes,
            "outer envelope physical length mismatch",
        )?;
        let payload = &bytes[REGISTRY_ENVELOPE_HEADER_BYTES..];
        require(&payload[..4] == b"MXOC", "inner OCP MX magic mismatch")?;
        require(
            payload[4] == 1 && payload[5] == 1 && payload[6] == 32 && payload[7] == 7,
            "inner OCP MX version/element/block/flags mismatch",
        )?;
        let qv = QuantizedVec {
            level: QuantLevel::Bits4Fp,
            dim: DIM,
            bytes: payload.to_vec(),
            scale: envelope.quant_scale,
            seed_id: decode_hex_32(&envelope.seed_id)?,
        };
        let storage = MxFp4Codec::new(DIM).inspect(&qv)?;
        let decoded = MxFp4Codec::new(DIM).decode(&qv)?;
        require(
            decoded == quantized_rows[*index] && decoded == **expected,
            "persisted MXFP4 payload did not decode to the known source vector",
        )?;
        let raw_bytes = raw_by_key
            .get(key)
            .ok_or_else(|| failure("raw sidecar is missing the compressed row key"))?;
        require(
            encode::decode_slot_vector(raw_bytes)?
                == (SlotVector::Dense {
                    dim: DIM as u32,
                    data: (*expected).clone(),
                }),
            "raw sidecar differs from known source vector",
        )?;
        let expected_blocks = encode_mxfp4(expected)?;
        let expected_body = expected_blocks
            .iter()
            .flat_map(|block| block.codes.iter().copied().chain([block.scale_e8m0]))
            .collect::<Vec<_>>();
        require(
            payload[MXFP_FORMAT_HEADER_BYTES..] == expected_body,
            "persisted body differs from canonical block bytes",
        )?;
        if [0, 31, 32, 63].contains(index) {
            inspected.push(json!({
                "cx_id": cx_id.to_string(),
                "ordinal": index,
                "outer_bytes": bytes.len(),
                "payload_bytes": payload.len(),
                "payload_sha256": sha256_hex(payload),
                "header_hex": hex(&payload[..MXFP_FORMAT_HEADER_BYTES]),
                "body_hex": hex(&payload[MXFP_FORMAT_HEADER_BYTES..]),
                "element_bytes": storage.element_bytes,
                "scale_bytes": storage.scale_bytes,
                "assay_attestation_id": envelope.seed_id,
            }));
        }
    }

    let index = fixture
        .registry
        .compressed_slot_index(vault, &fixture.slot)?;
    index.verify_at(snapshot)?;
    for (cx_id, (_, expected)) in &expected_by_id {
        let observed = index.read_at(*cx_id, snapshot)?;
        require(
            observed.as_dense() == Some(expected.as_slice()),
            "compression-aware index read differs from known source vector",
        )?;
    }
    let hits = index.search_at(&fixture.query.values, 1, snapshot)?;
    require(
        hits.len() == 1,
        "compressed top-1 returned the wrong hit count",
    )?;
    let expected_score = cosine(&fixture.query.values, &fixture.rows[32].1)?;
    require(
        hits[0].cx_id == fixture.rows[32].0 && (hits[0].score - expected_score).abs() <= 1.0e-6,
        "compressed top-1 did not return the expected known positive row and score",
    )?;

    Ok(json!({
        "snapshot": snapshot,
        "recovery_seq": vault.recovery_report().last_recovered_seq,
        "base_rows": base.len(),
        "anchor_rows": anchors.len(),
        "assay_rows": assay.len(),
        "compressed_rows": primary.len(),
        "validated_payload_rows": primary.len(),
        "manifest_bytes": manifest.len(),
        "manifest_sha256": sha256_hex(&manifest),
        "query_construction": "normalize(4 * measured_row_32 + measured_row_33)",
        "top1": {"cx_id": hits[0].cx_id.to_string(), "score": hits[0].score, "expected_score": expected_score},
        "rows": inspected,
    }))
}

fn logical_state(vault: &AsterVault<FixedClock>, slot: &Slot) -> AnyResult<Value> {
    let snapshot = vault.latest_seq();
    let families = [
        ("base", ColumnFamily::Base),
        ("anchors", ColumnFamily::Anchors),
        ("assay", ColumnFamily::Assay),
        ("primary", ColumnFamily::slot(slot.slot_id)),
        ("raw", ColumnFamily::slot_raw(slot.slot_id)),
        ("compression", ColumnFamily::Compression),
    ];
    let state = families
        .into_iter()
        .map(|(name, family)| {
            let rows = vault.scan_cf_at(snapshot, family)?;
            Ok::<_, Box<dyn Error>>((
                name.to_string(),
                json!({
                    "rows": rows.len(),
                    "value_bytes": rows.iter().map(|(_, value)| value.len()).sum::<usize>(),
                    "sha256": digest_rows(&rows),
                }),
            ))
        })
        .collect::<AnyResult<serde_json::Map<String, Value>>>()?;
    Ok(json!({"snapshot": snapshot, "families": state}))
}

fn physical_state(root: &Path) -> AnyResult<Value> {
    let mut files = Vec::new();
    collect_files(root, &mut files)?;
    files.sort();
    let mut total = 0_u64;
    let mut aggregate = Sha256::new();
    let file_count = files.len();
    let mut groups = BTreeMap::<String, Vec<(String, Vec<u8>)>>::new();
    for path in files {
        let relative = path
            .strip_prefix(root)?
            .to_string_lossy()
            .replace('\\', "/");
        let bytes = fs::read(&path)?;
        total += bytes.len() as u64;
        aggregate.update((relative.len() as u64).to_be_bytes());
        aggregate.update(relative.as_bytes());
        aggregate.update((bytes.len() as u64).to_be_bytes());
        aggregate.update(&bytes);
        let mut parts = relative.split('/');
        let first = parts.next().unwrap_or("root");
        let group = if first == "cf" {
            format!("cf/{}", parts.next().unwrap_or("unknown"))
        } else {
            first.to_string()
        };
        groups.entry(group).or_default().push((relative, bytes));
    }
    let group_report = groups
        .into_iter()
        .map(|(group, mut files)| {
            files.sort_by(|left, right| left.0.cmp(&right.0));
            let group_file_count = files.len();
            let mut digest = Sha256::new();
            let mut bytes = 0_u64;
            let mut largest: Option<(String, usize, String)> = None;
            for (path, data) in files {
                bytes += data.len() as u64;
                digest.update((path.len() as u64).to_be_bytes());
                digest.update(path.as_bytes());
                digest.update((data.len() as u64).to_be_bytes());
                digest.update(&data);
                if largest
                    .as_ref()
                    .is_none_or(|(_, largest_bytes, _)| data.len() > *largest_bytes)
                {
                    largest = Some((path, data.len(), sha256_hex(&data)));
                }
            }
            let (largest_path, largest_bytes, largest_sha256) =
                largest.ok_or_else(|| failure("physical group unexpectedly has no files"))?;
            Ok::<_, Box<dyn Error>>(json!({
                "group": group,
                "files": group_file_count,
                "bytes": bytes,
                "sha256": hex(&digest.finalize()),
                "largest_file": {
                    "path": largest_path,
                    "bytes": largest_bytes,
                    "sha256": largest_sha256,
                },
            }))
        })
        .collect::<AnyResult<Vec<_>>>()?;
    Ok(json!({
        "files": file_count,
        "bytes": total,
        "sha256": hex(&aggregate.finalize()),
        "groups": group_report,
    }))
}

fn open_writer(directory: &Path) -> AnyResult<AsterVault<FixedClock>> {
    Ok(AsterVault::new_durable_with_clock(
        directory,
        VaultId::from_str(VAULT_ID)?,
        VAULT_SALT,
        VaultOptions::default(),
        FixedClock::new(FIXED_TS),
    )?)
}

fn open_reader(directory: &Path) -> AnyResult<AsterVault<FixedClock>> {
    Ok(AsterVault::open_with_clock(
        directory,
        VaultId::from_str(VAULT_ID)?,
        VAULT_SALT,
        VaultOptions {
            read_only: true,
            restore_ledger_hook: false,
            ..VaultOptions::default()
        },
        FixedClock::new(FIXED_TS),
    )?)
}

fn corpus_cosine(left: &[Vec<f32>], right: &[Vec<f32>]) -> AnyResult<f32> {
    require(
        left.len() == right.len(),
        "corpus cosine row count mismatch",
    )?;
    let mut dot = 0.0_f64;
    let mut left_norm = 0.0_f64;
    let mut right_norm = 0.0_f64;
    for (left, right) in left.iter().zip(right) {
        require(
            left.len() == right.len(),
            "corpus cosine dimension mismatch",
        )?;
        for (&left, &right) in left.iter().zip(right) {
            dot += f64::from(left) * f64::from(right);
            left_norm += f64::from(left) * f64::from(left);
            right_norm += f64::from(right) * f64::from(right);
        }
    }
    require(
        left_norm > 0.0 && right_norm > 0.0,
        "corpus cosine has zero norm",
    )?;
    Ok((dot / (left_norm.sqrt() * right_norm.sqrt())) as f32)
}

fn recall_delta(
    rows: &[(CxId, Vec<f32>)],
    quantized: &[Vec<f32>],
    query: &[f32],
    k: usize,
) -> AnyResult<f32> {
    let raw = ranked(rows.iter().map(|(id, row)| (*id, row.as_slice())), query, k)?;
    let packed = ranked(
        rows.iter()
            .zip(quantized)
            .map(|((id, _), row)| (*id, row.as_slice())),
        query,
        k,
    )?;
    Ok(if raw == packed { 0.0 } else { 1.0 })
}

fn ranked<'a>(
    rows: impl Iterator<Item = (CxId, &'a [f32])>,
    query: &[f32],
    k: usize,
) -> AnyResult<Vec<CxId>> {
    let mut scored = rows
        .map(|(id, row)| Ok((id, cosine(query, row)?)))
        .collect::<AnyResult<Vec<_>>>()?;
    scored.sort_by(|left, right| {
        right
            .1
            .total_cmp(&left.1)
            .then_with(|| left.0.as_bytes().cmp(right.0.as_bytes()))
    });
    scored.truncate(k);
    Ok(scored.into_iter().map(|(id, _)| id).collect())
}

fn cosine(left: &[f32], right: &[f32]) -> AnyResult<f32> {
    require(left.len() == right.len(), "cosine dimension mismatch")?;
    let dot = left
        .iter()
        .zip(right)
        .map(|(&left, &right)| f64::from(left) * f64::from(right))
        .sum::<f64>();
    let left_norm = left
        .iter()
        .map(|value| f64::from(*value).powi(2))
        .sum::<f64>()
        .sqrt();
    let right_norm = right
        .iter()
        .map(|value| f64::from(*value).powi(2))
        .sum::<f64>()
        .sqrt();
    require(left_norm > 0.0 && right_norm > 0.0, "cosine has zero norm")?;
    Ok((dot / (left_norm * right_norm)) as f32)
}

fn digest_rows(rows: &[(Vec<u8>, Vec<u8>)]) -> String {
    let mut sorted = rows.to_vec();
    sorted.sort_by(|left, right| left.0.cmp(&right.0));
    let mut hasher = Sha256::new();
    for (key, value) in sorted {
        hasher.update((key.len() as u64).to_be_bytes());
        hasher.update(key);
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value);
    }
    hex(&hasher.finalize())
}

fn collect_files(root: &Path, out: &mut Vec<PathBuf>) -> AnyResult<()> {
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_files(&path, out)?;
        } else if path.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

fn cx_id_from_key(key: &[u8]) -> AnyResult<CxId> {
    let bytes: [u8; 16] = key
        .try_into()
        .map_err(|_| failure(format!("slot key has {} bytes instead of 16", key.len())))?;
    Ok(CxId::from_bytes(bytes))
}

fn decode_hex_32(value: &str) -> AnyResult<[u8; 32]> {
    require(value.len() == 64, "attestation hex is not 64 characters")?;
    let mut out = [0_u8; 32];
    for (index, output) in out.iter_mut().enumerate() {
        *output = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)?;
    }
    Ok(out)
}

fn calyx_error_json(error: &calyx_core::CalyxError) -> Value {
    json!({
        "code": error.code,
        "message": error.message,
        "remediation": error.remediation,
    })
}

fn sha256_file(path: &Path) -> AnyResult<String> {
    Ok(sha256_hex(&fs::read(path)?))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn require(condition: bool, message: impl Into<String>) -> AnyResult<()> {
    if condition {
        Ok(())
    } else {
        Err(failure(message))
    }
}

fn failure(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(FsvFailure {
        message: message.into(),
    })
}
