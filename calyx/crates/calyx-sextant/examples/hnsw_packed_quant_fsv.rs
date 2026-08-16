//! Manual Full State Verification driver for issue #553.
//!
//! This is not a test. It builds real packed HNSW indexes from byte-histogram
//! vectors derived from this repository's own Sextant source, persists the
//! actual serving artifacts, independently parses their physical headers and
//! checksums, starts a second process to reload/search them, and emits explicit
//! before/after state for boundary failures.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Instant;

use calyx_anneal::{
    AnnealLedger, AnnealLedgerAction, AsterAnnealLedgerStore, AsterBanditStorage, AsterHealthStore,
    CALYX_INDEX_ARTIFACT_ACTIVATION_REQUIRED, CALYX_INDEX_CACHE_WRITE_FAIL, ConfigBanditStore,
    DegradeRegistry, IndexArtifactActivator, IndexArtifactPromotionRequest, IndexConfig,
    IndexScopeTuner, QuantPromotionEvidence, bandit_key, decode_config_bandit, encode_index_config,
    index_slot_label, shape_key_hash, slot_autotune_key,
};
use calyx_aster::cf::ColumnFamily;
use calyx_aster::vault::{AsterVault, VaultOptions};
use calyx_core::{CalyxError, CxId, SlotId, SlotVector, SystemClock, VaultId};
use calyx_forge::{AutotuneCache, QuantLevel, TURBOQUANT_FORMAT_HEADER_BYTES, new_seed};
use calyx_ledger::{ActorId, LedgerAppender};
use calyx_sextant::{
    CALYX_SEXTANT_HNSW_POINTER_CORRUPT, CALYX_SEXTANT_HNSW_POINTER_STALE,
    CALYX_SEXTANT_HNSW_POINTER_UNSTAGED, HNSW_ACTIVE_POINTER_MAGIC, HNSW_ACTIVE_POINTER_VERSION,
    HNSW_ARTIFACT_MAGIC, HNSW_ARTIFACT_VERSION, HNSW_MAX_DIM, HnswArtifactActivator,
    HnswArtifactExpectation, HnswIndex, PackedQuery, PackedVector, QuantConfig, QuantKind,
    SEXTANT_QUANT_LAYOUT_VERSION, SextantIndex, score_packed,
};
use sha2::{Digest, Sha256};

const DIM: usize = 128;
const ROWS: usize = 200;
const QUERIES: usize = 8;
const K: usize = 10;
const SLOT: SlotId = SlotId::new(7);
const BASE_SEQ: u64 = 777;
const HEADER_BYTES: usize = 186;
const FOOTER_BYTES: usize = 32;
const POINTER_HEADER_BYTES: usize = 144;
const TURBOQUANT_SEED: &[u8] = b"calyx/sextant/hnsw/slot-7/turboquant/fsv-v1";
const ANNEAL_VAULT_ID: &str = "01J00000000000000000000553";
const ANNEAL_VAULT_SALT: &[u8] = b"calyx-553-anneal-fsv";
const ADMISSION_ROWS: usize = 32;
const ADMISSION_SAMPLES: usize = 64;
const ADMISSION_DIM: usize = HNSW_MAX_DIM as usize;
const ADMISSION_K: usize = 1;
const ADMISSION_MAX_COSINE_ERROR: f64 = 0.02;

#[derive(Clone, Copy)]
struct CodecMeasurement {
    recall: f64,
    latency_ns: u64,
}

struct AdmissionFixture {
    f32_artifact: PathBuf,
    scalar_artifact: PathBuf,
    f32_expectation: HnswArtifactExpectation,
    scalar_expectation: HnswArtifactExpectation,
    queries: Vec<Vec<f32>>,
    incumbent: CodecMeasurement,
    candidate: CodecMeasurement,
    quant_evidence: QuantPromotionEvidence,
    max_cosine_error: f64,
}

fn main() {
    let result = match std::env::args().nth(1).as_deref() {
        Some("--reload") => child_reload(),
        Some("--anneal-reload") => child_anneal_reload(),
        _ => parent_run(),
    };
    if let Err(error) = result {
        println!(
            "{{\"event\":\"fsv_failure\",\"error\":\"{}\"}}",
            json(&error.to_string())
        );
        std::process::exit(1);
    }
}

fn parent_run() -> Result<(), Box<dyn std::error::Error>> {
    let output_root = std::env::var_os("CALYX_FSV_OUTPUT")
        .map(PathBuf::from)
        .ok_or("CALYX_FSV_OUTPUT must name the retained manual-evidence directory")?;
    let run_dir = output_root.join(format!("hnsw-553-{}", std::process::id()));
    let before_exists = run_dir.exists();
    std::fs::create_dir_all(&run_dir)?;
    let tree_sha = std::env::var("CALYX_FSV_TREE_SHA")
        .map_err(|_| "CALYX_FSV_TREE_SHA must identify the exact committed source tree")?;
    let current_exe = std::env::current_exe()?;
    let executable_bytes = std::fs::read(&current_exe)?;
    let preserved_executable = run_dir.join("hnsw_packed_quant_fsv.exe");
    std::fs::copy(&current_exe, &preserved_executable)?;
    println!(
        "{{\"event\":\"source_of_truth\",\"path\":\"{}\",\"before_exists\":{},\"after_exists\":true,\"source\":\"persisted CLXHNSW1 files independently reopened from disk\"}}",
        json(&run_dir.display().to_string()),
        before_exists
    );
    println!(
        "{{\"event\":\"binary_provenance\",\"tree_sha\":\"{}\",\"binary_path\":\"{}\",\"binary_bytes\":{},\"binary_blake3\":\"{}\"}}",
        json(&tree_sha),
        json(&preserved_executable.display().to_string()),
        executable_bytes.len(),
        blake3::hash(&executable_bytes).to_hex()
    );

    let vectors = real_corpus_vectors(ROWS + QUERIES)?;
    let (rows, queries) = vectors.split_at(ROWS);
    let raw_truth: Vec<Vec<CxId>> = queries
        .iter()
        .map(|query| exact_top_k(query, rows, K))
        .collect();
    let scale = measured_scale(rows);
    println!(
        "{{\"event\":\"fsv_context\",\"platform\":\"{}\",\"arch\":\"{}\",\"artifact_version\":{},\"layout_version\":{},\"dim\":{},\"rows\":{},\"queries\":{},\"k\":{},\"corpus\":\"byte histograms of real calyx-sextant source bytes\"}}",
        std::env::consts::OS,
        std::env::consts::ARCH,
        HNSW_ARTIFACT_VERSION,
        SEXTANT_QUANT_LAYOUT_VERSION,
        DIM,
        ROWS,
        QUERIES,
        K
    );

    let turbo2p5_config =
        QuantConfig::turboquant_structured(new_seed(DIM, TURBOQUANT_SEED), QuantLevel::Bits2p5)?;
    let turbo2p5_geometry_id = turbo2p5_config.geometry_id();
    let turbo3p5_config =
        QuantConfig::turboquant_structured(new_seed(DIM, TURBOQUANT_SEED), QuantLevel::Bits3p5)?;
    let turbo3p5_geometry_id = turbo3p5_config.geometry_id();
    let turbo2p5_row_bytes = TURBOQUANT_FORMAT_HEADER_BYTES
        + ((DIM / 2 * 3 + (DIM % 2) * 2).div_ceil(8))
        + DIM.div_ceil(8)
        + 4;
    let turbo3p5_row_bytes = TURBOQUANT_FORMAT_HEADER_BYTES
        + ((DIM / 2 * 5 + (DIM % 2) * 3).div_ceil(8))
        + DIM.div_ceil(8)
        + 4;
    let mut artifacts = Vec::new();
    let mut f32_measurement = None;
    let mut turbo3p5_measurement = None;
    for (name, config, expected_tag, expected_vector_bytes, expected_geometry) in vec![
        ("f32", QuantConfig::none(), 0_u8, ROWS * DIM * 4, [0_u8; 32]),
        (
            "scalar8",
            QuantConfig::scalar8(scale),
            1_u8,
            ROWS * (DIM + 8),
            [0_u8; 32],
        ),
        (
            "binary",
            QuantConfig::binary(),
            2_u8,
            ROWS * (DIM.div_ceil(8) + 4),
            [0_u8; 32],
        ),
        (
            "turboquant2p5",
            turbo2p5_config,
            3_u8,
            ROWS * turbo2p5_row_bytes,
            turbo2p5_geometry_id,
        ),
        (
            "turboquant3p5",
            turbo3p5_config,
            4_u8,
            ROWS * turbo3p5_row_bytes,
            turbo3p5_geometry_id,
        ),
    ] {
        let mut index = HnswIndex::new(SLOT, DIM as u32, 553).with_quant(config)?;
        for (ordinal, data) in rows.iter().enumerate() {
            index.insert(
                cx(ordinal),
                SlotVector::Dense {
                    dim: DIM as u32,
                    data: data.clone(),
                },
                ordinal as u64 + 1,
            )?;
        }
        index.set_base_seq(BASE_SEQ);
        if index.physical_vector_bytes() != expected_vector_bytes {
            return Err(format!(
                "{name}: held packed bytes {} != expected {expected_vector_bytes}",
                index.physical_vector_bytes()
            )
            .into());
        }

        let started = Instant::now();
        let mut raw_recall = 0.0_f64;
        let mut packed_recall = 0.0_f64;
        for (query, truth) in queries.iter().zip(&raw_truth) {
            let hits = index.search(
                &SlotVector::Dense {
                    dim: DIM as u32,
                    data: query.clone(),
                },
                K,
                Some(64),
            )?;
            let got: Vec<CxId> = hits.iter().map(|hit| hit.cx_id).collect();
            raw_recall += overlap(&got, truth) as f64 / K as f64;
            let packed_truth: Vec<CxId> = index
                .brute_force(query, K)?
                .into_iter()
                .map(|(cx_id, _)| cx_id)
                .collect();
            packed_recall += overlap(&got, &packed_truth) as f64 / K as f64;
        }
        raw_recall /= QUERIES as f64;
        packed_recall /= QUERIES as f64;
        if packed_recall < 0.95 {
            return Err(format!(
                "{name}: HNSW recall {packed_recall:.3} below 0.95 against packed exact truth"
            )
            .into());
        }
        let search_us = started.elapsed().as_secs_f64() * 1_000_000.0 / QUERIES as f64;

        let path = run_dir.join(format!("{name}.clxhnsw"));
        let process_rss_bytes = process_rss_bytes()?;
        println!(
            "{{\"event\":\"happy_state_before\",\"kind\":\"{name}\",\"artifact_exists\":{},\"rows_in_memory\":{},\"packed_vector_bytes\":{},\"shared_geometry_bytes\":{},\"raw_rerank_bytes\":{},\"total_compressed_footprint_bytes\":{}}}",
            path.exists(),
            index.total_nodes(),
            index.physical_vector_bytes(),
            index.quant_geometry_bytes(),
            index.raw_rerank_vector_bytes(),
            index.total_compressed_footprint_bytes()
        );
        let receipt = index.persist_artifact(&path)?;
        let physical = independent_artifact_read(&path)?;
        if physical.magic != HNSW_ARTIFACT_MAGIC
            || physical.version != HNSW_ARTIFACT_VERSION
            || physical.layout != SEXTANT_QUANT_LAYOUT_VERSION
            || physical.kind_tag != expected_tag
            || physical.slot != SLOT.get()
            || physical.dim != DIM as u32
            || physical.base_seq != BASE_SEQ
            || physical.row_count != ROWS as u64
            || physical.packed_vector_bytes != expected_vector_bytes as u64
            || physical.geometry_id != expected_geometry
            || ((expected_tag == 3 || expected_tag == 4)
                && (physical.tqpr_rows != ROWS as u64 || physical.first_tqpr_digest == [0_u8; 32]))
            || (expected_tag < 3 && physical.tqpr_rows != 0)
            || physical.digest != receipt.metadata.digest
        {
            return Err(
                format!("{name}: independent physical header does not match receipt").into(),
            );
        }
        let reload = spawn_reload(&path, name)?;
        if !reload.status.success() || !reload.stdout.contains("\"event\":\"reload_success\"") {
            return Err(format!(
                "{name}: process restart reload failed status={} stdout={} stderr={}",
                reload.status, reload.stdout, reload.stderr
            )
            .into());
        }
        println!(
            "{{\"event\":\"happy_state_after\",\"kind\":\"{name}\",\"artifact_exists\":true,\"artifact_bytes\":{},\"body_bytes\":{},\"packed_vector_bytes\":{},\"process_rss_bytes\":{},\"digest\":\"{}\",\"tqpr_rows\":{},\"first_tqpr_digest\":\"{}\",\"recall_at_{}_vs_raw\":{:.3},\"recall_at_{}_vs_packed\":{:.3},\"search_us_per_query\":{:.1},\"child_readback\":{}}}",
            physical.artifact_bytes,
            physical.body_bytes,
            physical.packed_vector_bytes,
            process_rss_bytes,
            hex(&physical.digest),
            physical.tqpr_rows,
            hex(&physical.first_tqpr_digest),
            K,
            raw_recall,
            K,
            packed_recall,
            search_us,
            reload.stdout.trim()
        );
        let measurement = CodecMeasurement {
            recall: raw_recall,
            latency_ns: (search_us * 1_000.0).round() as u64,
        };
        if name == "f32" {
            f32_measurement = Some(measurement);
        } else if name == "turboquant3p5" {
            turbo3p5_measurement = Some(measurement);
        }
        artifacts.push((name, path, physical));
    }
    if artifacts
        .windows(2)
        .any(|pair| pair[0].2.packed_vector_bytes == pair[1].2.packed_vector_bytes)
    {
        return Err("quantization did not alter persisted physical vector bytes".into());
    }

    anneal_low_recall_refusal_fsv(
        &run_dir,
        f32_measurement.ok_or("missing measured F32 result")?,
        turbo3p5_measurement.ok_or("missing measured TQ3.5 result")?,
    )?;
    let admission = build_admission_fixture(&run_dir)?;
    anneal_activation_fsv(&run_dir, &admission)?;

    edge_empty(&run_dir, queries)?;
    edge_limits(&run_dir, rows)?;
    edge_invalid_config()?;
    edge_corrupt_stale_unsupported(&run_dir, &artifacts[4].1)?;

    println!(
        "{{\"event\":\"evidence_inventory\",\"path\":\"{}\",\"files\":{},\"bytes\":{}}}",
        json(&run_dir.display().to_string()),
        count_files(&run_dir)?,
        count_bytes(&run_dir)?
    );
    println!("{{\"event\":\"fsv_success\",\"issue\":553}}");
    Ok(())
}

fn child_reload() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(2);
    let path = PathBuf::from(args.next().ok_or("reload path missing")?);
    let name = args.next().ok_or("reload codec missing")?;
    if args.next().is_some() {
        return Err("unexpected reload arguments".into());
    }
    let kind = match name.as_str() {
        "f32" => QuantKind::None,
        "scalar8" => QuantKind::Scalar8,
        "binary" => QuantKind::Binary,
        "turboquant2p5" => QuantKind::TurboQuant2p5,
        "turboquant3p5" => QuantKind::TurboQuant3p5,
        _ => return Err(format!("unknown reload codec {name}").into()),
    };
    let quant_geometry_id = if let Some(level) = kind.turboquant_level() {
        QuantConfig::turboquant_structured(new_seed(DIM, TURBOQUANT_SEED), level)?.geometry_id()
    } else {
        [0_u8; 32]
    };
    let expectation = HnswArtifactExpectation {
        slot: SLOT,
        dim: DIM as u32,
        quant_kind: kind,
        quant_geometry_id,
        base_seq: BASE_SEQ,
    };
    let (index, metadata) = HnswIndex::load_artifact(&path, expectation)?;
    let vectors = real_corpus_vectors(ROWS + QUERIES)?;
    let (_, queries) = vectors.split_at(ROWS);
    let mut packed_recall = 0.0_f64;
    for query in queries {
        let hits = index.search(
            &SlotVector::Dense {
                dim: DIM as u32,
                data: query.clone(),
            },
            K,
            Some(64),
        )?;
        let got: Vec<CxId> = hits.iter().map(|hit| hit.cx_id).collect();
        let truth: Vec<CxId> = index
            .brute_force(query, K)?
            .into_iter()
            .map(|(cx_id, _)| cx_id)
            .collect();
        packed_recall += overlap(&got, &truth) as f64 / K as f64;
    }
    packed_recall /= QUERIES as f64;
    if packed_recall < 0.95 {
        return Err(format!("reloaded {name} recall {packed_recall:.3} below 0.95").into());
    }
    println!(
        "{{\"event\":\"reload_success\",\"kind\":\"{name}\",\"rows\":{},\"packed_vector_bytes\":{},\"artifact_bytes\":{},\"digest\":\"{}\",\"recall_at_{}_vs_packed\":{:.3}}}",
        metadata.row_count,
        metadata.packed_vector_bytes,
        metadata.artifact_bytes,
        hex(&metadata.digest),
        K,
        packed_recall
    );
    Ok(())
}

fn anneal_low_recall_refusal_fsv(
    run_dir: &Path,
    incumbent: CodecMeasurement,
    candidate: CodecMeasurement,
) -> Result<(), Box<dyn std::error::Error>> {
    let vault_dir = run_dir.join("tq-rejection-vault");
    let cache_path = run_dir.join("tq-rejection-cache.json");
    let vault = AsterVault::open(
        &vault_dir,
        ANNEAL_VAULT_ID.parse::<VaultId>()?,
        b"calyx-553-tq-rejection-fsv".to_vec(),
        VaultOptions::default(),
    )?;
    let cache = AutotuneCache::create_empty(&cache_path)?;
    println!(
        "{{\"event\":\"anneal_low_recall_before\",\"incumbent_recall\":{:.3},\"candidate_recall\":{:.3},\"incumbent_latency_ns\":{},\"candidate_latency_ns\":{},\"cache_exists\":{},\"ledger_rows\":0}}",
        incumbent.recall,
        candidate.recall,
        incumbent.latency_ns,
        candidate.latency_ns,
        cache_path.exists()
    );
    let appender = LedgerAppender::open(AsterAnnealLedgerStore::new(&vault), SystemClock)?;
    let ledger = AnnealLedger::new(
        appender,
        ActorId::Service("calyx-553-tq-rejection".to_string()),
    )?;
    let bandits = ConfigBanditStore::new(AsterBanditStorage::new(&vault));
    let health = DegradeRegistry::open(Arc::new(SystemClock), AsterHealthStore::new(&vault))?;
    let mut tuner = IndexScopeTuner::with_parts(cache, ledger, bandits, health);
    let (incumbent_config, candidate_config) = anneal_configs();
    tuner.install_candidates(
        SLOT,
        vec![
            incumbent_config,
            IndexConfig {
                quant_bits: 4,
                ..candidate_config
            },
        ],
    )?;
    tuner.on_search_for_arm(SLOT, 0, incumbent.latency_ns, incumbent.recall, 0.50)?;
    let mut won = false;
    let mut promoted = false;
    for _ in 0..3 {
        let decision = tuner.on_search_for_arm_with_quant_evidence(
            SLOT,
            1,
            candidate.latency_ns,
            candidate.recall,
            0.50,
            None,
        )?;
        won |= decision.won;
        promoted |= decision.promoted.is_some();
    }
    vault.flush()?;
    let bandit = persisted_bandit(&vault)?;
    let ledger_rows = read_anneal_entries(&vault)?.len();
    if won
        || promoted
        || bandit.incumbent_idx != 0
        || !cache_path.exists()
        || !AutotuneCache::open_existing(&cache_path)?.is_empty()?
        || ledger_rows != 0
    {
        return Err("measured low-recall TurboQuant candidate was not refused cleanly".into());
    }
    println!(
        "{{\"event\":\"anneal_low_recall_after\",\"won\":false,\"promoted\":false,\"persisted_bandit_incumbent\":{},\"cache_exists\":true,\"cache_entries\":0,\"ledger_rows\":{},\"reason\":\"measured raw recall regression\"}}",
        bandit.incumbent_idx, ledger_rows
    );
    Ok(())
}

fn build_admission_fixture(run_dir: &Path) -> Result<AdmissionFixture, Box<dyn std::error::Error>> {
    let rows = admission_rows();
    let queries = admission_queries();
    let scale = measured_scale(&rows);
    let mut f32 = HnswIndex::new(SLOT, ADMISSION_DIM as u32, 553).with_quant(QuantConfig::none())?;
    let mut scalar =
        HnswIndex::new(SLOT, ADMISSION_DIM as u32, 553).with_quant(QuantConfig::scalar8(scale))?;
    for (ordinal, row) in rows.iter().enumerate() {
        let vector = SlotVector::Dense {
            dim: ADMISSION_DIM as u32,
            data: row.clone(),
        };
        f32.insert(cx(ordinal), vector.clone(), ordinal as u64 + 1)?;
        scalar.insert(cx(ordinal), vector, ordinal as u64 + 1)?;
    }
    f32.set_base_seq(BASE_SEQ);
    scalar.set_base_seq(BASE_SEQ);
    let f32_artifact = run_dir.join("anneal-admission-f32.clxhnsw");
    let scalar_artifact = run_dir.join("anneal-admission-scalar8.clxhnsw");
    let f32_receipt = f32.persist_artifact(&f32_artifact)?;
    let scalar_receipt = scalar.persist_artifact(&scalar_artifact)?;
    let (incumbent, incumbent_mean_error, incumbent_max_error, incumbent_far) =
        measure_admission_index(&f32, &rows, &queries)?;
    let (candidate, candidate_mean_error, candidate_max_error, candidate_far) =
        measure_admission_index(&scalar, &rows, &queries)?;
    if incumbent.recall < 0.99
        || candidate.recall + f64::EPSILON < incumbent.recall
        || candidate.latency_ns >= incumbent.latency_ns
        || candidate_max_error > ADMISSION_MAX_COSINE_ERROR
        || candidate_far > incumbent_far + f64::EPSILON
    {
        return Err(format!(
            "measured Scalar8 admission fixture failed: recall {:.3}->{:.3}, p99 {}->{}, max_error {:.6}, FAR {:.6}->{:.6}",
            incumbent.recall,
            candidate.recall,
            incumbent.latency_ns,
            candidate.latency_ns,
            candidate_max_error,
            incumbent_far,
            candidate_far
        )
        .into());
    }
    let f32_physical = independent_artifact_read(&f32_artifact)?;
    let scalar_physical = independent_artifact_read(&scalar_artifact)?;
    if f32_physical.digest != f32_receipt.metadata.digest
        || scalar_physical.digest != scalar_receipt.metadata.digest
        || f32_physical.row_count != ADMISSION_ROWS as u64
        || scalar_physical.row_count != ADMISSION_ROWS as u64
        || scalar_physical.packed_vector_bytes != (ADMISSION_ROWS * (ADMISSION_DIM + 8)) as u64
    {
        return Err("admission artifacts did not independently reread as measured".into());
    }
    println!(
        "{{\"event\":\"anneal_admission_measurement\",\"corpus\":\"32 deterministic 4096-D unit-circle records with eight strict off-row queries\",\"rows\":{},\"heldout_queries\":{},\"k\":{},\"f32_recall\":{:.3},\"scalar8_recall\":{:.3},\"f32_p99_ns\":{},\"scalar8_p99_ns\":{},\"f32_mean_cosine_error\":{:.9},\"f32_max_cosine_error\":{:.9},\"scalar8_mean_cosine_error\":{:.9},\"scalar8_max_cosine_error\":{:.9},\"accepted_max_cosine_error\":{:.3},\"f32_far\":{:.6},\"scalar8_far\":{:.6},\"f32_artifact_bytes\":{},\"scalar8_artifact_bytes\":{},\"scalar8_packed_bytes\":{}}}",
        ADMISSION_ROWS,
        queries.len(),
        ADMISSION_K,
        incumbent.recall,
        candidate.recall,
        incumbent.latency_ns,
        candidate.latency_ns,
        incumbent_mean_error,
        incumbent_max_error,
        candidate_mean_error,
        candidate_max_error,
        ADMISSION_MAX_COSINE_ERROR,
        incumbent_far,
        candidate_far,
        f32_physical.artifact_bytes,
        scalar_physical.artifact_bytes,
        scalar_physical.packed_vector_bytes
    );
    Ok(AdmissionFixture {
        f32_artifact,
        scalar_artifact,
        f32_expectation: f32.artifact_expectation(),
        scalar_expectation: scalar.artifact_expectation(),
        queries,
        incumbent,
        candidate,
        quant_evidence: QuantPromotionEvidence {
            cosine_error_before: incumbent_mean_error,
            cosine_error_after: candidate_mean_error,
            max_cosine_error: ADMISSION_MAX_COSINE_ERROR,
            guard_far_before: incumbent_far,
            guard_far_after: candidate_far,
        },
        max_cosine_error: candidate_max_error,
    })
}

fn measure_admission_index(
    index: &HnswIndex,
    rows: &[Vec<f32>],
    queries: &[Vec<f32>],
) -> Result<(CodecMeasurement, f64, f64, f64), Box<dyn std::error::Error>> {
    let mut overlap_total = 0_usize;
    let mut errors = Vec::new();
    for query in queries {
        let truth = exact_top_k(query, rows, ADMISSION_K);
        let hits = index.search(
            &SlotVector::Dense {
                dim: ADMISSION_DIM as u32,
                data: query.clone(),
            },
            ADMISSION_K,
            Some(64),
        )?;
        let got: Vec<_> = hits.iter().map(|hit| hit.cx_id).collect();
        overlap_total += overlap(&got, &truth);
        for (cx_id, score) in index.brute_force(query, rows.len())? {
            let ordinal = u128::from_be_bytes(*cx_id.as_bytes()) as usize;
            errors.push((f64::from(score) - f64::from(cosine(query, &rows[ordinal]))).abs());
        }
    }
    for query in queries {
        let _ = index.search(
            &SlotVector::Dense {
                dim: ADMISSION_DIM as u32,
                data: query.clone(),
            },
            ADMISSION_K,
            Some(64),
        )?;
    }
    let mut sample_ns = Vec::with_capacity(ADMISSION_SAMPLES);
    for _ in 0..ADMISSION_SAMPLES {
        let started = Instant::now();
        for query in queries {
            let _ = index.search(
                &SlotVector::Dense {
                    dim: ADMISSION_DIM as u32,
                    data: query.clone(),
                },
                ADMISSION_K,
                Some(64),
            )?;
        }
        sample_ns.push((started.elapsed().as_nanos() / queries.len() as u128) as u64);
    }
    sample_ns.sort_unstable();
    let p99_index = (sample_ns.len() * 99).div_ceil(100).saturating_sub(1);
    let p99_ns = sample_ns[p99_index];
    let mut far_accepts = 0_usize;
    for (ordinal, row) in rows.iter().enumerate() {
        let far: Vec<f32> = row.iter().map(|value| -*value).collect();
        let score = index
            .brute_force(&far, rows.len())?
            .into_iter()
            .find(|(cx_id, _)| *cx_id == cx(ordinal))
            .ok_or("far-case row disappeared")?
            .1;
        far_accepts += usize::from(score >= 0.7);
    }
    let mean_error = errors.iter().sum::<f64>() / errors.len() as f64;
    let max_error = errors.into_iter().fold(0.0_f64, f64::max);
    Ok((
        CodecMeasurement {
            recall: overlap_total as f64 / (queries.len() * ADMISSION_K) as f64,
            latency_ns: p99_ns,
        },
        mean_error,
        max_error,
        far_accepts as f64 / rows.len() as f64,
    ))
}

fn admission_rows() -> Vec<Vec<f32>> {
    (0..ADMISSION_ROWS)
        .map(|ordinal| {
            let mut row = vec![0.0_f32; ADMISSION_DIM];
            let angle = std::f32::consts::TAU * ordinal as f32 / ADMISSION_ROWS as f32;
            let (sin, cos) = angle.sin_cos();
            row[0] = cos;
            row[1] = sin;
            row
        })
        .collect()
}

fn admission_queries() -> Vec<Vec<f32>> {
    (0..QUERIES)
        .map(|query_ordinal| {
            let mut query = vec![0.0_f32; ADMISSION_DIM];
            let position = query_ordinal as f32 * (ADMISSION_ROWS / QUERIES) as f32 + 0.20;
            let angle = std::f32::consts::TAU * position / ADMISSION_ROWS as f32;
            let (sin, cos) = angle.sin_cos();
            query[0] = cos;
            query[1] = sin;
            query
        })
        .collect()
}

fn anneal_activation_fsv(
    run_dir: &Path,
    fixture: &AdmissionFixture,
) -> Result<(), Box<dyn std::error::Error>> {
    let f32_artifact = &fixture.f32_artifact;
    let candidate_artifact = &fixture.scalar_artifact;
    let queries = &fixture.queries;
    let pointer_path = run_dir.join("slot-7.active.clxhnpt");
    let cache_path = run_dir.join("anneal-cache").join("autotune.json");
    let unconfigured_cache_path = run_dir.join("unconfigured-autotune.json");
    let missing_cache_path = run_dir
        .join("deliberately-missing-cache-parent")
        .join("autotune.json");
    let vault_dir = run_dir.join("anneal-vault");
    let (incumbent, candidate) = anneal_configs();
    let incumbent_hash = config_hash(&incumbent)?;
    let candidate_hash = config_hash(&candidate)?;
    let f32_expectation = fixture.f32_expectation;
    let candidate_expectation = fixture.scalar_expectation;

    let initializer = HnswArtifactActivator::new(&pointer_path, SLOT);
    println!(
        "{{\"event\":\"anneal_initial_pointer_before\",\"pointer_exists\":{},\"incumbent_quant_bits\":32}}",
        pointer_path.exists()
    );
    let initialized = initializer.initialize_active(
        incumbent_hash,
        32,
        f32_artifact,
        f32_expectation,
        queries.len() as u64,
    )?;
    let incumbent_pointer_bytes = std::fs::read(&pointer_path)?;
    let incumbent_physical = independent_pointer_read(&pointer_path)?;
    if initialized.config_hash != incumbent_hash
        || initialized.quant_bits != 32
        || incumbent_physical.config_hash != incumbent_hash
        || incumbent_physical.quant_bits != 32
        || incumbent_physical.kind_tag != 0
        || incumbent_physical.geometry_id != [0_u8; 32]
    {
        return Err("initial active pointer did not bind the F32 incumbent".into());
    }
    println!(
        "{{\"event\":\"anneal_initial_pointer_after\",\"pointer_exists\":true,\"pointer_bytes\":{},\"pointer_digest\":\"{}\",\"artifact_path\":\"{}\",\"artifact_digest\":\"{}\",\"quant_bits\":32}}",
        incumbent_physical.pointer_bytes,
        hex(&incumbent_physical.pointer_digest),
        json(&incumbent_physical.artifact_path),
        hex(&incumbent_physical.artifact_digest)
    );

    let vault_id = ANNEAL_VAULT_ID.parse::<VaultId>()?;
    let vault = AsterVault::open(
        &vault_dir,
        vault_id,
        ANNEAL_VAULT_SALT.to_vec(),
        VaultOptions::default(),
    )?;
    let unconfigured_cache = AutotuneCache::create_empty(&unconfigured_cache_path)?;

    // Edge 1: the default tuner is deliberately incapable of turning a
    // quant_bits metadata win into an administrative-only promotion.
    println!(
        "{{\"event\":\"anneal_unconfigured_before\",\"pointer_digest\":\"{}\",\"cache_exists\":{},\"ledger_rows\":{},\"bandit_rows\":{}}}",
        hex(blake3::hash(&incumbent_pointer_bytes).as_bytes()),
        unconfigured_cache_path.exists(),
        vault
            .scan_cf_at(vault.latest_seq(), ColumnFamily::Ledger)?
            .len(),
        vault
            .scan_cf_at(vault.latest_seq(), ColumnFamily::AnnealBandit)?
            .len()
    );
    let unconfigured_error = {
        let appender = LedgerAppender::open(AsterAnnealLedgerStore::new(&vault), SystemClock)?;
        let ledger = AnnealLedger::new(
            appender,
            ActorId::Service("calyx-553-unconfigured".to_string()),
        )?;
        let bandits = ConfigBanditStore::new(AsterBanditStorage::new(&vault));
        let health = DegradeRegistry::open(Arc::new(SystemClock), AsterHealthStore::new(&vault))?;
        let mut tuner = IndexScopeTuner::with_parts(unconfigured_cache, ledger, bandits, health);
        tuner.install_candidates(SLOT, vec![incumbent.clone(), candidate.clone()])?;
        tuner.on_search_for_arm(
            SLOT,
            0,
            fixture.incumbent.latency_ns,
            fixture.incumbent.recall,
            0.50,
        )?;
        for _ in 0..2 {
            let decision = tuner.on_search_for_arm_with_quant_evidence(
                SLOT,
                1,
                fixture.candidate.latency_ns,
                fixture.candidate.recall,
                0.50,
                Some(fixture.quant_evidence.clone()),
            )?;
            if !decision.won || decision.promoted.is_some() {
                return Err("unconfigured candidate did not remain in hysteresis".into());
            }
        }
        require_error(tuner.on_search_for_arm_with_quant_evidence(
            SLOT,
            1,
            fixture.candidate.latency_ns,
            fixture.candidate.recall,
            0.50,
            Some(fixture.quant_evidence.clone()),
        ))?
    };
    let after_unconfigured = std::fs::read(&pointer_path)?;
    let unconfigured_bandit = persisted_bandit(&vault)?;
    if unconfigured_error.code != CALYX_INDEX_ARTIFACT_ACTIVATION_REQUIRED
        || after_unconfigured != incumbent_pointer_bytes
        || !unconfigured_cache_path.exists()
        || !AutotuneCache::open_existing(&unconfigured_cache_path)?.is_empty()?
        || unconfigured_bandit.incumbent_idx != 0
        || !read_anneal_entries(&vault)?.is_empty()
    {
        return Err("unconfigured Anneal promotion mutated physical state".into());
    }
    println!(
        "{{\"event\":\"anneal_unconfigured_after\",\"error\":\"{}\",\"pointer_unchanged\":true,\"cache_exists\":true,\"cache_entries\":0,\"ledger_rows\":0,\"persisted_bandit_incumbent\":{}}}",
        unconfigured_error.code, unconfigured_bandit.incumbent_idx
    );

    // Edge 2: a real filesystem cache-write failure happens after activation;
    // the transaction must restore the exact prior pointer and bandit bytes.
    println!(
        "{{\"event\":\"anneal_cache_failure_before\",\"pointer_digest\":\"{}\",\"cache_parent_exists\":{},\"ledger_rows\":{}}}",
        hex(blake3::hash(&incumbent_pointer_bytes).as_bytes()),
        missing_cache_path
            .parent()
            .is_some_and(|parent| parent.exists()),
        read_anneal_entries(&vault)?.len()
    );
    let cache_failure = {
        let missing_parent = missing_cache_path
            .parent()
            .ok_or("missing cache failure path has no parent")?;
        std::fs::create_dir_all(missing_parent)?;
        let cache = AutotuneCache::create_empty(&missing_cache_path)?;
        std::fs::remove_file(&missing_cache_path)?;
        std::fs::remove_dir(missing_parent)?;
        let appender = LedgerAppender::open(AsterAnnealLedgerStore::new(&vault), SystemClock)?;
        let ledger = AnnealLedger::new(
            appender,
            ActorId::Service("calyx-553-cache-failure".to_string()),
        )?;
        let bandits = ConfigBanditStore::new(AsterBanditStorage::new(&vault));
        let health = DegradeRegistry::open(Arc::new(SystemClock), AsterHealthStore::new(&vault))?;
        let mut activator = HnswArtifactActivator::new(&pointer_path, SLOT);
        activator.stage_candidate(
            candidate_hash,
            8,
            candidate_artifact,
            candidate_expectation,
            queries.len() as u64,
        )?;
        let mut tuner =
            IndexScopeTuner::with_artifact_parts(cache, ledger, bandits, health, activator);
        tuner.install_candidates(SLOT, vec![incumbent.clone(), candidate.clone()])?;
        tuner.on_search_for_arm(
            SLOT,
            0,
            fixture.incumbent.latency_ns,
            fixture.incumbent.recall,
            0.50,
        )?;
        for _ in 0..2 {
            tuner.on_search_for_arm_with_quant_evidence(
                SLOT,
                1,
                fixture.candidate.latency_ns,
                fixture.candidate.recall,
                0.50,
                Some(fixture.quant_evidence.clone()),
            )?;
        }
        require_error(tuner.on_search_for_arm_with_quant_evidence(
            SLOT,
            1,
            fixture.candidate.latency_ns,
            fixture.candidate.recall,
            0.50,
            Some(fixture.quant_evidence.clone()),
        ))?
    };
    let after_cache_failure = std::fs::read(&pointer_path)?;
    let cache_failure_bandit = persisted_bandit(&vault)?;
    if cache_failure.code != CALYX_INDEX_CACHE_WRITE_FAIL
        || after_cache_failure != incumbent_pointer_bytes
        || missing_cache_path.exists()
        || cache_failure_bandit.incumbent_idx != 0
        || !read_anneal_entries(&vault)?.is_empty()
    {
        return Err("cache failure did not atomically roll back the promotion".into());
    }
    println!(
        "{{\"event\":\"anneal_cache_failure_after\",\"error\":\"{}\",\"pointer_rolled_back_exactly\":true,\"cache_exists\":false,\"ledger_rows\":0,\"persisted_bandit_incumbent\":{}}}",
        cache_failure.code, cache_failure_bandit.incumbent_idx
    );

    // Happy path: physical pointer, persistent cache, persistent bandit, and
    // append-only Anneal ledger all advance as one observed promotion.
    std::fs::create_dir_all(cache_path.parent().ok_or("cache parent missing")?)?;
    println!(
        "{{\"event\":\"anneal_promotion_before\",\"pointer_quant_bits\":32,\"pointer_digest\":\"{}\",\"cache_exists\":{},\"ledger_rows\":{},\"bandit_incumbent\":{}}}",
        hex(blake3::hash(&incumbent_pointer_bytes).as_bytes()),
        cache_path.exists(),
        read_anneal_entries(&vault)?.len(),
        persisted_bandit(&vault)?.incumbent_idx
    );
    let promotion = {
        let cache = AutotuneCache::create_empty(&cache_path)?;
        let appender = LedgerAppender::open(AsterAnnealLedgerStore::new(&vault), SystemClock)?;
        let ledger = AnnealLedger::new(
            appender,
            ActorId::Service("calyx-553-production-activation".to_string()),
        )?;
        let bandits = ConfigBanditStore::new(AsterBanditStorage::new(&vault));
        let health = DegradeRegistry::open(Arc::new(SystemClock), AsterHealthStore::new(&vault))?;
        let mut activator = HnswArtifactActivator::new(&pointer_path, SLOT);
        activator.stage_candidate(
            candidate_hash,
            8,
            candidate_artifact,
            candidate_expectation,
            queries.len() as u64,
        )?;
        let mut tuner =
            IndexScopeTuner::with_artifact_parts(cache, ledger, bandits, health, activator);
        tuner.install_candidates(SLOT, vec![incumbent.clone(), candidate.clone()])?;
        tuner.on_search_for_arm(
            SLOT,
            0,
            fixture.incumbent.latency_ns,
            fixture.incumbent.recall,
            0.50,
        )?;
        for _ in 0..2 {
            tuner.on_search_for_arm_with_quant_evidence(
                SLOT,
                1,
                fixture.candidate.latency_ns,
                fixture.candidate.recall,
                0.50,
                Some(fixture.quant_evidence.clone()),
            )?;
        }
        tuner
            .on_search_for_arm_with_quant_evidence(
                SLOT,
                1,
                fixture.candidate.latency_ns,
                fixture.candidate.recall,
                0.50,
                Some(fixture.quant_evidence.clone()),
            )?
            .promoted
            .ok_or("measured Scalar8 candidate did not promote")?
    };
    vault.flush()?;

    let active_pointer_bytes = std::fs::read(&pointer_path)?;
    let active_physical = independent_pointer_read(&pointer_path)?;
    let cache_bytes = std::fs::read(&cache_path)?;
    let cache_json: serde_json::Value = serde_json::from_slice(&cache_bytes)?;
    let cache_has_quant8 = cache_json["entries"].as_array().is_some_and(|entries| {
        entries
            .iter()
            .any(|entry| entry["config"]["extra"]["quant_bits"].as_str() == Some("8"))
    });
    let bandit = persisted_bandit(&vault)?;
    let anneal_entries = read_anneal_entries(&vault)?;
    let ledger_entry = anneal_entries
        .last()
        .ok_or("persisted Anneal promotion ledger row missing")?;
    let ledger_activation = ledger_entry
        .details
        .as_ref()
        .ok_or("persisted Anneal promotion activation details missing")?;
    let served_bits = ledger_activation["served_quant_bits"].as_u64();
    let ledger_artifact_bytes = ledger_activation["candidate_artifact_bytes"].as_u64();
    let ledger_heldout = ledger_activation["heldout_query_count"].as_u64();
    let ledger_cosine_after = ledger_activation["cosine_error_after"].as_f64();
    let (active_index, active) = HnswArtifactActivator::new(&pointer_path, SLOT).open_active()?;
    let live_hits = active_index.search(
        &SlotVector::Dense {
            dim: ADMISSION_DIM as u32,
            data: queries[0].clone(),
        },
        ADMISSION_K,
        Some(64),
    )?;
    if active_pointer_bytes == incumbent_pointer_bytes
        || active_physical.config_hash != candidate_hash
        || active_physical.quant_bits != 8
        || active_physical.kind_tag != 1
        || active_physical.geometry_id != [0_u8; 32]
        || active.config_hash != candidate_hash
        || active.quant_bits != 8
        || promotion.served_artifact.is_none()
        || !cache_has_quant8
        || bandit.incumbent_idx != 1
        || anneal_entries.len() != 1
        || ledger_entry.action != AnnealLedgerAction::AutotunePromote
        || served_bits != Some(8)
        || ledger_artifact_bytes != Some(active_physical.artifact_bytes)
        || ledger_heldout != Some(queries.len() as u64)
        || ledger_cosine_after != Some(fixture.quant_evidence.cosine_error_after)
        || promotion.latency_before_ns != fixture.incumbent.latency_ns
        || promotion.latency_after_ns != fixture.candidate.latency_ns
        || promotion.recall_before != fixture.incumbent.recall
        || promotion.recall_after != fixture.candidate.recall
        || fixture.max_cosine_error > fixture.quant_evidence.max_cosine_error
        || live_hits.len() != ADMISSION_K
    {
        return Err("successful Anneal promotion state is incomplete or inconsistent".into());
    }
    println!(
        "{{\"event\":\"anneal_promotion_after\",\"pointer_quant_bits\":8,\"codec\":\"scalar8\",\"measured_recall_before\":{:.3},\"measured_recall_after\":{:.3},\"measured_p99_ns_before\":{},\"measured_p99_ns_after\":{},\"measured_mean_cosine_error_after\":{:.9},\"measured_max_cosine_error_after\":{:.9},\"pointer_bytes\":{},\"pointer_digest\":\"{}\",\"artifact_path\":\"{}\",\"artifact_bytes\":{},\"artifact_digest\":\"{}\",\"cache_bytes\":{},\"cache_quant_bits\":8,\"persisted_bandit_incumbent\":{},\"ledger_rows\":{},\"ledger_action\":\"autotune_promote\",\"ledger_served_quant_bits\":{},\"live_search_hits\":{}}}",
        fixture.incumbent.recall,
        fixture.candidate.recall,
        fixture.incumbent.latency_ns,
        fixture.candidate.latency_ns,
        fixture.quant_evidence.cosine_error_after,
        fixture.max_cosine_error,
        active_physical.pointer_bytes,
        hex(&active_physical.pointer_digest),
        json(&active_physical.artifact_path),
        active_physical.artifact_bytes,
        hex(&active_physical.artifact_digest),
        cache_bytes.len(),
        bandit.incumbent_idx,
        anneal_entries.len(),
        served_bits.unwrap_or_default(),
        live_hits.len()
    );
    drop(vault);

    let restart = spawn_anneal_reload(run_dir)?;
    if !restart.status.success()
        || !restart
            .stdout
            .contains("\"event\":\"anneal_reload_success\"")
    {
        return Err(format!(
            "Anneal child-process restart failed status={} stdout={} stderr={}",
            restart.status, restart.stdout, restart.stderr
        )
        .into());
    }
    println!(
        "{{\"event\":\"anneal_restart_readback\",\"child_readback\":{}}}",
        restart.stdout.trim()
    );

    edge_pointer_state(
        &pointer_path,
        f32_artifact,
        f32_expectation,
        incumbent_hash,
        candidate_hash,
    )?;
    Ok(())
}

fn child_anneal_reload() -> Result<(), Box<dyn std::error::Error>> {
    let run_dir = PathBuf::from(
        std::env::args()
            .nth(2)
            .ok_or("Anneal reload run directory missing")?,
    );
    let pointer_path = run_dir.join("slot-7.active.clxhnpt");
    let cache_path = run_dir.join("anneal-cache").join("autotune.json");
    let vault_dir = run_dir.join("anneal-vault");
    let (index, active) = HnswArtifactActivator::new(&pointer_path, SLOT).open_active()?;
    let (_, candidate) = anneal_configs();
    let candidate_hash = config_hash(&candidate)?;
    let cache = AutotuneCache::open_existing(&cache_path)?;
    let cached = cache
        .get(&slot_autotune_key(SLOT, 0.99))?
        .ok_or("restarted autotune cache has no slot-7 entry")?;
    let cached_config = IndexConfig::from_best_config(cached)?;
    let vault = AsterVault::open(
        &vault_dir,
        ANNEAL_VAULT_ID.parse::<VaultId>()?,
        ANNEAL_VAULT_SALT.to_vec(),
        VaultOptions::default(),
    )?;
    let bandit = persisted_bandit(&vault)?;
    let entries = read_anneal_entries(&vault)?;
    let queries = admission_queries();
    let query = &queries[0];
    let hits = index.search(
        &SlotVector::Dense {
            dim: ADMISSION_DIM as u32,
            data: query.clone(),
        },
        ADMISSION_K,
        Some(64),
    )?;
    if active.config_hash != candidate_hash
        || active.quant_bits != 8
        || active.expectation.quant_kind != QuantKind::Scalar8
        || cached_config.quant_bits != 8
        || bandit.incumbent_idx != 1
        || entries.len() != 1
        || entries[0].action != AnnealLedgerAction::AutotunePromote
        || hits.len() != ADMISSION_K
    {
        return Err("restart did not recover the complete promoted state".into());
    }
    println!(
        "{{\"event\":\"anneal_reload_success\",\"pointer_quant_bits\":{},\"artifact_bytes\":{},\"artifact_digest\":\"{}\",\"cache_quant_bits\":{},\"bandit_incumbent\":{},\"ledger_rows\":{},\"search_hits\":{}}}",
        active.quant_bits,
        active.artifact_bytes,
        hex(&active.artifact_digest),
        cached_config.quant_bits,
        bandit.incumbent_idx,
        entries.len(),
        hits.len()
    );
    Ok(())
}

fn edge_pointer_state(
    pointer_path: &Path,
    f32_artifact: &Path,
    f32_expectation: HnswArtifactExpectation,
    incumbent_hash: [u8; 32],
    candidate_hash: [u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    let valid = std::fs::read(pointer_path)?;
    let valid_hash = *blake3::hash(&valid).as_bytes();
    let active = HnswArtifactActivator::new(pointer_path, SLOT)
        .open_active()?
        .1;
    println!(
        "{{\"event\":\"edge_pointer_before\",\"pointer_hash\":\"{}\",\"quant_bits\":{},\"artifact_digest\":\"{}\"}}",
        hex(&valid_hash),
        active.quant_bits,
        hex(&active.artifact_digest)
    );

    let unstaged_error = {
        let mut activator = HnswArtifactActivator::new(pointer_path, SLOT);
        require_error(activator.stage_candidate(
            [0x55_u8; 32],
            32,
            f32_artifact,
            f32_expectation,
            0,
        ))?
    };
    if std::fs::read(pointer_path)? != valid {
        return Err("zero-heldout staging attempt mutated the active pointer".into());
    }

    let stale_error = {
        let mut activator = HnswArtifactActivator::new(pointer_path, SLOT);
        activator.stage_candidate(
            incumbent_hash,
            32,
            f32_artifact,
            f32_expectation,
            QUERIES as u64,
        )?;
        require_error(activator.activate(&IndexArtifactPromotionRequest {
            slot_id: SLOT,
            prior_config_hash: incumbent_hash,
            candidate_config_hash: incumbent_hash,
            prior_quant_bits: 32,
            candidate_quant_bits: 32,
        }))?
    };
    if std::fs::read(pointer_path)? != valid {
        return Err("stale activation attempt mutated the active pointer".into());
    }

    let mut corrupt = valid.clone();
    corrupt[28] ^= 0x80;
    std::fs::write(pointer_path, &corrupt)?;
    let corrupt_error = require_error(
        HnswArtifactActivator::new(pointer_path, SLOT)
            .open_active()
            .map(|_| ()),
    )?;
    std::fs::write(pointer_path, &valid)?;
    let restored = HnswArtifactActivator::new(pointer_path, SLOT)
        .open_active()?
        .1;
    let after = std::fs::read(pointer_path)?;
    if unstaged_error.code != CALYX_SEXTANT_HNSW_POINTER_UNSTAGED
        || stale_error.code != CALYX_SEXTANT_HNSW_POINTER_STALE
        || corrupt_error.code != CALYX_SEXTANT_HNSW_POINTER_CORRUPT
        || after != valid
        || restored.config_hash != candidate_hash
    {
        return Err("active-pointer edge handling or restoration failed".into());
    }
    println!(
        "{{\"event\":\"edge_pointer_after\",\"zero_heldout_error\":\"{}\",\"stale_error\":\"{}\",\"corrupt_error\":\"{}\",\"pointer_restored_exactly\":true,\"pointer_hash\":\"{}\",\"quant_bits\":{}}}",
        unstaged_error.code,
        stale_error.code,
        corrupt_error.code,
        hex(blake3::hash(&after).as_bytes()),
        restored.quant_bits
    );
    Ok(())
}

fn anneal_configs() -> (IndexConfig, IndexConfig) {
    let incumbent = IndexConfig {
        hnsw_ef: 64,
        hnsw_m: 16,
        diskann_beamwidth: 32,
        spann_cutoff: 1024,
        quant_bits: 32,
    };
    let candidate = IndexConfig {
        quant_bits: 8,
        ..incumbent.clone()
    };
    (incumbent, candidate)
}

fn config_hash(config: &IndexConfig) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    Ok(*blake3::hash(&encode_index_config(config)?).as_bytes())
}

fn persisted_bandit(
    vault: &AsterVault,
) -> Result<calyx_anneal::ConfigBandit, Box<dyn std::error::Error>> {
    let key = bandit_key(shape_key_hash(&index_slot_label(SLOT)));
    let bytes = vault
        .read_cf_at(vault.latest_seq(), ColumnFamily::AnnealBandit, &key)?
        .ok_or("persisted slot-7 Anneal bandit row missing")?;
    Ok(decode_config_bandit(&bytes)?)
}

fn read_anneal_entries(
    vault: &AsterVault,
) -> Result<Vec<calyx_anneal::AnnealLedgerEntry>, Box<dyn std::error::Error>> {
    let appender = LedgerAppender::open(AsterAnnealLedgerStore::new(vault), SystemClock)?;
    let ledger = AnnealLedger::new(
        appender,
        ActorId::Service("calyx-553-ledger-readback".to_string()),
    )?;
    Ok(ledger.read_recent(32)?)
}

fn spawn_anneal_reload(run_dir: &Path) -> Result<ChildOutput, Box<dyn std::error::Error>> {
    let output = Command::new(std::env::current_exe()?)
        .arg("--anneal-reload")
        .arg(run_dir)
        .output()?;
    Ok(ChildOutput {
        status: output.status,
        stdout: String::from_utf8(output.stdout)?,
        stderr: String::from_utf8(output.stderr)?,
    })
}

fn edge_empty(run_dir: &Path, queries: &[Vec<f32>]) -> Result<(), Box<dyn std::error::Error>> {
    let path = run_dir.join("edge-empty.clxhnsw");
    let mut index =
        HnswIndex::new(SlotId::new(8), DIM as u32, 553).with_quant(QuantConfig::binary())?;
    index.set_base_seq(800);
    println!(
        "{{\"event\":\"edge_empty_before\",\"artifact_exists\":{},\"rows_in_memory\":0}}",
        path.exists()
    );
    index.persist_artifact(&path)?;
    let readback = independent_artifact_read(&path)?;
    let search_error = require_error(index.search(
        &SlotVector::Dense {
            dim: DIM as u32,
            data: queries[0].clone(),
        },
        K,
        None,
    ))?;
    println!(
        "{{\"event\":\"edge_empty_after\",\"artifact_exists\":true,\"persisted_rows\":{},\"artifact_bytes\":{},\"search_error\":\"{}\"}}",
        readback.row_count, readback.artifact_bytes, search_error.code
    );
    Ok(())
}

fn edge_limits(run_dir: &Path, rows: &[Vec<f32>]) -> Result<(), Box<dyn std::error::Error>> {
    let path = run_dir.join("edge-max-dim-turboquant3p5.clxhnsw");
    let mut max_data = Vec::with_capacity(HNSW_MAX_DIM as usize);
    for index in 0..HNSW_MAX_DIM as usize {
        max_data.push(rows[index % rows.len()][index % DIM]);
    }
    let mut max_index = HnswIndex::new(SlotId::new(9), HNSW_MAX_DIM, 553).with_quant(
        QuantConfig::turboquant_structured(
            new_seed(HNSW_MAX_DIM as usize, b"calyx/sextant/hnsw/max-dim/fsv-v1"),
            QuantLevel::Bits3p5,
        )?,
    )?;
    println!(
        "{{\"event\":\"edge_limits_before\",\"max_dim_artifact_exists\":{},\"over_limit_rows\":0}}",
        path.exists()
    );
    max_index.insert(
        cx(90_000),
        SlotVector::Dense {
            dim: HNSW_MAX_DIM,
            data: max_data,
        },
        1,
    )?;
    max_index.set_base_seq(900);
    max_index.persist_artifact(&path)?;
    let physical = independent_artifact_read(&path)?;
    let max_candidate_hits = max_index.search(
        &SlotVector::Dense {
            dim: HNSW_MAX_DIM,
            data: rows[0]
                .iter()
                .copied()
                .cycle()
                .take(HNSW_MAX_DIM as usize)
                .collect(),
        },
        usize::MAX,
        Some(usize::MAX),
    )?;
    let over_dim = HNSW_MAX_DIM + 1;
    let over_error = require_error(QuantConfig::turboquant_structured(
        new_seed(over_dim as usize, b"calyx/sextant/hnsw/over-dim/fsv-v1"),
        QuantLevel::Bits3p5,
    ))?;
    println!(
        "{{\"event\":\"edge_limits_after\",\"codec\":\"turboquant3p5\",\"max_dim\":{},\"max_dim_rows\":{},\"max_dim_packed_vector_bytes\":{},\"max_candidate_request\":\"usize::MAX\",\"max_candidate_hits\":{},\"over_dim\":{},\"over_limit_rows\":{},\"over_limit_error\":\"{}\"}}",
        HNSW_MAX_DIM,
        physical.row_count,
        physical.packed_vector_bytes,
        max_candidate_hits.len(),
        over_dim,
        0,
        over_error.code
    );
    Ok(())
}

fn edge_invalid_config() -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "{{\"event\":\"edge_invalid_config_before\",\"rows_in_memory\":{},\"scale\":\"NaN\"}}",
        0
    );
    let error = require_error(
        HnswIndex::new(SlotId::new(11), DIM as u32, 553).with_quant(QuantConfig::scalar8(f32::NAN)),
    )?;
    let mismatch_error = packed_kind_mismatch(&vec![1.0; DIM])?;
    let unsupported_backend_error = require_error(
        QuantConfig::turboquant_structured(new_seed(DIM, TURBOQUANT_SEED), QuantLevel::Bits3p5)?
            .cpu_gpu_delta(&vec![1.0; DIM]),
    )?;
    println!(
        "{{\"event\":\"edge_invalid_config_after\",\"rows_in_memory\":{},\"invalid_config_error\":\"{}\",\"mismatched_kernel_error\":\"{}\",\"unsupported_backend_error\":\"{}\"}}",
        0, error.code, mismatch_error.code, unsupported_backend_error.code
    );
    Ok(())
}

fn edge_corrupt_stale_unsupported(
    run_dir: &Path,
    valid_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let valid = std::fs::read(valid_path)?;
    let valid_hash = blake3::hash(&valid);
    let expected = HnswArtifactExpectation {
        slot: SLOT,
        dim: DIM as u32,
        quant_kind: QuantKind::TurboQuant3p5,
        quant_geometry_id: QuantConfig::turboquant_structured(
            new_seed(DIM, TURBOQUANT_SEED),
            QuantLevel::Bits3p5,
        )?
        .geometry_id(),
        base_seq: BASE_SEQ,
    };
    println!(
        "{{\"event\":\"edge_bytes_before\",\"valid_path\":\"{}\",\"valid_hash\":\"{}\",\"valid_bytes\":{}}}",
        json(&valid_path.display().to_string()),
        valid_hash.to_hex(),
        valid.len()
    );

    let corrupt_path = run_dir.join("edge-corrupt.clxhnsw");
    let mut corrupt = valid.clone();
    corrupt[HEADER_BYTES] ^= 0x40;
    std::fs::write(&corrupt_path, &corrupt)?;
    let corrupt_error = require_error(HnswIndex::load_artifact(&corrupt_path, expected))?;

    let malformed_path = run_dir.join("edge-malformed-tqpr-row.clxhnsw");
    let mut malformed = valid.clone();
    let first_tqpr_body_byte = HEADER_BYTES + 30 + 4 + TURBOQUANT_FORMAT_HEADER_BYTES;
    malformed[first_tqpr_body_byte] ^= 0x01;
    reseal(&mut malformed)?;
    std::fs::write(&malformed_path, &malformed)?;
    let malformed_error = require_error(HnswIndex::load_artifact(&malformed_path, expected))?;

    let stale_error = require_error(HnswIndex::load_artifact(
        valid_path,
        HnswArtifactExpectation {
            base_seq: BASE_SEQ + 1,
            ..expected
        },
    ))?;

    let wrong_dim_error = require_error(HnswIndex::load_artifact(
        valid_path,
        HnswArtifactExpectation {
            dim: DIM as u32 - 1,
            ..expected
        },
    ))?;

    let wrong_geometry_error = require_error(HnswIndex::load_artifact(
        valid_path,
        HnswArtifactExpectation {
            quant_geometry_id: [0xA5_u8; 32],
            ..expected
        },
    ))?;

    let unsupported_path = run_dir.join("edge-unsupported-version.clxhnsw");
    let mut unsupported = valid.clone();
    unsupported[8..10].copy_from_slice(&(HNSW_ARTIFACT_VERSION + 1).to_le_bytes());
    reseal(&mut unsupported)?;
    std::fs::write(&unsupported_path, &unsupported)?;
    let unsupported_error = require_error(HnswIndex::load_artifact(&unsupported_path, expected))?;

    let after_valid = std::fs::read(valid_path)?;
    if after_valid != valid {
        return Err("edge actions mutated the valid source artifact".into());
    }
    println!(
        "{{\"event\":\"edge_bytes_after\",\"valid_hash\":\"{}\",\"valid_unchanged\":true,\"corrupt_file_exists\":{},\"corrupt_error\":\"{}\",\"malformed_tqpr_file_exists\":{},\"malformed_tqpr_error\":\"{}\",\"stale_error\":\"{}\",\"wrong_dim_error\":\"{}\",\"wrong_geometry_error\":\"{}\",\"unsupported_file_exists\":{},\"unsupported_error\":\"{}\"}}",
        blake3::hash(&after_valid).to_hex(),
        corrupt_path.exists(),
        corrupt_error.code,
        malformed_path.exists(),
        malformed_error.code,
        stale_error.code,
        wrong_dim_error.code,
        wrong_geometry_error.code,
        unsupported_path.exists(),
        unsupported_error.code
    );
    Ok(())
}

struct ChildOutput {
    status: std::process::ExitStatus,
    stdout: String,
    stderr: String,
}

fn spawn_reload(path: &Path, name: &str) -> Result<ChildOutput, Box<dyn std::error::Error>> {
    let output = Command::new(std::env::current_exe()?)
        .arg("--reload")
        .arg(path)
        .arg(name)
        .output()?;
    Ok(ChildOutput {
        status: output.status,
        stdout: String::from_utf8(output.stdout)?,
        stderr: String::from_utf8(output.stderr)?,
    })
}

struct PhysicalReadback {
    magic: [u8; 8],
    version: u16,
    layout: u8,
    kind_tag: u8,
    slot: u16,
    dim: u32,
    base_seq: u64,
    geometry_id: [u8; 32],
    row_count: u64,
    packed_vector_bytes: u64,
    body_bytes: u64,
    artifact_bytes: u64,
    digest: [u8; 32],
    tqpr_rows: u64,
    first_tqpr_digest: [u8; 32],
}

struct PointerPhysicalReadback {
    quant_bits: u8,
    kind_tag: u8,
    geometry_id: [u8; 32],
    config_hash: [u8; 32],
    artifact_digest: [u8; 32],
    artifact_bytes: u64,
    artifact_path: String,
    pointer_bytes: u64,
    pointer_digest: [u8; 32],
}

fn independent_pointer_read(
    path: &Path,
) -> Result<PointerPhysicalReadback, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)?;
    if bytes.len() < POINTER_HEADER_BYTES + FOOTER_BYTES {
        return Err(format!("{} active pointer is truncated", path.display()).into());
    }
    if bytes[0..8] != HNSW_ACTIVE_POINTER_MAGIC
        || u16::from_le_bytes(bytes[8..10].try_into()?) != HNSW_ACTIVE_POINTER_VERSION
        || u16::from_le_bytes(bytes[10..12].try_into()?) != SLOT.get()
    {
        return Err(format!("{} active pointer identity mismatch", path.display()).into());
    }
    let payload_len = bytes.len() - FOOTER_BYTES;
    let mut pointer_digest = [0_u8; 32];
    pointer_digest.copy_from_slice(&bytes[payload_len..]);
    if pointer_digest != *blake3::hash(&bytes[..payload_len]).as_bytes() {
        return Err(format!("{} active pointer checksum mismatch", path.display()).into());
    }
    let path_len = u32::from_le_bytes(bytes[140..144].try_into()?) as usize;
    if POINTER_HEADER_BYTES + path_len != payload_len {
        return Err(format!("{} active pointer length mismatch", path.display()).into());
    }
    let artifact_path = std::str::from_utf8(&bytes[POINTER_HEADER_BYTES..payload_len])?.to_string();
    let mut config_hash = [0_u8; 32];
    config_hash.copy_from_slice(&bytes[60..92]);
    let mut geometry_id = [0_u8; 32];
    geometry_id.copy_from_slice(&bytes[28..60]);
    let mut artifact_digest = [0_u8; 32];
    artifact_digest.copy_from_slice(&bytes[92..124]);
    let artifact_bytes = u64::from_le_bytes(bytes[124..132].try_into()?);
    let artifact_physical = independent_artifact_read(Path::new(&artifact_path))?;
    if artifact_physical.artifact_bytes != artifact_bytes
        || artifact_physical.digest != artifact_digest
        || artifact_physical.kind_tag != bytes[13]
        || artifact_physical.geometry_id != geometry_id
    {
        return Err("active pointer artifact digest/length readback mismatch".into());
    }
    Ok(PointerPhysicalReadback {
        quant_bits: bytes[12],
        kind_tag: bytes[13],
        geometry_id,
        config_hash,
        artifact_digest,
        artifact_bytes,
        artifact_path,
        pointer_bytes: bytes.len() as u64,
        pointer_digest,
    })
}

fn independent_artifact_read(path: &Path) -> Result<PhysicalReadback, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)?;
    if bytes.len() < HEADER_BYTES + FOOTER_BYTES {
        return Err(format!("{} is truncated", path.display()).into());
    }
    let payload_len = bytes.len() - FOOTER_BYTES;
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(&bytes[payload_len..]);
    let computed = *blake3::hash(&bytes[..payload_len]).as_bytes();
    if digest != computed {
        return Err(format!("{} independent checksum mismatch", path.display()).into());
    }
    let body_bytes = u64::from_le_bytes(bytes[178..186].try_into()?);
    if HEADER_BYTES as u64 + body_bytes + FOOTER_BYTES as u64 != bytes.len() as u64 {
        return Err(format!("{} independent length mismatch", path.display()).into());
    }
    let kind_tag = bytes[11];
    let dim = u32::from_le_bytes(bytes[14..18].try_into()?);
    let geometry_id: [u8; 32] = bytes[122..154].try_into()?;
    let row_count = u64::from_le_bytes(bytes[154..162].try_into()?);
    let mut cursor = HEADER_BYTES;
    let mut tqpr_rows = 0_u64;
    let mut first_tqpr_digest = [0_u8; 32];
    for ordinal in 0..row_count {
        let fixed_end = cursor.checked_add(30).ok_or("row cursor overflow")?;
        let fixed = bytes
            .get(cursor..fixed_end)
            .ok_or("artifact row fixed fields are truncated")?;
        let neighbor_count = u32::from_le_bytes(fixed[26..30].try_into()?) as usize;
        cursor = fixed_end;
        let vector_bytes = match kind_tag {
            0 => dim as usize * 4,
            1 => dim as usize + 4,
            2 => (dim as usize).div_ceil(8),
            3 | 4 => {
                let pair_bits = if kind_tag == 3 { 3 } else { 5 };
                let odd_bits = if kind_tag == 3 { 2 } else { 3 };
                let scalar_bits = dim as usize / 2 * pair_bits + dim as usize % 2 * odd_bits;
                let payload_len = TURBOQUANT_FORMAT_HEADER_BYTES
                    + scalar_bits.div_ceil(8)
                    + (dim as usize).div_ceil(8);
                let row_end = cursor
                    .checked_add(4 + payload_len)
                    .ok_or("TQPR row length overflow")?;
                let row = bytes.get(cursor..row_end).ok_or("TQPR row is truncated")?;
                let source_norm = f32::from_bits(u32::from_le_bytes(row[0..4].try_into()?));
                let payload = &row[4..];
                let expected_level = if kind_tag == 3 { 1 } else { 2 };
                if !source_norm.is_finite()
                    || source_norm.is_sign_negative()
                    || &payload[0..4] != b"TQPR"
                    || payload[4] != 2
                    || payload[5] != expected_level
                    || u32::from_le_bytes(payload[8..12].try_into()?) != dim
                    || payload[24..56] != geometry_id
                {
                    return Err(format!(
                        "row {ordinal} independently parsed TQPR identity is invalid"
                    )
                    .into());
                }
                let mut hasher = Sha256::new();
                hasher.update(b"calyx/turboquant/tqpr/payload/v2\0");
                hasher.update(56_u64.to_le_bytes());
                hasher.update(&payload[..56]);
                hasher.update(((payload.len() - 88) as u64).to_le_bytes());
                hasher.update(&payload[88..]);
                hasher.update(source_norm.to_bits().to_le_bytes());
                let computed: [u8; 32] = hasher.finalize().into();
                if payload[56..88] != computed {
                    return Err(format!(
                        "row {ordinal} independently parsed TQPR SHA-256 mismatch"
                    )
                    .into());
                }
                if tqpr_rows == 0 {
                    first_tqpr_digest = computed;
                }
                tqpr_rows += 1;
                4 + payload_len
            }
            tag => return Err(format!("artifact codec tag {tag} is unknown").into()),
        };
        cursor = cursor
            .checked_add(vector_bytes)
            .and_then(|value| value.checked_add(neighbor_count * 4))
            .ok_or("artifact row cursor overflow")?;
        if cursor > payload_len {
            return Err(format!("row {ordinal} exceeds the artifact body").into());
        }
    }
    if cursor != payload_len {
        return Err(
            format!("independent row parse ended at {cursor}, expected {payload_len}").into(),
        );
    }
    Ok(PhysicalReadback {
        magic: bytes[0..8].try_into()?,
        version: u16::from_le_bytes(bytes[8..10].try_into()?),
        layout: bytes[10],
        kind_tag,
        slot: u16::from_le_bytes(bytes[12..14].try_into()?),
        dim,
        base_seq: u64::from_le_bytes(bytes[30..38].try_into()?),
        geometry_id,
        row_count,
        packed_vector_bytes: u64::from_le_bytes(bytes[170..178].try_into()?),
        body_bytes,
        artifact_bytes: bytes.len() as u64,
        digest,
        tqpr_rows,
        first_tqpr_digest,
    })
}

fn reseal(bytes: &mut [u8]) -> Result<(), Box<dyn std::error::Error>> {
    if bytes.len() < FOOTER_BYTES {
        return Err("cannot reseal a truncated artifact".into());
    }
    let payload_len = bytes.len() - FOOTER_BYTES;
    let digest = blake3::hash(&bytes[..payload_len]);
    bytes[payload_len..].copy_from_slice(digest.as_bytes());
    Ok(())
}

fn require_error<T>(
    result: Result<T, CalyxError>,
) -> Result<CalyxError, Box<dyn std::error::Error>> {
    match result {
        Ok(_) => Err("operation unexpectedly succeeded".into()),
        Err(error) => Ok(error),
    }
}

#[cfg(windows)]
fn process_rss_bytes() -> Result<u64, Box<dyn std::error::Error>> {
    use windows_sys::Win32::System::ProcessStatus::{
        GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    let mut counters = PROCESS_MEMORY_COUNTERS {
        cb: std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        PageFaultCount: 0,
        PeakWorkingSetSize: 0,
        WorkingSetSize: 0,
        QuotaPeakPagedPoolUsage: 0,
        QuotaPagedPoolUsage: 0,
        QuotaPeakNonPagedPoolUsage: 0,
        QuotaNonPagedPoolUsage: 0,
        PagefileUsage: 0,
        PeakPagefileUsage: 0,
    };
    // SAFETY: `counters` is a correctly sized writable PROCESS_MEMORY_COUNTERS
    // for the current pseudo-handle and remains alive for the entire call.
    let read = unsafe {
        GetProcessMemoryInfo(
            GetCurrentProcess(),
            &mut counters,
            std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        )
    };
    if read == 0 {
        return Err(format!(
            "GetProcessMemoryInfo failed: {}",
            std::io::Error::last_os_error()
        )
        .into());
    }
    Ok(counters.WorkingSetSize as u64)
}

fn cx(ordinal: usize) -> CxId {
    CxId::from_bytes((ordinal as u128).to_be_bytes())
}

fn measured_scale(rows: &[Vec<f32>]) -> f32 {
    rows.iter()
        .flatten()
        .fold(0.0_f32, |max_abs, value| max_abs.max(value.abs()))
        / 127.0
}

fn exact_top_k(query: &[f32], rows: &[Vec<f32>], k: usize) -> Vec<CxId> {
    let mut scored: Vec<(usize, f32)> = rows
        .iter()
        .enumerate()
        .map(|(ordinal, row)| (ordinal, cosine(query, row)))
        .collect();
    scored.sort_by(|left, right| right.1.total_cmp(&left.1).then(left.0.cmp(&right.0)));
    scored.truncate(k);
    scored.into_iter().map(|(ordinal, _)| cx(ordinal)).collect()
}

fn overlap(got: &[CxId], truth: &[CxId]) -> usize {
    got.iter().filter(|cx_id| truth.contains(cx_id)).count()
}

fn cosine(left: &[f32], right: &[f32]) -> f32 {
    let mut dot = 0.0_f64;
    let mut left_norm = 0.0_f64;
    let mut right_norm = 0.0_f64;
    for (a, b) in left.iter().zip(right) {
        dot += f64::from(*a) * f64::from(*b);
        left_norm += f64::from(*a) * f64::from(*a);
        right_norm += f64::from(*b) * f64::from(*b);
    }
    if left_norm == 0.0 || right_norm == 0.0 {
        0.0
    } else {
        (dot / (left_norm.sqrt() * right_norm.sqrt())) as f32
    }
}

fn real_corpus_vectors(count: usize) -> Result<Vec<Vec<f32>>, Box<dyn std::error::Error>> {
    let mut files = Vec::new();
    let mut stack = vec![PathBuf::from("calyx/crates/calyx-sextant/src")];
    if !stack[0].exists() {
        stack = vec![PathBuf::from("src")];
    }
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                files.push(path);
            }
        }
    }
    files.sort();
    let mut vectors = Vec::with_capacity(count);
    'files: for path in files {
        let bytes = std::fs::read(path)?;
        for chunk in bytes.chunks(2_048) {
            if chunk.len() < 256 {
                continue;
            }
            let mut histogram = [0.0_f32; DIM];
            for byte in chunk {
                histogram[usize::from(*byte) % DIM] += 1.0;
            }
            let mean = histogram.iter().sum::<f32>() / DIM as f32;
            let vector: Vec<f32> = histogram.iter().map(|value| value - mean).collect();
            if vector.iter().all(|value| *value == 0.0) {
                continue;
            }
            vectors.push(vector);
            if vectors.len() == count {
                break 'files;
            }
        }
    }
    if vectors.len() != count {
        return Err(format!("real corpus yielded {} of {count} vectors", vectors.len()).into());
    }
    Ok(vectors)
}

fn count_files(root: &Path) -> Result<u64, Box<dyn std::error::Error>> {
    let mut count = 0_u64;
    for entry in std::fs::read_dir(root)? {
        if entry?.file_type()?.is_file() {
            count += 1;
        }
    }
    Ok(count)
}

fn count_bytes(root: &Path) -> Result<u64, Box<dyn std::error::Error>> {
    let mut total = 0_u64;
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            total = total.saturating_add(entry.metadata()?.len());
        }
    }
    Ok(total)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn json(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

// Direct kernel mismatch edge retained as part of the public packed API audit.
fn packed_kind_mismatch(query: &[f32]) -> Result<CalyxError, Box<dyn std::error::Error>> {
    require_error(score_packed(
        &PackedQuery::F32 {
            values: query.to_vec(),
            norm: 1.0,
        },
        &PackedVector::Binary {
            bits: vec![0_u8; DIM.div_ceil(8)],
            dim: DIM as u32,
        },
    ))
}
