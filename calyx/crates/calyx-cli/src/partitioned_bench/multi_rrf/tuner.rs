use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use calyx_core::CalyxError;
use calyx_sextant::index::{
    BwPostcutoffConfig, BwPostcutoffTuner, TunerConfig, TunerObservation, TunerRange,
};
use serde::Serialize;
use serde_json::Value;

use crate::error::{CliError, CliResult};

const STATUS_REL: &str = "bench/bw_postcutoff_status.json";
const DEFAULT_LATENCY_SLO_US: u64 = 25_000;
const DEFAULT_RECALL_FLOOR: f32 = 0.85;
const RRF_POSTING_CUTOFF_MIN: usize = 1;
const RRF_POSTING_CUTOFF_MAX: usize = 65_536;
const RRF_POSTING_CUTOFF_STEP: usize = 1;
const RECALL_OBSERVATION_MODE: &str = "fused_aggregate_recall_repeated";
const POSTING_CUTOFF_SEMANTIC: &str = "partitioned_rrf_n_probe";

pub(super) struct StatusRequest<'a> {
    pub vault: &'a Path,
    pub latencies_us: &'a [u64],
    pub per_query_recall: &'a [f32],
    pub region_beam: usize,
    pub n_probe: usize,
    pub tuner_slo_us: Option<u64>,
    pub recall_floor: Option<f32>,
    pub report_path: Option<&'a Path>,
    pub report_latency_us: &'a Value,
    pub fused_recall: Option<f32>,
    pub lens_count: usize,
    pub queries: usize,
    pub k: usize,
}

pub(super) fn write_status(req: StatusRequest<'_>) -> CliResult<PathBuf> {
    if req.per_query_recall.is_empty() {
        return Err(tuner_error(
            "CALYX_FSV_PARTITIONED_RRF_TUNER_GROUND_TRUTH_REQUIRED",
            "--anneal-vault requires --ground-truth > 0 so tuner observations carry recall",
            "rerun fused RRF with --ground-truth N and --recall-floor before claiming #550",
        ));
    }
    if req.latencies_us.len() < req.per_query_recall.len() {
        return Err(tuner_error(
            "CALYX_FSV_PARTITIONED_RRF_TUNER_OBSERVATION_MISMATCH",
            format!(
                "latencies={} recall_rows={}",
                req.latencies_us.len(),
                req.per_query_recall.len()
            ),
            "record one latency and one recall value for every tuner observation",
        ));
    }
    let fused_recall = req.fused_recall.ok_or_else(|| {
        tuner_error(
            "CALYX_FSV_PARTITIONED_RRF_TUNER_AGGREGATE_RECALL_REQUIRED",
            "--anneal-vault requires aggregate fused recall readback",
            "rerun fused RRF with --ground-truth N so aggregate recall can be read",
        )
    })?;
    let recall_summary = RecallObservationSummary::from_rows(req.per_query_recall, fused_recall);

    let mut tuner = BwPostcutoffTuner::with_config(
        BwPostcutoffConfig {
            beamwidth: req.region_beam,
            posting_cutoff: req.n_probe,
        },
        TunerConfig {
            posting_cutoff: TunerRange::new(
                RRF_POSTING_CUTOFF_MIN,
                RRF_POSTING_CUTOFF_MAX.max(req.n_probe),
                RRF_POSTING_CUTOFF_STEP,
            ),
            latency_slo_us: req.tuner_slo_us.unwrap_or(DEFAULT_LATENCY_SLO_US),
            recall_floor: req.recall_floor.unwrap_or(DEFAULT_RECALL_FLOOR),
            ..TunerConfig::default()
        },
    );
    for &latency in req.latencies_us.iter().take(req.per_query_recall.len()) {
        tuner.observe(TunerObservation {
            query_latency_us: latency.max(1),
            recall_at_10: fused_recall,
            beamwidth: req.region_beam,
            posting_cutoff: req.n_probe,
        });
        let _ = tuner.maybe_adjust();
    }

    let status = Status {
        tuner: "bw_postcutoff",
        mode: "real_multi_slot_rrf",
        trigger: "calyx bench partitioned-rrf",
        current: tuner.current_config(),
        adjustments: tuner.adjustment_history(),
        ledger_entries: tuner.ledger_entries(),
        warnings: tuner.warnings(),
        observations: req.per_query_recall.len(),
        recall_observation_mode: RECALL_OBSERVATION_MODE,
        posting_cutoff_semantic: POSTING_CUTOFF_SEMANTIC,
        per_query_recall_summary: recall_summary,
        lens_count: req.lens_count,
        queries: req.queries,
        k: req.k,
        fused_ground_truth_recall_at_k: Some(fused_recall),
        latency_us: req.report_latency_us,
        report_path: req
            .report_path
            .map(|path| path.to_string_lossy().into_owned()),
    };
    let path = req.vault.join(STATUS_REL);
    let bytes = serde_json::to_vec_pretty(&status)
        .map_err(|error| CliError::runtime(format!("serialize tuner status: {error}")))?;
    write_bytes_atomic(&path, &bytes)?;
    Ok(path)
}

fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> CliResult {
    if path.exists() {
        return Err(tuner_error(
            "CALYX_FSV_PARTITIONED_RRF_TUNER_STATUS_EXISTS",
            format!("{} already exists", path.display()),
            "use a fresh --anneal-vault for each FSV trigger to avoid stale status readback",
        ));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    {
        let mut file = File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path).inspect_err(|_| {
        let _ = fs::remove_file(&tmp);
    })?;
    Ok(())
}

fn tuner_error(
    code: &'static str,
    message: impl Into<String>,
    remediation: &'static str,
) -> CliError {
    CliError::Calyx(CalyxError {
        code,
        message: message.into(),
        remediation,
    })
}

#[derive(Serialize)]
struct RecallObservationSummary {
    count: usize,
    min: f32,
    mean: f32,
    max: f32,
    aggregate_used_for_tuner: f32,
}

impl RecallObservationSummary {
    fn from_rows(rows: &[f32], aggregate: f32) -> Self {
        let min = rows.iter().copied().fold(f32::INFINITY, f32::min);
        let max = rows.iter().copied().fold(f32::NEG_INFINITY, f32::max);
        let mean = rows.iter().sum::<f32>() / rows.len() as f32;
        Self {
            count: rows.len(),
            min,
            mean,
            max,
            aggregate_used_for_tuner: aggregate,
        }
    }
}

#[derive(Serialize)]
struct Status<'a> {
    tuner: &'static str,
    mode: &'static str,
    trigger: &'static str,
    current: BwPostcutoffConfig,
    adjustments: &'a [calyx_sextant::TunerAdjustment],
    ledger_entries: &'a [calyx_sextant::TunerLedgerEntry],
    warnings: &'a [calyx_sextant::TunerWarning],
    observations: usize,
    recall_observation_mode: &'static str,
    posting_cutoff_semantic: &'static str,
    per_query_recall_summary: RecallObservationSummary,
    lens_count: usize,
    queries: usize,
    k: usize,
    fused_ground_truth_recall_at_k: Option<f32>,
    latency_us: &'a Value,
    report_path: Option<String>,
}

