use std::collections::BTreeMap;
use std::fs;

use serde::Deserialize;

use crate::error::CliResult;

use super::super::args::Args;
use super::super::{io_error, local_error};

#[derive(Clone, Debug, Deserialize)]
struct BitsReport {
    lenses: Option<Vec<BitsLens>>,
    report: Option<BitsReportInner>,
}

#[derive(Clone, Debug, Deserialize)]
struct BitsReportInner {
    lenses: Vec<BitsLens>,
}

#[derive(Clone, Debug, Deserialize)]
pub(super) struct BitsLens {
    pub(super) name: String,
    pub(super) bits_about: f32,
    pub(super) admitted: bool,
}

pub(super) fn streamable_for_mode(bits: &BitsLens, args: &Args) -> bool {
    bits.bits_about.is_finite()
        && bits.bits_about >= args.min_bits
        && (bits.admitted || !args.mode.requires_gate())
}

pub(super) fn load_bits(args: &Args) -> CliResult<BTreeMap<String, BitsLens>> {
    if args.a37_admission_cf_root.is_some() {
        return load_a37_admission_bits(args);
    }
    if args.diagnostic_bootstrap_without_admission() {
        return Ok(BTreeMap::new());
    }
    if args.mode.requires_gate() {
        return Err(local_error(
            "CALYX_FSV_ASSAY_STREAM_FBIN_A37_DB_REQUIRED",
            "--bits-report is diagnostic-only; gate mode must read A37 admission from Calyx/Aster",
            "write and read the A37 admission row through Calyx/Aster Graph CF before streaming",
        ));
    }
    let bits_report = args.bits_report.as_ref().ok_or_else(|| {
        local_error(
            "CALYX_FSV_ASSAY_STREAM_FBIN_BITS_MISSING",
            "missing --bits-report",
            "pass a diagnostic bits report or a DB-native A37 admission CF root",
        )
    })?;
    let report: BitsReport = serde_json::from_slice(&fs::read(bits_report).map_err(io_error)?)
        .map_err(|error| {
            local_error(
                "CALYX_FSV_ASSAY_STREAM_FBIN_BITS_INVALID",
                format!("parse {} failed: {error}", bits_report.display()),
                "pass assay_abundance.json or full bits-validate evidence",
            )
        })?;
    let lenses = report
        .lenses
        .or_else(|| report.report.map(|inner| inner.lenses))
        .ok_or_else(|| {
            local_error(
                "CALYX_FSV_ASSAY_STREAM_FBIN_BITS_INVALID",
                "bits report missing lenses",
                "pass a bits report with per-lens bits_about",
            )
        })?;
    Ok(lenses
        .into_iter()
        .map(|lens| (lens.name.clone(), lens))
        .collect())
}

pub(super) fn diagnostic_bootstrap_bits(name: &str, args: &Args) -> BitsLens {
    BitsLens {
        name: name.to_string(),
        bits_about: args.min_bits,
        admitted: false,
    }
}

pub(super) fn load_a37_admission(
    args: &Args,
) -> CliResult<crate::assay_multi_anchor_card::model::MultiAnchorReport> {
    let cf_root = args.a37_admission_cf_root.as_ref().ok_or_else(|| {
        local_error(
            "CALYX_FSV_ASSAY_STREAM_FBIN_A37_DB_MISSING",
            "missing --a37-admission-cf-root",
            "pass the A37 admission Graph CF root",
        )
    })?;
    let (report, _readback) = crate::a37_admission_store::read::<
        crate::assay_multi_anchor_card::model::MultiAnchorReport,
    >(cf_root, &args.a37_admission_key)
    .map_err(|error| {
        local_error(
            error.code,
            error.message,
            "write and read the A37 admission record through Calyx/Aster Graph CF",
        )
    })?;
    Ok(report)
}

fn load_a37_admission_bits(args: &Args) -> CliResult<BTreeMap<String, BitsLens>> {
    let report = load_a37_admission(args)?;
    if report.lenses.len() != report.lens_count {
        return Err(local_error(
            "CALYX_FSV_ASSAY_STREAM_FBIN_A37_DB_INVALID",
            format!(
                "A37 admission lens_count={} lenses={}",
                report.lens_count,
                report.lenses.len()
            ),
            "rewrite the DB-native A37 admission from a valid multi-anchor card",
        ));
    }
    let mut out = BTreeMap::new();
    for lens in report.lenses {
        if lens.name.trim().is_empty() || !lens.best_marginal_bits.is_finite() {
            return Err(local_error(
                "CALYX_FSV_ASSAY_STREAM_FBIN_A37_DB_INVALID",
                format!(
                    "A37 admission lens slot={} name='{}' best_marginal_bits={}",
                    lens.slot, lens.name, lens.best_marginal_bits
                ),
                "rewrite the DB-native A37 admission with finite named lens rows",
            ));
        }
        if out
            .insert(
                lens.name.clone(),
                BitsLens {
                    name: lens.name,
                    bits_about: lens.best_marginal_bits,
                    admitted: lens.passed && report.gate_passed,
                },
            )
            .is_some()
        {
            return Err(local_error(
                "CALYX_FSV_ASSAY_STREAM_FBIN_A37_DB_INVALID",
                "A37 admission contains duplicate lens names",
                "rewrite the DB-native A37 admission with a unique lens roster",
            ));
        }
    }
    Ok(out)
}
