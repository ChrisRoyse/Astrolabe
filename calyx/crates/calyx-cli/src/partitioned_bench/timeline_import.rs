use std::path::PathBuf;

use crate::error::{CliError, CliResult};
use crate::partitioned_bench::timeline_store::{self, DEFAULT_ASSOCIATION_KEY, DEFAULT_CHUNK_ROWS};

pub(crate) fn run(raw: &[String]) -> CliResult {
    let args = Args::parse(raw)?;
    let import = timeline_store::load_rows_from_jsonl(&args.timeline, args.expected_rows)
        .map_err(CliError::Calyx)?;
    let stats = timeline_store::stats(&import.rows).map_err(CliError::Calyx)?;
    let readback = timeline_store::write(
        &args.cf_root,
        &args.association_key,
        &import.source_sha256,
        &import.rows,
        args.chunk_rows,
    )
    .map_err(CliError::Calyx)?;

    println!(
        "partitioned_rrf_timeline_db cf_root={} association_key={} row_count={} active_count={} duplicate_event_time_rows={} out_of_order_event_time_rows={} chunk_count={} manifest_value_bytes={} manifest_value_sha256={} chunk_value_bytes={} chunk_value_sha256={} source_sha256={} readback_matches={}",
        readback.cf_root,
        readback.association_key,
        readback.row_count,
        stats.active_count,
        stats.duplicate_event_time_rows,
        stats.out_of_order_event_time_rows,
        readback.chunk_count,
        readback.manifest_value_bytes,
        readback.manifest_value_sha256,
        readback.chunk_value_bytes,
        readback.chunk_value_sha256,
        import.source_sha256,
        readback.readback_matches
    );
    Ok(())
}

#[derive(Clone, Debug)]
struct Args {
    timeline: PathBuf,
    cf_root: PathBuf,
    association_key: String,
    expected_rows: Option<usize>,
    chunk_rows: usize,
}

impl Args {
    fn parse(raw: &[String]) -> CliResult<Self> {
        let mut timeline = None;
        let mut cf_root = None;
        let mut association_key = DEFAULT_ASSOCIATION_KEY.to_string();
        let mut expected_rows = None;
        let mut chunk_rows = DEFAULT_CHUNK_ROWS;
        let mut it = raw.iter();
        while let Some(flag) = it.next() {
            let mut next = || {
                it.next()
                    .cloned()
                    .ok_or_else(|| CliError::usage(format!("{flag} requires a value")))
            };
            match flag.as_str() {
                "--timeline" => timeline = Some(PathBuf::from(next()?)),
                "--cf-root" => cf_root = Some(PathBuf::from(next()?)),
                "--association-key" | "--timeline-key" => association_key = next()?,
                "--expected-rows" => {
                    expected_rows = Some(super::parse(&next()?, "--expected-rows")?)
                }
                "--chunk-rows" => chunk_rows = super::parse(&next()?, "--chunk-rows")?,
                other => return Err(CliError::usage(format!("unknown flag: {other}"))),
            }
        }
        if association_key.trim().is_empty() {
            return Err(CliError::usage("--timeline-key must be non-empty"));
        }
        if chunk_rows == 0 {
            return Err(CliError::usage("--chunk-rows must be > 0"));
        }
        Ok(Self {
            timeline: timeline.ok_or_else(|| CliError::usage("--timeline <jsonl> is required"))?,
            cf_root: cf_root.ok_or_else(|| CliError::usage("--cf-root <aster-dir> is required"))?,
            association_key,
            expected_rows,
            chunk_rows,
        })
    }
}

