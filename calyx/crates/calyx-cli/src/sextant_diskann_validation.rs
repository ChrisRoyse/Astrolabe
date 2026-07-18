mod issue604;
mod support;

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::path::Path;
use std::time::Instant;

use calyx_core::{CxId, SlotId, SlotVector};
use calyx_sextant::index::{
    DiskAnnPqBuildParams, DiskAnnPqSearchBuild, DiskAnnSearch, SextantIndex,
};
use serde::Serialize;

use crate::error::CliError;
use support::{
    Mode, Paths, Request, approx_rows, build_params, cx, exact_top_k, file_len, percentile,
    rank_of, raw_vectors, search_params, write_json, write_raw_sidecar,
};

const SLOT: SlotId = SlotId::new(0);
#[derive(Serialize)]
struct Summary {
    mode: String,
    build_backend: String,
    root: String,
    graph_path: String,
    raw_dir: String,
    generation_id: String,
    source_hash: String,
    graph_hash: String,
    raw_hash: Option<String>,
    pq_hash: Option<String>,
    graph_component: String,
    raw_component: Option<String>,
    pq_path: Option<String>,
    metrics_dir: String,
    node_count: usize,
    dim: usize,
    query_count: usize,
    k: usize,
    beamwidth: usize,
    ef_search: usize,
    rescore_k: usize,
    recall_floor: Option<f64>,
    recall_at_10_avg: f64,
    recall_at_10_min: f64,
    build_us: u128,
    query_throughput_qps: f64,
    p50_us: u128,
    p99_us: u128,
    rss_after_build_bytes: u64,
    exact_query_node7_rank: usize,
    exact_query_node7_distance: f32,
    trait_top_rank: usize,
    trait_top_cx_id: String,
    active_pointer_bytes: u64,
    graph_bytes: u64,
    raw_file_count: usize,
    raw_bytes_total: u64,
    retained_physical_bytes: u64,
    retained_directory_file_count: usize,
    retained_directory_bytes: u64,
    pq_bytes: Option<u64>,
    pq_code_bits: Option<u8>,
    pq_ram_bytes: Option<usize>,
    pq_subvectors: Option<usize>,
    pq_centroids: Option<usize>,
    hits_tsv: String,
}

#[derive(Serialize)]
struct EdgeReport {
    mode: String,
    build_backend: String,
    root: String,
    graph_path: String,
    before_graph_exists: bool,
    after_graph_exists: bool,
    before_graph_bytes: Option<u64>,
    after_graph_bytes: Option<u64>,
    expected_error: String,
    observed_error: String,
    observed_message: String,
}

pub(crate) fn run(args: &[String]) -> crate::error::CliResult {
    if issue604::is_issue604(args) {
        return issue604::run(args);
    }
    let request = Request::parse(args).map_err(CliError::usage)?;
    match request.mode {
        Mode::Happy => run_happy(&request),
        Mode::Empty => run_empty_edge(&request),
        Mode::DimMismatch => run_dim_mismatch_edge(&request),
        Mode::Truncated => run_truncated_edge(&request),
        Mode::MissingRaw => run_missing_raw_edge(&request),
        Mode::CorruptPq => run_corrupt_pq_edge(&request),
        Mode::MismatchedPq => run_mismatched_pq_edge(&request),
        Mode::InvalidCode => run_invalid_pq_build_edge(&request, true),
        Mode::InvalidSubspace => run_invalid_pq_build_edge(&request, false),
        Mode::NonUnit => run_non_unit_edge(&request),
    }
}

fn run_happy(request: &Request) -> crate::error::CliResult {
    let paths = Paths::create(&request.root)?;
    let raw = raw_vectors(request.nodes, request.dim);
    let approx = approx_rows(&raw);
    write_raw_sidecar(&paths.raw_dir, &raw)?;
    let build_started = Instant::now();
    let index = build_index(request, &paths, &approx)?;
    let build_us = build_started.elapsed().as_micros();
    let rss_after_build_bytes = process_rss_bytes()?;
    let mut latencies = Vec::with_capacity(request.queries);
    let mut recalls = Vec::with_capacity(request.queries);
    let mut hits_tsv = String::from("query_id\trank\tnode_id\tdistance\texact_top10\n");
    let query_batch_started = Instant::now();
    for q in 0..request.queries {
        let query_id = (q * 17 + 7) % request.nodes;
        let exact = exact_top_k(&raw, query_id, request.k);
        let exact_ids: BTreeSet<_> = exact.iter().map(|(id, _)| *id).collect();
        let started = Instant::now();
        let hits = index.search_ids(&raw[query_id].1, request.k, &search_params(request))?;
        latencies.push(started.elapsed().as_micros());
        let got_ids: BTreeSet<_> = hits.iter().map(|(id, _)| *id).collect();
        let overlap = got_ids.intersection(&exact_ids).count();
        recalls.push(overlap as f64 / exact_ids.len() as f64);
        for (rank, (node_id, distance)) in hits.iter().enumerate() {
            hits_tsv.push_str(&format!(
                "{query_id}\t{}\t{node_id}\t{distance:.8}\t{}\n",
                rank + 1,
                exact_ids.contains(node_id)
            ));
        }
    }
    let query_batch_secs = query_batch_started.elapsed().as_secs_f64();
    let node7 = index.search_ids(&raw[7].1, request.k, &search_params(request))?;
    let trait_hits = index.search(
        &SlotVector::Dense {
            dim: request.dim as u32,
            data: raw[7].1.clone(),
        },
        request.k,
        Some(request.ef_search),
    )?;
    let hits_path = paths.metrics_dir.join("diskann_hits.tsv");
    fs::write(&hits_path, hits_tsv)?;
    let generation = index
        .generation()
        .ok_or_else(|| CliError::runtime("built DiskANN has no active generation"))?;
    let (retained_directory_file_count, retained_directory_bytes) =
        directory_physical_bytes(paths.graph_path.parent().expect("graph has parent"))?;
    let summary = Summary {
        mode: "happy".to_string(),
        build_backend: request.build_backend.as_str().to_string(),
        root: request.root.display().to_string(),
        graph_path: paths.graph_path.display().to_string(),
        raw_dir: paths.raw_dir.display().to_string(),
        generation_id: hex(generation.generation_id()),
        source_hash: hex(generation.source_hash()),
        graph_hash: hex(generation.graph_hash()),
        raw_hash: generation.raw_hash().map(hex),
        pq_hash: generation.pq_hash().map(hex),
        graph_component: generation.graph_path().display().to_string(),
        raw_component: generation.raw_path().map(|path| path.display().to_string()),
        pq_path: generation.pq_path().map(|path| path.display().to_string()),
        metrics_dir: paths.metrics_dir.display().to_string(),
        node_count: request.nodes,
        dim: request.dim,
        query_count: request.queries,
        k: request.k,
        beamwidth: request.beamwidth,
        ef_search: request.ef_search,
        rescore_k: request.rescore_k,
        recall_floor: request.recall_floor,
        recall_at_10_avg: recalls.iter().sum::<f64>() / recalls.len() as f64,
        recall_at_10_min: recalls.iter().copied().fold(f64::INFINITY, f64::min),
        build_us,
        query_throughput_qps: request.queries as f64 / query_batch_secs,
        p50_us: percentile(&latencies, 50),
        p99_us: percentile(&latencies, 99),
        rss_after_build_bytes,
        exact_query_node7_rank: rank_of(&node7, 7),
        exact_query_node7_distance: node7
            .iter()
            .find(|(id, _)| *id == 7)
            .map(|(_, distance)| *distance)
            .unwrap_or(f32::INFINITY),
        trait_top_rank: trait_hits.first().map(|hit| hit.rank).unwrap_or(usize::MAX),
        trait_top_cx_id: trait_hits
            .first()
            .map(|hit| hit.cx_id.to_string())
            .unwrap_or_else(|| "none".to_string()),
        active_pointer_bytes: generation.pointer_bytes(),
        graph_bytes: generation.graph_bytes(),
        raw_file_count: usize::from(generation.raw_path().is_some()),
        raw_bytes_total: generation.raw_bytes(),
        retained_physical_bytes: generation.physical_bytes(),
        retained_directory_file_count,
        retained_directory_bytes,
        pq_bytes: generation.pq_path().map(|_| generation.pq_bytes()),
        pq_code_bits: generation.pq_code_bits(),
        pq_ram_bytes: index.pq_ram_bytes(),
        pq_subvectors: index.pq_summary().map(|(_, subvectors, _)| subvectors),
        pq_centroids: index.pq_summary().map(|(_, _, centroids)| centroids),
        hits_tsv: hits_path.display().to_string(),
    };
    let summary_path = paths.metrics_dir.join("diskann_search_summary.json");
    write_json(&summary_path, &summary)?;
    enforce_recall_floor(&summary, request.recall_floor, &summary_path, &hits_path)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&summary)
            .map_err(|error| CliError::runtime(format!("serialize summary: {error}")))?
    );
    Ok(())
}

fn hex(bytes: [u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn directory_physical_bytes(path: &Path) -> crate::error::CliResult<(usize, u64)> {
    let mut files = 0_usize;
    let mut bytes = 0_u64;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let metadata = entry.metadata()?;
        if metadata.is_file() {
            files += 1;
            bytes = bytes
                .checked_add(metadata.len())
                .ok_or_else(|| CliError::runtime("DiskANN directory byte count overflow"))?;
        }
    }
    Ok((files, bytes))
}

#[cfg(windows)]
fn process_rss_bytes() -> crate::error::CliResult<u64> {
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
    // SAFETY: the writable counter has the declared Win32 size and remains
    // alive for the current-process pseudo-handle call.
    let read = unsafe {
        GetProcessMemoryInfo(
            GetCurrentProcess(),
            &mut counters,
            std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        )
    };
    if read == 0 {
        return Err(CliError::runtime(format!(
            "GetProcessMemoryInfo: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(counters.WorkingSetSize as u64)
}

fn enforce_recall_floor(
    summary: &Summary,
    floor: Option<f64>,
    summary_path: &Path,
    hits_path: &Path,
) -> crate::error::CliResult {
    let Some(floor) = floor else {
        return Ok(());
    };
    if summary.recall_at_10_min + f64::EPSILON < floor {
        return Err(CliError::runtime(format!(
            "CALYX_FSV_DISKANN_RECALL_BELOW_FLOOR: recall_at_10_min={:.6} recall_floor={:.6} summary={} hits={}",
            summary.recall_at_10_min,
            floor,
            summary_path.display(),
            hits_path.display()
        )));
    }
    Ok(())
}

fn run_empty_edge(request: &Request) -> crate::error::CliResult {
    let paths = Paths::for_root(&request.root);
    let before = file_len(&paths.graph_path);
    let err = DiskAnnSearch::build_with_backend(
        SLOT,
        &paths.graph_path,
        &[],
        build_params(request),
        None,
        search_params(request),
        request.build_backend,
    )
    .expect_err("empty graph build must fail closed");
    write_edge(
        &request.root,
        "empty",
        request.build_backend.as_str(),
        before,
        file_len(&paths.graph_path),
        err.code,
        &err.message,
    )
}

fn run_dim_mismatch_edge(request: &Request) -> crate::error::CliResult {
    let paths = Paths::create(&request.root)?;
    let raw = raw_vectors(32, request.dim);
    write_raw_sidecar(&paths.raw_dir, &raw)?;
    let index = build_edge_index(request, &paths, &raw)?;
    let before = file_len(&paths.graph_path);
    let err = index
        .search_ids(
            &raw[7].1[..raw[7].1.len() - 1],
            request.k,
            &search_params(request),
        )
        .expect_err("dim mismatch must fail closed");
    write_edge(
        &request.root,
        "dim-mismatch",
        request.build_backend.as_str(),
        before,
        file_len(&paths.graph_path),
        err.code,
        &err.message,
    )
}

fn run_truncated_edge(request: &Request) -> crate::error::CliResult {
    let paths = Paths::create(&request.root)?;
    let raw = raw_vectors(64, request.dim);
    write_raw_sidecar(&paths.raw_dir, &raw)?;
    let mut build_request = request.clone();
    build_request.pq = Some(edge_pq_params(request.dim));
    let index = build_edge_index(&build_request, &paths, &raw)?;
    let pq_path = index
        .generation()
        .and_then(|generation| generation.pq_path())
        .ok_or_else(|| CliError::runtime("truncated fixture has no retained PQ component"))?
        .to_path_buf();
    drop(index);
    let before = file_len(&paths.graph_path);
    OpenOptions::new()
        .write(true)
        .open(&pq_path)?
        .set_len(file_len(&pq_path).unwrap_or(0) / 2)?;
    let err = DiskAnnSearch::open(
        SLOT,
        &paths.graph_path,
        (0..64).map(cx).collect(),
        None,
        search_params(request),
    )
    .expect_err("truncated graph must fail closed");
    write_edge(
        &request.root,
        "truncated",
        request.build_backend.as_str(),
        before,
        file_len(&paths.graph_path),
        err.code,
        &err.message,
    )
}

fn edge_pq_params(dim: usize) -> DiskAnnPqBuildParams {
    let subvectors = (1..=dim)
        .rev()
        .find(|candidate| dim % candidate == 0 && *candidate <= 8)
        .unwrap_or(1);
    DiskAnnPqBuildParams {
        subvectors,
        centroids: 16,
        iterations: 2,
        code_bits: 4,
    }
}

fn run_missing_raw_edge(request: &Request) -> crate::error::CliResult {
    let paths = Paths::create(&request.root)?;
    let raw = raw_vectors(32, request.dim);
    write_raw_sidecar(&paths.raw_dir, &raw)?;
    let index = build_edge_index(request, &paths, &raw)?;
    let raw_component = index
        .generation()
        .and_then(|generation| generation.raw_path())
        .ok_or_else(|| CliError::runtime("missing-raw fixture has no retained raw component"))?
        .to_path_buf();
    drop(index);
    let before = file_len(&paths.graph_path);
    fs::remove_file(&raw_component)?;
    let err = DiskAnnSearch::open(
        SLOT,
        &paths.graph_path,
        (0..32).map(cx).collect(),
        None,
        search_params(request),
    )
    .expect_err("missing raw sidecar must fail closed");
    write_edge(
        &request.root,
        "missing-raw",
        request.build_backend.as_str(),
        before,
        file_len(&paths.graph_path),
        err.code,
        &err.message,
    )
}

fn build_edge_index(
    request: &Request,
    paths: &Paths,
    raw: &[(CxId, Vec<f32>)],
) -> crate::error::CliResult<DiskAnnSearch> {
    build_index(request, paths, &approx_rows(raw))
}

fn build_index(
    request: &Request,
    paths: &Paths,
    approx: &[(CxId, Vec<f32>)],
) -> crate::error::CliResult<DiskAnnSearch> {
    if let Some(pq) = request.pq {
        return Ok(DiskAnnSearch::build_with_pq_plan(
            SLOT,
            &paths.graph_path,
            approx,
            build_params(request),
            Some(paths.raw_dir.clone()),
            DiskAnnPqSearchBuild {
                search: search_params(request),
                pq,
                backend: request.build_backend,
            },
        )?);
    }
    Ok(DiskAnnSearch::build_with_backend(
        SLOT,
        &paths.graph_path,
        approx,
        build_params(request),
        Some(paths.raw_dir.clone()),
        search_params(request),
        request.build_backend,
    )?)
}

fn run_corrupt_pq_edge(request: &Request) -> crate::error::CliResult {
    let paths = Paths::create(&request.root)?;
    let raw = raw_vectors(64, request.dim);
    write_raw_sidecar(&paths.raw_dir, &raw)?;
    let mut build_request = request.clone();
    if build_request.pq.is_none() {
        build_request.pq = Some(DiskAnnPqBuildParams {
            subvectors: 4,
            centroids: 16,
            iterations: 2,
            code_bits: 4,
        });
    }
    let index = build_edge_index(&build_request, &paths, &raw)?;
    let pq_path = index
        .generation()
        .and_then(|generation| generation.pq_path())
        .ok_or_else(|| CliError::runtime("corrupt-PQ fixture has no retained PQ component"))?
        .to_path_buf();
    drop(index);
    let before = file_len(&paths.graph_path);
    fs::write(&pq_path, b"not-a-pq")?;
    let err = DiskAnnSearch::open(
        SLOT,
        &paths.graph_path,
        (0..64).map(cx).collect(),
        None,
        search_params(request),
    )
    .expect_err("corrupt pq sidecar must fail closed");
    write_edge(
        &request.root,
        "corrupt-pq",
        request.build_backend.as_str(),
        before,
        file_len(&paths.graph_path),
        err.code,
        &err.message,
    )
}

fn run_mismatched_pq_edge(request: &Request) -> crate::error::CliResult {
    let paths = Paths::create(&request.root)?;
    let raw = raw_vectors(64, request.dim);
    write_raw_sidecar(&paths.raw_dir, &raw)?;
    let mut build_request = request.clone();
    build_request.pq = Some(edge_pq_params(request.dim));
    let first = build_edge_index(&build_request, &paths, &raw)?;
    let stale_pq = fs::read(
        first
            .generation()
            .and_then(|generation| generation.pq_path())
            .ok_or_else(|| CliError::runtime("mismatched-PQ first generation has no PQ"))?,
    )?;
    let mut changed = approx_rows(&raw);
    changed[0].1[0] += 0.25;
    let second = build_index(&build_request, &paths, &changed)?;
    let current_pq = second
        .generation()
        .and_then(|generation| generation.pq_path())
        .ok_or_else(|| CliError::runtime("mismatched-PQ second generation has no PQ"))?
        .to_path_buf();
    drop(first);
    drop(second);
    let before = file_len(&paths.graph_path);
    fs::write(&current_pq, stale_pq)?;
    let err = DiskAnnSearch::open(
        SLOT,
        &paths.graph_path,
        (0..64).map(cx).collect(),
        None,
        search_params(request),
    )
    .expect_err("PQ from an older graph generation must fail closed");
    write_edge(
        &request.root,
        "mismatched-pq",
        request.build_backend.as_str(),
        before,
        file_len(&paths.graph_path),
        err.code,
        &err.message,
    )
}

fn run_invalid_pq_build_edge(request: &Request, invalid_code: bool) -> crate::error::CliResult {
    let paths = Paths::create(&request.root)?;
    let raw = raw_vectors(64, request.dim);
    write_raw_sidecar(&paths.raw_dir, &raw)?;
    let mut build_request = request.clone();
    build_request.pq = Some(if invalid_code {
        DiskAnnPqBuildParams {
            subvectors: 1,
            centroids: 17,
            iterations: 2,
            code_bits: 4,
        }
    } else {
        DiskAnnPqBuildParams {
            subvectors: request.dim.saturating_sub(1).max(2),
            centroids: 16,
            iterations: 2,
            code_bits: 4,
        }
    });
    let before = file_len(&paths.graph_path);
    let err = build_edge_index(&build_request, &paths, &raw)
        .expect_err("invalid PQ code/subspace contract must fail closed");
    let mode = if invalid_code {
        "invalid-code"
    } else {
        "invalid-subspace"
    };
    write_edge(
        &request.root,
        mode,
        request.build_backend.as_str(),
        before,
        file_len(&paths.graph_path),
        err.code(),
        err.message(),
    )
}

fn run_non_unit_edge(request: &Request) -> crate::error::CliResult {
    let paths = Paths::create(&request.root)?;
    let raw = raw_vectors(32, request.dim);
    write_raw_sidecar(&paths.raw_dir, &raw)?;
    let mut rows = approx_rows(&raw);
    rows[0].1.fill(0.0);
    let before = file_len(&paths.graph_path);
    let err = build_index(request, &paths, &rows)
        .expect_err("zero-norm directional source must fail closed");
    write_edge(
        &request.root,
        "non-unit",
        request.build_backend.as_str(),
        before,
        file_len(&paths.graph_path),
        err.code(),
        err.message(),
    )
}

fn write_edge(
    root: &Path,
    mode: &str,
    build_backend: &str,
    before: Option<u64>,
    after: Option<u64>,
    code: &'static str,
    message: &str,
) -> crate::error::CliResult {
    let paths = Paths::create(root)?;
    let report = EdgeReport {
        mode: mode.to_string(),
        build_backend: build_backend.to_string(),
        root: root.display().to_string(),
        graph_path: paths.graph_path.display().to_string(),
        before_graph_exists: before.is_some(),
        after_graph_exists: after.is_some(),
        before_graph_bytes: before,
        after_graph_bytes: after,
        expected_error: expected_error(mode).to_string(),
        observed_error: code.to_string(),
        observed_message: message.to_string(),
    };
    let path = paths.metrics_dir.join(format!("diskann_edge_{mode}.json"));
    write_json(&path, &report)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&report)
            .map_err(|error| CliError::runtime(format!("serialize edge report: {error}")))?
    );
    Ok(())
}

fn expected_error(mode: &str) -> &'static str {
    match mode {
        "empty" => "CALYX_INDEX_INVALID_PARAMS",
        "dim-mismatch" => "CALYX_INDEX_DIM_MISMATCH",
        "truncated" => "CALYX_INDEX_CORRUPT",
        "missing-raw" => "CALYX_INDEX_IO",
        "corrupt-pq" => "CALYX_INDEX_CORRUPT",
        "mismatched-pq" => "CALYX_INDEX_CORRUPT",
        "invalid-code" | "invalid-subspace" | "non-unit" => "CALYX_INDEX_INVALID_PARAMS",
        _ => "CALYX_INDEX_INVALID_PARAMS",
    }
}
