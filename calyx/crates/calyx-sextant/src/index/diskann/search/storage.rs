//! Atomic construction of the complete DiskANN serving generation.

use std::fs;
use std::path::{Path, PathBuf};

use calyx_core::Result;

use super::helpers::{DiskAnnDistanceMode, io};
use crate::error::{CALYX_INDEX_DIM_MISMATCH, CALYX_INDEX_IO, sextant_error};
use crate::index::diskann::build::{
    DiskAnnBuildBackend, DiskAnnBuildParams, DiskAnnBuildProgress,
    build_diskann_graph_physical_with_backend_and_progress,
    build_diskann_graph_raw_l2_physical_with_backend_and_progress, graph_source_hash,
    normalize_unit_rows,
};
use crate::index::diskann::generation::{self, DiskAnnGeneration, StagedComponents};
use crate::index::diskann::graph::{DiskAnnGraphReader, DiskAnnMetric};
use crate::index::diskann::pq::{DiskAnnPqBinding, DiskAnnPqBuildParams, DiskAnnPqIndex};
use crate::index::diskann::raw::DiskAnnRawIndex;

pub(super) fn build_search_generation_with_backend<F>(
    graph_path: &Path,
    rows: &[(u32, Vec<f32>)],
    build_params: DiskAnnBuildParams,
    raw_source: Option<PathBuf>,
    retain_raw: bool,
    pq_params: Option<DiskAnnPqBuildParams>,
    backend: DiskAnnBuildBackend,
    distance_mode: DiskAnnDistanceMode,
    progress: F,
) -> Result<DiskAnnGeneration>
where
    F: FnMut(DiskAnnBuildProgress) -> Result<()>,
{
    let graph_stage = generation::stage_path(graph_path, "graph");
    let raw_stage = generation::stage_path(graph_path, "raw");
    let pq_stage = generation::stage_path(graph_path, "pq");
    for path in [&graph_stage, &raw_stage, &pq_stage] {
        remove_stale_stage(path)?;
    }

    let result = build_staged_generation(
        graph_path,
        rows,
        build_params,
        raw_source.as_deref(),
        retain_raw,
        pq_params,
        backend,
        distance_mode,
        progress,
        &graph_stage,
        &raw_stage,
        &pq_stage,
    );
    for path in [&graph_stage, &raw_stage, &pq_stage] {
        let _ = fs::remove_file(path);
        let mut writer_tmp = path.as_os_str().to_owned();
        writer_tmp.push(".tmp");
        let _ = fs::remove_file(PathBuf::from(writer_tmp));
    }
    result
}

#[allow(clippy::too_many_arguments)]
fn build_staged_generation<F>(
    graph_path: &Path,
    rows: &[(u32, Vec<f32>)],
    build_params: DiskAnnBuildParams,
    raw_source: Option<&Path>,
    retain_raw: bool,
    pq_params: Option<DiskAnnPqBuildParams>,
    backend: DiskAnnBuildBackend,
    distance_mode: DiskAnnDistanceMode,
    mut progress: F,
    graph_stage: &Path,
    raw_stage: &Path,
    pq_stage: &Path,
) -> Result<DiskAnnGeneration>
where
    F: FnMut(DiskAnnBuildProgress) -> Result<()>,
{
    let pq_rows = match distance_mode {
        DiskAnnDistanceMode::UnitL2 => normalize_unit_rows(rows),
        DiskAnnDistanceMode::RawL2 => rows.to_vec(),
    };
    match distance_mode {
        DiskAnnDistanceMode::UnitL2 => {
            build_diskann_graph_physical_with_backend_and_progress(
                graph_stage,
                rows,
                build_params,
                backend,
                &mut progress,
            )?;
        }
        DiskAnnDistanceMode::RawL2 => {
            build_diskann_graph_raw_l2_physical_with_backend_and_progress(
                graph_stage,
                rows,
                build_params,
                backend,
                &mut progress,
            )?;
        }
    }

    let graph_reader = DiskAnnGraphReader::open_physical(graph_stage)?;
    let graph_header = *graph_reader.header();
    drop(graph_reader);
    if graph_source_hash(&pq_rows, graph_header.metric) != graph_header.source_hash {
        return Err(sextant_error(
            CALYX_INDEX_IO,
            "DiskANN normalized source hash drifted between graph and PQ construction",
        ));
    }
    let graph_hash = generation::component_hash(graph_stage)?;

    let raw_rows = match raw_source {
        Some(path) => Some(read_raw_source(path, rows.len(), build_params.dim)?),
        None if retain_raw => Some(rows.to_vec()),
        None => None,
    };
    if let Some(raw_rows) = &raw_rows {
        DiskAnnRawIndex::write_staged(
            raw_stage,
            raw_rows,
            graph_header.source_hash,
            graph_hash,
            graph_header.metric,
        )?;
    }

    let pq = if let Some(params) = pq_params {
        if graph_header.metric != DiskAnnMetric::UnitL2 {
            return Err(sextant_error(
                CALYX_INDEX_IO,
                "PQ navigation requires the declared UnitL2 graph metric",
            ));
        }
        let binding = DiskAnnPqBinding {
            source_hash: graph_header.source_hash,
            graph_hash,
            metric: graph_header.metric,
            dim: build_params.dim,
            node_count: rows.len(),
        };
        let pq = DiskAnnPqIndex::build_bound(&pq_rows, params, binding)?;
        pq.write_staged(pq_stage, graph_header.metric)?;
        Some(pq)
    } else {
        None
    };

    generation::publish(
        graph_path,
        StagedComponents {
            graph: graph_stage,
            raw: raw_rows.as_ref().map(|_| raw_stage),
            pq: pq.as_ref().map(|_| pq_stage),
            pq_code_bits: pq.as_ref().map_or(0, DiskAnnPqIndex::code_bits),
        },
    )
}

fn read_raw_source(path: &Path, node_count: usize, dim: usize) -> Result<Vec<(u32, Vec<f32>)>> {
    if !path.is_dir() {
        return Err(sextant_error(
            CALYX_INDEX_IO,
            format!("DiskANN raw source {} is not a directory", path.display()),
        ));
    }
    let expected_bytes = dim
        .checked_mul(4)
        .ok_or_else(|| sextant_error(CALYX_INDEX_IO, "DiskANN raw row byte size overflow"))?;
    let mut rows = Vec::with_capacity(node_count);
    for id in 0..node_count {
        let row_path = path.join(id.to_string());
        let bytes = fs::read(&row_path).map_err(|error| {
            io(
                &format!("read required raw source row {}", row_path.display()),
                error,
            )
        })?;
        if bytes.len() != expected_bytes {
            return Err(sextant_error(
                CALYX_INDEX_DIM_MISMATCH,
                format!(
                    "DiskANN raw source row {} is {} bytes, expected {expected_bytes}",
                    row_path.display(),
                    bytes.len()
                ),
            ));
        }
        let mut vector = Vec::with_capacity(dim);
        for chunk in bytes.chunks_exact(4) {
            let value = f32::from_le_bytes(chunk.try_into().expect("4B"));
            if !value.is_finite() {
                return Err(sextant_error(
                    CALYX_INDEX_IO,
                    format!(
                        "DiskANN raw source row {} contains non-finite f32",
                        row_path.display()
                    ),
                ));
            }
            vector.push(value);
        }
        rows.push((id as u32, vector));
    }
    Ok(rows)
}

fn remove_stale_stage(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io("remove stale DiskANN stage", error)),
    }
}
