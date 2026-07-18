use std::path::{Path, PathBuf};

use calyx_core::{CxId, Result, SlotId};

use super::helpers::{DiskAnnDistanceMode, dense_rows, invalid, positions};
use super::storage::build_search_generation_with_backend;
use super::{DiskAnnSearch, DiskAnnSearchParams, SearchBuildSidecars};
use crate::index::diskann::build::{DiskAnnBuildBackend, DiskAnnBuildParams, DiskAnnBuildProgress};
use crate::index::diskann::generation::DiskAnnGeneration;

impl DiskAnnSearch {
    pub fn open(
        slot: SlotId,
        graph_path: impl Into<PathBuf>,
        ids: Vec<CxId>,
        raw_sidecar: Option<PathBuf>,
        default_search: DiskAnnSearchParams,
    ) -> Result<Self> {
        let graph_path = graph_path.into();
        if let Some(path) = raw_sidecar {
            return Err(invalid(format!(
                "explicit raw path {} is forbidden when opening an atomic DiskANN generation; the active pointer owns every serving component",
                path.display()
            )));
        }
        let generation = DiskAnnGeneration::open(&graph_path)?;
        let reader = crate::index::diskann::graph::DiskAnnGraphReader::open_physical(
            generation.graph_path(),
        )?;
        let header = *reader.header();
        drop(reader);
        if ids.len() != header.node_count as usize {
            return Err(invalid(format!(
                "id map len {} != graph node_count {}",
                ids.len(),
                header.node_count
            )));
        }
        let build_params = DiskAnnBuildParams {
            dim: header.dim as usize,
            m_max: header.m_max as usize,
            ef_construction: default_search.ef_search.max(header.m_max as usize),
            alpha: 1.2,
        };
        let mut search = Self {
            slot,
            dim: header.dim,
            graph_path,
            generation: None,
            raw: None,
            pq: None,
            reader: None,
            graph_file: None,
            distance_mode: DiskAnnDistanceMode::UnitL2,
            positions: positions(&ids),
            ids,
            build_params,
            build_backend: DiskAnnBuildBackend::CpuVamana,
            default_search,
            built_at_seq: 0,
            base_seq: 0,
        };
        search.install_generation(generation)?;
        Ok(search)
    }

    pub fn build(
        slot: SlotId,
        graph_path: impl Into<PathBuf>,
        rows: &[(CxId, Vec<f32>)],
        build_params: DiskAnnBuildParams,
        raw_sidecar: Option<PathBuf>,
        default_search: DiskAnnSearchParams,
    ) -> Result<Self> {
        Self::build_with_default_raw_sidecar(
            slot,
            graph_path,
            rows,
            build_params,
            raw_sidecar,
            default_search,
            SearchBuildSidecars {
                write_default_raw_sidecar: true,
                pq: None,
                backend: DiskAnnBuildBackend::CpuVamana,
            },
        )
    }

    pub fn build_with_backend(
        slot: SlotId,
        graph_path: impl Into<PathBuf>,
        rows: &[(CxId, Vec<f32>)],
        build_params: DiskAnnBuildParams,
        raw_sidecar: Option<PathBuf>,
        default_search: DiskAnnSearchParams,
        backend: DiskAnnBuildBackend,
    ) -> Result<Self> {
        Self::build_with_default_raw_sidecar(
            slot,
            graph_path,
            rows,
            build_params,
            raw_sidecar,
            default_search,
            SearchBuildSidecars {
                write_default_raw_sidecar: true,
                pq: None,
                backend,
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn build_with_backend_and_progress<F>(
        slot: SlotId,
        graph_path: impl Into<PathBuf>,
        rows: &[(CxId, Vec<f32>)],
        build_params: DiskAnnBuildParams,
        raw_sidecar: Option<PathBuf>,
        default_search: DiskAnnSearchParams,
        backend: DiskAnnBuildBackend,
        progress: F,
    ) -> Result<Self>
    where
        F: FnMut(DiskAnnBuildProgress) -> Result<()>,
    {
        Self::build_with_default_raw_sidecar_and_progress(
            slot,
            graph_path,
            rows,
            build_params,
            raw_sidecar,
            default_search,
            SearchBuildSidecars {
                write_default_raw_sidecar: true,
                pq: None,
                backend,
            },
            progress,
        )
    }

    pub(crate) fn build_without_default_raw_sidecar_with_backend(
        slot: SlotId,
        graph_path: impl Into<PathBuf>,
        rows: &[(CxId, Vec<f32>)],
        build_params: DiskAnnBuildParams,
        raw_sidecar: Option<PathBuf>,
        default_search: DiskAnnSearchParams,
        backend: DiskAnnBuildBackend,
    ) -> Result<Self> {
        Self::build_with_default_raw_sidecar(
            slot,
            graph_path,
            rows,
            build_params,
            raw_sidecar,
            default_search,
            SearchBuildSidecars {
                write_default_raw_sidecar: false,
                pq: None,
                backend,
            },
        )
    }

    pub(crate) fn build_raw_l2_without_default_raw_sidecar_with_backend(
        slot: SlotId,
        graph_path: impl Into<PathBuf>,
        rows: &[(CxId, Vec<f32>)],
        build_params: DiskAnnBuildParams,
        raw_sidecar: Option<PathBuf>,
        default_search: DiskAnnSearchParams,
        backend: DiskAnnBuildBackend,
    ) -> Result<Self> {
        let graph_path = graph_path.into();
        let dense_rows = dense_rows(rows, build_params.dim)?;
        build_search_generation_with_backend(
            &graph_path,
            &dense_rows,
            build_params,
            raw_sidecar,
            false,
            None,
            backend,
            DiskAnnDistanceMode::RawL2,
            |_| Ok(()),
        )?;
        let mut search = Self::open(
            slot,
            graph_path,
            rows.iter().map(|(cx_id, _)| *cx_id).collect(),
            None,
            default_search,
        )?;
        search.build_backend = backend;
        Ok(search)
    }

    pub(super) fn build_with_default_raw_sidecar(
        slot: SlotId,
        graph_path: impl Into<PathBuf>,
        rows: &[(CxId, Vec<f32>)],
        build_params: DiskAnnBuildParams,
        raw_sidecar: Option<PathBuf>,
        default_search: DiskAnnSearchParams,
        sidecars: SearchBuildSidecars,
    ) -> Result<Self> {
        Self::build_with_default_raw_sidecar_and_progress(
            slot,
            graph_path,
            rows,
            build_params,
            raw_sidecar,
            default_search,
            sidecars,
            |_| Ok(()),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn build_with_default_raw_sidecar_and_progress<F>(
        slot: SlotId,
        graph_path: impl Into<PathBuf>,
        rows: &[(CxId, Vec<f32>)],
        build_params: DiskAnnBuildParams,
        raw_sidecar: Option<PathBuf>,
        default_search: DiskAnnSearchParams,
        sidecars: SearchBuildSidecars,
        progress: F,
    ) -> Result<Self>
    where
        F: FnMut(DiskAnnBuildProgress) -> Result<()>,
    {
        let graph_path = graph_path.into();
        let dense_rows = dense_rows(rows, build_params.dim)?;
        let retain_raw = raw_sidecar.is_some() || sidecars.write_default_raw_sidecar;
        build_search_generation_with_backend(
            &graph_path,
            &dense_rows,
            build_params,
            raw_sidecar,
            retain_raw,
            sidecars.pq,
            sidecars.backend,
            DiskAnnDistanceMode::UnitL2,
            progress,
        )?;
        let mut search = Self::open(
            slot,
            graph_path,
            rows.iter().map(|(cx_id, _)| *cx_id).collect(),
            None,
            default_search,
        )?;
        search.build_backend = sidecars.backend;
        Ok(search)
    }

    pub fn empty(slot: SlotId, dim: u32, graph_path: impl Into<PathBuf>) -> Self {
        Self {
            slot,
            dim,
            graph_path: graph_path.into(),
            generation: None,
            raw: None,
            pq: None,
            reader: None,
            graph_file: None,
            distance_mode: super::helpers::DiskAnnDistanceMode::UnitL2,
            ids: Vec::new(),
            positions: std::collections::HashMap::new(),
            build_params: DiskAnnBuildParams {
                dim: dim as usize,
                m_max: 32,
                ef_construction: 64,
                alpha: 1.2,
            },
            build_backend: DiskAnnBuildBackend::CpuVamana,
            default_search: DiskAnnSearchParams::default(),
            built_at_seq: 0,
            base_seq: 0,
        }
    }

    pub fn persist_path(&self) -> &Path {
        &self.graph_path
    }
}
