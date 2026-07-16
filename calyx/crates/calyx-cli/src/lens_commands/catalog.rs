use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use calyx_core::{Input, Lens, LensCost, Placement};
use calyx_registry::{
    CandlePrecision, LensHealth, LensRuntime, LensSpec, MultimodalAdapterLens, PlacementBudget,
    StaticLookupLens, choose_resolved_placement, legacy_lensforge_manifest_v1_ids_from_path,
    lens_spec_from_manifest_path, lens_spec_metadata_from_manifest_path,
    parse_frozen_device_policy,
};
use serde::{Deserialize, Serialize};

use super::flags::{Flags, value};
use super::support::{dim, hex_from_bytes, runtime_name};
use crate::error::{CliError, CliResult};
use crate::output::print_json;

mod budget;
mod store;

const LENS_IDENTITY_MIGRATION_REQUIRED: &str = "CALYX_LENS_IDENTITY_MIGRATION_REQUIRED";

pub(crate) use store::LensCatalogDbReadback;

use budget::placement_budget_from_catalog;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct LensCatalog {
    pub(crate) lenses: Vec<LensCatalogEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct LensCatalogEntry {
    pub(crate) lens_id: String,
    pub(crate) name: String,
    pub(crate) modality: String,
    pub(crate) runtime: String,
    pub(crate) dim: u32,
    #[serde(default)]
    pub(crate) retrieval_only: bool,
    #[serde(default)]
    pub(crate) excluded_from_dedup: bool,
    pub(crate) weights_sha256: String,
    pub(crate) manifest: PathBuf,
    #[serde(default)]
    pub(crate) cost: LensCost,
    #[serde(default)]
    pub(crate) placement: Placement,
}

#[derive(Serialize)]
pub(crate) struct AddReport {
    pub(crate) catalog: PathBuf,
    pub(crate) lens_id: String,
    pub(crate) name: String,
    pub(crate) manifest: PathBuf,
    pub(crate) cost: LensCost,
    pub(crate) placement: Placement,
    pub(crate) count: usize,
}

#[derive(Serialize)]
struct ListReport {
    catalog: PathBuf,
    count: usize,
    lenses: Vec<ListLensEntry>,
}

#[derive(Serialize)]
struct ListLensEntry {
    #[serde(flatten)]
    entry: LensCatalogEntry,
    health: LensHealth,
}

#[derive(Serialize)]
struct MigrateReport {
    source: PathBuf,
    catalog: PathBuf,
    count: usize,
    readback: LensCatalogDbReadback,
}

#[derive(Default)]
struct MigrateFlags {
    home: Option<PathBuf>,
    from: Option<PathBuf>,
}

pub(crate) fn add(args: &[String]) -> CliResult {
    let flags = Flags::parse(args)?;
    flags.reject_measure_flags("calyx lens add")?;
    let manifest = flags
        .manifest
        .ok_or_else(|| CliError::usage("calyx lens add requires --manifest <path>"))?;
    let report = add_manifest_to_catalog(flags.home.as_deref(), manifest)?;
    print_json(&report)
}

pub(crate) fn list(args: &[String]) -> CliResult {
    let flags = Flags::parse(args)?;
    flags.reject_measure_flags("calyx lens list")?;
    if flags.manifest.is_some() {
        return Err(CliError::usage(
            "calyx lens list does not accept --manifest",
        ));
    }
    let catalog_path = catalog_path(flags.home.as_deref())?;
    let catalog = read_catalog(&catalog_path)?;
    print_json(&ListReport {
        catalog: catalog_path,
        count: catalog.lenses.len(),
        lenses: catalog.lenses.into_iter().map(list_entry).collect(),
    })
}

pub(crate) fn migrate_catalog(args: &[String]) -> CliResult {
    let flags = MigrateFlags::parse(args)?;
    let catalog_path = catalog_path(flags.home.as_deref())?;
    let source = flags
        .from
        .unwrap_or_else(|| store::legacy_catalog_path(&catalog_path));
    let catalog = read_legacy_catalog(&source)?;
    validate_catalog_migration(&catalog)?;
    let readback = write_catalog(&catalog_path, &catalog)?;
    print_json(&MigrateReport {
        source,
        catalog: catalog_path,
        count: catalog.lenses.len(),
        readback,
    })
}

fn validate_catalog_migration(catalog: &LensCatalog) -> CliResult {
    for entry in &catalog.lenses {
        let spec = lens_spec_from_manifest_path(&entry.manifest).map_err(|error| {
            CliError::from(calyx_core::CalyxError {
                code: LENS_IDENTITY_MIGRATION_REQUIRED,
                message: format!(
                    "legacy catalog row name={} manifest={} lens_id={} cannot be reconstructed canonically: {}: {}",
                    entry.name,
                    entry.manifest.display(),
                    entry.lens_id,
                    error.code,
                    error.message
                ),
                remediation: "preserve the legacy catalog bytes and perform an explicit lineage migration before writing the catalog database",
            })
        })?;
        let collisions = catalog
            .lenses
            .iter()
            .filter(|candidate| {
                catalog_identity_collides(
                    candidate,
                    &spec.lens_id().to_string(),
                    &spec.name,
                    &entry.manifest,
                )
            })
            .collect::<Vec<_>>();
        if collisions.len() != 1
            || !canonical_catalog_identity_matches(entry, &spec, &entry.manifest)?
        {
            return Err(identity_migration_required(
                &collisions,
                &spec,
                &entry.manifest,
            ));
        }
    }
    Ok(())
}

pub(crate) fn add_manifest_to_catalog(
    home: Option<&Path>,
    manifest: PathBuf,
) -> CliResult<AddReport> {
    let spec = lens_spec_from_manifest_path(&manifest)?;
    let catalog_path = catalog_path(home)?;
    let mut catalog = read_catalog(&catalog_path)?;
    let lens_id = spec.lens_id().to_string();
    let collisions = catalog
        .lenses
        .iter()
        .filter(|entry| catalog_identity_collides(entry, &lens_id, &spec.name, &manifest))
        .collect::<Vec<_>>();
    if !collisions.is_empty() {
        if collisions.len() == 1
            && canonical_catalog_identity_matches(collisions[0], &spec, &manifest)?
        {
            let existing = collisions[0];
            return Ok(AddReport {
                catalog: catalog_path,
                lens_id: existing.lens_id.clone(),
                name: existing.name.clone(),
                manifest: existing.manifest.clone(),
                cost: existing.cost,
                placement: existing.placement,
                count: catalog.lenses.len(),
            });
        }
        return Err(identity_migration_required(&collisions, &spec, &manifest));
    }
    let mut cost = estimate_lens_cost(&spec)?;
    let resolved_placement = resolved_runtime_placement(&spec)?;
    if resolved_placement == Placement::Cpu {
        cost.vram_bytes = 0;
    }
    let budget = placement_budget_from_catalog(
        &catalog,
        resolved_placement == Placement::Gpu && cost.vram_bytes > 0,
    )?;
    let entry = entry_from_spec(&spec, manifest, cost, budget, resolved_placement)?;
    catalog.lenses.push(entry.clone());
    catalog
        .lenses
        .sort_by(|left, right| left.lens_id.cmp(&right.lens_id));
    write_catalog(&catalog_path, &catalog)?;
    Ok(AddReport {
        catalog: catalog_path,
        lens_id: entry.lens_id,
        name: entry.name,
        manifest: entry.manifest,
        cost: entry.cost,
        placement: entry.placement,
        count: catalog.lenses.len(),
    })
}

fn catalog_identity_collides(
    entry: &LensCatalogEntry,
    lens_id: &str,
    name: &str,
    manifest: &Path,
) -> bool {
    entry.lens_id == lens_id || entry.name == name || entry.manifest == manifest
}

pub(crate) fn canonical_catalog_identity_matches(
    entry: &LensCatalogEntry,
    spec: &LensSpec,
    manifest: &Path,
) -> CliResult<bool> {
    Ok(entry.lens_id == spec.lens_id().to_string()
        && entry.name == spec.name
        && entry.manifest == manifest
        && entry.modality == format!("{:?}", spec.modality).to_lowercase()
        && entry.runtime == runtime_name(&spec.runtime)
        && entry.dim == dim(spec.output)
        && entry.retrieval_only == spec.retrieval_only
        && entry.excluded_from_dedup == spec.excluded_from_dedup
        && entry.weights_sha256 == hex_from_bytes(&spec.weights_sha256)
        && entry.placement == resolved_runtime_placement(spec)?
        && catalog_cost_matches(spec, entry.cost)?)
}

pub(crate) fn catalog_cost_matches(spec: &LensSpec, cost: LensCost) -> CliResult<bool> {
    if !cost.total_ms.is_finite()
        || cost.total_ms < 0.0
        || !cost.ms_per_input.is_finite()
        || cost.ms_per_input < 0.0
    {
        return Ok(false);
    }
    match &spec.runtime {
        LensRuntime::Algorithmic { .. }
        | LensRuntime::ExternalCmd { .. }
        | LensRuntime::TeiHttp { .. } => Ok(cost == LensCost::zero()),
        LensRuntime::StaticLookup {
            embeddings_file,
            tokenizer,
            ..
        } => {
            let ram_bytes = path_size(embeddings_file)?.saturating_add(path_size(tokenizer)?);
            Ok(cost.total_ms == cost.ms_per_input
                && cost.vram_bytes == 0
                && cost.ram_bytes == ram_bytes
                && cost.batch_ceiling == batch_ceiling(cost.ms_per_input))
        }
        LensRuntime::MultimodalAdapter { files, .. } => {
            let bytes = files_size(files)?;
            let placement = resolved_runtime_placement(spec)?;
            Ok(cost.total_ms == 0.0
                && cost.ms_per_input == 0.0
                && cost.vram_bytes
                    == if placement == Placement::Gpu {
                        bytes
                    } else {
                        0
                    }
                && cost.ram_bytes == bytes
                && cost.batch_ceiling == u32::MAX)
        }
        LensRuntime::CandleLocal { files, .. }
        | LensRuntime::Onnx { files, .. }
        | LensRuntime::OnnxColbert { files, .. }
        | LensRuntime::FastembedSparse { files, .. }
        | LensRuntime::FastembedBgem3 { files, .. }
        | LensRuntime::FastembedReranker { files, .. }
        | LensRuntime::FastembedQwen3 { files, .. } => {
            let bytes = files_size(files)?;
            let placement = resolved_runtime_placement(spec)?;
            Ok(cost.total_ms == 0.0
                && cost.ms_per_input == 0.0
                && cost.vram_bytes
                    == if placement == Placement::Gpu {
                        bytes
                    } else {
                        0
                    }
                && cost.ram_bytes == bytes
                && cost.batch_ceiling == u32::MAX)
        }
    }
}

fn identity_migration_required(
    collisions: &[&LensCatalogEntry],
    spec: &LensSpec,
    manifest: &Path,
) -> CliError {
    let entry = collisions.first().copied();
    let mut legacy_errors = Vec::new();
    let recognized_legacy = collisions.iter().any(|entry| {
        match legacy_lensforge_manifest_v1_ids_from_path(&entry.manifest) {
            Ok(candidates) => candidates
                .iter()
                .any(|candidate| candidate.to_string() == entry.lens_id),
            Err(error) => {
                legacy_errors.push(format!(
                    "{}: {}: {}",
                    entry.manifest.display(),
                    error.code,
                    error.message
                ));
                false
            }
        }
    });
    let classification = if recognized_legacy {
        "recognized lensforge-manifest-v1 spec-side identity".to_string()
    } else if collisions.len() > 1 {
        "multiple persisted rows collide with the canonical identity".to_string()
    } else {
        "conflicting or ambiguous persisted identity".to_string()
    };
    let legacy_diagnostics = if legacy_errors.is_empty() {
        "none".to_string()
    } else {
        legacy_errors.join(" | ")
    };
    CliError::from(calyx_core::CalyxError {
        code: LENS_IDENTITY_MIGRATION_REQUIRED,
        message: format!(
            "{} catalog row(s) collide; first row name={} manifest={} lens_id={} conflicts with canonical name={} manifest={} lens_id={}: {classification}; legacy_reconstruction_errors={legacy_diagnostics}",
            collisions.len(),
            entry.map(|value| value.name.as_str()).unwrap_or("<none>"),
            entry
                .map(|value| value.manifest.display().to_string())
                .unwrap_or_else(|| "<none>".to_string()),
            entry
                .map(|value| value.lens_id.as_str())
                .unwrap_or("<none>"),
            spec.name,
            manifest.display(),
            spec.lens_id()
        ),
        remediation: "preserve the catalog bytes, inspect the legacy row, and perform an explicit lineage migration before admitting the canonical lens",
    })
}

impl MigrateFlags {
    fn parse(args: &[String]) -> CliResult<Self> {
        let mut flags = Self::default();
        let mut idx = 0;
        while idx < args.len() {
            match args[idx].as_str() {
                "--home" => {
                    idx += 1;
                    flags.home = Some(value(args, idx, "--home")?.into());
                }
                "--from" => {
                    idx += 1;
                    flags.from = Some(value(args, idx, "--from")?.into());
                }
                other => {
                    return Err(CliError::usage(format!(
                        "unexpected lens migrate-catalog flag {other}"
                    )));
                }
            }
            idx += 1;
        }
        Ok(flags)
    }
}

pub(crate) fn catalog_path(home: Option<&Path>) -> CliResult<PathBuf> {
    let root = match home {
        Some(path) => path.to_path_buf(),
        None => env::var_os("CALYX_HOME")
            .map(PathBuf::from)
            .ok_or_else(|| CliError::usage("CALYX_HOME is required or pass --home <dir>"))?,
    };
    Ok(root.join("lenses").join("catalog-db"))
}

pub(crate) fn read_catalog(path: &Path) -> CliResult<LensCatalog> {
    Ok(store::read(path)?)
}

pub(crate) fn read_catalog_with_readback(
    path: &Path,
) -> CliResult<(LensCatalog, LensCatalogDbReadback)> {
    Ok(store::read_with_readback(path)?)
}

fn read_legacy_catalog(path: &Path) -> CliResult<LensCatalog> {
    if !path.exists() {
        return Err(CliError::usage(format!(
            "legacy lens catalog {} does not exist",
            path.display()
        )));
    }
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(|err| {
        CliError::usage(format!(
            "parse legacy lens catalog {}: {err}",
            path.display()
        ))
    })
}

fn list_entry(entry: LensCatalogEntry) -> ListLensEntry {
    let health = health_from_manifest(&entry);
    ListLensEntry { entry, health }
}

fn health_from_manifest(entry: &LensCatalogEntry) -> LensHealth {
    match lens_spec_metadata_from_manifest_path(&entry.manifest) {
        Ok(spec) if spec.lens_id().to_string() == entry.lens_id => spec.health(),
        Ok(spec) => LensHealth::Failing {
            code: LENS_IDENTITY_MIGRATION_REQUIRED.to_string(),
            reason: format!(
                "catalog lens_id {} != canonical manifest lens_id {} for {}",
                entry.lens_id,
                spec.lens_id(),
                entry.manifest.display()
            ),
        },
        Err(error) => LensHealth::Failing {
            code: error.code.to_string(),
            reason: error.message,
        },
    }
}

pub(crate) fn write_catalog(
    path: &Path,
    catalog: &LensCatalog,
) -> CliResult<LensCatalogDbReadback> {
    Ok(store::write(path, catalog)?)
}

fn entry_from_spec(
    spec: &LensSpec,
    manifest: PathBuf,
    cost: LensCost,
    budget: PlacementBudget,
    resolved_placement: Placement,
) -> CliResult<LensCatalogEntry> {
    let placement = placement_from_spec(spec, cost, budget, resolved_placement)?;
    Ok(LensCatalogEntry {
        lens_id: spec.lens_id().to_string(),
        name: spec.name.clone(),
        modality: format!("{:?}", spec.modality).to_lowercase(),
        runtime: runtime_name(&spec.runtime).to_string(),
        dim: dim(spec.output),
        retrieval_only: spec.retrieval_only,
        excluded_from_dedup: spec.excluded_from_dedup,
        weights_sha256: hex_from_bytes(&spec.weights_sha256),
        manifest,
        cost,
        placement,
    })
}

fn placement_from_spec(
    spec: &LensSpec,
    cost: LensCost,
    budget: PlacementBudget,
    resolved_placement: Placement,
) -> CliResult<Placement> {
    let reason = match (&spec.runtime, resolved_placement) {
        (LensRuntime::CandleLocal { .. } | LensRuntime::FastembedQwen3 { .. }, _) => {
            "resolved Candle-family device policy"
        }
        (LensRuntime::MultimodalAdapter { .. }, _) => "resolved multimodal provider policy",
        (_, Placement::Cpu) => "CPU-native runtime",
        (_, Placement::Gpu) => "GPU-required runtime",
    };
    Ok(
        choose_resolved_placement(cost, budget, resolved_placement, reason)?
            .resource
            .placement,
    )
}

pub(crate) fn resolved_runtime_placement(spec: &LensSpec) -> CliResult<Placement> {
    match &spec.runtime {
        LensRuntime::Algorithmic { .. }
        | LensRuntime::StaticLookup { .. }
        | LensRuntime::ExternalCmd { .. } => Ok(Placement::Cpu),
        LensRuntime::CandleLocal { device, dtype, .. }
        | LensRuntime::FastembedQwen3 { device, dtype, .. } => {
            let policy = parse_frozen_device_policy(device)?;
            let precision = CandlePrecision::parse(dtype)?;
            if !policy.is_gpu() && precision != CandlePrecision::F32 {
                return Err(calyx_core::CalyxError {
                    code: "CALYX_LENS_CONFIG_INVALID",
                    message: format!(
                        "catalog admission refuses {} {} on {}; CPU companions require a distinct f32 frozen identity",
                        spec.name,
                        precision.as_str(),
                        policy.detail()
                    ),
                    remediation: "commission a CPU f32 companion manifest, or select the frozen CUDA manifest on its declared CUDA device",
                }
                .into());
            }
            Ok(policy.placement())
        }
        LensRuntime::MultimodalAdapter { .. } => {
            let lens = MultimodalAdapterLens::from_lens_spec(spec)?;
            Ok(if lens.provider().is_gpu() {
                Placement::Gpu
            } else {
                Placement::Cpu
            })
        }
        LensRuntime::TeiHttp { .. }
        | LensRuntime::Onnx { .. }
        | LensRuntime::OnnxColbert { .. }
        | LensRuntime::FastembedSparse { .. }
        | LensRuntime::FastembedBgem3 { .. }
        | LensRuntime::FastembedReranker { .. } => Ok(Placement::Gpu),
    }
}

fn estimate_lens_cost(spec: &LensSpec) -> CliResult<LensCost> {
    match &spec.runtime {
        LensRuntime::Algorithmic { .. }
        | LensRuntime::ExternalCmd { .. }
        | LensRuntime::TeiHttp { .. } => Ok(LensCost::zero()),
        LensRuntime::MultimodalAdapter { files, .. } => {
            let bytes = files_size(files)?;
            let lens = MultimodalAdapterLens::from_lens_spec(spec)?;
            if lens.provider().is_gpu() {
                return Ok(LensCost {
                    total_ms: 0.0,
                    ms_per_input: 0.0,
                    vram_bytes: bytes,
                    ram_bytes: bytes,
                    batch_ceiling: u32::MAX,
                });
            }
            Ok(LensCost {
                total_ms: 0.0,
                ms_per_input: 0.0,
                vram_bytes: 0,
                ram_bytes: bytes,
                batch_ceiling: u32::MAX,
            })
        }
        LensRuntime::StaticLookup {
            embeddings_file,
            tokenizer,
            ..
        } => measure_static_lookup_cost(spec, embeddings_file, tokenizer),
        LensRuntime::CandleLocal { files, .. }
        | LensRuntime::Onnx { files, .. }
        | LensRuntime::OnnxColbert { files, .. }
        | LensRuntime::FastembedSparse { files, .. }
        | LensRuntime::FastembedBgem3 { files, .. }
        | LensRuntime::FastembedReranker { files, .. }
        | LensRuntime::FastembedQwen3 { files, .. } => {
            let bytes = files_size(files)?;
            Ok(LensCost {
                total_ms: 0.0,
                ms_per_input: 0.0,
                vram_bytes: bytes,
                ram_bytes: bytes,
                batch_ceiling: u32::MAX,
            })
        }
    }
}

fn measure_static_lookup_cost(
    spec: &LensSpec,
    embeddings_file: &Path,
    tokenizer: &Path,
) -> CliResult<LensCost> {
    let lens = StaticLookupLens::from_lens_spec(spec)?;
    let probe = Input::new(
        spec.modality,
        b"Calyx lens admission profile probe".to_vec(),
    );
    let started = Instant::now();
    let _vector = lens.measure(&probe)?;
    let total_ms = started.elapsed().as_secs_f64() as f32 * 1000.0;
    Ok(LensCost {
        total_ms,
        ms_per_input: total_ms,
        vram_bytes: 0,
        ram_bytes: path_size(embeddings_file)?.saturating_add(path_size(tokenizer)?),
        batch_ceiling: batch_ceiling(total_ms),
    })
}

fn files_size(files: &[PathBuf]) -> CliResult<u64> {
    files
        .iter()
        .try_fold(0_u64, |acc, path| Ok(acc.saturating_add(path_size(path)?)))
}

fn path_size(path: &Path) -> CliResult<u64> {
    Ok(fs::metadata(path)?.len())
}

fn batch_ceiling(ms_per_input: f32) -> u32 {
    if !ms_per_input.is_finite() || ms_per_input < 0.0 {
        return 1;
    }
    if ms_per_input <= f32::EPSILON {
        return u32::MAX;
    }
    (1_000.0 / ms_per_input).floor().clamp(1.0, u32::MAX as f32) as u32
}
