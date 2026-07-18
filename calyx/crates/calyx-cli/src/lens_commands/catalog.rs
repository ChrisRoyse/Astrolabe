use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use calyx_core::{Input, Lens, LensCost, Placement};
use calyx_registry::{
    CandlePrecision, LensHealth, LensRuntime, LensSpec, MultimodalAdapterLens, OnnxInt8Attestation,
    PlacementBudget, StaticLookupLens, choose_resolved_placement,
    legacy_lensforge_manifest_v1_ids_from_path, parse_frozen_device_policy,
};
use serde::{Deserialize, Serialize};

use super::flags::{Flags, value};
use super::support::{dim, hex_from_bytes, runtime_name};
use crate::error::{CliError, CliResult};
use crate::output::print_json;

pub(super) mod admission;
mod budget;
mod store;

const LENS_IDENTITY_MIGRATION_REQUIRED: &str = "CALYX_LENS_IDENTITY_MIGRATION_REQUIRED";

pub(crate) use store::LensCatalogDbReadback;

use admission::{AttestedCatalogAdmission, attest_manifest};
pub(crate) use admission::{
    LocalExecutionAttestationReport, reparse_manifest_binding,
    reparse_manifest_binding_with_onnx_int8_attestation,
};
use budget::placement_budget_from_catalog;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct LensCatalog {
    pub(crate) lenses: Vec<LensCatalogEntry>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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
    pub(crate) manifest_sha256: String,
    #[serde(default)]
    pub(crate) execution_attestation: Option<LocalExecutionAttestationReport>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) onnx_int8_attestation: Option<OnnxInt8Attestation>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    onnx_int8_attestation: Option<OnnxInt8Attestation>,
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
    let source = match flags.from {
        Some(source) => source,
        None if store::has_v1_catalog_state(&catalog_path)? => catalog_path.clone(),
        None => store::legacy_catalog_path(&catalog_path),
    };
    let (catalog, v1_source_sha256, legacy_source, source) = if source.is_dir() {
        match store::read_v1_for_migration(&source)? {
            store::V1MigrationRead::Live(snapshot) => {
                (snapshot.catalog, Some(snapshot.source_sha256), None, source)
            }
            store::V1MigrationRead::Retired { catalog, readback } => {
                if !store::same_existing_catalog_path(&source, &catalog_path)? {
                    return Err(CliError::from(calyx_core::CalyxError {
                        code: "CALYX_LENS_CATALOG_SCHEMA_MIGRATION_REQUIRED",
                        message: format!(
                            "retired migration source {} cannot stand in for distinct destination {}",
                            source.display(),
                            catalog_path.display()
                        ),
                        remediation: "retired-v1 verification is in-place only: rerun without --from and point --home at the home that owns this catalog; a distinct empty destination requires a live-v1 catalog or a legacy registry.json source",
                    }));
                }
                validate_catalog_bindings(&catalog)?;
                return print_json(&MigrateReport {
                    source,
                    catalog: catalog_path,
                    count: catalog.lenses.len(),
                    readback,
                });
            }
        }
    } else {
        let (catalog, legacy_source) = read_legacy_catalog(&source)?;
        let source = legacy_source.canonical_path().to_path_buf();
        (catalog, None, Some(legacy_source), source)
    };
    let migrated = validate_catalog_migration(&catalog)?;
    let mutation_guard = store::CatalogMutationGuard::acquire(&catalog_path, "migrate-catalog")?;
    // This is the final path-byte snapshot before publication, performed
    // while every compliant catalog writer is excluded.
    validate_catalog_bindings(&migrated)?;
    let readback = store::write_migration(
        &catalog_path,
        &migrated,
        &source,
        v1_source_sha256.as_deref(),
        legacy_source.as_ref(),
        &mutation_guard,
    )?;
    drop(mutation_guard);
    print_json(&MigrateReport {
        source,
        catalog: catalog_path,
        count: migrated.lenses.len(),
        readback,
    })
}

fn validate_catalog_migration(catalog: &LensCatalog) -> CliResult<LensCatalog> {
    let mut migrated = Vec::with_capacity(catalog.lenses.len());
    for entry in &catalog.lenses {
        // Mandatory local rows execute and attest here. Every admission is
        // gathered before the sole catalog write below, so a later failure
        // cannot partially migrate the source catalog.
        let admission = attest_manifest(entry.manifest.clone()).map_err(|error| {
            CliError::from(calyx_core::CalyxError {
                code: LENS_IDENTITY_MIGRATION_REQUIRED,
                message: format!(
                    "legacy catalog row name={} manifest={} lens_id={} cannot be attested canonically: {}",
                    entry.name,
                    entry.manifest.display(),
                    entry.lens_id,
                    error
                ),
                remediation: "preserve the legacy catalog bytes, repair the manifest/runtime using the nested structured error, and rerun explicit migration",
            })
        })?;
        let (spec, manifest, manifest_sha256, execution_attestation, _) = admission.into_parts();
        let collisions = catalog
            .lenses
            .iter()
            .filter(|candidate| {
                catalog_identity_collides(
                    candidate,
                    &spec.lens_id().to_string(),
                    &spec.name,
                    &manifest,
                )
            })
            .collect::<Vec<_>>();
        if collisions.len() != 1 || !legacy_catalog_identity_matches(entry, &spec, &manifest)? {
            return Err(identity_migration_required(&collisions, &spec, &manifest));
        }
        let mut migrated_entry = entry.clone();
        migrated_entry.manifest = manifest;
        migrated_entry.manifest_sha256 = manifest_sha256;
        migrated_entry.execution_attestation = execution_attestation;
        migrated.push(migrated_entry);
    }
    migrated.sort_by(|left, right| left.lens_id.cmp(&right.lens_id));
    Ok(LensCatalog { lenses: migrated })
}

pub(crate) fn add_manifest_to_catalog(
    home: Option<&Path>,
    manifest: PathBuf,
) -> CliResult<AddReport> {
    // Verification deliberately precedes even the catalog read and
    // idempotent collision path.
    let admission = attest_manifest(manifest)?;
    add_attested_manifest_to_catalog(home, admission)
}

pub(crate) fn add_attested_manifest_to_catalog(
    home: Option<&Path>,
    admission: AttestedCatalogAdmission,
) -> CliResult<AddReport> {
    let (spec, manifest, manifest_sha256, execution_attestation, onnx_int8_attestation) =
        admission.into_parts();
    let catalog_path = catalog_path(home)?;
    let mutation_guard = store::CatalogMutationGuard::acquire(&catalog_path, "lens-add")?;
    let mut catalog = read_catalog(&catalog_path)?;
    let expected_catalog_sha256 = store::catalog_sha256(&catalog)?;
    let lens_id = spec.lens_id().to_string();
    let collisions = catalog
        .lenses
        .iter()
        .filter(|entry| catalog_identity_collides(entry, &lens_id, &spec.name, &manifest))
        .collect::<Vec<_>>();
    if !collisions.is_empty() {
        if collisions.len() == 1
            && canonical_catalog_identity_matches(collisions[0], &spec, &manifest)?
            && collisions[0].manifest_sha256 == manifest_sha256
            && execution_attestations_match(
                collisions[0].execution_attestation.as_ref(),
                execution_attestation.as_ref(),
            )
        {
            let existing = collisions[0];
            return Ok(AddReport {
                catalog: catalog_path,
                lens_id: existing.lens_id.clone(),
                name: existing.name.clone(),
                manifest: existing.manifest.clone(),
                cost: existing.cost,
                placement: existing.placement,
                onnx_int8_attestation,
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
    let entry = entry_from_spec(
        &spec,
        manifest,
        manifest_sha256.clone(),
        execution_attestation,
        cost,
        budget,
        resolved_placement,
    )?;
    catalog.lenses.push(entry.clone());
    catalog
        .lenses
        .sort_by(|left, right| left.lens_id.cmp(&right.lens_id));
    // Last operation before persistence: reparse and rehash one byte snapshot
    // and require admitted == current == row.
    let (write_spec, write_sha256) = reparse_manifest_binding(&entry.manifest)?;
    if write_spec != spec
        || write_sha256 != entry.manifest_sha256
        || write_sha256 != manifest_sha256
    {
        return Err(CliError::from(calyx_core::CalyxError {
            code: "CALYX_LENS_CATALOG_ADMISSION_STALE",
            message: format!(
                "manifest {} changed after runtime admission (admitted_sha256={} current_sha256={})",
                entry.manifest.display(),
                manifest_sha256,
                write_sha256
            ),
            remediation: "preserve both manifest hashes, discard the stale admission, and rerun verification against the final immutable bytes",
        }));
    }
    write_catalog(
        &catalog_path,
        &catalog,
        &expected_catalog_sha256,
        &mutation_guard,
    )?;
    Ok(AddReport {
        catalog: catalog_path,
        lens_id: entry.lens_id,
        name: entry.name,
        manifest: entry.manifest,
        cost: entry.cost,
        placement: entry.placement,
        onnx_int8_attestation,
        count: catalog.lenses.len(),
    })
}

fn execution_attestations_match(
    persisted: Option<&LocalExecutionAttestationReport>,
    admitted: Option<&LocalExecutionAttestationReport>,
) -> bool {
    match (persisted, admitted) {
        (Some(persisted), Some(admitted)) => persisted.same_execution_identity(admitted),
        (None, None) => true,
        _ => false,
    }
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
    let (persisted_spec, manifest_sha256) = reparse_manifest_binding(manifest)?;
    canonical_catalog_snapshot_matches(entry, spec, manifest, &persisted_spec, &manifest_sha256)
}

pub(crate) fn bound_spec_from_catalog_entry(entry: &LensCatalogEntry) -> CliResult<LensSpec> {
    let (spec, manifest_sha256) = reparse_manifest_binding(&entry.manifest)?;
    if canonical_catalog_snapshot_matches(entry, &spec, &entry.manifest, &spec, &manifest_sha256)? {
        return Ok(spec);
    }
    Err(CliError::from(calyx_core::CalyxError {
        code: "CALYX_LENS_CATALOG_MANIFEST_BINDING_MISMATCH",
        message: format!(
            "catalog row {} does not match the current one-snapshot parse/hash of {} (row_sha256={} current_sha256={})",
            entry.lens_id,
            entry.manifest.display(),
            entry.manifest_sha256,
            manifest_sha256
        ),
        remediation: "preserve the catalog and manifest bytes, restore the admitted manifest, and rerun explicit attestation; never rewrite a frozen manifest in place",
    }))
}

pub(crate) fn canonical_catalog_snapshot_matches(
    entry: &LensCatalogEntry,
    admitted_spec: &LensSpec,
    manifest: &Path,
    observed_spec: &LensSpec,
    observed_manifest_sha256: &str,
) -> CliResult<bool> {
    Ok(observed_spec == admitted_spec
        && entry.manifest_sha256 == observed_manifest_sha256
        && legacy_catalog_identity_matches(entry, admitted_spec, manifest)?)
}

fn legacy_catalog_identity_matches(
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
        | LensRuntime::FastembedDense { files, .. }
        | LensRuntime::FastembedDensePlaced { files, .. }
        | LensRuntime::OnnxColbert { files, .. }
        | LensRuntime::FastembedSparse { files, .. }
        | LensRuntime::FastembedBgem3 { files, .. }
        | LensRuntime::FastembedReranker { files, .. }
        | LensRuntime::FastembedSparsePlaced { files, .. }
        | LensRuntime::FastembedBgem3Placed { files, .. }
        | LensRuntime::FastembedRerankerPlaced { files, .. }
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
                    if flags.home.is_some() {
                        return Err(CliError::from(calyx_core::CalyxError {
                            code: "CALYX_LENS_CATALOG_CLI_DUPLICATE_FLAG",
                            message: "lens migrate-catalog received --home more than once"
                                .to_string(),
                            remediation: "provide exactly one --home <dir> selector so the authoritative destination is unambiguous",
                        }));
                    }
                    idx += 1;
                    flags.home = Some(value(args, idx, "--home")?.into());
                }
                "--from" => {
                    if flags.from.is_some() {
                        return Err(CliError::from(calyx_core::CalyxError {
                            code: "CALYX_LENS_CATALOG_CLI_DUPLICATE_FLAG",
                            message: "lens migrate-catalog received --from more than once"
                                .to_string(),
                            remediation: "provide exactly one --from <catalog-db|registry.json> selector so the attested source is unambiguous",
                        }));
                    }
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
    let catalog = store::read(path)?;
    validate_catalog_bindings(&catalog)?;
    Ok(catalog)
}

pub(crate) fn read_catalog_with_readback(
    path: &Path,
) -> CliResult<(LensCatalog, LensCatalogDbReadback)> {
    let (catalog, readback) = store::read_with_readback(path)?;
    validate_catalog_bindings(&catalog)?;
    Ok((catalog, readback))
}

fn read_legacy_catalog(path: &Path) -> CliResult<(LensCatalog, store::LegacyCatalogSource)> {
    let source = store::LegacyCatalogSource::open(path)?;
    let catalog = serde_json::from_slice(source.bytes()).map_err(|err| {
        CliError::from(calyx_core::CalyxError {
            code: "CALYX_LENS_CATALOG_IMPORT_SOURCE_INVALID",
            message: format!(
                "legacy catalog source {} is not valid catalog JSON at line {} column {}: {err}",
                source.canonical_path().display(),
                err.line(),
                err.column()
            ),
            remediation: "preserve the exact source bytes for investigation, repair the JSON at the reported location without changing its intended catalog meaning, then rerun migration from that same source path",
        })
    })?;
    Ok((catalog, source))
}

fn list_entry(entry: LensCatalogEntry) -> ListLensEntry {
    let (health, onnx_int8_attestation) = health_from_manifest(&entry);
    ListLensEntry {
        entry,
        health,
        onnx_int8_attestation,
    }
}

fn health_from_manifest(entry: &LensCatalogEntry) -> (LensHealth, Option<OnnxInt8Attestation>) {
    match reparse_manifest_binding_with_onnx_int8_attestation(&entry.manifest) {
        Ok((spec, manifest_sha256, attestation))
            if spec.lens_id().to_string() == entry.lens_id
                && manifest_sha256 == entry.manifest_sha256 =>
        {
            (spec.health(), attestation)
        }
        Ok((_, manifest_sha256, _)) if manifest_sha256 != entry.manifest_sha256 => (
            LensHealth::Failing {
                code: "CALYX_LENS_CATALOG_MANIFEST_DIGEST_MISMATCH".to_string(),
                reason: format!(
                    "catalog manifest_sha256 {} != current manifest_sha256 {} for {}",
                    entry.manifest_sha256,
                    manifest_sha256,
                    entry.manifest.display()
                ),
            },
            None,
        ),
        Ok((spec, _, _)) => (
            LensHealth::Failing {
                code: LENS_IDENTITY_MIGRATION_REQUIRED.to_string(),
                reason: format!(
                    "catalog lens_id {} != canonical manifest lens_id {} for {}",
                    entry.lens_id,
                    spec.lens_id(),
                    entry.manifest.display()
                ),
            },
            None,
        ),
        Err(error) => (
            LensHealth::Failing {
                code: error.code().to_string(),
                reason: error.message().to_string(),
            },
            None,
        ),
    }
}

fn write_catalog(
    path: &Path,
    catalog: &LensCatalog,
    expected_catalog_sha256: &str,
    mutation_guard: &store::CatalogMutationGuard,
) -> CliResult<LensCatalogDbReadback> {
    validate_catalog_bindings(catalog)?;
    Ok(store::write(
        path,
        catalog,
        expected_catalog_sha256,
        mutation_guard,
    )?)
}

pub(super) fn write_catalog_reduction(
    path: &Path,
    proposed: &LensCatalog,
    expected_catalog_sha256: &str,
) -> CliResult<LensCatalogDbReadback> {
    let mutation_guard = store::CatalogMutationGuard::acquire(path, "lens-remove")?;
    let current = read_catalog(path)?;
    let current_sha256 = store::catalog_sha256(&current)?;
    if current_sha256 != expected_catalog_sha256 {
        return Err(CliError::from(calyx_core::CalyxError {
            code: "CALYX_LENS_CATALOG_CONCURRENT_MUTATION",
            message: format!(
                "catalog {} changed before reduction (expected_sha256={} current_sha256={})",
                path.display(),
                expected_catalog_sha256,
                current_sha256
            ),
            remediation: "preserve both catalog readbacks, recompute the removal from the current authoritative catalog, and retry",
        }));
    }
    if proposed.lenses.len() >= current.lenses.len()
        || proposed
            .lenses
            .iter()
            .any(|entry| !current.lenses.contains(entry))
    {
        return Err(CliError::from(calyx_core::CalyxError {
            code: "CALYX_LENS_CATALOG_REDUCTION_INVALID",
            message: "catalog reduction must contain only byte-equivalent existing entries and remove at least one row".to_string(),
            remediation: "read the authoritative v2 catalog, remove only the selected existing row, and retry; additions require sealed runtime admission",
        }));
    }
    validate_catalog_bindings(proposed)?;
    Ok(store::write(
        path,
        proposed,
        expected_catalog_sha256,
        &mutation_guard,
    )?)
}

pub(super) fn catalog_fingerprint(catalog: &LensCatalog) -> CliResult<String> {
    Ok(store::catalog_sha256(catalog)?)
}

fn validate_catalog_bindings(catalog: &LensCatalog) -> CliResult<()> {
    for entry in &catalog.lenses {
        bound_spec_from_catalog_entry(entry)?;
    }
    Ok(())
}

fn entry_from_spec(
    spec: &LensSpec,
    manifest: PathBuf,
    manifest_sha256: String,
    execution_attestation: Option<LocalExecutionAttestationReport>,
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
        manifest_sha256,
        execution_attestation,
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
        LensRuntime::FastembedDensePlaced { execution, .. }
        | LensRuntime::FastembedSparsePlaced { execution, .. }
        | LensRuntime::FastembedBgem3Placed { execution, .. }
        | LensRuntime::FastembedRerankerPlaced { execution, .. } => {
            fastembed_placement(execution)
        }
        LensRuntime::TeiHttp { .. }
        | LensRuntime::Onnx { .. }
        | LensRuntime::OnnxColbert { .. } => Ok(Placement::Gpu),
        LensRuntime::FastembedDense { .. }
        | LensRuntime::FastembedSparse { .. }
        | LensRuntime::FastembedBgem3 { .. }
        | LensRuntime::FastembedReranker { .. } => Err(calyx_core::CalyxError {
            code: "CALYX_FASTEMBED_LEGACY_EXECUTION_UNBOUND",
            message: format!(
                "catalog refuses legacy FastEmbed lens {} without an execution identity",
                spec.name
            ),
            remediation: "recommission the lens with execution_device set explicitly to cuda_fail_loud or cpu_explicit",
        }
        .into()),
    }
}

fn fastembed_placement(execution: &str) -> CliResult<Placement> {
    match execution {
        "cuda_fail_loud" => Ok(Placement::Gpu),
        "cpu_explicit" => Ok(Placement::Cpu),
        other => Err(calyx_core::CalyxError {
            code: "CALYX_FASTEMBED_EXECUTION_IDENTITY_NONCANONICAL",
            message: format!("catalog found noncanonical FastEmbed execution token {other:?}"),
            remediation: "recommission the lens with execution_device set explicitly to cuda_fail_loud or cpu_explicit; never rewrite frozen identity in place",
        }
        .into()),
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
        | LensRuntime::FastembedDense { files, .. }
        | LensRuntime::FastembedDensePlaced { files, .. }
        | LensRuntime::OnnxColbert { files, .. }
        | LensRuntime::FastembedSparse { files, .. }
        | LensRuntime::FastembedBgem3 { files, .. }
        | LensRuntime::FastembedReranker { files, .. }
        | LensRuntime::FastembedSparsePlaced { files, .. }
        | LensRuntime::FastembedBgem3Placed { files, .. }
        | LensRuntime::FastembedRerankerPlaced { files, .. }
        | LensRuntime::FastembedQwen3 { files, .. } => {
            let bytes = files_size(files)?;
            let placement = resolved_runtime_placement(spec)?;
            Ok(LensCost {
                total_ms: 0.0,
                ms_per_input: 0.0,
                vram_bytes: if placement == Placement::Gpu {
                    bytes
                } else {
                    0
                },
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
