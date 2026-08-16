use calyx_aster::mvcc::Snapshot;
use calyx_aster::vault::{SlotVectorResolver, StrictRawSlotResolver};
use calyx_core::{CxId, SlotId, SystemClock};
use calyx_registry::VaultPanelState;

use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RebuildProgress<'a> {
    pub phase: &'static str,
    pub slot: Option<SlotId>,
    pub rows: Option<usize>,
    pub base_seq: Option<u64>,
    pub manifest_path: Option<&'a Path>,
    /// Free-form context for exceptional events, e.g. why prior-segment
    /// reuse was declined during a rebuild (#1109).
    pub detail: Option<String>,
}

impl<'a> RebuildProgress<'a> {
    pub(super) fn phase(phase: &'static str) -> Self {
        Self {
            phase,
            slot: None,
            rows: None,
            base_seq: None,
            manifest_path: None,
            detail: None,
        }
    }

    pub(super) fn slot(
        phase: &'static str,
        slot: SlotId,
        rows: Option<usize>,
        base_seq: Option<u64>,
    ) -> Self {
        Self {
            phase,
            slot: Some(slot),
            rows,
            base_seq,
            manifest_path: None,
            detail: None,
        }
    }

    pub(super) fn slot_detail(phase: &'static str, slot: SlotId, detail: String) -> Self {
        Self {
            detail: Some(detail),
            ..Self::slot(phase, slot, None, None)
        }
    }

    pub(super) fn manifest(phase: &'static str, manifest_path: &'a Path, base_seq: u64) -> Self {
        Self {
            phase,
            slot: None,
            rows: None,
            base_seq: Some(base_seq),
            manifest_path: Some(manifest_path),
            detail: None,
        }
    }
}

pub fn rebuild_for_vault(vault_dir: &Path, vault: &AsterVault) -> CliResult {
    rebuild_for_vault_with_resolver(vault_dir, vault, &StrictRawSlotResolver, |_| Ok(()))
}

/// Rebuilds persistent search indexes through the exact persisted panel and
/// registry interpretation. Compressed generations are decoded only after the
/// Registry whole-column primary/proof/Assay serving audit succeeds.
pub fn rebuild_for_vault_resolved(
    vault_dir: &Path,
    vault: &AsterVault,
    state: &VaultPanelState,
) -> CliResult {
    rebuild_for_vault_with_resolver(vault_dir, vault, state, |_| Ok(()))
}

pub fn rebuild_for_vault_with_progress<F>(
    vault_dir: &Path,
    vault: &AsterVault,
    mut progress: F,
) -> CliResult
where
    F: FnMut(RebuildProgress<'_>) + Send,
{
    rebuild_for_vault_with_resolver(vault_dir, vault, &StrictRawSlotResolver, |event| {
        progress(event);
        Ok(())
    })
}

/// Progress-reporting variant of [`rebuild_for_vault_resolved`].
pub fn rebuild_for_vault_with_progress_resolved<F>(
    vault_dir: &Path,
    vault: &AsterVault,
    state: &VaultPanelState,
    mut progress: F,
) -> CliResult
where
    F: FnMut(RebuildProgress<'_>) + Send,
{
    rebuild_for_vault_with_resolver(vault_dir, vault, state, |event| {
        progress(event);
        Ok(())
    })
}

pub fn rebuild_for_vault_with_fallible_progress<F>(
    vault_dir: &Path,
    vault: &AsterVault,
    progress: F,
) -> CliResult
where
    F: FnMut(RebuildProgress<'_>) -> CliResult + Send,
{
    rebuild_for_vault_with_resolver(vault_dir, vault, &StrictRawSlotResolver, progress)
}

/// Fallible progress-reporting variant of [`rebuild_for_vault_resolved`].
pub fn rebuild_for_vault_with_fallible_progress_resolved<F>(
    vault_dir: &Path,
    vault: &AsterVault,
    state: &VaultPanelState,
    progress: F,
) -> CliResult
where
    F: FnMut(RebuildProgress<'_>) -> CliResult + Send,
{
    rebuild_for_vault_with_resolver(vault_dir, vault, state, progress)
}

fn rebuild_for_vault_with_resolver<F, R>(
    vault_dir: &Path,
    vault: &AsterVault,
    resolver: &R,
    progress: F,
) -> CliResult
where
    F: FnMut(RebuildProgress<'_>) -> CliResult + Send,
    R: SlotVectorResolver<SystemClock> + Sync + ?Sized,
{
    super::rebuild_stream::rebuild_for_vault_with_progress(vault_dir, vault, resolver, progress)
}

pub(super) fn previous_manifest(vault_dir: &Path) -> CliResult<Option<SearchIndexManifest>> {
    let path = manifest_path(vault_dir);
    if !path.exists() {
        return Ok(None);
    }
    let manifest: SearchIndexManifest =
        serde_json::from_slice(&fs::read(&path)?).map_err(|err| {
            stale(format!(
                "persistent search index manifest {} is unreadable before rebuild: {err}",
                path.display()
            ))
        })?;
    if manifest.format != MANIFEST_FORMAT {
        return Err(stale(format!(
            "persistent search index manifest {} has format {}; expected {MANIFEST_FORMAT}",
            path.display(),
            manifest.format
        )));
    }
    Ok(Some(manifest))
}

pub fn load_docs(vault: &AsterVault) -> CliResult<BTreeMap<CxId, Constellation>> {
    load_docs_with_resolver(vault, &StrictRawSlotResolver)
}

/// Loads the complete visible corpus through the exact persisted panel and
/// registry interpretation.
pub fn load_docs_resolved(
    vault: &AsterVault,
    state: &VaultPanelState,
) -> CliResult<BTreeMap<CxId, Constellation>> {
    load_docs_with_resolver(vault, state)
}

fn load_docs_with_resolver<R>(
    vault: &AsterVault,
    resolver: &R,
) -> CliResult<BTreeMap<CxId, Constellation>>
where
    R: SlotVectorResolver<SystemClock> + ?Sized,
{
    let snapshot = vault.pin_reader(
        calyx_aster::mvcc::Freshness::FreshDerived,
        calyx_aster::knobs::SNAPSHOT_PIN_SESSION_STALL_WINDOW_MS.default,
    );
    let _guard = PinnedReadGuard::new(vault, snapshot);
    load_docs_at_with_resolver(vault, _guard.snapshot(), resolver)
}

fn load_docs_at_with_resolver<R>(
    vault: &AsterVault,
    snapshot: Snapshot,
    resolver: &R,
) -> CliResult<BTreeMap<CxId, Constellation>>
where
    R: SlotVectorResolver<SystemClock> + ?Sized,
{
    Ok(vault
        .load_constellations_resolved_at(snapshot.seq(), resolver)?
        .into_iter()
        .map(|constellation| (constellation.cx_id, constellation))
        .collect())
}

struct PinnedReadGuard<'a> {
    vault: &'a AsterVault,
    snapshot: Snapshot,
}

impl<'a> PinnedReadGuard<'a> {
    fn new(vault: &'a AsterVault, snapshot: Snapshot) -> Self {
        Self { vault, snapshot }
    }

    fn snapshot(&self) -> Snapshot {
        self.snapshot
    }
}

impl Drop for PinnedReadGuard<'_> {
    fn drop(&mut self) {
        let _ = self.vault.release_reader(self.snapshot.lease().id());
    }
}

pub(super) fn prune_stale_index_artifacts(
    vault_dir: &Path,
    root: &Path,
    manifest: &SearchIndexManifest,
) -> CliResult {
    let keep = referenced_index_artifacts(vault_dir, root, manifest)?;
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if !is_prunable_index_artifact(&name) || keep.iter().any(|item| item == &path) {
            continue;
        }
        if entry.file_type()?.is_dir() {
            fs::remove_dir_all(&path)?;
        } else {
            fs::remove_file(&path)?;
        }
    }
    Ok(())
}

fn referenced_index_artifacts(
    vault_dir: &Path,
    root: &Path,
    manifest: &SearchIndexManifest,
) -> CliResult<Vec<PathBuf>> {
    let mut keep = vec![manifest_path(vault_dir)];
    if let Some(filter) = &manifest.filter {
        keep.push(vault_dir.join(&filter.index_rel));
    }
    for entry in &manifest.slots {
        if let Some(index_rel) = &entry.index_rel {
            keep.push(vault_dir.join(index_rel));
            if entry.kind == "multi_maxsim_segments" {
                keep.extend(multi::referenced_segment_artifacts(
                    vault_dir,
                    entry,
                    SlotId::new(entry.slot),
                )?);
            }
        }
        if let Some(graph_rel) = &entry.graph_rel {
            let graph = vault_dir.join(graph_rel);
            let ann_dir = graph.parent().ok_or_else(|| {
                stale(format!(
                    "persistent slot {} graph path has no parent directory",
                    entry.slot
                ))
            })?;
            if ann_dir.parent().is_some_and(|parent| parent == root) {
                keep.push(ann_dir.to_path_buf());
            } else {
                keep.push(graph);
            }
        }
        if let Some(id_map_rel) = &entry.id_map_rel {
            keep.push(vault_dir.join(id_map_rel));
        }
    }
    keep.sort();
    keep.dedup();
    Ok(keep)
}

fn is_prunable_index_artifact(name: &str) -> bool {
    name.starts_with("slot_") || name.starts_with("filter_") || name.starts_with("filters_")
}
