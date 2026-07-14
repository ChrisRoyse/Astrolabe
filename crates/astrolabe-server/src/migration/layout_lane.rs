//! Directory-role frame + `placement_truth` cross-term + `layout_map` aspect
//! server wiring (#311 / #180b).
//!
//! This module is the thin server surface over the tested
//! `astrolabe_kernel::layout` computation layer. It has two halves:
//!
//! * **Write path** ([`persist_layout_frames`]) — runs during shadow
//!   import/weave. It reconstructs each directory's role frame from the members'
//!   persisted S23 `layer_role` posteriors (or the declared-map prior), writes
//!   the frame rows into the Kernel CF (`astrolabe.scope_summary.v1` substrate)
//!   and the `placement_truth` cross-term rows into the XTerm CF, all in one
//!   `write_cf_batch_with_ledger_entry` commit, then independently reads every
//!   row back at the commit seq (FSV). It mirrors the
//!   [`super::persist_delta_invalidations`] write-batch + ledger + readback
//!   discipline.
//! * **Read path** ([`read_layout_map_aspect`]) — runs inside
//!   `get_architecture`. It reopens the persisted shadow vault read-only,
//!   recomputes the directory frames from persisted S23 state, folds
//!   [`astrolabe_kernel::build_layout_map_aspect`] and
//!   [`astrolabe_kernel::layout_boundary_diff`] into the `layout_map` aspect,
//!   and prepends the first-touch orientation preamble
//!   ([`astrolabe_kernel::first_touch_layout`], fail-closed). It never
//!   zero-fills: when the S23 posteriors that the frame aggregates from are not
//!   persisted (a vault imported before the panel v2 roster landed, or one with
//!   no applicable symbols), the aspect is a labeled `unavailable` payload, never
//!   a fabricated or empty map. Since #336 the shadow pipeline runs panel v2
//!   ([`SHADOW_PANEL_VERSION`], S0–S23), so S23 `layer_role` posteriors are
//!   persisted for applicable symbols and real repos yield real frames.
//!
//! No thresholds live here: every structural decision is the kernel's fixed math
//! (argmax role, overlap agreement). This module only reads persisted bytes,
//! shapes the response, and preserves the HONEST trust/freshness/provenance
//! labels.

use super::*;
use astrolabe_kernel::{
    ASTRO_LAYOUT_FIRST_TOUCH_UNAVAILABLE, ASTRO_LAYOUT_FRAME_EMPTY,
    DIRECTORY_ROLE_FRAME_PROVENANCE, DeclaredLearnedDisagreement, DirectoryLayoutEntry,
    DirectoryLayoutInput, DirectoryMember, DirectoryRoleFrame, FirstTouchLayout, FrameProvenance,
    LAYOUT_MAP_ASPECT_SCHEMA, PLACEMENT_TRUTH_PROVENANCE, build_layout_map_aspect,
    compute_directory_role_frame, compute_placement_truth, declared_role_for_path,
    directory_role_frame_artifact_bytes, first_touch_layout, layout_boundary_diff,
    placement_truth_row_bytes, placement_truth_xterm_key,
};
use astrolabe_panel::LayerRole;
use astrolabe_panel::layout_registry::{
    LAYOUT_COHERENCE_FLOOR, LAYOUT_ESCALATION_THRESHOLD, classify_layout_coherence,
};
use calyx_core::CxId;
use calyx_ledger::EntryKind;

/// Ledger + aspect schema for the persisted directory-role frame lane.
const LAYOUT_FRAME_SCHEMA: &str = "astrolabe.layout_frame_lane.v1";
/// Ledger actor for the layout-frame write lane.
const LAYOUT_FRAME_ACTOR: &str = "astrolabe-shadow-layout-frame";
/// Kernel CF key prefix for a persisted directory-role frame row.
const LAYOUT_FRAME_PREFIX: &[u8] = b"astrolabe:shadow:layout_frame:v1\0";
/// XTerm CF key prefix for a persisted `placement_truth` cross-term row.
const LAYOUT_PLACEMENT_PREFIX: &[u8] = b"astrolabe:shadow:placement_truth:v1\0";
/// Kv CF key prefix for a persisted per-scope layout-coherence enforcement row
/// (the observe-only / escalation-ladder decision — #313).
const LAYOUT_ENFORCE_PREFIX: &[u8] = b"astrolabe:shadow:layout_enforcement:v1\0";
/// Reserved scope name for the whole-project enforcement row (mean coherence).
/// A real directory path from [`directory_of`] never begins with `@`, so this
/// cannot collide with a directory scope.
const LAYOUT_ENFORCE_PROJECT_SCOPE: &str = "@project";
/// Row/aspect schema for a persisted layout-coherence enforcement decision.
const LAYOUT_ENFORCE_SCHEMA: &str = "astrolabe.layout.enforcement.v1";
/// Provenance label: the physical source of a persisted enforcement row.
const LAYOUT_ENFORCE_PROVENANCE: &str = "AsterVault:ColumnFamily::Kv:layout_enforcement";
/// S23 `layer_role` slot id — the posterior a directory-role frame aggregates.
const LAYER_ROLE_SLOT: u16 = 23;

/// One directory member paired with its CxId (for the `placement_truth` key).
struct LayoutMember {
    symbol_cx: CxId,
    member: DirectoryMember,
}

/// One directory's fully-derived layout bundle: its frame, members, stable
/// directory identity, and declared role (if any).
struct DirectoryBundle {
    directory_path: String,
    directory_cx: Vec<u8>,
    declared_role: Option<LayerRole>,
    frame: DirectoryRoleFrame,
    members: Vec<LayoutMember>,
}

/// The gathered layout state derived from persisted vault state.
struct GatheredLayout {
    bundles: Vec<DirectoryBundle>,
    /// Non-structural symbols whose S23 posterior was decoded off persisted state.
    s23_symbols_seen: usize,
    /// Non-structural symbols with a CxId but no persisted S23 posterior.
    missing_s23: usize,
}

/// Stable 32-byte directory identity: `sha256(project \0 directory_path)`.
fn directory_cx_bytes(project: &str, directory_path: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"astrolabe-layout-directory-v1");
    hasher.update([0]);
    hasher.update(project.as_bytes());
    hasher.update([0]);
    hasher.update(directory_path.as_bytes());
    hasher.finalize().to_vec()
}

/// Kernel CF key for a directory-role frame row.
fn layout_frame_key(project: &str, directory_cx: &[u8]) -> Vec<u8> {
    let mut key = LAYOUT_FRAME_PREFIX.to_vec();
    key.extend_from_slice(project.as_bytes());
    key.push(0);
    key.extend_from_slice(directory_cx);
    key
}

/// XTerm CF key for a `placement_truth` cross-term row. The inner
/// `(symbol_cx || directory_cx)` shape is the kernel's canonical key; the
/// server prefix keeps these rows scannable and disjoint from agreement rows.
fn layout_placement_key(project: &str, symbol_cx: &[u8], directory_cx: &[u8]) -> Vec<u8> {
    let mut key = LAYOUT_PLACEMENT_PREFIX.to_vec();
    key.extend_from_slice(project.as_bytes());
    key.push(0);
    key.extend_from_slice(&placement_truth_xterm_key(symbol_cx, directory_cx));
    key
}

/// Kv CF key for a per-scope layout-coherence enforcement row.
fn layout_enforcement_key(project: &str, scope: &str) -> Vec<u8> {
    let mut key = LAYOUT_ENFORCE_PREFIX.to_vec();
    key.extend_from_slice(project.as_bytes());
    key.push(0);
    key.extend_from_slice(scope.as_bytes());
    key
}

/// Canonical value bytes for one persisted enforcement decision row.
///
/// `coherence` is emitted both as a JSON number (for the readiness surface) and as
/// its exact IEEE-754 bit pattern (for byte-stable readback). The enforcement mode
/// is classified by the frozen [`classify_layout_coherence`] ladder — the registry
/// knob thresholds, never inline literals.
fn layout_enforcement_row_bytes(
    scope: &str,
    scope_kind: &str,
    coherence: f32,
    member_count: usize,
    directory_count: usize,
    trust: &str,
) -> Vec<u8> {
    let mode = classify_layout_coherence(coherence);
    serde_json::to_vec(&json!({
        "schema": LAYOUT_ENFORCE_SCHEMA,
        "scope": scope,
        "scope_kind": scope_kind,
        "coherence": coherence,
        "coherence_bits": format!("{:08x}", coherence.to_bits()),
        "member_count": member_count,
        "directory_count": directory_count,
        "coherence_floor": LAYOUT_COHERENCE_FLOOR,
        "escalation_threshold": LAYOUT_ESCALATION_THRESHOLD,
        "enforcement_mode": mode.as_str(),
        "enforcement_skipped": mode.is_observe_only(),
        "knob_content_sha256": hex_lower(&astrolabe_panel::layout_registry::enforcement_content_sha()),
        "provenance": LAYOUT_ENFORCE_PROVENANCE,
        "trust": trust,
    }))
    .expect("encode layout enforcement row")
}

/// Prefix over which persisted frame rows for a project can be scanned back.
#[cfg(test)]
fn layout_frame_scan_prefix(project: &str) -> Vec<u8> {
    let mut key = LAYOUT_FRAME_PREFIX.to_vec();
    key.extend_from_slice(project.as_bytes());
    key.push(0);
    key
}

/// Prefix over which persisted `placement_truth` rows for a project can be scanned.
#[cfg(test)]
fn layout_placement_scan_prefix(project: &str) -> Vec<u8> {
    let mut key = LAYOUT_PLACEMENT_PREFIX.to_vec();
    key.extend_from_slice(project.as_bytes());
    key.push(0);
    key
}

/// Derives the directory path of a symbol's source file (parent components,
/// separator-normalized). Root-level files map to `"."` — a labeled directory,
/// never an empty key.
fn directory_of(file_path: &str) -> String {
    let mut components: Vec<&str> = file_path
        .split(['/', '\\'])
        .filter(|component| !component.is_empty())
        .collect();
    if components.len() <= 1 {
        return ".".to_string();
    }
    components.pop();
    components.join("/")
}

/// Reads a symbol's persisted S23 posterior and re-encodes it into the exact
/// guard-raw envelope the kernel frame decodes ([`astrolabe_panel::decode_slot_raw`]).
///
/// The persisted bytes live in the guard-raw sidecar CF `slot_23.raw`; the
/// quantized `slot_23` CF is a fallback for pipelines that do not carry the
/// guard sidecar. `Ok(None)` is a *labeled absence* (no S23 posterior persisted
/// for this symbol), never a fabricated vector.
fn read_member_s23_bytes<C>(
    vault: &AsterVault<C>,
    at_seq: u64,
    cx_id: CxId,
) -> Result<Option<Vec<u8>>, DynError>
where
    C: Clock,
{
    let slot = SlotId::new(LAYER_ROLE_SLOT);
    let key = slot_key(cx_id);
    let raw = vault.read_cf_at(at_seq, ColumnFamily::slot_raw(slot), &key)?;
    let bytes = match raw {
        Some(bytes) => bytes,
        None => match vault.read_cf_at(at_seq, ColumnFamily::slot(slot), &key)? {
            Some(bytes) => bytes,
            None => return Ok(None),
        },
    };
    // Decode via the vault codec, re-encode via the panel guard-raw codec so the
    // kernel's `decode_slot_raw` accepts the bytes regardless of which CF codec
    // wrote them. Both consume `calyx_core::SlotVector`.
    let vector = calyx_aster::vault::encode::decode_slot_vector(&bytes)?;
    if matches!(vector, SlotVector::Absent { .. }) {
        // A guard-raw sidecar records a concrete measured vector; an Absent
        // envelope carries no role mass — treat as a labeled absence.
        return Ok(None);
    }
    let raw_bytes = astrolabe_panel::slot_raw_bytes(&vector).map_err(|error| {
        format!(
            "re-encode S23 guard-raw sidecar failed: {}",
            error.message()
        )
    })?;
    Ok(Some(raw_bytes))
}

/// Reconstructs the directory-role bundles from persisted vault state: groups
/// non-structural symbols by source directory, reads each member's persisted S23
/// posterior, and computes each directory's frame (declared prior when the
/// directory declares a role, else the L1 aggregate of its members' posteriors).
///
/// Directories with neither a declared role nor a single decodable S23 member
/// are dropped (the kernel refuses an empty frame); the drop is counted, never
/// silently defaulted.
fn gather_directory_layout<C>(
    vault: &AsterVault<C>,
    project: &str,
    at_seq: u64,
) -> Result<GatheredLayout, DynError>
where
    C: Clock,
{
    let snapshot = astrolabe_ingest::read_cbm_graph_snapshot(vault, project)?;
    // directory_path -> Vec<LayoutMember>, deterministic order.
    let mut by_directory: BTreeMap<String, Vec<LayoutMember>> = BTreeMap::new();
    // Deterministic set of every directory seen, so a declared directory with no
    // decodable members still gets a (declared) frame.
    let mut directory_paths: BTreeSet<String> = BTreeSet::new();
    let mut s23_symbols_seen = 0usize;
    let mut missing_s23 = 0usize;

    for node in snapshot.nodes.iter().filter(|node| !node.structural) {
        let directory_path = directory_of(&node.file_path);
        directory_paths.insert(directory_path.clone());
        let Some(cx_id) = node.cx_id else {
            continue;
        };
        match read_member_s23_bytes(vault, at_seq, cx_id)? {
            Some(bytes) => {
                s23_symbols_seen += 1;
                by_directory
                    .entry(directory_path)
                    .or_default()
                    .push(LayoutMember {
                        symbol_cx: cx_id,
                        member: DirectoryMember::new(
                            node.qualified_name.clone(),
                            node.qualified_name.clone(),
                            bytes,
                        ),
                    });
            }
            None => missing_s23 += 1,
        }
    }

    let mut bundles = Vec::new();
    for directory_path in directory_paths {
        let members = by_directory.remove(&directory_path).unwrap_or_default();
        let declared_role = declared_role_for_path(&directory_path);
        let kernel_members: Vec<DirectoryMember> =
            members.iter().map(|member| member.member.clone()).collect();
        let frame = match compute_directory_role_frame(
            directory_path.clone(),
            directory_path.clone(),
            declared_role,
            &kernel_members,
        ) {
            Ok(frame) => frame,
            Err(error) if error.code() == ASTRO_LAYOUT_FRAME_EMPTY => continue,
            Err(error) => return Err(error.into()),
        };
        let directory_cx = directory_cx_bytes(project, &directory_path);
        bundles.push(DirectoryBundle {
            directory_path,
            directory_cx,
            declared_role,
            frame,
            members,
        });
    }

    Ok(GatheredLayout {
        bundles,
        s23_symbols_seen,
        missing_s23,
    })
}

/// Computes and persists directory-role frames (Kernel CF) and `placement_truth`
/// cross-terms (XTerm CF) for the live shadow vault, paired with one ledger
/// entry and verified by independent CF-row readback (FSV).
///
/// Returns a labeled `skipped` payload (never an error) when no frame can be
/// formed from persisted state — most commonly because the shadow pipeline has
/// not persisted S23 posteriors yet. Fails closed only on a genuine vault fault.
pub(crate) fn persist_layout_frames<C>(
    vault: &AsterVault<C>,
    project: &str,
    import_changed: bool,
) -> Result<Value, DynError>
where
    C: Clock,
{
    if !import_changed {
        return Ok(json!({
            "schema": LAYOUT_FRAME_SCHEMA,
            "status": "unchanged",
            "writes_skipped": true,
            "provenance": "content-addressed import reported no mutation; no layout frames recomputed",
        }));
    }

    let at_seq = vault.snapshot();
    let gathered = gather_directory_layout(vault, project, at_seq)?;
    if gathered.bundles.is_empty() {
        return Ok(json!({
            "schema": LAYOUT_FRAME_SCHEMA,
            "status": "skipped_no_frame",
            "writes_skipped": true,
            "s23_symbols_seen": gathered.s23_symbols_seen,
            "missing_s23": gathered.missing_s23,
            "provenance": "no declared directory role and no persisted S23 posterior to aggregate a directory-role frame from",
            "remediation": "persist S23 layer_role posteriors (panel v2 guard-raw slot_23.raw) during shadow import, or declare directory roles in astro.layout.declared_map.v1",
        }));
    }

    let mut rows: Vec<(ColumnFamily, Vec<u8>, Vec<u8>)> = Vec::new();
    let mut placement_rows_written = 0usize;
    let mut disagreeing_rows = 0usize;
    // Per-scope layout coherence (mean placement_truth agreement) drives the
    // enforcement ladder (#313). Computed here off the same placements the frame
    // lane already scores, so the persisted coherence is byte-consistent with the
    // layout_map aspect's `mean_coherence`.
    let mut coherence_sum = 0.0_f64;
    let mut coherence_count = 0usize;
    let mut enforcement_rows: Vec<(String, String, f32, usize, &'static str)> = Vec::new();
    let mut observe_only_scopes = 0usize;
    for bundle in &gathered.bundles {
        rows.push((
            ColumnFamily::Kernel,
            layout_frame_key(project, &bundle.directory_cx),
            directory_role_frame_artifact_bytes(&bundle.frame),
        ));
        let mut agreement_sum = 0.0_f64;
        for member in &bundle.members {
            let placement = compute_placement_truth(&member.member, &bundle.frame)?;
            if !placement.agrees {
                disagreeing_rows += 1;
            }
            agreement_sum += f64::from(placement.agreement);
            rows.push((
                ColumnFamily::XTerm,
                layout_placement_key(project, member.symbol_cx.as_bytes(), &bundle.directory_cx),
                placement_truth_row_bytes(&placement),
            ));
            placement_rows_written += 1;
        }
        // A directory with no scored members has no measured coherence — never
        // zero-filled; it simply persists no enforcement row (fail-closed absence).
        if !bundle.members.is_empty() {
            let coherence = (agreement_sum / bundle.members.len() as f64) as f32;
            coherence_sum += f64::from(coherence);
            coherence_count += 1;
            if classify_layout_coherence(coherence).is_observe_only() {
                observe_only_scopes += 1;
            }
            enforcement_rows.push((
                bundle.directory_path.clone(),
                "directory".to_string(),
                coherence,
                bundle.members.len(),
                bundle.frame.trust,
            ));
        }
    }

    // Whole-project scope: mean over directories that have a scored coherence,
    // matching `LayoutMapAspect::mean_coherence`. Only persisted when at least one
    // directory scored, so the readiness tier fails closed (unavailable) otherwise.
    let project_coherence =
        (coherence_count > 0).then(|| (coherence_sum / coherence_count as f64) as f32);
    if let Some(project_coherence) = project_coherence {
        if classify_layout_coherence(project_coherence).is_observe_only() {
            observe_only_scopes += 1;
        }
        rows.push((
            ColumnFamily::Kv,
            layout_enforcement_key(project, LAYOUT_ENFORCE_PROJECT_SCOPE),
            layout_enforcement_row_bytes(
                LAYOUT_ENFORCE_PROJECT_SCOPE,
                "project",
                project_coherence,
                placement_rows_written,
                coherence_count,
                "verified",
            ),
        ));
    }
    for (scope, scope_kind, coherence, member_count, trust) in &enforcement_rows {
        rows.push((
            ColumnFamily::Kv,
            layout_enforcement_key(project, scope),
            layout_enforcement_row_bytes(scope, scope_kind, *coherence, *member_count, 1, trust),
        ));
    }
    let enforcement_rows_written =
        enforcement_rows.len() + usize::from(project_coherence.is_some());

    let frame_rows_written = gathered.bundles.len();
    let row_count = rows.len();
    let ledger_rows_before = vault.scan_cf_at(at_seq, ColumnFamily::Ledger)?.len();
    let payload = layout_ledger_payload(
        project,
        at_seq,
        frame_rows_written,
        placement_rows_written,
        disagreeing_rows,
    )?;
    let commit_seq = vault.write_cf_batch_with_ledger_entry(
        rows.clone(),
        EntryKind::Migrate,
        SubjectId::Query(layout_subject(project, &payload)),
        payload,
        ActorId::Service(LAYOUT_FRAME_ACTOR.to_string()),
    )?;

    let mut readback_verified = 0usize;
    for (cf, key, expected) in &rows {
        let actual = vault.read_cf_at(commit_seq, *cf, key)?;
        if actual.as_deref() != Some(expected.as_slice()) {
            return Err(format!(
                "layout frame FSV readback mismatch for {:?} key {} at seq {commit_seq}",
                cf,
                hex_lower(key)
            )
            .into());
        }
        readback_verified += 1;
    }
    let ledger_rows_after = vault.scan_cf_at(commit_seq, ColumnFamily::Ledger)?.len();

    Ok(json!({
        "schema": LAYOUT_FRAME_SCHEMA,
        "status": "persisted",
        "trust": "verified",
        "freshness": "current",
        "provenance": "AsterVault Kernel(directory_role_frame)+XTerm(placement_truth) CF readback after shadow weave",
        "snapshot_seq_before": at_seq,
        "commit_seq": commit_seq,
        "ledger_rows_added": ledger_rows_after.saturating_sub(ledger_rows_before),
        "directory_frame_rows_written": frame_rows_written,
        "placement_truth_rows_written": placement_rows_written,
        "placement_disagreements": disagreeing_rows,
        "s23_symbols_seen": gathered.s23_symbols_seen,
        "missing_s23": gathered.missing_s23,
        "rows_written": row_count,
        "enforcement": {
            "schema": LAYOUT_ENFORCE_SCHEMA,
            "rows_written": enforcement_rows_written,
            "project_coherence": project_coherence,
            "observe_only_scopes": observe_only_scopes,
            "coherence_floor": LAYOUT_COHERENCE_FLOOR,
            "escalation_threshold": LAYOUT_ESCALATION_THRESHOLD,
            "provenance": LAYOUT_ENFORCE_PROVENANCE,
        },
        "fsv": {
            "kind": "vault_cf_readback",
            "readback_verified_rows": readback_verified,
            "families": ["Kernel", "XTerm", "Kv", "Ledger"],
        },
    }))
}

/// Reads the persisted per-scope layout-coherence enforcement decision row back
/// off the shadow vault (`ColumnFamily::Kv`), for the readiness surface (#313).
///
/// `Ok(None)` is a labeled absence (no enforcement row persisted for this scope —
/// the shadow import has not scored layout coherence for it, e.g. no S23 posteriors
/// or a directory with no members), never a fabricated verdict. Fails closed on a
/// genuine vault fault or a corrupt row.
pub(crate) fn read_layout_enforcement_row(
    cache_dir: &Path,
    project: &str,
    scope: &str,
) -> Result<Option<Value>, DynError> {
    let (vault_dir, vault_id, vault_salt) = shadow_vault_config_at(cache_dir, project)?;
    if !vault_dir.exists() {
        return Ok(None);
    }
    let vault = match open_shadow_vault_read_only(
        &vault_dir,
        &vault_id,
        &vault_salt,
        vec![ColumnFamily::Kv],
    ) {
        Ok(vault) => vault,
        Err(_) => return Ok(None),
    };
    let Some(bytes) = vault.read_cf_at(
        vault.snapshot(),
        ColumnFamily::Kv,
        &layout_enforcement_key(project, scope),
    )?
    else {
        return Ok(None);
    };
    let value: Value = serde_json::from_slice(&bytes).map_err(|error| {
        format!("persisted layout enforcement row for scope {scope} is corrupt: {error}")
    })?;
    Ok(Some(value))
}

/// The reserved whole-project enforcement scope name (for the readiness surface).
pub(crate) fn layout_enforcement_project_scope() -> &'static str {
    LAYOUT_ENFORCE_PROJECT_SCOPE
}

/// Seeds one persisted layout-coherence enforcement row into a fresh shadow vault,
/// for readiness-surface tests that need a measured `layout_coherence` tier without
/// running a full shadow import. Writes the same bytes the production persist path
/// writes, so the readback path exercises real persisted state.
#[cfg(test)]
pub(crate) fn seed_layout_enforcement_row_for_test(
    cache_dir: &Path,
    project: &str,
    scope: &str,
    coherence: f32,
    member_count: usize,
) -> Result<(), DynError> {
    let vault = AsterVault::new_durable(
        vault_dir(cache_dir, project),
        VaultId::from_str(SHADOW_VAULT_ID)?,
        vault_salt(project).as_bytes().to_vec(),
        VaultOptions::default(),
    )?;
    vault.write_cf_batch([(
        ColumnFamily::Kv,
        layout_enforcement_key(project, scope),
        layout_enforcement_row_bytes(scope, "directory", coherence, member_count, 1, "verified"),
    )])?;
    Ok(())
}

fn layout_ledger_payload(
    project: &str,
    at_seq: u64,
    frame_rows: usize,
    placement_rows: usize,
    disagreeing_rows: usize,
) -> Result<Vec<u8>, DynError> {
    Ok(serde_json::to_vec(&json!({
        "schema": LAYOUT_FRAME_SCHEMA,
        "project": project,
        "snapshot_seq_before": at_seq,
        "panel_version": SHADOW_PANEL_VERSION,
        "directory_frame_rows": frame_rows,
        "placement_truth_rows": placement_rows,
        "placement_disagreements": disagreeing_rows,
    }))?)
}

fn layout_subject(project: &str, payload: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(LAYOUT_FRAME_SCHEMA.as_bytes());
    hasher.update([0]);
    hasher.update(project.as_bytes());
    hasher.update([0]);
    hasher.update(payload);
    hasher.finalize().to_vec()
}

/// Reads the `layout_map` aspect from the persisted shadow vault for
/// `get_architecture`.
///
/// Returns a labeled `unavailable` payload (freshness `not_evaluated`, trust
/// `provisional`) when the shadow vault is absent, a persisted row is corrupt,
/// or no S23 posterior / declared role exists to build a single frame — never a
/// silent or fabricated map. The `first_touch` preamble is the fail-closed
/// orientation the kernel serves before any retrieval.
pub(crate) fn read_layout_map_aspect(cache_dir: &Path, project: &str) -> Result<Value, DynError> {
    let (vault_dir, vault_id, vault_salt) = shadow_vault_config_at(cache_dir, project)?;
    if !vault_dir.exists() {
        return Ok(layout_map_unavailable_json(
            "shadow vault absent; rerun index_repository with calyx=\"shadow\" before requesting the layout_map aspect",
        ));
    }
    let vault = match open_shadow_vault_read_only(
        &vault_dir,
        &vault_id,
        &vault_salt,
        // read_cbm_graph_snapshot reads Graph (node map) + Base, and its legacy
        // guards scan Kv + Recurrence; the frame aggregates the S23 posterior.
        vec![
            ColumnFamily::Graph,
            ColumnFamily::Base,
            ColumnFamily::Kv,
            ColumnFamily::Recurrence,
            ColumnFamily::slot_raw(SlotId::new(LAYER_ROLE_SLOT)),
            ColumnFamily::slot(SlotId::new(LAYER_ROLE_SLOT)),
        ],
    ) {
        Ok(vault) => vault,
        Err(error) => {
            return Ok(layout_map_unavailable_json(&format!(
                "shadow vault open failed: {error}"
            )));
        }
    };

    let gathered = match gather_directory_layout(&vault, project, vault.snapshot()) {
        Ok(gathered) => gathered,
        Err(error) => {
            return Ok(layout_map_unavailable_json(&format!(
                "layout frame recompute failed: {error}"
            )));
        }
    };
    if gathered.bundles.is_empty() {
        return Ok(layout_map_unavailable_json(
            "no persisted S23 layer_role posterior and no declared directory role; the layout_map aspect requires panel v2 S23 posteriors persisted during shadow import or an astro.layout.declared_map.v1 declaration",
        ));
    }

    // Boundary diffs: declared directories whose members behave otherwise.
    let mut boundary_findings: Vec<DeclaredLearnedDisagreement> = Vec::new();
    for bundle in &gathered.bundles {
        if let Some(declared) = bundle.declared_role {
            let kernel_members: Vec<DirectoryMember> = bundle
                .members
                .iter()
                .map(|member| member.member.clone())
                .collect();
            if kernel_members.is_empty() {
                continue;
            }
            match layout_boundary_diff(
                bundle.directory_path.clone(),
                bundle.directory_path.clone(),
                declared,
                &kernel_members,
            ) {
                Ok(Some(finding)) => boundary_findings.push(finding),
                Ok(None) => {}
                Err(error) => {
                    return Ok(layout_map_unavailable_json(&format!(
                        "boundary diff failed: {}: {}",
                        error.code(),
                        error.message()
                    )));
                }
            }
        }
    }
    boundary_findings.sort_by(|left, right| left.directory_path.cmp(&right.directory_path));

    let inputs: Vec<DirectoryLayoutInput> = gathered
        .bundles
        .iter()
        .map(|bundle| DirectoryLayoutInput {
            frame: bundle.frame.clone(),
            members: bundle
                .members
                .iter()
                .map(|member| member.member.clone())
                .collect(),
        })
        .collect();
    let aspect = match build_layout_map_aspect(&inputs) {
        Ok(aspect) => aspect,
        Err(error) => {
            return Ok(layout_map_unavailable_json(&format!(
                "layout_map aspect build failed: {}: {}",
                error.code(),
                error.message()
            )));
        }
    };

    // First-touch preamble: declared entries serve orientation directly; else the
    // learned map; else the kernel fail-closed refusal.
    let declared_entries: Vec<DirectoryLayoutEntry> = aspect
        .directories
        .iter()
        .filter(|entry| entry.source == FrameProvenance::Declared)
        .cloned()
        .collect();
    let declared_opt = (!declared_entries.is_empty()).then(|| declared_entries.clone());
    let learned_opt = (aspect.status == "built").then(|| aspect.clone());
    let first_touch = first_touch_json(first_touch_layout(declared_opt, learned_opt));

    Ok(json!({
        "schema": LAYOUT_MAP_ASPECT_SCHEMA,
        "status": aspect.status,
        "trust": aspect.trust,
        "freshness": aspect.freshness,
        "provenance": aspect.provenance,
        "directory_count": aspect.directory_count,
        "directories": aspect
            .directories
            .iter()
            .map(directory_entry_json)
            .collect::<Vec<_>>(),
        "mean_coherence": aspect.mean_coherence,
        "disagreement_count": aspect.disagreement_count,
        "declared_learned_disagreements": boundary_findings
            .iter()
            .map(boundary_finding_json)
            .collect::<Vec<_>>(),
        "first_touch": first_touch,
        "source_state": {
            "source": DIRECTORY_ROLE_FRAME_PROVENANCE,
            "placement_truth_source": PLACEMENT_TRUTH_PROVENANCE,
            "vault_dir": vault_dir,
            "s23_symbols_seen": gathered.s23_symbols_seen,
            "missing_s23": gathered.missing_s23,
        },
    }))
}

/// Labeled fail-closed payload for a `layout_map` aspect that could not be
/// recomputed from persisted state.
pub(crate) fn layout_map_unavailable_json(reason: &str) -> Value {
    json!({
        "schema": LAYOUT_MAP_ASPECT_SCHEMA,
        "status": "unavailable",
        "freshness": "not_evaluated",
        "trust": "provisional",
        "provenance": DIRECTORY_ROLE_FRAME_PROVENANCE,
        "reason": reason,
        "remediation": "rerun index_repository with calyx=\"shadow\" and persisted S23 layer_role posteriors before requesting the layout_map aspect",
    })
}

fn directory_entry_json(entry: &DirectoryLayoutEntry) -> Value {
    json!({
        "directory_id": entry.directory_id,
        "directory_path": entry.directory_path,
        "role": entry.role.as_str(),
        "role_vector": entry.role_vector.to_vec(),
        "source": entry.source.as_str(),
        "coherence": entry.coherence,
        "member_count": entry.member_count,
        "trust": entry.trust,
        "top_disagreements": entry
            .top_disagreements
            .iter()
            .map(|drift| {
                json!({
                    "symbol_id": drift.symbol_id,
                    "qualified_name": drift.qualified_name,
                    "symbol_role": drift.symbol_role.as_str(),
                    "directory_role": drift.directory_role.as_str(),
                    "agreement": drift.agreement,
                    "code": drift.code,
                    "message": drift.message,
                    "remediation": drift.remediation,
                })
            })
            .collect::<Vec<_>>(),
    })
}

fn boundary_finding_json(finding: &DeclaredLearnedDisagreement) -> Value {
    json!({
        "directory_path": finding.directory_path,
        "directory_id": finding.directory_id,
        "declared_role": finding.declared_role.as_str(),
        "learned_role": finding.learned_role.as_str(),
        "off_declared_fraction": finding.off_declared_fraction,
        "member_count": finding.member_count,
        "code": finding.code,
        "message": finding.message,
        "remediation": finding.remediation,
    })
}

fn first_touch_json(result: astrolabe_domain::Result<FirstTouchLayout>) -> Value {
    match result {
        Ok(FirstTouchLayout::Declared(entries)) => json!({
            "status": "declared",
            "orientation": "declared_map",
            "trust": "verified",
            "provenance": "astro.layout.declared_map.v1",
            "directories": entries.iter().map(directory_entry_json).collect::<Vec<_>>(),
        }),
        Ok(FirstTouchLayout::Learned(aspect)) => json!({
            "status": "learned",
            "orientation": "learned_layout_map",
            "trust": aspect.trust,
            "provenance": aspect.provenance,
            "directory_count": aspect.directory_count,
        }),
        Err(error) => json!({
            "status": "unavailable",
            "code": error.code(),
            "message": error.message(),
            "remediation": error.remediation(),
        }),
    }
}

// A stable reference to the fail-closed code, so a first-touch refusal is always
// the kernel's declared code (documentation of intent, kept live).
#[allow(dead_code)]
const FIRST_TOUCH_UNAVAILABLE_CODE: &str = ASTRO_LAYOUT_FIRST_TOUCH_UNAVAILABLE;

#[cfg(test)]
mod tests {
    use super::*;
    use astrolabe_kernel::parse_directory_role_frame_artifact;
    use astrolabe_panel::{CANONICAL_ROLES, LAYER_ROLE_COUNT, slot_raw_bytes};
    use calyx_aster::cf::prefix_range;
    use calyx_core::SlotVector;

    fn temp_root(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "astrolabe-layout-lane-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create layout lane test dir");
        dir
    }

    fn one_hot(role: LayerRole) -> Vec<u8> {
        let mut mass = vec![0.0_f32; LAYER_ROLE_COUNT];
        mass[role.index()] = 1.0;
        slot_raw_bytes(&SlotVector::Dense {
            dim: LAYER_ROLE_COUNT as u32,
            data: mass,
        })
        .expect("encode guard-raw S23 posterior")
    }

    // A directory with no declared role: the persisted frame row must parse back
    // via the kernel parser (frame_hash verified) and equal the L1 aggregate of
    // the members' one-hots. Independent Kernel-CF-row readback.
    #[test]
    fn persisted_frame_row_parses_back_with_frame_hash() {
        let root = temp_root("frame-readback");
        let vault = AsterVault::new_durable(
            vault_dir(&root, "demo"),
            VaultId::from_str(SHADOW_VAULT_ID).unwrap(),
            vault_salt("demo").as_bytes().to_vec(),
            VaultOptions::default(),
        )
        .unwrap();

        // Two members in "src/mixed": one transport, one persistence one-hot.
        // Kernel CF frame key is derived from sha256(project\0directory).
        let dir_path = "src/mixed";
        let dir_cx = directory_cx_bytes("demo", dir_path);
        let members = [
            DirectoryMember::new("a", "mixed::serve", one_hot(LayerRole::TransportApi)),
            DirectoryMember::new("b", "mixed::store", one_hot(LayerRole::Persistence)),
        ];
        let frame = compute_directory_role_frame(dir_path, dir_path, None, &members).unwrap();
        assert_eq!(frame.source, FrameProvenance::LearnedAggregate);

        vault
            .write_cf_batch([(
                ColumnFamily::Kernel,
                layout_frame_key("demo", &dir_cx),
                directory_role_frame_artifact_bytes(&frame),
            )])
            .unwrap();

        // Independent CF-row readback: scan the Kernel CF by the layout prefix.
        let rows = vault
            .scan_cf_range_at(
                vault.snapshot(),
                ColumnFamily::Kernel,
                &prefix_range(&layout_frame_scan_prefix("demo")),
            )
            .unwrap();
        assert_eq!(rows.len(), 1, "exactly one persisted frame row");
        let parsed = parse_directory_role_frame_artifact(&rows[0].1).expect("frame parses back");
        assert_eq!(parsed.frame_hash, frame.frame_hash);
        assert_eq!(parsed.role_vector, frame.role_vector);
        // Aggregate of transport + persistence one-hots.
        let mut expected = [0.0_f32; LAYER_ROLE_COUNT];
        expected[LayerRole::TransportApi.index()] = 0.5;
        expected[LayerRole::Persistence.index()] = 0.5;
        assert_eq!(parsed.role_vector, expected);

        drop(vault);
        let _ = fs::remove_dir_all(&root);
    }

    // A misplaced (persistence-behaving) symbol under a declared TransportApi
    // directory: the persisted placement_truth XTerm row bytes must be exact.
    #[test]
    fn persisted_placement_truth_row_bytes_exact() {
        let root = temp_root("placement-bytes");
        let vault = AsterVault::new_durable(
            vault_dir(&root, "demo"),
            VaultId::from_str(SHADOW_VAULT_ID).unwrap(),
            vault_salt("demo").as_bytes().to_vec(),
            VaultOptions::default(),
        )
        .unwrap();

        let dir_path = "api";
        let dir_cx = directory_cx_bytes("demo", dir_path);
        let frame =
            compute_directory_role_frame(dir_path, dir_path, Some(LayerRole::TransportApi), &[])
                .unwrap();
        let member = DirectoryMember::new("mp", "api::save_user", one_hot(LayerRole::Persistence));
        let placement = compute_placement_truth(&member, &frame).unwrap();
        assert!(!placement.agrees);
        let expected_bytes = placement_truth_row_bytes(&placement);
        let symbol_cx = CxId::from_input(b"api::save_user", 1, b"symbol");

        vault
            .write_cf_batch([(
                ColumnFamily::XTerm,
                layout_placement_key("demo", symbol_cx.as_bytes(), &dir_cx),
                expected_bytes.clone(),
            )])
            .unwrap();

        let rows = vault
            .scan_cf_range_at(
                vault.snapshot(),
                ColumnFamily::XTerm,
                &prefix_range(&layout_placement_scan_prefix("demo")),
            )
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1, expected_bytes, "placement_truth row bytes exact");
        let text = String::from_utf8(rows[0].1.clone()).unwrap();
        assert!(text.contains("symbol_role=persistence"));
        assert!(text.contains("directory_role=transport_api"));
        assert!(text.contains("agrees=false"));
        assert!(text.contains(&format!("agreement={:08x}", 0.0_f32.to_bits())));

        drop(vault);
        let _ = fs::remove_dir_all(&root);
    }

    // Fail-closed: an absent shadow vault yields a labeled unavailable aspect,
    // never an empty or fabricated map.
    #[test]
    fn absent_vault_yields_labeled_unavailable() {
        let root = temp_root("absent");
        let aspect = read_layout_map_aspect(&root, "no-such-project").unwrap();
        assert_eq!(aspect["status"], "unavailable");
        assert_eq!(aspect["trust"], "provisional");
        assert_eq!(aspect["freshness"], "not_evaluated");
        assert!(
            aspect["reason"]
                .as_str()
                .unwrap()
                .contains("shadow vault absent")
        );
        let _ = fs::remove_dir_all(&root);
    }

    // directory_of normalizes separators and maps root-level files to ".".
    #[test]
    fn directory_of_normalizes() {
        assert_eq!(directory_of("src/api/handler.rs"), "src/api");
        assert_eq!(directory_of("src\\api\\handler.rs"), "src/api");
        assert_eq!(directory_of("main.rs"), ".");
        assert_eq!(directory_of("a/b/c/x.rs"), "a/b/c");
    }

    // Canonical-role coordinate order is frozen (used implicitly by the frame
    // vector layout the persisted bytes encode).
    #[test]
    fn canonical_roles_are_frozen_length() {
        assert_eq!(CANONICAL_ROLES.len(), LAYER_ROLE_COUNT);
    }

    // #336 / #311 FSV-2 (real corpus): a full shadow import at panel v2
    // (SHADOW_PANEL_VERSION) over a real subset of the repo's own `cbm/` tree
    // persists S23 `layer_role` posteriors into the slot(23) CF, the layout-frame
    // lane forms real directory frames (never `skipped_no_frame`), and each
    // directory frame equals the L1 aggregate independently recomputed from the
    // members' persisted S23 CF bytes read straight back off the vault.
    //
    // This is the end-to-end regression for #336: before the v2 bump the shadow
    // import ran panel v1 (S0–S22), never wrote slot(23), and this frame lane
    // returned `skipped_no_frame` on every real repo.
    #[test]
    fn real_cbm_corpus_shadow_import_persists_s23_and_aggregates_frames() {
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        // Smallest real subset spanning two real directories of the owned cbm/
        // corpus. `route` mirrors the parser-emitted route surface for a symbol on
        // the transport layer; the rest carry no role evidence (→ LayerRole::Other),
        // exactly as the production encoder resolves an unflagged C function.
        let files: [(&str, &str, Option<&str>); 3] = [
            ("cbm/internal/cbm/arena.c", "arena_alloc", None),
            ("cbm/internal/cbm/ac.c", "ac_scan", Some("/scan")),
            ("cbm/src/main.c", "cbm_main", None),
        ];
        // Real-data-never-a-blocker: the repo's own cbm/ tree is the established
        // corpus. If it moved, fail loudly rather than silently degrade.
        for (rel, _, _) in &files {
            assert!(
                repo_root.join(rel).is_file(),
                "real cbm corpus file missing: {rel}"
            );
        }

        let project = "cbmreal";
        let mut nodes = vec![astrolabe_bridge::CbmPipelineNodeRow {
            id: 1,
            project: project.to_string(),
            label: "Project".to_string(),
            name: project.to_string(),
            qualified_name: project.to_string(),
            file_path: String::new(),
            start_line: 0,
            end_line: 0,
            properties_json: "{}".to_string(),
        }];
        for (index, (rel, fname, route)) in files.iter().enumerate() {
            let bytes = fs::read(repo_root.join(rel)).expect("read real cbm source file");
            let line_count = bytes.iter().filter(|byte| **byte == b'\n').count() as i64;
            let properties_json = match route {
                Some(path) => format!(r#"{{"route_path":"{path}","route_method":"GET"}}"#),
                None => "{}".to_string(),
            };
            nodes.push(astrolabe_bridge::CbmPipelineNodeRow {
                id: (index as i64) + 2,
                project: project.to_string(),
                label: "Function".to_string(),
                name: (*fname).to_string(),
                qualified_name: format!("{project}::{fname}"),
                file_path: (*rel).to_string(),
                start_line: 1,
                end_line: line_count.max(1),
                properties_json,
            });
        }
        let rows = astrolabe_bridge::CbmPipelineRows {
            project: project.to_string(),
            nodes,
            edges: Vec::new(),
        };

        let root = temp_root("real-cbm-s23");
        let vault = AsterVault::new_durable(
            vault_dir(&root, project),
            VaultId::from_str(SHADOW_VAULT_ID).unwrap(),
            vault_salt(project).as_bytes().to_vec(),
            VaultOptions::default(),
        )
        .unwrap();

        // The real production shadow-import entrypoint at the real roster version.
        let options = SqliteImportOptions::new(project, "real-commit", SHADOW_PANEL_VERSION)
            .with_available_slots(shadow_available_slots());
        let imported = import_shadow_vault_report(
            &root.join("unused.db"),
            &vault,
            &ShadowSlotRuntime,
            &options,
            Some(row_sink_import_candidate_from_rows(rows)),
        )
        .expect("real cbm shadow import");
        assert_eq!(imported.report.constellation_inputs, 3);

        // --- Independent readback #1: slot(23) rows are non-empty for the real
        // symbols (the #336 core claim). Before the v2 bump this CF was empty.
        let snapshot = astrolabe_ingest::read_cbm_graph_snapshot(&vault, project).unwrap();
        let at_seq = vault.snapshot();
        let mut s23_rows = 0usize;
        let mut by_dir: BTreeMap<String, Vec<CxId>> = BTreeMap::new();
        for node in snapshot.nodes.iter().filter(|node| !node.structural) {
            let cx_id = node.cx_id.expect("real function symbol has a cx_id");
            let raw = vault
                .read_cf_at(
                    at_seq,
                    ColumnFamily::slot(SlotId::new(LAYER_ROLE_SLOT)),
                    &slot_key(cx_id),
                )
                .unwrap();
            assert!(
                raw.is_some(),
                "slot(23) row must be persisted for {}",
                node.qualified_name
            );
            s23_rows += 1;
            by_dir
                .entry(directory_of(&node.file_path))
                .or_default()
                .push(cx_id);
        }
        assert_eq!(s23_rows, 3, "S23 persisted for all three real symbols");
        assert!(
            by_dir.contains_key("cbm/internal/cbm") && by_dir.contains_key("cbm/src"),
            "two real directories present: {:?}",
            by_dir.keys().collect::<Vec<_>>()
        );

        // --- The frame lane forms real frames — never skipped_no_frame (#336).
        let persisted = persist_layout_frames(&vault, project, true).unwrap();
        assert_eq!(
            persisted["status"], "persisted",
            "frames formed: {persisted}"
        );
        assert_eq!(persisted["s23_symbols_seen"], 3);
        assert_eq!(persisted["missing_s23"], 0);
        assert_eq!(persisted["directory_frame_rows_written"], 2);

        // --- #313: the enforcement ladder scored every directory + the project.
        // cbm/internal/cbm = {transport, other} -> coherence 0.5 (escalation);
        // cbm/src = {other} -> coherence 1.0 (escalation); project mean 0.75.
        assert_eq!(persisted["enforcement"]["rows_written"], 3);
        assert_eq!(persisted["enforcement"]["observe_only_scopes"], 0);
        let project_coh = persisted["enforcement"]["project_coherence"]
            .as_f64()
            .expect("project coherence");
        assert!((project_coh - 0.75).abs() < 1e-6, "project coherence 0.75");
        // Independent readback of the persisted per-scope enforcement rows.
        let enforce_commit = vault.snapshot();
        for (scope, want_coherence) in [
            (LAYOUT_ENFORCE_PROJECT_SCOPE, 0.75_f64),
            ("cbm/internal/cbm", 0.5),
            ("cbm/src", 1.0),
        ] {
            let bytes = vault
                .read_cf_at(
                    enforce_commit,
                    ColumnFamily::Kv,
                    &layout_enforcement_key(project, scope),
                )
                .unwrap()
                .unwrap_or_else(|| panic!("enforcement row for {scope}"));
            let row: Value = serde_json::from_slice(&bytes).unwrap();
            assert!((row["coherence"].as_f64().unwrap() - want_coherence).abs() < 1e-6);
            assert_eq!(
                row["enforcement_mode"], "escalation_licensed",
                "coherence {want_coherence} licenses escalation"
            );
            assert_eq!(row["enforcement_skipped"], false);
        }

        // --- Independent readback #2 (FSV-2): recompute each directory's L1
        // aggregate straight from the members' persisted S23 CF bytes and compare
        // to the persisted Kernel-CF frame row (frame_hash-verified parse).
        let commit_seq = vault.snapshot();
        for (dir_path, members) in &by_dir {
            let frame_bytes = vault
                .read_cf_at(
                    commit_seq,
                    ColumnFamily::Kernel,
                    &layout_frame_key(project, &directory_cx_bytes(project, dir_path)),
                )
                .unwrap()
                .expect("persisted directory-role frame row");
            let parsed = parse_directory_role_frame_artifact(&frame_bytes)
                .expect("frame row parses back (frame_hash verified)");

            // Independent aggregate: mean of the members' decoded posteriors.
            let mut accum = [0.0_f32; LAYER_ROLE_COUNT];
            for cx_id in members {
                let bytes = read_member_s23_bytes(&vault, commit_seq, *cx_id)
                    .unwrap()
                    .expect("member S23 bytes present");
                let vector = astrolabe_panel::decode_slot_raw(&bytes).unwrap();
                let SlotVector::Dense { dim, data } = vector else {
                    panic!("S23 posterior must decode to Dense(8)");
                };
                assert_eq!(dim, LAYER_ROLE_COUNT as u32);
                for (slot, value) in accum.iter_mut().zip(data.iter()) {
                    *slot += *value;
                }
            }
            let count = members.len() as f32;
            for slot in accum.iter_mut() {
                *slot /= count;
            }
            assert_eq!(
                parsed.role_vector, accum,
                "persisted frame for {dir_path} == independent L1 aggregate of persisted S23 bytes"
            );
        }

        // The transport-flagged real symbol pulls its directory frame off pure
        // Other: the mixed directory must carry transport_api mass, proving the
        // real S23 encoder output (not a fabricated prior) drove the frame.
        let mixed = vault
            .read_cf_at(
                commit_seq,
                ColumnFamily::Kernel,
                &layout_frame_key(project, &directory_cx_bytes(project, "cbm/internal/cbm")),
            )
            .unwrap()
            .expect("mixed directory frame");
        let mixed_frame = parse_directory_role_frame_artifact(&mixed).unwrap();
        assert!(
            mixed_frame.role_vector[LayerRole::TransportApi.index()] > 0.0,
            "transport-flagged real symbol contributes transport_api mass: {:?}",
            mixed_frame.role_vector
        );

        drop(vault);
        let _ = fs::remove_dir_all(&root);
    }

    // #313: the enforcement ladder thresholds are the frozen registry knob, and the
    // observe-only floor is the chance line (1/LAYER_ROLE_COUNT).
    #[test]
    fn enforcement_ladder_boundaries_are_the_registry_knob() {
        assert_eq!(LAYOUT_COHERENCE_FLOOR, 1.0 / LAYER_ROLE_COUNT as f32);
        assert_eq!(LAYOUT_ESCALATION_THRESHOLD, 0.5);
        // At or below the chance floor: observe-only.
        assert!(classify_layout_coherence(LAYOUT_COHERENCE_FLOOR).is_observe_only());
        assert!(classify_layout_coherence(0.05).is_observe_only());
        // Between floor and threshold: monitored, not escalatable.
        assert_eq!(classify_layout_coherence(0.3).as_str(), "monitor");
        // At or above the majority boundary: escalation licensed.
        assert_eq!(
            classify_layout_coherence(LAYOUT_ESCALATION_THRESHOLD).as_str(),
            "escalation_licensed"
        );
    }

    // #313 FSV 5(a): a below-floor coherence persists an observe-only skip row, and
    // the readiness tier reads that persisted row back and refuses (observe-only,
    // not ready) — enforcement is never silently escalated below the floor.
    #[test]
    fn below_floor_coherence_persists_observe_only_skip_row_and_tier_refuses() {
        let root = temp_root("enforce-observe");
        // 0.1 < 1/8: the chance-floor case. Written with the production row bytes,
        // so classify_layout_coherence stamps observe_only + enforcement_skipped.
        seed_layout_enforcement_row_for_test(&root, "demo", LAYOUT_ENFORCE_PROJECT_SCOPE, 0.1, 8)
            .unwrap();

        // FSV: the persisted skip row read straight back off the Kv CF.
        let row = read_layout_enforcement_row(&root, "demo", LAYOUT_ENFORCE_PROJECT_SCOPE)
            .unwrap()
            .expect("persisted enforcement row");
        assert_eq!(row["enforcement_mode"], "observe_only");
        assert_eq!(row["enforcement_skipped"], true);
        assert!(
            row["coherence"].as_f64().unwrap() <= row["coherence_floor"].as_f64().unwrap(),
            "coherence at or below the floor"
        );

        // The readiness tier reads the persisted verdict and drives observe-only.
        let tier = readiness_layout_coherence_tier(&root, "demo", "demo").unwrap();
        assert_eq!(tier["tier"], "layout_coherence");
        assert_eq!(tier["measured"], true);
        assert_eq!(tier["pass"], false);
        assert_eq!(tier["observe_only"], true);
        assert_eq!(tier["enforcement_mode"], "observe_only");
        assert!(
            tier["cheapest_fix"]
                .as_str()
                .unwrap()
                .contains("observe-only")
        );
        let _ = fs::remove_dir_all(&root);
    }

    // #313: a coherence at or above the escalation threshold licenses escalation and
    // the tier passes, read back off the persisted row.
    #[test]
    fn above_threshold_coherence_licenses_escalation_tier() {
        let root = temp_root("enforce-escalate");
        seed_layout_enforcement_row_for_test(&root, "demo", LAYOUT_ENFORCE_PROJECT_SCOPE, 0.9, 5)
            .unwrap();
        let tier = readiness_layout_coherence_tier(&root, "demo", "demo").unwrap();
        assert_eq!(tier["measured"], true);
        assert_eq!(tier["pass"], true);
        assert_eq!(tier["enforcement_mode"], "escalation_licensed");
        assert_eq!(tier["observe_only"], false);
        assert_eq!(tier["cheapest_fix"], Value::Null);
        let _ = fs::remove_dir_all(&root);
    }

    // #313 fail-closed: no shadow vault at all -> unavailable tier, never a
    // fabricated pass.
    #[test]
    fn absent_layout_enforcement_yields_unavailable_tier() {
        let root = temp_root("enforce-absent");
        let tier =
            readiness_layout_coherence_tier(&root, "no-such-project", "no-such-project").unwrap();
        assert_eq!(tier["tier"], "layout_coherence");
        assert_eq!(tier["measured"], false);
        assert_eq!(tier["pass"], false);
        assert!(tier["cheapest_fix"].as_str().unwrap().contains("index"));
        let _ = fs::remove_dir_all(&root);
    }

    // #313 fail-closed: a shadow vault that persisted no layout coherence (no S23
    // posteriors / degenerate project) -> unavailable tier.
    #[test]
    fn vault_without_enforcement_row_yields_unavailable_tier() {
        let root = temp_root("enforce-no-row");
        let vault = AsterVault::new_durable(
            vault_dir(&root, "demo"),
            VaultId::from_str(SHADOW_VAULT_ID).unwrap(),
            vault_salt("demo").as_bytes().to_vec(),
            VaultOptions::default(),
        )
        .unwrap();
        drop(vault);
        let tier = readiness_layout_coherence_tier(&root, "demo", "demo").unwrap();
        assert_eq!(tier["tier"], "layout_coherence");
        assert_eq!(tier["measured"], false);
        assert_eq!(tier["pass"], false);
        let _ = fs::remove_dir_all(&root);
    }
}
