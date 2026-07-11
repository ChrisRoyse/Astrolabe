use super::*;
pub(crate) const SHADOW_VAULT_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
// Shadow-import content-freshness refusal codes (#93). Freshness is derived by
// recomputing the live CBM SQLite fingerprint and comparing it to the watermark
// persisted at import time — never from artifact/row/file existence. Each code below
// marks a verify-relevant input that is missing, so freshness cannot be asserted and
// the surface fails closed rather than reporting current/fresh/verified.
pub(crate) const ASTRO_SHADOW_SOURCE_MISSING: &str = "ASTRO_SHADOW_SOURCE_MISSING";
pub(crate) const ASTRO_SHADOW_FINGERPRINT_MISSING: &str = "ASTRO_SHADOW_FINGERPRINT_MISSING";
pub(crate) const ASTRO_SHADOW_LOWERED_MISSING: &str = "ASTRO_SHADOW_LOWERED_MISSING";
pub(crate) const ASTRO_SHADOW_VERIFY_NOT_INTACT: &str = "ASTRO_SHADOW_VERIFY_NOT_INTACT";
pub(crate) const SHADOW_SOURCE_MISSING_REMEDIATION: &str = "run index_repository with calyx=\"shadow\" to build the CBM SQLite source and shadow vault before reading shadow freshness";
pub(crate) const SHADOW_FINGERPRINT_MISSING_REMEDIATION: &str = "no shadow import watermark is recorded; run index_repository with calyx=\"shadow\" so the vault_fingerprint content watermark is persisted";
pub(crate) const SHADOW_LOWERED_MISSING_REMEDIATION: &str = "the lowered artifact is absent; rerun index_repository with calyx=\"shadow\" (or retry index_status to trigger a background refresh) to rebuild it";
pub(crate) const SHADOW_VERIFY_NOT_INTACT_REMEDIATION: &str = "the vault ledger chain does not verify intact; quarantine the vault and rerun index_repository with calyx=\"shadow\" to rebuild from current source";
pub(crate) const SHADOW_STALE_REMEDIATION: &str = "the CBM SQLite changed since the last shadow import; rerun index_repository with calyx=\"shadow\" (or retry index_status to trigger a background refresh) so the vault and lowered artifact are rebuilt from current source";

#[derive(Debug, Clone)]
pub(crate) struct ShadowImportOutcome {
    pub(crate) vault_dir: PathBuf,
    pub(crate) vault_id: String,
    pub(crate) vault_salt: String,
    pub(crate) sqlite_path: PathBuf,
    pub(crate) sqlite_fingerprint_sha256: String,
    /// Content-freshness watermark (#221): the SHA-256 of the CBM SQLite *source file*
    /// bytes (`fingerprint_sqlite_hex`), captured at import time and independent of how
    /// the graph was imported. `evaluate_shadow_content_freshness` recomputes exactly this
    /// digest over the live source and compares byte-for-byte. It MUST be the source-file
    /// fingerprint — never the row-sink content fingerprint (`row_sink_fingerprint`, a
    /// digest over the in-memory rows) that the direct import path records in
    /// `sqlite_fingerprint_sha256`. Those two digests are computed over different inputs
    /// with different domain separators and can never be equal, so persisting the row-sink
    /// value as the watermark made freshness permanently Stale after every row-sink import,
    /// which triggered a runner-less refresh that clobbered the provenance surface as
    /// "unavailable" and broke get_provenance end-to-end.
    pub(crate) content_freshness_watermark_sha256: String,
    pub(crate) lowered_sqlite_path: PathBuf,
    pub(crate) lowered_artifact_sha256: String,
    pub(crate) lowered_vault_fingerprint_sha256: String,
    pub(crate) lowered_manifest_seq: u64,
    pub(crate) lowered_nodes: usize,
    pub(crate) lowered_edges: usize,
    pub(crate) lowered_skipped_edges: usize,
    pub(crate) sqlite_nodes: usize,
    pub(crate) sqlite_edges: usize,
    pub(crate) constellation_inputs: usize,
    pub(crate) structural_only: usize,
    pub(crate) new_cx_ids: usize,
    pub(crate) reused_cx_ids: usize,
    pub(crate) graph_rows_written: usize,
    pub(crate) edge_rows_written: usize,
    pub(crate) cx_id_set_sha256: String,
    pub(crate) ledger_seq: u64,
    pub(crate) ledger_rows_after: u64,
    pub(crate) verify_chain_status: String,
    pub(crate) vault_import_source: String,
    pub(crate) vault_import_fallback_reason: Option<String>,
    pub(crate) security_screen: Value,
    pub(crate) search_scale: Value,
    pub(crate) skill_tree: Value,
    pub(crate) bridges: Value,
    pub(crate) kernel_context: Value,
    pub(crate) anomalies: Value,
    pub(crate) provenance: Value,
}

#[derive(Debug, Clone)]
pub(crate) struct RowSinkSnapshot {
    pub(crate) snapshot: CbmGraphSnapshot,
    pub(crate) source_fingerprint_sha256: [u8; 32],
    pub(crate) security_screen: Value,
    pub(crate) skill_tree: Value,
    pub(crate) bridges: Value,
    pub(crate) kernel_context: Value,
    pub(crate) anomalies: Value,
    pub(crate) provenance: Value,
}

#[derive(Debug, Clone)]
pub(crate) enum RowSinkImportCandidate {
    Available(Box<RowSinkSnapshot>),
    Unavailable(String),
}

#[derive(Debug)]
pub(crate) struct ShadowVaultImport {
    pub(crate) report: astrolabe_ingest::SqliteImportReport,
    pub(crate) source: String,
    pub(crate) fallback_reason: Option<String>,
    pub(crate) security_screen: Value,
    pub(crate) skill_tree: Value,
    pub(crate) bridges: Value,
    pub(crate) kernel_context: Value,
    pub(crate) anomalies: Value,
    pub(crate) provenance: Value,
}

#[derive(Debug)]
pub(crate) struct ShadowSlotRuntime;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum ShadowRefreshStatus {
    Current,
    Refreshed,
    Busy,
}

impl SlotRuntime for ShadowSlotRuntime {
    fn measure_slot(&self, _slot: &PanelSlotSpec, _input: &PanelInput) -> PanelResult<SlotVector> {
        Ok(SlotVector::Absent {
            reason: AbsentReason::LensUnavailable,
        })
    }
}

pub(crate) fn shadow_refresh_status_str(status: ShadowRefreshStatus) -> &'static str {
    match status {
        ShadowRefreshStatus::Current => "current",
        ShadowRefreshStatus::Refreshed => "refreshed",
        ShadowRefreshStatus::Busy => "busy",
    }
}

/// Content-verified freshness verdict for a persisted shadow import (#93).
///
/// Freshness is derived by recomputing the live CBM SQLite fingerprint and comparing
/// it to the `vault_fingerprint` watermark persisted at import time — never from mere
/// artifact/row/file existence (an emptied vault still verifies intact-with-0-rows, and
/// a stale watermark still "exists"). Every path that cannot prove a byte-for-byte
/// content match fails closed as [`ShadowContentVerdict::Unverifiable`] rather than
/// reporting current/fresh/verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ShadowContentVerdict {
    /// The live CBM SQLite fingerprint equals the persisted watermark and the derived
    /// artifacts (lowered SQLite + intact vault chain) are present.
    Fresh,
    /// The live CBM SQLite fingerprint differs from the persisted watermark: the source
    /// mutated out of band since the last shadow import.
    Stale { expected: String, actual: String },
    /// A verify-relevant input is missing, so freshness cannot be asserted from content.
    Unverifiable {
        code: &'static str,
        message: String,
        remediation: &'static str,
        /// True only when the CBM SQLite source itself is absent, so no re-import is
        /// possible and the refresh trigger has nothing to act on.
        source_missing: bool,
    },
}

/// Evaluates shadow-import freshness against the live CBM SQLite by content, not
/// existence (#93): recompute the source fingerprint and compare it to the watermark
/// persisted at import time. Any missing verify-relevant input fails closed.
pub(crate) fn evaluate_shadow_content_freshness(
    cache_dir: &Path,
    project: &str,
) -> Result<ShadowContentVerdict, DynError> {
    let source_path = sqlite_path(cache_dir, project);
    if !source_path.exists() {
        return Ok(ShadowContentVerdict::Unverifiable {
            code: ASTRO_SHADOW_SOURCE_MISSING,
            message: format!(
                "{ASTRO_SHADOW_SOURCE_MISSING}: CBM SQLite source {} is missing; shadow freshness cannot be verified against content",
                source_path.display()
            ),
            remediation: SHADOW_SOURCE_MISSING_REMEDIATION,
            source_missing: true,
        });
    }

    let Some(expected) = read_config_value(cache_dir, &metadata_key(project, "vault_fingerprint"))?
    else {
        return Ok(ShadowContentVerdict::Unverifiable {
            code: ASTRO_SHADOW_FINGERPRINT_MISSING,
            message: format!(
                "{ASTRO_SHADOW_FINGERPRINT_MISSING}: no persisted vault_fingerprint watermark for project {project:?}; a prior shadow import never recorded one"
            ),
            remediation: SHADOW_FINGERPRINT_MISSING_REMEDIATION,
            source_missing: false,
        });
    };

    let configured_lowered_path =
        read_config_value(cache_dir, &metadata_key(project, "lowered_sqlite_path"))?
            .map(PathBuf::from)
            .unwrap_or_else(|| lowered_sqlite_path(cache_dir, project));
    if !configured_lowered_path.exists() {
        return Ok(ShadowContentVerdict::Unverifiable {
            code: ASTRO_SHADOW_LOWERED_MISSING,
            message: format!(
                "{ASTRO_SHADOW_LOWERED_MISSING}: lowered artifact {} is missing; the shadow surface cannot be served",
                configured_lowered_path.display()
            ),
            remediation: SHADOW_LOWERED_MISSING_REMEDIATION,
            source_missing: false,
        });
    }

    let configured_vault_dir = read_config_value(cache_dir, &metadata_key(project, "vault_dir"))?
        .map(PathBuf::from)
        .unwrap_or_else(|| vault_dir(cache_dir, project));
    let verify_intact = configured_vault_dir.exists()
        && astrolabe_ingest::verify_chain_vault_path(&configured_vault_dir)
            .map(|report| report.is_intact())
            .unwrap_or(false);
    if !verify_intact {
        return Ok(ShadowContentVerdict::Unverifiable {
            code: ASTRO_SHADOW_VERIFY_NOT_INTACT,
            message: format!(
                "{ASTRO_SHADOW_VERIFY_NOT_INTACT}: vault ledger chain for project {project:?} does not verify intact"
            ),
            remediation: SHADOW_VERIFY_NOT_INTACT_REMEDIATION,
            source_missing: false,
        });
    }

    // Content gate: recompute the live CBM SQLite fingerprint and compare it to the
    // watermark persisted at import time. Existence of the artifacts above is necessary
    // but never sufficient — only a byte-for-byte fingerprint match proves freshness.
    let actual = astrolabe_ingest::fingerprint_sqlite_hex(&source_path)?;
    if actual == expected {
        Ok(ShadowContentVerdict::Fresh)
    } else {
        Ok(ShadowContentVerdict::Stale { expected, actual })
    }
}

pub(crate) fn ensure_shadow_import_current(project: &str) -> Result<ShadowRefreshStatus, DynError> {
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    match evaluate_shadow_content_freshness(&cache_dir, project)? {
        // Live source fingerprint matches the persisted watermark: nothing to refresh.
        ShadowContentVerdict::Fresh => return Ok(ShadowRefreshStatus::Current),
        // No CBM source present, so no re-import is possible. This is not a freshness
        // claim — the status summary labels this state unverified/fail-closed; the
        // refresh trigger simply has no source to act on.
        ShadowContentVerdict::Unverifiable {
            source_missing: true,
            ..
        } => return Ok(ShadowRefreshStatus::Current),
        // Stale content, or a missing/broken derived artifact with a live source:
        // fall through and re-import to reconcile against the current source.
        ShadowContentVerdict::Stale { .. }
        | ShadowContentVerdict::Unverifiable {
            source_missing: false,
            ..
        } => {}
    }

    let Some(_shadow_import_lock) = try_shadow_import_lock(&cache_dir, project)? else {
        return Ok(ShadowRefreshStatus::Busy);
    };
    let search_scale_settings = search_scale_settings_for_import(project, None)?;
    let outcome = import_shadow_vault(project, None, &search_scale_settings)?;
    persist_shadow_outcome(project, &outcome)?;
    Ok(ShadowRefreshStatus::Refreshed)
}

pub(crate) fn try_shadow_import_lock(
    cache_dir: &Path,
    project: &str,
) -> Result<Option<ShadowImportLock>, DynError> {
    fs::create_dir_all(cache_dir)?;
    let lock_path = shadow_import_lock_path(cache_dir, project);
    Ok(
        try_readable_marker_lock(&lock_path)?.map(|guard| ShadowImportLock {
            _guard: guard,
            path: lock_path,
        }),
    )
}

pub(crate) fn shadow_import_busy_summary_at(cache_dir: &Path, project: &str) -> Value {
    json!({
        "calyx": "shadow",
        "shadow_import": {
            "status": "busy",
            "freshness": "stale_ok",
            "trust": "provisional",
            "owner": "another-process",
            "lock_path": shadow_import_lock_path(cache_dir, project),
            "remediation": "retry after the active Astrolabe shadow import completes; legacy SQLite results remain served by codebase-memory-mcp",
        }
    })
}

pub(crate) fn shadow_import_current_summary(verdict: &ShadowContentVerdict) -> Value {
    // The label is derived from a content verdict (#93): `current/fresh/verified` is
    // emitted only when the live CBM SQLite fingerprint matches the persisted watermark.
    // Mismatch is reported stale; any missing verify-relevant input fails closed as
    // unverified — never fresh/verified from mere artifact existence.
    match verdict {
        ShadowContentVerdict::Fresh => json!({
            "status": "current",
            "freshness": "fresh",
            "trust": "verified",
            "verification": "content_fingerprint_match",
            "remediation": Value::Null,
        }),
        ShadowContentVerdict::Stale { expected, actual } => json!({
            "status": "stale",
            "freshness": "stale",
            "trust": "provisional",
            "verification": "content_fingerprint_mismatch",
            "expected_vault_fingerprint": expected,
            "actual_vault_fingerprint": actual,
            "remediation": SHADOW_STALE_REMEDIATION,
        }),
        ShadowContentVerdict::Unverifiable {
            code,
            message,
            remediation,
            ..
        } => json!({
            "status": "unverified",
            "freshness": "stale_or_missing",
            "trust": "provisional",
            "verification": "content_unverifiable",
            "code": code,
            "message": message,
            "remediation": remediation,
        }),
    }
}

pub(crate) fn import_shadow_vault(
    project: &str,
    row_sink: Option<RowSinkImportCandidate>,
    search_scale_settings: &SearchScaleSettings,
) -> Result<ShadowImportOutcome, DynError> {
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    fs::create_dir_all(&cache_dir)?;
    let sqlite_path = sqlite_path(&cache_dir, project);
    if !sqlite_path.exists() {
        return Err(format!(
            "CBM SQLite store is missing after index_repository: {}",
            sqlite_path.display()
        )
        .into());
    }

    // Content-freshness watermark (#221): fingerprint the CBM SQLite *source file* exactly
    // as `evaluate_shadow_content_freshness` will later recompute it over the live source.
    // This is deliberately the source-file digest, NOT `report.sqlite_fingerprint_sha256`:
    // in the row-sink direct import path that report field carries `row_sink_fingerprint`
    // (a digest over the in-memory rows with a different domain separator), which is
    // incommensurable with `fingerprint_sqlite_hex` and would make freshness permanently
    // Stale, triggering a runner-less refresh that clobbers the provenance surface. Captured
    // here at the top so it reflects the source bytes at import-decision time.
    let content_freshness_watermark_sha256 =
        astrolabe_ingest::fingerprint_sqlite_hex(&sqlite_path)?;

    let vault_dir = vault_dir(&cache_dir, project);
    fs::create_dir_all(&vault_dir)?;
    let vault_id = VaultId::from_str(SHADOW_VAULT_ID)?;
    let vault_salt = vault_salt(project);
    let vault = AsterVault::new_durable(
        &vault_dir,
        vault_id,
        vault_salt.as_bytes().to_vec(),
        VaultOptions::default(),
    )?;
    let options = SqliteImportOptions::new(
        project,
        format!("shadow-import-v1:{project}"),
        DEFAULT_PANEL_VERSION,
    )
    .with_available_slots(std::iter::empty());
    let shadow_import =
        import_shadow_vault_report(&sqlite_path, &vault, &ShadowSlotRuntime, &options, row_sink)?;
    let report = shadow_import.report;
    let lowered_sqlite_path = lowered_sqlite_path(&cache_dir, project);
    let lower_report = lower_shadow_sqlite(&cache_dir, project, &vault)?;
    let verify = verify_chain(&vault)?;
    if !verify.is_intact() {
        return Err(format!(
            "shadow vault ledger verification failed after import/lower: {}",
            verify.status
        )
        .into());
    }
    let total_records = (report.sqlite_nodes as u64).saturating_add(report.sqlite_edges as u64);
    let search_scale = search_scale_summary(search_scale_settings, total_records)?;
    let provenance = provenance_surface_with_chain(
        shadow_import.provenance,
        &lower_report.vault_fingerprint_sha256,
        lower_report.manifest_seq,
        &verify,
    );

    Ok(ShadowImportOutcome {
        vault_dir,
        vault_id: SHADOW_VAULT_ID.to_string(),
        vault_salt,
        sqlite_path,
        sqlite_fingerprint_sha256: hex_lower(&report.sqlite_fingerprint_sha256),
        content_freshness_watermark_sha256,
        lowered_sqlite_path,
        lowered_artifact_sha256: lower_report.artifact_sha256,
        lowered_vault_fingerprint_sha256: lower_report.vault_fingerprint_sha256,
        lowered_manifest_seq: lower_report.manifest_seq,
        lowered_nodes: lower_report.node_count,
        lowered_edges: lower_report.edge_count,
        lowered_skipped_edges: lower_report.skipped_edges,
        sqlite_nodes: report.sqlite_nodes,
        sqlite_edges: report.sqlite_edges,
        constellation_inputs: report.constellation_inputs,
        structural_only: report.structural_only,
        new_cx_ids: report.new_cx_ids,
        reused_cx_ids: report.reused_cx_ids,
        graph_rows_written: report.graph_rows_written,
        edge_rows_written: report.edge_rows_written,
        cx_id_set_sha256: cx_id_set_sha256(&report.cx_ids),
        ledger_seq: lower_report.manifest_seq,
        ledger_rows_after: verify.ledger_rows,
        verify_chain_status: verify.status,
        vault_import_source: shadow_import.source,
        vault_import_fallback_reason: shadow_import.fallback_reason,
        security_screen: shadow_import.security_screen,
        search_scale,
        skill_tree: shadow_import.skill_tree,
        bridges: shadow_import.bridges,
        kernel_context: shadow_import.kernel_context,
        anomalies: shadow_import.anomalies,
        provenance,
    })
}

pub(crate) fn import_shadow_vault_report<C, R>(
    sqlite_path: &Path,
    vault: &AsterVault<C>,
    runtime: &R,
    options: &SqliteImportOptions,
    row_sink: Option<RowSinkImportCandidate>,
) -> Result<ShadowVaultImport, DynError>
where
    C: Clock,
    R: SlotRuntime + Sync,
{
    match row_sink {
        Some(RowSinkImportCandidate::Available(snapshot)) => {
            let security_screen = snapshot.security_screen.clone();
            let skill_tree = snapshot.skill_tree.clone();
            let bridges = snapshot.bridges.clone();
            let kernel_context = snapshot.kernel_context.clone();
            let anomalies = snapshot.anomalies.clone();
            let provenance = snapshot.provenance.clone();
            match import_cbm_graph_snapshot_to_vault_direct(
                &snapshot.snapshot,
                snapshot.source_fingerprint_sha256,
                vault,
                runtime,
                options,
            ) {
                Ok(report) => Ok(ShadowVaultImport {
                    report,
                    source: "row_sink_direct".to_string(),
                    fallback_reason: None,
                    security_screen,
                    skill_tree,
                    bridges,
                    kernel_context,
                    anomalies,
                    provenance,
                }),
                Err(error) => {
                    let reason = format!("row-sink direct import failed: {error}");
                    let report = import_sqlite_to_vault(sqlite_path, vault, runtime, options)?;
                    Ok(ShadowVaultImport {
                        report,
                        source: "sqlite_fallback".to_string(),
                        fallback_reason: Some(reason),
                        security_screen,
                        skill_tree,
                        bridges,
                        kernel_context,
                        anomalies,
                        provenance,
                    })
                }
            }
        }
        Some(RowSinkImportCandidate::Unavailable(reason)) => {
            let report = import_sqlite_to_vault(sqlite_path, vault, runtime, options)?;
            let security_screen =
                security_screen_unavailable(security_screen_subject(&options.project), &reason);
            let skill_tree = skill_tree_unavailable_json(&reason);
            let bridges = bridges_unavailable_json(&reason);
            let kernel_context = kernel_context_unavailable_json(&reason);
            let anomalies = anomaly_report_unavailable_json(&reason);
            let provenance = provenance_unavailable_json(&reason);
            Ok(ShadowVaultImport {
                report,
                source: "sqlite_fallback".to_string(),
                fallback_reason: Some(reason),
                security_screen,
                skill_tree,
                bridges,
                kernel_context,
                anomalies,
                provenance,
            })
        }
        None => {
            let report = import_sqlite_to_vault(sqlite_path, vault, runtime, options)?;
            let reason = "row-sink snapshot not available for recovery import";
            Ok(ShadowVaultImport {
                report,
                source: "sqlite_fallback".to_string(),
                fallback_reason: Some(reason.to_string()),
                security_screen: security_screen_unavailable(
                    security_screen_subject(&options.project),
                    reason,
                ),
                skill_tree: skill_tree_unavailable_json(reason),
                bridges: bridges_unavailable_json(reason),
                kernel_context: kernel_context_unavailable_json(reason),
                anomalies: anomaly_report_unavailable_json(reason),
                provenance: provenance_unavailable_json(reason),
            })
        }
    }
}

pub(crate) fn row_sink_import_candidate_from_rows(rows: CbmPipelineRows) -> RowSinkImportCandidate {
    if rows.project.trim().is_empty() {
        return RowSinkImportCandidate::Unavailable(
            "single-run row sink produced no project name".to_string(),
        );
    }
    if rows.nodes.is_empty() && rows.edges.is_empty() {
        return RowSinkImportCandidate::Unavailable(
            "single-run row sink produced zero nodes and zero edges".to_string(),
        );
    }
    let source_fingerprint_sha256 = row_sink_fingerprint(&rows);
    let security_screen = security_screen_from_row_sink_rows(&rows);
    let skill_tree = skill_tree_from_row_sink_rows(&rows);
    let bridges = bridges_from_row_sink_rows(&rows);
    let kernel_context = kernel_context_from_row_sink_rows(&rows);
    let anomalies = anomalies_from_row_sink_rows(&rows);
    let provenance = provenance_from_row_sink_rows(&rows);
    RowSinkImportCandidate::Available(Box::new(RowSinkSnapshot {
        snapshot: pipeline_rows_to_graph_snapshot(rows),
        source_fingerprint_sha256,
        security_screen,
        skill_tree,
        bridges,
        kernel_context,
        anomalies,
        provenance,
    }))
}

pub(crate) fn pipeline_rows_to_graph_snapshot(rows: CbmPipelineRows) -> CbmGraphSnapshot {
    let project = rows.project.clone();
    let nodes = rows
        .nodes
        .into_iter()
        .map(|node| CbmGraphNode {
            source_node_id: node.id,
            project: node.project,
            label: node.label,
            name: node.name,
            qualified_name: node.qualified_name,
            file_path: node.file_path,
            start_line: node.start_line,
            end_line: node.end_line,
            properties_json: node.properties_json,
            node_vector: None,
            cx_id: None,
            structural: false,
        })
        .collect();
    let edges = rows
        .edges
        .into_iter()
        .map(|edge| CbmGraphEdge {
            sqlite_edge_id: edge.id,
            project: edge.project,
            source_node_id: edge.source_id,
            target_node_id: edge.target_id,
            src: None,
            dst: None,
            edge_type: edge.edge_type,
            local_name_gen: edge.local_name_gen,
            weight: 1.0,
            properties_json: edge.properties_json,
        })
        .collect();
    CbmGraphSnapshot {
        project,
        panel_version: Some(DEFAULT_PANEL_VERSION),
        projects: Vec::new(),
        nodes,
        edges,
        file_hashes: Vec::new(),
        project_summaries: Vec::new(),
        token_vectors: Vec::new(),
    }
}

pub(crate) fn row_sink_fingerprint(rows: &CbmPipelineRows) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"astrolabe-cbm-row-sink-v1\0");
    hash_str(&mut hasher, &rows.project);

    let mut nodes = rows.nodes.iter().collect::<Vec<_>>();
    nodes.sort_by_key(|node| node.id);
    hash_u64(&mut hasher, nodes.len() as u64);
    for node in nodes {
        hash_i64(&mut hasher, node.id);
        hash_str(&mut hasher, &node.project);
        hash_str(&mut hasher, &node.label);
        hash_str(&mut hasher, &node.name);
        hash_str(&mut hasher, &node.qualified_name);
        hash_str(&mut hasher, &node.file_path);
        hash_i64(&mut hasher, node.start_line);
        hash_i64(&mut hasher, node.end_line);
        hash_str(&mut hasher, &node.properties_json);
    }

    let mut edges = rows.edges.iter().collect::<Vec<_>>();
    edges.sort_by(|left, right| {
        left.id
            .cmp(&right.id)
            .then_with(|| left.source_id.cmp(&right.source_id))
            .then_with(|| left.target_id.cmp(&right.target_id))
            .then_with(|| left.edge_type.cmp(&right.edge_type))
            .then_with(|| left.local_name_gen.cmp(&right.local_name_gen))
    });
    hash_u64(&mut hasher, edges.len() as u64);
    for edge in edges {
        hash_i64(&mut hasher, edge.id);
        hash_str(&mut hasher, &edge.project);
        hash_i64(&mut hasher, edge.source_id);
        hash_i64(&mut hasher, edge.target_id);
        hash_str(&mut hasher, &edge.edge_type);
        hash_str(&mut hasher, &edge.properties_json);
        hash_str(&mut hasher, &edge.url_path_gen);
        hash_str(&mut hasher, &edge.local_name_gen);
    }

    hasher.finalize().into()
}

pub(crate) fn hash_str(hasher: &mut Sha256, value: &str) {
    hash_u64(hasher, value.len() as u64);
    hasher.update(value.as_bytes());
}

pub(crate) fn hash_i64(hasher: &mut Sha256, value: i64) {
    hasher.update(value.to_le_bytes());
}

pub(crate) fn hash_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_le_bytes());
}

pub(crate) fn lower_shadow_sqlite<C>(
    cache_dir: &Path,
    project: &str,
    vault: &AsterVault<C>,
) -> Result<astrolabe_lower::LoweredSqliteReport, DynError>
where
    C: Clock,
{
    with_lowered_sqlite_lock(cache_dir, project, || {
        lower_cbm_sqlite(
            vault,
            lowered_sqlite_path(cache_dir, project),
            &LowerSqliteOptions::new(project),
        )
        .map_err(Into::into)
    })
}

pub(crate) fn grounding_summary(outcome: &ShadowImportOutcome) -> Value {
    json!({
        "status": "imported",
        "sqlite_nodes": outcome.sqlite_nodes,
        "sqlite_edges": outcome.sqlite_edges,
        "constellation_inputs": outcome.constellation_inputs,
        "structural_only": outcome.structural_only,
        "idempotency": {
            "new_cx_ids": outcome.new_cx_ids,
            "reused_cx_ids": outcome.reused_cx_ids,
            "graph_rows_written": outcome.graph_rows_written,
            "edge_rows_written": outcome.edge_rows_written,
            "cx_id_set_sha256": outcome.cx_id_set_sha256,
        },
        "sqlite_path": outcome.sqlite_path,
        "lowered_sqlite": lowered_summary(
            &outcome.lowered_sqlite_path,
            Some(&outcome.lowered_artifact_sha256),
            Some(&outcome.lowered_vault_fingerprint_sha256),
            Some(outcome.lowered_manifest_seq),
            Some(outcome.lowered_nodes),
            Some(outcome.lowered_edges),
            Some(outcome.lowered_skipped_edges),
        ),
        "vault_dir": outcome.vault_dir,
        "vault_id": outcome.vault_id,
        "vault_salt": outcome.vault_salt,
        "ledger_seq": outcome.ledger_seq,
        "ledger_rows_after": outcome.ledger_rows_after,
        "verify_chain": outcome.verify_chain_status,
        "panel_version": DEFAULT_PANEL_VERSION,
        "panel_runtime": "lens_unavailable",
        "vault_import": vault_import_summary(
            &outcome.vault_import_source,
            outcome.vault_import_fallback_reason.as_deref(),
        ),
        "security_screen": outcome.security_screen.clone(),
        "search_scale": outcome.search_scale.clone(),
        "skill_tree": outcome.skill_tree.clone(),
        "bridges": outcome.bridges.clone(),
        "kernel_context": outcome.kernel_context.clone(),
        "anomalies": outcome.anomalies.clone(),
        "provenance": outcome.provenance.clone(),
        "health": health_surface_json(
            outcome_project_label(outcome),
            &outcome.verify_chain_status,
            outcome.lowered_sqlite_path.exists(),
            Some(outcome.ledger_seq),
            Some(outcome.ledger_rows_after),
            None,
            None,
        ),
        "stores": stores_summary(
            &outcome.sqlite_path,
            &outcome.vault_dir,
            Some(&outcome.lowered_sqlite_path),
        ),
    })
}

pub(crate) fn outcome_project_label(outcome: &ShadowImportOutcome) -> &str {
    outcome
        .sqlite_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .filter(|stem| !stem.is_empty())
        .unwrap_or("unknown")
}

pub(crate) fn open_shadow_vault_read_only(
    vault_dir: &Path,
    vault_id: &str,
    vault_salt: &str,
    selected_cfs: Vec<ColumnFamily>,
) -> Result<AsterVault, DynError> {
    open_shadow_vault_with_access(vault_dir, vault_id, vault_salt, selected_cfs, true)
}

pub(crate) fn open_shadow_vault_writable(
    vault_dir: &Path,
    vault_id: &str,
    vault_salt: &str,
    selected_cfs: Vec<ColumnFamily>,
) -> Result<AsterVault, DynError> {
    open_shadow_vault_with_access(vault_dir, vault_id, vault_salt, selected_cfs, false)
}

pub(crate) fn open_shadow_vault_with_access(
    vault_dir: &Path,
    vault_id: &str,
    vault_salt: &str,
    selected_cfs: Vec<ColumnFamily>,
    read_only: bool,
) -> Result<AsterVault, DynError> {
    let vault_id = VaultId::from_str(vault_id)?;
    let options = VaultOptions {
        read_only,
        restore_ledger_hook: !read_only,
        selected_cfs: read_only.then_some(selected_cfs),
        ..VaultOptions::default()
    };
    Ok(AsterVault::open(
        vault_dir,
        vault_id,
        vault_salt.as_bytes().to_vec(),
        options,
    )?)
}

pub(crate) fn vault_import_summary(source: &str, fallback_reason: Option<&str>) -> Value {
    let fallback_reason = fallback_reason.and_then(|reason| {
        let trimmed = reason.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    });
    let fallback = fallback_reason.is_some() || source == "sqlite_fallback" || source == "unknown";
    json!({
        "source": source,
        "trust": if fallback { "provisional" } else { "verified" },
        "fallback_reason": fallback_reason,
    })
}

pub(crate) fn lowered_summary(
    path: &Path,
    artifact_sha256: Option<&String>,
    vault_fingerprint_sha256: Option<&String>,
    manifest_seq: Option<u64>,
    nodes: Option<usize>,
    edges: Option<usize>,
    skipped_edges: Option<usize>,
) -> Value {
    json!({
        "writer": "astrolabe",
        "path": path,
        "exists": path.exists(),
        "artifact_sha256": artifact_sha256,
        "vault_fingerprint_sha256": vault_fingerprint_sha256,
        "manifest_seq": manifest_seq,
        "nodes": nodes,
        "edges": edges,
        "skipped_edges": skipped_edges,
        "serves_legacy_tools": false,
    })
}

pub(crate) fn stores_summary(
    sqlite_path: &Path,
    vault_dir: &Path,
    lowered_sqlite_path: Option<&Path>,
) -> Value {
    let mut stores = Map::new();
    stores.insert(
        "sqlite".to_string(),
        json!({
            "writer": "codebase-memory-mcp",
            "path": sqlite_path,
            "serves_legacy_tools": true,
        }),
    );
    stores.insert(
        "vault".to_string(),
        json!({
            "writer": "astrolabe",
            "path": vault_dir,
            "serves_legacy_tools": false,
        }),
    );
    if let Some(path) = lowered_sqlite_path {
        stores.insert(
            "lowered_sqlite".to_string(),
            json!({
                "writer": "astrolabe",
                "path": path,
                "serves_legacy_tools": false,
            }),
        );
    }
    Value::Object(stores)
}

pub(crate) fn persist_shadow_outcome(
    project: &str,
    outcome: &ShadowImportOutcome,
) -> Result<(), DynError> {
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    persist_shadow_outcome_at(&cache_dir, project, outcome)
}

pub(crate) fn persist_shadow_outcome_at(
    cache_dir: &Path,
    project: &str,
    outcome: &ShadowImportOutcome,
) -> Result<(), DynError> {
    let mut conn = open_config(cache_dir)?;
    let security_screen_json = serde_json::to_string(&outcome.security_screen)?;
    let search_scale_json = serde_json::to_string(&outcome.search_scale)?;
    let skill_tree_json = serde_json::to_string(&outcome.skill_tree)?;
    let bridge_reports_json = serde_json::to_string(&outcome.bridges)?;
    let kernel_context_json = serde_json::to_string(&outcome.kernel_context)?;
    let anomaly_report_json = serde_json::to_string(&outcome.anomalies)?;
    let provenance_json = serde_json::to_string(&outcome.provenance)?;
    // Atomic multi-key persist: a crash or error mid-write must not leave a torn
    // mix of new and old metadata that a reader would serve as fresh/verified
    // (e.g. a new vault_fingerprint beside a stale kernel_context_json) — #95.
    let tx = conn.transaction()?;
    for (key, value) in [
        ("vault_dir", outcome.vault_dir.display().to_string()),
        ("vault_id", outcome.vault_id.clone()),
        ("vault_salt", outcome.vault_salt.clone()),
        ("sqlite_path", outcome.sqlite_path.display().to_string()),
        // Content-freshness watermark (#93/#221): the SHA-256 of the CBM SQLite *source
        // file* at import time, taken from `content_freshness_watermark_sha256` — NOT from
        // `sqlite_fingerprint_sha256`, which in the row-sink direct import path carries the
        // row-sink content digest and is incommensurable with what the freshness gate
        // recomputes. `evaluate_shadow_content_freshness` reads this exact key with no
        // fallback and re-fingerprints the live source against it; if the key is absent (or,
        // previously, held the wrong-domain row digest so it never matched) freshness reads
        // Stale/Unverifiable and `ensure_shadow_import_current` re-imports with no row-sink
        // candidate, clobbering the just-persisted provenance with an "unavailable" surface.
        // Persist the source-file digest so an unchanged source stays Fresh.
        (
            "vault_fingerprint",
            outcome.content_freshness_watermark_sha256.clone(),
        ),
        (
            "lowered_sqlite_path",
            outcome.lowered_sqlite_path.display().to_string(),
        ),
        (
            "lowered_artifact_sha256",
            outcome.lowered_artifact_sha256.clone(),
        ),
        (
            "lowered_vault_fingerprint_sha256",
            outcome.lowered_vault_fingerprint_sha256.clone(),
        ),
        (
            "lowered_manifest_seq",
            outcome.lowered_manifest_seq.to_string(),
        ),
        ("lowered_nodes", outcome.lowered_nodes.to_string()),
        ("lowered_edges", outcome.lowered_edges.to_string()),
        (
            "lowered_skipped_edges",
            outcome.lowered_skipped_edges.to_string(),
        ),
        ("ledger_seq", outcome.ledger_seq.to_string()),
        ("ledger_rows", outcome.ledger_rows_after.to_string()),
        ("panel_version", DEFAULT_PANEL_VERSION.to_string()),
        ("structural_only", outcome.structural_only.to_string()),
        ("new_cx_ids", outcome.new_cx_ids.to_string()),
        ("reused_cx_ids", outcome.reused_cx_ids.to_string()),
        ("graph_rows_written", outcome.graph_rows_written.to_string()),
        ("edge_rows_written", outcome.edge_rows_written.to_string()),
        ("cx_id_set_sha256", outcome.cx_id_set_sha256.clone()),
        ("vault_import_source", outcome.vault_import_source.clone()),
        (
            "vault_import_fallback_reason",
            outcome
                .vault_import_fallback_reason
                .clone()
                .unwrap_or_default(),
        ),
        ("security_screen_json", security_screen_json),
        ("search_scale_json", search_scale_json),
        ("skill_tree_json", skill_tree_json),
        ("bridge_reports_json", bridge_reports_json),
        ("kernel_context_json", kernel_context_json),
        ("anomaly_report_json", anomaly_report_json),
        ("provenance_json", provenance_json),
    ] {
        tx.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
            params![metadata_key(project, key), value],
        )?;
    }
    tx.commit()?;
    Ok(())
}
