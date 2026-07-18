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
/// Genuine source staleness that the read path refuses to reconcile on its own, because
/// the refresh available to it cannot rebuild the row-sink-derived surfaces (#222).
pub(crate) const ASTRO_SHADOW_STALE_REINDEX_REQUIRED: &str = "ASTRO_SHADOW_STALE_REINDEX_REQUIRED";
/// The live git source tree changed out of band since the last shadow import (#347):
/// its content fingerprint no longer matches the persisted git-source watermark. The
/// derived CBM `<project>.db` is unchanged (an out-of-band `git commit`/edit never
/// touches it), so the CBM-db content gate alone would have wrongly reported Fresh.
pub(crate) const ASTRO_SHADOW_SOURCE_OUT_OF_BAND: &str = "ASTRO_SHADOW_SOURCE_OUT_OF_BAND";
/// A git-source watermark and repo path are persisted, but the live git source
/// fingerprint cannot be recomputed (the source tree was moved/deleted, or git is
/// unavailable), so freshness cannot be asserted against the real source (#347).
pub(crate) const ASTRO_SHADOW_GIT_SOURCE_UNREADABLE: &str = "ASTRO_SHADOW_GIT_SOURCE_UNREADABLE";
pub(crate) const SHADOW_SOURCE_OUT_OF_BAND_REMEDIATION: &str = "the git source tree changed out of band (commit or working-tree edit) since the last shadow import; rerun index_repository with calyx=\"shadow\" so the vault, lowered artifact, and row-sink-derived surfaces are rebuilt from the current source. index_status reconciles this automatically when a CBM tool runner is available";
pub(crate) const SHADOW_GIT_SOURCE_UNREADABLE_REMEDIATION: &str = "the persisted git source path could not be fingerprinted (the source tree was moved/deleted, or git is unavailable); restore the source tree at its indexed path, or rerun index_repository with calyx=\"shadow\" from the current source location";
/// Metadata key holding the git working-tree source fingerprint captured at import time.
pub(crate) const GIT_SOURCE_FINGERPRINT_KEY: &str = "git_source_fingerprint";
/// Metadata key holding the absolute repo path whose git source fingerprint was recorded,
/// so the read-path freshness gate can recompute it against the live tree (#347).
pub(crate) const GIT_SOURCE_REPO_PATH_KEY: &str = "git_source_repo_path";
/// The row-sink direct import failed and there is no CBM SQLite artifact to fall back to
/// (the sqlite path is intentionally absent). Falling back would only mask the real
/// row-sink error behind a misleading "cannot open SQLite" error, so the direct-import
/// error is surfaced verbatim and fail-closed (#23).
pub(crate) const ASTRO_SHADOW_ROW_SINK_IMPORT_FAILED: &str = "ASTRO_SHADOW_ROW_SINK_IMPORT_FAILED";
/// The row-sink direct import failed AND the CBM SQLite fallback import also failed. Both
/// underlying errors are chained verbatim so neither cause is masked (#23).
pub(crate) const ASTRO_SHADOW_IMPORT_BOTH_FAILED: &str = "ASTRO_SHADOW_IMPORT_BOTH_FAILED";
/// The out-of-process shadow index pass did not complete cleanly (#405): a hard
/// C-level abort (segfault/abort-class), a hang, a non-fault kill, or a spawn
/// failure. The CBM pipeline pass runs in a supervised worker subprocess precisely
/// so such a fault is contained there and can never leave a partially-written
/// vault — vault writes begin only after a fully clean pass. This code marks that
/// contained failure; the vault is left fully intact (no partial manifests/surfaces).
pub(crate) const ASTRO_SHADOW_INDEX_PASS_CRASHED: &str = "ASTRO_SHADOW_INDEX_PASS_CRASHED";
pub(crate) const SHADOW_INDEX_PASS_CRASHED_REMEDIATION: &str = "the CBM index pass did not complete cleanly in its isolated worker subprocess; the fault was contained and the shadow vault was left untouched (not partially committed). Inspect the worker exit code / log tail carried in this error to find the offending input, then rerun index_repository with calyx=\"shadow\"";
pub(crate) const SHADOW_ROW_SINK_IMPORT_FAILED_REMEDIATION: &str = "the CBM row-sink snapshot could not be imported directly and no CBM SQLite artifact exists to recover from; fix the row-sink rows (the chained error names the exact offending row/field) and rerun index_repository with calyx=\"shadow\"";
pub(crate) const SHADOW_IMPORT_BOTH_FAILED_REMEDIATION: &str = "both the CBM row-sink direct import and the CBM SQLite fallback import failed; the chained errors name each root cause — resolve the row-sink error first (it is the primary source), then rerun index_repository with calyx=\"shadow\"";
pub(crate) const SHADOW_SOURCE_MISSING_REMEDIATION: &str = "run index_repository with calyx=\"shadow\" to build the CBM SQLite source and shadow vault before reading shadow freshness";
pub(crate) const SHADOW_FINGERPRINT_MISSING_REMEDIATION: &str = "no shadow import watermark is recorded; run index_repository with calyx=\"shadow\" so the vault_fingerprint content watermark is persisted";
/// #222: `index_status` deliberately no longer promises a background refresh here. The
/// only refresh it can run has no `CbmToolRunner`, so it would overwrite the persisted
/// provenance/security/skill/bridge/kernel/anomaly surfaces with "unavailable". A reindex
/// is the honest remediation.
pub(crate) const SHADOW_LOWERED_MISSING_REMEDIATION: &str = "the lowered artifact is absent; rerun index_repository with calyx=\"shadow\" to rebuild it from current source";
pub(crate) const SHADOW_VERIFY_NOT_INTACT_REMEDIATION: &str = "the vault ledger chain does not verify intact; quarantine the vault and rerun index_repository with calyx=\"shadow\" to rebuild from current source";
pub(crate) const SHADOW_STALE_REMEDIATION: &str = "the CBM SQLite changed since the last shadow import; rerun index_repository with calyx=\"shadow\" so the vault, the lowered artifact, and the row-sink-derived surfaces (provenance, security screen, skill tree, bridges, kernel context, anomalies) are all rebuilt from current source. index_status will not reconcile this for you: it has no CBM tool runner and would have to overwrite those surfaces with \"unavailable\"";

/// The config keys holding the row-sink-derived surfaces of a shadow import.
///
/// Every one of these is produced only by an import that carries a
/// [`RowSinkImportCandidate::Available`] snapshot — i.e. one driven by a live
/// `CbmToolRunner`. The `None` branch of [`import_shadow_vault_report`] replaces all of
/// them with `*_unavailable_json(..)`, and [`persist_shadow_outcome_at`] then writes that
/// over whatever was there. A freshness-triggered refresh has no runner, so if any of
/// these keys already holds a value, refreshing would destroy last-known-good state
/// (#222). [`has_persisted_derived_surfaces`] is the guard that makes that impossible.
pub(crate) const SHADOW_DERIVED_SURFACE_KEYS: [&str; 6] = [
    "provenance_json",
    "security_screen_json",
    "skill_tree_json",
    "bridge_reports_json",
    "kernel_context_json",
    "anomaly_report_json",
];

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
    pub(crate) series_inputs: usize,
    pub(crate) series_mutated_rows: usize,
    /// Unforgeable readback witness for the SQLite/row-sink import mutation.
    pub(crate) import_fsv: Option<astrolabe_domain::fsv::FsvAck>,
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
    pub(crate) git_archaeology: Value,
    pub(crate) weave: Value,
    /// Git working-tree source fingerprint captured at import time (#347), present only
    /// when the import ran against a real repo path. Persisted as the source-of-truth
    /// freshness watermark the read path recomputes against the live tree.
    pub(crate) git_source_fingerprint: Option<String>,
    /// Absolute repo path whose git source fingerprint was recorded, so the read-path
    /// freshness gate can recompute it (#347). `None` when the import had no repo path.
    pub(crate) git_source_repo_path: Option<String>,
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

#[derive(Debug, Clone, Default)]
pub(crate) struct WeaveDelta {
    pub(crate) dirty_qualified_names: BTreeSet<String>,
    pub(crate) removed_qualified_names: BTreeSet<String>,
    pub(crate) removed_cx_ids: BTreeSet<calyx_core::CxId>,
}

#[derive(Debug, Clone)]
struct ShadowLowerState {
    artifact_sha256: String,
    vault_fingerprint_sha256: String,
    manifest_seq: u64,
    node_count: usize,
    edge_count: usize,
    skipped_edges: usize,
}

impl From<astrolabe_lower::LoweredSqliteReport> for ShadowLowerState {
    fn from(report: astrolabe_lower::LoweredSqliteReport) -> Self {
        Self {
            artifact_sha256: report.artifact_sha256,
            vault_fingerprint_sha256: report.vault_fingerprint_sha256,
            manifest_seq: report.manifest_seq,
            node_count: report.node_count,
            edge_count: report.edge_count,
            skipped_edges: report.skipped_edges,
        }
    }
}

static SHADOW_EMBEDDING_TABLE: OnceLock<PanelResult<astrolabe_panel::StaticEmbeddingTable>> =
    OnceLock::new();

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum ShadowRefreshStatus {
    Current,
    Refreshed,
    Busy,
    /// The shadow import is provably not current, and the read-path refresh cannot
    /// reconcile it without destroying state (#222).
    ///
    /// [`ensure_shadow_import_current`] has no `CbmToolRunner`, so the only import it can
    /// run passes `row_sink = None`; that import persists `*_unavailable_json(..)` over
    /// every row-sink-derived surface. When such surfaces already exist, refreshing would
    /// silently downgrade good provenance / security-screen / skill-tree / bridge /
    /// kernel-context / anomaly state to "unavailable" — a silent fallback that destroys
    /// good data (standing invariants #2 and #3). Instead the refresh **persists nothing**
    /// and returns this status: the last-known-good surfaces are preserved, `index_status`
    /// reports `shadow_import.status = "stale_reindex_required"` with a coded remediation,
    /// and `team_artifact export` refuses. An explicit `index_repository` with
    /// `calyx="shadow"` — which does have a runner — is the reconciliation path.
    StaleReindexRequired,
}

impl SlotRuntime for ShadowSlotRuntime {
    fn measure_slot(&self, slot: &PanelSlotSpec, input: &PanelInput) -> PanelResult<SlotVector> {
        if matches!(slot.slot, 18..=20) {
            let table = SHADOW_EMBEDDING_TABLE
                .get_or_init(astrolabe_panel::StaticEmbeddingTable::load_default)
                .as_ref()
                .map_err(Clone::clone)?;
            return astrolabe_panel::encode_static_embedding_slot(
                slot.slot_id(),
                &shadow_embedding_input(input),
                table,
            );
        }
        astrolabe_panel::encode_slot(slot.slot_id(), &shadow_encoder_input(input))
    }
}

fn shadow_embedding_input(input: &PanelInput) -> astrolabe_panel::StaticEmbeddingInput {
    astrolabe_panel::StaticEmbeddingInput {
        body_tokens: property_string(&input.properties, "bt")
            .map(text_tokens)
            .unwrap_or_else(|| text_tokens(&String::from_utf8_lossy(&input.source_bytes))),
        doc_tokens: property_string(&input.properties, "docstring")
            .map(text_tokens)
            .unwrap_or_default(),
        name: input.symbol_name.clone(),
        qualified_name: input.qualified_name.clone(),
    }
}

fn shadow_encoder_input(input: &PanelInput) -> astrolabe_panel::EncoderLensInput {
    use astrolabe_panel::{
        ComplexityMetrics, ConfigEnvSurfaceInput, EncoderLensInput, ErrorSurfaceInput,
        IdentifierLexicalInput, LangLabelInput, PathHierarchyInput, RECORD_VECTOR_SCALAR_KEYS,
        RecordVectorInput, RoleFlagsInput, RouteObservation, RouteSurfaceInput, TypeSurfaceInput,
    };

    let properties = &input.properties;
    let body_identifiers = property_string(properties, "bt")
        .map(text_tokens)
        .unwrap_or_else(|| text_tokens(&String::from_utf8_lossy(&input.source_bytes)));
    let complexity = numeric_property(properties, "complexity");
    let cognitive = numeric_property(properties, "cognitive");
    let loop_count = numeric_property(properties, "loop_count");
    let loop_depth = numeric_property(properties, "loop_depth");
    let max_access_depth = numeric_property(properties, "max_access_depth");
    let param_count = numeric_property(properties, "param_count");
    let body_lines = numeric_property(properties, "lines").or_else(|| {
        Some(
            input
                .source_bytes
                .iter()
                .filter(|byte| **byte == b'\n')
                .count() as f32,
        )
    });
    let body_tokens = property_string(properties, "bt")
        .map(|tokens| text_tokens(tokens).len() as f32)
        .or(Some(body_identifiers.len() as f32));
    let complexity_input = Some(ComplexityMetrics {
        cyclomatic: complexity.unwrap_or(0.0),
        cognitive: cognitive.unwrap_or(0.0),
        loop_count: loop_count.unwrap_or(0.0),
        loop_depth: loop_depth.unwrap_or(0.0),
        max_access_depth: max_access_depth.unwrap_or(0.0),
        param_count: param_count.unwrap_or(0.0),
        body_lines: body_lines.unwrap_or(0.0),
        body_tokens: body_tokens.unwrap_or(0.0),
    });

    let mut record_scalars = RECORD_VECTOR_SCALAR_KEYS
        .iter()
        .map(|key| ((*key).to_string(), 0.0_f32))
        .collect::<BTreeMap<_, _>>();
    for (key, value) in [
        ("complexity.cyclomatic", complexity),
        ("complexity.cognitive", cognitive),
        ("complexity.loop_count", loop_count),
        ("complexity.loop_depth", loop_depth),
        ("complexity.max_access_depth", max_access_depth),
        ("complexity.param_count", param_count),
        ("complexity.body_lines", body_lines),
        ("complexity.body_tokens", body_tokens),
    ] {
        if let Some(value) = value {
            record_scalars.insert(key.to_string(), value);
        }
    }

    let route_path = property_string(properties, "route_path").unwrap_or_default();
    let route_surface = (!route_path.trim().is_empty()).then(|| RouteSurfaceInput {
        routes: vec![RouteObservation {
            method: property_string(properties, "route_method")
                .unwrap_or_default()
                .to_string(),
            path: route_path.to_string(),
        }],
        channels: Vec::new(),
    });
    let docstring = property_string(properties, "docstring").unwrap_or_default();

    EncoderLensInput {
        ast_profile: property_string(properties, "sp").and_then(parse_ast_profile),
        // S1 (struct_trigrams) / S4 (api_callees) guard-slot encoder sources, now
        // serialized by libcbm at index time (#374): the `st` property carries the
        // normalised AST node-type trigram list and `callees` the deduplicated
        // api-callee counts. Both parse to `None` when absent so a symbol libcbm
        // could not measure stays honestly unmeasured (a fail-closed slot deficit),
        // never a fabricated vector.
        struct_trigrams: property_string(properties, "st").and_then(parse_struct_trigrams),
        complexity: complexity_input,
        api_calls: property_string(properties, "callees").and_then(parse_api_callees),
        type_surface: Some(TypeSurfaceInput {
            param_types: property_strings(properties, "param_types"),
            return_types: property_string(properties, "return_type")
                .filter(|value| !value.trim().is_empty())
                .map(|value| vec![value.to_string()])
                .unwrap_or_default(),
            uses_types: property_strings(properties, "base_classes"),
            instantiates: Vec::new(),
        }),
        decorators: Some(property_strings(properties, "decorators")),
        identifiers: Some(IdentifierLexicalInput {
            name: input.symbol_name.clone(),
            qualified_name: input.qualified_name.clone(),
            body_identifiers,
        }),
        graph_position: None,
        path_hierarchy: Some(PathHierarchyInput {
            path: input.rel_file_path.clone(),
        }),
        churn_profile: None,
        recency: None,
        role_flags: Some(RoleFlagsInput {
            is_test: bool_property(properties, "is_test"),
            is_entry: bool_property(properties, "is_entry_point"),
            is_exported: bool_property(properties, "is_exported"),
            is_abstract: bool_property(properties, "is_abstract"),
            is_async: bool_property(properties, "is_async"),
            is_generator: bool_property(properties, "is_generator"),
            is_route: route_surface.is_some(),
            is_handler: route_surface.is_some(),
            is_dead: bool_property(properties, "is_dead"),
            is_recursive: bool_property(properties, "self_recursive"),
            is_generated: input.rel_file_path.contains("generated")
                || input.rel_file_path.contains("vendor"),
            is_documented: !docstring.trim().is_empty(),
        }),
        lang_label: Some(LangLabelInput {
            language: input.language.clone(),
            label: input.label.as_str().to_string(),
        }),
        test_topology: None,
        error_surface: Some(ErrorSurfaceInput {
            thrown: property_strings(properties, "throws"),
            raised: property_strings(properties, "raises"),
            caught: property_strings(properties, "catches"),
        }),
        config_env_surface: Some(ConfigEnvSurfaceInput {
            env_keys: property_strings(properties, "env_keys"),
            config_keys: property_strings(properties, "config_keys"),
        }),
        route_surface,
        record_vec: Some(RecordVectorInput {
            scalars: record_scalars,
        }),
    }
}

fn property_string<'a>(properties: &'a Value, key: &str) -> Option<&'a str> {
    properties.get(key).and_then(Value::as_str)
}

fn property_strings(properties: &Value, key: &str) -> Vec<String> {
    properties
        .get(key)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn numeric_property(properties: &Value, key: &str) -> Option<f32> {
    properties
        .get(key)
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite())
        .map(|value| value as f32)
}

fn bool_property(properties: &Value, key: &str) -> bool {
    properties
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn text_tokens(text: &str) -> Vec<String> {
    text.split(|character: char| !character.is_alphanumeric() && character != '_')
        .filter(|part| !part.is_empty())
        .flat_map(astrolabe_panel::cbm_camel_split_tokens)
        .collect()
}

fn parse_ast_profile(encoded: &str) -> Option<astrolabe_panel::AstProfile> {
    let values = encoded
        .split(',')
        .map(str::parse::<f32>)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    if values.len() != 25 || values.iter().any(|value| !value.is_finite()) {
        return None;
    }
    Some(astrolabe_panel::AstProfile {
        if_count: values[0],
        for_count: values[1],
        while_count: values[2],
        switch_count: values[3],
        try_count: values[4],
        return_count: values[5],
        max_nesting_depth: values[6],
        avg_nesting_depth_x10: values[7],
        comparison_ops: values[8],
        arithmetic_ops: values[9],
        logical_ops: values[10],
        assignment_count: values[11],
        string_literals: values[12],
        number_literals: values[13],
        bool_literals: values[14],
        param_count: values[15],
        params_in_returns: values[16],
        params_in_conditions: values[17],
        variable_reassigns: values[18],
        unique_operators: values[19],
        unique_operands: values[20],
        total_operators: values[21],
        total_operands: values[22],
        body_lines: values[23],
        body_tokens: values[24],
    })
}

/// Parse libcbm's serialized struct-trigram list (panel S1 encoder source, the
/// `st` node property emitted by pass_definitions.c) into panel trigrams. Each
/// non-empty line is `a\tb\tc\tweight`; a line that is not exactly four
/// tab-separated fields, or whose weight is not a finite number, is skipped
/// rather than fabricated. Returns `None` when no valid trigram survives so the
/// slot stays honestly unmeasured (never an empty encoded vector).
fn parse_struct_trigrams(encoded: &str) -> Option<Vec<astrolabe_panel::StructuralTrigram>> {
    let trigrams: Vec<astrolabe_panel::StructuralTrigram> = encoded
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| {
            let mut fields = line.split('\t');
            let a = fields.next()?;
            let b = fields.next()?;
            let c = fields.next()?;
            let weight = fields.next()?.trim().parse::<f32>().ok()?;
            if fields.next().is_some() || !weight.is_finite() {
                return None;
            }
            Some(astrolabe_panel::StructuralTrigram {
                a: a.to_string(),
                b: b.to_string(),
                c: c.to_string(),
                weight,
            })
        })
        .collect();
    (!trigrams.is_empty()).then_some(trigrams)
}

/// Parse libcbm's serialized api-callee list (panel S4 encoder source, the
/// `callees` node property) into panel [`astrolabe_panel::ApiCall`]s. Each
/// non-empty line is `name\tcount`; the callees are index-time attributed by
/// enclosing function, so they are marked unresolved to match the guard
/// per-snippet reparse instrument (which sees no cross-file resolution).
/// Returns `None` when no valid callee survives.
fn parse_api_callees(encoded: &str) -> Option<Vec<astrolabe_panel::ApiCall>> {
    let calls: Vec<astrolabe_panel::ApiCall> = encoded
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| {
            let mut fields = line.split('\t');
            let callee = fields.next()?.trim();
            let count = fields.next()?.trim().parse::<f32>().ok()?;
            if callee.is_empty() || fields.next().is_some() || !count.is_finite() || count < 0.0 {
                return None;
            }
            Some(astrolabe_panel::ApiCall {
                callee: callee.to_string(),
                call_count: count,
                resolved: false,
            })
        })
        .collect();
    (!calls.is_empty()).then_some(calls)
}

/// Panel roster version the shadow import pipeline measures and persists.
///
/// v2 (S0–S23) rather than v1 (S0–S22): the v1 roster never measured the S23
/// `layer_role` slot, so `ColumnFamily::slot_raw(23)` was never written and the
/// #311 directory-role layout frames were permanently starved (`skipped_no_frame`
/// on every real repo — #336). v2 is the honest path per frozen-roster discipline:
/// rosters change only by version bump, so persisting S23 means minting shadow
/// constellations under panel version 2 (their CxIds are v2-derived).
pub(crate) const SHADOW_PANEL_VERSION: u32 = astrolabe_panel::PANEL_V2_VERSION;

/// Slots the shadow import feeds to the panel driver.
///
/// The v2 roster minus S22 (`token_multi`, `SlotShape::Multi` — the CBM shadow
/// substrate carries no token-multi source, so it stays a labeled `LensUnavailable`
/// absence rather than a measured row). S23 (`layer_role`) IS included so the
/// directory-role layout frames can be built (#336). Applicability is still enforced
/// per class by the panel driver, so value/structural atoms carry `NotApplicable` for
/// S23 exactly as the v2 contract prescribes.
pub(crate) fn shadow_available_slots() -> Vec<SlotId> {
    astrolabe_panel::PANEL_V2_SLOTS
        .iter()
        .filter(|slot| slot.slot <= 21 || slot.slot == 23)
        .map(|slot| (*slot).slot_id())
        .collect()
}

/// Fixed permutation seed for the index-time MMD drift null. A declared RNG seed
/// (not a threshold), so the drift null is a pure function of the persisted
/// samples, seed, and config — identical across runs of a byte-identical import.
const SHADOW_DRIFT_SEED: u64 = 0x0DD1_DEAF_1DE7_5EED;

/// Best-effort index-time drift production layered on a completed shadow import
/// (#356): measures per-slot MMD drift of this import against the persisted
/// reference window, persists the recognized `astrolabe.assay_anomalies.v1`
/// payload the live `detect_anomalies` drift kind consumes, ledger-pairs each
/// card into the assay diff-card ledger, and snapshots the current samples as the
/// next import's reference window. Drift is telemetry over an already-verified
/// import, so any failure is a labeled degradation in the returned summary, never
/// a hard import failure. The first import (no reference window) reports every
/// populated slot as a labeled absence and produces no card.
fn index_time_drift_summary<C>(vault: &AsterVault<C>, project: &str, vault_dir: &Path) -> Value
where
    C: Clock,
{
    let config = match astrolabe_assay::DiffConfig::from_defaults() {
        Ok(config) => config,
        Err(error) => {
            return json!({
                "status": "unavailable",
                "reason": format!("drift config unavailable: {error}"),
                "trust": "provisional",
                "provenance": "unavailable",
            });
        }
    };
    let ledger = match astrolabe_assay::DiffLedger::open(vault_dir.join("drift-cards.ndjson")) {
        Ok(ledger) => ledger,
        Err(error) => {
            return json!({
                "status": "unavailable",
                "reason": format!("drift card ledger unavailable: {error}"),
                "trust": "provisional",
                "provenance": "unavailable",
            });
        }
    };
    let cache_key = calyx_assay::AssayCacheKey::scoped(
        SHADOW_PANEL_VERSION,
        format!("drift:{project}"),
        vault.vault_id(),
        calyx_core::AnchorKind::Reward,
    );
    match run_index_time_drift(
        vault,
        project,
        &shadow_available_slots(),
        cache_key,
        format!("shadow-drift:{project}"),
        SHADOW_DRIFT_SEED,
        &config,
        Some(&ledger),
    ) {
        Ok(report) => json!({
            "status": "produced",
            "cards_written": report.cards_written,
            "slots_missing_reference": report.slots_missing_reference,
            "slots_short_history": report.slots_short_history,
            "cards_payload_persisted": report.cards_payload_persisted,
            "reference_persisted": report.reference_persisted,
            "cards_ledgered": report.cards_ledgered,
            "assay_cotenant_rows_skipped": report.assay_cotenant_rows_skipped,
            "trust": "measured",
            "provenance": "index_time_drift",
        }),
        Err(error) => json!({
            "status": "unavailable",
            "reason": format!("drift production failed: {error}"),
            "trust": "provisional",
            "provenance": "unavailable",
        }),
    }
}

/// Fixed RNG seed for the index-time signal-ranking bits null. A declared seed
/// (not a threshold), so each per-axis ranking is a pure function of the persisted
/// slot vectors, the derived structural axes, and the bits config.
const SHADOW_SIGNAL_CARDS_SEED: u64 = 0x5165_A15C_A5D5_EED1;

/// Labeled fail-closed degradation for the index-time signal-card summary — a
/// telemetry surface, so a failure is labeled, never a hard import failure.
fn signal_cards_unavailable(reason: String) -> Value {
    json!({
        "status": "unavailable",
        "reason": reason,
        "trust": "provisional",
        "provenance": "unavailable",
    })
}

/// Best-effort index-time signal-card production (#379), the write counterpart of
/// the `get_architecture` `signal_ranking` aspect (`read_signal_ranking_aspect`),
/// which reads per-axis `assay_card.signals.axis:*` config rows that nothing
/// produced on a real corpus — so the aspect served labeled-`unavailable` forever.
///
/// Derives each symbol's structural axes (`symbol_kind`, `structural_degree`) from
/// the persisted graph and measures every dense slot's bits about each axis
/// ([`astrolabe_weave::measure_index_time_signal_cards`]), then persists one
/// `astrolabe.assay_card.v1` doc per axis to the config store (keyed exactly as
/// `measure_bits` mode=signals and the aspect reader expect) and ledger-pairs each
/// card into an append-only hash-chained [`astrolabe_assay::CardLedger`]. Every
/// persisted doc is proved by an independent readback (invariant 5). Signal
/// production is telemetry over an already-verified import, so any failure is a
/// labeled degradation in the returned summary, never a hard import failure; a
/// corpus with no informative axis is a labeled `absent`, leaving the aspect
/// honestly `unavailable` rather than fabricating a card.
fn index_time_signal_cards_summary<C>(
    cache_dir: &Path,
    vault: &AsterVault<C>,
    project: &str,
    vault_dir: &Path,
) -> Value
where
    C: Clock,
{
    let slots = shadow_available_slots();
    let production = match astrolabe_weave::measure_index_time_signal_cards(
        vault,
        project,
        &slots,
        SHADOW_SIGNAL_CARDS_SEED,
    ) {
        Ok(production) => production,
        Err(error) => {
            return json!({
                "status": "unavailable",
                "reason": format!("signal-card production failed: {error}"),
                "trust": "provisional",
                "provenance": "unavailable",
            });
        }
    };
    if production.cards.is_empty() {
        // Genuinely absent: no informative index-time axis for this corpus. The
        // aspect stays labeled-unavailable — an honest absence, not a faked card.
        return json!({
            "status": "absent",
            "reason": "no informative index-time signal axis for this corpus",
            "symbols_measured": production.symbols_measured,
            "axes_skipped_degenerate": production.axes_skipped_degenerate,
            "slots_skipped_no_dense": production.slots_skipped_no_dense,
            "trust": "provisional",
            "provenance": "index_time_signal_cards",
        });
    }

    let ledger = match astrolabe_assay::CardLedger::open(vault_dir.join("signal-cards.ndjson")) {
        Ok(ledger) => ledger,
        Err(error) => {
            return json!({
                "status": "unavailable",
                "reason": format!("signal card ledger unavailable: {error}"),
                "trust": "provisional",
                "provenance": "unavailable",
            });
        }
    };
    let produced_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut axes = Vec::new();
    let mut cards_persisted = 0usize;
    let mut cards_ledgered = 0usize;
    for card in &production.cards {
        let axis = card.axis.clone();
        // Ledger the card first so the persisted config doc can cite its entry.
        // The fingerprint pairs the entry with the (project, axis, seed) that
        // produced it (a provenance tag; the reproducible-input hash is future work
        // once the aligned observation matrix is captured alongside the card).
        let fingerprint =
            format!("index_time_signal_cards:{project}:{axis}:seed{SHADOW_SIGNAL_CARDS_SEED:#x}");
        let entry = match ledger.append(card, SHADOW_SIGNAL_CARDS_SEED, &fingerprint) {
            Ok(entry) => entry,
            Err(error) => {
                return signal_cards_unavailable(format!(
                    "ledger append for axis {axis:?} failed: {error}"
                ));
            }
        };
        cards_ledgered += 1;

        let card_value = match serde_json::to_value(card) {
            Ok(value) => value,
            Err(error) => {
                return signal_cards_unavailable(format!("encode card for axis {axis:?}: {error}"));
            }
        };
        // A card is Trusted only when no contributing slot was a below-floor
        // provisional posterior estimate.
        let trust = if card.signals.iter().any(|signal| signal.provisional) {
            "provisional"
        } else {
            "trusted"
        };
        let key = measure_bits_card_key(project, "signals", Some(&axis), None);
        let doc = json!({
            "schema": ASSAY_CARD_SCHEMA,
            "mode": "signals",
            "project": project,
            "axis": axis,
            "scope": Value::Null,
            "seq": entry.seq,
            "produced_at": produced_at,
            "freshness": "fresh",
            "freshness_lag": 0,
            "trust": trust,
            "provenance": [
                format!("index_time_signal_cards:{project}"),
                format!("ledger:signal-cards.ndjson#{}", entry.seq),
                format!("axis:{axis}"),
            ],
            "card": card_value,
        });
        let serialized = doc.to_string();
        if let Err(error) = write_config_value(cache_dir, &key, &serialized) {
            return signal_cards_unavailable(format!(
                "persist card for axis {axis:?} failed: {error}"
            ));
        }
        // FSV: read the row back through a fresh connection and confirm the
        // persisted bytes parse to exactly the document written (invariant 5).
        match read_config_value(cache_dir, &key) {
            Ok(Some(raw)) => match serde_json::from_str::<Value>(&raw) {
                Ok(readback) if readback == doc => {}
                Ok(_) => {
                    return signal_cards_unavailable(format!(
                        "card for axis {axis:?} read back a different value than written"
                    ));
                }
                Err(error) => {
                    return signal_cards_unavailable(format!(
                        "card for axis {axis:?} did not parse after write: {error}"
                    ));
                }
            },
            Ok(None) => {
                return signal_cards_unavailable(format!(
                    "card for axis {axis:?} was not readable back immediately after write"
                ));
            }
            Err(error) => {
                return signal_cards_unavailable(format!(
                    "card for axis {axis:?} readback failed: {error}"
                ));
            }
        }
        cards_persisted += 1;
        axes.push(json!({
            "axis": axis,
            "signal_count": card.signals.len(),
            "trust": trust,
            "ledger_seq": entry.seq,
            "config_key": key,
        }));
    }

    json!({
        "status": "produced",
        "axis_count": production.cards.len(),
        "cards_persisted": cards_persisted,
        "cards_ledgered": cards_ledgered,
        "symbols_measured": production.symbols_measured,
        "axes_skipped_degenerate": production.axes_skipped_degenerate,
        "slots_skipped_no_dense": production.slots_skipped_no_dense,
        "axes": axes,
        "trust": "measured",
        "provenance": "index_time_signal_cards",
    })
}

pub(crate) fn shadow_refresh_status_str(status: ShadowRefreshStatus) -> &'static str {
    match status {
        ShadowRefreshStatus::Current => "current",
        ShadowRefreshStatus::Refreshed => "refreshed",
        ShadowRefreshStatus::Busy => "busy",
        ShadowRefreshStatus::StaleReindexRequired => "stale_reindex_required",
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
    /// mutated out of band since the last shadow import. Both digests were produced by the
    /// same domain ([`SHADOW_WATERMARK_ALGO`]/[`SHADOW_WATERMARK_VERSION`]), so the
    /// inequality is real staleness and not a units mismatch.
    Stale { expected: String, actual: String },
    /// The live git source tree changed out of band since the last shadow import (#347):
    /// its fingerprint differs from the persisted git-source watermark, even though the
    /// derived CBM `<project>.db` fingerprint still matches (a commit/edit never rewrites
    /// the db). This is real staleness sourced from the ground truth (git) rather than the
    /// derived artifact, so it is reconciled exactly like [`ShadowContentVerdict::Stale`]
    /// but labeled distinctly so the mismatch is diagnosable as an out-of-band source
    /// change rather than a db drift.
    SourceOutOfBand { expected: String, actual: String },
    /// The persisted watermark's digest domain is not — or cannot be proven to be — the
    /// domain the gate recomputes, so the two digests are incommensurable and comparing
    /// them is meaningless (#223).
    ///
    /// This is deliberately **not** [`ShadowContentVerdict::Stale`]. A wrong-domain
    /// watermark can never equal the recomputed digest, so reporting it as staleness makes
    /// a systematic bug (#221) indistinguishable from ordinary source drift and reads
    /// "permanently stale" forever. It fails closed with a code + remediation instead.
    ///
    /// Covers three fail-closed classes, distinguished by `code`:
    /// [`ASTRO_SHADOW_WATERMARK_DOMAIN_MISMATCH`] (a foreign algo/version tag),
    /// [`ASTRO_SHADOW_WATERMARK_LEGACY_UNTAGGED`] (a pre-#223 bare digest whose domain was
    /// never recorded), and [`ASTRO_SHADOW_WATERMARK_MALFORMED`] (corrupt metadata).
    WatermarkDomainMismatch {
        code: &'static str,
        message: String,
        remediation: &'static str,
        /// The algo/version actually persisted, as recorded by the stored value itself.
        persisted_algo: String,
        persisted_version: String,
        /// The algo/version this gate computes and would compare against.
        expected_algo: &'static str,
        expected_version: &'static str,
    },
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

/// A chain-verify result already computed by the caller for one vault dir, so a
/// single status response does not re-walk the whole ledger per section (#96). It
/// is honored only when the freshness evaluation resolves the same vault dir;
/// any mismatch recomputes (fails closed) instead of trusting a stale result.
#[derive(Debug, Clone, Copy)]
pub(crate) struct KnownChainVerify<'a> {
    pub(crate) vault_dir: &'a Path,
    pub(crate) intact: bool,
}

/// Evaluates shadow-import freshness against the live CBM SQLite by content, not
/// existence (#93): recompute the source fingerprint and compare it to the watermark
/// persisted at import time. Any missing verify-relevant input fails closed.
pub(crate) fn evaluate_shadow_content_freshness(
    cache_dir: &Path,
    project: &str,
) -> Result<ShadowContentVerdict, DynError> {
    evaluate_shadow_content_freshness_with_verify(cache_dir, project, None)
}

/// [`evaluate_shadow_content_freshness`] with an optional caller-shared chain-verify
/// result (#96: one verify per status response instead of one per section).
pub(crate) fn evaluate_shadow_content_freshness_with_verify(
    cache_dir: &Path,
    project: &str,
    known_verify: Option<KnownChainVerify<'_>>,
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

    let Some(persisted_watermark) =
        read_config_value(cache_dir, &metadata_key(project, "vault_fingerprint"))?
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

    // Domain gate (#223), before any comparison: the watermark describes which digest
    // function produced it. Only a value tagged with the domain this gate recomputes is
    // comparable. A foreign tag, a pre-#223 untagged digest, or a corrupt value fails
    // loud with a code + remediation — never as ordinary staleness, which is what made
    // the #221 wrong-domain watermark read "permanently Stale" and drove the
    // provenance-clobbering refresh.
    let expected = match parse_shadow_watermark(&persisted_watermark) {
        ShadowWatermark::Tagged {
            algo,
            version,
            digest,
        } if algo == SHADOW_WATERMARK_ALGO && version == SHADOW_WATERMARK_VERSION => digest,
        ShadowWatermark::Tagged { algo, version, .. } => {
            return Ok(watermark_domain_mismatch_verdict(
                ASTRO_SHADOW_WATERMARK_DOMAIN_MISMATCH,
                format!(
                    "{ASTRO_SHADOW_WATERMARK_DOMAIN_MISMATCH}: the persisted shadow freshness watermark for project {project:?} is tagged {algo}:{version}, but this gate recomputes {SHADOW_WATERMARK_ALGO}:{SHADOW_WATERMARK_VERSION}; the two digests are incommensurable, so no freshness comparison against it is meaningful"
                ),
                SHADOW_WATERMARK_DOMAIN_MISMATCH_REMEDIATION,
                algo,
                version,
            ));
        }
        ShadowWatermark::LegacyUntagged { .. } => {
            return Ok(watermark_domain_mismatch_verdict(
                ASTRO_SHADOW_WATERMARK_LEGACY_UNTAGGED,
                format!(
                    "{ASTRO_SHADOW_WATERMARK_LEGACY_UNTAGGED}: the persisted shadow freshness watermark for project {project:?} is an untagged ({SHADOW_WATERMARK_LEGACY_VERSION}) bare digest that records no digest domain; it may be the {SHADOW_WATERMARK_ALGO} source-file digest or the incommensurable row-sink digest (#221), and nothing in the stored value distinguishes them, so it must not be compared"
                ),
                SHADOW_WATERMARK_LEGACY_UNTAGGED_REMEDIATION,
                SHADOW_WATERMARK_LEGACY_ALGO.to_string(),
                SHADOW_WATERMARK_LEGACY_VERSION.to_string(),
            ));
        }
        ShadowWatermark::Malformed { raw, reason } => {
            return Ok(watermark_domain_mismatch_verdict(
                ASTRO_SHADOW_WATERMARK_MALFORMED,
                format!(
                    "{ASTRO_SHADOW_WATERMARK_MALFORMED}: the persisted shadow freshness watermark for project {project:?} ({raw:?}) does not parse: {reason}"
                ),
                SHADOW_WATERMARK_MALFORMED_REMEDIATION,
                SHADOW_WATERMARK_UNPARSEABLE_ALGO.to_string(),
                SHADOW_WATERMARK_UNPARSEABLE_VERSION.to_string(),
            ));
        }
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
        && match known_verify {
            // #96: reuse the caller's verify result for the same vault dir rather
            // than re-walking the ledger; a dir mismatch recomputes (fails closed).
            Some(known) if known.vault_dir == configured_vault_dir => known.intact,
            _ => astrolabe_ingest::verify_chain_vault_path(&configured_vault_dir)
                .map(|report| report.is_intact())
                .unwrap_or(false),
        };
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

    // Source-of-truth gate (#347): the CBM `<project>.db` only changes when
    // `index_repository` re-runs, so the db-fingerprint content gate below is blind to an
    // out-of-band `git commit`/edit — it would report Fresh while the real source has
    // moved on, and the reconcile path would never engage. When a git-source watermark and
    // repo path were persisted at import time, recompute the live git working-tree
    // fingerprint and compare: any drift is real staleness sourced from the ground truth.
    // This runs BEFORE the db gate so a source change is caught even when the db is
    // byte-identical to the last import.
    // An empty stored value is the explicit "no git-source watermark" sentinel a
    // repo-less recovery import writes to clear a prior repo-aware watermark, so it is
    // treated as absent — never as a present-but-empty fingerprint to compare.
    if let Some(persisted_source_fp) = read_config_value(
        cache_dir,
        &metadata_key(project, GIT_SOURCE_FINGERPRINT_KEY),
    )?
    .filter(|value| !value.trim().is_empty())
    {
        // A watermark with no companion repo path cannot be checked; fall through to the
        // db gate rather than guessing a path (labeled by absence, never a false Fresh
        // claim about git-tracked freshness).
        if let Some(repo_path) =
            read_config_value(cache_dir, &metadata_key(project, GIT_SOURCE_REPO_PATH_KEY))?
                .filter(|value| !value.trim().is_empty())
        {
            match astrolabe_anchors::archaeology::git_source_fingerprint(Path::new(&repo_path)) {
                Ok(live) if live == persisted_source_fp => {
                    // Source unchanged; the db gate below decides Fresh vs db-Stale.
                }
                Ok(live) => {
                    return Ok(ShadowContentVerdict::SourceOutOfBand {
                        expected: persisted_source_fp,
                        actual: live,
                    });
                }
                Err(error) => {
                    return Ok(ShadowContentVerdict::Unverifiable {
                        code: ASTRO_SHADOW_GIT_SOURCE_UNREADABLE,
                        message: format!(
                            "{ASTRO_SHADOW_GIT_SOURCE_UNREADABLE}: the persisted git source path {repo_path:?} for project {project:?} could not be fingerprinted: {error}"
                        ),
                        remediation: SHADOW_GIT_SOURCE_UNREADABLE_REMEDIATION,
                        source_missing: false,
                    });
                }
            }
        }
    }

    // Content gate: recompute the live CBM SQLite fingerprint and compare it to the
    // watermark persisted at import time. Existence of the artifacts above is necessary
    // but never sufficient — only a byte-for-byte fingerprint match proves freshness.
    // Reaching here means the domain gate proved both digests come from the same domain,
    // so an inequality is real staleness rather than a units mismatch (#223).
    let actual = astrolabe_ingest::fingerprint_sqlite_hex(&source_path)?;
    if actual == expected {
        Ok(ShadowContentVerdict::Fresh)
    } else {
        Ok(ShadowContentVerdict::Stale { expected, actual })
    }
}

/// Builds the fail-closed [`ShadowContentVerdict::WatermarkDomainMismatch`] refusal (#223).
fn watermark_domain_mismatch_verdict(
    code: &'static str,
    message: String,
    remediation: &'static str,
    persisted_algo: String,
    persisted_version: String,
) -> ShadowContentVerdict {
    ShadowContentVerdict::WatermarkDomainMismatch {
        code,
        message,
        remediation,
        persisted_algo,
        persisted_version,
        expected_algo: SHADOW_WATERMARK_ALGO,
        expected_version: SHADOW_WATERMARK_VERSION,
    }
}

/// True when any row-sink-derived surface is already persisted for `project` (#222).
///
/// This is the guard that makes the destructive runner-less refresh impossible: it answers
/// "is there last-known-good derived state here that a `row_sink = None` re-import would
/// overwrite with `unavailable`?". See [`SHADOW_DERIVED_SURFACE_KEYS`].
pub(crate) fn has_persisted_derived_surfaces(
    cache_dir: &Path,
    project: &str,
) -> Result<bool, DynError> {
    for key in SHADOW_DERIVED_SURFACE_KEYS {
        if read_config_value(cache_dir, &metadata_key(project, key))?.is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn ensure_shadow_import_current(project: &str) -> Result<ShadowRefreshStatus, DynError> {
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    ensure_shadow_import_current_at(&cache_dir, project)
}

/// [`ensure_shadow_import_current`] against an explicit CBM cache dir.
///
/// `cache_dir` must be the process CBM cache dir (`astrolabe_bridge::cbm_cache_dir`): the
/// recovery-import branch below calls [`import_shadow_vault`], which resolves that dir
/// itself. The parameter exists so the refusal paths — which persist nothing and never
/// reach that branch — are directly testable against an isolated fixture root.
///
/// # Reconciliation policy (#222)
///
/// The refresh this function can run has **no `CbmToolRunner`**, so it must pass
/// `row_sink = None` to [`import_shadow_vault`]. The `None` branch of
/// [`import_shadow_vault_report`] fills every row-sink-derived surface with
/// `*_unavailable_json(..)`, and [`persist_shadow_outcome`] writes those over whatever is
/// stored. Refreshing on top of good surfaces therefore *destroys* them: a caller who made
/// a genuine out-of-band source change and then merely called `index_status` used to find
/// `get_provenance`, `detect_anomalies`, and the security screen all silently downgraded to
/// "unavailable", with no reindex ever requested.
///
/// So the refresh runs **only when there is nothing to destroy** — i.e. when no derived
/// surface has ever been persisted for this project. In every other not-current state it
/// persists nothing and returns [`ShadowRefreshStatus::StaleReindexRequired`], preserving
/// the last-known-good surfaces and pushing the caller to an explicit
/// `index_repository(calyx="shadow")`, which does have a runner and can rebuild them.
///
/// (Threading a `CbmToolRunner` into this path is the eventual true-reconciliation design;
/// it is deliberately out of scope here.)
pub(crate) fn ensure_shadow_import_current_at(
    cache_dir: &Path,
    project: &str,
) -> Result<ShadowRefreshStatus, DynError> {
    match evaluate_shadow_content_freshness(cache_dir, project)? {
        // Live source fingerprint matches the persisted watermark, in the same digest
        // domain: nothing to refresh.
        ShadowContentVerdict::Fresh => return Ok(ShadowRefreshStatus::Current),
        // No CBM source present, so no re-import is possible. This is not a freshness
        // claim — the status summary labels this state unverified/fail-closed; the
        // refresh trigger simply has no source to act on.
        ShadowContentVerdict::Unverifiable {
            source_missing: true,
            ..
        } => return Ok(ShadowRefreshStatus::Current),
        // Genuine staleness (#222), an out-of-band git source change (#347), an unusable
        // watermark domain (#223), or a missing/broken derived artifact while the source
        // is live. All need reconciliation against current source — but only an import
        // that can rebuild the derived surfaces may persist one.
        ShadowContentVerdict::Stale { .. }
        | ShadowContentVerdict::SourceOutOfBand { .. }
        | ShadowContentVerdict::WatermarkDomainMismatch { .. }
        | ShadowContentVerdict::Unverifiable {
            source_missing: false,
            ..
        } => {
            if has_persisted_derived_surfaces(cache_dir, project)? {
                return Ok(ShadowRefreshStatus::StaleReindexRequired);
            }
        }
    }

    // No derived surface has ever been persisted for this project, so the runner-less
    // recovery import has no good state to overwrite: reconcile the vault and lowered
    // artifact from source. The surfaces it writes are honestly labeled "unavailable"
    // with a reason, and a later index_repository run replaces them with real ones.
    let Some(_shadow_import_lock) = try_shadow_import_lock(cache_dir, project)? else {
        return Ok(ShadowRefreshStatus::Busy);
    };
    let search_scale_settings = search_scale_settings_for_import(project, None)?;
    let outcome = import_shadow_vault(project, None, &search_scale_settings)?;
    persist_shadow_outcome(project, &outcome)?;
    Ok(ShadowRefreshStatus::Refreshed)
}

/// #244: metadata key holding the exact calyx-stripped CBM `index_repository` args
/// last used for this project, so a freshness-triggered refresh can replay the CBM
/// pipeline verbatim through a runner and regenerate real row-sink-derived surfaces.
/// A shadow index without a filesystem path in its args (project resolved from the
/// tool result) records nothing here, and reconciliation then falls back to the
/// #222 fail-closed floor rather than guessing a path.
pub(crate) const SHADOW_INDEX_ARGS_KEY: &str = "index_args_json";
pub(crate) const GIT_ARCHAEOLOGY_HEAD_KEY: &str = "git_archaeology_head";

/// Metadata key recording the path convention under which this project's git-archaeology
/// anchors and historical constellations were minted (#418).
pub(crate) const GIT_ARCHAEOLOGY_PATH_CONVENTION_KEY: &str = "git_archaeology_path_convention";
/// Current git-archaeology identity path convention.
///
/// `subtree_relative_v1` (#418): historical constellation identity and anchor attribution
/// use the SAME subtree-relative `rel_file_path` the LIVE shadow import uses, so an
/// unchanged member symbol shares one CxId across live and historical imports. The prior
/// (unversioned, pre-#418) code re-anchored historical member node paths UP to the
/// `corpus_rel/`-prefixed toplevel namespace, deriving CxIds disjoint from the live graph
/// (`historical_constellations_reused` stuck at 0, anchors off-graph). A member vault
/// imported under the old convention still carries those toplevel-namespace anchors; the
/// mode gate below detects the absent/mismatched marker and forces a full re-mine so every
/// anchor is re-derived under this convention (explicit reconciliation, never a silent
/// mixed-convention incremental).
pub(crate) const GIT_ARCHAEOLOGY_PATH_CONVENTION: &str = "subtree_relative_v1";

/// Persists the calyx-stripped `index_repository` args so a later runner-driven
/// refresh can replay them for true reconciliation (#244).
pub(crate) fn persist_shadow_index_args(
    cache_dir: &Path,
    project: &str,
    sanitized_index_args: &str,
) -> Result<(), DynError> {
    write_config_value(
        cache_dir,
        &metadata_key(project, SHADOW_INDEX_ARGS_KEY),
        sanitized_index_args,
    )
}

/// [`ensure_shadow_import_current`] with a `CbmToolRunner`, so genuine staleness is
/// *repaired* instead of merely refused (#244).
///
/// # Reconciliation policy (#244, superseding #222's runner-less deferral)
///
/// [`ensure_shadow_import_current`] has no runner, so it can never rebuild the
/// row-sink-derived surfaces and must fail closed to avoid clobbering them (#222).
/// This path *does* have a runner: on genuine staleness it replays the persisted
/// CBM index args through it, captures the row sink, and re-imports with a real
/// [`RowSinkImportCandidate::Available`] — regenerating provenance, security screen,
/// skill tree, bridges, kernel context, and anomalies from current source and
/// returning [`ShadowRefreshStatus::Refreshed`].
///
/// The #222 guard remains the fail-closed floor. Reconciliation persists a real
/// import **only** when the runner produces an `Available` candidate; if there are
/// no persisted index args to replay, or the runner cannot produce an `Available`
/// candidate (the pipeline errored or captured no rows), it defers to
/// [`ensure_shadow_import_current_at`], which preserves last-known-good surfaces
/// and returns [`ShadowRefreshStatus::StaleReindexRequired`] rather than
/// overwriting them with "unavailable".
pub(crate) fn reconcile_shadow_import_current(
    runner: &CbmToolRunner,
    project: &str,
) -> Result<ShadowRefreshStatus, DynError> {
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    reconcile_shadow_import_current_at(runner, &cache_dir, project)
}

/// [`reconcile_shadow_import_current`] against an explicit CBM cache dir.
///
/// `cache_dir` is used for the freshness evaluation and the persisted index-args
/// lookup; the actual re-import resolves the process cache dir itself (via
/// [`import_shadow_vault`]), exactly as [`ensure_shadow_import_current_at`] does.
pub(crate) fn reconcile_shadow_import_current_at(
    runner: &CbmToolRunner,
    cache_dir: &Path,
    project: &str,
) -> Result<ShadowRefreshStatus, DynError> {
    match evaluate_shadow_content_freshness(cache_dir, project)? {
        // Live source fingerprint matches the persisted watermark: nothing to do.
        ShadowContentVerdict::Fresh => return Ok(ShadowRefreshStatus::Current),
        // No CBM source present, so no re-import is possible; the refresh trigger
        // has nothing to act on. Not a freshness claim.
        ShadowContentVerdict::Unverifiable {
            source_missing: true,
            ..
        } => return Ok(ShadowRefreshStatus::Current),
        // Genuine staleness, an out-of-band git source change (#347), an unusable
        // watermark domain, or a missing/broken derived artifact while the source is
        // live: all need reconciliation.
        ShadowContentVerdict::Stale { .. }
        | ShadowContentVerdict::SourceOutOfBand { .. }
        | ShadowContentVerdict::WatermarkDomainMismatch { .. }
        | ShadowContentVerdict::Unverifiable {
            source_missing: false,
            ..
        } => {}
    }

    // True reconciliation requires the CBM index args to replay. Without them we
    // cannot reconstruct the source path, so we fall back to the #222 fail-closed
    // floor rather than guessing.
    let Some(index_args) =
        read_config_value(cache_dir, &metadata_key(project, SHADOW_INDEX_ARGS_KEY))?
    else {
        return ensure_shadow_import_current_at(cache_dir, project);
    };

    // Replay the CBM pipeline verbatim, OUT OF PROCESS (#405), and rebuild the
    // row-sink-equivalent candidate from the child's persisted `<project>.db`. A
    // hard pass abort during staleness repair is therefore contained in the child
    // and cannot leave a partial vault. The lock is taken only for the
    // import+persist below (like index_repository), never around the pipeline run.
    //
    // Persist a real import ONLY for a genuine Available candidate. A contained
    // crash, a spawn failure, an empty/Unavailable candidate, or any infrastructure
    // error yields no Available candidate, so we fall back to the #222 fail-closed
    // floor — preserving last-known-good surfaces and returning
    // StaleReindexRequired rather than clobbering them with "unavailable".
    let skills = SkillDiscoveryConfig::default();
    let row_sink = match run_shadow_index_pass(runner, &index_args, Some(project), &skills) {
        Ok(ShadowIndexPassOutcome::Completed {
            candidate: available @ RowSinkImportCandidate::Available(_),
            ..
        }) => available,
        _ => return ensure_shadow_import_current_at(cache_dir, project),
    };

    let Some(_shadow_import_lock) = try_shadow_import_lock(cache_dir, project)? else {
        return Ok(ShadowRefreshStatus::Busy);
    };
    let search_scale_settings = search_scale_settings_for_import(project, None)?;
    // Resolve the source repo path from the replayed index args (#347): passing it to
    // the repo-aware import both mines archaeology Since the previous head and refreshes
    // the git-source watermark, so a subsequent freshness check sees the reconciled tree
    // as current instead of permanently out-of-band.
    let repo = repo_path_from_index_args(&index_args);
    let outcome = import_shadow_vault_with_archaeology(
        project,
        Some(row_sink),
        &search_scale_settings,
        repo.as_deref(),
    )?;
    persist_shadow_outcome(project, &outcome)?;
    Ok(ShadowRefreshStatus::Refreshed)
}

/// Extracts the source repo path from persisted CBM `index_repository` args (#347),
/// mirroring `handle_index_repository`'s `repo_path`/`name` resolution. Returns `None`
/// when the args carry no filesystem path (project resolved from the tool result), in
/// which case the reconcile import proceeds without archaeology / git-source refresh.
pub(crate) fn repo_path_from_index_args(index_args: &str) -> Option<PathBuf> {
    let value = serde_json::from_str::<Value>(index_args).ok()?;
    let object = value.as_object()?;
    for key in ["repo_path", "name"] {
        if let Some(path) = object.get(key).and_then(Value::as_str)
            && !path.trim().is_empty()
        {
            return Some(PathBuf::from(path));
        }
    }
    None
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
    // emitted only when the live CBM SQLite fingerprint matches the persisted watermark
    // *in the same digest domain*. Genuine staleness is reported stale_reindex_required
    // (#222 — the read path will not reconcile it, because doing so would clobber the
    // row-sink-derived surfaces); a watermark whose domain is wrong or unprovable is
    // reported as its own coded refusal (#223), never as staleness; any missing
    // verify-relevant input fails closed as unverified. Never fresh/verified from mere
    // artifact existence.
    //
    // Every arm declares `watermark_format` so a consumer can see which self-describing
    // watermark contract this server writes and parses.
    match verdict {
        ShadowContentVerdict::Fresh => json!({
            "status": "current",
            "freshness": "fresh",
            "trust": "verified",
            "verification": "content_fingerprint_match",
            "watermark_format": SHADOW_WATERMARK_FORMAT_REGISTRY_VERSION,
            "remediation": Value::Null,
        }),
        ShadowContentVerdict::Stale { expected, actual } => json!({
            // #222: the read path detected the drift but deliberately did NOT re-import,
            // because the only import it can run would overwrite the provenance, security
            // screen, skill tree, bridges, kernel context, and anomaly surfaces with
            // "unavailable". Those surfaces are preserved as last-known-good and the
            // caller is told, in a machine-readable way, to reindex.
            "status": "stale_reindex_required",
            "freshness": "stale",
            "trust": "provisional",
            "verification": "content_fingerprint_mismatch",
            "watermark_format": SHADOW_WATERMARK_FORMAT_REGISTRY_VERSION,
            "code": ASTRO_SHADOW_STALE_REINDEX_REQUIRED,
            "expected_vault_fingerprint": expected,
            "actual_vault_fingerprint": actual,
            "derived_surfaces": "last_known_good_preserved",
            "remediation": SHADOW_STALE_REMEDIATION,
        }),
        ShadowContentVerdict::SourceOutOfBand { expected, actual } => json!({
            // #347: the git source tree changed out of band (commit/edit). The derived
            // CBM db is unchanged, so a db-only gate would have reported "current"; the
            // source-of-truth gate caught it. Reconciled exactly like db-Stale (surfaces
            // preserved as last-known-good until a runner-driven reindex rebuilds them),
            // but labeled distinctly so it reads as a source change, not db drift.
            "status": "stale_reindex_required",
            "freshness": "stale",
            "trust": "provisional",
            "verification": "source_fingerprint_mismatch",
            "watermark_format": SHADOW_WATERMARK_FORMAT_REGISTRY_VERSION,
            "code": ASTRO_SHADOW_SOURCE_OUT_OF_BAND,
            "expected_source_fingerprint": expected,
            "actual_source_fingerprint": actual,
            "derived_surfaces": "last_known_good_preserved",
            "remediation": SHADOW_SOURCE_OUT_OF_BAND_REMEDIATION,
        }),
        ShadowContentVerdict::WatermarkDomainMismatch {
            code,
            message,
            remediation,
            persisted_algo,
            persisted_version,
            expected_algo,
            expected_version,
        } => json!({
            // #223: NOT "stale". The persisted digest was produced by a different (or
            // unprovable) function than the gate recomputes, so the two are incommensurable
            // and comparing them would be meaningless. Fail loud with the domain on both
            // sides so the mismatch is diagnosable rather than looking like ordinary drift.
            "status": "watermark_domain_mismatch",
            "freshness": "unverifiable",
            "trust": "provisional",
            "verification": "watermark_domain_mismatch",
            "watermark_format": SHADOW_WATERMARK_FORMAT_REGISTRY_VERSION,
            "code": code,
            "message": message,
            "persisted_watermark_algo": persisted_algo,
            "persisted_watermark_version": persisted_version,
            "expected_watermark_algo": expected_algo,
            "expected_watermark_version": expected_version,
            "derived_surfaces": "last_known_good_preserved",
            "remediation": remediation,
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
            "watermark_format": SHADOW_WATERMARK_FORMAT_REGISTRY_VERSION,
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
    import_shadow_vault_with_archaeology(project, row_sink, search_scale_settings, None)
}

pub(crate) fn import_shadow_vault_with_archaeology(
    project: &str,
    row_sink: Option<RowSinkImportCandidate>,
    search_scale_settings: &SearchScaleSettings,
    repo: Option<&Path>,
) -> Result<ShadowImportOutcome, DynError> {
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    import_shadow_vault_with_archaeology_at(
        &cache_dir,
        project,
        row_sink,
        search_scale_settings,
        repo,
    )
}

pub(crate) fn import_shadow_vault_with_archaeology_at(
    cache_dir: &Path,
    project: &str,
    row_sink: Option<RowSinkImportCandidate>,
    search_scale_settings: &SearchScaleSettings,
    repo: Option<&Path>,
) -> Result<ShadowImportOutcome, DynError> {
    fs::create_dir_all(cache_dir)?;
    let sqlite_path = sqlite_path(cache_dir, project);
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

    let vault_dir = vault_dir(cache_dir, project);
    fs::create_dir_all(&vault_dir)?;
    let vault_id = VaultId::from_str(SHADOW_VAULT_ID)?;
    let vault_salt = vault_salt(project);
    let vault = AsterVault::new_durable(
        &vault_dir,
        vault_id,
        vault_salt.as_bytes().to_vec(),
        VaultOptions::default(),
    )?;
    // Gate every git-dependent step on the corpus actually being a git work tree
    // (#406): `dispatch.rs` passes `repo = Some(dir)` for ANY indexed directory, so a
    // non-git corpus would otherwise hit `git_head`'s `rev-parse --verify HEAD` and
    // abort the whole shadow import with ASTRO_ARCHAEOLOGY_GIT_FAILED. Filtering to a
    // real work tree here routes a non-git corpus through the existing graceful `None`
    // arms (synthetic commit, absent source fingerprint, archaeology unavailable) so it
    // completes rc=0 with archaeology honestly labeled unavailable. A genuine git fault
    // *inside* a real repo still fails closed in the mining queries below.
    let git_repo = repo.filter(|r| astrolabe_anchors::archaeology::is_git_work_tree(r));
    let commit = match git_repo {
        Some(repo) => astrolabe_anchors::archaeology::git_head(repo)?,
        None => format!("shadow-import-v1:{project}"),
    };
    // Source-of-truth watermark (#347): fingerprint the live git working tree of the
    // indexed repo now, at import time, so the read-path freshness gate can later detect
    // an out-of-band commit/edit that never touches the derived CBM db. Absent for a
    // recovery import with no repo path — freshness then falls back to the db gate,
    // labeled by the watermark's absence rather than a false git-freshness claim.
    let (git_source_fingerprint, git_source_repo_path) = match git_repo {
        Some(repo) => (
            Some(astrolabe_anchors::archaeology::git_source_fingerprint(
                repo,
            )?),
            Some(repo.to_string_lossy().into_owned()),
        ),
        None => (None, None),
    };
    // Measured host parallelism, not a constant (#23): the corpus-wide import
    // passes (symbol preparation, row encode/reconcile, readback verification)
    // are worker-count-invariant in results, and one worker left the whole
    // delta path serial on many-core hosts.
    let options = SqliteImportOptions::new(project, commit, SHADOW_PANEL_VERSION)
        .with_workers(
            std::thread::available_parallelism()
                .map(std::num::NonZeroUsize::get)
                .unwrap_or(1),
        )
        .with_available_slots(shadow_available_slots())
        .with_series_registry(repo.is_some());
    // A fresh vault carries no `astrolabe:cbm-project:v1` row yet: the first import of a
    // project has no prior constellation to diff, so the before-map is legitimately empty
    // (the delta below is already `None` for an empty map). Only that exact refusal is
    // absorbed; every other read error still fails closed (#335).
    let before_cx_by_qn = match astrolabe_ingest::read_cbm_graph_snapshot(&vault, project) {
        Ok(snapshot) => snapshot
            .nodes
            .into_iter()
            .filter_map(|node| node.cx_id.map(|cx_id| (node.qualified_name, cx_id)))
            .collect::<BTreeMap<_, _>>(),
        Err(err) if err.code() == Some(astrolabe_ingest::ASTRO_MISSING_CBM_PROJECT_ROW) => {
            BTreeMap::new()
        }
        Err(err) => return Err(err.into()),
    };
    // #401 shadow-import phase telemetry: opt-in, labeled, permanent (mirrors the
    // libcbm CBM_PROFILE pattern). Silent unless the operator sets ASTRO_SHADOW_TIMING,
    // so a normal index prints nothing; when set, each corpus-wide phase's wall-clock
    // is emitted to stderr so cold-index throughput can be attributed to a real phase
    // instead of guessed. Low volume (one line per phase per index), never per-row spew.
    let shadow_timing = std::env::var_os("ASTRO_SHADOW_TIMING").is_some();
    let mut _shadow_mark = std::time::Instant::now();
    macro_rules! shadow_phase {
        ($name:expr) => {{
            if shadow_timing {
                eprintln!(
                    "astro.shadow.timing phase={} ms={}",
                    $name,
                    _shadow_mark.elapsed().as_millis()
                );
            }
            _shadow_mark = std::time::Instant::now();
        }};
    }
    let shadow_import =
        import_shadow_vault_report(&sqlite_path, &vault, &ShadowSlotRuntime, &options, row_sink)?;
    let report = shadow_import.report;
    if shadow_timing {
        for (label, ms) in &report.timing_ms.0 {
            eprintln!("astro.shadow.timing phase=import_raw.{label} ms={ms}");
        }
    }
    shadow_phase!("import_raw_total");
    let git_archaeology = match git_repo {
        Some(repo) => {
            let mode = match read_config_value(
                cache_dir,
                &metadata_key(project, GIT_ARCHAEOLOGY_HEAD_KEY),
            )? {
                Some(previous_head) => {
                    // Convention-migration gate (#418): a prior import may have minted
                    // archaeology anchors and historical constellations under the OLD
                    // toplevel-prefixed path convention, whose CxIds are disjoint from the
                    // live subtree-relative graph. An incremental (`Since`) import would
                    // only mine NEW commits, silently leaving that off-graph evidence in
                    // place — a mixed-convention vault. When the persisted convention marker
                    // is absent (pre-#418 import) or does not match the current convention,
                    // force a FULL re-mine so every anchor is re-derived under the unified
                    // subtree-relative convention and attaches on the live graph. This is
                    // explicit reconciliation, not a silent fallback; the resulting
                    // `mode: "full"` is visible in the persisted git_archaeology summary.
                    let persisted_convention = read_config_value(
                        cache_dir,
                        &metadata_key(project, GIT_ARCHAEOLOGY_PATH_CONVENTION_KEY),
                    )?;
                    if persisted_convention.as_deref() == Some(GIT_ARCHAEOLOGY_PATH_CONVENTION) {
                        astrolabe_anchors::archaeology::GitMineMode::Since { previous_head }
                    } else {
                        eprintln!(
                            "astro.archaeology.migration project={project} \
                             reason=path_convention_changed action=force_full_remine \
                             persisted={persisted_convention:?} current={GIT_ARCHAEOLOGY_PATH_CONVENTION:?}"
                        );
                        astrolabe_anchors::archaeology::GitMineMode::Full
                    }
                }
                None => astrolabe_anchors::archaeology::GitMineMode::Full,
            };
            git_archaeology_summary(&run_git_archaeology(
                repo, project, cache_dir, &vault, mode,
            )?)
        }
        None => json!({
            "status": "unavailable",
            "reason": "repository path is unavailable on this recovery import",
            "trust": "provisional",
            "provenance": "unavailable",
        }),
    };
    shadow_phase!("git_archaeology");
    let import_changed = report.new_cx_ids > 0
        || report.graph_rows_written > 0
        || report.edge_rows_written > 0
        || report.series_mutated_rows > 0;
    // Read the post-import snapshot ONCE and share it with the weave and the
    // invalidation lane below (#23): re-reading the full graph in each phase
    // tripled the largest fixed cost of the delta path at M scale.
    let after_snapshot = astrolabe_ingest::read_cbm_graph_snapshot(&vault, project)?;
    shadow_phase!("after_snapshot_read");
    let after_cx_by_qn = after_snapshot
        .nodes
        .iter()
        .filter_map(|node| node.cx_id.map(|cx_id| (node.qualified_name.clone(), cx_id)))
        .collect::<BTreeMap<_, _>>();
    let new_cx_ids = report
        .new_cx_id_values
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let delta = (!before_cx_by_qn.is_empty()).then(|| WeaveDelta {
        dirty_qualified_names: after_cx_by_qn
            .iter()
            .filter(|(_, cx_id)| new_cx_ids.contains(cx_id))
            .map(|(qualified_name, _)| qualified_name.clone())
            .collect(),
        removed_qualified_names: before_cx_by_qn
            .iter()
            .filter(|(qualified_name, cx_id)| after_cx_by_qn.get(*qualified_name) != Some(*cx_id))
            .map(|(qualified_name, _)| qualified_name.clone())
            .collect(),
        removed_cx_ids: before_cx_by_qn
            .iter()
            .filter(|(qualified_name, cx_id)| after_cx_by_qn.get(*qualified_name) != Some(*cx_id))
            .map(|(_, cx_id)| *cx_id)
            .collect(),
    });
    shadow_phase!("weave_delta_prepare");
    let mut weave = run_live_weave_with_snapshot(
        &vault,
        project,
        import_changed,
        delta.as_ref(),
        Some(&after_snapshot),
    )?;
    shadow_phase!("weave");
    let invalidations = persist_delta_invalidations_with_snapshot(
        &vault,
        project,
        import_changed,
        delta.as_ref(),
        &weave,
        Some(&after_snapshot),
    )?;
    shadow_phase!("invalidations");
    let layout_frames = persist_layout_frames(&vault, project, import_changed)?;
    shadow_phase!("layout_frames");
    let drift = index_time_drift_summary(&vault, project, &vault_dir);
    shadow_phase!("drift");
    // #365 index-time hook (lane F): persist the real KernelArtifact for this
    // project into the vault Kernel CF via build_and_persist_kernel, grounded on
    // the promotion-aware anchor trust map (#352). Single post-import call — placed
    // after the graph import and weave (so S18 vectors and the composite kernel
    // projection are materialized) and before ledger verification (so the artifact
    // write is inside the verified chain). Best-effort: a scope that cannot yet
    // build a kernel is a labeled surface, never an index failure. (Overlaps lane
    // A's shadow_import.rs — keep this to exactly this one call.)
    let kernel_artifact = persist_index_time_kernel_artifact(&vault, project);
    shadow_phase!("kernel_artifact");
    // #379 index-time hook (lane A/w15): produce and persist the per-axis
    // signal-ranking cards the get_architecture signal_ranking aspect reads, so
    // that aspect serves real measured bits instead of labeled-unavailable
    // forever. Single post-import call — placed after the graph import and weave
    // (so slot vectors and the graph snapshot are materialized) and before ledger
    // verification (so the config writes sit alongside a verified chain).
    // Best-effort telemetry: a labeled degradation in the summary, never an index
    // failure. (Shares shadow_import.rs with lane D/E/F index-time hooks — keep
    // this to exactly this one call.)
    let signal_cards = index_time_signal_cards_summary(cache_dir, &vault, project, &vault_dir);
    shadow_phase!("signal_cards");
    // #390 index-time hook (lane E): grounded-label SEED PRODUCER + live
    // propagation. ── EXACT INSERTION POINT ── one post-import call, placed
    // immediately AFTER the kernel artifact persist above (its members are the
    // primary grounded seed source) and before ledger verification (so the seed
    // graph + propagation writes are inside the verified chain). Overlaps lanes
    // A/D on this file — keep this to exactly this one call. It rebuilds the
    // served kernel_context.label_propagation from the independently read-back
    // persisted propagated-label rows so a real corpus (cbm/) serves label data
    // instead of the starved zero_seed_scope.
    let index_time_label_propagation = persist_index_time_label_propagation(&vault, project);
    shadow_phase!("label_propagation");
    let kernel_context = kernel_context_with_persisted_labels(
        shadow_import.kernel_context,
        index_time_label_propagation,
    );
    // #400 index-time hook: the served `kernel_context.scope_summaries` was derived
    // from the CBM row-sink node properties (`kernel_scopes`/`summary_scopes`/
    // `scopes`), which a real corpus like `cbm/` never emits — so it stayed the
    // labeled `unavailable` block and both `get_kernel mode=read` and the
    // `grounding_gaps` architecture aspect refused fail-closed even on a fully
    // indexed corpus. Rebuild scope_summaries from the persisted KernelArtifact
    // members (persisted immediately above), read back independently, so those two
    // surfaces serve grounded scope data. A scope-less corpus (no artifact / no
    // members) keeps the honest `unavailable` refusal.
    let index_time_scope_summaries =
        scope_summaries_from_persisted_kernel_artifact(&vault, project);
    shadow_phase!("scope_summaries");
    let kernel_context =
        kernel_context_with_persisted_scope_summaries(kernel_context, index_time_scope_summaries);
    if let Some(object) = weave.as_object_mut() {
        object.insert("invalidations".to_string(), invalidations);
        object.insert("layout_frames".to_string(), layout_frames);
        object.insert("drift".to_string(), drift);
        object.insert("kernel_artifact".to_string(), kernel_artifact);
        object.insert("signal_cards".to_string(), signal_cards);
    }
    let lowered_sqlite_path = lowered_sqlite_path(cache_dir, project);
    let prior_lower = if delta.is_some() {
        read_persisted_lower_state(cache_dir, project)?
    } else {
        None
    };
    let lower_state = match prior_lower {
        Some(prior) if lowered_sqlite_path.exists() => {
            schedule_lowering_after_convergence(cache_dir, project, import_changed, &weave)?;
            prior
        }
        _ => ShadowLowerState::from(lower_shadow_sqlite(cache_dir, project, &vault)?),
    };
    shadow_phase!("lowering");
    let verify = verify_chain(&vault)?;
    shadow_phase!("verify_chain");
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
        &lower_state.vault_fingerprint_sha256,
        lower_state.manifest_seq,
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
        lowered_artifact_sha256: lower_state.artifact_sha256,
        lowered_vault_fingerprint_sha256: lower_state.vault_fingerprint_sha256,
        lowered_manifest_seq: lower_state.manifest_seq,
        lowered_nodes: lower_state.node_count,
        lowered_edges: lower_state.edge_count,
        lowered_skipped_edges: lower_state.skipped_edges,
        sqlite_nodes: report.sqlite_nodes,
        sqlite_edges: report.sqlite_edges,
        constellation_inputs: report.constellation_inputs,
        structural_only: report.structural_only,
        new_cx_ids: report.new_cx_ids,
        reused_cx_ids: report.reused_cx_ids,
        graph_rows_written: report.graph_rows_written,
        edge_rows_written: report.edge_rows_written,
        series_inputs: report.series_inputs,
        series_mutated_rows: report.series_mutated_rows,
        import_fsv: report.fsv.clone(),
        cx_id_set_sha256: cx_id_set_sha256(&report.cx_ids),
        ledger_seq: vault.latest_seq(),
        ledger_rows_after: verify.ledger_rows,
        verify_chain_status: verify.status,
        vault_import_source: shadow_import.source,
        vault_import_fallback_reason: shadow_import.fallback_reason,
        security_screen: shadow_import.security_screen,
        search_scale,
        skill_tree: shadow_import.skill_tree,
        bridges: shadow_import.bridges,
        kernel_context,
        anomalies: shadow_import.anomalies,
        provenance,
        git_archaeology,
        weave,
        git_source_fingerprint,
        git_source_repo_path,
    })
}

// Self-reading convenience wrapper: production always passes the shared
// post-import snapshot (#23), so only tests exercise this shape. Gated to test
// builds rather than shipped as dead code (invariant 6).

/// [`run_live_weave`] with an optional caller-preloaded graph snapshot (#23).
///
/// A shadow import already reads the full CBM graph snapshot to derive the
/// weave delta; re-reading it here doubled the largest fixed cost of the delta
/// path at M scale. `snapshot` must be the current live graph for `project`
/// (read at a seq with no intervening node/edge mutation); `None` preserves the
/// self-reading behavior.
pub(crate) fn run_live_weave_with_snapshot<C>(
    vault: &AsterVault<C>,
    project: &str,
    import_changed: bool,
    delta: Option<&WeaveDelta>,
    snapshot: Option<&CbmGraphSnapshot>,
) -> Result<Value, DynError>
where
    C: Clock,
{
    if !import_changed {
        return Ok(json!({
            "status": "unchanged",
            "trust": "verified",
            "freshness": "current",
            "provenance": "content-addressed import reported no graph, edge, slot, or series mutation",
            "writes_skipped": true,
        }));
    }

    let t_snapshot = std::time::Instant::now();
    let owned_snapshot = match snapshot {
        Some(_) => None,
        None => Some(astrolabe_ingest::read_cbm_graph_snapshot(vault, project)?),
    };
    let snapshot = snapshot
        .or(owned_snapshot.as_ref())
        .expect("weave snapshot present by construction");
    let ms_snapshot = t_snapshot.elapsed().as_millis() as u64;
    let at_seq = vault.snapshot();
    let t_slot_load = std::time::Instant::now();
    let slots = EagerAgreementKind::ALL
        .into_iter()
        .flat_map(|kind| {
            let (left, right) = kind.slots();
            [left, right]
        })
        .chain([
            SlotId::new(1),
            SlotId::new(4),
            SlotId::new(18),
            SlotId::new(21),
        ])
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    // One range scan per slot CF instead of one MVCC point read per (node, slot):
    // the slot CFs are keyed by CxId, so a full-CF scan yields every row this loop
    // previously fetched individually (~700k point reads at M scale).
    let mut slot_rows_by_slot = BTreeMap::<SlotId, BTreeMap<Vec<u8>, Vec<u8>>>::new();
    for slot in &slots {
        slot_rows_by_slot.insert(
            *slot,
            vault
                .scan_cf_at(at_seq, ColumnFamily::slot(*slot))?
                .into_iter()
                .collect(),
        );
    }
    let live_nodes = snapshot
        .nodes
        .iter()
        .filter(|node| !node.structural)
        .collect::<Vec<_>>();
    // Per-node slot decode is independent, so chunking the node list over
    // measured host parallelism cannot change results (#23); chunk outputs are
    // concatenated in input order and the duplicate check runs sequentially
    // below, exactly as before.
    let workers = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1)
        .min(live_nodes.len())
        .max(1);
    let chunk_size = live_nodes.len().div_ceil(workers);
    struct SlotChunk {
        nodes: Vec<(SimilarityNode, calyx_core::CxId)>,
        absent: usize,
        missing: usize,
    }
    let chunk_results: Vec<Result<SlotChunk, DynError>> = std::thread::scope(|scope| {
        let slots = &slots;
        let slot_rows_by_slot = &slot_rows_by_slot;
        live_nodes
            .chunks(chunk_size.max(1))
            .map(|chunk| {
                scope.spawn(move || -> Result<SlotChunk, DynError> {
                    let mut built = Vec::with_capacity(chunk.len());
                    let mut absent = 0usize;
                    let mut missing = 0usize;
                    for node in chunk {
                        let cx_id = node.cx_id.ok_or_else(|| {
                            format!(
                                "live non-structural graph node {:?} has no CxId",
                                node.qualified_name
                            )
                        })?;
                        let mut similarity_node = SimilarityNode::new(node.qualified_name.clone());
                        for slot in slots {
                            let Some(bytes) = slot_rows_by_slot
                                .get(slot)
                                .and_then(|rows| rows.get(slot_key(cx_id).as_slice()))
                            else {
                                missing += 1;
                                continue;
                            };
                            let vector = calyx_aster::vault::encode::decode_slot_vector(bytes)?;
                            if matches!(vector, SlotVector::Absent { .. }) {
                                absent += 1;
                            }
                            similarity_node.slots.insert(*slot, vector);
                        }
                        built.push((similarity_node, cx_id));
                    }
                    Ok(SlotChunk {
                        nodes: built,
                        absent,
                        missing,
                    })
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .unwrap_or_else(|_| Err("weave slot worker panicked".into()))
            })
            .collect()
    });
    let mut nodes = Vec::with_capacity(live_nodes.len());
    let mut cx_ids = BTreeMap::new();
    let mut absent_slot_rows = 0usize;
    let mut missing_slot_rows = 0usize;
    for chunk in chunk_results {
        let chunk = chunk?;
        absent_slot_rows += chunk.absent;
        missing_slot_rows += chunk.missing;
        for (similarity_node, cx_id) in chunk.nodes {
            if cx_ids
                .insert(similarity_node.qualified_name.clone(), cx_id)
                .is_some()
            {
                return Err(format!(
                    "duplicate live qualified name {:?} while planning weave",
                    similarity_node.qualified_name
                )
                .into());
            }
            nodes.push(similarity_node);
        }
    }
    let ms_slot_load = t_slot_load.elapsed().as_millis() as u64;

    let t_similarity = std::time::Instant::now();
    let mut ms_sim_read_rows = 0u64;
    let mut ms_sim_expand = 0u64;
    let similarity_config = SimilarityPlannerConfig::default();
    let (similarity_plan, similarity_region) = match delta {
        Some(delta) => {
            let t_read_rows = std::time::Instant::now();
            let persisted = read_similarity_edge_rows(vault)?;
            ms_sim_read_rows = t_read_rows.elapsed().as_millis() as u64;
            let mut changed = delta.dirty_qualified_names.clone();
            changed.extend(delta.removed_qualified_names.iter().cloned());
            let t_expand = std::time::Instant::now();
            let region =
                expand_similarity_dirty_region(&nodes, &changed, &persisted, &similarity_config);
            ms_sim_expand = t_expand.elapsed().as_millis() as u64;
            let region_nodes = nodes
                .iter()
                .filter(|node| region.contains(&node.qualified_name))
                .cloned()
                .collect::<Vec<_>>();
            (
                plan_similarity_edges(&region_nodes, &similarity_config)?,
                Some(region),
            )
        }
        None => (plan_similarity_edges(&nodes, &similarity_config)?, None),
    };
    let ms_sim_plan = (t_similarity.elapsed().as_millis() as u64)
        .saturating_sub(ms_sim_read_rows)
        .saturating_sub(ms_sim_expand);
    let vector_skip_count = similarity_plan.skips.vector_skips.len();
    let family_opt_out_count = similarity_plan.skips.family_opt_outs.len();
    let t_sim_persist = std::time::Instant::now();
    let similarity = match (delta, similarity_region.as_ref()) {
        (Some(delta), Some(region)) => persist_similarity_edges_delta(
            vault,
            &similarity_plan,
            region,
            &delta.removed_qualified_names,
            "astrolabe-shadow-weave",
        )?,
        _ => persist_similarity_edges(vault, &similarity_plan, "astrolabe-shadow-weave")?,
    };
    let ms_sim_persist = t_sim_persist.elapsed().as_millis() as u64;
    let ms_similarity = t_similarity.elapsed().as_millis() as u64;
    let t_xterm = std::time::Instant::now();
    // Abundance accounting is derived from the panel roster that was physically
    // persisted for this import, never a compiled-in slot count (#522): the
    // active slot count is the frozen roster of the shadow panel version. A stale
    // or unknown panel version fails closed here rather than overclaiming a
    // different panel's pair yield.
    let active_slot_count = astrolabe_panel::slots_for_version(SHADOW_PANEL_VERSION)?.len();
    let xterm_plan = match delta {
        Some(delta) => {
            plan_eager_cross_terms_for_symbols(&nodes, &delta.dirty_qualified_names, active_slot_count)?
        }
        None => plan_eager_cross_terms(&nodes, active_slot_count)?,
    };
    let xterm = match delta {
        Some(delta) => {
            let dirty_cx_ids = cx_ids
                .iter()
                .filter(|(qualified_name, _)| delta.dirty_qualified_names.contains(*qualified_name))
                .map(|(qualified_name, cx_id)| (qualified_name.clone(), *cx_id))
                .collect::<BTreeMap<_, _>>();
            persist_eager_cross_terms_delta(
                vault,
                &xterm_plan,
                &dirty_cx_ids,
                &delta.removed_cx_ids,
                "astrolabe-shadow-weave",
            )?
        }
        None => persist_eager_cross_terms(vault, &xterm_plan, &cx_ids, "astrolabe-shadow-weave")?,
    };
    let ms_xterm = t_xterm.elapsed().as_millis() as u64;
    let absent_by_kind = xterm
        .absent_by_kind
        .iter()
        .map(|(kind, count)| (kind.wire_name(), *count))
        .collect::<BTreeMap<_, _>>();

    Ok(json!({
        "status": "reconciled",
        "timing_ms": {
            "snapshot_read": ms_snapshot,
            "slot_load": ms_slot_load,
            "similarity": ms_similarity,
            "similarity_read_rows": ms_sim_read_rows,
            "similarity_expand_region": ms_sim_expand,
            "similarity_plan": ms_sim_plan,
            // #433 permanent labeled attribution INSIDE the plan: per-family ANN
            // candidate generation vs exact-cosine rescoring, so the superlinear
            // residue is attributable to a real sub-stage instead of guessed.
            "similarity_plan_internal": similarity_plan
                .timing_ms
                .iter()
                .map(|(label, ms)| (label.clone(), json!(ms)))
                .collect::<serde_json::Map<_, _>>(),
            "similarity_persist": ms_sim_persist,
            "similarity_persist_internal": similarity
                .timing_ms
                .0
                .iter()
                .map(|(label, ms)| ((*label).to_string(), json!(ms)))
                .collect::<serde_json::Map<_, _>>(),
            "xterm": ms_xterm,
        },
        "trust": "verified",
        "freshness": "current",
        "provenance": "AsterVault Graph + persisted Slot CF readback",
        "input": {
            "symbols": nodes.len(),
            "slot_rows_expected": nodes.len().saturating_mul(slots.len()),
            "slot_rows_absent": absent_slot_rows,
            "slot_rows_missing": missing_slot_rows,
        },
        "similarity": {
            "edge_count": similarity.edge_count,
            "rows_written": similarity.rows_written,
            "rows_unchanged": similarity.rows_unchanged,
            "rows_tombstoned": similarity.rows_tombstoned,
            "edge_dump_hash": similarity.edge_dump_hash,
            "vector_skips": vector_skip_count,
            "family_opt_outs": family_opt_out_count,
            "fsv": similarity.fsv.as_ref().map(fsv_ack_envelope),
        },
        "eager_cross_terms": {
            "symbol_count": xterm.symbol_count,
            "rows_written": xterm.rows_written,
            "rows_unchanged": xterm.rows_unchanged,
            "rows_tombstoned": xterm.rows_tombstoned,
            "absent_by_kind": absent_by_kind,
            "xterm_dump_hash": xterm.xterm_dump_hash,
            "fsv": xterm.fsv.as_ref().map(fsv_ack_envelope),
            // #433 neighborhood peer sample-cap disclosure (invariant 3): the
            // applied `weave_neighborhood_sample_cap` and how many (symbol, kind)
            // neighborhood agreements were scored over a seeded peer subsample of
            // the cap instead of every comparable peer. Zero capped evaluations
            // means the plan is byte-identical to the uncapped path.
            "neighborhood_sample_cap": xterm_plan.neighborhood_sample_cap,
            "neighborhood_capped_evaluations": xterm_plan.neighborhood_capped_evaluations,
        },
    }))
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
            // #59 dial flip: the streaming FFI row-sink writer is now the PRIMARY
            // single-parse persistence path for the shadow import. The materialized
            // row-sink snapshot is streamed row-by-row through
            // `import_cbm_row_stream_to_vault` (registry-bounded drain/backpressure
            // window) instead of being handed to the whole-snapshot direct writer.
            // Both paths persist byte-identical CFs (one ledger-paired batch), proven
            // by `astrolabe-ingest`'s raw-CF parity suite and the shadow-level parity
            // test below; routing the primary write through the streaming writer makes
            // the single-parse pipeline the shipped path rather than a capability held
            // behind the dial. The #23 fail-closed error chaining (labeled
            // `sqlite_fallback` recovery only when a real CBM SQLite artifact exists,
            // otherwise the row-sink error is surfaced verbatim) is preserved verbatim.
            let RowSinkSnapshot {
                snapshot: graph_snapshot,
                source_fingerprint_sha256,
                security_screen,
                skill_tree,
                bridges,
                kernel_context,
                anomalies,
                provenance,
            } = *snapshot;
            match import_cbm_row_stream_to_vault(
                source_fingerprint_sha256,
                snapshot_into_row_stream(graph_snapshot),
                &RowSinkStreamParams::from_registry(),
                vault,
                runtime,
                options,
            )
            .map(|stream_report| stream_report.import)
            {
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
                Err(row_sink_error) => {
                    // Fail-closed error chaining (#23): the row-sink direct import is the
                    // primary source of truth. The SQLite fallback is a *recovery* path
                    // that only exists when a real CBM SQLite artifact is present (the
                    // production caller guarantees this — `import_shadow_vault_with_archaeology`
                    // refuses when the sqlite source is missing). If the sqlite path is
                    // intentionally absent, attempting the fallback would open a missing
                    // file and return a misleading "cannot open SQLite" error that *masks*
                    // the real row-sink cause. So skip the fallback entirely and surface the
                    // row-sink error verbatim, fail-closed.
                    if !sqlite_path.exists() {
                        return Err(astrolabe_domain::DomainError::new(
                            ASTRO_SHADOW_ROW_SINK_IMPORT_FAILED,
                            format!(
                                "{ASTRO_SHADOW_ROW_SINK_IMPORT_FAILED}: row-sink direct import failed and no CBM SQLite artifact exists at {} to recover from. Row-sink error: {row_sink_error}",
                                sqlite_path.display()
                            ),
                            SHADOW_ROW_SINK_IMPORT_FAILED_REMEDIATION,
                        )
                        .into());
                    }
                    // A real sqlite artifact is present: attempt recovery. On success this is
                    // a *labeled* degradation (`fallback_reason` carries the row-sink error
                    // verbatim). On failure, chain BOTH errors so neither cause is masked.
                    let reason = format!("row-sink direct import failed: {row_sink_error}");
                    match import_sqlite_to_vault(sqlite_path, vault, runtime, options) {
                        Ok(report) => Ok(ShadowVaultImport {
                            report,
                            source: "sqlite_fallback".to_string(),
                            fallback_reason: Some(reason),
                            security_screen,
                            skill_tree,
                            bridges,
                            kernel_context,
                            anomalies,
                            provenance,
                        }),
                        Err(fallback_error) => Err(astrolabe_domain::DomainError::new(
                            ASTRO_SHADOW_IMPORT_BOTH_FAILED,
                            format!(
                                "{ASTRO_SHADOW_IMPORT_BOTH_FAILED}: row-sink direct import failed AND CBM SQLite fallback import from {} failed. Row-sink error: {row_sink_error}. SQLite fallback error: {fallback_error}",
                                sqlite_path.display()
                            ),
                            SHADOW_IMPORT_BOTH_FAILED_REMEDIATION,
                        )
                        .into()),
                    }
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

// Default-skills convenience wrapper used only by tests; every production caller passes
// explicit skills via *_with_skills below, so this is gated to test builds rather than
// shipped as dead code (invariant 6).

/// Outcome of running the shadow CBM index pass OUT OF PROCESS (#405).
///
/// The pass runs in a supervised worker subprocess (no FFI row sink — a callback
/// cannot cross the process boundary), so a hard abort is contained in the child.
pub(crate) enum ShadowIndexPassOutcome {
    /// The child exited clean. `raw_result` is its `index_repository` response,
    /// `project` the resolved project name, and `candidate` the row-sink-equivalent
    /// import candidate rebuilt from the child's persisted CBM SQLite.
    Completed {
        raw_result: String,
        project: String,
        candidate: RowSinkImportCandidate,
    },
    /// The pass failed closed — a contained hard abort/hang/spawn-failure, or a
    /// graceful libcbm error. `error_result` is the raw `{isError}` tool result;
    /// the vault was never touched (no partial manifests/surfaces).
    Failed { error_result: String },
}

/// Reads the CBM SQLite (`<project>.db`) written by the out-of-process index pass
/// back into the row-sink-equivalent [`CbmPipelineRows`] (#405).
///
/// The SQLite `nodes`/`edges` tables and the in-process row-sink stream are two
/// serializations of the identical in-memory dump arrays (same final ids), so this
/// readback reproduces the row stream the sink would have delivered — see
/// [`astrolabe_ingest::read_cbm_sqlite_pipeline_rows`]. Feeding the result through
/// the same [`row_sink_import_candidate_from_rows_with_skills`] keeps every derived
/// shadow surface byte-identical to the old in-process path.
pub(crate) fn read_shadow_pipeline_rows(
    sqlite_path: &Path,
    project: &str,
) -> Result<CbmPipelineRows, DynError> {
    let rows = astrolabe_ingest::read_cbm_sqlite_pipeline_rows(sqlite_path, project)?;
    Ok(CbmPipelineRows {
        project: rows.project,
        nodes: rows
            .nodes
            .into_iter()
            .map(|node| astrolabe_bridge::CbmPipelineNodeRow {
                id: node.id,
                project: node.project,
                label: node.label,
                name: node.name,
                qualified_name: node.qualified_name,
                file_path: node.file_path,
                start_line: node.start_line,
                end_line: node.end_line,
                properties_json: node.properties_json,
            })
            .collect(),
        edges: rows
            .edges
            .into_iter()
            .map(|edge| astrolabe_bridge::CbmPipelineEdgeRow {
                id: edge.id,
                project: edge.project,
                source_id: edge.source_id,
                target_id: edge.target_id,
                edge_type: edge.edge_type,
                properties_json: edge.properties_json,
                url_path_gen: edge.url_path_gen,
                local_name_gen: edge.local_name_gen,
            })
            .collect(),
    })
}

/// Runs the shadow CBM index pass OUT OF PROCESS via the supervisor and, on a clean
/// child exit, rebuilds the row-sink-equivalent import candidate from the child's
/// persisted CBM SQLite (#405).
///
/// This replaces the in-process FFI row sink for the shadow full-index path: the
/// pipeline runs in a supervised child, so a hard pass abort (segfault/abort-class)
/// is contained there and the vault is never touched until a fully clean pass. On a
/// clean exit the child's `<project>.db` is read back into [`CbmPipelineRows`] and
/// fed through the identical candidate builder, so the derived surfaces match the
/// old path byte-for-byte. Any non-clean pass (contained crash/hang/spawn-failure or
/// a graceful libcbm error) is returned as [`ShadowIndexPassOutcome::Failed`].
pub(crate) fn run_shadow_index_pass(
    runner: &CbmToolRunner,
    sanitized_args: &str,
    project_hint: Option<&str>,
    skills: &SkillDiscoveryConfig,
) -> Result<ShadowIndexPassOutcome, DynError> {
    let raw_result = runner.handle_index_repository_supervised(sanitized_args)?;
    if tool_result_is_error(&raw_result)? {
        return Ok(ShadowIndexPassOutcome::Failed {
            error_result: raw_result,
        });
    }
    let project = project_hint
        .map(ToOwned::to_owned)
        .or_else(|| project_from_tool_result(&raw_result))
        .ok_or("shadow index pass completed without a resolvable project name")?;
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    let sqlite_path = sqlite_path(&cache_dir, &project);
    if !sqlite_path.exists() {
        return Err(format!(
            "shadow index pass completed but its CBM SQLite {} is missing; cannot rebuild the graph row stream",
            sqlite_path.display()
        )
        .into());
    }
    let rows = read_shadow_pipeline_rows(&sqlite_path, &project)?;
    let candidate = row_sink_import_candidate_from_rows_with_skills(rows, skills);
    Ok(ShadowIndexPassOutcome::Completed {
        raw_result,
        project,
        candidate,
    })
}

/// Maps a fail-closed out-of-process index-pass result into a structured MCP tool
/// error (#405).
///
/// A contained hard abort (the supervisor reports `outcome` in
/// crash/hang/killed/exit_nonzero/spawn_failed) is surfaced as
/// [`ASTRO_SHADOW_INDEX_PASS_CRASHED`] with the worker exit code / log tail, and the
/// vault is guaranteed untouched (the pass ran out of process and returned no graph
/// to import). A graceful libcbm error (no crash `outcome`) is returned verbatim,
/// failing closed exactly as before.
pub(crate) fn shadow_index_pass_error_result(error_result: &str) -> Result<String, DynError> {
    let inner = serde_json::from_str::<Value>(error_result)
        .ok()
        .and_then(|value| {
            value
                .get("content")
                .and_then(Value::as_array)
                .and_then(|items| items.first())
                .and_then(|item| item.get("text"))
                .and_then(Value::as_str)
                .and_then(|text| serde_json::from_str::<Value>(text).ok())
        });
    let outcome = inner
        .as_ref()
        .and_then(|value| value.get("outcome"))
        .and_then(Value::as_str);
    let crash_outcome = matches!(
        outcome,
        Some("crash" | "hang" | "killed" | "exit_nonzero" | "spawn_failed")
    );
    if !crash_outcome {
        // Graceful libcbm error — fail closed exactly as today, verbatim.
        return Ok(error_result.to_string());
    }
    let outcome = outcome.unwrap_or("crash");
    let mut structured = json!({
        "code": ASTRO_SHADOW_INDEX_PASS_CRASHED,
        "message": format!(
            "{ASTRO_SHADOW_INDEX_PASS_CRASHED}: the CBM index pass did not complete cleanly (outcome={outcome}) in its isolated worker subprocess; the fault was contained and the shadow vault was left untouched (not partially committed)"
        ),
        "remediation": SHADOW_INDEX_PASS_CRASHED_REMEDIATION,
        "outcome": outcome,
    });
    if let Some(inner) = inner {
        // Carry the worker's own evidence verbatim so the contained failure is
        // attributable from this artifact alone (worker exit code / log tail).
        for (key, dest) in [
            ("worker_exit_code", "worker_exit_code"),
            ("worker_log_tail", "worker_log_tail"),
            ("worker_response_tail", "worker_response_tail"),
            ("repo_path", "repo_path"),
            ("message", "pass_message"),
        ] {
            if let Some(value) = inner.get(key) {
                structured[dest] = value.clone();
            }
        }
    }
    tool_json_error_result(structured)
}

/// Builds the row-sink import candidate, running skill discovery under `skills` — the
/// registry defaults unless the caller supplied a `calyx_skills` override (#198).
pub(crate) fn row_sink_import_candidate_from_rows_with_skills(
    rows: CbmPipelineRows,
    skills: &SkillDiscoveryConfig,
) -> RowSinkImportCandidate {
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
    let skill_tree = skill_tree_from_row_sink_rows_with_config(&rows, skills);
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
        panel_version: Some(SHADOW_PANEL_VERSION),
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

/// Regenerates the lowered SQLite sidecar for a project, opening the writable
/// vault **inside** the `.astrolabe-lowered.lock` critical section (#225 box 3).
///
/// This is the standalone regen entrypoint a debounced post-weave lowering lane
/// (`astrolabe_lower::LowerDebouncer::run_due`) drives: because lowering appends
/// an Admin manifest ledger entry (a durable vault mutation), the writable handle
/// must be opened under the same OS file lock that serializes the artifact write.
/// Two processes both calling this therefore never hold two durable writers at
/// once — the second blocks on the lock, then opens, regenerates, and observes a
/// complete (never torn) artifact.
///
/// Exercised end-to-end by the two-process FSV test
/// `lowered_regen_serializes_across_two_real_processes_under_lock`. The production
/// The production lowering lane drives this entrypoint through
/// `LowerDebouncer::run_due` after a persisted weave mutation.
pub(crate) fn regenerate_lowered_under_lock(
    cache_dir: &Path,
    project: &str,
) -> Result<astrolabe_lower::LoweredSqliteReport, DynError> {
    let vault_dir = read_config_value(cache_dir, &metadata_key(project, "vault_dir"))?
        .map(PathBuf::from)
        .unwrap_or_else(|| vault_dir(cache_dir, project));
    let vault_id = read_config_value(cache_dir, &metadata_key(project, "vault_id"))?
        .unwrap_or_else(|| SHADOW_VAULT_ID.to_string());
    let salt = read_config_value(cache_dir, &metadata_key(project, "vault_salt"))?
        .unwrap_or_else(|| vault_salt(project));
    with_lowered_sqlite_lock(cache_dir, project, || {
        let vault = open_shadow_vault_writable(&vault_dir, &vault_id, &salt, Vec::new())?;
        lower_cbm_sqlite(
            &vault,
            lowered_sqlite_path(cache_dir, project),
            &LowerSqliteOptions::new(project),
        )
        .map_err(Into::into)
    })
}

fn read_persisted_lower_state(
    cache_dir: &Path,
    project: &str,
) -> Result<Option<ShadowLowerState>, DynError> {
    let Some(artifact_sha256) =
        read_config_value(cache_dir, &metadata_key(project, "lowered_artifact_sha256"))?
    else {
        return Ok(None);
    };
    let Some(vault_fingerprint_sha256) = read_config_value(
        cache_dir,
        &metadata_key(project, "lowered_vault_fingerprint_sha256"),
    )?
    else {
        return Ok(None);
    };
    let Some(manifest_seq) = read_lower_config_u64(cache_dir, project, "lowered_manifest_seq")?
    else {
        return Ok(None);
    };
    let Some(node_count) = read_lower_config_usize(cache_dir, project, "lowered_nodes")? else {
        return Ok(None);
    };
    let Some(edge_count) = read_lower_config_usize(cache_dir, project, "lowered_edges")? else {
        return Ok(None);
    };
    let Some(skipped_edges) = read_lower_config_usize(cache_dir, project, "lowered_skipped_edges")?
    else {
        return Ok(None);
    };
    Ok(Some(ShadowLowerState {
        artifact_sha256,
        vault_fingerprint_sha256,
        manifest_seq,
        node_count,
        edge_count,
        skipped_edges,
    }))
}

fn read_lower_config_u64(
    cache_dir: &Path,
    project: &str,
    name: &str,
) -> Result<Option<u64>, DynError> {
    read_config_value(cache_dir, &metadata_key(project, name))?
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|error| format!("invalid persisted {name}: {error}").into())
        })
        .transpose()
}

fn read_lower_config_usize(
    cache_dir: &Path,
    project: &str,
    name: &str,
) -> Result<Option<usize>, DynError> {
    read_config_value(cache_dir, &metadata_key(project, name))?
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|error| format!("invalid persisted {name}: {error}").into())
        })
        .transpose()
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
            "series_inputs": outcome.series_inputs,
            "series_mutated_rows": outcome.series_mutated_rows,
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
        "fsv": outcome.import_fsv.as_ref().map(fsv_ack_envelope),
        "panel_version": SHADOW_PANEL_VERSION,
        "panel_runtime": "cbm_frozen_v1",
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
        "git_archaeology": outcome.git_archaeology.clone(),
        "weave": outcome.weave.clone(),
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
    // Vault CF-selection contract (calyx-aster durable.rs): `None` = open all CFs;
    // `Some(non-empty)` = open only those CFs; `Some(empty)` is rejected fail-closed
    // (a guard against accidental empty selections). A caller that wants a read-only
    // handle over ALL CFs therefore passes an empty list, which must map to `None`,
    // not `Some(empty)` — otherwise the open fails with CALYX_VAULT_OPTIONS_INVALID
    // (the #43 as_of historical-read break). Writable handles never select CFs.
    let selected_cfs = if read_only && !selected_cfs.is_empty() {
        Some(selected_cfs)
    } else {
        None
    };
    let options = VaultOptions {
        read_only,
        restore_ledger_hook: !read_only,
        selected_cfs,
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
    let git_archaeology_json = serde_json::to_string(&outcome.git_archaeology)?;
    let weave_json = serde_json::to_string(&outcome.weave)?;
    let invalidations_json =
        serde_json::to_string(outcome.weave.get("invalidations").unwrap_or(&json!({
            "schema": "astrolabe.delta_invalidation.v1",
            "status": "unavailable",
            "reason": "outcome predates delta invalidation metadata",
        })))?;
    // Atomic multi-key persist: a crash or error mid-write must not leave a torn
    // mix of new and old metadata that a reader would serve as fresh/verified
    // (e.g. a new vault_fingerprint beside a stale kernel_context_json) — #95.
    let tx = conn.transaction()?;
    for (key, value) in [
        ("vault_dir", outcome.vault_dir.display().to_string()),
        ("vault_id", outcome.vault_id.clone()),
        ("vault_salt", outcome.vault_salt.clone()),
        ("sqlite_path", outcome.sqlite_path.display().to_string()),
        // Content-freshness watermark (#93/#221/#223): the SHA-256 of the CBM SQLite
        // *source file* at import time, taken from `content_freshness_watermark_sha256` —
        // NOT from `sqlite_fingerprint_sha256`, which in the row-sink direct import path
        // carries the row-sink content digest and is incommensurable with what the
        // freshness gate recomputes.
        //
        // #223: it is persisted through `format_shadow_watermark`, so the stored value is
        // self-describing (`sqlite-file-sha256:v1:<hex>`) and records which function
        // produced it. `evaluate_shadow_content_freshness` parses the tag before comparing
        // anything: a value from another domain now fails closed with
        // ASTRO_SHADOW_WATERMARK_DOMAIN_MISMATCH instead of silently reading "permanently
        // Stale" — the exact failure mode that let the #221 row-digest bug masquerade as
        // ordinary staleness and drive the provenance-clobbering refresh.
        (
            "vault_fingerprint",
            format_shadow_watermark(&outcome.content_freshness_watermark_sha256),
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
        ("panel_version", SHADOW_PANEL_VERSION.to_string()),
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
        ("git_archaeology_json", git_archaeology_json),
        ("weave_json", weave_json),
        ("invalidations_json", invalidations_json),
    ] {
        tx.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
            params![metadata_key(project, key), value],
        )?;
    }
    if let Some(head) = outcome.git_archaeology.get("head").and_then(Value::as_str) {
        tx.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
            params![metadata_key(project, GIT_ARCHAEOLOGY_HEAD_KEY), head],
        )?;
        // #418: stamp the identity path convention this archaeology pass was minted under,
        // atomically with the head it advances, so the next import's mode gate can force a
        // full re-mine if the convention ever changes again (never a silent mixed-convention
        // incremental). Written only when archaeology actually ran (a real head exists).
        tx.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
            params![
                metadata_key(project, GIT_ARCHAEOLOGY_PATH_CONVENTION_KEY),
                GIT_ARCHAEOLOGY_PATH_CONVENTION
            ],
        )?;
    }
    // #347: persist the git-source watermark + repo path (or clear them when this import
    // had no repo, so a stale watermark from a prior repo-aware import can never linger
    // and drive a false out-of-band verdict). Written inside the same transaction as the
    // rest of the outcome so the watermark and the vault/db it describes commit atomically.
    tx.execute(
        "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
        params![
            metadata_key(project, GIT_SOURCE_FINGERPRINT_KEY),
            outcome.git_source_fingerprint.clone().unwrap_or_default()
        ],
    )?;
    tx.execute(
        "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
        params![
            metadata_key(project, GIT_SOURCE_REPO_PATH_KEY),
            outcome.git_source_repo_path.clone().unwrap_or_default()
        ],
    )?;
    tx.commit()?;
    Ok(())
}
