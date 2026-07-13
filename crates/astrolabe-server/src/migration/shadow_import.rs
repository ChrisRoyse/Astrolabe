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
        // Genuine staleness (#222), an unusable watermark domain (#223), or a
        // missing/broken derived artifact while the source is live. All need
        // reconciliation against current source — but only an import that can rebuild the
        // derived surfaces may persist one.
        ShadowContentVerdict::Stale { .. }
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
        // Genuine staleness, an unusable watermark domain, or a missing/broken
        // derived artifact while the source is live: all need reconciliation.
        ShadowContentVerdict::Stale { .. }
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

    // Replay the CBM pipeline verbatim and capture the row sink, mirroring
    // handle_index_repository's row-sink path. The lock is taken only for the
    // import+persist below (like index_repository), never around the pipeline run.
    let skills = SkillDiscoveryConfig::default();
    let candidate = match runner.handle_index_repository_with_rows(&index_args) {
        Ok(run) => match run.rows {
            Ok(rows) => Some(row_sink_import_candidate_from_rows_with_skills(
                rows, &skills,
            )),
            Err(_) => None,
        },
        Err(_) => None,
    };

    // Persist a real import ONLY for a genuine Available candidate. An absent or
    // Unavailable candidate must not clobber good surfaces with "unavailable" — the
    // #222 floor preserves them and returns StaleReindexRequired instead.
    let row_sink = match candidate {
        Some(available @ RowSinkImportCandidate::Available(_)) => available,
        _ => return ensure_shadow_import_current_at(cache_dir, project),
    };

    let Some(_shadow_import_lock) = try_shadow_import_lock(cache_dir, project)? else {
        return Ok(ShadowRefreshStatus::Busy);
    };
    let search_scale_settings = search_scale_settings_for_import(project, None)?;
    let outcome = import_shadow_vault(project, Some(row_sink), &search_scale_settings)?;
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
    let commit = match repo {
        Some(repo) => astrolabe_anchors::archaeology::git_head(repo)?,
        None => format!("shadow-import-v1:{project}"),
    };
    let options = SqliteImportOptions::new(project, commit, DEFAULT_PANEL_VERSION)
        .with_available_slots(std::iter::empty())
        .with_series_registry(repo.is_some());
    let shadow_import =
        import_shadow_vault_report(&sqlite_path, &vault, &ShadowSlotRuntime, &options, row_sink)?;
    let report = shadow_import.report;
    let git_archaeology = match repo {
        Some(repo) => {
            let mode = match read_config_value(
                &cache_dir,
                &metadata_key(project, GIT_ARCHAEOLOGY_HEAD_KEY),
            )? {
                Some(previous_head) => {
                    astrolabe_anchors::archaeology::GitMineMode::Since { previous_head }
                }
                None => astrolabe_anchors::archaeology::GitMineMode::Full,
            };
            git_archaeology_summary(&run_git_archaeology(
                repo, project, &cache_dir, &vault, mode,
            )?)
        }
        None => json!({
            "status": "unavailable",
            "reason": "repository path is unavailable on this recovery import",
            "trust": "provisional",
            "provenance": "unavailable",
        }),
    };
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
        series_inputs: report.series_inputs,
        series_mutated_rows: report.series_mutated_rows,
        import_fsv: report.fsv.clone(),
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
        git_archaeology,
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

// Default-skills convenience wrapper used only by tests; every production caller passes
// explicit skills via *_with_skills below, so this is gated to test builds rather than
// shipped as dead code (invariant 6).
#[cfg(test)]
pub(crate) fn row_sink_import_candidate_from_rows(rows: CbmPipelineRows) -> RowSinkImportCandidate {
    row_sink_import_candidate_from_rows_with_skills(rows, &SkillDiscoveryConfig::default())
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
/// caller — the debounced post-weave lowering lane driving this on
/// `LowerDebouncer::run_due` — lands with the remaining server weave-production
/// path (#225 Scope), so this seam is `dead_code` in non-test builds until then.
#[allow(dead_code)]
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
        "git_archaeology": outcome.git_archaeology.clone(),
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
    let git_archaeology_json = serde_json::to_string(&outcome.git_archaeology)?;
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
        ("git_archaeology_json", git_archaeology_json),
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
    }
    tx.commit()?;
    Ok(())
}
