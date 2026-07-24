use super::*;
use rusqlite::OpenFlags;
use rusqlite::backup::Backup;
use std::io::{Read, Write};

const PUBLICATION_DIR: &str = ".astrolabe-shadow-publication";
const PUBLICATION_JOURNAL: &str = "transaction.json";

/// Failure-atomic publication context for one shadow-index generation.
///
/// All CBM, Calyx, weave, lower, and kernel work happens below `stage_cache`.
/// The live cache is not mutated until every stage has validated. Publication
/// then installs the three project artifacts with explicit backups and rolls
/// them all back on any pre-commit error. The config transaction is the commit
/// point and includes the dial, replay args, and every derived metadata row.
pub(crate) struct ShadowPublication {
    live_cache: PathBuf,
    project: String,
    project_root: PathBuf,
    transaction_dir: PathBuf,
    stage_cache: PathBuf,
    backup_dir: PathBuf,
}

impl ShadowPublication {
    pub(crate) fn begin(live_cache: &Path, project: &str) -> Result<Self, DynError> {
        fs::create_dir_all(live_cache)?;
        let project_digest = hex_lower(&Sha256::digest(project.as_bytes()));
        let project_root = live_cache.join(PUBLICATION_DIR).join(&project_digest[..32]);
        reconcile_completed_transactions(&project_root)?;
        if project_root.exists() && fs::read_dir(&project_root)?.next().is_some() {
            return Err(format!(
                "ASTRO_SHADOW_PUBLICATION_INCOMPLETE: an unfinished shadow publication exists for project {project:?} under {}; live state is not safe to mutate. Remediation: inspect transaction.json and the backup/stage hashes, restore or finalize that exact transaction, then retry",
                project_root.display()
            )
            .into());
        }

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| format!("ASTRO_SHADOW_PUBLICATION_CLOCK: {error}"))?
            .as_nanos();
        fs::create_dir_all(&project_root)?;
        let transaction_dir = project_root.join(format!("{}-{nonce}", std::process::id()));
        let stage_cache = transaction_dir.join("stage");
        let backup_dir = transaction_dir.join("backup");
        fs::create_dir(&transaction_dir)?;
        let publication = Self {
            live_cache: live_cache.to_path_buf(),
            project: project.to_string(),
            project_root,
            transaction_dir,
            stage_cache,
            backup_dir,
        };
        let initialized = (|| -> Result<(), DynError> {
            fs::create_dir(&publication.stage_cache)?;
            fs::create_dir(&publication.backup_dir)?;
            publication.write_journal("initializing", json!({}))?;
            publication.seed_stage()?;
            let inventory = publication.stage_inventory()?;
            publication.write_journal("staged", inventory)?;
            Ok(())
        })();
        match initialized {
            Ok(()) => Ok(publication),
            Err(error) => Err(publication.abort_error("stage initialization", error)),
        }
    }

    pub(crate) fn stage_cache(&self) -> &Path {
        &self.stage_cache
    }

    pub(crate) fn checkpoint_stage_source(&self) -> Result<(), DynError> {
        checkpoint_sqlite(&sqlite_path(&self.stage_cache, &self.project), "CBM source")
    }

    pub(crate) fn abort(self, phase: &str, error: impl std::fmt::Display) -> DynError {
        self.abort_error(phase, error)
    }

    /// Remove an unpublished staged transaction while preserving an already
    /// validated MCP tool-error envelope for the caller. The originating error
    /// may be returned only after both the abort journal and physical cleanup
    /// succeed; otherwise the cleanup failure becomes authoritative.
    pub(crate) fn abort_preserving_tool_error(
        self,
        phase: &str,
        error_result: &str,
    ) -> Result<(), DynError> {
        self.abort_cleanup(phase, error_result)
    }

    pub(crate) fn publish(
        self,
        mut outcome: ShadowImportOutcome,
        dial: MigrationDial,
        sanitized_index_args: &str,
    ) -> Result<ShadowImportOutcome, DynError> {
        remap_outcome_paths(&mut outcome, &self.stage_cache, &self.live_cache);

        let staged_source = sqlite_path(&self.stage_cache, &self.project);
        let staged_lowered = lowered_sqlite_path(&self.stage_cache, &self.project);
        let staged_vault = vault_dir(&self.stage_cache, &self.project);
        for (kind, path) in [
            ("CBM source", &staged_source),
            ("lowered SQLite", &staged_lowered),
            ("Aster vault", &staged_vault),
        ] {
            if !path.exists() {
                return Err(self.abort_error(
                    "pre-publication validation",
                    format!("required staged {kind} is missing at {}", path.display()),
                ));
            }
        }
        let validation =
            (|| -> Result<(String, String, String, Vec<(String, String)>), DynError> {
                checkpoint_sqlite(&staged_source, "staged CBM source")?;
                checkpoint_sqlite(&staged_lowered, "staged lowered SQLite")?;
                let source_hash = sha256_file_hex(&staged_source)?;
                let lowered_hash = sha256_file_hex(&staged_lowered)?;
                let vault_hash = sha256_tree_hex(&staged_vault)?;
                let config_prefix = format!("{CONFIG_KEY_PREFIX}{}", self.project);
                let metadata_prefix = format!("{config_prefix}.");
                let staged_config_rows = scan_config_prefix(&self.stage_cache, &config_prefix)?
                    .into_iter()
                    .filter(|(key, _)| {
                        key == &dial_key(&self.project) || key.starts_with(&metadata_prefix)
                    })
                    .collect::<Vec<_>>();
                Ok((source_hash, lowered_hash, vault_hash, staged_config_rows))
            })();
        let (source_hash, lowered_hash, vault_hash, staged_config_rows) = match validation {
            Ok(validation) => validation,
            Err(error) => return Err(self.abort_error("staged readback validation", error)),
        };
        if source_hash != outcome.content_freshness_watermark_sha256 {
            return Err(self.abort_error(
                "pre-publication source readback",
                format!(
                    "ASTRO_SHADOW_PUBLICATION_SOURCE_HASH_MISMATCH: staged CBM source hash {source_hash} differs from validated import watermark {}",
                    outcome.content_freshness_watermark_sha256
                ),
            ));
        }
        if lowered_hash != outcome.lowered_artifact_sha256 {
            return Err(self.abort_error(
                "pre-publication lowered readback",
                format!(
                    "ASTRO_SHADOW_PUBLICATION_LOWERED_HASH_MISMATCH: staged lowered hash {lowered_hash} differs from validated outcome {}",
                    outcome.lowered_artifact_sha256
                ),
            ));
        }
        if let Err(error) = self.write_journal(
            "validated",
            json!({
                "source_sha256": source_hash,
                "lowered_sha256": lowered_hash,
                "vault_tree_sha256": vault_hash,
            }),
        ) {
            return Err(self.abort_error("validated journal persist", error));
        }

        let live_source = sqlite_path(&self.live_cache, &self.project);
        let live_lowered = lowered_sqlite_path(&self.live_cache, &self.project);
        let live_vault = vault_dir(&self.live_cache, &self.project);
        let mut installed = Vec::<PathBuf>::new();
        let install_result = (|| -> Result<(), DynError> {
            self.backup_live_artifact(&live_vault, "vault")?;
            self.backup_live_sqlite_family(&live_lowered, "lowered")?;
            self.backup_live_sqlite_family(&live_source, "source")?;

            fs::rename(&staged_vault, &live_vault)?;
            installed.push(live_vault.clone());
            fs::rename(&staged_lowered, &live_lowered)?;
            installed.push(live_lowered.clone());
            fs::rename(&staged_source, &live_source)?;
            installed.push(live_source.clone());
            Ok(())
        })();
        if let Err(error) = install_result {
            let rollback = self.rollback_artifacts(&installed);
            return Err(self.abort_error(
                "artifact installation",
                combine_rollback_error(error, rollback),
            ));
        }
        let installed_readback = (|| -> Result<Value, DynError> {
            let actual_source = sha256_file_hex(&live_source)?;
            let actual_lowered = sha256_file_hex(&live_lowered)?;
            let actual_vault = sha256_tree_hex(&live_vault)?;
            if actual_source != source_hash
                || actual_lowered != lowered_hash
                || actual_vault != vault_hash
            {
                return Err(format!(
                    "ASTRO_SHADOW_PUBLICATION_ARTIFACT_READBACK_MISMATCH: installed hashes source={actual_source}, lowered={actual_lowered}, vault={actual_vault}; expected source={source_hash}, lowered={lowered_hash}, vault={vault_hash}"
                )
                .into());
            }
            Ok(json!({
                "source_sha256": actual_source,
                "lowered_sha256": actual_lowered,
                "vault_tree_sha256": actual_vault,
            }))
        })();
        let installed_readback = match installed_readback {
            Ok(readback) => readback,
            Err(error) => {
                let rollback = self.rollback_artifacts(&installed);
                return Err(self.abort_error(
                    "installed artifact readback",
                    combine_rollback_error(error, rollback),
                ));
            }
        };
        if let Err(error) = self.write_journal("artifacts_installed", installed_readback) {
            let rollback = self.rollback_artifacts(&installed);
            return Err(self.abort_error(
                "artifact installation journal",
                combine_rollback_error(error, rollback),
            ));
        }

        if let Err(error) = persist_shadow_publication_at(
            &self.live_cache,
            &self.project,
            &outcome,
            dial,
            sanitized_index_args,
            &staged_config_rows,
        ) {
            let rollback = self.rollback_artifacts(&installed);
            return Err(self.abort_error("config commit", combine_rollback_error(error, rollback)));
        }

        let config_readback = (|| -> Result<(Option<String>, Option<String>), DynError> {
            Ok((
                read_config_value(
                    &self.live_cache,
                    &metadata_key(&self.project, "sqlite_path"),
                )?,
                read_config_value(
                    &self.live_cache,
                    &metadata_key(&self.project, "vault_fingerprint"),
                )?,
            ))
        })();
        let (persisted_source, persisted_watermark) = match config_readback {
            Ok(readback) => readback,
            Err(error) => {
                let _ = self.write_journal(
                    "committed_readback_failed",
                    json!({"error": error.to_string()}),
                );
                return Err(format!(
                    "ASTRO_SHADOW_PUBLICATION_COMMIT_READBACK: config transaction committed but its independent read failed for project {:?}: {error}; artifacts and transaction evidence remain at {}. Remediation: inspect the config database and exact transaction journal before serving this project",
                    self.project,
                    self.transaction_dir.display()
                )
                .into());
            }
        };
        let expected_watermark =
            format_shadow_watermark(&outcome.content_freshness_watermark_sha256);
        if persisted_source.as_deref() != Some(outcome.sqlite_path.to_string_lossy().as_ref())
            || persisted_watermark.as_deref() != Some(expected_watermark.as_str())
        {
            self.write_journal(
                "committed_readback_failed",
                json!({
                    "persisted_source": persisted_source,
                    "expected_source": outcome.sqlite_path,
                    "persisted_watermark": persisted_watermark,
                    "expected_watermark": expected_watermark,
                }),
            )?;
            return Err(format!(
                "ASTRO_SHADOW_PUBLICATION_COMMIT_READBACK: config transaction committed but independent readback does not match for project {:?}; artifacts and transaction evidence remain at {}. Remediation: inspect the config rows and exact transaction journal before serving this project",
                self.project,
                self.transaction_dir.display()
            )
            .into());
        }

        self.write_journal(
            "complete",
            json!({
                "source_sha256": source_hash,
                "lowered_sha256": lowered_hash,
                "vault_tree_sha256": vault_hash,
                "config_source": persisted_source,
                "config_watermark": persisted_watermark,
            }),
        )?;
        remove_transaction_tree(&self.transaction_dir, &self.project_root)?;
        remove_empty_dir(&self.project_root)?;
        if let Some(parent) = self.project_root.parent() {
            remove_empty_dir(parent)?;
        }
        Ok(outcome)
    }

    fn seed_stage(&self) -> Result<(), DynError> {
        let live_config = self.live_cache.join("_config.db");
        if live_config.exists() {
            sqlite_snapshot(&live_config, &self.stage_cache.join("_config.db"))?;
        }
        let live_source = sqlite_path(&self.live_cache, &self.project);
        let live_lowered = lowered_sqlite_path(&self.live_cache, &self.project);
        let live_vault = vault_dir(&self.live_cache, &self.project);
        with_lowered_sqlite_lock(&self.live_cache, &self.project, || {
            if live_source.exists() {
                sqlite_snapshot(&live_source, &sqlite_path(&self.stage_cache, &self.project))?;
            }

            match (live_lowered.exists(), live_vault.exists()) {
                (false, false) => Ok(()),
                (true, true) => {
                    let staged_lowered = lowered_sqlite_path(&self.stage_cache, &self.project);
                    exact_quiescent_sqlite_snapshot(
                        &live_lowered,
                        &staged_lowered,
                        "lowered SQLite",
                    )?;

                    let staged_vault_dir = vault_dir(&self.stage_cache, &self.project);
                    let salt = vault_salt(&self.project);
                    let vault = AsterVault::new_durable(
                        &live_vault,
                        VaultId::from_str(SHADOW_VAULT_ID)?,
                        salt.clone().into_bytes(),
                        VaultOptions::default(),
                    )?;
                    vault.copy_durable_snapshot_to(&staged_vault_dir)?;
                    drop(vault);

                    let staged_vault = open_shadow_vault_read_only(
                        &staged_vault_dir,
                        SHADOW_VAULT_ID,
                        &salt,
                        Vec::new(),
                    )?;
                    let verification = verify_lowered_artifact(
                        &staged_vault,
                        &staged_lowered,
                        &self.project,
                    )
                    .map_err(|error| {
                        format!(
                            "ASTRO_SHADOW_PUBLICATION_SEED_LOWERED_UNVERIFIED: staged lowered artifact and vault manifest do not verify for project {:?}: {error}. Remediation: do not publish this generation; inspect the live lowered artifact, vault lowering manifest, and ledger chain, then rebuild them from source",
                            self.project
                        )
                    })?;
                    let configured_hash = read_config_value(
                        &self.stage_cache,
                        &metadata_key(&self.project, "lowered_artifact_sha256"),
                    )?
                    .ok_or_else(|| {
                        format!(
                            "ASTRO_SHADOW_PUBLICATION_SEED_LOWERED_HASH_MISSING: live project {:?} has a lowered artifact and vault manifest but no persisted lowered_artifact_sha256. Remediation: do not publish mixed-generation state; rebuild the project from source",
                            self.project
                        )
                    })?;
                    if verification.artifact_sha256 != configured_hash {
                        return Err(format!(
                            "ASTRO_SHADOW_PUBLICATION_SEED_LOWERED_HASH_MISMATCH: exact staged lowered artifact hashes to {} but the staged config commits to {configured_hash} for project {:?}. Remediation: do not publish mixed-generation state; inspect the live config transaction and rebuild the project from source",
                            verification.artifact_sha256, self.project
                        )
                        .into());
                    }
                    Ok(())
                }
                (lowered_present, vault_present) => Err(format!(
                    "ASTRO_SHADOW_PUBLICATION_SEED_INCOMPLETE: project {:?} has asymmetric live derived state (lowered_present={lowered_present}, vault_present={vault_present}). Remediation: do not synthesize or reuse a partial generation; inspect the prior publication transaction and rebuild the project from source",
                    self.project
                )
                .into()),
            }
        })
    }

    fn stage_inventory(&self) -> Result<Value, DynError> {
        Ok(json!({
            "stage_cache": self.stage_cache,
            "source_present": sqlite_path(&self.stage_cache, &self.project).exists(),
            "lowered_present": lowered_sqlite_path(&self.stage_cache, &self.project).exists(),
            "vault_present": vault_dir(&self.stage_cache, &self.project).exists(),
        }))
    }

    fn backup_live_artifact(&self, live: &Path, name: &str) -> Result<(), DynError> {
        if live.exists() {
            fs::rename(live, self.backup_dir.join(name))?;
        }
        Ok(())
    }

    fn backup_live_sqlite_family(&self, live: &Path, name: &str) -> Result<(), DynError> {
        self.backup_live_artifact(live, name)?;
        for suffix in ["-wal", "-shm"] {
            let sidecar = PathBuf::from(format!("{}{suffix}", live.display()));
            if sidecar.exists() {
                fs::rename(&sidecar, self.backup_dir.join(format!("{name}{suffix}")))?;
            }
        }
        Ok(())
    }

    fn rollback_artifacts(&self, installed: &[PathBuf]) -> Result<(), DynError> {
        for live in installed.iter().rev() {
            remove_artifact(live)?;
        }
        for (name, live) in [
            ("vault", vault_dir(&self.live_cache, &self.project)),
            (
                "lowered",
                lowered_sqlite_path(&self.live_cache, &self.project),
            ),
            ("source", sqlite_path(&self.live_cache, &self.project)),
        ] {
            let backup = self.backup_dir.join(name);
            if backup.exists() {
                fs::rename(backup, &live)?;
            }
            for suffix in ["-wal", "-shm"] {
                let backup_sidecar = self.backup_dir.join(format!("{name}{suffix}"));
                if backup_sidecar.exists() {
                    fs::rename(
                        backup_sidecar,
                        PathBuf::from(format!("{}{suffix}", live.display())),
                    )?;
                }
            }
        }
        Ok(())
    }

    fn write_journal(&self, phase: &str, evidence: Value) -> Result<(), DynError> {
        let path = self.transaction_dir.join(PUBLICATION_JOURNAL);
        let temporary = self.transaction_dir.join("transaction.json.pending");
        let bytes = serde_json::to_vec_pretty(&json!({
            "schema": "astrolabe.shadow-publication.v1",
            "project": self.project,
            "phase": phase,
            "live_cache": self.live_cache,
            "stage_cache": self.stage_cache,
            "backup_dir": self.backup_dir,
            "evidence": evidence,
        }))?;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(temporary, path)?;
        Ok(())
    }

    fn abort_cleanup(&self, phase: &str, error: impl std::fmt::Display) -> Result<(), DynError> {
        let journal_error = self.write_journal(
            "aborted",
            json!({"failed_phase": phase, "error": error.to_string()}),
        );
        let cleanup_error = remove_transaction_tree(&self.transaction_dir, &self.project_root);
        let root_cleanup_error = remove_empty_dir(&self.project_root);
        match (journal_error, cleanup_error, root_cleanup_error) {
            (Ok(()), Ok(()), Ok(())) => Ok(()),
            (journal, cleanup, root_cleanup) => Err(format!(
                "ASTRO_SHADOW_PUBLICATION_ABORT_CLEANUP_FAILED: transaction evidence cleanup was incomplete (journal={journal:?}, cleanup={cleanup:?}, root_cleanup={root_cleanup:?}) at {}; originating_error={}; remediation: do not serve or retry this project until the exact transaction tree is inspected and safely reconciled",
                self.transaction_dir.display(),
                error
            )
            .into()),
        }
    }

    fn abort_error(&self, phase: &str, error: impl std::fmt::Display) -> DynError {
        let error = error.to_string();
        if let Err(cleanup_error) = self.abort_cleanup(phase, &error) {
            return cleanup_error;
        }
        format!(
            "ASTRO_SHADOW_PUBLICATION_ABORTED: shadow publication for project {:?} failed during {phase}: {error}. The prior live generation was not committed. Remediation: fix the named phase error and rerun index_repository with calyx=\"shadow\"",
            self.project
        )
        .into()
    }
}

fn sqlite_snapshot(source: &Path, destination: &Path) -> Result<(), DynError> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    let source_path = astrolabe_domain::winpath::sqlite_open_path(source)?;
    let destination_path = astrolabe_domain::winpath::sqlite_open_path(destination)?;
    let source_conn = Connection::open_with_flags(source_path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut destination_conn = Connection::open(destination_path)?;
    let backup = Backup::new(&source_conn, &mut destination_conn)?;
    backup.run_to_completion(256, Duration::from_millis(5), None)?;
    drop(backup);
    let integrity: String =
        destination_conn.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(format!(
            "ASTRO_SHADOW_SQLITE_SNAPSHOT_CORRUPT: backup readback for {} returned integrity_check={integrity:?}; remediation: inspect the source database and storage device before retrying",
            destination.display()
        )
        .into());
    }
    destination_conn.execute_batch("PRAGMA journal_mode=DELETE;")?;
    drop(destination_conn);
    Ok(())
}

/// Copies a quiescent SQLite artifact without changing any byte that its
/// external manifest commits to. The caller must hold the artifact's writer
/// lock for this entire operation.
fn exact_quiescent_sqlite_snapshot(
    source: &Path,
    destination: &Path,
    kind: &str,
) -> Result<(), DynError> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let sidecar = PathBuf::from(format!("{}{suffix}", source.display()));
        if sidecar.exists() {
            return Err(format!(
                "ASTRO_SHADOW_EXACT_SNAPSHOT_SIDECAR: {kind} at {} has live SQLite sidecar {}; exact single-file identity is not safe to copy. Remediation: stop the writer, complete SQLite recovery/checkpointing, and retry only after every sidecar is absent",
                source.display(),
                sidecar.display()
            )
            .into());
        }
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    let source_bytes_before = fs::metadata(source)?.len();
    let source_hash_before = sha256_file_hex(source)?;
    let copied = (|| -> Result<(), DynError> {
        let mut input = OpenOptions::new().read(true).open(source)?;
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(destination)?;
        let copied = std::io::copy(&mut input, &mut output)?;
        output.sync_all()?;
        if copied != source_bytes_before {
            return Err(format!(
                "copied {copied} bytes but the retained source length was {source_bytes_before}"
            )
            .into());
        }
        Ok(())
    })();
    if let Err(error) = copied {
        let cleanup = match fs::remove_file(destination) {
            Ok(()) => "partial destination removed".to_string(),
            Err(remove_error) if remove_error.kind() == std::io::ErrorKind::NotFound => {
                "no partial destination existed".to_string()
            }
            Err(remove_error) => format!("partial destination cleanup failed: {remove_error}"),
        };
        return Err(format!(
            "ASTRO_SHADOW_EXACT_SNAPSHOT_IO: could not copy {kind} from {} to {}: {error}; {cleanup}. Remediation: inspect the named filesystem error and retry only after source stability and destination cleanup are proven",
            source.display(),
            destination.display()
        )
        .into());
    }

    let source_bytes_after = fs::metadata(source)?.len();
    let destination_bytes = fs::metadata(destination)?.len();
    let source_hash_after = sha256_file_hex(source)?;
    let destination_hash = sha256_file_hex(destination)?;
    if source_bytes_before != source_bytes_after
        || source_bytes_before != destination_bytes
        || source_hash_before != source_hash_after
        || source_hash_before != destination_hash
    {
        let cleanup = match fs::remove_file(destination) {
            Ok(()) => "drifted destination removed".to_string(),
            Err(remove_error) => format!("drifted destination cleanup failed: {remove_error}"),
        };
        return Err(format!(
            "ASTRO_SHADOW_EXACT_SNAPSHOT_DRIFT: {kind} changed or copied non-identically (source_bytes_before={source_bytes_before}, source_bytes_after={source_bytes_after}, destination_bytes={destination_bytes}, source_hash_before={source_hash_before}, source_hash_after={source_hash_after}, destination_hash={destination_hash}); {cleanup}. Remediation: identify the writer that bypassed the project lowered lock or the storage fault before retrying"
        )
        .into());
    }

    let destination_path = astrolabe_domain::winpath::sqlite_open_path(destination)?;
    let destination_conn =
        Connection::open_with_flags(destination_path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let integrity: String =
        destination_conn.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(format!(
            "ASTRO_SHADOW_EXACT_SNAPSHOT_CORRUPT: exact {kind} snapshot at {} returned integrity_check={integrity:?}. Remediation: do not publish it; inspect the source artifact and storage device, then rebuild from source",
            destination.display()
        )
        .into());
    }
    Ok(())
}

fn checkpoint_sqlite(path: &Path, kind: &str) -> Result<(), DynError> {
    if !path.exists() {
        return Err(format!(
            "ASTRO_SHADOW_SQLITE_MISSING: {kind} database is missing at {}; remediation: inspect the preceding index/lower phase",
            path.display()
        )
        .into());
    }
    let open_path = astrolabe_domain::winpath::sqlite_open_path(path)?;
    let conn = Connection::open(open_path)?;
    conn.busy_timeout(Duration::from_millis(CONFIG_DB_BUSY_TIMEOUT_MS))?;
    let (busy, _log, _checkpointed): (i64, i64, i64) =
        conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
    if busy != 0 {
        return Err(format!(
            "ASTRO_SHADOW_SQLITE_CHECKPOINT_BUSY: {kind} at {} could not checkpoint because {busy} reader/writer(s) still hold it; remediation: stop the conflicting client and retry",
            path.display()
        )
        .into());
    }
    let integrity: String = conn.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(format!(
            "ASTRO_SHADOW_SQLITE_INTEGRITY: {kind} at {} failed integrity_check with {integrity:?}; remediation: inspect the producing phase and rebuild from source",
            path.display()
        )
        .into());
    }
    Ok(())
}

fn remap_outcome_paths(outcome: &mut ShadowImportOutcome, from: &Path, to: &Path) {
    outcome.sqlite_path = remap_path(&outcome.sqlite_path, from, to);
    outcome.vault_dir = remap_path(&outcome.vault_dir, from, to);
    outcome.lowered_sqlite_path = remap_path(&outcome.lowered_sqlite_path, from, to);
    for value in [
        &mut outcome.security_screen,
        &mut outcome.search_scale,
        &mut outcome.skill_tree,
        &mut outcome.bridges,
        &mut outcome.kernel_context,
        &mut outcome.anomalies,
        &mut outcome.provenance,
        &mut outcome.git_archaeology,
        &mut outcome.weave,
    ] {
        remap_value_paths(value, from, to);
    }
}

fn remap_path(path: &Path, from: &Path, to: &Path) -> PathBuf {
    path.strip_prefix(from)
        .map(|relative| to.join(relative))
        .unwrap_or_else(|_| path.to_path_buf())
}

fn remap_value_paths(value: &mut Value, from: &Path, to: &Path) {
    match value {
        Value::String(text) => {
            let from = from.to_string_lossy();
            if let Some(relative) = text.strip_prefix(from.as_ref()) {
                *text = format!("{}{}", to.display(), relative);
            }
        }
        Value::Array(values) => {
            for value in values {
                remap_value_paths(value, from, to);
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                remap_value_paths(value, from, to);
            }
        }
        _ => {}
    }
}

fn reconcile_completed_transactions(project_root: &Path) -> Result<(), DynError> {
    if !project_root.exists() {
        return Ok(());
    }
    let entries = fs::read_dir(project_root)?.collect::<std::io::Result<Vec<_>>>()?;
    for entry in entries {
        let transaction = entry.path();
        let journal = transaction.join(PUBLICATION_JOURNAL);
        let value: Value = serde_json::from_slice(&fs::read(&journal).map_err(|error| {
            format!(
                "ASTRO_SHADOW_PUBLICATION_JOURNAL_UNREADABLE: read {}: {error}",
                journal.display()
            )
        })?)?;
        if value.get("phase").and_then(Value::as_str) != Some("complete") {
            continue;
        }
        remove_transaction_tree(&transaction, project_root)?;
    }
    remove_empty_dir(project_root)
}

fn remove_transaction_tree(transaction: &Path, project_root: &Path) -> Result<(), DynError> {
    if transaction == project_root || !transaction.starts_with(project_root) {
        return Err(format!(
            "ASTRO_SHADOW_PUBLICATION_CLEANUP_SCOPE: refused recursive cleanup outside exact project transaction root: transaction={} root={}",
            transaction.display(),
            project_root.display()
        )
        .into());
    }
    if transaction.exists() {
        fs::remove_dir_all(transaction)?;
    }
    Ok(())
}

fn remove_empty_dir(path: &Path) -> Result<(), DynError> {
    if path.exists() && fs::read_dir(path)?.next().is_none() {
        fs::remove_dir(path)?;
    }
    Ok(())
}

fn remove_artifact(path: &Path) -> Result<(), DynError> {
    if !path.exists() {
        return Ok(());
    }
    if path.is_dir() {
        fs::remove_dir_all(path)?;
    } else {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn combine_rollback_error(
    primary: impl std::fmt::Display,
    rollback: Result<(), DynError>,
) -> String {
    match rollback {
        Ok(()) => primary.to_string(),
        Err(rollback) => format!(
            "{primary}; ASTRO_SHADOW_PUBLICATION_ROLLBACK_FAILED: {rollback}; remediation: do not serve the project, inspect transaction.json and restore the exact backup artifacts"
        ),
    }
}

fn sha256_file_hex(path: &Path) -> Result<String, DynError> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex_lower(&hasher.finalize()))
}

fn sha256_tree_hex(root: &Path) -> Result<String, DynError> {
    let mut files = Vec::new();
    collect_tree_files(root, root, &mut files)?;
    files.sort();
    let mut hasher = Sha256::new();
    hasher.update(b"astrolabe.shadow-publication.tree.v1\0");
    for relative in files {
        let bytes = relative.to_string_lossy().as_bytes().to_vec();
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
        let path = root.join(&relative);
        let digest = sha256_file_hex(&path)?;
        hasher.update((digest.len() as u64).to_le_bytes());
        hasher.update(digest.as_bytes());
    }
    Ok(hex_lower(&hasher.finalize()))
}

fn collect_tree_files(
    root: &Path,
    directory: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<(), DynError> {
    let mut entries = fs::read_dir(directory)?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            return Err(format!(
                "ASTRO_SHADOW_PUBLICATION_SYMLINK: refused linked vault entry {}",
                path.display()
            )
            .into());
        }
        if kind.is_dir() {
            collect_tree_files(root, &path, files)?;
        } else if kind.is_file() {
            files.push(path.strip_prefix(root)?.to_path_buf());
        } else {
            return Err(format!(
                "ASTRO_SHADOW_PUBLICATION_SPECIAL_FILE: refused special vault entry {}",
                path.display()
            )
            .into());
        }
    }
    Ok(())
}
