use super::*;
use rusqlite::OpenFlags;
use rusqlite::backup::Backup;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;

const PUBLICATION_DIR: &str = ".astrolabe-shadow-publication";
const PUBLICATION_JOURNAL: &str = "transaction.json";
const PUBLICATION_SCHEMA: &str = "astrolabe.shadow-publication.v3";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicationOwner {
    pid: u32,
    process_start_utc_ticks: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileEvidence {
    bytes: u64,
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SqliteFamilyEvidence {
    main: Option<FileEvidence>,
    wal: Option<FileEvidence>,
    shm: Option<FileEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactGenerationEvidence {
    source: SqliteFamilyEvidence,
    lowered: SqliteFamilyEvidence,
    vault_tree_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicationRecoveryManifest {
    prior: ArtifactGenerationEvidence,
    candidate: ArtifactGenerationEvidence,
    prior_config_generation: Option<String>,
    candidate_config_generation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MetadataAcknowledgementRecoveryManifest {
    artifact_generation: ArtifactGenerationEvidence,
    publication_generation: String,
    keys: Vec<String>,
    prior_rows_sha256: String,
    candidate_rows_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicationJournal {
    schema: String,
    project: String,
    phase: String,
    live_cache: PathBuf,
    stage_cache: PathBuf,
    backup_dir: PathBuf,
    generation: String,
    owner: PublicationOwner,
    recovery_manifest: Option<PublicationRecoveryManifest>,
    metadata_acknowledgement: Option<MetadataAcknowledgementRecoveryManifest>,
    evidence: Value,
}

type StagedArtifactValidation = (String, String, String, String, Vec<(String, String)>);
type PublicationConfigReadback = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

#[derive(Debug, Clone)]
struct SeedLowerRepair {
    prior: ShadowLowerState,
    repaired: ShadowLowerState,
}

impl SeedLowerRepair {
    fn evidence_json(&self) -> Value {
        json!({
            "schema": "astrolabe.shadow-seed-lower-repair.v1",
            "reason": astrolabe_lower::ASTRO_LOWER_ARTIFACT_STALE,
            "prior": self.prior.evidence_json(),
            "repaired": self.repaired.evidence_json(),
            "live_generation_mutated": false,
        })
    }
}

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
    generation: String,
    owner: PublicationOwner,
    recovery_manifest: Option<PublicationRecoveryManifest>,
    metadata_acknowledgement: Option<MetadataAcknowledgementRecoveryManifest>,
    seed_lower_repair: Option<SeedLowerRepair>,
}

impl ShadowPublication {
    pub(crate) fn begin(live_cache: &Path, project: &str) -> Result<Self, DynError> {
        fs::create_dir_all(live_cache)?;
        let project_root = publication_project_root(live_cache, project);
        reconcile_shadow_publications_for_project(live_cache, project)?;
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
        let owner_pid = std::process::id();
        let owner_process_start_utc_ticks =
            astrolabe_bridge::process_start_utc_ticks(owner_pid).map_err(|error| {
                format!(
                    "ASTRO_SHADOW_PUBLICATION_OWNER_IDENTITY_UNREADABLE: exact owner creation ticks for pid {owner_pid} could not be read: {error}; remediation: do not create a publication without a durable exact process generation"
                )
            })?;
        let generation = format!("{owner_pid}-{owner_process_start_utc_ticks}-{nonce}");
        fs::create_dir_all(&project_root)?;
        let transaction_dir = project_root.join(&generation);
        let stage_cache = transaction_dir.join("stage");
        let backup_dir = transaction_dir.join("backup");
        fs::create_dir(&transaction_dir)?;
        let mut publication = Self {
            live_cache: live_cache.to_path_buf(),
            project: project.to_string(),
            project_root,
            transaction_dir,
            stage_cache,
            backup_dir,
            generation,
            owner: PublicationOwner {
                pid: owner_pid,
                process_start_utc_ticks: owner_process_start_utc_ticks,
            },
            recovery_manifest: None,
            metadata_acknowledgement: None,
            seed_lower_repair: None,
        };
        let initialized = (|| -> Result<(), DynError> {
            fs::create_dir(&publication.stage_cache)?;
            fs::create_dir(&publication.backup_dir)?;
            publication.write_journal("initializing", json!({}))?;
            publication.seed_lower_repair = publication.seed_stage()?;
            if let Some(repair) = publication.seed_lower_repair.as_ref() {
                eprintln!(
                    "astro.shadow.seed_lower_repair project={} evidence={}",
                    publication.project,
                    repair.evidence_json()
                );
            }
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
        mut self,
        mut outcome: ShadowImportOutcome,
        dial: MigrationDial,
        sanitized_index_args: &str,
        index_admission_identity: &ShadowIndexAdmissionIdentity,
    ) -> Result<ShadowImportOutcome, DynError> {
        let repaired_unchanged_generation =
            self.seed_lower_repair.is_some() && !outcome.publication_required;
        let prior_live_source_sha256 = repaired_unchanged_generation
            .then(|| outcome.content_freshness_watermark_sha256.clone());
        if repaired_unchanged_generation {
            outcome.publication_required = true;
            outcome.metadata_publication_required = false;
            outcome.publication_reason = "seed_lower_repair";
        }
        if !outcome.publication_required {
            return self.discard_unchanged(
                outcome,
                dial,
                sanitized_index_args,
                index_admission_identity,
            );
        }
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
        let validation = (|| -> Result<StagedArtifactValidation, DynError> {
            checkpoint_sqlite(&staged_source, "staged CBM source")?;
            checkpoint_sqlite(&staged_lowered, "staged lowered SQLite")?;
            let source_hash = sha256_file_hex(&staged_source)?;
            let lowered_hash = sha256_file_hex(&staged_lowered)?;
            let vault_hash = sha256_tree_hex(&staged_vault)?;
            let vault = open_shadow_vault_read_only(
                &staged_vault,
                &outcome.vault_id,
                &outcome.vault_salt,
                Vec::new(),
            )?;
            let chain = verify_chain(&vault)?;
            if !chain.is_intact()
                || vault.latest_seq() != outcome.ledger_seq
                || chain.ledger_rows != outcome.ledger_rows_after
            {
                return Err(format!(
                    "ASTRO_SHADOW_PUBLICATION_VAULT_READBACK_MISMATCH: staged vault verification for project {:?} is status={:?}, latest_seq={}, ledger_rows={}; outcome binds latest_seq={}, ledger_rows={}. Remediation: abort this generation and inspect the staged writer that changed the vault after outcome construction",
                    self.project,
                    chain.status,
                    vault.latest_seq(),
                    chain.ledger_rows,
                    outcome.ledger_seq,
                    outcome.ledger_rows_after,
                )
                .into());
            }
            let lowered_verification =
                verify_lowered_artifact(&vault, &staged_lowered, &self.project).map_err(
                    |error| -> DynError {
                        format!(
                            "ASTRO_SHADOW_PUBLICATION_LOWERED_UNVERIFIED: staged lowered artifact does not verify against the exact pre-commit vault generation for project {:?}: {error}. Remediation: abort this generation; regenerate and verify the lower inside the same unpublished stage before retrying",
                            self.project
                        )
                        .into()
                    },
                )?;
            if lowered_verification.artifact_sha256 != lowered_hash {
                return Err(format!(
                    "ASTRO_SHADOW_PUBLICATION_LOWERED_READBACK_MISMATCH: independently verified lower for project {:?} hashes to {}, but the physical pre-commit read hashes to {lowered_hash}. Remediation: abort this generation and inspect the concurrent staged artifact writer",
                    self.project, lowered_verification.artifact_sha256
                )
                .into());
            }
            let config_prefix = format!("{CONFIG_KEY_PREFIX}{}", self.project);
            let metadata_prefix = format!("{config_prefix}.");
            let staged_config_rows = scan_config_prefix(&self.stage_cache, &config_prefix)?
                .into_iter()
                .filter(|(key, _)| {
                    key == &dial_key(&self.project) || key.starts_with(&metadata_prefix)
                })
                .collect::<Vec<_>>();
            Ok((
                source_hash,
                lowered_hash,
                vault_hash,
                lowered_verification.vault_fingerprint_sha256,
                staged_config_rows,
            ))
        })();
        let (source_hash, lowered_hash, vault_hash, lowered_vault_fingerprint, staged_config_rows) =
            match validation {
                Ok(validation) => validation,
                Err(error) => return Err(self.abort_error("staged readback validation", error)),
            };
        // An exact content/Git no-op normally binds the prior live source hash because
        // its staged SQLite container is discarded. A staged lower repair changes that
        // transaction into a real publication: bind it to the exact checkpointed
        // candidate source that will be installed, never to the prior generation.
        if repaired_unchanged_generation {
            eprintln!(
                "astro.shadow.publication_identity project={} generation={} reason={} prior_live_source_sha256={} candidate_source_sha256={}",
                self.project,
                self.generation,
                outcome.publication_reason,
                prior_live_source_sha256.as_deref().unwrap_or("absent"),
                source_hash,
            );
            outcome.content_freshness_watermark_sha256 = source_hash.clone();
        }
        if source_hash != outcome.content_freshness_watermark_sha256 {
            return Err(self.abort_error(
                "pre-publication source readback",
                format!(
                    "ASTRO_SHADOW_PUBLICATION_SOURCE_HASH_MISMATCH: project={:?}, generation={}, publication_reason={}, staged_source_sha256={source_hash}, validated_import_source_sha256={}, prior_live_source_sha256={}; remediation: preserve the staged and live generations, inspect which exact source identity changed, and retry only from one authoritative generation",
                    self.project,
                    self.generation,
                    outcome.publication_reason,
                    outcome.content_freshness_watermark_sha256,
                    prior_live_source_sha256.as_deref().unwrap_or("not-applicable"),
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
        if lowered_vault_fingerprint != outcome.lowered_vault_fingerprint_sha256 {
            return Err(self.abort_error(
                "pre-publication lowered fingerprint readback",
                format!(
                    "ASTRO_SHADOW_PUBLICATION_LOWERED_FINGERPRINT_MISMATCH: staged lower verifies at vault fingerprint {lowered_vault_fingerprint}, but the validated outcome binds {}",
                    outcome.lowered_vault_fingerprint_sha256
                ),
            ));
        }
        let prior_generation = capture_artifact_generation(
            &sqlite_path(&self.live_cache, &self.project),
            &lowered_sqlite_path(&self.live_cache, &self.project),
            &vault_dir(&self.live_cache, &self.project),
        )?;
        let candidate_generation =
            capture_artifact_generation(&staged_source, &staged_lowered, &staged_vault)?;
        let prior_config_generation = read_config_value(
            &self.live_cache,
            &metadata_key(&self.project, SHADOW_PUBLICATION_GENERATION_KEY),
        )?;
        self.recovery_manifest = Some(PublicationRecoveryManifest {
            prior: prior_generation,
            candidate: candidate_generation,
            prior_config_generation,
            candidate_config_generation: self.generation.clone(),
        });
        if let Err(error) = self.write_journal(
            "validated",
            json!({
                "publication_reason": outcome.publication_reason,
                "source_sha256": source_hash,
                "prior_live_source_sha256": prior_live_source_sha256,
                "lowered_sha256": lowered_hash,
                "lowered_vault_fingerprint_sha256": lowered_vault_fingerprint,
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
            index_admission_identity,
            &staged_config_rows,
            &self.generation,
        ) {
            let rollback = self.rollback_artifacts(&installed);
            return Err(self.abort_error("config commit", combine_rollback_error(error, rollback)));
        }

        let config_readback = (|| -> Result<PublicationConfigReadback, DynError> {
            Ok((
                read_config_value(
                    &self.live_cache,
                    &metadata_key(&self.project, "sqlite_path"),
                )?,
                read_config_value(
                    &self.live_cache,
                    &metadata_key(&self.project, "vault_fingerprint"),
                )?,
                read_config_value(
                    &self.live_cache,
                    &metadata_key(&self.project, "symbol_canonical_schema"),
                )?,
                read_config_value(
                    &self.live_cache,
                    &metadata_key(&self.project, SHADOW_PUBLICATION_GENERATION_KEY),
                )?,
                read_config_value(
                    &self.live_cache,
                    &metadata_key(&self.project, SHADOW_INDEX_ADMISSION_IDENTITY_KEY),
                )?,
                read_config_value(
                    &self.live_cache,
                    &metadata_key(
                        &self.project,
                        SHADOW_INDEX_ADMISSION_PUBLICATION_GENERATION_KEY,
                    ),
                )?,
            ))
        })();
        let (
            persisted_source,
            persisted_watermark,
            persisted_symbol_schema,
            persisted_publication_generation,
            persisted_index_admission_identity,
            persisted_index_admission_publication_generation,
        ) = match config_readback {
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
        let expected_index_admission_identity = index_admission_identity.record_json()?;
        if persisted_source.as_deref() != Some(outcome.sqlite_path.to_string_lossy().as_ref())
            || persisted_watermark.as_deref() != Some(expected_watermark.as_str())
            || persisted_symbol_schema.as_deref() != Some(SYMBOL_CANONICAL_TAG)
            || persisted_publication_generation.as_deref() != Some(self.generation.as_str())
            || persisted_index_admission_identity.as_deref()
                != Some(expected_index_admission_identity.as_str())
            || persisted_index_admission_publication_generation.as_deref()
                != Some(self.generation.as_str())
        {
            self.write_journal(
                "committed_readback_failed",
                json!({
                    "persisted_source": persisted_source,
                    "expected_source": outcome.sqlite_path,
                    "persisted_watermark": persisted_watermark,
                    "expected_watermark": expected_watermark,
                    "persisted_symbol_canonical_schema": persisted_symbol_schema,
                    "expected_symbol_canonical_schema": SYMBOL_CANONICAL_TAG,
                    "persisted_publication_generation": persisted_publication_generation,
                    "expected_publication_generation": self.generation,
                    "persisted_index_admission_identity": persisted_index_admission_identity,
                    "expected_index_admission_identity": expected_index_admission_identity,
                    "persisted_index_admission_publication_generation": persisted_index_admission_publication_generation,
                    "expected_index_admission_publication_generation": self.generation,
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
                "publication_reason": outcome.publication_reason,
                "source_sha256": source_hash,
                "lowered_sha256": lowered_hash,
                "vault_tree_sha256": vault_hash,
                "config_source": persisted_source,
                "config_watermark": persisted_watermark,
                "config_symbol_canonical_schema": persisted_symbol_schema,
                "config_publication_generation": persisted_publication_generation,
                "config_index_admission_identity": persisted_index_admission_identity,
                "config_index_admission_publication_generation": persisted_index_admission_publication_generation,
                "seed_lower_repair": self
                    .seed_lower_repair
                    .as_ref()
                    .map(SeedLowerRepair::evidence_json),
            }),
        )?;
        remove_transaction_tree(&self.transaction_dir, &self.project_root)?;
        remove_empty_dir(&self.project_root)?;
        if let Some(parent) = self.project_root.parent() {
            remove_empty_dir(parent)?;
        }
        Ok(outcome)
    }

    fn discard_unchanged(
        self,
        mut outcome: ShadowImportOutcome,
        dial: MigrationDial,
        sanitized_index_args: &str,
        index_admission_identity: &ShadowIndexAdmissionIdentity,
    ) -> Result<ShadowImportOutcome, DynError> {
        let validation = (|| -> Result<(String, String, Vec<(String, String)>), DynError> {
            let freshness = evaluate_shadow_content_freshness(&self.live_cache, &self.project)?;
            if freshness != ShadowContentVerdict::Fresh {
                return Err(format!(
                    "ASTRO_SHADOW_NOOP_LIVE_NOT_FRESH: project {:?} was unchanged in the staged content-addressed import, but the live generation no longer verifies fresh ({freshness:?}); remediation: preserve the live and staged generations, inspect the exact source/lowered/vault/config mismatch, and retry only after repairing the authoritative live state",
                    self.project
                )
                .into());
            }

            let live_source = sqlite_path(&self.live_cache, &self.project);
            let live_lowered = lowered_sqlite_path(&self.live_cache, &self.project);
            let live_vault = vault_dir(&self.live_cache, &self.project);
            for (kind, path) in [
                ("CBM source", &live_source),
                ("lowered SQLite", &live_lowered),
                ("Aster vault", &live_vault),
            ] {
                if !path.exists() {
                    return Err(format!(
                        "ASTRO_SHADOW_NOOP_LIVE_ARTIFACT_MISSING: required live {kind} is absent at {}; remediation: preserve the staged transaction, inspect the prior publication, and rebuild the project from source",
                        path.display()
                    )
                    .into());
                }
            }

            let source_hash = sha256_file_hex(&live_source)?;
            if source_hash != outcome.content_freshness_watermark_sha256 {
                return Err(format!(
                    "ASTRO_SHADOW_NOOP_SOURCE_HASH_MISMATCH: live source hashes to {source_hash}, but the unchanged staged outcome is bound to {}; remediation: preserve both generations, inspect the concurrent source divergence, and retry only from one authoritative source generation",
                    outcome.content_freshness_watermark_sha256
                )
                .into());
            }
            let lowered_hash = sha256_file_hex(&live_lowered)?;
            if lowered_hash != outcome.lowered_artifact_sha256 {
                return Err(format!(
                    "ASTRO_SHADOW_NOOP_LOWERED_HASH_MISMATCH: live lowered artifact hashes to {lowered_hash}, but the unchanged staged outcome is bound to {}; remediation: preserve both generations, inspect the prior publication, and rebuild from source",
                    outcome.lowered_artifact_sha256
                )
                .into());
            }

            let config_prefix = format!("{CONFIG_KEY_PREFIX}{}", self.project);
            let metadata_prefix = format!("{config_prefix}.");
            let project_rows = |cache: &Path| -> Result<Vec<(String, String)>, DynError> {
                Ok(scan_config_prefix(cache, &config_prefix)?
                    .into_iter()
                    .filter(|(key, _)| {
                        key == &dial_key(&self.project) || key.starts_with(&metadata_prefix)
                    })
                    .collect())
            };
            let staged_config_rows = project_rows(&self.stage_cache)?;
            let live_config_rows = project_rows(&self.live_cache)?;
            if live_config_rows != staged_config_rows {
                return Err(format!(
                    "ASTRO_SHADOW_NOOP_CONFIG_DIVERGED: persisted project config changed after the staged generation was seeded (stage_rows={}, live_rows={}, stage_sha256={}, live_sha256={}); remediation: preserve both generations, inspect the concurrent config writer, and retry only after one authoritative project generation is established",
                    staged_config_rows.len(),
                    live_config_rows.len(),
                    hex_lower(&Sha256::digest(serde_json::to_vec(&staged_config_rows)?)),
                    hex_lower(&Sha256::digest(serde_json::to_vec(&live_config_rows)?)),
                )
                .into());
            }

            let vault_id = read_config_value(
                &self.live_cache,
                &metadata_key(&self.project, "vault_id"),
            )?
            .ok_or_else(|| -> DynError {
                format!(
                    "ASTRO_SHADOW_NOOP_VAULT_ID_MISSING: project {:?} has no persisted vault id; remediation: preserve both generations, inspect the prior publication, and rebuild from source",
                    self.project
                )
                .into()
            })?;
            let vault_salt = read_config_value(
                &self.live_cache,
                &metadata_key(&self.project, "vault_salt"),
            )?
            .ok_or_else(|| -> DynError {
                format!(
                    "ASTRO_SHADOW_NOOP_VAULT_SALT_MISSING: project {:?} has no persisted vault salt; remediation: preserve both generations, inspect the prior publication, and rebuild from source",
                    self.project
                )
                .into()
            })?;
            if vault_id != outcome.vault_id || vault_salt != outcome.vault_salt {
                return Err(format!(
                    "ASTRO_SHADOW_NOOP_VAULT_IDENTITY_MISMATCH: live vault identity for project {:?} is id={vault_id:?}, salt_sha256={}; staged identity is id={:?}, salt_sha256={}; remediation: preserve both generations, inspect the mixed config/vault publication, and rebuild from source",
                    self.project,
                    hex_lower(&Sha256::digest(vault_salt.as_bytes())),
                    outcome.vault_id,
                    hex_lower(&Sha256::digest(outcome.vault_salt.as_bytes())),
                )
                .into());
            }
            let vault =
                open_shadow_vault_read_only(&live_vault, &vault_id, &vault_salt, Vec::new())?;
            let verification = verify_chain(&vault)?;
            if !verification.is_intact()
                || vault.latest_seq() != outcome.ledger_seq
                || verification.ledger_rows != outcome.ledger_rows_after
            {
                return Err(format!(
                    "ASTRO_SHADOW_NOOP_VAULT_MISMATCH: live vault verification for project {:?} is status={:?}, latest_seq={}, ledger_rows={}; unchanged staged outcome expected latest_seq={}, ledger_rows={}; remediation: preserve both generations, inspect the exact ledger divergence, and rebuild from source",
                    self.project,
                    verification.status,
                    vault.latest_seq(),
                    verification.ledger_rows,
                    outcome.ledger_seq,
                    outcome.ledger_rows_after
                )
                .into());
            }
            let lowered_verification =
                verify_lowered_artifact(&vault, &live_lowered, &self.project).map_err(
                    |error| -> DynError {
                        format!(
                            "ASTRO_SHADOW_NOOP_LOWERED_UNVERIFIED: live lowered artifact no longer verifies against the exact live vault generation for project {:?}: {error}; remediation: preserve both generations, inspect the artifact/vault divergence, and rebuild from source",
                            self.project
                        )
                        .into()
                    },
                )?;
            if lowered_verification.artifact_sha256 != lowered_hash
                || lowered_verification.vault_fingerprint_sha256
                    != outcome.lowered_vault_fingerprint_sha256
            {
                return Err(format!(
                    "ASTRO_SHADOW_NOOP_LOWERED_IDENTITY_MISMATCH: live lowered verification returned artifact_sha256={}, vault_fingerprint_sha256={}, but the staged generation is bound to artifact_sha256={lowered_hash}, vault_fingerprint_sha256={}; remediation: preserve both generations, inspect the mixed generation, and rebuild from source",
                    lowered_verification.artifact_sha256,
                    lowered_verification.vault_fingerprint_sha256,
                    outcome.lowered_vault_fingerprint_sha256
                )
                .into());
            }
            drop(vault);
            Ok((source_hash, lowered_hash, live_config_rows))
        })();
        let (source_hash, lowered_hash, live_config_rows) = match validation {
            Ok(validation) => validation,
            Err(error) => {
                return Err(self.abort_error("unchanged live-generation validation", error));
            }
        };

        remap_outcome_paths(&mut outcome, &self.stage_cache, &self.live_cache);
        outcome.content_freshness_watermark_sha256 = source_hash.clone();
        outcome.lowered_artifact_sha256 = lowered_hash.clone();
        if outcome.metadata_publication_required {
            return self.acknowledge_unchanged_action_metadata(
                outcome,
                dial,
                sanitized_index_args,
                index_admission_identity,
                live_config_rows,
                source_hash,
                lowered_hash,
            );
        }
        if let Err(error) = self.write_journal(
            "unchanged_validated",
            json!({
                "source_sha256": source_hash,
                "lowered_sha256": lowered_hash,
                "ledger_seq": outcome.ledger_seq,
                "ledger_rows": outcome.ledger_rows_after,
                "live_generation_preserved": true,
                "stage_publication_skipped": true,
            }),
        ) {
            return Err(self.abort_error("unchanged validation journal", error));
        }
        if let Err(error) = remove_transaction_tree(&self.transaction_dir, &self.project_root) {
            return Err(self.abort_error("unchanged transaction cleanup", error));
        }
        if let Err(error) = remove_empty_dir(&self.project_root) {
            return Err(self.abort_error("unchanged project-root cleanup", error));
        }
        if let Some(parent) = self.project_root.parent()
            && let Err(error) = remove_empty_dir(parent)
        {
            return Err(self.abort_error("unchanged publication-root cleanup", error));
        }
        Ok(outcome)
    }

    #[allow(clippy::too_many_arguments)]
    fn acknowledge_unchanged_action_metadata(
        mut self,
        outcome: ShadowImportOutcome,
        dial: MigrationDial,
        sanitized_index_args: &str,
        index_admission_identity: &ShadowIndexAdmissionIdentity,
        live_config_rows: Vec<(String, String)>,
        source_hash: String,
        lowered_hash: String,
    ) -> Result<ShadowImportOutcome, DynError> {
        let publication_generation = read_config_value(
            &self.live_cache,
            &metadata_key(&self.project, SHADOW_PUBLICATION_GENERATION_KEY),
        )?
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            self.abort_error(
                "action metadata generation binding",
                format!(
                    "ASTRO_SHADOW_ACTION_METADATA_GENERATION_MISSING: project {:?} has no artifact publication generation; remediation: preserve the staged transaction and rebuild the project from authoritative source",
                    self.project
                ),
            )
        })?;
        let artifact_generation = capture_artifact_generation(
            &sqlite_path(&self.live_cache, &self.project),
            &lowered_sqlite_path(&self.live_cache, &self.project),
            &vault_dir(&self.live_cache, &self.project),
        )?;
        let candidate_rows = action_metadata_candidate_rows(
            &self.project,
            dial,
            sanitized_index_args,
            index_admission_identity,
            &publication_generation,
            &outcome,
        )?;
        let keys = candidate_rows
            .iter()
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        let prior_rows = select_config_rows(&live_config_rows, &keys);
        if prior_rows.len() != keys.len() {
            return Err(self.abort_error(
                "action metadata prior-row validation",
                format!(
                    "ASTRO_SHADOW_ACTION_METADATA_PRIOR_INCOMPLETE: project {:?} has {} of {} required action metadata rows; remediation: preserve the incomplete generation and rebuild it from authoritative source",
                    self.project,
                    prior_rows.len(),
                    keys.len()
                ),
            ));
        }
        let prior_rows_sha256 = config_rows_sha256(&prior_rows)?;
        let candidate_rows_sha256 = config_rows_sha256(&candidate_rows)?;
        let candidate_project_rows = replace_config_rows(&live_config_rows, &candidate_rows);
        if prior_rows_sha256 == candidate_rows_sha256 {
            return Err(self.abort_error(
                "action metadata change validation",
                format!(
                    "ASTRO_SHADOW_ACTION_METADATA_NOT_CHANGED: project {:?} requested a metadata publication but the exact candidate row set equals the prior set; remediation: inspect action classification and do not publish a false metadata change",
                    self.project
                ),
            ));
        }
        self.metadata_acknowledgement = Some(MetadataAcknowledgementRecoveryManifest {
            artifact_generation: artifact_generation.clone(),
            publication_generation: publication_generation.clone(),
            keys: keys.clone(),
            prior_rows_sha256: prior_rows_sha256.clone(),
            candidate_rows_sha256: candidate_rows_sha256.clone(),
        });
        if let Err(error) = self.write_journal(
            "unchanged_metadata_validated",
            json!({
                "publication_reason": outcome.publication_reason,
                "source_sha256": source_hash,
                "lowered_sha256": lowered_hash,
                "artifact_generation": artifact_generation,
                "publication_generation": publication_generation,
                "prior_rows_sha256": prior_rows_sha256,
                "candidate_rows_sha256": candidate_rows_sha256,
                "metadata_keys": keys,
                "physical_artifacts_preserved": true,
            }),
        ) {
            return Err(self.abort_error("action metadata validation journal", error));
        }

        if let Err(error) = persist_action_metadata_acknowledgement(
            &self.live_cache,
            &self.project,
            &live_config_rows,
            &candidate_project_rows,
            &publication_generation,
            &candidate_rows,
        ) {
            return Err(self.abort_error("action metadata config commit", error));
        }

        let readback = (|| -> Result<Value, DynError> {
            let project_rows = project_config_rows(&self.live_cache, &self.project)?;
            if project_rows != candidate_project_rows {
                return Err(format!(
                    "ASTRO_SHADOW_ACTION_METADATA_PROJECT_READBACK_MISMATCH: project {:?} complete config rows changed outside the acknowledged action metadata set (expected_sha256={}, actual_sha256={}); remediation: preserve the transaction and inspect the concurrent project config writer",
                    self.project,
                    config_rows_sha256(&candidate_project_rows)?,
                    config_rows_sha256(&project_rows)?
                )
                .into());
            }
            let persisted_rows = select_config_rows(&project_rows, &keys);
            if persisted_rows != candidate_rows {
                return Err(format!(
                    "ASTRO_SHADOW_ACTION_METADATA_READBACK_MISMATCH: project {:?} committed candidate row hash {}, but independent readback returned {}; remediation: preserve the transaction and inspect the exact config WAL/database state before serving this project",
                    self.project,
                    candidate_rows_sha256,
                    config_rows_sha256(&persisted_rows)?
                )
                .into());
            }
            let persisted_publication_generation = read_config_value(
                &self.live_cache,
                &metadata_key(&self.project, SHADOW_PUBLICATION_GENERATION_KEY),
            )?;
            if persisted_publication_generation.as_deref() != Some(publication_generation.as_str())
            {
                return Err(format!(
                    "ASTRO_SHADOW_ACTION_METADATA_GENERATION_CHANGED: project {:?} artifact publication generation changed from {:?} to {:?} during metadata acknowledgement; remediation: preserve the transaction and inspect the concurrent config writer",
                    self.project,
                    publication_generation,
                    persisted_publication_generation
                )
                .into());
            }
            let persisted_artifacts = capture_artifact_generation(
                &sqlite_path(&self.live_cache, &self.project),
                &lowered_sqlite_path(&self.live_cache, &self.project),
                &vault_dir(&self.live_cache, &self.project),
            )?;
            if persisted_artifacts != artifact_generation {
                return Err(format!(
                    "ASTRO_SHADOW_ACTION_METADATA_ARTIFACT_CHANGED: project {:?} source/lowered/vault generation changed during metadata-only publication; remediation: preserve the transaction and inspect the concurrent artifact writer",
                    self.project
                )
                .into());
            }
            Ok(json!({
                "publication_reason": outcome.publication_reason,
                "publication_generation": publication_generation,
                "metadata_rows_sha256": candidate_rows_sha256,
                "metadata_keys": keys,
                "artifact_generation": persisted_artifacts,
                "physical_artifacts_preserved": true,
            }))
        })();
        let readback = match readback {
            Ok(readback) => readback,
            Err(error) => {
                let _ = self.write_journal(
                    "unchanged_metadata_committed_readback_failed",
                    json!({"error": error.to_string()}),
                );
                return Err(format!(
                    "ASTRO_SHADOW_ACTION_METADATA_COMMIT_READBACK: metadata transaction committed but independent readback failed for project {:?}: {error}; transaction evidence remains at {}. Remediation: inspect and reconcile that exact transaction before serving or retrying this project",
                    self.project,
                    self.transaction_dir.display()
                )
                .into());
            }
        };
        self.write_journal("unchanged_metadata_complete", readback)?;
        remove_transaction_tree(&self.transaction_dir, &self.project_root)?;
        remove_empty_dir(&self.project_root)?;
        if let Some(parent) = self.project_root.parent() {
            remove_empty_dir(parent)?;
        }
        Ok(outcome)
    }

    fn seed_stage(&self) -> Result<Option<SeedLowerRepair>, DynError> {
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
                (false, false) => Ok(None),
                (true, true) => {
                    let staged_lowered = lowered_sqlite_path(&self.stage_cache, &self.project);
                    exact_quiescent_sqlite_snapshot(
                        &live_lowered,
                        &staged_lowered,
                        "lowered SQLite",
                    )?;

                    let staged_vault_dir = vault_dir(&self.stage_cache, &self.project);
                    let salt = vault_salt(&self.project);
                    let vault = open_shadow_vault_read_only(
                        &live_vault,
                        SHADOW_VAULT_ID,
                        &salt,
                        Vec::new(),
                    )?;
                    vault.copy_durable_snapshot_to(&staged_vault_dir)?;
                    drop(vault);

                    let staged_vault = open_shadow_vault_read_only(
                        &staged_vault_dir,
                        SHADOW_VAULT_ID,
                        &salt,
                        Vec::new(),
                    )?;
                    let prior = read_persisted_lower_state(&self.stage_cache, &self.project)?
                        .ok_or_else(|| {
                            format!(
                                "ASTRO_SHADOW_PUBLICATION_SEED_LOWER_STATE_INCOMPLETE: live project {:?} has derived artifacts but no complete persisted lower metadata. Remediation: preserve the mixed generation and rebuild it from authoritative source; do not infer missing bindings",
                                self.project
                            )
                        })?;
                    validate_configured_lower_artifact_hash(
                        &self.project,
                        &staged_lowered,
                        &prior,
                    )?;
                    match verify_lowered_artifact(
                        &staged_vault,
                        &staged_lowered,
                        &self.project,
                    ) {
                        Ok(verification) => {
                            validate_lower_verification(
                                &self.project,
                                &prior,
                                &verification,
                            )?;
                            Ok(None)
                        }
                        Err(error)
                            if error.code()
                                == Some(astrolabe_lower::ASTRO_LOWER_ARTIFACT_STALE) =>
                        {
                            drop(staged_vault);
                            let writable_vault = open_shadow_vault_writable(
                                &staged_vault_dir,
                                SHADOW_VAULT_ID,
                                &salt,
                                Vec::new(),
                            )?;
                            let repaired = regenerate_and_persist_shadow_lower(
                                &self.stage_cache,
                                &self.project,
                                &writable_vault,
                            )?;
                            drop(writable_vault);
                            let readback_vault = open_shadow_vault_read_only(
                                &staged_vault_dir,
                                SHADOW_VAULT_ID,
                                &salt,
                                Vec::new(),
                            )?;
                            let readback = verify_lowered_artifact(
                                &readback_vault,
                                &staged_lowered,
                                &self.project,
                            )?;
                            validate_lower_verification(
                                &self.project,
                                &repaired,
                                &readback,
                            )?;
                            Ok(Some(SeedLowerRepair { prior, repaired }))
                        }
                        Err(error) => Err(format!(
                            "ASTRO_SHADOW_PUBLICATION_SEED_LOWERED_UNVERIFIED: staged lowered artifact and vault manifest do not verify for project {:?}: {error}. Remediation: do not publish this generation; inspect the live lowered artifact, vault lowering manifest, config binding, and ledger chain, then rebuild from source",
                            self.project
                        )
                        .into()),
                    }
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
            "seed_lower_repair": self
                .seed_lower_repair
                .as_ref()
                .map(SeedLowerRepair::evidence_json),
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
            "schema": PUBLICATION_SCHEMA,
            "project": self.project,
            "phase": phase,
            "live_cache": self.live_cache,
            "stage_cache": self.stage_cache,
            "backup_dir": self.backup_dir,
            "generation": self.generation,
            "owner": self.owner,
            "recovery_manifest": self.recovery_manifest,
            "metadata_acknowledgement": self.metadata_acknowledgement,
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
        let publication_root_cleanup_error = if let Some(parent) = self.project_root.parent() {
            remove_empty_dir(parent)
        } else {
            Err(format!(
                "ASTRO_SHADOW_PUBLICATION_ROOT_MISSING: project transaction root {} has no publication parent; remediation: preserve the exact transaction path and inspect its construction before retrying",
                self.project_root.display()
            )
            .into())
        };
        match (
            journal_error,
            cleanup_error,
            root_cleanup_error,
            publication_root_cleanup_error,
        ) {
            (Ok(()), Ok(()), Ok(()), Ok(())) => Ok(()),
            (journal, cleanup, root_cleanup, publication_root_cleanup) => Err(format!(
                "ASTRO_SHADOW_PUBLICATION_ABORT_CLEANUP_FAILED: transaction evidence cleanup was incomplete (journal={journal:?}, cleanup={cleanup:?}, root_cleanup={root_cleanup:?}, publication_root_cleanup={publication_root_cleanup:?}) at {}; originating_error={}; remediation: do not serve or retry this project until the exact transaction tree is inspected and safely reconciled",
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

fn publication_project_root(live_cache: &Path, project: &str) -> PathBuf {
    let project_digest = hex_lower(&Sha256::digest(project.as_bytes()));
    live_cache.join(PUBLICATION_DIR).join(&project_digest[..32])
}

fn project_config_rows(cache_dir: &Path, project: &str) -> Result<Vec<(String, String)>, DynError> {
    let prefix = format!("{CONFIG_KEY_PREFIX}{project}");
    let metadata_prefix = format!("{prefix}.");
    Ok(scan_config_prefix(cache_dir, &prefix)?
        .into_iter()
        .filter(|(key, _)| key == &dial_key(project) || key.starts_with(&metadata_prefix))
        .collect())
}

fn project_config_rows_on_connection(
    connection: &Connection,
    project: &str,
) -> Result<Vec<(String, String)>, DynError> {
    let prefix = format!("{CONFIG_KEY_PREFIX}{project}");
    let metadata_prefix = format!("{prefix}.");
    let escaped = prefix
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    let pattern = format!("{escaped}%");
    let mut statement = connection
        .prepare("SELECT key, value FROM config WHERE key LIKE ? ESCAPE '\\' ORDER BY key")?;
    let rows = statement.query_map(params![pattern], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let row = row?;
        if row.0 == dial_key(project) || row.0.starts_with(&metadata_prefix) {
            out.push(row);
        }
    }
    Ok(out)
}

fn select_config_rows(rows: &[(String, String)], keys: &[String]) -> Vec<(String, String)> {
    let key_set = keys.iter().map(String::as_str).collect::<BTreeSet<_>>();
    rows.iter()
        .filter(|(key, _)| key_set.contains(key.as_str()))
        .cloned()
        .collect()
}

fn config_rows_sha256(rows: &[(String, String)]) -> Result<String, DynError> {
    Ok(hex_lower(&Sha256::digest(serde_json::to_vec(rows)?)))
}

fn replace_config_rows(
    prior_rows: &[(String, String)],
    replacement_rows: &[(String, String)],
) -> Vec<(String, String)> {
    let mut rows = prior_rows.iter().cloned().collect::<BTreeMap<_, _>>();
    for (key, value) in replacement_rows {
        rows.insert(key.clone(), value.clone());
    }
    rows.into_iter().collect()
}

fn action_metadata_candidate_rows(
    project: &str,
    dial: MigrationDial,
    sanitized_index_args: &str,
    index_admission_identity: &ShadowIndexAdmissionIdentity,
    publication_generation: &str,
    outcome: &ShadowImportOutcome,
) -> Result<Vec<(String, String)>, DynError> {
    let mut rows = vec![
        (dial_key(project), dial.as_str().to_string()),
        (
            metadata_key(project, SHADOW_INDEX_ARGS_KEY),
            sanitized_index_args.to_string(),
        ),
        (
            metadata_key(project, SHADOW_INDEX_ADMISSION_IDENTITY_KEY),
            index_admission_identity.record_json()?,
        ),
        (
            metadata_key(project, SHADOW_INDEX_ADMISSION_PUBLICATION_GENERATION_KEY),
            publication_generation.to_string(),
        ),
        (
            metadata_key(project, "search_scale_json"),
            serde_json::to_string(&outcome.search_scale)?,
        ),
        (
            metadata_key(project, "skill_tree_json"),
            serde_json::to_string(&outcome.skill_tree)?,
        ),
    ];
    rows.sort_by(|left, right| left.0.cmp(&right.0));
    if rows.iter().map(|(key, _)| key.clone()).collect::<Vec<_>>() != action_metadata_keys(project)
    {
        return Err(
            "ASTRO_SHADOW_ACTION_METADATA_KEYSET_INVALID: candidate rows do not equal the canonical action metadata key set; remediation: do not publish the incomplete acknowledgement"
                .into(),
        );
    }
    Ok(rows)
}

fn action_metadata_keys(project: &str) -> Vec<String> {
    let mut keys = vec![
        dial_key(project),
        metadata_key(project, SHADOW_INDEX_ARGS_KEY),
        metadata_key(project, SHADOW_INDEX_ADMISSION_IDENTITY_KEY),
        metadata_key(project, SHADOW_INDEX_ADMISSION_PUBLICATION_GENERATION_KEY),
        metadata_key(project, "search_scale_json"),
        metadata_key(project, "skill_tree_json"),
    ];
    keys.sort();
    keys
}

fn publication_recovery_relevant_config_rows(
    cache_dir: &Path,
    project: &str,
) -> Result<Vec<(String, String)>, DynError> {
    let mut keys = action_metadata_keys(project);
    keys.push(metadata_key(project, SHADOW_PUBLICATION_GENERATION_KEY));
    keys.sort();
    keys.dedup();
    let mut rows = Vec::new();
    for key in keys {
        if let Some(value) = read_config_value(cache_dir, &key)? {
            rows.push((key, value));
        }
    }
    Ok(rows)
}

pub(crate) fn shadow_publication_recovery_observation(
    live_cache: &Path,
    project: &str,
    fault_code: &str,
) -> Result<Option<Value>, DynError> {
    let project_root = publication_project_root(live_cache, project);
    if !project_root.exists() || fs::read_dir(&project_root)?.next().is_none() {
        return Ok(None);
    }
    let transaction_inventory_sha256 = sha256_tree_hex(&project_root)?;
    let config_rows = publication_recovery_relevant_config_rows(live_cache, project)?;
    let publication_config_sha256 = config_rows_sha256(&config_rows)?;
    Ok(Some(json!({
        "schema": "astrolabe.shadow-publication-recovery-observation.v1",
        "project": project,
        "fault_code": fault_code,
        "transaction_root": project_root,
        "transaction_inventory_sha256": transaction_inventory_sha256,
        "publication_config_sha256": publication_config_sha256,
        "publication_config_rows": config_rows,
    })))
}

pub(crate) fn shadow_publication_recovery_sentinel(
    live_cache: &Path,
    project: &str,
    fault_code: &str,
) -> Result<Option<Value>, DynError> {
    let project_root = publication_project_root(live_cache, project);
    if !project_root.exists() || fs::read_dir(&project_root)?.next().is_none() {
        return Ok(None);
    }
    let transaction_metadata = compact_transaction_sentinel(&project_root, live_cache, project)?;
    let config_rows = publication_recovery_relevant_config_rows(live_cache, project)?;
    let publication_config_sha256 = config_rows_sha256(&config_rows)?;
    Ok(Some(json!({
        "schema": "astrolabe.shadow-publication-recovery-sentinel.v1",
        "project": project,
        "fault_code": fault_code,
        "transaction_root": project_root,
        "transaction_metadata": transaction_metadata,
        "publication_config_sha256": publication_config_sha256,
        "publication_config_row_count": config_rows.len(),
        "publication_config_keys": config_rows
            .iter()
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>(),
    })))
}

fn compact_transaction_sentinel(
    project_root: &Path,
    live_cache: &Path,
    project: &str,
) -> Result<Value, DynError> {
    let mut sentinel = CompactTransactionSentinel::new();
    collect_compact_transaction_sentinel(project_root, live_cache, project, &mut sentinel)?;
    let entry_digest = sentinel.entries_sha256();
    Ok(json!({
        "schema": "astrolabe.shadow-publication-recovery-compact-sentinel.v1",
        "root": project_root,
        "strategy": "project-root-direct-entries+journal-sha256+journal-bound-artifact-metadata",
        "entry_count": sentinel.entry_count,
        "file_count": sentinel.file_count,
        "directory_count": sentinel.directory_count,
        "total_file_bytes": sentinel.total_file_bytes,
        "transaction_count": sentinel.transaction_count,
        "journal_count": sentinel.journal_count,
        "artifact_probe_count": sentinel.artifact_probe_count,
        "direct_entry_count": sentinel.direct_entry_count,
        "entries_sha256": entry_digest,
    }))
}

struct CompactTransactionSentinel {
    entry_count: u64,
    file_count: u64,
    directory_count: u64,
    total_file_bytes: u64,
    transaction_count: u64,
    journal_count: u64,
    artifact_probe_count: u64,
    direct_entry_count: u64,
    hasher: Sha256,
}

impl CompactTransactionSentinel {
    fn new() -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"astrolabe.shadow-publication.compact-sentinel.v1\0");
        Self {
            entry_count: 0,
            file_count: 0,
            directory_count: 0,
            total_file_bytes: 0,
            transaction_count: 0,
            journal_count: 0,
            artifact_probe_count: 0,
            direct_entry_count: 0,
            hasher,
        }
    }

    fn push(
        &mut self,
        relative_path: &str,
        kind: &str,
        entry_class: &str,
        bytes: Option<u64>,
        metadata: Value,
    ) -> Result<(), DynError> {
        self.entry_count += 1;
        if kind.contains("artifact") {
            self.artifact_probe_count += 1;
        }
        if kind.contains("direct") {
            self.direct_entry_count += 1;
        }
        match entry_class {
            "file" => {
                self.file_count += 1;
                self.total_file_bytes += bytes.unwrap_or(0);
            }
            "directory" => {
                self.directory_count += 1;
            }
            _ => {}
        }
        let entry = json!({
            "relative_path": relative_path,
            "kind": kind,
            "entry_class": entry_class,
            "bytes": bytes,
            "metadata": metadata,
        });
        let bytes = serde_json::to_vec(&entry)?;
        self.hasher.update((bytes.len() as u64).to_le_bytes());
        self.hasher.update(&bytes);
        Ok(())
    }

    fn entries_sha256(&self) -> String {
        hex_lower(&self.hasher.clone().finalize())
    }
}

fn collect_compact_transaction_sentinel(
    project_root: &Path,
    live_cache: &Path,
    project: &str,
    sentinel: &mut CompactTransactionSentinel,
) -> Result<(), DynError> {
    let mut transactions = fs::read_dir(project_root)?.collect::<std::io::Result<Vec<_>>>()?;
    transactions.sort_by_key(|entry| entry.file_name());
    for transaction in transactions {
        let path = transaction.path();
        let metadata = fs::symlink_metadata(&path)?;
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            return Err(format!(
                "ASTRO_SHADOW_PUBLICATION_SENTINEL_SYMLINK: refused linked transaction entry {}; remediation: preserve the transaction and inspect the named path before retrying recovery",
                path.display()
            )
            .into());
        }
        if file_type.is_dir() {
            sentinel.transaction_count += 1;
            let relative_path = sentinel_relative_path(project_root, &path)?;
            sentinel.push(
                &relative_path,
                "transaction_directory",
                "directory",
                None,
                cheap_directory_metadata(&metadata),
            )?;
            push_direct_children_sentinel(project_root, &path, sentinel)?;
            push_transaction_journal_sentinel(project_root, live_cache, project, &path, sentinel)?;
        } else if file_type.is_file() {
            let relative_path = sentinel_relative_path(project_root, &path)?;
            sentinel.push(
                &relative_path,
                "project_root_direct_file",
                "file",
                Some(metadata.len()),
                cheap_file_metadata(&metadata),
            )?;
        } else {
            return Err(format!(
                "ASTRO_SHADOW_PUBLICATION_SENTINEL_SPECIAL_FILE: refused special transaction entry {}; remediation: preserve the transaction and inspect the named path before retrying recovery",
                path.display()
            )
            .into());
        }
    }
    Ok(())
}

fn push_direct_children_sentinel(
    project_root: &Path,
    directory: &Path,
    sentinel: &mut CompactTransactionSentinel,
) -> Result<(), DynError> {
    let mut children = fs::read_dir(directory)?.collect::<std::io::Result<Vec<_>>>()?;
    children.sort_by_key(|entry| entry.file_name());
    for child in children {
        let path = child.path();
        let metadata = fs::symlink_metadata(&path)?;
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            return Err(format!(
                "ASTRO_SHADOW_PUBLICATION_SENTINEL_SYMLINK: refused linked transaction direct entry {}; remediation: preserve the transaction and inspect the named path before retrying recovery",
                path.display()
            )
            .into());
        }
        let relative_path = sentinel_display_path(project_root, &path);
        if file_type.is_dir() {
            sentinel.push(
                &relative_path,
                "transaction_direct_directory",
                "directory",
                None,
                cheap_directory_metadata(&metadata),
            )?;
        } else if file_type.is_file() {
            sentinel.push(
                &relative_path,
                "transaction_direct_file",
                "file",
                Some(metadata.len()),
                cheap_file_metadata(&metadata),
            )?;
        } else {
            return Err(format!(
                "ASTRO_SHADOW_PUBLICATION_SENTINEL_SPECIAL_FILE: refused special transaction direct entry {}; remediation: preserve the transaction and inspect the named path before retrying recovery",
                path.display()
            )
            .into());
        }
    }
    Ok(())
}

fn push_transaction_journal_sentinel(
    project_root: &Path,
    live_cache: &Path,
    project: &str,
    transaction: &Path,
    sentinel: &mut CompactTransactionSentinel,
) -> Result<(), DynError> {
    let journal_path = transaction.join(PUBLICATION_JOURNAL);
    let journal_bytes = fs::read(&journal_path).map_err(|error| {
        format!(
            "ASTRO_SHADOW_PUBLICATION_SENTINEL_JOURNAL_UNREADABLE: read {}: {error}; remediation: preserve the transaction and inspect the journal before retrying recovery",
            journal_path.display()
        )
    })?;
    let journal_sha256 = hex_lower(&Sha256::digest(&journal_bytes));
    let metadata = fs::symlink_metadata(&journal_path)?;
    if !metadata.file_type().is_file() {
        return Err(format!(
            "ASTRO_SHADOW_PUBLICATION_SENTINEL_JOURNAL_NOT_FILE: journal {} is not an ordinary file; remediation: preserve the transaction and inspect the exact path",
            journal_path.display()
        )
        .into());
    }
    let journal = read_publication_journal(&journal_path)?;
    validate_publication_journal_identity(
        &journal,
        transaction,
        project_root,
        live_cache,
        project,
    )?;
    sentinel.journal_count += 1;
    let manifest_kind = if journal.recovery_manifest.is_some() {
        "artifact_recovery"
    } else if journal.metadata_acknowledgement.is_some() {
        "metadata_acknowledgement"
    } else {
        "none"
    };
    sentinel.push(
        &sentinel_display_path(project_root, &journal_path),
        "transaction_journal",
        "file",
        Some(metadata.len()),
        json!({
            "journal_sha256": journal_sha256,
            "metadata": cheap_file_metadata(&metadata),
            "phase": journal.phase,
            "generation": journal.generation,
            "owner": journal.owner,
            "manifest_kind": manifest_kind,
        }),
    )?;
    if let Some(manifest) = journal.recovery_manifest.as_ref() {
        push_recovery_manifest_sentinel(project_root, &journal, manifest, sentinel)?;
    }
    if let Some(manifest) = journal.metadata_acknowledgement.as_ref() {
        push_metadata_acknowledgement_sentinel(project_root, &journal, manifest, sentinel)?;
    }
    Ok(())
}

fn push_recovery_manifest_sentinel(
    project_root: &Path,
    journal: &PublicationJournal,
    manifest: &PublicationRecoveryManifest,
    sentinel: &mut CompactTransactionSentinel,
) -> Result<(), DynError> {
    push_sqlite_family_sentinel(
        project_root,
        &journal.backup_dir.join("source"),
        "artifact_backup_source",
        &manifest.prior.source,
        sentinel,
    )?;
    push_sqlite_family_sentinel(
        project_root,
        &journal.backup_dir.join("lowered"),
        "artifact_backup_lowered",
        &manifest.prior.lowered,
        sentinel,
    )?;
    push_vault_sentinel(
        project_root,
        &journal.backup_dir.join("vault"),
        "artifact_backup_vault",
        &manifest.prior.vault_tree_sha256,
        sentinel,
    )?;
    push_sqlite_family_sentinel(
        project_root,
        &sqlite_path(&journal.stage_cache, &journal.project),
        "artifact_stage_source",
        &manifest.candidate.source,
        sentinel,
    )?;
    push_sqlite_family_sentinel(
        project_root,
        &lowered_sqlite_path(&journal.stage_cache, &journal.project),
        "artifact_stage_lowered",
        &manifest.candidate.lowered,
        sentinel,
    )?;
    push_vault_sentinel(
        project_root,
        &vault_dir(&journal.stage_cache, &journal.project),
        "artifact_stage_vault",
        &manifest.candidate.vault_tree_sha256,
        sentinel,
    )?;
    Ok(())
}

fn push_metadata_acknowledgement_sentinel(
    project_root: &Path,
    journal: &PublicationJournal,
    manifest: &MetadataAcknowledgementRecoveryManifest,
    sentinel: &mut CompactTransactionSentinel,
) -> Result<(), DynError> {
    sentinel.push(
        "metadata_acknowledgement_manifest",
        "metadata_acknowledgement",
        "logical",
        None,
        json!({
            "publication_generation": manifest.publication_generation,
            "keys": manifest.keys,
            "prior_rows_sha256": manifest.prior_rows_sha256,
            "candidate_rows_sha256": manifest.candidate_rows_sha256,
        }),
    )?;
    push_sqlite_family_sentinel(
        project_root,
        &sqlite_path(&journal.live_cache, &journal.project),
        "artifact_live_source",
        &manifest.artifact_generation.source,
        sentinel,
    )?;
    push_sqlite_family_sentinel(
        project_root,
        &lowered_sqlite_path(&journal.live_cache, &journal.project),
        "artifact_live_lowered",
        &manifest.artifact_generation.lowered,
        sentinel,
    )?;
    push_vault_sentinel(
        project_root,
        &vault_dir(&journal.live_cache, &journal.project),
        "artifact_live_vault",
        &manifest.artifact_generation.vault_tree_sha256,
        sentinel,
    )?;
    Ok(())
}

fn push_sqlite_family_sentinel(
    project_root: &Path,
    base: &Path,
    kind_prefix: &str,
    expected: &SqliteFamilyEvidence,
    sentinel: &mut CompactTransactionSentinel,
) -> Result<(), DynError> {
    push_file_probe_sentinel(
        project_root,
        base,
        &format!("{kind_prefix}_main"),
        &expected.main,
        sentinel,
    )?;
    push_file_probe_sentinel(
        project_root,
        &sqlite_sidecar_path(base, "-wal"),
        &format!("{kind_prefix}_wal"),
        &expected.wal,
        sentinel,
    )?;
    push_file_probe_sentinel(
        project_root,
        &sqlite_sidecar_path(base, "-shm"),
        &format!("{kind_prefix}_shm"),
        &expected.shm,
        sentinel,
    )?;
    Ok(())
}

fn push_file_probe_sentinel(
    project_root: &Path,
    path: &Path,
    kind: &str,
    expected: &Option<FileEvidence>,
    sentinel: &mut CompactTransactionSentinel,
) -> Result<(), DynError> {
    let (entry_class, bytes, observed) = match fs::symlink_metadata(path) {
        Ok(metadata) => {
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                return Err(format!(
                    "ASTRO_SHADOW_PUBLICATION_SENTINEL_SYMLINK: refused linked artifact probe {}; remediation: preserve the transaction and inspect the named path before retrying recovery",
                    path.display()
                )
                .into());
            }
            if !file_type.is_file() {
                return Err(format!(
                    "ASTRO_SHADOW_PUBLICATION_SENTINEL_ARTIFACT_NOT_FILE: artifact probe {} is not an ordinary file; remediation: preserve the transaction and inspect the named path before retrying recovery",
                    path.display()
                )
                .into());
            }
            ("file", Some(metadata.len()), cheap_file_metadata(&metadata))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            ("logical", None, json!({"state": "absent"}))
        }
        Err(error) => {
            return Err(format!(
                "ASTRO_SHADOW_PUBLICATION_SENTINEL_ARTIFACT_UNREADABLE: metadata {}: {error}; remediation: preserve the transaction and inspect the named path before retrying recovery",
                path.display()
            )
            .into());
        }
    };
    sentinel.push(
        &sentinel_display_path(project_root, path),
        kind,
        entry_class,
        bytes,
        json!({
            "expected": expected,
            "observed": observed,
        }),
    )
}

fn push_vault_sentinel(
    project_root: &Path,
    path: &Path,
    kind: &str,
    expected_tree_sha256: &Option<String>,
    sentinel: &mut CompactTransactionSentinel,
) -> Result<(), DynError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return sentinel.push(
                &sentinel_display_path(project_root, path),
                kind,
                "logical",
                None,
                json!({
                    "expected_tree_sha256": expected_tree_sha256,
                    "observed": {"state": "absent"},
                }),
            );
        }
        Err(error) => {
            return Err(format!(
                "ASTRO_SHADOW_PUBLICATION_SENTINEL_VAULT_UNREADABLE: metadata {}: {error}; remediation: preserve the transaction and inspect the named vault before retrying recovery",
                path.display()
            )
            .into());
        }
    };
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(format!(
            "ASTRO_SHADOW_PUBLICATION_SENTINEL_SYMLINK: refused linked vault probe {}; remediation: preserve the transaction and inspect the named path before retrying recovery",
            path.display()
        )
        .into());
    }
    if !file_type.is_dir() {
        return Err(format!(
            "ASTRO_SHADOW_PUBLICATION_SENTINEL_VAULT_NOT_DIRECTORY: vault probe {} is not a directory; remediation: preserve the transaction and inspect the named path before retrying recovery",
            path.display()
        )
        .into());
    }
    sentinel.push(
        &sentinel_display_path(project_root, path),
        kind,
        "directory",
        None,
        json!({
            "expected_tree_sha256": expected_tree_sha256,
            "observed": cheap_directory_metadata(&metadata),
        }),
    )?;
    push_direct_children_sentinel(project_root, path, sentinel)?;
    for relative in [
        "CURRENT",
        "MANIFEST",
        "ROUTER_HANDOFF",
        "ledger_head/current.json",
    ] {
        let marker = path.join(relative);
        push_file_probe_sentinel(
            project_root,
            &marker,
            &format!("{kind}_marker_{}", relative.replace(['/', '\\'], "_")),
            &None,
            sentinel,
        )?;
    }
    Ok(())
}

fn sentinel_relative_path(root: &Path, path: &Path) -> Result<String, DynError> {
    Ok(path
        .strip_prefix(root)?
        .to_string_lossy()
        .replace('\\', "/"))
}

fn sentinel_display_path(root: &Path, path: &Path) -> String {
    sentinel_relative_path(root, path).unwrap_or_else(|_| path.to_string_lossy().replace('\\', "/"))
}

fn cheap_file_metadata(metadata: &fs::Metadata) -> Value {
    #[cfg(windows)]
    {
        return json!({
            "platform": "windows",
            "kind": "file",
            "file_attributes": metadata.file_attributes(),
            "file_size": metadata.file_size(),
            "creation_filetime_100ns": metadata.creation_time(),
            "last_write_filetime_100ns": metadata.last_write_time(),
            "readonly": metadata.permissions().readonly(),
        });
    }
    #[cfg(not(windows))]
    {
        json!({
            "platform": "portable",
            "kind": "file",
            "bytes": metadata.len(),
            "readonly": metadata.permissions().readonly(),
        })
    }
}

fn cheap_directory_metadata(metadata: &fs::Metadata) -> Value {
    #[cfg(windows)]
    {
        return json!({
            "platform": "windows",
            "kind": "directory",
            "file_attributes": metadata.file_attributes(),
            "creation_filetime_100ns": metadata.creation_time(),
            "readonly": metadata.permissions().readonly(),
        });
    }
    #[cfg(not(windows))]
    {
        json!({
            "platform": "portable",
            "kind": "directory",
            "readonly": metadata.permissions().readonly(),
        })
    }
}

fn persist_action_metadata_acknowledgement(
    cache_dir: &Path,
    project: &str,
    expected_project_rows: &[(String, String)],
    candidate_project_rows: &[(String, String)],
    expected_publication_generation: &str,
    candidate_rows: &[(String, String)],
) -> Result<(), DynError> {
    let mut connection = open_config(cache_dir)?;
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let transaction_project_rows = project_config_rows_on_connection(&transaction, project)?;
    if transaction_project_rows != expected_project_rows {
        return Err(format!(
            "ASTRO_SHADOW_ACTION_METADATA_CONFIG_PREIMAGE_CHANGED: project {project:?} config changed before the metadata write transaction (expected_sha256={}, actual_sha256={}); remediation: preserve the staged transaction and retry only after the concurrent project operation completes",
            config_rows_sha256(expected_project_rows)?,
            config_rows_sha256(&transaction_project_rows)?
        )
        .into());
    }
    let publication_generation = transaction
        .query_row(
            "SELECT value FROM config WHERE key = ?1",
            params![metadata_key(project, SHADOW_PUBLICATION_GENERATION_KEY)],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if publication_generation.as_deref() != Some(expected_publication_generation) {
        return Err(format!(
            "ASTRO_SHADOW_ACTION_METADATA_GENERATION_PREIMAGE_CHANGED: project {project:?} artifact publication generation is {publication_generation:?}, expected {expected_publication_generation:?}; remediation: preserve the staged transaction and retry only from one authoritative generation"
        )
        .into());
    }
    for (key, value) in candidate_rows {
        transaction.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
    }
    let transaction_readback = project_config_rows_on_connection(&transaction, project)?;
    if transaction_readback != candidate_project_rows {
        return Err(format!(
            "ASTRO_SHADOW_ACTION_METADATA_TRANSACTION_PROJECT_READBACK_MISMATCH: candidate project config differs inside the write transaction (expected_sha256={}, actual_sha256={}); remediation: roll back and inspect the exact writer set before retrying",
            config_rows_sha256(candidate_project_rows)?,
            config_rows_sha256(&transaction_readback)?
        )
        .into());
    }
    let candidate_keys = candidate_rows
        .iter()
        .map(|(key, _)| key.clone())
        .collect::<Vec<_>>();
    if select_config_rows(&transaction_readback, &candidate_keys) != candidate_rows {
        return Err(
            "ASTRO_SHADOW_ACTION_METADATA_TRANSACTION_READBACK_MISMATCH: candidate rows did not read back inside the write transaction; remediation: roll back and inspect the config database before retrying"
                .into(),
        );
    }
    transaction.commit()?;
    Ok(())
}

/// Reconcile any dead publication generation before a resident accepts the
/// persisted source checkpoint as current.
///
/// The enabled watcher registration boundary calls this before comparing the
/// live Git fingerprint with the persisted one. A pre-commit interruption is
/// rolled back and therefore schedules the ordinary catch-up path; a committed
/// candidate is finalized and remains fresh without a second index pass.
pub(crate) fn reconcile_shadow_publications_for_project(
    live_cache: &Path,
    project: &str,
) -> Result<bool, DynError> {
    let project_root = publication_project_root(live_cache, project);
    let had_transactions = project_root.exists() && fs::read_dir(&project_root)?.next().is_some();
    reconcile_completed_transactions(&project_root, live_cache, project)?;
    Ok(had_transactions)
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

fn capture_file_evidence(path: &Path) -> Result<Option<FileEvidence>, DynError> {
    if !path.exists() {
        return Ok(None);
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(format!(
            "ASTRO_SHADOW_PUBLICATION_RECOVERY_FILE_KIND: expected one ordinary file at {}, found a different filesystem object; remediation: preserve the transaction and inspect the named path",
            path.display()
        )
        .into());
    }
    Ok(Some(FileEvidence {
        bytes: metadata.len(),
        sha256: sha256_file_hex(path)?,
    }))
}

fn sqlite_sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    PathBuf::from(format!("{}{suffix}", path.display()))
}

fn capture_sqlite_family(path: &Path) -> Result<SqliteFamilyEvidence, DynError> {
    Ok(SqliteFamilyEvidence {
        main: capture_file_evidence(path)?,
        wal: capture_file_evidence(&sqlite_sidecar_path(path, "-wal"))?,
        shm: capture_file_evidence(&sqlite_sidecar_path(path, "-shm"))?,
    })
}

fn capture_vault_evidence(path: &Path) -> Result<Option<String>, DynError> {
    if !path.exists() {
        return Ok(None);
    }
    if !fs::symlink_metadata(path)?.file_type().is_dir() {
        return Err(format!(
            "ASTRO_SHADOW_PUBLICATION_RECOVERY_VAULT_KIND: expected one ordinary directory at {}, found a different filesystem object; remediation: preserve the transaction and inspect the named path",
            path.display()
        )
        .into());
    }
    Ok(Some(sha256_tree_hex(path)?))
}

fn capture_artifact_generation(
    source: &Path,
    lowered: &Path,
    vault: &Path,
) -> Result<ArtifactGenerationEvidence, DynError> {
    Ok(ArtifactGenerationEvidence {
        source: capture_sqlite_family(source)?,
        lowered: capture_sqlite_family(lowered)?,
        vault_tree_sha256: capture_vault_evidence(vault)?,
    })
}

fn capture_backup_generation(backup: &Path) -> Result<ArtifactGenerationEvidence, DynError> {
    capture_artifact_generation(
        &backup.join("source"),
        &backup.join("lowered"),
        &backup.join("vault"),
    )
}

fn publication_owner_state(owner: &PublicationOwner) -> Result<String, DynError> {
    match astrolabe_bridge::process_generation_state(
        owner.pid,
        owner.process_start_utc_ticks,
    )
    .map_err(|error| {
        format!(
            "ASTRO_SHADOW_PUBLICATION_OWNER_UNEVALUABLE: exact owner ({},{}) could not be classified: {error}; remediation: preserve the complete transaction until that exact process generation is evaluable",
            owner.pid, owner.process_start_utc_ticks
        )
    })? {
        astrolabe_bridge::ProcessGenerationState::Absent => Ok("absent".to_string()),
        astrolabe_bridge::ProcessGenerationState::Reused {
            actual_start_utc_ticks,
        } => Ok(format!("pid_reused:{actual_start_utc_ticks}")),
        astrolabe_bridge::ProcessGenerationState::Matching => Err(format!(
            "ASTRO_SHADOW_PUBLICATION_OWNER_LIVE: exact owner ({},{}) is still live; remediation: wait for that exact generation to finish and never recover or remove its transaction",
            owner.pid, owner.process_start_utc_ticks
        )
        .into()),
    }
}

fn read_publication_journal(path: &Path) -> Result<PublicationJournal, DynError> {
    let bytes = fs::read(path).map_err(|error| {
        format!(
            "ASTRO_SHADOW_PUBLICATION_JOURNAL_UNREADABLE: read {}: {error}",
            path.display()
        )
    })?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|error| {
        format!(
            "ASTRO_SHADOW_PUBLICATION_JOURNAL_MALFORMED: parse {}: {error}; remediation: preserve the transaction and inspect the exact journal bytes",
            path.display()
        )
    })?;
    if value.get("schema").and_then(Value::as_str) != Some(PUBLICATION_SCHEMA) {
        return Err(format!(
            "ASTRO_SHADOW_PUBLICATION_LEGACY_PRESERVED: journal {} does not name schema {PUBLICATION_SCHEMA:?}; remediation: preserve every byte and recover the legacy transaction only through a separately specified migration",
            path.display()
        )
        .into());
    }
    serde_json::from_value(value).map_err(|error| {
        format!(
            "ASTRO_SHADOW_PUBLICATION_JOURNAL_FIELDS: strict schema-v2 decode of {} failed: {error}; remediation: preserve every byte and repair the named journal field",
            path.display()
        )
        .into()
    })
}

fn validate_publication_journal_identity(
    journal: &PublicationJournal,
    transaction: &Path,
    project_root: &Path,
    live_cache: &Path,
    project: &str,
) -> Result<(), DynError> {
    let file_name = transaction
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| -> DynError {
            format!(
                "ASTRO_SHADOW_PUBLICATION_TRANSACTION_NAME_INVALID: transaction path {} has no UTF-8 generation name; remediation: preserve the transaction",
                transaction.display()
            )
            .into()
        })?;
    if journal.schema != PUBLICATION_SCHEMA
        || journal.project != project
        || journal.live_cache != live_cache
        || journal.generation != file_name
        || journal.stage_cache != transaction.join("stage")
        || journal.backup_dir != transaction.join("backup")
        || transaction.parent() != Some(project_root)
    {
        return Err(format!(
            "ASTRO_SHADOW_PUBLICATION_RECOVERY_IDENTITY_MISMATCH: journal identity/path fields do not exactly bind transaction {}; remediation: preserve every byte and inspect schema/project/live/stage/backup/generation fields",
            transaction.display()
        )
        .into());
    }
    if journal.recovery_manifest.is_some() && journal.metadata_acknowledgement.is_some() {
        return Err(
            "ASTRO_SHADOW_PUBLICATION_RECOVERY_MANIFEST_AMBIGUOUS: transaction binds both artifact replacement and metadata-only recovery; remediation: preserve every byte and inspect the journal producer"
                .into(),
        );
    }
    Ok(())
}

fn write_recovery_journal(
    transaction: &Path,
    journal: &PublicationJournal,
    phase: &str,
    evidence: Value,
) -> Result<(), DynError> {
    let actor_pid = std::process::id();
    let actor_ticks = astrolabe_bridge::process_start_utc_ticks(actor_pid)?;
    let replacement = PublicationJournal {
        schema: journal.schema.clone(),
        project: journal.project.clone(),
        phase: phase.to_string(),
        live_cache: journal.live_cache.clone(),
        stage_cache: journal.stage_cache.clone(),
        backup_dir: journal.backup_dir.clone(),
        generation: journal.generation.clone(),
        owner: journal.owner.clone(),
        recovery_manifest: journal.recovery_manifest.clone(),
        metadata_acknowledgement: journal.metadata_acknowledgement.clone(),
        evidence: json!({
            "schema": "astrolabe.shadow-publication-recovery.v1",
            "prior_phase": journal.phase,
            "owner_state": publication_owner_state(&journal.owner)?,
            "recovery_actor": {
                "pid": actor_pid,
                "process_start_utc_ticks": actor_ticks,
            },
            "readback": evidence,
        }),
    };
    let pending = transaction.join("transaction.recovery.pending.json");
    let bytes = serde_json::to_vec_pretty(&replacement)?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&pending)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(pending, transaction.join(PUBLICATION_JOURNAL))?;
    Ok(())
}

fn family_entry<'a>(family: &'a SqliteFamilyEvidence, suffix: &str) -> &'a Option<FileEvidence> {
    match suffix {
        "" => &family.main,
        "-wal" => &family.wal,
        "-shm" => &family.shm,
        _ => unreachable!("fixed SQLite family suffix"),
    }
}

fn validate_file_distribution(
    label: &str,
    live_base: &Path,
    backup_base: &Path,
    stage_base: &Path,
    prior: &SqliteFamilyEvidence,
    candidate: &SqliteFamilyEvidence,
) -> Result<(), DynError> {
    for suffix in ["", "-wal", "-shm"] {
        let live = capture_file_evidence(&sqlite_sidecar_path(live_base, suffix))?;
        let backup = capture_file_evidence(&sqlite_sidecar_path(backup_base, suffix))?;
        let stage = capture_file_evidence(&sqlite_sidecar_path(stage_base, suffix))?;
        let expected_prior = family_entry(prior, suffix);
        let expected_candidate = family_entry(candidate, suffix);
        if backup.is_some() && &backup != expected_prior {
            return Err(format!(
                "ASTRO_SHADOW_PUBLICATION_RECOVERY_BACKUP_MISMATCH: {label}{suffix} backup does not equal the journal-bound prior file; remediation: preserve every byte"
            )
            .into());
        }
        if stage.is_some() && &stage != expected_candidate {
            return Err(format!(
                "ASTRO_SHADOW_PUBLICATION_RECOVERY_STAGE_MISMATCH: {label}{suffix} stage does not equal the journal-bound candidate file; remediation: preserve every byte"
            )
            .into());
        }
        if let Some(live) = &live
            && Some(live) != expected_prior.as_ref()
            && Some(live) != expected_candidate.as_ref()
        {
            return Err(format!(
                "ASTRO_SHADOW_PUBLICATION_RECOVERY_LIVE_MISMATCH: live {label}{suffix} equals neither journal-bound prior nor candidate; remediation: preserve every byte"
            )
            .into());
        }
    }
    Ok(())
}

fn restore_file_family(
    live_base: &Path,
    backup_base: &Path,
    prior: &SqliteFamilyEvidence,
    candidate: &SqliteFamilyEvidence,
) -> Result<(), DynError> {
    for suffix in ["", "-wal", "-shm"] {
        let live_path = sqlite_sidecar_path(live_base, suffix);
        let backup_path = sqlite_sidecar_path(backup_base, suffix);
        let live = capture_file_evidence(&live_path)?;
        let backup = capture_file_evidence(&backup_path)?;
        let expected_prior = family_entry(prior, suffix);
        let expected_candidate = family_entry(candidate, suffix);
        match expected_prior {
            Some(prior_file) if live.as_ref() == Some(prior_file) => {
                if backup.is_some() {
                    return Err("ASTRO_SHADOW_PUBLICATION_RECOVERY_DUPLICATE_PRIOR: prior file exists in both live and backup; remediation: preserve every byte".into());
                }
            }
            Some(prior_file) => {
                if backup.as_ref() != Some(prior_file) {
                    return Err("ASTRO_SHADOW_PUBLICATION_RECOVERY_PRIOR_MISSING: journal-bound prior file exists in neither live nor backup; remediation: preserve every byte".into());
                }
                if let Some(live_file) = live {
                    if Some(&live_file) != expected_candidate.as_ref() {
                        return Err("ASTRO_SHADOW_PUBLICATION_RECOVERY_CANDIDATE_MISMATCH: live replacement is not the journal-bound candidate; remediation: preserve every byte".into());
                    }
                    fs::remove_file(&live_path)?;
                }
                fs::rename(&backup_path, &live_path)?;
            }
            None => {
                if backup.is_some() {
                    return Err("ASTRO_SHADOW_PUBLICATION_RECOVERY_UNEXPECTED_BACKUP: journal says the prior file was absent but a backup exists; remediation: preserve every byte".into());
                }
                if let Some(live_file) = live {
                    if Some(&live_file) != expected_candidate.as_ref() {
                        return Err("ASTRO_SHADOW_PUBLICATION_RECOVERY_UNEXPECTED_LIVE: journal says the prior file was absent and live is not the candidate; remediation: preserve every byte".into());
                    }
                    fs::remove_file(&live_path)?;
                }
            }
        }
    }
    Ok(())
}

fn validate_vault_distribution(
    live: &Path,
    backup: &Path,
    stage: &Path,
    prior: &Option<String>,
    candidate: &Option<String>,
) -> Result<(), DynError> {
    let live_hash = capture_vault_evidence(live)?;
    let backup_hash = capture_vault_evidence(backup)?;
    let stage_hash = capture_vault_evidence(stage)?;
    if backup_hash.is_some() && &backup_hash != prior {
        return Err("ASTRO_SHADOW_PUBLICATION_RECOVERY_BACKUP_VAULT_MISMATCH: backup vault does not equal the bound prior tree; remediation: preserve every byte".into());
    }
    if stage_hash.is_some() && &stage_hash != candidate {
        return Err("ASTRO_SHADOW_PUBLICATION_RECOVERY_STAGE_VAULT_MISMATCH: stage vault does not equal the bound candidate tree; remediation: preserve every byte".into());
    }
    if live_hash.is_some() && &live_hash != prior && &live_hash != candidate {
        return Err("ASTRO_SHADOW_PUBLICATION_RECOVERY_LIVE_VAULT_MISMATCH: live vault equals neither bound tree; remediation: preserve every byte".into());
    }
    Ok(())
}

fn restore_vault(
    live: &Path,
    backup: &Path,
    prior: &Option<String>,
    candidate: &Option<String>,
) -> Result<(), DynError> {
    let live_hash = capture_vault_evidence(live)?;
    let backup_hash = capture_vault_evidence(backup)?;
    match prior {
        Some(prior_hash) if live_hash.as_ref() == Some(prior_hash) => {
            if backup_hash.is_some() {
                return Err("ASTRO_SHADOW_PUBLICATION_RECOVERY_DUPLICATE_PRIOR_VAULT: prior vault exists in both live and backup; remediation: preserve every byte".into());
            }
        }
        Some(prior_hash) => {
            if backup_hash.as_ref() != Some(prior_hash) {
                return Err("ASTRO_SHADOW_PUBLICATION_RECOVERY_PRIOR_VAULT_MISSING: prior vault exists in neither live nor backup; remediation: preserve every byte".into());
            }
            if let Some(live_value) = live_hash {
                if Some(&live_value) != candidate.as_ref() {
                    return Err("ASTRO_SHADOW_PUBLICATION_RECOVERY_CANDIDATE_VAULT_MISMATCH: live vault is not the bound candidate; remediation: preserve every byte".into());
                }
                fs::remove_dir_all(live)?;
            }
            fs::rename(backup, live)?;
        }
        None => {
            if backup_hash.is_some() {
                return Err("ASTRO_SHADOW_PUBLICATION_RECOVERY_UNEXPECTED_BACKUP_VAULT: prior vault was absent but backup exists; remediation: preserve every byte".into());
            }
            if let Some(live_value) = live_hash {
                if Some(&live_value) != candidate.as_ref() {
                    return Err("ASTRO_SHADOW_PUBLICATION_RECOVERY_UNEXPECTED_LIVE_VAULT: prior vault was absent and live is not candidate; remediation: preserve every byte".into());
                }
                fs::remove_dir_all(live)?;
            }
        }
    }
    Ok(())
}

fn validate_backup_names(backup: &Path) -> Result<(), DynError> {
    if !backup.exists() {
        return Ok(());
    }
    let allowed = BTreeSet::from([
        "source",
        "source-wal",
        "source-shm",
        "lowered",
        "lowered-wal",
        "lowered-shm",
        "vault",
    ]);
    for entry in fs::read_dir(backup)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err("ASTRO_SHADOW_PUBLICATION_RECOVERY_BACKUP_NAME_INVALID: non-UTF-8 backup entry; remediation: preserve every byte".into());
        };
        if !allowed.contains(name) {
            return Err(format!(
                "ASTRO_SHADOW_PUBLICATION_RECOVERY_BACKUP_ENTRY_UNEXPECTED: backup entry {name:?} is not an owned artifact name; remediation: preserve every byte"
            )
            .into());
        }
    }
    Ok(())
}

fn rollback_interrupted_publication(
    journal: &PublicationJournal,
    manifest: &PublicationRecoveryManifest,
) -> Result<Value, DynError> {
    validate_backup_names(&journal.backup_dir)?;
    let live_source = sqlite_path(&journal.live_cache, &journal.project);
    let live_lowered = lowered_sqlite_path(&journal.live_cache, &journal.project);
    let live_vault = vault_dir(&journal.live_cache, &journal.project);
    let backup_source = journal.backup_dir.join("source");
    let backup_lowered = journal.backup_dir.join("lowered");
    let backup_vault = journal.backup_dir.join("vault");
    let stage_source = sqlite_path(&journal.stage_cache, &journal.project);
    let stage_lowered = lowered_sqlite_path(&journal.stage_cache, &journal.project);
    let stage_vault = vault_dir(&journal.stage_cache, &journal.project);

    validate_file_distribution(
        "source",
        &live_source,
        &backup_source,
        &stage_source,
        &manifest.prior.source,
        &manifest.candidate.source,
    )?;
    validate_file_distribution(
        "lowered",
        &live_lowered,
        &backup_lowered,
        &stage_lowered,
        &manifest.prior.lowered,
        &manifest.candidate.lowered,
    )?;
    validate_vault_distribution(
        &live_vault,
        &backup_vault,
        &stage_vault,
        &manifest.prior.vault_tree_sha256,
        &manifest.candidate.vault_tree_sha256,
    )?;

    restore_vault(
        &live_vault,
        &backup_vault,
        &manifest.prior.vault_tree_sha256,
        &manifest.candidate.vault_tree_sha256,
    )?;
    restore_file_family(
        &live_lowered,
        &backup_lowered,
        &manifest.prior.lowered,
        &manifest.candidate.lowered,
    )?;
    restore_file_family(
        &live_source,
        &backup_source,
        &manifest.prior.source,
        &manifest.candidate.source,
    )?;
    let readback = capture_artifact_generation(&live_source, &live_lowered, &live_vault)?;
    if readback != manifest.prior {
        return Err("ASTRO_SHADOW_PUBLICATION_RECOVERY_ROLLBACK_READBACK_MISMATCH: restored live generation does not equal journal-bound prior state; remediation: preserve transaction and live bytes".into());
    }
    Ok(serde_json::to_value(readback)?)
}

fn finalize_interrupted_publication(
    journal: &PublicationJournal,
    manifest: &PublicationRecoveryManifest,
) -> Result<Value, DynError> {
    validate_backup_names(&journal.backup_dir)?;
    let live = capture_artifact_generation(
        &sqlite_path(&journal.live_cache, &journal.project),
        &lowered_sqlite_path(&journal.live_cache, &journal.project),
        &vault_dir(&journal.live_cache, &journal.project),
    )?;
    if live != manifest.candidate {
        return Err("ASTRO_SHADOW_PUBLICATION_RECOVERY_COMMITTED_ARTIFACT_MISMATCH: config committed the candidate generation but live artifacts do not equal its bound hashes; remediation: preserve every byte".into());
    }
    let backup = capture_backup_generation(&journal.backup_dir)?;
    if backup != manifest.prior {
        return Err("ASTRO_SHADOW_PUBLICATION_RECOVERY_COMMITTED_BACKUP_MISMATCH: committed transaction backup does not equal its bound prior generation; remediation: preserve every byte".into());
    }
    let admission_publication_generation = read_config_value(
        &journal.live_cache,
        &metadata_key(
            &journal.project,
            SHADOW_INDEX_ADMISSION_PUBLICATION_GENERATION_KEY,
        ),
    )?;
    if admission_publication_generation.as_deref()
        != Some(manifest.candidate_config_generation.as_str())
    {
        return Err(format!(
            "ASTRO_SHADOW_PUBLICATION_RECOVERY_ADMISSION_BINDING_MISMATCH: committed artifact generation {:?} has admission binding {admission_publication_generation:?}; remediation: preserve every byte and inspect the atomic config transaction",
            manifest.candidate_config_generation
        )
        .into());
    }
    Ok(json!({
        "live": live,
        "backup": backup,
        "config_generation": manifest.candidate_config_generation,
        "admission_publication_generation": admission_publication_generation,
    }))
}

fn reconcile_metadata_acknowledgement(
    journal: &PublicationJournal,
    manifest: &MetadataAcknowledgementRecoveryManifest,
) -> Result<(&'static str, Value), DynError> {
    if manifest.keys != action_metadata_keys(&journal.project) {
        return Err(
            "ASTRO_SHADOW_ACTION_METADATA_RECOVERY_KEYS_INVALID: journal metadata keys do not equal the canonical project-scoped action key set; remediation: preserve every byte and inspect the journal producer"
                .into(),
        );
    }
    if journal.backup_dir.exists() && fs::read_dir(&journal.backup_dir)?.next().is_some() {
        return Err(
            "ASTRO_SHADOW_ACTION_METADATA_RECOVERY_BACKUP_NOT_EMPTY: metadata-only transaction contains artifact backups; remediation: preserve every byte because the journal and physical scope disagree"
                .into(),
        );
    }
    let live_artifacts = capture_artifact_generation(
        &sqlite_path(&journal.live_cache, &journal.project),
        &lowered_sqlite_path(&journal.live_cache, &journal.project),
        &vault_dir(&journal.live_cache, &journal.project),
    )?;
    if live_artifacts != manifest.artifact_generation {
        return Err(
            "ASTRO_SHADOW_ACTION_METADATA_RECOVERY_ARTIFACT_DRIFT: source/lowered/vault bytes no longer equal the journal-bound unchanged generation; remediation: preserve every byte and inspect the concurrent artifact mutation"
                .into(),
        );
    }
    let publication_generation = read_config_value(
        &journal.live_cache,
        &metadata_key(&journal.project, SHADOW_PUBLICATION_GENERATION_KEY),
    )?;
    if publication_generation.as_deref() != Some(manifest.publication_generation.as_str()) {
        return Err(format!(
            "ASTRO_SHADOW_ACTION_METADATA_RECOVERY_GENERATION_DRIFT: live artifact publication generation is {publication_generation:?}, journal binds {:?}; remediation: preserve every byte and inspect the competing project publication",
            manifest.publication_generation
        )
        .into());
    }
    let rows = project_config_rows(&journal.live_cache, &journal.project)?;
    let selected_rows = select_config_rows(&rows, &manifest.keys);
    let rows_sha256 = config_rows_sha256(&selected_rows)?;
    let candidate = rows_sha256 == manifest.candidate_rows_sha256;
    let prior = rows_sha256 == manifest.prior_rows_sha256;
    let resolved_phase = match journal.phase.as_str() {
        "unchanged_metadata_complete" if candidate => "complete",
        "unchanged_metadata_validated" | "unchanged_metadata_committed_readback_failed"
            if candidate =>
        {
            "complete"
        }
        "unchanged_metadata_validated" | "aborted" if prior => "rolled_back",
        phase => {
            return Err(format!(
                "ASTRO_SHADOW_ACTION_METADATA_RECOVERY_STATE_MISMATCH: journal phase {phase:?} has selected-row hash {rows_sha256}, prior {}, candidate {}; remediation: preserve every byte because the atomic metadata outcome cannot be classified",
                manifest.prior_rows_sha256, manifest.candidate_rows_sha256
            )
            .into());
        }
    };
    Ok((
        resolved_phase,
        json!({
            "artifact_generation": live_artifacts,
            "publication_generation": publication_generation,
            "metadata_rows_sha256": rows_sha256,
            "classified_as": resolved_phase,
        }),
    ))
}

fn reconcile_completed_transactions(
    project_root: &Path,
    live_cache: &Path,
    project: &str,
) -> Result<(), DynError> {
    if !project_root.exists() {
        return Ok(());
    }
    let mut entries = fs::read_dir(project_root)?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let transaction = entry.path();
        let journal = transaction.join(PUBLICATION_JOURNAL);
        let mut value = read_publication_journal(&journal)?;
        validate_publication_journal_identity(
            &value,
            &transaction,
            project_root,
            live_cache,
            project,
        )?;
        let owner_state = publication_owner_state(&value.owner)?;
        if let Some(metadata_acknowledgement) = value.metadata_acknowledgement.as_ref() {
            let (resolved_phase, readback) =
                reconcile_metadata_acknowledgement(&value, metadata_acknowledgement)?;
            write_recovery_journal(
                &transaction,
                &value,
                resolved_phase,
                json!({"owner_state": owner_state, "metadata_acknowledgement": readback}),
            )?;
            value.phase = resolved_phase.to_string();
            remove_transaction_tree(&transaction, project_root)?;
            continue;
        }
        match value.phase.as_str() {
            "complete" => {}
            "initializing" | "staged" | "unchanged_validated" | "aborted" => {
                if value.backup_dir.exists() && fs::read_dir(&value.backup_dir)?.next().is_some() {
                    return Err(format!(
                        "ASTRO_SHADOW_PUBLICATION_RECOVERY_PREINSTALL_BACKUP_NOT_EMPTY: phase {:?} has backup artifacts; remediation: preserve every byte because the journal and physical phase disagree",
                        value.phase
                    )
                    .into());
                }
                write_recovery_journal(
                    &transaction,
                    &value,
                    "rolled_back",
                    json!({"owner_state": owner_state, "live_generation_mutated": false}),
                )?;
                value.phase = "rolled_back".to_string();
            }
            "validated" | "artifacts_installed" | "committed_readback_failed" => {
                let manifest = value.recovery_manifest.as_ref().ok_or_else(|| -> DynError {
                    format!(
                        "ASTRO_SHADOW_PUBLICATION_RECOVERY_MANIFEST_MISSING: phase {:?} has no hash-bound recovery manifest; remediation: preserve every byte",
                        value.phase
                    )
                    .into()
                })?;
                let config_generation = read_config_value(
                    live_cache,
                    &metadata_key(project, SHADOW_PUBLICATION_GENERATION_KEY),
                )?;
                if config_generation == Some(manifest.candidate_config_generation.clone()) {
                    let readback = finalize_interrupted_publication(&value, manifest)?;
                    write_recovery_journal(&transaction, &value, "complete", readback)?;
                    value.phase = "complete".to_string();
                } else if config_generation == manifest.prior_config_generation {
                    let readback = rollback_interrupted_publication(&value, manifest)?;
                    write_recovery_journal(&transaction, &value, "rolled_back", readback)?;
                    value.phase = "rolled_back".to_string();
                } else {
                    return Err(format!(
                        "ASTRO_SHADOW_PUBLICATION_RECOVERY_CONFIG_GENERATION_MISMATCH: live config generation {config_generation:?} equals neither prior {:?} nor candidate {:?}; remediation: preserve every byte",
                        manifest.prior_config_generation,
                        manifest.candidate_config_generation
                    )
                    .into());
                }
            }
            "rolled_back" => {
                let manifest = value.recovery_manifest.as_ref().ok_or_else(|| -> DynError {
                    "ASTRO_SHADOW_PUBLICATION_RECOVERY_MANIFEST_MISSING: rolled-back phase has no recovery manifest; remediation: preserve every byte".into()
                })?;
                let live = capture_artifact_generation(
                    &sqlite_path(live_cache, project),
                    &lowered_sqlite_path(live_cache, project),
                    &vault_dir(live_cache, project),
                )?;
                let config_generation = read_config_value(
                    live_cache,
                    &metadata_key(project, SHADOW_PUBLICATION_GENERATION_KEY),
                )?;
                if live != manifest.prior || config_generation != manifest.prior_config_generation {
                    return Err("ASTRO_SHADOW_PUBLICATION_RECOVERY_ROLLED_BACK_DRIFT: terminal rollback readback no longer equals the journal-bound prior generation; remediation: preserve every byte".into());
                }
            }
            other => {
                return Err(format!(
                    "ASTRO_SHADOW_PUBLICATION_RECOVERY_PHASE_INVALID: phase {other:?} is not recoverable; remediation: preserve every byte and inspect the exact journal"
                )
                .into());
            }
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

pub(crate) fn sha256_file_hex(path: &Path) -> Result<String, DynError> {
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
