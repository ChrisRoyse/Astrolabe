//! Preserved staged CBM stores for aborted shadow publications (#1037).
//!
//! A publication abort deletes its whole transaction tree, which used to include
//! the multi-hour CBM product `stage/<project>.db`. This module keeps exactly one
//! preserved stage per project in its own store-root namespace, records why it was
//! preserved, and lets an explicitly requested retry adopt it only when every
//! keying dimension matches exactly.
//!
//! Namespace: `<store>/.astrolabe-shadow-preserved-stage/<sha256(project)[..32]>/`
//! holding `<project>.db` plus `preserved-stage.json`. Deliberately a sibling of
//! `.astrolabe-shadow-publication` because `ShadowPublication::begin` refuses a
//! non-empty project transaction root.

use super::*;
use rusqlite::OpenFlags;
use serde::{Deserialize, Serialize};
use std::io::Write as _;

pub(crate) const PRESERVED_STAGE_DIR: &str = ".astrolabe-shadow-preserved-stage";
const PRESERVED_STAGE_MANIFEST: &str = "preserved-stage.json";
const PRESERVED_STAGE_SCHEMA: &str = "astrolabe.shadow-preserved-stage.v1";
const PRESERVED_STAGE_FINGERPRINT_SCHEMA: &str = "astrolabe.shadow-preserved-stage.fingerprint.v1";

/// Registry-declared retention: at most this many preserved stages per project.
/// A preserved stage is a full CBM store (multi-GB), so the replacement is a
/// bounded atomic swap, never an accumulating history.
pub(crate) const PRESERVED_STAGE_RETENTION: usize = 1;

/// Registry-declared default: an armed stage is preserved on abort. Overridable
/// per run via `ASTRO_SHADOW_PRESERVE_ABORTED_STAGE` so an operator with a full
/// volume can opt out explicitly (never silently).
pub(crate) const PRESERVE_ABORTED_STAGE_DEFAULT: bool = true;

/// Registry-declared default: a preserved stage is NEVER consulted unless the
/// operator explicitly asks for it via `ASTRO_SHADOW_RESUME_PRESERVED_STAGE`.
/// Opt-in lookup is what keeps "mismatch = refusal" honest: an ordinary index can
/// never be affected by a stale preserved stage.
pub(crate) const RESUME_PRESERVED_STAGE_DEFAULT: bool = false;

pub(crate) const ASTRO_SHADOW_STAGE_PRESERVED: &str = "ASTRO_SHADOW_STAGE_PRESERVED";
pub(crate) const ASTRO_SHADOW_STAGE_PRESERVE_FAILED: &str = "ASTRO_SHADOW_STAGE_PRESERVE_FAILED";
pub(crate) const ASTRO_SHADOW_PRESERVED_STAGE_ABSENT: &str = "ASTRO_SHADOW_PRESERVED_STAGE_ABSENT";
pub(crate) const ASTRO_SHADOW_PRESERVED_STAGE_MANIFEST_INVALID: &str =
    "ASTRO_SHADOW_PRESERVED_STAGE_MANIFEST_INVALID";
pub(crate) const ASTRO_SHADOW_PRESERVED_STAGE_FINGERPRINT_MISMATCH: &str =
    "ASTRO_SHADOW_PRESERVED_STAGE_FINGERPRINT_MISMATCH";
pub(crate) const ASTRO_SHADOW_PRESERVED_STAGE_PAYLOAD_MISMATCH: &str =
    "ASTRO_SHADOW_PRESERVED_STAGE_PAYLOAD_MISMATCH";
pub(crate) const ASTRO_SHADOW_PRESERVED_STAGE_CORPUS_UNIDENTIFIABLE: &str =
    "ASTRO_SHADOW_PRESERVED_STAGE_CORPUS_UNIDENTIFIABLE";
pub(crate) const ASTRO_SHADOW_PRESERVED_STAGE_ADOPT_FAILED: &str =
    "ASTRO_SHADOW_PRESERVED_STAGE_ADOPT_FAILED";

fn env_flag(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(value) if value == "0" || value.eq_ignore_ascii_case("false") => false,
        Ok(value) if value == "1" || value.eq_ignore_ascii_case("true") => true,
        _ => default,
    }
}

pub(crate) fn preserve_aborted_stage_enabled() -> bool {
    env_flag(
        "ASTRO_SHADOW_PRESERVE_ABORTED_STAGE",
        PRESERVE_ABORTED_STAGE_DEFAULT,
    )
}

pub(crate) fn resume_preserved_stage_requested() -> bool {
    env_flag(
        "ASTRO_SHADOW_RESUME_PRESERVED_STAGE",
        RESUME_PRESERVED_STAGE_DEFAULT,
    )
}

pub(crate) fn preserved_stage_root(live_cache: &Path) -> PathBuf {
    live_cache.join(PRESERVED_STAGE_DIR)
}

pub(crate) fn preserved_stage_dir(live_cache: &Path, project: &str) -> PathBuf {
    let project_digest = hex_lower(&Sha256::digest(project.as_bytes()));
    preserved_stage_root(live_cache).join(project_digest[..32].to_string())
}

/// Every keying dimension of the CBM pass. A preserved stage is adopted only when
/// all of them match exactly; a dimension that cannot be measured is a refusal,
/// never an omitted key component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PreservedStageFingerprint {
    pub(crate) schema: String,
    pub(crate) project: String,
    pub(crate) admission_identity_sha256: String,
    pub(crate) producer_executable_sha256: String,
    pub(crate) canonical_repo_path: String,
    pub(crate) git_head_oid: String,
    pub(crate) git_source_fingerprint: String,
    pub(crate) symbol_canonical_schema: String,
    pub(crate) panel_version: u32,
    pub(crate) publication_schema: String,
}

impl PreservedStageFingerprint {
    pub(crate) fn capture(
        project: &str,
        repo: Option<&Path>,
        identity: &ShadowIndexAdmissionIdentity,
        publication_schema: &str,
    ) -> Result<Self, DynError> {
        let repo = repo
            .filter(|repo| astrolabe_anchors::archaeology::is_git_work_tree(repo))
            .ok_or_else(|| -> DynError {
                format!(
                    "{ASTRO_SHADOW_PRESERVED_STAGE_CORPUS_UNIDENTIFIABLE}: project {project:?} has no git work tree to fingerprint, so a staged CBM store cannot be keyed to an exact corpus identity; remediation: index a git work tree, or accept that aborted stages for this corpus are not preservable/resumable"
                )
                .into()
            })?;
        let canonical_repo = fs::canonicalize(repo).map_err(|error| -> DynError {
            format!(
                "{ASTRO_SHADOW_PRESERVED_STAGE_CORPUS_UNIDENTIFIABLE}: canonicalizing corpus {} failed: {error}; remediation: restore the exact indexed source root before preserving or resuming a stage",
                repo.display()
            )
            .into()
        })?;
        Ok(Self {
            schema: PRESERVED_STAGE_FINGERPRINT_SCHEMA.to_string(),
            project: project.to_string(),
            admission_identity_sha256: identity.identity_sha256().to_string(),
            producer_executable_sha256: identity.producer_executable_sha256().to_string(),
            canonical_repo_path: canonical_repo.display().to_string(),
            git_head_oid: astrolabe_anchors::archaeology::git_head(&canonical_repo)?,
            git_source_fingerprint: astrolabe_anchors::archaeology::git_source_fingerprint(
                &canonical_repo,
            )?,
            symbol_canonical_schema: SYMBOL_CANONICAL_TAG.to_string(),
            panel_version: SHADOW_PANEL_VERSION,
            publication_schema: publication_schema.to_string(),
        })
    }

    /// The resume token: a domain-separated digest over every keying dimension.
    pub(crate) fn token_sha256(&self) -> Result<String, DynError> {
        let bytes = serde_json::to_vec(self)?;
        let mut hasher = Sha256::new();
        hasher.update(b"astrolabe.shadow-preserved-stage.fingerprint.v1\0");
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
        Ok(hex_lower(&hasher.finalize()))
    }

    /// Names every dimension that differs, so a refusal can say exactly what moved.
    fn mismatches(&self, other: &Self) -> Vec<String> {
        let mut differences = Vec::new();
        let mut compare = |name: &str, expected: &str, found: &str| {
            if expected != found {
                differences.push(format!(
                    "{name}(expected={expected:?}, preserved={found:?})"
                ));
            }
        };
        compare("schema", &self.schema, &other.schema);
        compare("project", &self.project, &other.project);
        compare(
            "admission_identity_sha256",
            &self.admission_identity_sha256,
            &other.admission_identity_sha256,
        );
        compare(
            "producer_executable_sha256",
            &self.producer_executable_sha256,
            &other.producer_executable_sha256,
        );
        compare(
            "canonical_repo_path",
            &self.canonical_repo_path,
            &other.canonical_repo_path,
        );
        compare("git_head_oid", &self.git_head_oid, &other.git_head_oid);
        compare(
            "git_source_fingerprint",
            &self.git_source_fingerprint,
            &other.git_source_fingerprint,
        );
        compare(
            "symbol_canonical_schema",
            &self.symbol_canonical_schema,
            &other.symbol_canonical_schema,
        );
        compare(
            "panel_version",
            &self.panel_version.to_string(),
            &other.panel_version.to_string(),
        );
        compare(
            "publication_schema",
            &self.publication_schema,
            &other.publication_schema,
        );
        differences
    }
}

/// What a publication carries once its CBM pass has completed successfully. Only
/// an armed publication preserves its stage on abort; an abort before or during
/// the pass has no durable CBM product worth keeping and cleans up exactly as
/// before.
#[derive(Debug, Clone)]
pub(crate) struct PreservedStageArming {
    fingerprint: PreservedStageFingerprint,
    fingerprint_sha256: String,
    index_tool_result: String,
    index_tool_result_sha256: String,
}

impl PreservedStageArming {
    pub(crate) fn new(
        fingerprint: &PreservedStageFingerprint,
        index_tool_result: &str,
    ) -> Result<Self, DynError> {
        Ok(Self {
            fingerprint: fingerprint.clone(),
            fingerprint_sha256: fingerprint.token_sha256()?,
            index_tool_result: index_tool_result.to_string(),
            index_tool_result_sha256: hex_lower(&Sha256::digest(index_tool_result.as_bytes())),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PreservedStageRecord {
    schema: String,
    project: String,
    generation: String,
    preserved_at_unix_nanos: u128,
    owner_pid: u32,
    owner_process_start_utc_ticks: u64,
    abort_phase: String,
    abort_error: String,
    fingerprint: PreservedStageFingerprint,
    fingerprint_sha256: String,
    source_file: String,
    source_bytes: u64,
    source_sha256: String,
    index_tool_result: String,
    index_tool_result_sha256: String,
    superseded_generation: Option<String>,
    retention: usize,
}

/// A preserved stage that passed every fingerprint and payload check and whose
/// database now lives in the caller's fresh stage.
#[derive(Debug, Clone)]
pub(crate) struct AdoptedPreservedStage {
    record: PreservedStageRecord,
    adopted_from: PathBuf,
    staged_source: PathBuf,
}

impl AdoptedPreservedStage {
    pub(crate) fn index_tool_result(&self) -> &str {
        &self.record.index_tool_result
    }

    pub(crate) fn staged_source(&self) -> &Path {
        &self.staged_source
    }

    pub(crate) fn evidence_json(&self) -> Value {
        json!({
            "schema": "astrolabe.shadow-preserved-stage-adoption.v1",
            "adopted_from": self.adopted_from,
            "staged_source": self.staged_source,
            "resume_token": self.record.fingerprint_sha256,
            "source_sha256": self.record.source_sha256,
            "source_bytes": self.record.source_bytes,
            "preserved_generation": self.record.generation,
            "preserved_abort_phase": self.record.abort_phase,
            "cbm_pass_skipped": true,
        })
    }
}

fn write_json_durably(path: &Path, bytes: &[u8]) -> Result<(), DynError> {
    let temporary = PathBuf::from(format!("{}.pending", path.display()));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(temporary, path)?;
    Ok(())
}

/// Moves the staged CBM store out of a dying transaction into the project's
/// preserved-stage slot, replacing any prior slot atomically. Returns the labeled
/// evidence the abort error carries.
///
/// The payload is moved with `fs::rename` inside the same store root, so this
/// never needs a second copy of a multi-GB database and never doubles peak disk.
#[allow(clippy::too_many_arguments)]
pub(crate) fn preserve_stage(
    live_cache: &Path,
    project: &str,
    generation: &str,
    owner_pid: u32,
    owner_process_start_utc_ticks: u64,
    stage_cache: &Path,
    phase: &str,
    error: &str,
    arming: &PreservedStageArming,
) -> Result<Value, DynError> {
    let staged_source = sqlite_path(stage_cache, project);
    if !staged_source.exists() {
        return Err(format!(
            "{ASTRO_SHADOW_STAGE_PRESERVE_FAILED}: project {project:?} armed stage preservation but its staged CBM SQLite is absent at {}; remediation: inspect the index pass that reported success without a durable store",
            staged_source.display()
        )
        .into());
    }
    checkpoint_sqlite(&staged_source, "preserved CBM source")?;
    for suffix in ["-wal", "-shm", "-journal"] {
        let sidecar = PathBuf::from(format!("{}{suffix}", staged_source.display()));
        if sidecar.exists() {
            return Err(format!(
                "{ASTRO_SHADOW_STAGE_PRESERVE_FAILED}: staged CBM source {} still has live SQLite sidecar {} after checkpointing; a single-file preserved identity is not safe to take; remediation: stop the staged writer and preserve only a quiescent store",
                staged_source.display(),
                sidecar.display()
            )
            .into());
        }
    }
    let source_bytes = fs::metadata(&staged_source)?.len();
    let source_sha256 = sha256_file_hex(&staged_source)?;
    let file_name = staged_source
        .file_name()
        .ok_or_else(|| -> DynError {
            format!(
                "{ASTRO_SHADOW_STAGE_PRESERVE_FAILED}: staged CBM source path {} has no file name; remediation: inspect the stage layout construction",
                staged_source.display()
            )
            .into()
        })?
        .to_string_lossy()
        .into_owned();

    let root = preserved_stage_root(live_cache);
    let target = preserved_stage_dir(live_cache, project);
    let incoming = PathBuf::from(format!("{}.incoming-{generation}", target.display()));
    let superseded = PathBuf::from(format!("{}.superseded-{generation}", target.display()));
    fs::create_dir_all(&root)?;
    if incoming.exists() {
        fs::remove_dir_all(&incoming)?;
    }
    fs::create_dir(&incoming)?;

    let published = (|| -> Result<PreservedStageRecord, DynError> {
        fs::rename(&staged_source, incoming.join(&file_name))?;
        let record = PreservedStageRecord {
            schema: PRESERVED_STAGE_SCHEMA.to_string(),
            project: project.to_string(),
            generation: generation.to_string(),
            preserved_at_unix_nanos: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|error| format!("{ASTRO_SHADOW_STAGE_PRESERVE_FAILED}: {error}"))?
                .as_nanos(),
            owner_pid,
            owner_process_start_utc_ticks,
            abort_phase: phase.to_string(),
            abort_error: error.to_string(),
            fingerprint: arming.fingerprint.clone(),
            fingerprint_sha256: arming.fingerprint_sha256.clone(),
            source_file: file_name.clone(),
            source_bytes,
            source_sha256: source_sha256.clone(),
            index_tool_result: arming.index_tool_result.clone(),
            index_tool_result_sha256: arming.index_tool_result_sha256.clone(),
            superseded_generation: None,
            retention: PRESERVED_STAGE_RETENTION,
        };
        let mut record = record;
        if target.exists() {
            record.superseded_generation = read_record(&target).ok().map(|prior| prior.generation);
        }
        write_json_durably(
            &incoming.join(PRESERVED_STAGE_MANIFEST),
            &serde_json::to_vec_pretty(&record)?,
        )?;
        // RocksDB-checkpoint style swap: a crash inside this window leaves either
        // the prior preserved stage or the new one, never a torn slot.
        if target.exists() {
            fs::rename(&target, &superseded)?;
        }
        fs::rename(&incoming, &target)?;
        if superseded.exists() {
            fs::remove_dir_all(&superseded)?;
        }
        Ok(record)
    })();

    let record = match published {
        Ok(record) => record,
        Err(error) => {
            // Never leave a half-published slot behind; the abort error carries the
            // labeled failure so this is a disclosed loss, not a silent one.
            let _ = fs::remove_dir_all(&incoming);
            return Err(error);
        }
    };

    // Independent readback of the published slot before the transaction tree dies.
    let published_source = target.join(&record.source_file);
    let published_bytes = fs::metadata(&published_source)?.len();
    let published_sha256 = sha256_file_hex(&published_source)?;
    if published_bytes != source_bytes || published_sha256 != source_sha256 {
        return Err(format!(
            "{ASTRO_SHADOW_STAGE_PRESERVE_FAILED}: preserved payload readback at {} is bytes={published_bytes} sha256={published_sha256}, expected bytes={source_bytes} sha256={source_sha256}; remediation: preserve every byte of {} by hand and inspect the storage device before retrying",
            published_source.display(),
            target.display()
        )
        .into());
    }
    Ok(json!({
        "schema": "astrolabe.shadow-preserved-stage-evidence.v1",
        "preserved_stage_dir": target,
        "source_path": published_source,
        "source_bytes": published_bytes,
        "source_sha256": published_sha256,
        "resume_token": record.fingerprint_sha256,
        "generation": record.generation,
        "superseded_generation": record.superseded_generation,
        "abort_phase": record.abort_phase,
        "retention": PRESERVED_STAGE_RETENTION,
    }))
}

fn read_record(dir: &Path) -> Result<PreservedStageRecord, DynError> {
    let manifest = dir.join(PRESERVED_STAGE_MANIFEST);
    let bytes = fs::read(&manifest).map_err(|error| -> DynError {
        format!(
            "{ASTRO_SHADOW_PRESERVED_STAGE_MANIFEST_INVALID}: preserved stage manifest {} is unreadable: {error}; remediation: preserve the directory and inspect it before retrying a seeded resume",
            manifest.display()
        )
        .into()
    })?;
    let record: PreservedStageRecord = serde_json::from_slice(&bytes).map_err(|error| -> DynError {
        format!(
            "{ASTRO_SHADOW_PRESERVED_STAGE_MANIFEST_INVALID}: preserved stage manifest {} does not parse as {PRESERVED_STAGE_SCHEMA}: {error}; remediation: preserve the directory and rebuild from authoritative source rather than adopting an unreadable stage",
            manifest.display()
        )
        .into()
    })?;
    if record.schema != PRESERVED_STAGE_SCHEMA {
        return Err(format!(
            "{ASTRO_SHADOW_PRESERVED_STAGE_MANIFEST_INVALID}: preserved stage manifest {} declares schema {:?}, this build adopts only {PRESERVED_STAGE_SCHEMA:?}; remediation: preserve the directory and rebuild from authoritative source",
            manifest.display(),
            record.schema
        )
        .into());
    }
    Ok(record)
}

/// Adopts the project's preserved stage into `stage_cache` when — and only when —
/// every fingerprint dimension and the payload bytes match exactly. Consumes the
/// preserved slot on success (rsync `--partial-dir` semantics: the partial data is
/// deleted once it has served its purpose); leaves it byte-identical on every
/// refusal.
pub(crate) fn adopt_preserved_stage(
    live_cache: &Path,
    project: &str,
    stage_cache: &Path,
    expected: &PreservedStageFingerprint,
) -> Result<AdoptedPreservedStage, DynError> {
    let dir = preserved_stage_dir(live_cache, project);
    if !dir.exists() {
        return Err(format!(
            "{ASTRO_SHADOW_PRESERVED_STAGE_ABSENT}: a seeded resume was requested for project {project:?} but no preserved stage exists at {}; remediation: unset ASTRO_SHADOW_RESUME_PRESERVED_STAGE and run a full index, or restore the preserved stage recorded by the abort that produced it",
            dir.display()
        )
        .into());
    }
    let record = read_record(&dir)?;
    let recomputed = record.fingerprint.token_sha256()?;
    if recomputed != record.fingerprint_sha256 {
        return Err(format!(
            "{ASTRO_SHADOW_PRESERVED_STAGE_MANIFEST_INVALID}: preserved stage {} binds resume token {} but its recorded fingerprint hashes to {recomputed}; remediation: preserve the directory and rebuild from authoritative source; a manifest that disagrees with itself is never adopted",
            dir.display(),
            record.fingerprint_sha256
        )
        .into());
    }
    let differences = expected.mismatches(&record.fingerprint);
    if !differences.is_empty() {
        return Err(format!(
            "{ASTRO_SHADOW_PRESERVED_STAGE_FINGERPRINT_MISMATCH}: preserved stage {} was produced under a different identity — mismatching dimensions: {}; expected_resume_token={}, preserved_resume_token={}; remediation: the preserved CBM store does not describe this corpus/build/arguments — run a full index (unset ASTRO_SHADOW_RESUME_PRESERVED_STAGE), or restore the exact inputs that produced the preserved stage; Astrolabe never adopts a stage across a changed input",
            dir.display(),
            differences.join(", "),
            expected.token_sha256()?,
            record.fingerprint_sha256
        )
        .into());
    }
    let payload = dir.join(&record.source_file);
    let payload_bytes = fs::metadata(&payload)
        .map_err(|error| -> DynError {
            format!(
                "{ASTRO_SHADOW_PRESERVED_STAGE_PAYLOAD_MISMATCH}: preserved payload {} is unreadable: {error}; remediation: preserve the directory and rebuild from authoritative source",
                payload.display()
            )
            .into()
        })?
        .len();
    let payload_sha256 = sha256_file_hex(&payload)?;
    if payload_bytes != record.source_bytes || payload_sha256 != record.source_sha256 {
        return Err(format!(
            "{ASTRO_SHADOW_PRESERVED_STAGE_PAYLOAD_MISMATCH}: preserved payload {} is bytes={payload_bytes} sha256={payload_sha256}, but its manifest binds bytes={} sha256={}; remediation: preserve the directory, inspect the storage device, and rebuild from authoritative source",
            payload.display(),
            record.source_bytes,
            record.source_sha256
        )
        .into());
    }
    let recomputed_result = hex_lower(&Sha256::digest(record.index_tool_result.as_bytes()));
    if recomputed_result != record.index_tool_result_sha256 {
        return Err(format!(
            "{ASTRO_SHADOW_PRESERVED_STAGE_MANIFEST_INVALID}: preserved index tool result in {} hashes to {recomputed_result}, manifest binds {}; remediation: preserve the directory and rebuild from authoritative source",
            dir.display(),
            record.index_tool_result_sha256
        )
        .into());
    }

    // The stage already holds a seeded snapshot of the LIVE source; the preserved
    // store supersedes it wholesale.
    let staged_source = sqlite_path(stage_cache, project);
    if staged_source.exists() {
        fs::remove_file(&staged_source)?;
    }
    for suffix in ["-wal", "-shm", "-journal"] {
        let sidecar = PathBuf::from(format!("{}{suffix}", staged_source.display()));
        if sidecar.exists() {
            fs::remove_file(&sidecar)?;
        }
    }
    fs::rename(&payload, &staged_source).map_err(|error| -> DynError {
        format!(
            "{ASTRO_SHADOW_PRESERVED_STAGE_ADOPT_FAILED}: moving preserved payload {} into stage {} failed: {error}; remediation: the preserved stage is intact — inspect the stage volume and retry",
            payload.display(),
            staged_source.display()
        )
        .into()
    })?;

    // Independent readback at the destination before the slot is consumed.
    let adopted_bytes = fs::metadata(&staged_source)?.len();
    let adopted_sha256 = sha256_file_hex(&staged_source)?;
    if adopted_bytes != record.source_bytes || adopted_sha256 != record.source_sha256 {
        return Err(format!(
            "{ASTRO_SHADOW_PRESERVED_STAGE_PAYLOAD_MISMATCH}: adopted stage {} reads back bytes={adopted_bytes} sha256={adopted_sha256}, expected bytes={} sha256={}; remediation: do not publish this generation; inspect the stage volume and rebuild from authoritative source",
            staged_source.display(),
            record.source_bytes,
            record.source_sha256
        )
        .into());
    }
    let integrity = {
        let open_path = astrolabe_domain::winpath::sqlite_open_path(&staged_source)?;
        let conn = Connection::open_with_flags(open_path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        conn.query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))?
    };
    if integrity != "ok" {
        return Err(format!(
            "{ASTRO_SHADOW_PRESERVED_STAGE_PAYLOAD_MISMATCH}: adopted stage {} returned integrity_check={integrity:?}; remediation: do not publish this generation; rebuild from authoritative source",
            staged_source.display()
        )
        .into());
    }
    fs::remove_dir_all(&dir)?;
    Ok(AdoptedPreservedStage {
        record,
        adopted_from: dir,
        staged_source,
    })
}
