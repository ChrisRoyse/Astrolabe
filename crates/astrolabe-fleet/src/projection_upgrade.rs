//! Exact-source regeneration of legacy CBM/Graph projections (#814).
//!
//! A populated `user_version=0` CBM database predates stable source atoms and
//! cannot be upgraded truthfully in place. This module therefore performs the
//! only lawful first half of the migration: under the fleet farm lock, bind
//! both the exact revision represented by the legacy projection and the clean
//! current source revision, then move the complete SQLite
//! `.db`/`-wal`/`-shm` family into a hash-bound same-volume archive. The
//! ordinary pipeline is the second half and remains the sole writer of current
//! CBM and Aster projection state.
//!
//! The archive is a resumable transaction. Every member is independently
//! classified as source or archived bytes before a rename; both-present,
//! both-absent, changed hash, an unexpected rollback journal, or an unknown
//! schema refuses without deleting anything.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use calyx_core::CalyxError;
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::catalog::FleetCatalog;
use crate::clone_farm::{git_capture, integrity_gate, same_remote, target_dir};
use crate::orchestrator::{RepoStoreIdentity, repo_store_identity};
use crate::record::FleetRepoRow;
use crate::state::RepoState;

/// Cause-specific refusal for the explicit legacy projection upgrade.
pub const ASTRO_FLEET_PROJECTION_UPGRADE_REFUSED: &str = "ASTRO_FLEET_PROJECTION_UPGRADE_REFUSED";

const CURRENT_CBM_SCHEMA_VERSION: i64 = 4;
const TRANSACTION_SCHEMA_V1: &str = "astrolabe.projection-upgrade.intent.v1";
const TRANSACTION_SCHEMA: &str = "astrolabe.projection-upgrade.intent.v2";
const MEMBER_SCHEMA: &str = "astrolabe.projection-upgrade.member.v1";
const ARCHIVE_COMPLETION_SCHEMA: &str = "astrolabe.projection-upgrade.archive-completion.v1";
const PROJECTION_COMPLETION_SCHEMA_V1: &str =
    "astrolabe.projection-upgrade.projection-completion.v1";
const PROJECTION_COMPLETION_SCHEMA: &str = "astrolabe.projection-upgrade.projection-completion.v2";
const MIGRATION_DIR: &str = "projection-v3";
const LEGACY_NODE_COLUMNS: [&str; 9] = [
    "id",
    "project",
    "label",
    "name",
    "qualified_name",
    "file_path",
    "start_line",
    "end_line",
    "properties",
];
const CURRENT_NODE_COLUMNS: [&str; 15] = [
    "id",
    "project",
    "label",
    "name",
    "qualified_name",
    "file_path",
    "start_line",
    "end_line",
    "properties",
    "atom_id",
    "source_present",
    "source_bytes",
    "source_sha256",
    "start_byte",
    "end_byte",
];
const CURRENT_EDGE_COLUMNS: [&str; 8] = [
    "id",
    "project",
    "source_id",
    "target_id",
    "type",
    "properties",
    "url_path_gen",
    "local_name_gen",
];

/// Exact paths and mutation timestamp for one projection upgrade.
#[derive(Clone, Debug, Serialize)]
pub struct ProjectionUpgradeConfig {
    /// Clone farm containing the catalog-bound checkout.
    pub farm_root: PathBuf,
    /// Per-repository fleet store root.
    pub store_root: PathBuf,
    /// Positive Unix timestamp recorded in a newly created intent.
    pub at_unix_secs: u64,
}

/// Durable archive preparation returned to the CLI before pipeline execution.
#[derive(Clone, Debug, Serialize)]
pub struct ProjectionUpgradePreparation {
    /// Exact repository identity.
    pub repo: String,
    /// Stable outer store key.
    pub store_key: String,
    /// Path-derived CBM/Aster project identity.
    pub index_project: String,
    /// Exact source revision verified before archive admission.
    pub source_head: String,
    /// Exact revision represented by the admitted projection.
    pub indexed_commit_hash: String,
    /// `current_noop`, `current_refresh_required`, `archived`,
    /// `archive_recovered`, `projection_recovered`, or
    /// `projection_recovered_refresh_required`.
    pub outcome: String,
    /// Whether the ordinary exact-source pipeline must now run.
    pub reindex_required: bool,
    /// Durable transaction id when a legacy family was archived.
    pub transaction_id: Option<String>,
    /// Intent path when a legacy family was archived.
    pub intent_path: Option<String>,
    /// Archive-completion path when a legacy family was archived.
    pub archive_completion_path: Option<String>,
    /// Current or archived main-database SHA-256.
    pub database_sha256: String,
    /// Current schema version when this was a no-op.
    pub current_schema_version: Option<i64>,
}

#[derive(Clone, Debug)]
struct SchemaState {
    kind: SchemaKind,
    user_version: i64,
    node_count: u64,
    edge_count: u64,
    project: String,
    root_path: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SchemaKind {
    LegacyUnstamped,
    Current,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct FamilyMember {
    role: String,
    source_path: String,
    archive_path: String,
    present: bool,
    bytes: Option<u64>,
    sha256: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct UpgradeIntent {
    schema: String,
    transaction_id: String,
    created_at_unix_secs: u64,
    repo: String,
    github_id: u64,
    store_key: String,
    index_project: String,
    kernel_scope: String,
    source_path: String,
    source_head: String,
    indexed_commit_hash: String,
    remote_url: String,
    database_user_version: i64,
    database_nodes: u64,
    database_edges: u64,
    database_project: String,
    database_root_path: String,
    members: Vec<FamilyMember>,
}

/// Verifies the exact source and archives a known legacy SQLite family.
///
/// The caller must hold the fleet farm lock for the complete call and, when
/// `reindex_required` is true, through the following ordinary pipeline pass.
pub fn prepare_projection_upgrade(
    catalog: &FleetCatalog,
    config: &ProjectionUpgradeConfig,
    repo: &str,
) -> Result<ProjectionUpgradePreparation, CalyxError> {
    if config.at_unix_secs == 0 {
        return Err(refusal(
            repo,
            "projection upgrade requires a positive at_unix_secs",
        ));
    }
    let row = catalog
        .query(None, None)?
        .into_iter()
        .find(|row| row.record.full_name == repo)
        .ok_or_else(|| {
            refusal(
                repo,
                "the fleet catalog has no exact repository with this owner/name",
            )
        })?;
    if row.state != RepoState::Kerneled {
        return Err(refusal(
            repo,
            &format!(
                "projection upgrade requires a kerneled catalog row, found {}",
                row.state.as_str()
            ),
        ));
    }
    let identity = repo_store_identity(&row)?;
    let source_path = row
        .clone_path
        .as_deref()
        .map(PathBuf::from)
        .ok_or_else(|| refusal(repo, "kerneled row has no live clone_path"))?;
    let expected_source = target_dir(&config.farm_root, repo);
    let source_path = canonical_dir(repo, &source_path, "catalog clone_path")?;
    let expected_source = canonical_dir(repo, &expected_source, "expected clone path")?;
    if source_path != expected_source {
        return Err(refusal(
            repo,
            &format!(
                "catalog clone path {} differs from canonical farm path {}",
                source_path.display(),
                expected_source.display()
            ),
        ));
    }
    let source_head = verify_source(&row.record.clone_url, &source_path, repo)?;
    let catalog_head = row.head_commit_hash.as_deref().ok_or_else(|| {
        refusal(
            repo,
            "kerneled row has no head_commit_hash source grounding fact",
        )
    })?;
    if catalog_head != source_head {
        return Err(refusal(
            repo,
            &format!("source HEAD {source_head} differs from catalog HEAD {catalog_head}"),
        ));
    }
    let indexed_head = row.indexed_commit_hash.as_deref().ok_or_else(|| {
        refusal(
            repo,
            "kerneled row has no indexed_commit_hash grounding fact",
        )
    })?;
    verify_commit_object(repo, &source_path, indexed_head)?;

    let store_dir = config.store_root.join(&identity.store_key);
    let database_path = store_dir.join(format!("{}.db", identity.index_project));
    let migration_root = store_dir.join("migrations").join(MIGRATION_DIR);
    let pending = pending_transaction(&migration_root, repo)?;
    if let Some(intent) = pending {
        verify_intent_binding(&intent, &identity, &row, &source_path, &source_head)?;
        let transaction_dir = migration_root.join(&intent.transaction_id);
        let archive_completion = transaction_dir.join("archive-completion.json");
        let archive_recovered = if archive_completion.try_exists().map_err(|error| {
            refusal(
                repo,
                &format!(
                    "cannot inspect archive completion {}: {error}",
                    archive_completion.display()
                ),
            )
        })? {
            verify_archive_completion(repo, &intent, &archive_completion, false)?;
            false
        } else {
            archive_family(repo, &intent, &transaction_dir)?;
            true
        };
        let legacy_database_path = PathBuf::from(
            intent
                .members
                .iter()
                .find(|member| member.role == "database")
                .ok_or_else(|| refusal(repo, "pending intent has no main-database member"))?
                .source_path
                .as_str(),
        );
        let legacy_projection_current = verify_recreated_family(
            repo,
            &legacy_database_path,
            &intent.index_project,
            &source_path,
            &intent,
        )?;
        let current_database_path = store_dir.join(format!("{}.db", identity.index_project));
        let projection_current = if identity.index_project == intent.index_project {
            legacy_projection_current
        } else {
            if legacy_projection_current {
                return Err(refusal(
                    repo,
                    "catalog identity advanced while the legacy projection namespace was recreated",
                ));
            }
            verify_current_family(
                repo,
                &current_database_path,
                &identity.index_project,
                &source_path,
            )?
        };
        if identity.index_project != intent.index_project && !projection_current {
            return Err(refusal(
                repo,
                "catalog identity advanced beyond the archived legacy identity, but its current projection family is absent",
            ));
        }
        let database_sha256 = if projection_current {
            sha256_file(repo, &current_database_path)?
        } else {
            intent
                .members
                .iter()
                .find(|member| member.role == "database")
                .and_then(|member| member.sha256.clone())
                .ok_or_else(|| refusal(repo, "pending intent has no main-database hash"))?
        };
        let catalog_current = row.indexed_commit_hash.as_deref() == Some(source_head.as_str());
        return Ok(ProjectionUpgradePreparation {
            repo: repo.to_string(),
            store_key: identity.store_key,
            index_project: identity.index_project,
            source_head,
            indexed_commit_hash: intent.indexed_commit_hash,
            outcome: if projection_current && catalog_current {
                "projection_recovered"
            } else if projection_current {
                "projection_recovered_refresh_required"
            } else if archive_recovered {
                "archive_recovered"
            } else {
                "archived"
            }
            .to_string(),
            reindex_required: !projection_current || !catalog_current,
            transaction_id: Some(intent.transaction_id),
            intent_path: Some(transaction_dir.join("intent.json").display().to_string()),
            archive_completion_path: Some(archive_completion.display().to_string()),
            database_sha256,
            current_schema_version: projection_current.then_some(CURRENT_CBM_SCHEMA_VERSION),
        });
    }

    if !database_path.try_exists().map_err(|error| {
        refusal(
            repo,
            &format!(
                "cannot inspect database namespace {}: {error}",
                database_path.display()
            ),
        )
    })? {
        return Err(refusal(
            repo,
            &format!(
                "database {} is absent and no incomplete projection-upgrade transaction can authorize recovery",
                database_path.display()
            ),
        ));
    }
    refuse_rollback_journal(repo, &database_path)?;
    let schema = inspect_schema(repo, &database_path, &identity.index_project, &source_path)?;
    if schema.kind == SchemaKind::Current {
        let database_sha256 = sha256_file(repo, &database_path)?;
        let stale = indexed_head != source_head;
        return Ok(ProjectionUpgradePreparation {
            repo: repo.to_string(),
            store_key: identity.store_key,
            index_project: identity.index_project,
            source_head,
            indexed_commit_hash: indexed_head.to_string(),
            outcome: if stale {
                "current_refresh_required"
            } else {
                "current_noop"
            }
            .to_string(),
            reindex_required: stale,
            transaction_id: None,
            intent_path: None,
            archive_completion_path: None,
            database_sha256,
            current_schema_version: Some(schema.user_version),
        });
    }

    let transaction_id = transaction_id(repo, &source_head, &database_path)?;
    let transaction_dir = migration_root.join(&transaction_id);
    let archive_dir = transaction_dir.join("original");
    let members = capture_family(repo, &database_path, &archive_dir)?;
    let intent = UpgradeIntent {
        schema: TRANSACTION_SCHEMA.to_string(),
        transaction_id: transaction_id.clone(),
        created_at_unix_secs: config.at_unix_secs,
        repo: repo.to_string(),
        github_id: row.record.github_id,
        store_key: identity.store_key.clone(),
        index_project: identity.index_project.clone(),
        kernel_scope: identity.kernel_scope,
        source_path: source_path.display().to_string(),
        source_head: source_head.clone(),
        indexed_commit_hash: indexed_head.to_string(),
        remote_url: row.record.clone_url,
        database_user_version: schema.user_version,
        database_nodes: schema.node_count,
        database_edges: schema.edge_count,
        database_project: schema.project,
        database_root_path: schema.root_path,
        members,
    };
    let intent_path = transaction_dir.join("intent.json");
    write_json_exact(repo, &intent_path, &intent)?;
    let readback = read_intent(repo, &intent_path)?;
    if readback.schema != TRANSACTION_SCHEMA
        || readback.transaction_id != intent.transaction_id
        || serde_json::to_value(&readback).ok() != serde_json::to_value(&intent).ok()
    {
        return Err(refusal(
            repo,
            "durable projection-upgrade intent readback differs from the admitted bytes",
        ));
    }
    archive_family(repo, &intent, &transaction_dir)?;
    let database_sha256 = intent
        .members
        .iter()
        .find(|member| member.role == "database")
        .and_then(|member| member.sha256.clone())
        .ok_or_else(|| refusal(repo, "new intent has no main-database hash"))?;
    Ok(ProjectionUpgradePreparation {
        repo: repo.to_string(),
        store_key: identity.store_key,
        index_project: identity.index_project,
        source_head,
        indexed_commit_hash: indexed_head.to_string(),
        outcome: "archived".to_string(),
        reindex_required: true,
        transaction_id: Some(transaction_id),
        intent_path: Some(intent_path.display().to_string()),
        archive_completion_path: Some(
            transaction_dir
                .join("archive-completion.json")
                .display()
                .to_string(),
        ),
        database_sha256,
        current_schema_version: None,
    })
}

/// Publishes the final receipt after the ordinary pipeline and kernel
/// readback have both succeeded.
pub fn complete_projection_upgrade(
    config: &ProjectionUpgradeConfig,
    preparation: &ProjectionUpgradePreparation,
    current_identity: &RepoStoreIdentity,
    kernel_members_hash: &str,
    kernel_member_count: usize,
    pipeline_report: &Value,
) -> Result<Value, CalyxError> {
    if current_identity.store_key != preparation.store_key {
        return Err(refusal(
            &preparation.repo,
            "current catalog identity changed the stable store key during projection upgrade",
        ));
    }
    let pipeline_report_bytes = serde_json::to_vec(pipeline_report).map_err(|error| {
        refusal(
            &preparation.repo,
            &format!("cannot encode the exact pipeline report: {error}"),
        )
    })?;
    let pipeline_report_sha256 = sha256_bytes(&pipeline_report_bytes);
    let Some(transaction_id) = preparation.transaction_id.as_deref() else {
        let current_database_path = config
            .store_root
            .join(&current_identity.store_key)
            .join(format!("{}.db", current_identity.index_project));
        let current_database_sha256 = sha256_file(&preparation.repo, &current_database_path)?;
        return Ok(json!({
            "outcome": if preparation.reindex_required {
                "projection_refreshed"
            } else {
                "current_noop"
            },
            "admission_database_sha256": preparation.database_sha256,
            "database_sha256": current_database_sha256,
            "admission_indexed_commit_hash": preparation.indexed_commit_hash,
            "source_head": preparation.source_head,
            "current_index_project": current_identity.index_project,
            "current_kernel_scope": current_identity.kernel_scope,
            "kernel_members_hash": kernel_members_hash,
            "kernel_member_count": kernel_member_count,
            "pipeline_report_sha256": pipeline_report_sha256,
        }));
    };
    let store_dir = config.store_root.join(&preparation.store_key);
    let database_path = store_dir.join(format!("{}.db", current_identity.index_project));
    let source_path = config.farm_root.join(&preparation.store_key);
    let schema = inspect_schema(
        &preparation.repo,
        &database_path,
        &current_identity.index_project,
        &source_path,
    )?;
    if schema.kind != SchemaKind::Current {
        return Err(refusal(
            &preparation.repo,
            "ordinary pipeline returned without a current v4 CBM database",
        ));
    }
    let transaction_dir = store_dir
        .join("migrations")
        .join(MIGRATION_DIR)
        .join(transaction_id);
    let intent_path = transaction_dir.join("intent.json");
    let intent = read_intent(&preparation.repo, &intent_path)?;
    verify_archive_completion(
        &preparation.repo,
        &intent,
        &transaction_dir.join("archive-completion.json"),
        false,
    )?;
    let current_family = capture_current_family(&preparation.repo, &database_path)?;
    let completion_schema = if intent.schema == TRANSACTION_SCHEMA_V1 {
        PROJECTION_COMPLETION_SCHEMA_V1
    } else {
        PROJECTION_COMPLETION_SCHEMA
    };
    let mut completion = json!({
        "schema": completion_schema,
        "transaction_id": transaction_id,
        "repo": preparation.repo,
        "source_head": preparation.source_head,
        "archived_index_project": intent.index_project,
        "current_index_project": current_identity.index_project,
        "current_kernel_scope": current_identity.kernel_scope,
        "database_user_version": schema.user_version,
        "database_nodes": schema.node_count,
        "database_edges": schema.edge_count,
        "current_family": current_family,
        "kernel_members_hash": kernel_members_hash,
        "kernel_member_count": kernel_member_count,
        "pipeline_report_sha256": pipeline_report_sha256,
    });
    if completion_schema == PROJECTION_COMPLETION_SCHEMA {
        let object = completion
            .as_object_mut()
            .ok_or_else(|| refusal(&preparation.repo, "projection completion is not an object"))?;
        object.insert(
            "legacy_indexed_commit_hash".to_string(),
            Value::String(intent.indexed_commit_hash.clone()),
        );
        object.insert(
            "source_path".to_string(),
            Value::String(intent.source_path.clone()),
        );
        object.insert(
            "remote_url".to_string(),
            Value::String(intent.remote_url.clone()),
        );
        object.insert(
            "archived_family".to_string(),
            serde_json::to_value(&intent.members).map_err(|error| {
                refusal(
                    &preparation.repo,
                    &format!("cannot encode archived family in completion: {error}"),
                )
            })?,
        );
    }
    let completion_path = transaction_dir.join("projection-completion.json");
    write_json_exact(&preparation.repo, &completion_path, &completion)?;
    let readback: Value = read_json(&preparation.repo, &completion_path)?;
    if readback != completion {
        return Err(refusal(
            &preparation.repo,
            "projection completion readback differs from the published receipt",
        ));
    }
    Ok(json!({
        "outcome": "projection_current",
        "transaction_id": transaction_id,
        "completion_path": completion_path.display().to_string(),
        "completion": completion,
    }))
}

/// Re-reads the catalog and current projection after the ordinary pipeline.
///
/// The explicit upgrade can legitimately migrate a legacy caller-selected
/// project identity to the server's current path-derived identity. The
/// admission preparation therefore cannot remain the destination authority
/// after the pipeline commits. This readback resolves the durable catalog row,
/// re-verifies its exact source facts, and accepts only a complete current
/// projection family under the newly published identity.
pub fn read_current_projection_identity(
    catalog: &FleetCatalog,
    config: &ProjectionUpgradeConfig,
    preparation: &ProjectionUpgradePreparation,
) -> Result<RepoStoreIdentity, CalyxError> {
    let row = catalog
        .query(None, None)?
        .into_iter()
        .find(|row| row.record.full_name == preparation.repo)
        .ok_or_else(|| {
            refusal(
                &preparation.repo,
                "the fleet catalog lost the exact repository during projection upgrade",
            )
        })?;
    if row.state != RepoState::Kerneled {
        return Err(refusal(
            &preparation.repo,
            &format!(
                "current projection readback requires a kerneled catalog row, found {}",
                row.state.as_str()
            ),
        ));
    }
    let identity = repo_store_identity(&row)?;
    if identity.store_key != preparation.store_key {
        return Err(refusal(
            &preparation.repo,
            "current catalog identity changed the stable store key during projection upgrade",
        ));
    }
    let source_path = row
        .clone_path
        .as_deref()
        .map(PathBuf::from)
        .ok_or_else(|| {
            refusal(
                &preparation.repo,
                "current catalog row has no live clone_path",
            )
        })?;
    let expected_source = target_dir(&config.farm_root, &preparation.repo);
    let source_path = canonical_dir(&preparation.repo, &source_path, "catalog clone_path")?;
    let expected_source =
        canonical_dir(&preparation.repo, &expected_source, "expected clone path")?;
    if source_path != expected_source {
        return Err(refusal(
            &preparation.repo,
            &format!(
                "current catalog clone path {} differs from canonical farm path {}",
                source_path.display(),
                expected_source.display()
            ),
        ));
    }
    let source_head = verify_source(&row.record.clone_url, &source_path, &preparation.repo)?;
    if source_head != preparation.source_head
        || row.head_commit_hash.as_deref() != Some(preparation.source_head.as_str())
        || row.indexed_commit_hash.as_deref() != Some(preparation.source_head.as_str())
    {
        return Err(refusal(
            &preparation.repo,
            "current catalog/source revision differs from the upgrade admission revision",
        ));
    }
    let database_path = config
        .store_root
        .join(&identity.store_key)
        .join(format!("{}.db", identity.index_project));
    if !verify_current_family(
        &preparation.repo,
        &database_path,
        &identity.index_project,
        &source_path,
    )? {
        return Err(refusal(
            &preparation.repo,
            "current catalog identity has no complete current projection family",
        ));
    }
    Ok(identity)
}

fn verify_source(expected_remote: &str, source: &Path, repo: &str) -> Result<String, CalyxError> {
    let head = integrity_gate(source).map_err(|detail| refusal(repo, &detail))?;
    let (remote_ok, remote, remote_stderr) = git_capture(&["remote", "get-url", "origin"], source)?;
    if !remote_ok {
        return Err(refusal(
            repo,
            &format!("git remote get-url origin failed: {remote_stderr}"),
        ));
    }
    if !same_remote(&remote, expected_remote) {
        return Err(refusal(
            repo,
            &format!("origin {remote:?} differs from catalog clone URL {expected_remote:?}"),
        ));
    }
    let (clean_ok, dirty, clean_stderr) = git_capture(
        &["status", "--porcelain=v1", "--untracked-files=all"],
        source,
    )?;
    if !clean_ok {
        return Err(refusal(
            repo,
            &format!("git status cleanliness probe failed: {clean_stderr}"),
        ));
    }
    if !dirty.is_empty() {
        return Err(refusal(
            repo,
            &format!("source worktree is not clean: {}", one_line(&dirty)),
        ));
    }
    Ok(head)
}

fn verify_commit_object(repo: &str, source: &Path, commit: &str) -> Result<(), CalyxError> {
    if !matches!(commit.len(), 40 | 64)
        || !commit
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(refusal(
            repo,
            &format!("indexed_commit_hash {commit:?} is not a canonical Git object id"),
        ));
    }
    let commitish = format!("{commit}^{{commit}}");
    let (ok, resolved, stderr) = git_capture(
        &["rev-parse", "--verify", "--end-of-options", &commitish],
        source,
    )?;
    if !ok {
        return Err(refusal(
            repo,
            &format!(
                "indexed_commit_hash {commit} is not an available commit object: {}",
                one_line(&stderr)
            ),
        ));
    }
    if resolved != commit {
        return Err(refusal(
            repo,
            &format!("indexed_commit_hash {commit} resolved to different commit object {resolved}"),
        ));
    }
    Ok(())
}

fn inspect_schema(
    repo: &str,
    database_path: &Path,
    expected_project: &str,
    expected_source: &Path,
) -> Result<SchemaState, CalyxError> {
    let connection = Connection::open_with_flags(
        database_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| {
        refusal(
            repo,
            &format!(
                "cannot open SQLite database {} read-only: {error}",
                database_path.display()
            ),
        )
    })?;
    let user_version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|error| refusal(repo, &format!("cannot read PRAGMA user_version: {error}")))?;
    let quick_check: String = connection
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(|error| refusal(repo, &format!("SQLite quick_check failed: {error}")))?;
    if quick_check != "ok" {
        return Err(refusal(
            repo,
            &format!("SQLite quick_check returned {quick_check:?}"),
        ));
    }
    let node_columns = table_columns(repo, &connection, "nodes")?;
    let kind = if user_version == 0 && node_columns == LEGACY_NODE_COLUMNS {
        SchemaKind::LegacyUnstamped
    } else if user_version == CURRENT_CBM_SCHEMA_VERSION && node_columns == CURRENT_NODE_COLUMNS {
        let edge_columns = table_columns(repo, &connection, "edges")?;
        if edge_columns != CURRENT_EDGE_COLUMNS {
            return Err(refusal(
                repo,
                &format!("current v4 database has unexpected edge columns: {edge_columns:?}"),
            ));
        }
        let identity_failures: i64 = connection
            .query_row(
                "SELECT count(*) FROM nodes WHERE atom_id = '' OR atom_id IS NULL \
                 OR source_present NOT IN (0,1) \
                 OR (source_present = 0 AND (source_bytes IS NOT NULL OR source_sha256 != '' OR start_byte != 0 OR end_byte != 0)) \
                 OR (source_present = 1 AND (source_bytes IS NULL OR length(source_sha256) != 64 OR end_byte < start_byte OR length(source_bytes) != end_byte - start_byte))",
                [],
                |row| row.get(0),
            )
            .map_err(|error| {
                refusal(
                    repo,
                    &format!("cannot verify current atom/source identities: {error}"),
                )
            })?;
        if identity_failures != 0 {
            return Err(refusal(
                repo,
                &format!(
                    "current v4 database contains {identity_failures} invalid atom/source rows"
                ),
            ));
        }
        SchemaKind::Current
    } else {
        return Err(refusal(
            repo,
            &format!(
                "SQLite schema is neither exact populated legacy nor current v4: user_version={user_version}, node_columns={node_columns:?}"
            ),
        ));
    };
    let mut projects = connection
        .prepare("SELECT name, root_path FROM projects ORDER BY name")
        .map_err(|error| {
            refusal(
                repo,
                &format!("cannot prepare project identity read: {error}"),
            )
        })?;
    let mut rows = projects
        .query([])
        .map_err(|error| refusal(repo, &format!("cannot query project identity: {error}")))?;
    let first = rows
        .next()
        .map_err(|error| refusal(repo, &format!("cannot step project identity: {error}")))?
        .ok_or_else(|| refusal(repo, "SQLite projects table is empty"))?;
    let project: String = first
        .get(0)
        .map_err(|error| refusal(repo, &format!("cannot decode project name: {error}")))?;
    let root_path: String = first
        .get(1)
        .map_err(|error| refusal(repo, &format!("cannot decode project root_path: {error}")))?;
    if rows
        .next()
        .map_err(|error| refusal(repo, &format!("cannot step project cardinality: {error}")))?
        .is_some()
    {
        return Err(refusal(
            repo,
            "per-repository SQLite store contains more than one project",
        ));
    }
    if project != expected_project {
        return Err(refusal(
            repo,
            &format!(
                "SQLite project {project:?} differs from catalog-bound project {expected_project:?}"
            ),
        ));
    }
    let recorded_source = canonical_dir(repo, Path::new(&root_path), "SQLite root_path")?;
    let expected_source = canonical_dir(repo, expected_source, "expected source root")?;
    if recorded_source != expected_source {
        return Err(refusal(
            repo,
            &format!(
                "SQLite root_path {} differs from exact source {}",
                recorded_source.display(),
                expected_source.display()
            ),
        ));
    }
    let node_count = scalar_count(repo, &connection, "SELECT count(*) FROM nodes")?;
    let edge_count = scalar_count(repo, &connection, "SELECT count(*) FROM edges")?;
    if node_count == 0 {
        return Err(refusal(
            repo,
            "projection upgrade refuses an empty application database",
        ));
    }
    drop(rows);
    drop(projects);
    drop(connection);
    Ok(SchemaState {
        kind,
        user_version,
        node_count,
        edge_count,
        project,
        root_path,
    })
}

fn table_columns(
    repo: &str,
    connection: &Connection,
    table: &str,
) -> Result<Vec<String>, CalyxError> {
    let mut statement = connection
        .prepare(&format!("PRAGMA table_xinfo({table})"))
        .map_err(|error| {
            refusal(
                repo,
                &format!("cannot prepare {table} column read: {error}"),
            )
        })?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|error| refusal(repo, &format!("cannot query {table} columns: {error}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| refusal(repo, &format!("cannot decode {table} columns: {error}")))?;
    Ok(columns)
}

fn scalar_count(repo: &str, connection: &Connection, sql: &str) -> Result<u64, CalyxError> {
    let value: i64 = connection
        .query_row(sql, [], |row| row.get(0))
        .map_err(|error| refusal(repo, &format!("cannot read persisted count: {error}")))?;
    u64::try_from(value).map_err(|_| {
        refusal(
            repo,
            &format!("persisted count is negative and cannot be trusted: {value}"),
        )
    })
}

fn capture_family(
    repo: &str,
    database_path: &Path,
    archive_dir: &Path,
) -> Result<Vec<FamilyMember>, CalyxError> {
    let mut members = Vec::with_capacity(3);
    for (role, source) in family_paths(database_path) {
        // Keep archived members out of SQLite's live-family namespace. If the
        // original `database.db`, `database.db-wal`, and `database.db-shm`
        // basenames remain adjacent, opening the archived database for an
        // audit lets SQLite checkpoint or remove the archived sidecars. Role
        // filenames preserve the exact bytes while making every member an
        // inert artifact.
        let archive = archive_dir.join(format!("{role}.bin"));
        let present = source.try_exists().map_err(|error| {
            refusal(
                repo,
                &format!("cannot inspect family member {}: {error}", source.display()),
            )
        })?;
        let (bytes, sha256) = if present {
            let metadata = fs::metadata(&source).map_err(|error| {
                refusal(
                    repo,
                    &format!("cannot stat family member {}: {error}", source.display()),
                )
            })?;
            if !metadata.is_file() {
                return Err(refusal(
                    repo,
                    &format!("family member {} is not a regular file", source.display()),
                ));
            }
            (Some(metadata.len()), Some(sha256_file(repo, &source)?))
        } else {
            (None, None)
        };
        members.push(FamilyMember {
            role: role.to_string(),
            source_path: source.display().to_string(),
            archive_path: archive.display().to_string(),
            present,
            bytes,
            sha256,
        });
    }
    if !members[0].present {
        return Err(refusal(
            repo,
            "main SQLite database disappeared before intent",
        ));
    }
    Ok(members)
}

fn capture_current_family(repo: &str, database_path: &Path) -> Result<Vec<Value>, CalyxError> {
    let mut values = Vec::new();
    for (role, path) in family_paths(database_path) {
        let present = path.try_exists().map_err(|error| {
            refusal(
                repo,
                &format!("cannot inspect current family {}: {error}", path.display()),
            )
        })?;
        values.push(if present {
            let bytes = fs::metadata(&path)
                .map_err(|error| {
                    refusal(
                        repo,
                        &format!("cannot stat current family {}: {error}", path.display()),
                    )
                })?
                .len();
            json!({
                "role": role,
                "path": path.display().to_string(),
                "present": true,
                "bytes": bytes,
                "sha256": sha256_file(repo, &path)?,
            })
        } else {
            json!({
                "role": role,
                "path": path.display().to_string(),
                "present": false,
            })
        });
    }
    Ok(values)
}

fn archive_family(
    repo: &str,
    intent: &UpgradeIntent,
    transaction_dir: &Path,
) -> Result<(), CalyxError> {
    refuse_rollback_journal(repo, Path::new(&intent.members[0].source_path))?;
    fs::create_dir_all(transaction_dir.join("original")).map_err(|error| {
        refusal(
            repo,
            &format!(
                "cannot create transaction archive {}: {error}",
                transaction_dir.display()
            ),
        )
    })?;
    for (index, member) in intent.members.iter().enumerate() {
        archive_member(repo, intent, transaction_dir, index, member)?;
    }
    for member in &intent.members {
        let source = Path::new(&member.source_path);
        if source.try_exists().map_err(|error| {
            refusal(
                repo,
                &format!(
                    "cannot read back source absence {}: {error}",
                    source.display()
                ),
            )
        })? {
            return Err(refusal(
                repo,
                &format!(
                    "source family member {} remains after archive",
                    source.display()
                ),
            ));
        }
    }
    refuse_rollback_journal(repo, Path::new(&intent.members[0].source_path))?;
    let completion = json!({
        "schema": ARCHIVE_COMPLETION_SCHEMA,
        "transaction_id": intent.transaction_id,
        "repo": intent.repo,
        "source_family_absent": true,
        "members": intent.members,
    });
    let completion_path = transaction_dir.join("archive-completion.json");
    write_json_exact(repo, &completion_path, &completion)?;
    verify_archive_completion(repo, intent, &completion_path, true)
}

fn archive_member(
    repo: &str,
    intent: &UpgradeIntent,
    transaction_dir: &Path,
    index: usize,
    member: &FamilyMember,
) -> Result<(), CalyxError> {
    let source = Path::new(&member.source_path);
    let archive = Path::new(&member.archive_path);
    let source_exists = source.try_exists().map_err(|error| {
        refusal(
            repo,
            &format!("cannot inspect source member {}: {error}", source.display()),
        )
    })?;
    let archive_exists = archive.try_exists().map_err(|error| {
        refusal(
            repo,
            &format!(
                "cannot inspect archive member {}: {error}",
                archive.display()
            ),
        )
    })?;
    if !member.present {
        if source_exists || archive_exists {
            return Err(refusal(
                repo,
                &format!(
                    "family member {} was absent at intent but now exists at source={} archive={}",
                    member.role, source_exists, archive_exists
                ),
            ));
        }
        return Ok(());
    }
    match (source_exists, archive_exists) {
        (true, false) => {
            verify_member_bytes(repo, source, member)?;
            fs::rename(source, archive).map_err(|error| {
                refusal(
                    repo,
                    &format!(
                        "same-volume rename {} -> {} failed: {error}",
                        source.display(),
                        archive.display()
                    ),
                )
            })?;
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(archive)
                .map_err(|error| {
                    refusal(
                        repo,
                        &format!(
                            "cannot open archived member {} for durability flush: {error}",
                            archive.display()
                        ),
                    )
                })?;
            file.sync_all().map_err(|error| {
                refusal(
                    repo,
                    &format!(
                        "cannot flush archived member {}: {error}",
                        archive.display()
                    ),
                )
            })?;
            verify_member_bytes(repo, archive, member)?;
            if source.try_exists().map_err(|error| {
                refusal(
                    repo,
                    &format!("cannot verify source absence {}: {error}", source.display()),
                )
            })? {
                return Err(refusal(
                    repo,
                    &format!("source {} still exists after rename", source.display()),
                ));
            }
        }
        (false, true) => verify_member_bytes(repo, archive, member)?,
        (true, true) => {
            return Err(refusal(
                repo,
                &format!(
                    "family member {} exists at both source and archive",
                    member.role
                ),
            ));
        }
        (false, false) => {
            return Err(refusal(
                repo,
                &format!(
                    "family member {} is absent from both source and archive",
                    member.role
                ),
            ));
        }
    }
    let receipt = json!({
        "schema": MEMBER_SCHEMA,
        "transaction_id": intent.transaction_id,
        "repo": intent.repo,
        "index": index,
        "role": member.role,
        "source_path": member.source_path,
        "archive_path": member.archive_path,
        "bytes": member.bytes,
        "sha256": member.sha256,
        "source_absent": true,
        "archive_verified": true,
    });
    let receipt_path = transaction_dir.join(format!("member-{index:02}-{}.json", member.role));
    write_json_exact(repo, &receipt_path, &receipt)?;
    let readback: Value = read_json(repo, &receipt_path)?;
    if readback != receipt {
        return Err(refusal(
            repo,
            &format!("member receipt {} readback differs", receipt_path.display()),
        ));
    }
    Ok(())
}

fn verify_member_bytes(repo: &str, path: &Path, member: &FamilyMember) -> Result<(), CalyxError> {
    let metadata = fs::metadata(path).map_err(|error| {
        refusal(
            repo,
            &format!("cannot stat bound member {}: {error}", path.display()),
        )
    })?;
    let expected_bytes = member
        .bytes
        .ok_or_else(|| refusal(repo, "present family member has no bound length"))?;
    let expected_sha = member
        .sha256
        .as_deref()
        .ok_or_else(|| refusal(repo, "present family member has no bound SHA-256"))?;
    let actual_sha = sha256_file(repo, path)?;
    if metadata.len() != expected_bytes || actual_sha != expected_sha {
        return Err(refusal(
            repo,
            &format!(
                "family member {} drifted: bytes {}/{}, SHA-256 {}/{}",
                path.display(),
                metadata.len(),
                expected_bytes,
                actual_sha,
                expected_sha
            ),
        ));
    }
    Ok(())
}

fn verify_archive_completion(
    repo: &str,
    intent: &UpgradeIntent,
    completion_path: &Path,
    require_source_absent: bool,
) -> Result<(), CalyxError> {
    let completion: Value = read_json(repo, completion_path)?;
    let expected_members = serde_json::to_value(&intent.members).map_err(|error| {
        refusal(
            repo,
            &format!("cannot encode the bound archive member set: {error}"),
        )
    })?;
    if completion["schema"].as_str() != Some(ARCHIVE_COMPLETION_SCHEMA)
        || completion["transaction_id"].as_str() != Some(intent.transaction_id.as_str())
        || completion["repo"].as_str() != Some(intent.repo.as_str())
        || completion["source_family_absent"].as_bool() != Some(true)
        || completion["members"] != expected_members
    {
        return Err(refusal(
            repo,
            &format!(
                "archive completion {} does not bind the exact transaction",
                completion_path.display()
            ),
        ));
    }
    for member in &intent.members {
        let source = Path::new(&member.source_path);
        if require_source_absent
            && source.try_exists().map_err(|error| {
                refusal(
                    repo,
                    &format!(
                        "cannot inspect completed source {}: {error}",
                        source.display()
                    ),
                )
            })?
        {
            return Err(refusal(
                repo,
                &format!(
                    "archive completion claims absence but source {} exists",
                    source.display()
                ),
            ));
        }
        if member.present {
            verify_member_bytes(repo, Path::new(&member.archive_path), member)?;
        } else if Path::new(&member.archive_path)
            .try_exists()
            .map_err(|error| {
                refusal(
                    repo,
                    &format!(
                        "cannot inspect absent archive member {}: {error}",
                        member.archive_path
                    ),
                )
            })?
        {
            return Err(refusal(
                repo,
                &format!(
                    "archive member {} was absent at intent but now exists",
                    member.archive_path
                ),
            ));
        }
    }
    Ok(())
}

fn verify_recreated_family(
    repo: &str,
    database_path: &Path,
    index_project: &str,
    source_path: &Path,
    intent: &UpgradeIntent,
) -> Result<bool, CalyxError> {
    if verify_current_family(repo, database_path, index_project, source_path)? {
        return Ok(true);
    }
    for member in &intent.members {
        if Path::new(&member.source_path)
            .try_exists()
            .map_err(|error| {
                refusal(
                    repo,
                    &format!(
                        "cannot inspect incomplete regenerated family member {}: {error}",
                        member.source_path
                    ),
                )
            })?
        {
            return Err(refusal(
                repo,
                &format!(
                    "projection database is absent while family member {} exists",
                    member.source_path
                ),
            ));
        }
    }
    Ok(false)
}

fn verify_current_family(
    repo: &str,
    database_path: &Path,
    index_project: &str,
    source_path: &Path,
) -> Result<bool, CalyxError> {
    if database_path.try_exists().map_err(|error| {
        refusal(
            repo,
            &format!(
                "cannot inspect regenerated database {}: {error}",
                database_path.display()
            ),
        )
    })? {
        refuse_rollback_journal(repo, database_path)?;
        let schema = inspect_schema(repo, database_path, index_project, source_path)?;
        if schema.kind != SchemaKind::Current {
            return Err(refusal(
                repo,
                "a regenerated database is not the exact current CBM schema",
            ));
        }
        return Ok(true);
    }
    refuse_rollback_journal(repo, database_path)?;
    for (role, member) in family_paths(database_path).into_iter().skip(1) {
        if member.try_exists().map_err(|error| {
            refusal(
                repo,
                &format!(
                    "cannot inspect current {role} family member {}: {error}",
                    member.display()
                ),
            )
        })? {
            return Err(refusal(
                repo,
                &format!(
                    "current projection database is absent while its {role} family member {} exists",
                    member.display()
                ),
            ));
        }
    }
    Ok(false)
}

fn verify_intent_binding(
    intent: &UpgradeIntent,
    identity: &RepoStoreIdentity,
    row: &FleetRepoRow,
    source_path: &Path,
    source_head: &str,
) -> Result<(), CalyxError> {
    let repo = row.record.full_name.as_str();
    let intent_kernel_scope = format!("repo:{}", intent.index_project);
    // Recovery may observe either the pre-pipeline indexed revision or the
    // post-pipeline source revision. No third catalog phase is admissible.
    let catalog_indexed = row.indexed_commit_hash.as_deref();
    let indexed_phase_valid = catalog_indexed == Some(intent.indexed_commit_hash.as_str())
        || catalog_indexed == Some(intent.source_head.as_str());
    if intent.schema != TRANSACTION_SCHEMA && intent.schema != TRANSACTION_SCHEMA_V1 {
        return Err(refusal(
            repo,
            "incomplete projection-upgrade intent has an unsupported schema",
        ));
    }
    if intent.repo != repo
        || intent.github_id != row.record.github_id
        || intent.store_key != identity.store_key
        || intent.kernel_scope != intent_kernel_scope
        || Path::new(&intent.source_path) != source_path
        || intent.source_head != source_head
        || row.head_commit_hash.as_deref() != Some(intent.source_head.as_str())
        || !indexed_phase_valid
        || intent.remote_url != row.record.clone_url
    {
        return Err(refusal(
            repo,
            "incomplete projection-upgrade intent differs from current catalog/source identity",
        ));
    }
    verify_commit_object(repo, source_path, &intent.indexed_commit_hash)?;
    Ok(())
}

fn pending_transaction(
    migration_root: &Path,
    repo: &str,
) -> Result<Option<UpgradeIntent>, CalyxError> {
    if !migration_root.try_exists().map_err(|error| {
        refusal(
            repo,
            &format!(
                "cannot inspect migration root {}: {error}",
                migration_root.display()
            ),
        )
    })? {
        return Ok(None);
    }
    let mut pending = Vec::new();
    let entries = fs::read_dir(migration_root).map_err(|error| {
        refusal(
            repo,
            &format!(
                "cannot enumerate migration root {}: {error}",
                migration_root.display()
            ),
        )
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            refusal(
                repo,
                &format!("cannot enumerate projection transaction: {error}"),
            )
        })?;
        if !entry
            .file_type()
            .map_err(|error| {
                refusal(
                    repo,
                    &format!("cannot classify {}: {error}", entry.path().display()),
                )
            })?
            .is_dir()
        {
            return Err(refusal(
                repo,
                &format!(
                    "migration root contains non-directory entry {}",
                    entry.path().display()
                ),
            ));
        }
        let intent = read_intent(repo, &entry.path().join("intent.json"))?;
        if intent.repo != repo {
            return Err(refusal(
                repo,
                &format!(
                    "transaction {} belongs to different repo {:?}",
                    entry.path().display(),
                    intent.repo
                ),
            ));
        }
        let directory_name = entry.file_name();
        if directory_name.to_str() != Some(intent.transaction_id.as_str()) {
            return Err(refusal(
                repo,
                &format!(
                    "transaction directory {} does not equal bound id {}",
                    entry.path().display(),
                    intent.transaction_id
                ),
            ));
        }
        let projection_completion = entry.path().join("projection-completion.json");
        if projection_completion.try_exists().map_err(|error| {
            refusal(
                repo,
                &format!(
                    "cannot inspect projection completion {}: {error}",
                    projection_completion.display()
                ),
            )
        })? {
            verify_archive_completion(
                repo,
                &intent,
                &entry.path().join("archive-completion.json"),
                false,
            )?;
            verify_projection_completion_record(repo, &intent, &projection_completion)?;
        } else {
            pending.push(intent);
        }
    }
    if pending.len() > 1 {
        return Err(refusal(
            repo,
            "more than one incomplete projection-upgrade transaction exists",
        ));
    }
    Ok(pending.pop())
}

fn verify_projection_completion_record(
    repo: &str,
    intent: &UpgradeIntent,
    completion_path: &Path,
) -> Result<(), CalyxError> {
    let completion: Value = read_json(repo, completion_path)?;
    let completion_schema = completion["schema"].as_str();
    let schema_valid = completion_schema == Some(PROJECTION_COMPLETION_SCHEMA)
        || (intent.schema == TRANSACTION_SCHEMA_V1
            && completion_schema == Some(PROJECTION_COMPLETION_SCHEMA_V1));
    let common_valid = schema_valid
        && completion["transaction_id"].as_str() == Some(intent.transaction_id.as_str())
        && completion["repo"].as_str() == Some(intent.repo.as_str())
        && completion["source_head"].as_str() == Some(intent.source_head.as_str())
        && completion["archived_index_project"].as_str() == Some(intent.index_project.as_str())
        && completion["current_index_project"]
            .as_str()
            .is_some_and(|project| !project.is_empty())
        && completion["current_kernel_scope"]
            .as_str()
            .is_some_and(|scope| {
                completion["current_index_project"]
                    .as_str()
                    .is_some_and(|project| scope == format!("repo:{project}"))
            })
        && completion["database_user_version"].as_i64() == Some(CURRENT_CBM_SCHEMA_VERSION)
        && completion["database_nodes"]
            .as_u64()
            .is_some_and(|count| count > 0)
        && completion["database_edges"].as_u64().is_some()
        && completion["current_family"].as_array().is_some()
        && completion["kernel_members_hash"]
            .as_str()
            .is_some_and(|hash| !hash.is_empty())
        && completion["kernel_member_count"]
            .as_u64()
            .is_some_and(|count| count > 0)
        && completion["pipeline_report_sha256"]
            .as_str()
            .is_some_and(|hash| {
                hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
            });
    let v2_valid = completion_schema != Some(PROJECTION_COMPLETION_SCHEMA)
        || (completion["legacy_indexed_commit_hash"].as_str()
            == Some(intent.indexed_commit_hash.as_str())
            && completion["source_path"].as_str() == Some(intent.source_path.as_str())
            && completion["remote_url"].as_str() == Some(intent.remote_url.as_str())
            && completion["archived_family"]
                == serde_json::to_value(&intent.members).map_err(|error| {
                    refusal(
                        repo,
                        &format!("cannot encode archived family for completion readback: {error}"),
                    )
                })?);
    let valid = common_valid && v2_valid;
    if !valid {
        return Err(refusal(
            repo,
            &format!(
                "projection completion {} does not bind a complete current projection",
                completion_path.display()
            ),
        ));
    }
    Ok(())
}

fn read_intent(repo: &str, path: &Path) -> Result<UpgradeIntent, CalyxError> {
    let intent: UpgradeIntent = read_json(repo, path)?;
    if intent.schema != TRANSACTION_SCHEMA && intent.schema != TRANSACTION_SCHEMA_V1 {
        return Err(refusal(
            repo,
            &format!("intent {} has unknown schema", path.display()),
        ));
    }
    Ok(intent)
}

fn read_json<T: for<'de> Deserialize<'de>>(repo: &str, path: &Path) -> Result<T, CalyxError> {
    let bytes = fs::read(path).map_err(|error| {
        refusal(
            repo,
            &format!("cannot read durable JSON {}: {error}", path.display()),
        )
    })?;
    serde_json::from_slice(&bytes).map_err(|error| {
        refusal(
            repo,
            &format!("cannot decode durable JSON {}: {error}", path.display()),
        )
    })
}

fn write_json_exact<T: Serialize>(repo: &str, path: &Path, value: &T) -> Result<(), CalyxError> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|error| {
        refusal(
            repo,
            &format!("cannot encode durable JSON {}: {error}", path.display()),
        )
    })?;
    bytes.push(b'\n');
    write_durable_exact(repo, path, &bytes)
}

fn write_durable_exact(repo: &str, path: &Path, bytes: &[u8]) -> Result<(), CalyxError> {
    let parent = path
        .parent()
        .ok_or_else(|| refusal(repo, "durable record has no parent"))?;
    fs::create_dir_all(parent).map_err(|error| {
        refusal(
            repo,
            &format!("cannot create durable parent {}: {error}", parent.display()),
        )
    })?;
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut file) => {
            file.write_all(bytes).map_err(|error| {
                refusal(
                    repo,
                    &format!("cannot write durable record {}: {error}", path.display()),
                )
            })?;
            file.sync_all().map_err(|error| {
                refusal(
                    repo,
                    &format!("cannot flush durable record {}: {error}", path.display()),
                )
            })?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = fs::read(path).map_err(|read_error| {
                refusal(
                    repo,
                    &format!(
                        "cannot read existing durable record {}: {read_error}",
                        path.display()
                    ),
                )
            })?;
            if existing != bytes {
                return Err(refusal(
                    repo,
                    &format!(
                        "existing durable record {} differs from exact bytes",
                        path.display()
                    ),
                ));
            }
        }
        Err(error) => {
            return Err(refusal(
                repo,
                &format!("cannot create durable record {}: {error}", path.display()),
            ));
        }
    }
    let readback = fs::read(path).map_err(|error| {
        refusal(
            repo,
            &format!(
                "cannot read back durable record {}: {error}",
                path.display()
            ),
        )
    })?;
    if readback != bytes {
        return Err(refusal(
            repo,
            &format!("durable record {} readback differs", path.display()),
        ));
    }
    Ok(())
}

fn transaction_id(
    repo: &str,
    source_head: &str,
    database_path: &Path,
) -> Result<String, CalyxError> {
    let database_sha = sha256_file(repo, database_path)?;
    let mut hasher = Sha256::new();
    for field in [
        b"astrolabe.projection-upgrade.transaction.v1".as_slice(),
        repo.as_bytes(),
        source_head.as_bytes(),
        database_sha.as_bytes(),
    ] {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    Ok(format!(
        "projection-v3-{}",
        &hex_lower(&hasher.finalize())[..32]
    ))
}

fn family_paths(database_path: &Path) -> Vec<(&'static str, PathBuf)> {
    let text = database_path.as_os_str().to_os_string();
    let mut wal = text.clone();
    wal.push("-wal");
    let mut shm = text;
    shm.push("-shm");
    vec![
        ("database", database_path.to_path_buf()),
        ("wal", PathBuf::from(wal)),
        ("shm", PathBuf::from(shm)),
    ]
}

fn refuse_rollback_journal(repo: &str, database_path: &Path) -> Result<(), CalyxError> {
    let mut journal = database_path.as_os_str().to_os_string();
    journal.push("-journal");
    let journal = PathBuf::from(journal);
    if journal.try_exists().map_err(|error| {
        refusal(
            repo,
            &format!(
                "cannot inspect rollback journal {}: {error}",
                journal.display()
            ),
        )
    })? {
        return Err(refusal(
            repo,
            &format!(
                "unexpected rollback journal {} exists; preserve it and recover SQLite before projection upgrade",
                journal.display()
            ),
        ));
    }
    Ok(())
}

fn canonical_dir(repo: &str, path: &Path, role: &str) -> Result<PathBuf, CalyxError> {
    fs::canonicalize(path).map_err(|error| {
        refusal(
            repo,
            &format!("cannot canonicalize {role} {}: {error}", path.display()),
        )
    })
}

fn sha256_file(repo: &str, path: &Path) -> Result<String, CalyxError> {
    let mut file = fs::File::open(path).map_err(|error| {
        refusal(
            repo,
            &format!("cannot open {} for SHA-256: {error}", path.display()),
        )
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            refusal(
                repo,
                &format!("cannot read {} for SHA-256: {error}", path.display()),
            )
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex_lower(&hasher.finalize()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn one_line(text: &str) -> String {
    text.lines().take(3).collect::<Vec<_>>().join(" | ")
}

fn refusal(repo: &str, detail: &str) -> CalyxError {
    CalyxError {
        code: ASTRO_FLEET_PROJECTION_UPGRADE_REFUSED,
        message: format!("projection upgrade for {repo} refused: {detail}"),
        remediation: "preserve the source, SQLite family, migration transaction, vault, and catalog bytes; repair the exact named mismatch, then resume this explicit repository upgrade",
    }
}
