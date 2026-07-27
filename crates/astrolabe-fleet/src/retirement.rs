//! Crash-recoverable post-kernel source retirement (#807).
//!
//! A checkout is disposable only after its exact per-repo kernel is present in
//! an independently verified cumulative fleet kernel. Retirement is therefore
//! a write-ahead catalog transaction, not a recursive delete:
//!
//! `intent -> renamed -> deleting -> retired`
//!
//! The same-volume rename is the authority boundary. Once `deleting` is
//! durable, an interrupted `remove_dir_all` resumes against only the unique
//! bound tombstone. Any identity, path, inventory, Git, or kernel mismatch
//! preserves remaining bytes and refuses with a cause-specific error.

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use calyx_core::CalyxError;
use serde::Serialize;
use serde_json::{Value, json};

use crate::catalog::FleetCatalog;
use crate::clone_farm::{git_capture, integrity_gate, same_remote, target_dir};
use crate::compose::{FLEET_KERNEL_REPORT_KIND, load_repo_kernel, read_fleet_kernel};
use crate::record::{FleetRepoRow, SourceRetirement, SourceRetirementStage};
use crate::state::RepoState;

/// A retirement precondition or durable-stage readback failed.
pub const ASTRO_FLEET_SOURCE_RETIREMENT_REFUSED: &str = "ASTRO_FLEET_SOURCE_RETIREMENT_REFUSED";
/// One or more repositories in a retirement pass refused.
pub const ASTRO_FLEET_SOURCE_RETIREMENT_INCOMPLETE: &str =
    "ASTRO_FLEET_SOURCE_RETIREMENT_INCOMPLETE";

/// Inputs shared by one source-retirement pass.
#[derive(Clone, Debug, Serialize)]
pub struct RetirementConfig {
    /// Clone farm root containing `<owner>__<repo>` checkouts.
    pub farm_root: PathBuf,
    /// Per-repo durable store root.
    pub store_root: PathBuf,
    /// Cumulative fleet scope that must already contain every retired repo.
    pub scope: String,
    /// Mutation time in Unix seconds.
    pub at_unix_secs: u64,
}

/// Persisted pass report plus the fail-closed refusal a direct CLI caller must
/// surface. Growth cycles retain the report and count the refusal.
pub struct RetirementPassOutcome {
    /// Readback-backed report.
    pub report: Value,
    /// Number of refused repositories.
    pub failed: usize,
    /// Pass-level refusal when `failed > 0`.
    pub refusal: Option<CalyxError>,
}

#[derive(Clone, Debug)]
struct KernelBinding {
    repo_members_hash: String,
    fleet_compose_input_hash: String,
    fleet_members_hash: String,
}

#[derive(Clone, Debug)]
struct Inventory {
    hash: String,
    entries: u64,
    bytes: u64,
}

#[derive(Clone, Debug)]
struct InventoryEntry {
    relative: String,
    kind: &'static str,
    bytes: u64,
    link_target: Option<String>,
}

/// Retires explicitly named repositories, persisting a pass report even when
/// individual repositories refuse.
pub fn run_source_retirement_pass(
    catalog: &FleetCatalog,
    config: &RetirementConfig,
    repos: &[String],
) -> Result<RetirementPassOutcome, CalyxError> {
    if config.at_unix_secs == 0 {
        return Err(refusal(
            "<pass>",
            "retirement requires a positive at_unix_secs",
        ));
    }
    if config.scope.trim().is_empty() {
        return Err(refusal(
            "<pass>",
            "retirement requires a non-empty fleet scope",
        ));
    }
    if repos.is_empty() {
        return Err(refusal(
            "<pass>",
            "retirement requires at least one explicit repository",
        ));
    }
    let unique: BTreeSet<&str> = repos.iter().map(String::as_str).collect();
    if unique.len() != repos.len() {
        return Err(refusal(
            "<pass>",
            "retirement repository list contains duplicates",
        ));
    }

    let started = std::time::Instant::now();
    let all_rows = catalog.query(None, None)?;
    let mut outcomes = Vec::with_capacity(repos.len());
    let mut failed = 0_usize;
    for name in repos {
        let Some(row) = all_rows
            .iter()
            .find(|candidate| candidate.record.full_name == *name)
        else {
            failed += 1;
            outcomes.push(json!({
                "full_name": name,
                "outcome": "refused",
                "code": crate::catalog::ASTRO_FLEET_RECORD_MISSING,
                "detail": "repository is not in the fleet catalog",
            }));
            continue;
        };
        match retire_one(catalog, config, row) {
            Ok(outcome) => outcomes.push(outcome),
            Err(error) => {
                failed += 1;
                outcomes.push(json!({
                    "full_name": name,
                    "github_id": row.record.github_id,
                    "outcome": "refused",
                    "code": error.code,
                    "detail": error.message,
                    "remediation": error.remediation,
                }));
            }
        }
    }

    let run_id = format!(
        "source-retire-{}-{}",
        config.at_unix_secs,
        std::process::id()
    );
    let report = json!({
        "run_id": run_id,
        "kind": "source-retirement",
        "config": config,
        "counts": {
            "requested": repos.len(),
            "completed": repos.len() - failed,
            "failed": failed,
        },
        "outcomes": outcomes,
        "wall_secs": started.elapsed().as_secs_f64(),
    });
    let report_bytes = serde_json::to_vec_pretty(&report).expect("retirement report serializes");
    let report_path = config
        .farm_root
        .join("runs")
        .join("source-retirements")
        .join("passes")
        .join(format!("{run_id}.json"));
    write_durable_exact(&report_path, &report_bytes)?;
    let summary = serde_json::to_vec(&json!({
        "event": "fleet_source_retirement_run",
        "run_id": run_id,
        "requested": repos.len(),
        "completed": repos.len() - failed,
        "failed": failed,
        "report_file": report_path.display().to_string(),
    }))
    .expect("retirement report summary serializes");
    let (commit_seq, ledger_seq) =
        catalog.record_run_report(&run_id, report_bytes.clone(), summary)?;
    let readback = catalog
        .read_run_report(&run_id)?
        .ok_or_else(|| refusal("<pass>", "retirement report absent after catalog commit"))?;
    if readback.report_bytes != report_bytes {
        return Err(refusal(
            "<pass>",
            "retirement report bytes diverged on independent catalog readback",
        ));
    }
    let mut report = report;
    report["report_file"] = json!(report_path.display().to_string());
    report["commit_seq"] = json!(commit_seq);
    report["ledger_seq"] = json!(ledger_seq);
    report["catalog_report_readback"] = json!("byte_identical");
    let pass_refusal = (failed > 0).then(|| CalyxError {
        code: ASTRO_FLEET_SOURCE_RETIREMENT_INCOMPLETE,
        message: format!(
            "source-retirement pass {run_id} refused {failed}/{} repositories; report {}",
            repos.len(),
            report_path.display()
        ),
        remediation: "inspect each cause-specific outcome; preserve any pending tombstone and resume only its exact transaction",
    });
    Ok(RetirementPassOutcome {
        report,
        failed,
        refusal: pass_refusal,
    })
}

fn retire_one(
    catalog: &FleetCatalog,
    config: &RetirementConfig,
    observed: &FleetRepoRow,
) -> Result<Value, CalyxError> {
    let name = observed.record.full_name.as_str();
    let row = catalog.get_by_identity(observed.record.github_id, name)?;
    if row.state != RepoState::Kerneled {
        return Err(refusal(
            name,
            &format!(
                "state {} is not kerneled; source is still required by the pipeline",
                row.state.as_str()
            ),
        ));
    }
    if let Some(transaction) = &row.source_retirement {
        match transaction.stage {
            SourceRetirementStage::Intent
            | SourceRetirementStage::Renamed
            | SourceRetirementStage::Deleting => {
                return resume_transaction(catalog, config, &row, transaction.clone(), true);
            }
            SourceRetirementStage::Retired => {
                return readback_retired(catalog, config, &row, transaction);
            }
            SourceRetirementStage::Rehydrated => {}
        }
    }

    let source = row
        .clone_path
        .as_deref()
        .ok_or_else(|| refusal(name, "kerneled row has no clone_path and is not retired"))?;
    let clone_bytes = row
        .clone_bytes
        .ok_or_else(|| refusal(name, "kerneled row has no measured clone_bytes"))?;
    let head = row
        .head_commit_hash
        .as_deref()
        .ok_or_else(|| refusal(name, "kerneled row has no head_commit_hash"))?;
    if row.indexed_commit_hash.as_deref() != Some(head) {
        return Err(refusal(
            name,
            "indexed_commit_hash differs from clone HEAD; refresh the kernel before retirement",
        ));
    }
    let source_path = PathBuf::from(source);
    let expected_source = target_dir(&config.farm_root, name);
    if source_path != expected_source {
        return Err(refusal(
            name,
            &format!(
                "catalog clone_path {} differs from canonical farm target {}",
                source_path.display(),
                expected_source.display()
            ),
        ));
    }
    if !source_path.is_dir() {
        return Err(refusal(
            name,
            &format!("source checkout {} is absent", source_path.display()),
        ));
    }
    verify_git(&row, &source_path)?;
    let inventory = inventory(&source_path)?;
    if inventory.bytes != clone_bytes {
        return Err(refusal(
            name,
            &format!(
                "strict measured source bytes {} differ from catalog clone_bytes {clone_bytes}",
                inventory.bytes
            ),
        ));
    }
    let binding = verify_kernel_binding(catalog, &config.store_root, &config.scope, &row, None)?;
    let transaction_id = transaction_id(
        config.at_unix_secs,
        row.record.github_id,
        head,
        &inventory.hash,
    );
    let tombstone =
        source_path.with_file_name(format!(".astrolabe-source-retirement-{transaction_id}"));
    if tombstone.try_exists().map_err(|error| {
        refusal(
            name,
            &format!("cannot inspect tombstone {}: {error}", tombstone.display()),
        )
    })? {
        return Err(refusal(
            name,
            &format!(
                "new transaction tombstone already exists: {}",
                tombstone.display()
            ),
        ));
    }
    let transaction = SourceRetirement {
        transaction_id,
        stage: SourceRetirementStage::Intent,
        requested_at_unix_secs: config.at_unix_secs,
        completed_at_unix_secs: None,
        source_path: source_path.display().to_string(),
        tombstone_path: tombstone.display().to_string(),
        head_commit_hash: head.to_string(),
        pushed_at: row.record.pushed_at.clone(),
        clone_bytes,
        inventory_hash: inventory.hash,
        inventory_entries: inventory.entries,
        repo_members_hash: binding.repo_members_hash,
        fleet_scope: config.scope.clone(),
        fleet_compose_input_hash: binding.fleet_compose_input_hash,
        fleet_members_hash: binding.fleet_members_hash,
    };
    catalog.begin_source_retirement(row.record.github_id, name, transaction.clone())?;
    resume_transaction(catalog, config, &row, transaction, false)
}

fn resume_transaction(
    catalog: &FleetCatalog,
    config: &RetirementConfig,
    row: &FleetRepoRow,
    mut transaction: SourceRetirement,
    resumed: bool,
) -> Result<Value, CalyxError> {
    let name = row.record.full_name.as_str();
    let source = PathBuf::from(&transaction.source_path);
    let tombstone = PathBuf::from(&transaction.tombstone_path);
    let expected_source = target_dir(&config.farm_root, name);
    if source != expected_source || tombstone.parent() != source.parent() {
        return Err(refusal(
            name,
            "durable transaction paths do not bind the canonical source and same parent",
        ));
    }
    if transaction.fleet_scope != config.scope {
        return Err(refusal(
            name,
            &format!(
                "pending transaction scope {:?} differs from requested {:?}",
                transaction.fleet_scope, config.scope
            ),
        ));
    }
    let _binding = verify_kernel_binding(
        catalog,
        &config.store_root,
        &config.scope,
        row,
        Some(&transaction.repo_members_hash),
    )?;
    let intent_path = transaction_dir(config, &transaction).join("intent.json");
    let mut intent_record = transaction.clone();
    intent_record.stage = SourceRetirementStage::Intent;
    intent_record.completed_at_unix_secs = None;
    let intent_bytes =
        serde_json::to_vec_pretty(&intent_record).expect("source retirement intent serializes");
    write_durable_exact(&intent_path, &intent_bytes)?;

    if transaction.stage == SourceRetirementStage::Intent {
        let source_exists = try_exists(name, &source)?;
        let tombstone_exists = try_exists(name, &tombstone)?;
        match (source_exists, tombstone_exists) {
            (true, false) => {
                verify_git(row, &source)?;
                verify_inventory(name, &source, &transaction)?;
                fs::rename(&source, &tombstone).map_err(|error| {
                    refusal(
                        name,
                        &format!(
                            "same-volume rename {} -> {} failed: {error}",
                            source.display(),
                            tombstone.display()
                        ),
                    )
                })?;
                if try_exists(name, &source)? || !try_exists(name, &tombstone)? {
                    return Err(refusal(
                        name,
                        "rename returned but source/tombstone namespace readback is wrong",
                    ));
                }
                verify_inventory(name, &tombstone, &transaction)?;
            }
            (false, true) => {
                verify_inventory(name, &tombstone, &transaction)?;
            }
            (true, true) => {
                return Err(refusal(
                    name,
                    "both source and tombstone exist at intent stage",
                ));
            }
            (false, false) => {
                return Err(refusal(
                    name,
                    "source and tombstone are both absent before renamed stage became durable",
                ));
            }
        }
        catalog.advance_source_retirement(
            row.record.github_id,
            name,
            &transaction.transaction_id,
            SourceRetirementStage::Intent,
            SourceRetirementStage::Renamed,
            config.at_unix_secs,
        )?;
        transaction.stage = SourceRetirementStage::Renamed;
    }

    if transaction.stage == SourceRetirementStage::Renamed {
        if try_exists(name, &source)? || !try_exists(name, &tombstone)? {
            return Err(refusal(
                name,
                "renamed stage requires source absent and tombstone present",
            ));
        }
        verify_inventory(name, &tombstone, &transaction)?;
        catalog.advance_source_retirement(
            row.record.github_id,
            name,
            &transaction.transaction_id,
            SourceRetirementStage::Renamed,
            SourceRetirementStage::Deleting,
            config.at_unix_secs,
        )?;
        transaction.stage = SourceRetirementStage::Deleting;
    }

    if transaction.stage == SourceRetirementStage::Deleting {
        if try_exists(name, &source)? {
            return Err(refusal(
                name,
                "source path reappeared after deletion authority became durable",
            ));
        }
        if try_exists(name, &tombstone)? {
            fs::remove_dir_all(&tombstone).map_err(|error| {
                refusal(
                    name,
                    &format!(
                        "bound tombstone deletion was incomplete and remains resumable at {}: {error}",
                        tombstone.display()
                    ),
                )
            })?;
        }
        if try_exists(name, &source)? || try_exists(name, &tombstone)? {
            return Err(refusal(
                name,
                "source or tombstone still exists after deletion returned",
            ));
        }
        catalog.finalize_source_retirement(
            row.record.github_id,
            name,
            &transaction.transaction_id,
            config.at_unix_secs,
        )?;
        transaction.stage = SourceRetirementStage::Retired;
        transaction.completed_at_unix_secs = Some(config.at_unix_secs);
    }

    let final_row = catalog.get_by_identity(row.record.github_id, name)?;
    let final_transaction = final_row
        .source_retirement
        .as_ref()
        .ok_or_else(|| refusal(name, "final row lost the retirement transaction"))?;
    if final_transaction.transaction_id != transaction.transaction_id
        || final_transaction.stage != SourceRetirementStage::Retired
        || final_row.clone_path.is_some()
        || final_row.clone_bytes.is_some()
        || try_exists(name, &source)?
        || try_exists(name, &tombstone)?
    {
        return Err(refusal(
            name,
            "final catalog and filesystem readback does not prove retirement",
        ));
    }
    let post_binding = verify_kernel_binding(
        catalog,
        &config.store_root,
        &config.scope,
        &final_row,
        Some(&transaction.repo_members_hash),
    )?;
    let completion_path = persist_completion(config, &final_row, final_transaction)?;
    Ok(json!({
        "full_name": name,
        "github_id": row.record.github_id,
        "outcome": if resumed { "recovered_and_retired" } else { "retired" },
        "transaction_id": transaction.transaction_id,
        "source_path": source.display().to_string(),
        "tombstone_path": tombstone.display().to_string(),
        "source_absent": true,
        "tombstone_absent": true,
        "clone_bytes_reclaimed": transaction.clone_bytes,
        "inventory_hash": transaction.inventory_hash,
        "inventory_entries": transaction.inventory_entries,
        "repo_members_hash": transaction.repo_members_hash,
        "fleet_scope": transaction.fleet_scope,
        "fleet_compose_input_hash_at_intent": transaction.fleet_compose_input_hash,
        "fleet_compose_input_hash_current": post_binding.fleet_compose_input_hash,
        "fleet_members_hash_at_intent": transaction.fleet_members_hash,
        "fleet_members_hash_current": post_binding.fleet_members_hash,
        "completion_file": completion_path.display().to_string(),
        "completion_readback": "byte_identical",
    }))
}

fn readback_retired(
    catalog: &FleetCatalog,
    config: &RetirementConfig,
    row: &FleetRepoRow,
    transaction: &SourceRetirement,
) -> Result<Value, CalyxError> {
    let name = row.record.full_name.as_str();
    if transaction.fleet_scope != config.scope {
        return Err(refusal(
            name,
            &format!(
                "retired transaction scope {:?} differs from requested {:?}",
                transaction.fleet_scope, config.scope
            ),
        ));
    }
    if row.clone_path.is_some()
        || row.clone_bytes.is_some()
        || try_exists(name, Path::new(&transaction.source_path))?
        || try_exists(name, Path::new(&transaction.tombstone_path))?
    {
        return Err(refusal(
            name,
            "retired row disagrees with live clone facts or filesystem namespace",
        ));
    }
    let binding = verify_kernel_binding(
        catalog,
        &config.store_root,
        &config.scope,
        row,
        Some(&transaction.repo_members_hash),
    )?;
    // Catalog finalization is the source of truth. A process can terminate
    // after that commit and before publishing the external completion receipt;
    // an idempotent readback must close that exact crash window by recreating
    // only the byte-identical receipt bound to the retired transaction.
    let completion_path = persist_completion(config, row, transaction)?;
    Ok(json!({
        "full_name": name,
        "github_id": row.record.github_id,
        "outcome": "already_retired",
        "transaction_id": transaction.transaction_id,
        "source_absent": true,
        "tombstone_absent": true,
        "repo_members_hash": binding.repo_members_hash,
        "fleet_compose_input_hash_current": binding.fleet_compose_input_hash,
        "fleet_members_hash_current": binding.fleet_members_hash,
        "completion_file": completion_path.display().to_string(),
        "completion_readback": "byte_identical",
    }))
}

fn persist_completion(
    config: &RetirementConfig,
    row: &FleetRepoRow,
    transaction: &SourceRetirement,
) -> Result<PathBuf, CalyxError> {
    let name = row.record.full_name.as_str();
    if transaction.stage != SourceRetirementStage::Retired
        || transaction.completed_at_unix_secs.is_none()
        || row.clone_path.is_some()
        || row.clone_bytes.is_some()
    {
        return Err(refusal(
            name,
            "completion receipt requires a finalized retired row",
        ));
    }
    let completion = json!({
        "schema": "astrolabe.source-retirement.completion.v1",
        "transaction": transaction,
        "source_absent": true,
        "tombstone_absent": true,
        "catalog_clone_path": row.clone_path,
        "catalog_clone_bytes": row.clone_bytes,
        "repo_members_hash": transaction.repo_members_hash,
        "fleet_compose_input_hash_at_retirement": transaction.fleet_compose_input_hash,
        "fleet_members_hash_at_retirement": transaction.fleet_members_hash,
    });
    let completion_bytes =
        serde_json::to_vec_pretty(&completion).expect("retirement completion serializes");
    let completion_path = transaction_dir(config, transaction).join("completion.json");
    write_durable_exact(&completion_path, &completion_bytes)?;
    let persisted_completion = fs::read(&completion_path).map_err(|error| {
        refusal(
            name,
            &format!(
                "cannot read completion {}: {error}",
                completion_path.display()
            ),
        )
    })?;
    if persisted_completion != completion_bytes {
        return Err(refusal(
            name,
            "completion file diverged on independent readback",
        ));
    }
    Ok(completion_path)
}

fn verify_git(row: &FleetRepoRow, source: &Path) -> Result<(), CalyxError> {
    let name = row.record.full_name.as_str();
    let head = integrity_gate(source)
        .map_err(|detail| refusal(name, &format!("Git integrity gate failed: {detail}")))?;
    if Some(head.as_str()) != row.head_commit_hash.as_deref()
        || Some(head.as_str()) != row.indexed_commit_hash.as_deref()
    {
        return Err(refusal(
            name,
            &format!(
                "Git HEAD {head} differs from catalog head/index grounding {:?}/{:?}",
                row.head_commit_hash, row.indexed_commit_hash
            ),
        ));
    }
    let (ok, remote, stderr) = git_capture(&["remote", "get-url", "origin"], source)?;
    if !ok || !same_remote(&remote, &row.record.clone_url) {
        return Err(refusal(
            name,
            &format!(
                "Git origin mismatch: command_ok={ok}, actual={remote:?}, expected={:?}, stderr={stderr}",
                row.record.clone_url
            ),
        ));
    }
    Ok(())
}

fn verify_kernel_binding(
    catalog: &FleetCatalog,
    store_root: &Path,
    scope: &str,
    row: &FleetRepoRow,
    expected_repo_hash: Option<&str>,
) -> Result<KernelBinding, CalyxError> {
    let name = row.record.full_name.as_str();
    let project = name.replace('/', "__");
    let repo = load_repo_kernel(store_root, &project)?
        .ok_or_else(|| refusal(name, "per-repo persisted kernel is absent"))?;
    if let Some(expected) = expected_repo_hash
        && repo.members_hash != expected
    {
        return Err(refusal(
            name,
            &format!(
                "per-repo members hash {} differs from durable retirement hash {expected}",
                repo.members_hash
            ),
        ));
    }
    let (fleet_summary, _fleet_raw) = read_fleet_kernel(catalog, scope)?;
    let sidecar_bytes = catalog
        .read_fleet_report(FLEET_KERNEL_REPORT_KIND, scope)?
        .ok_or_else(|| refusal(name, "fleet-kernel sidecar is absent"))?;
    let sidecar: Value = serde_json::from_slice(&sidecar_bytes).map_err(|error| {
        refusal(
            name,
            &format!("fleet-kernel sidecar does not parse: {error}"),
        )
    })?;
    let repo_claim = sidecar["repos"]
        .as_array()
        .and_then(|repos| {
            repos
                .iter()
                .find(|claim| claim["project"].as_str() == Some(project.as_str()))
        })
        .ok_or_else(|| {
            refusal(
                name,
                &format!("fleet scope {scope:?} does not include project {project}"),
            )
        })?;
    if repo_claim["members_hash"].as_str() != Some(repo.members_hash.as_str()) {
        return Err(refusal(
            name,
            "fleet sidecar repo members hash differs from the physical per-repo kernel",
        ));
    }
    let fleet_members_hash = fleet_summary["members_hash_persisted"]
        .as_str()
        .ok_or_else(|| {
            refusal(
                name,
                "fleet kernel readback carries no persisted members hash",
            )
        })?
        .to_string();
    if sidecar["kernel"]["members_hash"].as_str() != Some(fleet_members_hash.as_str()) {
        return Err(refusal(
            name,
            "fleet sidecar kernel hash differs from the physical fleet artifact",
        ));
    }
    let compose_input_hash = sidecar["compose_input_hash"]
        .as_str()
        .ok_or_else(|| refusal(name, "fleet sidecar carries no compose_input_hash"))?
        .to_string();
    let chain = astrolabe_ingest::verify_chain(catalog.vault()).map_err(|error| {
        refusal(
            name,
            &format!("catalog ledger verification failed: {error}"),
        )
    })?;
    if !chain.is_intact() {
        return Err(refusal(
            name,
            &format!(
                "catalog ledger chain is {} at {:?}",
                chain.status, chain.at_seq
            ),
        ));
    }
    Ok(KernelBinding {
        repo_members_hash: repo.members_hash,
        fleet_compose_input_hash: compose_input_hash,
        fleet_members_hash,
    })
}

fn inventory(root: &Path) -> Result<Inventory, CalyxError> {
    let mut entries = Vec::new();
    collect_inventory(root, root, &mut entries)?;
    entries.sort_by(|left, right| left.relative.cmp(&right.relative));
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"astrolabe.source-retirement.inventory.v1");
    let mut bytes = 0_u64;
    for entry in &entries {
        hash_frame(&mut hasher, entry.relative.as_bytes());
        hash_frame(&mut hasher, entry.kind.as_bytes());
        hash_frame(&mut hasher, &entry.bytes.to_be_bytes());
        hash_frame(
            &mut hasher,
            entry.link_target.as_deref().unwrap_or("").as_bytes(),
        );
        if entry.kind != "directory" {
            bytes = bytes.saturating_add(entry.bytes);
        }
    }
    Ok(Inventory {
        hash: hasher.finalize().to_hex().to_string(),
        entries: entries.len() as u64,
        bytes,
    })
}

fn collect_inventory(
    root: &Path,
    directory: &Path,
    out: &mut Vec<InventoryEntry>,
) -> Result<(), CalyxError> {
    let mut children = fs::read_dir(directory)
        .map_err(|error| {
            refusal(
                &root.display().to_string(),
                &format!("cannot enumerate {}: {error}", directory.display()),
            )
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            refusal(
                &root.display().to_string(),
                &format!(
                    "cannot read an entry under {}: {error}",
                    directory.display()
                ),
            )
        })?;
    children.sort_by_key(|entry| entry.file_name());
    for entry in children {
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .expect("inventory descendants stay below root")
            .to_string_lossy()
            .replace('\\', "/");
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            refusal(
                &root.display().to_string(),
                &format!("cannot stat {}: {error}", path.display()),
            )
        })?;
        let kind = metadata.file_type();
        if kind.is_symlink() {
            let target = fs::read_link(&path).map_err(|error| {
                refusal(
                    &root.display().to_string(),
                    &format!("cannot read link {}: {error}", path.display()),
                )
            })?;
            out.push(InventoryEntry {
                relative,
                kind: "symlink",
                bytes: metadata.len(),
                link_target: Some(target.to_string_lossy().into_owned()),
            });
        } else if kind.is_dir() {
            out.push(InventoryEntry {
                relative,
                kind: "directory",
                bytes: 0,
                link_target: None,
            });
            collect_inventory(root, &path, out)?;
        } else if kind.is_file() {
            out.push(InventoryEntry {
                relative,
                kind: "file",
                bytes: metadata.len(),
                link_target: None,
            });
        } else {
            return Err(refusal(
                &root.display().to_string(),
                &format!("unsupported filesystem entry {}", path.display()),
            ));
        }
    }
    Ok(())
}

fn verify_inventory(
    name: &str,
    path: &Path,
    expected: &SourceRetirement,
) -> Result<(), CalyxError> {
    let actual = inventory(path)?;
    if actual.hash != expected.inventory_hash
        || actual.entries != expected.inventory_entries
        || actual.bytes != expected.clone_bytes
    {
        return Err(refusal(
            name,
            &format!(
                "inventory mismatch at {}: hash {}/{}, entries {}/{}, bytes {}/{}",
                path.display(),
                actual.hash,
                expected.inventory_hash,
                actual.entries,
                expected.inventory_entries,
                actual.bytes,
                expected.clone_bytes
            ),
        ));
    }
    Ok(())
}

fn transaction_id(at: u64, github_id: u64, head: &str, inventory_hash: &str) -> String {
    let preimage = format!("{at}\n{github_id}\n{head}\n{inventory_hash}");
    let digest = blake3::hash(preimage.as_bytes()).to_hex().to_string();
    format!("retire-{at}-{github_id}-{}", &digest[..16])
}

fn transaction_dir(config: &RetirementConfig, transaction: &SourceRetirement) -> PathBuf {
    config
        .farm_root
        .join("runs")
        .join("source-retirements")
        .join(&transaction.transaction_id)
}

fn write_durable_exact(path: &Path, bytes: &[u8]) -> Result<(), CalyxError> {
    let name = path.display().to_string();
    let parent = path
        .parent()
        .ok_or_else(|| refusal(&name, "durable record has no parent directory"))?;
    fs::create_dir_all(parent).map_err(|error| {
        refusal(
            &name,
            &format!(
                "cannot create durable record parent {}: {error}",
                parent.display()
            ),
        )
    })?;
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut file) => {
            file.write_all(bytes).map_err(|error| {
                refusal(&name, &format!("cannot write durable record: {error}"))
            })?;
            file.sync_all().map_err(|error| {
                refusal(&name, &format!("cannot flush durable record: {error}"))
            })?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = fs::read(path).map_err(|read_error| {
                refusal(
                    &name,
                    &format!("cannot read existing durable record: {read_error}"),
                )
            })?;
            if existing != bytes {
                return Err(refusal(
                    &name,
                    "existing durable record differs from the transaction bytes",
                ));
            }
        }
        Err(error) => {
            return Err(refusal(
                &name,
                &format!("cannot create durable record: {error}"),
            ));
        }
    }
    let readback = fs::read(path)
        .map_err(|error| refusal(&name, &format!("cannot read durable record: {error}")))?;
    if readback != bytes {
        return Err(refusal(
            &name,
            "durable record readback differs from bytes written",
        ));
    }
    Ok(())
}

fn hash_frame(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn try_exists(name: &str, path: &Path) -> Result<bool, CalyxError> {
    path.try_exists().map_err(|error| {
        refusal(
            name,
            &format!("cannot inspect namespace {}: {error}", path.display()),
        )
    })
}

fn refusal(name: &str, detail: &str) -> CalyxError {
    CalyxError {
        code: ASTRO_FLEET_SOURCE_RETIREMENT_REFUSED,
        message: format!("source retirement for {name} refused: {detail}"),
        remediation: "preserve source, tombstone, catalog, and kernel bytes; repair the named mismatch, then resume only the exact durable transaction",
    }
}
