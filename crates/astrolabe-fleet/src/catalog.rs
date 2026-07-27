//! The fleet catalog vault: durable repo records with a fail-closed lifecycle
//! state machine, every mutation ledger-paired and readback-verified
//! (issue #449).
//!
//! # Write-path FSV
//!
//! Every mutation commits through
//! [`AsterVault::write_cf_batch_with_ledger_entry`] — one atomic batch holding
//! the Base row and its ledger entry — and then, **before returning**,
//! independently re-reads the committed row and the ledger entry at the commit
//! snapshot and compares them field-for-field ([`ASTRO_FLEET_FSV_MISMATCH`] on
//! any divergence). A catalog mutation that cannot prove itself persisted is
//! an error, not a success.

use std::collections::BTreeMap;
use std::path::Path;
use std::str::FromStr;

use calyx_aster::cf::{ColumnFamily, base_key, ledger_key};
use calyx_aster::vault::encode::{decode_constellation_base, encode_constellation_base};
use calyx_aster::vault::{AsterVault, VaultOptions};
use calyx_core::{CalyxError, Constellation, CxId, LedgerRef, Seq, VaultId};
use calyx_ledger::{ActorId, EntryKind, RedactionPolicy, SubjectId};
use serde::Serialize;
use serde_json::json;

use crate::record::{
    FleetRepoRow, RepoRecord, SourceRetirement, SourceRetirementStage, TransitionContext,
    decode_repo_constellation, encode_repo_constellation, repo_cx_id,
};
use crate::state::{ALL_STATES, RepoState, check_transition};

/// Refusal code when a requested record is not in the catalog.
pub const ASTRO_FLEET_RECORD_MISSING: &str = "ASTRO_FLEET_RECORD_MISSING";
/// Refusal code when a stored row's identity fields disagree with its CxId.
pub const ASTRO_FLEET_IDENTITY_CONFLICT: &str = "ASTRO_FLEET_IDENTITY_CONFLICT";
/// Refusal code when quarantining without a recorded reason.
pub const ASTRO_FLEET_QUARANTINE_REASON_REQUIRED: &str = "ASTRO_FLEET_QUARANTINE_REASON_REQUIRED";
/// Refusal code when departing a repo without a recorded reason (#450).
pub const ASTRO_FLEET_DEPARTED_REASON_REQUIRED: &str = "ASTRO_FLEET_DEPARTED_REASON_REQUIRED";
/// Refusal code when the post-commit readback diverges from the claim.
pub const ASTRO_FLEET_FSV_MISMATCH: &str = "ASTRO_FLEET_FSV_MISMATCH";
/// Returned when a fleet report is recorded with an empty/invalid kind or id.
pub const ASTRO_FLEET_REPORT_INVALID: &str = "ASTRO_FLEET_REPORT_INVALID";
/// Refusal code for a transition timestamp of zero.
pub const ASTRO_FLEET_TIMESTAMP_REQUIRED: &str = "ASTRO_FLEET_TIMESTAMP_REQUIRED";
/// Refusal code for an `update_facts` call that would change nothing (#451).
pub const ASTRO_FLEET_FACTS_UNCHANGED: &str = "ASTRO_FLEET_FACTS_UNCHANGED";
/// Refusal code for a mismatched source-retirement catalog transaction.
pub const ASTRO_FLEET_SOURCE_RETIREMENT_STATE: &str = "ASTRO_FLEET_SOURCE_RETIREMENT_STATE";

/// Declared vault id of the fleet catalog (a fixed ULID so every open
/// resolves the same vault identity).
pub const FLEET_VAULT_ID: &str = "01K449FC00000000000000000A";
/// Declared vault salt of the fleet catalog.
pub const FLEET_VAULT_SALT: &[u8] = b"astrolabe-fleet-catalog:v1";
/// Ledger actor recorded for every catalog mutation.
pub const FLEET_ACTOR: &str = "astrolabe-fleet";

/// What a registration call did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegisterOutcome {
    /// New record persisted at `discovered`.
    Registered,
    /// Existing record's discovery facts were updated in place.
    Refreshed,
    /// Existing record already carried identical discovery facts; no write.
    Unchanged,
}

/// Report of one registration, including the commit it can be audited at.
#[derive(Clone, Debug, Serialize)]
pub struct RegisterReport {
    /// Content-addressed identity of the record.
    pub cx_id: CxId,
    /// What happened.
    pub outcome: RegisterOutcome,
    /// Commit sequence of the write (`None` for [`RegisterOutcome::Unchanged`]).
    pub commit_seq: Option<Seq>,
    /// Ledger entry paired with the write (`None` for unchanged).
    pub ledger_seq: Option<u64>,
}

/// Report of one lifecycle transition.
#[derive(Clone, Debug, Serialize)]
pub struct TransitionReport {
    /// Content-addressed identity of the record.
    pub cx_id: CxId,
    /// State before the transition.
    pub from: RepoState,
    /// State after the transition.
    pub to: RepoState,
    /// Commit sequence of the write.
    pub commit_seq: Seq,
    /// Ledger entry paired with the write.
    pub ledger_seq: u64,
}

/// Handle over the fleet catalog vault.
pub struct FleetCatalog {
    vault: AsterVault,
    vault_id: VaultId,
}

impl FleetCatalog {
    /// The underlying catalog vault — the persistence root for fleet-scope
    /// kernel artifacts (#456): `persist_kernel_artifact` writes its Kernel CF
    /// rows and paired Kernel ledger entry here, and `kernel-read` reads them
    /// back independently.
    pub fn vault(&self) -> &AsterVault {
        &self.vault
    }

    /// Creates or opens the fleet catalog vault rooted at `root`.
    pub fn open(root: &Path) -> Result<Self, CalyxError> {
        std::fs::create_dir_all(root).map_err(|error| CalyxError {
            code: "ASTRO_FLEET_ROOT_UNAVAILABLE",
            message: format!(
                "cannot create fleet catalog root {}: {error}",
                root.display()
            ),
            remediation: "pass a writable --root directory for the fleet catalog vault",
        })?;
        let vault_id = VaultId::from_str(FLEET_VAULT_ID).map_err(|error| CalyxError {
            code: "ASTRO_FLEET_VAULT_ID_INVALID",
            message: format!("declared fleet vault id failed to parse: {error:?}"),
            remediation: "internal defect: FLEET_VAULT_ID must be a valid ULID literal",
        })?;
        let vault = AsterVault::open(
            root,
            vault_id,
            FLEET_VAULT_SALT.to_vec(),
            VaultOptions {
                read_only: false,
                restore_ledger_hook: true,
                ..VaultOptions::default()
            },
        )?;
        Ok(Self { vault, vault_id })
    }

    /// Registers (or idempotently re-registers) a repository.
    ///
    /// A brand-new identity persists at [`RepoState::Discovered`] with an
    /// `Ingest` ledger entry. Re-registration with identical discovery facts
    /// writes nothing and reports [`RegisterOutcome::Unchanged`] with the same
    /// CxId. Re-registration with changed discovery facts (a discovery
    /// refresh: stars moved, new push, new etag) rewrites only the discovery
    /// fields — lifecycle state and timestamps are preserved — with an `Admin`
    /// ledger entry.
    pub fn register(
        &self,
        record: RepoRecord,
        at_unix_secs: u64,
    ) -> Result<RegisterReport, CalyxError> {
        record.validate()?;
        require_timestamp(at_unix_secs)?;
        let cx_id = repo_cx_id(record.github_id, &record.full_name, FLEET_VAULT_SALT);

        if let Some(mut existing) = self.try_get(cx_id)? {
            if existing.record.github_id != record.github_id
                || existing.record.full_name != record.full_name
            {
                return Err(CalyxError {
                    code: ASTRO_FLEET_IDENTITY_CONFLICT,
                    message: format!(
                        "catalog row {cx_id} holds identity {}#{} but registration computed it for {}#{}",
                        existing.record.github_id,
                        existing.record.full_name,
                        record.github_id,
                        record.full_name
                    ),
                    remediation: "the catalog vault is corrupt or the addressing scheme changed; audit the vault ledger before writing anything else",
                });
            }
            if existing.record == record {
                return Ok(RegisterReport {
                    cx_id,
                    outcome: RegisterOutcome::Unchanged,
                    commit_seq: None,
                    ledger_seq: None,
                });
            }
            let payload = serde_json::to_vec(&json!({
                "event": "fleet_repo_refreshed",
                "github_id": record.github_id,
                "full_name": record.full_name,
                "stars": record.stars,
                "state": existing.state.as_str(),
                "at_unix_secs": at_unix_secs,
            }))
            .expect("static ledger payload serializes");
            existing.record = record;
            let (commit_seq, ledger_seq) = self.commit_row(&existing, EntryKind::Admin, payload)?;
            return Ok(RegisterReport {
                cx_id,
                outcome: RegisterOutcome::Refreshed,
                commit_seq: Some(commit_seq),
                ledger_seq: Some(ledger_seq),
            });
        }

        let mut state_timestamps = BTreeMap::new();
        state_timestamps.insert(RepoState::Discovered.as_str().to_string(), at_unix_secs);
        let row = FleetRepoRow {
            cx_id,
            record,
            state: RepoState::Discovered,
            state_timestamps,
            clone_path: None,
            head_commit_hash: None,
            index_watermark: None,
            indexed_commit_hash: None,
            kernel_scope_id: None,
            quarantine_reason: None,
            departed_reason: None,
            clone_bytes: None,
            store_bytes: None,
            checkout_exclusions: Vec::new(),
            source_retirement: None,
        };
        let payload = serde_json::to_vec(&json!({
            "event": "fleet_repo_registered",
            "github_id": row.record.github_id,
            "full_name": row.record.full_name,
            "stars": row.record.stars,
            "language": row.record.language,
            "state": row.state.as_str(),
            "at_unix_secs": at_unix_secs,
        }))
        .expect("static ledger payload serializes");
        let (commit_seq, ledger_seq) = self.commit_row(&row, EntryKind::Ingest, payload)?;
        Ok(RegisterReport {
            cx_id,
            outcome: RegisterOutcome::Registered,
            commit_seq: Some(commit_seq),
            ledger_seq: Some(ledger_seq),
        })
    }

    /// Applies one lifecycle transition, fail-closed on any illegal edge.
    pub fn transition(
        &self,
        github_id: u64,
        full_name: &str,
        to: RepoState,
        ctx: TransitionContext,
    ) -> Result<TransitionReport, CalyxError> {
        require_timestamp(ctx.at_unix_secs)?;
        let cx_id = repo_cx_id(github_id, full_name, FLEET_VAULT_SALT);
        let mut row = self.get(cx_id)?;
        let from = row.state;
        check_transition(from, to)?;
        if to == RepoState::Quarantined
            && ctx
                .quarantine_reason
                .as_deref()
                .is_none_or(|reason| reason.trim().is_empty())
        {
            return Err(CalyxError {
                code: ASTRO_FLEET_QUARANTINE_REASON_REQUIRED,
                message: format!("quarantining {full_name} requires a non-empty quarantine_reason"),
                remediation: "pass the concrete failure being quarantined for (e.g. clone integrity failure, license gate)",
            });
        }
        if to == RepoState::Departed
            && ctx
                .departed_reason
                .as_deref()
                .is_none_or(|reason| reason.trim().is_empty())
        {
            return Err(CalyxError {
                code: ASTRO_FLEET_DEPARTED_REASON_REQUIRED,
                message: format!("departing {full_name} requires a non-empty departed_reason"),
                remediation: "pass why the repo left the enumeration (deleted, private, renamed, below star floor)",
            });
        }

        if let Some(clone_path) = ctx.clone_path {
            row.clone_path = Some(clone_path);
        }
        if let Some(head) = ctx.head_commit_hash {
            row.head_commit_hash = Some(head);
        }
        if let Some(watermark) = ctx.index_watermark {
            row.index_watermark = Some(watermark);
        }
        if let Some(grounded) = ctx.indexed_commit_hash {
            row.indexed_commit_hash = Some(grounded);
        }
        if let Some(scope) = ctx.kernel_scope_id {
            row.kernel_scope_id = Some(scope);
        }
        if let Some(reason) = ctx.quarantine_reason.clone() {
            row.quarantine_reason = Some(reason);
        }
        if let Some(reason) = ctx.departed_reason.clone() {
            row.departed_reason = Some(reason);
        }
        if let Some(bytes) = ctx.clone_bytes {
            row.clone_bytes = Some(bytes);
        }
        if let Some(bytes) = ctx.store_bytes {
            row.store_bytes = Some(bytes);
        }
        if let Some(exclusions) = ctx.checkout_exclusions {
            row.checkout_exclusions = exclusions;
        }
        if from == RepoState::Departed && to == RepoState::Discovered {
            // Reappearance: the departure reason described the previous
            // absence; the ledger keeps that history, the live row does not.
            row.departed_reason = None;
        }
        if from == RepoState::Quarantined && to == RepoState::Discovered {
            // Retry release (#457): the quarantine reason described the
            // failure being retried; the ledger keeps that history.
            row.quarantine_reason = None;
        }
        row.state = to;
        row.state_timestamps
            .insert(to.as_str().to_string(), ctx.at_unix_secs);

        let mut payload = json!({
            "event": "fleet_state_transition",
            "github_id": github_id,
            "full_name": full_name,
            "from_state": from.as_str(),
            "to_state": to.as_str(),
            "at_unix_secs": ctx.at_unix_secs,
        });
        if let Some(head) = &row.head_commit_hash {
            payload["head_commit_hash"] = json!(head);
        }
        if let Some(grounded) = &row.indexed_commit_hash {
            payload["indexed_commit_hash"] = json!(grounded);
        }
        if let Some(reason) = &row.quarantine_reason {
            payload["quarantine_reason"] = json!(reason);
        }
        if let Some(reason) = &row.departed_reason {
            payload["departed_reason"] = json!(reason);
        }
        if let Some(bytes) = row.clone_bytes {
            payload["clone_bytes"] = json!(bytes);
        }
        if let Some(bytes) = row.store_bytes {
            payload["store_bytes"] = json!(bytes);
        }
        if !row.checkout_exclusions.is_empty() {
            payload["checkout_exclusions"] = json!({
                "count": row.checkout_exclusions.len(),
                "paths": row.checkout_exclusions,
            });
        }
        let payload = serde_json::to_vec(&payload).expect("static ledger payload serializes");
        let (commit_seq, ledger_seq) = self.commit_row(&row, EntryKind::Admin, payload)?;
        Ok(TransitionReport {
            cx_id,
            from,
            to,
            commit_seq,
            ledger_seq,
        })
    }

    /// Rewrites lifecycle facts on a record **without** changing its state
    /// (issue #451: an update fetch advances `head_commit_hash`/`clone_bytes`
    /// on a repo that stays `cloned`/`indexed`/…). Ledger-paired like every
    /// other mutation (`fleet_facts_updated`), and refused when nothing would
    /// change so no-op updates never mint ledger noise.
    pub fn update_facts(
        &self,
        github_id: u64,
        full_name: &str,
        ctx: TransitionContext,
    ) -> Result<TransitionReport, CalyxError> {
        require_timestamp(ctx.at_unix_secs)?;
        let cx_id = repo_cx_id(github_id, full_name, FLEET_VAULT_SALT);
        let mut row = self.get(cx_id)?;
        let before = row.clone();
        if let Some(clone_path) = ctx.clone_path {
            row.clone_path = Some(clone_path);
        }
        if let Some(head) = ctx.head_commit_hash {
            row.head_commit_hash = Some(head);
        }
        if let Some(watermark) = ctx.index_watermark {
            row.index_watermark = Some(watermark);
        }
        if let Some(grounded) = ctx.indexed_commit_hash {
            row.indexed_commit_hash = Some(grounded);
        }
        if let Some(scope) = ctx.kernel_scope_id {
            row.kernel_scope_id = Some(scope);
        }
        if let Some(bytes) = ctx.clone_bytes {
            row.clone_bytes = Some(bytes);
        }
        if let Some(bytes) = ctx.store_bytes {
            row.store_bytes = Some(bytes);
        }
        if let Some(exclusions) = ctx.checkout_exclusions {
            row.checkout_exclusions = exclusions;
        }
        if row == before {
            return Err(CalyxError {
                code: ASTRO_FLEET_FACTS_UNCHANGED,
                message: format!("update_facts for {full_name} would change nothing"),
                remediation: "pass at least one changed fact, or treat the repo as an explicit no-op instead of updating it",
            });
        }
        let mut payload = json!({
            "event": "fleet_facts_updated",
            "github_id": github_id,
            "full_name": full_name,
            "state": row.state.as_str(),
            "at_unix_secs": ctx.at_unix_secs,
        });
        if let Some(head) = &row.head_commit_hash {
            payload["head_commit_hash"] = json!(head);
        }
        if let Some(bytes) = row.clone_bytes {
            payload["clone_bytes"] = json!(bytes);
        }
        if let Some(bytes) = row.store_bytes {
            payload["store_bytes"] = json!(bytes);
        }
        if !row.checkout_exclusions.is_empty() {
            payload["checkout_exclusions"] = json!({
                "count": row.checkout_exclusions.len(),
                "paths": row.checkout_exclusions,
            });
        }
        let payload = serde_json::to_vec(&payload).expect("static ledger payload serializes");
        let (commit_seq, ledger_seq) = self.commit_row(&row, EntryKind::Admin, payload)?;
        Ok(TransitionReport {
            cx_id,
            from: row.state,
            to: row.state,
            commit_seq,
            ledger_seq,
        })
    }

    /// Persists the write-ahead intent for one exact post-kernel source
    /// retirement (#807). The row remains `kerneled`: its durable kernel still
    /// exists and remains a fleet-composition input.
    pub fn begin_source_retirement(
        &self,
        github_id: u64,
        full_name: &str,
        retirement: SourceRetirement,
    ) -> Result<TransitionReport, CalyxError> {
        require_timestamp(retirement.requested_at_unix_secs)?;
        if retirement.stage != SourceRetirementStage::Intent {
            return Err(source_retirement_error(
                full_name,
                format!(
                    "new transaction {} starts at {}, expected intent",
                    retirement.transaction_id,
                    retirement.stage.as_str()
                ),
            ));
        }
        let cx_id = repo_cx_id(github_id, full_name, FLEET_VAULT_SALT);
        let mut row = self.get(cx_id)?;
        if row.state != RepoState::Kerneled {
            return Err(source_retirement_error(
                full_name,
                format!("state {} is not kerneled", row.state.as_str()),
            ));
        }
        if row
            .source_retirement
            .as_ref()
            .is_some_and(|existing| existing.stage != SourceRetirementStage::Rehydrated)
        {
            return Err(source_retirement_error(
                full_name,
                "another source-retirement transaction is already durable".to_string(),
            ));
        }
        if row.clone_path.as_deref() != Some(retirement.source_path.as_str())
            || row.clone_bytes != Some(retirement.clone_bytes)
            || row.head_commit_hash.as_deref() != Some(retirement.head_commit_hash.as_str())
        {
            return Err(source_retirement_error(
                full_name,
                "intent source path, bytes, or HEAD differs from the live catalog facts"
                    .to_string(),
            ));
        }
        row.source_retirement = Some(retirement.clone());
        let payload = serde_json::to_vec(&json!({
            "event": "fleet_source_retirement_intent",
            "github_id": github_id,
            "full_name": full_name,
            "transaction_id": retirement.transaction_id,
            "stage": retirement.stage.as_str(),
            "at_unix_secs": retirement.requested_at_unix_secs,
            "source_path": retirement.source_path,
            "tombstone_path": retirement.tombstone_path,
            "head_commit_hash": retirement.head_commit_hash,
            "clone_bytes": retirement.clone_bytes,
            "inventory_hash": retirement.inventory_hash,
            "inventory_entries": retirement.inventory_entries,
            "repo_members_hash": retirement.repo_members_hash,
            "fleet_scope": retirement.fleet_scope,
            "fleet_compose_input_hash": retirement.fleet_compose_input_hash,
            "fleet_members_hash": retirement.fleet_members_hash,
        }))
        .expect("source retirement intent serializes");
        let (commit_seq, ledger_seq) = self.commit_row(&row, EntryKind::Admin, payload)?;
        Ok(TransitionReport {
            cx_id,
            from: row.state,
            to: row.state,
            commit_seq,
            ledger_seq,
        })
    }

    /// Advances an exact source-retirement transaction through its two
    /// pre-finalization stages.
    pub fn advance_source_retirement(
        &self,
        github_id: u64,
        full_name: &str,
        transaction_id: &str,
        expected: SourceRetirementStage,
        next: SourceRetirementStage,
        at_unix_secs: u64,
    ) -> Result<TransitionReport, CalyxError> {
        require_timestamp(at_unix_secs)?;
        let legal = matches!(
            (expected, next),
            (
                SourceRetirementStage::Intent,
                SourceRetirementStage::Renamed
            ) | (
                SourceRetirementStage::Renamed,
                SourceRetirementStage::Deleting
            )
        );
        if !legal {
            return Err(source_retirement_error(
                full_name,
                format!(
                    "illegal retirement stage advance {} -> {}",
                    expected.as_str(),
                    next.as_str()
                ),
            ));
        }
        let cx_id = repo_cx_id(github_id, full_name, FLEET_VAULT_SALT);
        let mut row = self.get(cx_id)?;
        let retirement = row.source_retirement.as_mut().ok_or_else(|| {
            source_retirement_error(full_name, "row has no retirement transaction".to_string())
        })?;
        if retirement.transaction_id != transaction_id || retirement.stage != expected {
            return Err(source_retirement_error(
                full_name,
                format!(
                    "expected transaction {transaction_id} at {}, found {} at {}",
                    expected.as_str(),
                    retirement.transaction_id,
                    retirement.stage.as_str()
                ),
            ));
        }
        retirement.stage = next;
        let payload = serde_json::to_vec(&json!({
            "event": "fleet_source_retirement_stage",
            "github_id": github_id,
            "full_name": full_name,
            "transaction_id": transaction_id,
            "from_stage": expected.as_str(),
            "to_stage": next.as_str(),
            "at_unix_secs": at_unix_secs,
        }))
        .expect("source retirement stage serializes");
        let (commit_seq, ledger_seq) = self.commit_row(&row, EntryKind::Admin, payload)?;
        Ok(TransitionReport {
            cx_id,
            from: row.state,
            to: row.state,
            commit_seq,
            ledger_seq,
        })
    }

    /// Finalizes exact source/tombstone absence, clears only live clone facts,
    /// and retains the full retirement evidence on the row.
    pub fn finalize_source_retirement(
        &self,
        github_id: u64,
        full_name: &str,
        transaction_id: &str,
        at_unix_secs: u64,
    ) -> Result<TransitionReport, CalyxError> {
        require_timestamp(at_unix_secs)?;
        let cx_id = repo_cx_id(github_id, full_name, FLEET_VAULT_SALT);
        let mut row = self.get(cx_id)?;
        let retirement = row.source_retirement.as_mut().ok_or_else(|| {
            source_retirement_error(full_name, "row has no retirement transaction".to_string())
        })?;
        if retirement.transaction_id != transaction_id
            || retirement.stage != SourceRetirementStage::Deleting
        {
            return Err(source_retirement_error(
                full_name,
                format!(
                    "finalize expected transaction {transaction_id} at deleting, found {} at {}",
                    retirement.transaction_id,
                    retirement.stage.as_str()
                ),
            ));
        }
        if row.clone_path.as_deref() != Some(retirement.source_path.as_str())
            || row.clone_bytes != Some(retirement.clone_bytes)
            || row.head_commit_hash.as_deref() != Some(retirement.head_commit_hash.as_str())
        {
            return Err(source_retirement_error(
                full_name,
                "live clone facts drifted after retirement intent".to_string(),
            ));
        }
        retirement.stage = SourceRetirementStage::Retired;
        retirement.completed_at_unix_secs = Some(at_unix_secs);
        row.clone_path = None;
        row.clone_bytes = None;
        let payload = serde_json::to_vec(&json!({
            "event": "fleet_source_retirement_finalized",
            "github_id": github_id,
            "full_name": full_name,
            "transaction_id": transaction_id,
            "stage": SourceRetirementStage::Retired.as_str(),
            "at_unix_secs": at_unix_secs,
            "head_commit_hash": retirement.head_commit_hash,
            "inventory_hash": retirement.inventory_hash,
            "repo_members_hash": retirement.repo_members_hash,
            "fleet_scope": retirement.fleet_scope,
            "fleet_compose_input_hash": retirement.fleet_compose_input_hash,
            "fleet_members_hash": retirement.fleet_members_hash,
        }))
        .expect("source retirement finalization serializes");
        let (commit_seq, ledger_seq) = self.commit_row(&row, EntryKind::Admin, payload)?;
        Ok(TransitionReport {
            cx_id,
            from: row.state,
            to: row.state,
            commit_seq,
            ledger_seq,
        })
    }

    /// Restores live clone facts on an exactly retired kernel without
    /// changing its durable lifecycle state or discarding kernel history.
    pub fn rehydrate_source(
        &self,
        github_id: u64,
        full_name: &str,
        at_unix_secs: u64,
        clone_path: String,
        head_commit_hash: String,
        clone_bytes: u64,
        checkout_exclusions: Vec<String>,
    ) -> Result<TransitionReport, CalyxError> {
        require_timestamp(at_unix_secs)?;
        let cx_id = repo_cx_id(github_id, full_name, FLEET_VAULT_SALT);
        let mut row = self.get(cx_id)?;
        let retirement = row.source_retirement.as_mut().ok_or_else(|| {
            source_retirement_error(full_name, "row has no retirement transaction".to_string())
        })?;
        if row.state != RepoState::Kerneled
            || retirement.stage != SourceRetirementStage::Retired
            || row.clone_path.is_some()
            || row.clone_bytes.is_some()
        {
            return Err(source_retirement_error(
                full_name,
                format!(
                    "rehydration requires a kerneled, retired row with no live clone facts; state={}, stage={}, clone_path_present={}, clone_bytes_present={}",
                    row.state.as_str(),
                    retirement.stage.as_str(),
                    row.clone_path.is_some(),
                    row.clone_bytes.is_some()
                ),
            ));
        }
        retirement.stage = SourceRetirementStage::Rehydrated;
        row.clone_path = Some(clone_path.clone());
        row.head_commit_hash = Some(head_commit_hash.clone());
        row.clone_bytes = Some(clone_bytes);
        row.checkout_exclusions = checkout_exclusions;
        let payload = serde_json::to_vec(&json!({
            "event": "fleet_source_rehydrated",
            "github_id": github_id,
            "full_name": full_name,
            "transaction_id": retirement.transaction_id,
            "stage": SourceRetirementStage::Rehydrated.as_str(),
            "at_unix_secs": at_unix_secs,
            "clone_path": clone_path,
            "head_commit_hash": head_commit_hash,
            "clone_bytes": clone_bytes,
        }))
        .expect("source rehydration serializes");
        let (commit_seq, ledger_seq) = self.commit_row(&row, EntryKind::Admin, payload)?;
        Ok(TransitionReport {
            cx_id,
            from: row.state,
            to: row.state,
            commit_seq,
            ledger_seq,
        })
    }

    /// Reads one record by content-addressed id, or `None` if absent.
    pub fn try_get(&self, cx_id: CxId) -> Result<Option<FleetRepoRow>, CalyxError> {
        let snapshot = self.vault.latest_seq();
        let Some(bytes) = self
            .vault
            .read_cf_at(snapshot, ColumnFamily::Base, &base_key(cx_id))?
        else {
            return Ok(None);
        };
        let constellation = decode_constellation_base(&bytes)?;
        Ok(Some(decode_repo_constellation(&constellation)?))
    }

    /// Reads one record by content-addressed id, refusing if absent.
    pub fn get(&self, cx_id: CxId) -> Result<FleetRepoRow, CalyxError> {
        self.try_get(cx_id)?.ok_or_else(|| CalyxError {
            code: ASTRO_FLEET_RECORD_MISSING,
            message: format!("no fleet catalog record for {cx_id}"),
            remediation: "register the repository first (state=discovered), then transition it",
        })
    }

    /// Reads one record by repository identity, refusing if absent.
    pub fn get_by_identity(
        &self,
        github_id: u64,
        full_name: &str,
    ) -> Result<FleetRepoRow, CalyxError> {
        self.get(repo_cx_id(github_id, full_name, FLEET_VAULT_SALT))
    }

    /// Lists records, optionally filtered by state and/or language, sorted by
    /// `full_name` for deterministic output. An empty catalog yields an empty
    /// list — an explicit zero, never an error.
    pub fn query(
        &self,
        state: Option<RepoState>,
        language: Option<&str>,
    ) -> Result<Vec<FleetRepoRow>, CalyxError> {
        let snapshot = self.vault.latest_seq();
        let mut rows = Vec::new();
        for (_key, bytes) in self.vault.scan_cf_at(snapshot, ColumnFamily::Base)? {
            let row = decode_repo_constellation(&decode_constellation_base(&bytes)?)?;
            if let Some(state) = state
                && row.state != state
            {
                continue;
            }
            if let Some(language) = language
                && !row.record.language.eq_ignore_ascii_case(language)
            {
                continue;
            }
            rows.push(row);
        }
        rows.sort_by(|left, right| left.record.full_name.cmp(&right.record.full_name));
        Ok(rows)
    }

    /// Per-state record counts with an explicit zero for every state.
    pub fn counts_by_state(&self) -> Result<BTreeMap<&'static str, u64>, CalyxError> {
        let mut counts: BTreeMap<&'static str, u64> =
            ALL_STATES.iter().map(|state| (state.as_str(), 0)).collect();
        for row in self.query(None, None)? {
            *counts
                .get_mut(row.state.as_str())
                .expect("ALL_STATES covers every parsed state") += 1;
        }
        Ok(counts)
    }

    /// Persists a discovery run report (#450): the full report bytes as a
    /// Blob-CF row under the reserved `fleetrun:` keyspace, paired with an
    /// `Admin` ledger entry carrying `summary_payload`, committed atomically
    /// and independently read back before returning.
    ///
    /// Returns `(commit_seq, ledger_seq)`.
    pub fn record_run_report(
        &self,
        run_id: &str,
        report_bytes: Vec<u8>,
        summary_payload: Vec<u8>,
    ) -> Result<(Seq, u64), CalyxError> {
        RedactionPolicy::check_payload(&summary_payload)?;
        let key = run_report_key(run_id);
        let subject = SubjectId::Query(format!("fleet-discovery-run:{run_id}").into_bytes());
        let actor = ActorId::Service(FLEET_ACTOR.to_string());
        let commit_seq = self.vault.write_cf_batch_with_ledger_entry(
            vec![(ColumnFamily::Blob, key.clone(), report_bytes.clone())],
            EntryKind::Admin,
            subject.clone(),
            summary_payload.clone(),
            actor.clone(),
        )?;
        self.vault.flush()?;

        let mismatch = |what: String| CalyxError {
            code: ASTRO_FLEET_FSV_MISMATCH,
            message: format!("fleet run report readback mismatch for {run_id}: {what}"),
            remediation: "the committed run report does not match the claim; audit the catalog vault before trusting this run",
        };
        let persisted = self
            .vault
            .read_cf_at(commit_seq, ColumnFamily::Blob, &key)?
            .ok_or_else(|| mismatch("report row absent after commit".to_string()))?;
        if persisted != report_bytes {
            return Err(mismatch(
                "report row bytes diverge from the claim".to_string(),
            ));
        }
        // The report row is not a Base constellation, so no ledger ref is
        // stamped into it; find the paired entry by scanning the ledger CF at
        // the commit snapshot for this run's subject — an independent readback.
        let mut found = None;
        for (_key, bytes) in self.vault.scan_cf_at(commit_seq, ColumnFamily::Ledger)? {
            let entry = calyx_ledger::decode(&bytes)?;
            if entry.subject == subject {
                found = Some(entry);
            }
        }
        let entry = found.ok_or_else(|| mismatch("no ledger entry for this run".to_string()))?;
        if entry.payload != summary_payload {
            return Err(mismatch(format!(
                "ledger entry {} payload diverges from the run summary",
                entry.seq
            )));
        }
        if entry.actor != actor {
            return Err(mismatch(format!(
                "ledger entry {} actor diverges from {FLEET_ACTOR}",
                entry.seq
            )));
        }
        Ok((commit_seq, entry.seq))
    }

    /// Independently reads back a persisted run report: the Blob-CF bytes under
    /// the `fleetrun:` keyspace plus the paired `Admin` ledger entry for the
    /// run's subject (`fleet-discovery-run:<run_id>`), from the latest
    /// snapshot. Returns `None` when no report row exists for `run_id`; a row
    /// without its paired ledger entry is a fail-closed mismatch, never a
    /// silent partial read.
    pub fn read_run_report(&self, run_id: &str) -> Result<Option<RunReportReadback>, CalyxError> {
        let snapshot = self.vault.latest_seq();
        let Some(bytes) =
            self.vault
                .read_cf_at(snapshot, ColumnFamily::Blob, &run_report_key(run_id))?
        else {
            return Ok(None);
        };
        let subject = SubjectId::Query(format!("fleet-discovery-run:{run_id}").into_bytes());
        let mut found = None;
        for (_key, entry_bytes) in self.vault.scan_cf_at(snapshot, ColumnFamily::Ledger)? {
            let entry = calyx_ledger::decode(&entry_bytes)?;
            if entry.subject == subject {
                found = Some(entry);
            }
        }
        let entry = found.ok_or_else(|| CalyxError {
            code: ASTRO_FLEET_FSV_MISMATCH,
            message: format!(
                "run report {run_id} has a Blob row but no paired Admin ledger entry"
            ),
            remediation: "the catalog vault violated the row+ledger pairing; audit it before trusting this run",
        })?;
        Ok(Some(RunReportReadback {
            report_bytes: bytes,
            ledger_seq: entry.seq,
            ledger_payload: entry.payload,
        }))
    }

    /// Persists a kind-scoped fleet report (#458 and later fleet artifacts):
    /// full report bytes as a Blob-CF row under the `fleetreport:v1:` keyspace,
    /// paired with an `Admin` ledger entry carrying `summary_payload`, committed
    /// atomically and independently read back before returning — the same
    /// fail-closed discipline as [`Self::record_run_report`].
    ///
    /// Returns `(commit_seq, ledger_seq)`.
    pub fn record_fleet_report(
        &self,
        kind: &str,
        report_id: &str,
        report_bytes: Vec<u8>,
        summary_payload: Vec<u8>,
    ) -> Result<(Seq, u64), CalyxError> {
        if kind.is_empty()
            || report_id.is_empty()
            || !kind
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        {
            return Err(CalyxError {
                code: ASTRO_FLEET_REPORT_INVALID,
                message: format!(
                    "fleet report kind must be non-empty kebab/snake ascii and report_id non-empty; got kind={kind:?} report_id={report_id:?}"
                ),
                remediation: "pass --kind like language-coverage and a non-empty --id",
            });
        }
        RedactionPolicy::check_payload(&summary_payload)?;
        let key = fleet_report_key(kind, report_id);
        let subject = SubjectId::Query(format!("fleet-report:{kind}:{report_id}").into_bytes());
        let actor = ActorId::Service(FLEET_ACTOR.to_string());
        let commit_seq = self.vault.write_cf_batch_with_ledger_entry(
            vec![(ColumnFamily::Blob, key.clone(), report_bytes.clone())],
            EntryKind::Admin,
            subject.clone(),
            summary_payload.clone(),
            actor.clone(),
        )?;
        self.vault.flush()?;
        let mismatch = |what: String| CalyxError {
            code: ASTRO_FLEET_FSV_MISMATCH,
            message: format!("fleet report readback mismatch for {kind}:{report_id}: {what}"),
            remediation: "the committed report does not match the claim; audit the catalog vault before trusting it",
        };
        let persisted = self
            .vault
            .read_cf_at(commit_seq, ColumnFamily::Blob, &key)?
            .ok_or_else(|| mismatch("report row absent after commit".to_string()))?;
        if persisted != report_bytes {
            return Err(mismatch(
                "report row bytes diverge from the claim".to_string(),
            ));
        }
        let mut found = None;
        for (_key, bytes) in self.vault.scan_cf_at(commit_seq, ColumnFamily::Ledger)? {
            let entry = calyx_ledger::decode(&bytes)?;
            if entry.subject == subject {
                found = Some(entry);
            }
        }
        let entry = found.ok_or_else(|| mismatch("no ledger entry for this report".to_string()))?;
        if entry.payload != summary_payload {
            return Err(mismatch(format!(
                "ledger entry {} payload diverges from the report summary",
                entry.seq
            )));
        }
        Ok((commit_seq, entry.seq))
    }

    /// Reads back a kind-scoped fleet report's bytes, or `None` if absent.
    pub fn read_fleet_report(
        &self,
        kind: &str,
        report_id: &str,
    ) -> Result<Option<Vec<u8>>, CalyxError> {
        let snapshot = self.vault.latest_seq();
        self.vault.read_cf_at(
            snapshot,
            ColumnFamily::Blob,
            &fleet_report_key(kind, report_id),
        )
    }

    /// Lists the report ids persisted under `kind`, ascending (report ids sort
    /// lexicographically, so timestamp-prefixed ids list oldest-first).
    pub fn list_fleet_reports(&self, kind: &str) -> Result<Vec<String>, CalyxError> {
        let mut prefix = fleet_report_key(kind, "");
        let marker = prefix.clone();
        prefix.truncate(marker.len());
        let snapshot = self.vault.latest_seq();
        let mut ids = Vec::new();
        for (key, _val) in self.vault.scan_cf_at(snapshot, ColumnFamily::Blob)? {
            if key.starts_with(&marker) {
                ids.push(String::from_utf8_lossy(&key[marker.len()..]).into_owned());
            }
        }
        ids.sort();
        Ok(ids)
    }

    /// Commits `row` and its ledger entry in one atomic batch, then re-reads
    /// both from the committed snapshot and compares before returning.
    fn commit_row(
        &self,
        row: &FleetRepoRow,
        kind: EntryKind,
        payload: Vec<u8>,
    ) -> Result<(Seq, u64), CalyxError> {
        RedactionPolicy::check_payload(&payload)?;
        let expected = encode_repo_constellation(self.vault_id, FLEET_VAULT_SALT, row)?;
        let base_bytes = encode_constellation_base(&expected)?;
        let subject = SubjectId::Cx(row.cx_id);
        let actor = ActorId::Service(FLEET_ACTOR.to_string());
        let commit_seq = self.vault.write_cf_batch_with_ledger_entry(
            vec![(ColumnFamily::Base, base_key(row.cx_id), base_bytes)],
            kind,
            subject.clone(),
            payload,
            actor.clone(),
        )?;
        self.vault.flush()?;
        let ledger_seq =
            self.verify_committed(row.cx_id, &expected, commit_seq, kind, &subject, &actor)?;
        Ok((commit_seq, ledger_seq))
    }

    /// Independent post-commit readback (invariant 5): the Base row must match
    /// the claim byte-for-byte (modulo the ledger ref the commit stamped), and
    /// that stamped ledger ref must resolve to a ledger entry of the expected
    /// kind/subject/actor whose hash matches.
    fn verify_committed(
        &self,
        cx_id: CxId,
        expected: &Constellation,
        commit_seq: Seq,
        kind: EntryKind,
        subject: &SubjectId,
        actor: &ActorId,
    ) -> Result<u64, CalyxError> {
        let mismatch = |what: String| CalyxError {
            code: ASTRO_FLEET_FSV_MISMATCH,
            message: format!(
                "fleet catalog readback mismatch for {cx_id} at seq {commit_seq}: {what}"
            ),
            remediation: "the committed state does not match the claim; do not trust this catalog write — audit the vault before continuing",
        };
        let bytes = self
            .vault
            .read_cf_at(commit_seq, ColumnFamily::Base, &base_key(cx_id))?
            .ok_or_else(|| mismatch("Base row absent after commit".to_string()))?;
        let mut persisted = decode_constellation_base(&bytes)?;
        // NOTE: seq 0 is a legitimate ledger seq (the first entry of a fresh
        // vault) — the stub-vs-real distinction is proven by the hash pairing
        // below, never by the seq value.
        let stamped = persisted.provenance.clone();
        persisted.provenance = LedgerRef {
            seq: 0,
            hash: [0; 32],
        };
        let normalized_expected = encode_constellation_base(expected)?;
        let normalized_persisted = encode_constellation_base(&persisted)?;
        if normalized_expected != normalized_persisted {
            return Err(mismatch(
                "persisted Base row bytes diverge from the claim".to_string(),
            ));
        }

        let ledger_bytes = self
            .vault
            .read_cf_at(commit_seq, ColumnFamily::Ledger, &ledger_key(stamped.seq))?
            .ok_or_else(|| {
                mismatch(format!(
                    "ledger entry {} referenced by the row is absent",
                    stamped.seq
                ))
            })?;
        let entry = calyx_ledger::decode(&ledger_bytes)?;
        if entry.entry_hash != stamped.hash {
            return Err(mismatch(format!(
                "ledger entry {} hash diverges from the row's ledger ref",
                stamped.seq
            )));
        }
        if entry.kind != kind {
            return Err(mismatch(format!(
                "ledger entry {} kind {:?} != expected {:?}",
                stamped.seq, entry.kind, kind
            )));
        }
        if &entry.subject != subject {
            return Err(mismatch(format!(
                "ledger entry {} subject diverges from the mutated row",
                stamped.seq
            )));
        }
        if &entry.actor != actor {
            return Err(mismatch(format!(
                "ledger entry {} actor diverges from {FLEET_ACTOR}",
                stamped.seq
            )));
        }
        Ok(stamped.seq)
    }
}

/// Reserved Blob-CF keyspace for discovery run reports: a `0xFD` discriminant
/// (disjoint from the collection blob layer's `0x05`) followed by a versioned
/// namespace and the run id.
/// Independent readback of a persisted run report: the exact Blob-CF bytes
/// plus the paired `Admin` ledger entry's sequence and payload.
#[derive(Clone, Debug)]
pub struct RunReportReadback {
    /// Exact report bytes read back from the Blob CF.
    pub report_bytes: Vec<u8>,
    /// Sequence of the paired `Admin` ledger entry.
    pub ledger_seq: u64,
    /// Payload of the paired `Admin` ledger entry (the run summary).
    pub ledger_payload: Vec<u8>,
}

pub const RUN_REPORT_DISC: u8 = 0xFD;
/// Versioned namespace tag for run-report rows.
pub const RUN_REPORT_NAMESPACE: &[u8] = b"fleetrun:v1:";

/// Versioned namespace tag for kind-scoped fleet report rows (#458): shares the
/// `0xFD` discriminant with run reports but a distinct namespace, so the two
/// keyspaces never collide and both stay disjoint from the collection blob layer.
pub const FLEET_REPORT_NAMESPACE: &[u8] = b"fleetreport:v1:";

/// Blob-CF key of a kind-scoped fleet report row: `0xFD ++ "fleetreport:v1:" ++
/// kind ++ ":" ++ report_id`.
pub fn fleet_report_key(kind: &str, report_id: &str) -> Vec<u8> {
    let mut key =
        Vec::with_capacity(1 + FLEET_REPORT_NAMESPACE.len() + kind.len() + 1 + report_id.len());
    key.push(RUN_REPORT_DISC);
    key.extend_from_slice(FLEET_REPORT_NAMESPACE);
    key.extend_from_slice(kind.as_bytes());
    key.push(b':');
    key.extend_from_slice(report_id.as_bytes());
    key
}

/// Blob-CF key of a discovery run report row.
pub fn run_report_key(run_id: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + RUN_REPORT_NAMESPACE.len() + run_id.len());
    key.push(RUN_REPORT_DISC);
    key.extend_from_slice(RUN_REPORT_NAMESPACE);
    key.extend_from_slice(run_id.as_bytes());
    key
}

fn source_retirement_error(full_name: &str, detail: String) -> CalyxError {
    CalyxError {
        code: ASTRO_FLEET_SOURCE_RETIREMENT_STATE,
        message: format!("source-retirement state for {full_name} is inconsistent: {detail}"),
        remediation: "preserve the source/tombstone and catalog bytes; resume only the exact durable transaction after repairing the named mismatch",
    }
}

fn require_timestamp(at_unix_secs: u64) -> Result<(), CalyxError> {
    if at_unix_secs == 0 {
        return Err(CalyxError {
            code: ASTRO_FLEET_TIMESTAMP_REQUIRED,
            message: "fleet catalog mutations require a real at_unix_secs timestamp".to_string(),
            remediation: "pass the observation time in unix seconds (the CLI defaults to now)",
        });
    }
    Ok(())
}
