//! Server wiring for the guard identity-lock inventory (P7.4, #48 server residue).
//!
//! The guard crate (`astrolabe_guard::lock`) owns the *inventory* core — the
//! locked set derived from extraction export flags, the fail-closed lock/unlock
//! semantics, and the canonical, reversible byte image. This module owns the
//! *persistence + surfacing*: the inventory's canonical bytes are stored in the
//! config store (read-back verified), each lock/unlock is ledgered to the real
//! **Guard column family** (`EntryKind::Guard`) for an auditable trail, and the
//! `guard_lock` MCP tool serves/mutates it. [`load_lock_inventory`] is the shared
//! reader `guard_check` consults to route a target as identity-locked (enforcing
//! the public-API signature slot `AllRequired` at the identity FAR) or content-class.
//!
//! Reversibility is proven at the server boundary: an unlock returns the persisted
//! inventory byte-for-byte to its pre-lock image (the core guarantee), and the
//! surfaced `inventory_hash` before/after lets an independent reader confirm it.

use super::*;

use astrolabe_guard::lock::{LockCandidate, LockInventory};

/// Actor recorded on every guard-lock Ledger entry.
pub(crate) const GUARD_LOCK_ACTOR: &str = "astrolabe-server-guard-lock";
/// Schema tag on the surfaced lock envelope.
pub(crate) const GUARD_LOCK_SURFACE_SCHEMA: &str = "astro.guard.lock_surface.v1";
/// Config-store key (per project) holding the inventory's canonical bytes.
const GUARD_LOCK_INVENTORY_KEY: &str = "guard_lock_inventory_json";

/// Ledger subject bytes for a project's lock journal (`SubjectId::Guard`).
fn guard_lock_subject(project: &str) -> Vec<u8> {
    format!("guard-lock:{project}").into_bytes()
}

/// Load the persisted identity-lock inventory for a project (empty when unset).
///
/// Shared with `guard_check`: a target present here is identity-locked. The stored
/// canonical bytes are reconstructed into a [`LockInventory`] via `from_extraction`
/// over the locked entries (all exported by construction), which re-sorts to the
/// same canonical image.
pub(crate) fn load_lock_inventory(
    cache_dir: &Path,
    project: &str,
) -> Result<LockInventory, DynError> {
    let Some(raw) = read_config_value(cache_dir, &metadata_key(project, GUARD_LOCK_INVENTORY_KEY))?
    else {
        return Ok(LockInventory::new());
    };
    let value: Value = serde_json::from_str(&raw)?;
    let mut candidates = Vec::new();
    if let Some(locked) = value.get("locked").and_then(Value::as_array) {
        for entry in locked {
            let Some(cx) = entry.get("cx").and_then(Value::as_str) else {
                continue;
            };
            let qualified_name = entry
                .get("qualified_name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            candidates.push(LockCandidate {
                cx_id_hex: cx.to_string(),
                qualified_name,
                exported: true,
            });
        }
    }
    Ok(LockInventory::from_extraction(&candidates))
}

/// Persist the inventory canonical bytes, verified by readback.
fn persist_lock_inventory(
    cache_dir: &Path,
    project: &str,
    inventory: &LockInventory,
) -> Result<(), DynError> {
    let bytes = inventory.canonical_bytes();
    let text = String::from_utf8(bytes.clone())?;
    write_config_value(
        cache_dir,
        &metadata_key(project, GUARD_LOCK_INVENTORY_KEY),
        &text,
    )?;
    let readback = read_config_value(cache_dir, &metadata_key(project, GUARD_LOCK_INVENTORY_KEY))?;
    if readback.map(String::into_bytes).as_deref() != Some(bytes.as_slice()) {
        return Err(format!(
            "ASTRO_GUARD_LOCK_MIRROR_MISMATCH: lock inventory for project {project:?} did not read back byte-identically; remediation: the config store diverged from the committed inventory"
        )
        .into());
    }
    Ok(())
}

/// Append one lock/unlock event to the project's Guard Ledger CF.
fn append_guard_lock_entry(
    cache_dir: &Path,
    project: &str,
    payload: Vec<u8>,
) -> Result<LedgerRef, DynError> {
    let (vault_dir, vault_id, vault_salt) = shadow_vault_config_at(cache_dir, project)?;
    if !vault_dir.exists() {
        return Err(format!(
            "ASTRO_GUARD_LOCK_VAULT_MISSING: shadow vault dir missing: {}; remediation: rerun index_repository with calyx=\"shadow\" before locking symbols",
            vault_dir.display()
        )
        .into());
    }
    let vault = open_shadow_vault_writable_latest_selected(
        &vault_dir,
        &vault_id,
        &vault_salt,
        vec![ColumnFamily::Ledger, ColumnFamily::TimeIndex],
    )?;
    let ledger_ref = vault.append_ledger_entry(
        calyx_ledger::EntryKind::Guard,
        SubjectId::Guard(guard_lock_subject(project)),
        payload,
        ActorId::Service(GUARD_LOCK_ACTOR.to_string()),
    )?;
    drop(vault);
    Ok(ledger_ref)
}

/// MCP entry point: `guard_lock` with modes `lock`, `unlock`, `inventory`, `rebuild`.
pub(crate) fn handle_guard_lock(args_json: &str) -> Result<String, DynError> {
    let args = serde_json::from_str::<Value>(args_json)?;
    let Some(args_obj) = args.as_object() else {
        return tool_error_result(
            "ASTRO_GUARD_LOCK_INVALID: guard_lock arguments must be a JSON object; remediation: pass a JSON object with project and mode",
        );
    };
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    guard_lock_at(&cache_dir, args_obj)
}

/// Cache-dir-explicit entry point for `guard_lock` (shared by the MCP handler and
/// in-process FSV tests, avoiding the process-global cbm cache dir).
pub(crate) fn guard_lock_at(
    cache_dir: &Path,
    args_obj: &Map<String, Value>,
) -> Result<String, DynError> {
    let Some(project) = status_project_from_args(args_obj)? else {
        return tool_error_result(
            "ASTRO_GUARD_LOCK_INVALID: guard_lock requires project; remediation: pass the shadow-indexed project whose lock inventory is consulted",
        );
    };
    if read_dial_at(cache_dir, &project)? != MigrationDial::Shadow {
        return tool_error_result(
            "ASTRO_GUARD_LOCK_NOT_SHADOW: guard_lock requires calyx shadow indexing; remediation: run index_repository with calyx=\"shadow\" before locking symbols",
        );
    }
    let mode = string_arg(args_obj, "mode").unwrap_or("inventory");
    match mode {
        "lock" => guard_lock_mutate(cache_dir, &project, args_obj, true),
        "unlock" => guard_lock_mutate(cache_dir, &project, args_obj, false),
        "inventory" => guard_lock_inventory_at(cache_dir, &project),
        "rebuild" => guard_lock_rebuild_at(cache_dir, &project, args_obj),
        other => tool_error_result(format!(
            "ASTRO_GUARD_LOCK_MODE_UNSUPPORTED: guard_lock mode {other:?} is not available; remediation: use mode=\"lock\", mode=\"unlock\", mode=\"inventory\", or mode=\"rebuild\""
        )),
    }
}

fn guard_lock_mutate(
    cache_dir: &Path,
    project: &str,
    args_obj: &Map<String, Value>,
    lock: bool,
) -> Result<String, DynError> {
    let Some(cx) = string_arg(args_obj, "cx") else {
        return tool_error_result(format!(
            "ASTRO_GUARD_LOCK_INVALID: guard_lock mode=\"{}\" requires cx; remediation: pass the target symbol's CxId hex",
            if lock { "lock" } else { "unlock" }
        ));
    };
    let mut inventory = load_lock_inventory(cache_dir, project)?;
    let before_hash = hex_lower(&Sha256::digest(inventory.canonical_bytes()));

    let change = if lock {
        let qualified_name = string_arg(args_obj, "qualified_name")
            .unwrap_or(cx)
            .to_string();
        let exported = args_obj
            .get("exported")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let candidate = LockCandidate {
            cx_id_hex: cx.to_string(),
            qualified_name,
            exported,
        };
        match inventory.lock(&candidate) {
            Ok(change) => change,
            Err(error) => return calibration_refused(error),
        }
    } else {
        match inventory.unlock(cx) {
            Ok(change) => change,
            Err(error) => return calibration_refused(error),
        }
    };

    persist_lock_inventory(cache_dir, project, &inventory)?;
    let after_hash = hex_lower(&Sha256::digest(&change.inventory_bytes));

    let payload = lock_event_payload_bytes(project, lock, &change.cx_id_hex, &after_hash);
    let ledger_ref = append_guard_lock_entry(cache_dir, project, payload)?;

    tool_json_result(json!({
        "schema": GUARD_LOCK_SURFACE_SCHEMA,
        "status": if lock { "locked" } else { "unlocked" },
        "project": project,
        "cx": change.cx_id_hex,
        "was_locked": change.was_locked,
        "now_locked": change.now_locked,
        "idempotent": change.idempotent,
        "inventory_hash_before": before_hash,
        "inventory_hash_after": after_hash,
        "locked_count": inventory.len(),
        "ledger_ref": {
            "seq": ledger_ref.seq,
            "entry_hash": hex_lower(&ledger_ref.hash),
            "kind": "guard",
        },
        "trust": "verified",
        "freshness": "fresh",
        "provenance": [format!("guard_lock:{}:{}", if lock { "lock" } else { "unlock" }, ledger_ref.seq)],
        "source": format!("AsterVault:ColumnFamily::Ledger seq={}", ledger_ref.seq),
    }))
}

fn guard_lock_inventory_at(cache_dir: &Path, project: &str) -> Result<String, DynError> {
    let inventory = load_lock_inventory(cache_dir, project)?;
    let locked: Vec<&str> = inventory.locked_cx_ids().collect();
    tool_json_result(json!({
        "schema": GUARD_LOCK_SURFACE_SCHEMA,
        "status": "served",
        "project": project,
        "locked_count": inventory.len(),
        "locked": locked,
        "inventory_hash": hex_lower(&Sha256::digest(inventory.canonical_bytes())),
        "trust": "verified",
        "freshness": "fresh",
        "provenance": ["guard_lock:inventory"],
        "source": "config-store:guard_lock_inventory_json",
    }))
}

fn guard_lock_rebuild_at(
    cache_dir: &Path,
    project: &str,
    args_obj: &Map<String, Value>,
) -> Result<String, DynError> {
    let Some(symbols) = args_obj.get("symbols").and_then(Value::as_array) else {
        return tool_error_result(
            "ASTRO_GUARD_LOCK_INVALID: guard_lock mode=\"rebuild\" requires a symbols array; remediation: pass extraction symbols, each {cx, qualified_name, exported}",
        );
    };
    let mut candidates = Vec::with_capacity(symbols.len());
    let mut exported_count = 0usize;
    for (index, entry) in symbols.iter().enumerate() {
        let Some(obj) = entry.as_object() else {
            return tool_error_result(format!(
                "ASTRO_GUARD_LOCK_INVALID: symbols[{index}] must be an object; remediation: each symbol is {{cx, qualified_name, exported}}"
            ));
        };
        let Some(cx) = obj.get("cx").and_then(Value::as_str) else {
            return tool_error_result(format!(
                "ASTRO_GUARD_LOCK_INVALID: symbols[{index}] is missing cx; remediation: pass the symbol's CxId hex"
            ));
        };
        let qualified_name = obj
            .get("qualified_name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let exported = obj
            .get("exported")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if exported {
            exported_count += 1;
        }
        candidates.push(LockCandidate {
            cx_id_hex: cx.to_string(),
            qualified_name,
            exported,
        });
    }
    let inventory = LockInventory::from_extraction(&candidates);
    persist_lock_inventory(cache_dir, project, &inventory)?;

    tool_json_result(json!({
        "schema": GUARD_LOCK_SURFACE_SCHEMA,
        "status": "rebuilt",
        "project": project,
        "symbols_seen": candidates.len(),
        "exported_seen": exported_count,
        "locked_count": inventory.len(),
        "parity": inventory.len() == exported_count,
        "inventory_hash": hex_lower(&Sha256::digest(inventory.canonical_bytes())),
        "trust": "verified",
        "freshness": "fresh",
        "provenance": ["guard_lock:rebuild"],
        "source": "extraction-export-flags",
    }))
}

fn lock_event_payload_bytes(project: &str, lock: bool, cx: &str, inventory_hash: &str) -> Vec<u8> {
    let value = json!({
        "cx": cx,
        "inventory_sha256": inventory_hash,
        "kind": if lock { "lock" } else { "unlock" },
        "repo": project,
        "schema": "astro.guard.lock_decision.v1",
    });
    serde_json::to_vec(&value).expect("guard lock event payload serializes")
}

fn calibration_refused(
    error: astrolabe_guard::calibration::CalibrationError,
) -> Result<String, DynError> {
    tool_error_result(format!(
        "{}: {}; remediation: {}",
        error.code(),
        error.message(),
        error.remediation()
    ))
}
