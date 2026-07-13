use super::*;
#[cfg(test)]
use calyx_aster::cf::prefix_range;
use calyx_ledger::EntryKind;

const INVALIDATION_SCHEMA: &str = "astrolabe.delta_invalidation.v1";
const INVALIDATION_ACTOR: &str = "astrolabe-shadow-invalidation";
const INVALIDATION_PREFIX: &[u8] = b"astrolabe:shadow:invalidation:v1\0";

#[derive(Debug, Clone)]
struct KernelDirtyScc {
    id: String,
    members: Vec<String>,
    dirty_members: Vec<String>,
    removed_members: Vec<String>,
}

pub(crate) fn persist_delta_invalidations<C>(
    vault: &AsterVault<C>,
    project: &str,
    import_changed: bool,
    delta: Option<&WeaveDelta>,
    weave: &Value,
) -> Result<Value, DynError>
where
    C: Clock,
{
    if !import_changed {
        return Ok(json!({
            "schema": INVALIDATION_SCHEMA,
            "status": "unchanged",
            "writes_skipped": true,
            "provenance": "content-addressed import reported no mutation; no invalidation rows written",
        }));
    }

    let snapshot = astrolabe_ingest::read_cbm_graph_snapshot(vault, project)?;
    let live_symbols = snapshot
        .nodes
        .iter()
        .filter(|node| !node.structural)
        .map(|node| node.qualified_name.clone())
        .collect::<BTreeSet<_>>();
    let dirty_symbols = match delta {
        Some(delta) => delta.dirty_qualified_names.clone(),
        None => live_symbols.clone(),
    };
    let removed_symbols = delta
        .map(|delta| delta.removed_qualified_names.clone())
        .unwrap_or_default();
    let affected_symbols = dirty_symbols
        .union(&removed_symbols)
        .cloned()
        .collect::<BTreeSet<_>>();
    if affected_symbols.is_empty() {
        return Ok(json!({
            "schema": INVALIDATION_SCHEMA,
            "status": "skipped_no_symbol_delta",
            "writes_skipped": true,
            "provenance": "import changed only structural/project metadata; no symbol-scoped assay/kernel/guard invalidations were required",
        }));
    }

    let snapshot_seq = vault.snapshot();
    let kernel_sccs = kernel_dirty_sccs(&snapshot, &dirty_symbols, &removed_symbols);
    let mut rows = Vec::new();

    for qualified_name in &affected_symbols {
        let value = assay_dirty_value(project, qualified_name, snapshot_seq);
        rows.push((
            ColumnFamily::Assay,
            assay_invalidation_key(project, qualified_name),
            value,
        ));
    }
    for scc in &kernel_sccs {
        let value = kernel_dirty_value(project, scc, snapshot_seq);
        rows.push((
            ColumnFamily::Kernel,
            kernel_invalidation_key(project, &scc.id),
            value,
        ));
    }
    for qualified_name in &affected_symbols {
        let previous = read_guard_drift_count(vault, snapshot_seq, project, qualified_name)?;
        let value = guard_drift_value(project, qualified_name, previous, snapshot_seq);
        rows.push((
            ColumnFamily::Guard,
            guard_invalidation_key(project, qualified_name),
            value,
        ));
    }

    let row_count = rows.len();
    let ledger_rows_before = vault.scan_cf_at(snapshot_seq, ColumnFamily::Ledger)?.len();
    let payload = invalidation_ledger_payload(
        project,
        snapshot_seq,
        &dirty_symbols,
        &removed_symbols,
        &kernel_sccs,
        weave,
    )?;
    let commit_seq = vault.write_cf_batch_with_ledger_entry(
        rows.clone(),
        EntryKind::Migrate,
        SubjectId::Query(invalidation_subject(project, &payload)),
        payload,
        ActorId::Service(INVALIDATION_ACTOR.to_string()),
    )?;
    let mut readback_verified = 0usize;
    for (cf, key, expected) in &rows {
        let actual = vault.read_cf_at(commit_seq, *cf, key)?;
        if actual.as_deref() != Some(expected.as_slice()) {
            return Err(format!(
                "invalidation FSV readback mismatch for {:?} key {} at seq {commit_seq}",
                cf,
                String::from_utf8_lossy(key)
            )
            .into());
        }
        readback_verified += 1;
    }
    let ledger_rows_after = vault.scan_cf_at(commit_seq, ColumnFamily::Ledger)?.len();

    Ok(json!({
        "schema": INVALIDATION_SCHEMA,
        "status": "dirty",
        "trust": "verified",
        "freshness": "current",
        "provenance": "AsterVault Assay/Kernel/Guard CF readback after delta weave",
        "snapshot_seq_before": snapshot_seq,
        "commit_seq": commit_seq,
        "ledger_rows_added": ledger_rows_after.saturating_sub(ledger_rows_before),
        "dirty_symbols": dirty_symbols.iter().cloned().collect::<Vec<_>>(),
        "removed_symbols": removed_symbols.iter().cloned().collect::<Vec<_>>(),
        "affected_symbol_count": affected_symbols.len(),
        "assay": {
            "status": "dirty",
            "dirty_strata": affected_symbols.iter().map(|symbol| assay_stratum(project, symbol)).collect::<Vec<_>>(),
            "rows_written": affected_symbols.len(),
        },
        "kernel": {
            "status": "dirty",
            "dirty_scc_count": kernel_sccs.len(),
            "dirty_sccs": kernel_sccs.iter().map(kernel_scc_json).collect::<Vec<_>>(),
            "rows_written": kernel_sccs.len(),
        },
        "guard": {
            "status": "drift_counted",
            "counter_count": affected_symbols.len(),
            "rows_written": affected_symbols.len(),
        },
        "rows_written": row_count,
        "fsv": {
            "kind": "vault_cf_readback",
            "readback_verified_rows": readback_verified,
            "families": ["Assay", "Kernel", "Guard", "Ledger"],
        },
    }))
}

pub(crate) fn read_invalidation_metadata(
    cache_dir: &Path,
    project: &str,
) -> Result<Value, DynError> {
    let Some(raw) = read_config_value(cache_dir, &metadata_key(project, "invalidations_json"))?
    else {
        return Ok(json!({
            "schema": INVALIDATION_SCHEMA,
            "status": "unavailable",
            "reason": "no shadow delta invalidation metadata has been persisted",
        }));
    };
    Ok(serde_json::from_str(&raw)?)
}

pub(crate) fn invalidation_prefix(project: &str, family: &str) -> Vec<u8> {
    let mut key = INVALIDATION_PREFIX.to_vec();
    key.extend_from_slice(project.as_bytes());
    key.push(0);
    key.extend_from_slice(family.as_bytes());
    key.push(0);
    key
}

fn assay_invalidation_key(project: &str, qualified_name: &str) -> Vec<u8> {
    let mut key = invalidation_prefix(project, "assay");
    key.extend_from_slice(qualified_name.as_bytes());
    key
}

fn kernel_invalidation_key(project: &str, scc_id: &str) -> Vec<u8> {
    let mut key = invalidation_prefix(project, "kernel");
    key.extend_from_slice(scc_id.as_bytes());
    key
}

fn guard_invalidation_key(project: &str, qualified_name: &str) -> Vec<u8> {
    let mut key = invalidation_prefix(project, "guard");
    key.extend_from_slice(qualified_name.as_bytes());
    key
}

fn assay_stratum(project: &str, qualified_name: &str) -> String {
    format!("panel_v{DEFAULT_PANEL_VERSION}:project:{project}:symbol:{qualified_name}")
}

fn assay_dirty_value(project: &str, qualified_name: &str, snapshot_seq: u64) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema": INVALIDATION_SCHEMA,
        "kind": "assay_stratum_dirty",
        "project": project,
        "panel_version": DEFAULT_PANEL_VERSION,
        "qualified_name": qualified_name,
        "stratum": assay_stratum(project, qualified_name),
        "dirty": true,
        "dirty_since_seq": snapshot_seq,
        "reason": "symbol delta changed the panel/slot inputs consumed by assay caches",
    }))
    .expect("encode assay invalidation")
}

fn kernel_dirty_value(project: &str, scc: &KernelDirtyScc, snapshot_seq: u64) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema": INVALIDATION_SCHEMA,
        "kind": "kernel_dirty_scc",
        "project": project,
        "panel_version": DEFAULT_PANEL_VERSION,
        "scc_id": scc.id,
        "members": scc.members,
        "dirty_members": scc.dirty_members,
        "removed_members": scc.removed_members,
        "dirty": true,
        "dirty_since_seq": snapshot_seq,
        "algorithm": "live_graph_directed_scc_v1",
    }))
    .expect("encode kernel invalidation")
}

fn guard_drift_value(
    project: &str,
    qualified_name: &str,
    previous_count: u64,
    snapshot_seq: u64,
) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema": INVALIDATION_SCHEMA,
        "kind": "guard_drift_counter",
        "project": project,
        "qualified_name": qualified_name,
        "previous_count": previous_count,
        "drift_count": previous_count.saturating_add(1),
        "dirty_since_seq": snapshot_seq,
        "reason": "symbol delta changed guard-observed code semantics or removed a guarded subject",
    }))
    .expect("encode guard invalidation")
}

fn read_guard_drift_count<C>(
    vault: &AsterVault<C>,
    snapshot: u64,
    project: &str,
    qualified_name: &str,
) -> Result<u64, DynError>
where
    C: Clock,
{
    let Some(bytes) = vault.read_cf_at(
        snapshot,
        ColumnFamily::Guard,
        &guard_invalidation_key(project, qualified_name),
    )?
    else {
        return Ok(0);
    };
    let value: Value = serde_json::from_slice(&bytes)?;
    Ok(value
        .get("drift_count")
        .and_then(Value::as_u64)
        .unwrap_or(0))
}

fn kernel_scc_json(scc: &KernelDirtyScc) -> Value {
    json!({
        "scc_id": scc.id,
        "members": scc.members,
        "dirty_members": scc.dirty_members,
        "removed_members": scc.removed_members,
    })
}

fn invalidation_ledger_payload(
    project: &str,
    snapshot_seq: u64,
    dirty_symbols: &BTreeSet<String>,
    removed_symbols: &BTreeSet<String>,
    kernel_sccs: &[KernelDirtyScc],
    weave: &Value,
) -> Result<Vec<u8>, DynError> {
    Ok(serde_json::to_vec(&json!({
        "schema": INVALIDATION_SCHEMA,
        "project": project,
        "snapshot_seq_before": snapshot_seq,
        "panel_version": DEFAULT_PANEL_VERSION,
        "dirty_symbol_count": dirty_symbols.len(),
        "removed_symbol_count": removed_symbols.len(),
        "kernel_dirty_scc_count": kernel_sccs.len(),
        "similarity_rows_written": weave.pointer("/similarity/rows_written").and_then(Value::as_u64),
        "similarity_rows_tombstoned": weave.pointer("/similarity/rows_tombstoned").and_then(Value::as_u64),
        "xterm_rows_written": weave.pointer("/eager_cross_terms/rows_written").and_then(Value::as_u64),
        "xterm_rows_tombstoned": weave.pointer("/eager_cross_terms/rows_tombstoned").and_then(Value::as_u64),
    }))?)
}

fn invalidation_subject(project: &str, payload: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(INVALIDATION_SCHEMA.as_bytes());
    hasher.update([0]);
    hasher.update(project.as_bytes());
    hasher.update([0]);
    hasher.update(payload);
    hasher.finalize().to_vec()
}

fn kernel_dirty_sccs(
    snapshot: &CbmGraphSnapshot,
    dirty_symbols: &BTreeSet<String>,
    removed_symbols: &BTreeSet<String>,
) -> Vec<KernelDirtyScc> {
    let mut id_to_qn = BTreeMap::<i64, String>::new();
    for node in snapshot.nodes.iter().filter(|node| !node.structural) {
        id_to_qn.insert(node.source_node_id, node.qualified_name.clone());
    }
    let mut adjacency = id_to_qn
        .values()
        .cloned()
        .map(|qualified_name| (qualified_name, BTreeSet::<String>::new()))
        .collect::<BTreeMap<_, _>>();
    let mut reverse = adjacency
        .keys()
        .cloned()
        .map(|qualified_name| (qualified_name, BTreeSet::<String>::new()))
        .collect::<BTreeMap<_, _>>();
    for edge in &snapshot.edges {
        let (Some(source), Some(target)) = (
            id_to_qn.get(&edge.source_node_id),
            id_to_qn.get(&edge.target_node_id),
        ) else {
            continue;
        };
        if source == target {
            continue;
        }
        if let Some(targets) = adjacency.get_mut(source) {
            targets.insert(target.clone());
        }
        if let Some(sources) = reverse.get_mut(target) {
            sources.insert(source.clone());
        }
    }

    let mut visited = BTreeSet::<String>::new();
    let mut order = Vec::<String>::new();
    for node in adjacency.keys() {
        if visited.contains(node) {
            continue;
        }
        let mut stack = vec![(node.clone(), false)];
        while let Some((current, expanded)) = stack.pop() {
            if expanded {
                order.push(current);
                continue;
            }
            if !visited.insert(current.clone()) {
                continue;
            }
            stack.push((current.clone(), true));
            if let Some(neighbors) = adjacency.get(&current) {
                for neighbor in neighbors.iter().rev() {
                    if !visited.contains(neighbor) {
                        stack.push((neighbor.clone(), false));
                    }
                }
            }
        }
    }

    let live_dirty = dirty_symbols
        .iter()
        .filter(|symbol| adjacency.contains_key(*symbol))
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut assigned = BTreeSet::<String>::new();
    let mut sccs = Vec::<KernelDirtyScc>::new();
    for node in order.into_iter().rev() {
        if !assigned.insert(node.clone()) {
            continue;
        }
        let mut component = BTreeSet::new();
        let mut stack = vec![node];
        while let Some(current) = stack.pop() {
            component.insert(current.clone());
            if let Some(neighbors) = reverse.get(&current) {
                for neighbor in neighbors {
                    if assigned.insert(neighbor.clone()) {
                        stack.push(neighbor.clone());
                    }
                }
            }
        }
        let dirty_members = component
            .intersection(&live_dirty)
            .cloned()
            .collect::<Vec<_>>();
        if dirty_members.is_empty() {
            continue;
        }
        let members = component.iter().cloned().collect::<Vec<_>>();
        let id = dirty_scc_id(&members, &[]);
        sccs.push(KernelDirtyScc {
            id,
            members,
            dirty_members,
            removed_members: Vec::new(),
        });
    }

    for removed in removed_symbols {
        if adjacency.contains_key(removed) && live_dirty.contains(removed) {
            continue;
        }
        let members = vec![removed.clone()];
        sccs.push(KernelDirtyScc {
            id: dirty_scc_id(&[], &members),
            members: Vec::new(),
            dirty_members: Vec::new(),
            removed_members: members,
        });
    }
    sccs.sort_by(|left, right| left.id.cmp(&right.id));
    sccs
}

fn dirty_scc_id(members: &[String], removed_members: &[String]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"kernel-dirty-scc-v1");
    for member in members {
        hasher.update([0]);
        hasher.update(member.as_bytes());
    }
    hasher.update([1]);
    for member in removed_members {
        hasher.update([0]);
        hasher.update(member.as_bytes());
    }
    hex_lower(&hasher.finalize())
}

#[cfg(test)]
pub(crate) fn scan_invalidation_rows<C>(
    vault: &AsterVault<C>,
    snapshot: u64,
    cf: ColumnFamily,
    project: &str,
    family: &str,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>, DynError>
where
    C: Clock,
{
    Ok(vault.scan_cf_range_at(
        snapshot,
        cf,
        &prefix_range(&invalidation_prefix(project, family)),
    )?)
}
