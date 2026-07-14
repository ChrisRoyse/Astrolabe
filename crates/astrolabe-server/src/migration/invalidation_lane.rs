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

/// Raw `(key, value)` rows scanned from a column family.
#[cfg(test)]
type RawCfRows = Vec<(Vec<u8>, Vec<u8>)>;

// Self-reading convenience wrapper: production always passes the shared
// post-import snapshot (#23), so only tests exercise this shape. Gated to test
// builds rather than shipped as dead code (invariant 6).
#[cfg(test)]
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
    persist_delta_invalidations_with_snapshot(vault, project, import_changed, delta, weave, None)
}

/// [`persist_delta_invalidations`] with an optional caller-preloaded graph
/// snapshot (#23). The invalidation lane only consumes node/edge rows, which the
/// weave phase leaves untouched, so a snapshot read for the delta derivation or
/// the weave remains valid here; `None` preserves the self-reading behavior.
pub(crate) fn persist_delta_invalidations_with_snapshot<C>(
    vault: &AsterVault<C>,
    project: &str,
    import_changed: bool,
    delta: Option<&WeaveDelta>,
    weave: &Value,
    preloaded_snapshot: Option<&CbmGraphSnapshot>,
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

    let t_snapshot = std::time::Instant::now();
    let owned_snapshot = match preloaded_snapshot {
        Some(_) => None,
        None => Some(astrolabe_ingest::read_cbm_graph_snapshot(vault, project)?),
    };
    let snapshot = preloaded_snapshot
        .or(owned_snapshot.as_ref())
        .expect("invalidation snapshot present by construction");
    let ms_snapshot = t_snapshot.elapsed().as_millis() as u64;
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
    let t_kernel_sccs = std::time::Instant::now();
    let kernel_sccs = kernel_dirty_sccs(snapshot, &dirty_symbols, &removed_symbols);
    let ms_kernel_sccs = t_kernel_sccs.elapsed().as_millis() as u64;
    let t_guard_reads = std::time::Instant::now();
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

    let ms_guard_reads = t_guard_reads.elapsed().as_millis() as u64;
    let row_count = rows.len();
    let t_ledger_before = std::time::Instant::now();
    let ledger_rows_before = vault.scan_cf_at(snapshot_seq, ColumnFamily::Ledger)?.len();
    let ms_ledger_scan_before = t_ledger_before.elapsed().as_millis() as u64;
    let t_commit = std::time::Instant::now();
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
    let ms_commit = t_commit.elapsed().as_millis() as u64;
    let t_readback = std::time::Instant::now();
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
    let ms_readback = t_readback.elapsed().as_millis() as u64;
    let t_ledger_after = std::time::Instant::now();
    let ledger_rows_after = vault.scan_cf_at(commit_seq, ColumnFamily::Ledger)?.len();
    let ms_ledger_scan_after = t_ledger_after.elapsed().as_millis() as u64;

    Ok(json!({
        "schema": INVALIDATION_SCHEMA,
        "status": "dirty",
        "timing_ms": {
            "snapshot_read": ms_snapshot,
            "kernel_sccs": ms_kernel_sccs,
            "guard_reads": ms_guard_reads,
            "ledger_scan_before": ms_ledger_scan_before,
            "commit": ms_commit,
            "readback": ms_readback,
            "ledger_scan_after": ms_ledger_scan_after,
        },
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
    // Index-based Kosaraju over the live graph (#23): the previous String-keyed
    // BTreeMap adjacency cloned qualified names per edge and per traversal step
    // (~1s at 50k nodes / 500k edges). Components are traversal-order-invariant
    // sets, member lists are sorted before hashing, and the final list is
    // sorted by id, so the output is byte-identical to the map-based shape.
    let mut id_to_qn = BTreeMap::<i64, &str>::new();
    for node in snapshot.nodes.iter().filter(|node| !node.structural) {
        id_to_qn.insert(node.source_node_id, node.qualified_name.as_str());
    }
    // Deterministic node indexing by qualified name (BTreeSet iteration order).
    let qns = id_to_qn.values().copied().collect::<BTreeSet<_>>();
    let qn_list = qns.iter().copied().collect::<Vec<_>>();
    let qn_index = qn_list
        .iter()
        .enumerate()
        .map(|(index, qn)| (*qn, index))
        .collect::<BTreeMap<_, _>>();
    let node_count = qn_list.len();
    let mut adjacency = vec![Vec::<u32>::new(); node_count];
    let mut reverse = vec![Vec::<u32>::new(); node_count];
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
        let source = qn_index[source];
        let target = qn_index[target];
        adjacency[source].push(target as u32);
        reverse[target].push(source as u32);
    }
    for neighbors in adjacency.iter_mut().chain(reverse.iter_mut()) {
        neighbors.sort_unstable();
        neighbors.dedup();
    }

    let mut visited = vec![false; node_count];
    let mut order = Vec::<u32>::with_capacity(node_count);
    for start in 0..node_count {
        if visited[start] {
            continue;
        }
        let mut stack = vec![(start as u32, false)];
        while let Some((current, expanded)) = stack.pop() {
            if expanded {
                order.push(current);
                continue;
            }
            if visited[current as usize] {
                continue;
            }
            visited[current as usize] = true;
            stack.push((current, true));
            for neighbor in adjacency[current as usize].iter().rev() {
                if !visited[*neighbor as usize] {
                    stack.push((*neighbor, false));
                }
            }
        }
    }

    let live_dirty_indices = dirty_symbols
        .iter()
        .filter_map(|symbol| qn_index.get(symbol.as_str()).map(|index| *index as u32))
        .collect::<BTreeSet<u32>>();
    let mut assigned = vec![false; node_count];
    let mut sccs = Vec::<KernelDirtyScc>::new();
    for node in order.into_iter().rev() {
        if assigned[node as usize] {
            continue;
        }
        assigned[node as usize] = true;
        let mut component = Vec::<u32>::new();
        let mut stack = vec![node];
        while let Some(current) = stack.pop() {
            component.push(current);
            for neighbor in &reverse[current as usize] {
                if !assigned[*neighbor as usize] {
                    assigned[*neighbor as usize] = true;
                    stack.push(*neighbor);
                }
            }
        }
        component.sort_unstable();
        let dirty_members = component
            .iter()
            .filter(|index| live_dirty_indices.contains(*index))
            .map(|index| qn_list[*index as usize].to_string())
            .collect::<Vec<_>>();
        if dirty_members.is_empty() {
            continue;
        }
        let members = component
            .iter()
            .map(|index| qn_list[*index as usize].to_string())
            .collect::<Vec<_>>();
        let id = dirty_scc_id(&members, &[]);
        sccs.push(KernelDirtyScc {
            id,
            members,
            dirty_members,
            removed_members: Vec::new(),
        });
    }

    for removed in removed_symbols {
        if let Some(index) = qn_index.get(removed.as_str())
            && live_dirty_indices.contains(&(*index as u32))
        {
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
) -> Result<RawCfRows, DynError>
where
    C: Clock,
{
    Ok(vault.scan_cf_range_at(
        snapshot,
        cf,
        &prefix_range(&invalidation_prefix(project, family)),
    )?)
}
