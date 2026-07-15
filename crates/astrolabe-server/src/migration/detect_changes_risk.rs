use super::*;

use astrolabe_kernel::{ReachConfig, change_reach, reach_risk_permille};
use astrolabe_oracle::{OracleEvidence, PredictConfig, grounded_risk};
use calyx_core::CxId;

/// Envelope schema for the grounded-risk block layered onto `detect_changes`.
pub(crate) const DETECT_CHANGES_RISK_SCHEMA: &str = "astrolabe.detect_changes_grounded_risk.v1";

/// Runs the legacy CBM `detect_changes` and layers oracle-backed grounded risk
/// onto its impacted symbols (blueprint P6.3 scaffold, finalized #52).
///
/// The augmentation is strictly additive: the CBM result's legacy shape
/// (`changed_files`, `changed_count`, `impacted_symbols`, `depth`) is preserved
/// verbatim and a `grounded_risk` block is merged alongside it. For each impacted
/// symbol the oracle change→outcome corpus provides a probability-based risk when
/// grounded evidence exists; a symbol with no evidence (or a repo with no mined
/// corpus) falls back to the registry-declared provisional risk, clearly labeled
/// `trust: provisional` (HONEST invariant 3 — every degradation is labeled, never
/// silent). Any augmentation error degrades to the legacy shape with a labeled
/// `grounded_risk` block explaining why, so `detect_changes` never fails on the
/// grounding path.
pub(crate) fn handle_detect_changes_grounded_risk(
    runner: &CbmToolRunner,
    args_json: &str,
) -> Result<String, DynError> {
    // Always run the real CBM tool first; grounded risk is layered on additively.
    let raw = runner.handle_tool_raw("detect_changes", args_json)?;

    // A CBM error result carries no symbols to ground: return it untouched.
    if tool_result_is_error(&raw).unwrap_or(false) {
        return Ok(raw);
    }

    // Resolve the project so we can open its grounded-change vault.
    let project = serde_json::from_str::<Value>(args_json)
        .ok()
        .as_ref()
        .and_then(Value::as_object)
        .and_then(|obj| status_project_from_args(obj).ok().flatten());
    let Some(project) = project else {
        return augment_tool_result(
            &raw,
            ungrounded_block("no project argument; cannot resolve a grounded-change vault"),
        );
    };

    let cache_dir = match astrolabe_bridge::cbm_cache_dir() {
        Ok(cache_dir) => cache_dir,
        Err(error) => {
            return augment_tool_result(
                &raw,
                ungrounded_block(&format!("cbm cache dir unavailable: {error}")),
            );
        }
    };
    match grounded_risk_block(&cache_dir, &project, &raw) {
        Ok(block) => augment_tool_result(&raw, block),
        Err(error) => augment_tool_result(
            &raw,
            ungrounded_block(&format!("grounded-risk augmentation unavailable: {error}")),
        ),
    }
}

/// Builds the grounded-risk block for a shadow-indexed project by reading the
/// oracle occurrence corpus and the CBM graph back from the persisted vault.
///
/// #339: CBM `detect_changes` reports impacted symbols by their *short* name
/// (`nodes[i].name`), which is not guaranteed to equal the vault's
/// `qualified_name` keys (short name vs FQN, language-specific canonicalization).
/// Resolving the short name directly against the node map under-matches
/// namespaced symbols, silently downgrading them to the provisional hop-risk path
/// even when grounded evidence exists. The [`SymbolResolver`] built from the CBM
/// graph snapshot resolves each impacted symbol by exact qualified name first,
/// then by short name disambiguated with the reported file, then by FQN-suffix
/// match — so an under-match becomes a correct match. A name that matches more
/// than one distinct constellation is a **labeled** ambiguous partial (never a
/// silent provisional downgrade, HONEST invariant 3).
pub(crate) fn grounded_risk_block(
    cache_dir: &Path,
    project: &str,
    raw: &str,
) -> Result<Value, DynError> {
    let (vault_dir, vault_id, vault_salt) = shadow_vault_config_at(cache_dir, project)?;
    if !vault_dir.exists() {
        return Ok(ungrounded_block(
            "shadow vault missing; run index_repository with calyx=\"shadow\" before grounding risk",
        ));
    }

    // FSV read path: the evidence index and CBM graph are reconstructed from the
    // durable Kv/Graph/Base CF rows, never from an in-memory planner echo.
    let vault = open_shadow_vault_read_only(
        &vault_dir,
        &vault_id,
        &vault_salt,
        vec![
            ColumnFamily::Kv,
            ColumnFamily::Graph,
            ColumnFamily::Base,
            ColumnFamily::Kernel,
        ],
    )?;
    let evidence = OracleEvidence::from_vault(&vault)?;
    let snapshot = astrolabe_ingest::read_cbm_graph_snapshot(&vault, project)?;
    // #366: the answer-path blast-radius reach term reads the persisted kernel
    // graph + artifact back from the vault (read-only). When either is absent the
    // reach term is skipped entirely and the served risk stays byte-compatible with
    // today's per-symbol behavior (labeled below).
    let reach_state = ChangeReachState::from_vault(&vault, project);
    drop(vault);

    let resolver = SymbolResolver::from_snapshot(&snapshot);

    let config = PredictConfig::default();
    let fallback = config.provisional_fallback_risk();
    let ceiling = config.served_ceiling();

    let mut symbols = Vec::new();
    let mut grounded_count = 0usize;
    let mut ambiguous_count = 0usize;
    let mut reach_symbol_count = 0usize;
    let mut all_trusted = true;
    for symbol in impacted_symbols(raw) {
        let mut entry = json!({
            "symbol": symbol.name,
            "file": symbol.file,
            "ceiling": ceiling,
        });
        let obj = entry.as_object_mut().expect("symbol entry is an object");
        match resolver.resolve(&symbol.name, &symbol.file) {
            SymbolResolution::Resolved { cx, how } => {
                // Oracle-backed probability replaces the structural fallback.
                let risk = grounded_risk(&evidence, cx, fallback, &config)?;
                if risk.grounded {
                    grounded_count += 1;
                }
                let trust = risk.trust.as_str();
                if trust != "trusted" {
                    all_trusted = false;
                }
                obj.insert("resolution".to_string(), json!(how));
                obj.insert("cx".to_string(), json!(hex_lower(cx.as_bytes())));
                obj.insert("risk".to_string(), json!(risk.risk));
                obj.insert("trust".to_string(), json!(trust));
                obj.insert("grounded".to_string(), json!(risk.grounded));
                obj.insert("evidence_occurrences".to_string(), json!(risk.evidence_n));
                // #366: fold the kernel-graph blast radius into risk, additively.
                // Only present when the kernel graph + artifact were persisted; the
                // oracle `risk` field above is preserved verbatim so the
                // artifact-absent path stays byte-compatible with today.
                if let Some(reach_block) = reach_state.reach_for(cx, risk.risk) {
                    reach_symbol_count += 1;
                    obj.insert("reach".to_string(), reach_block);
                }
            }
            SymbolResolution::Ambiguous { how, candidates } => {
                // A name matching more than one distinct constellation is a labeled
                // partial — never a silent provisional downgrade. The risk is the
                // provisional fallback, but the envelope names the ambiguity so a
                // caller can disambiguate by qualified name.
                ambiguous_count += 1;
                all_trusted = false;
                obj.insert("resolution".to_string(), json!("ambiguous"));
                obj.insert("ambiguous".to_string(), json!(true));
                obj.insert("ambiguous_via".to_string(), json!(how));
                obj.insert("candidate_count".to_string(), json!(candidates));
                obj.insert("risk".to_string(), json!(fallback));
                obj.insert("trust".to_string(), json!("provisional"));
                obj.insert("grounded".to_string(), json!(false));
                obj.insert("evidence_occurrences".to_string(), json!(0));
                obj.insert(
                    "note".to_string(),
                    json!(format!(
                        "CBM name {:?} matched {candidates} distinct constellations; \
                         re-run detect_changes risk with the qualified name to ground it",
                        symbol.name
                    )),
                );
            }
            SymbolResolution::Unresolved => {
                // Name not in the indexed graph at all: labeled provisional fallback.
                all_trusted = false;
                obj.insert("resolution".to_string(), json!("unresolved"));
                obj.insert("risk".to_string(), json!(fallback));
                obj.insert("trust".to_string(), json!("provisional"));
                obj.insert("grounded".to_string(), json!(false));
                obj.insert("evidence_occurrences".to_string(), json!(0));
            }
        }
        symbols.push(entry);
    }

    // Any ambiguity makes the block a labeled partial; otherwise grounded evidence
    // makes it grounded, and its absence makes it ungrounded.
    let status = if ambiguous_count > 0 {
        "partial"
    } else if grounded_count > 0 {
        "grounded"
    } else {
        "ungrounded"
    };
    let block_trust = if !symbols.is_empty() && all_trusted && ambiguous_count == 0 {
        "trusted"
    } else {
        "provisional"
    };
    Ok(json!({
        "grounded_risk": {
            "schema": DETECT_CHANGES_RISK_SCHEMA,
            "status": status,
            "grounded_symbol_count": grounded_count,
            "ambiguous_symbol_count": ambiguous_count,
            "symbol_count": symbols.len(),
            "symbols": symbols,
            // #366: labeled reach component — present and applied when the kernel
            // graph + artifact are persisted, labeled absent otherwise (the
            // per-symbol risk above is then byte-compatible with today).
            "reach_component": reach_state.summary(reach_symbol_count),
            "trust": block_trust,
            "freshness": "fresh",
            "provenance": [
                format!("oracle-corpus:project={project}"),
                "vault:ColumnFamily::Kv+Graph+Base+Kernel".to_string(),
                "resolver:cbm-name-vs-vault-fqn".to_string(),
                "kernel:answer-path-reach(#366)".to_string(),
            ],
        }
    }))
}

/// The persisted kernel graph + artifact used to measure each changed symbol's
/// blast-radius reach (#366). Absent when no kernel artifact/graph is persisted —
/// the reach term is then skipped and the served risk stays byte-compatible.
struct ChangeReachState {
    inner: Option<ChangeReachInner>,
    reason: Option<String>,
}

struct ChangeReachInner {
    graph: astrolabe_kernel::KernelGraph,
    kernel_members: BTreeSet<CxId>,
    gap_members: BTreeSet<CxId>,
    config: ReachConfig,
}

impl ChangeReachState {
    /// Reads the persisted composite kernel graph projection and kernel artifact
    /// back from the vault, read-only. Any absence/read error becomes a labeled
    /// `reason` and disables the reach term (never a hard failure).
    fn from_vault<C>(vault: &AsterVault<C>, project: &str) -> Self
    where
        C: Clock,
    {
        let scope_id = kernel_artifact_scope_id(project);
        let artifact = match astrolabe_ingest::read_persisted_kernel_artifact(vault, &scope_id) {
            Ok(Some(artifact)) => artifact,
            Ok(None) => {
                return Self::unavailable("no persisted kernel artifact for this project");
            }
            Err(error) => {
                return Self::unavailable(&format!("kernel artifact read failed: {error}"));
            }
        };
        let csr = match astrolabe_ingest::read_graph_projection_csr(
            vault,
            astrolabe_ingest::GraphProjectionKind::KernelGraph,
        ) {
            Ok(Some(csr)) => csr,
            Ok(None) => return Self::unavailable("no persisted kernel graph projection"),
            Err(error) => {
                return Self::unavailable(&format!("kernel graph projection read failed: {error}"));
            }
        };
        let graph = match astrolabe_ingest::kernel_graph_from_projection_csr(&csr, &BTreeMap::new())
        {
            Ok(graph) => graph,
            Err(error) => {
                return Self::unavailable(&format!("kernel graph adapt failed: {error}"));
            }
        };
        let kernel_members: BTreeSet<CxId> = artifact.members.iter().map(|m| m.id).collect();
        let gap_members: BTreeSet<CxId> = artifact
            .members
            .iter()
            .filter(|m| !m.grounded)
            .map(|m| m.id)
            .collect();
        Self {
            inner: Some(ChangeReachInner {
                graph,
                kernel_members,
                gap_members,
                config: ReachConfig::with_registry_defaults(),
            }),
            reason: None,
        }
    }

    fn unavailable(reason: &str) -> Self {
        Self {
            inner: None,
            reason: Some(reason.to_string()),
        }
    }

    /// The measured reach block for one changed symbol, or `None` when the reach
    /// term is unavailable or the symbol has no kernel-graph node. `base_risk` is
    /// the oracle's grounded consequence probability (`[0, 1]`), elevated by the
    /// blast radius into a composed `blast_risk_permille` (never below the oracle
    /// base, never above `1000`).
    fn reach_for(&self, cx: CxId, base_risk: f64) -> Option<Value> {
        let inner = self.inner.as_ref()?;
        let reach = change_reach(
            &inner.graph,
            cx,
            &inner.kernel_members,
            &inner.gap_members,
            &inner.config,
        )
        .ok()?;
        let base_permille = (base_risk.clamp(0.0, 1.0) * 1000.0).round() as u64;
        let composed = reach_risk_permille(base_permille, &reach, &inner.config).ok()?;
        Some(json!({
            "schema": astrolabe_kernel::CHANGE_REACH_SCHEMA,
            "from_is_kernel_member": reach.from_is_kernel_member,
            "from_is_gap": reach.from_is_gap,
            "reached_count": reach.reached_count,
            "reach_mass_permille": reach.reach_mass_permille,
            "kernel_member_reach_permille": reach.kernel_member_reach_permille,
            "gap_reach_permille": reach.gap_reach_permille,
            "base_risk_permille": composed.grounded_consequence_permille,
            "gap_exposure_permille": composed.gap_exposure_permille,
            "elevation_permille": composed.elevation_permille,
            "blast_risk_permille": composed.risk_permille,
            "reached": reach.reached.iter().map(|node| json!({
                "symbol_id": hex_lower(node.id.as_bytes()),
                "hop": node.hop,
                "reach_permille": node.reach_permille,
                "kernel_member": node.kernel_member,
                "gap": node.gap,
            })).collect::<Vec<_>>(),
        }))
    }

    /// A labeled summary of the reach component for the top-level block.
    fn summary(&self, applied_count: usize) -> Value {
        match &self.inner {
            Some(_) => json!({
                "status": "applied",
                "reach_symbol_count": applied_count,
                "knob_registry_version": astrolabe_kernel::CHANGE_REACH_KNOB_REGISTRY_VERSION,
                "trust": "provisional",
            }),
            None => json!({
                "status": "unavailable",
                "reason": self.reason.clone().unwrap_or_else(|| "kernel reach unavailable".to_string()),
                "reach_symbol_count": 0,
                "trust": "provisional",
            }),
        }
    }
}

/// The outcome of resolving one CBM impacted-symbol name to a constellation.
#[derive(Debug, Clone, PartialEq)]
enum SymbolResolution {
    /// Resolved to exactly one constellation; `how` records the strategy.
    Resolved { cx: CxId, how: &'static str },
    /// The name matched more than one distinct constellation — a labeled partial,
    /// never a silent provisional downgrade.
    Ambiguous {
        how: &'static str,
        candidates: usize,
    },
    /// The name did not match any indexed constellation.
    Unresolved,
}

/// One short-name candidate carried by the CBM graph snapshot.
#[derive(Debug, Clone)]
struct NameCandidate {
    file_path: String,
    cx: CxId,
}

/// Resolves CBM `detect_changes` short symbol names against the vault's qualified
/// names (#339). Built once per call from the persisted CBM graph snapshot.
struct SymbolResolver {
    /// qualified_name -> distinct resolved constellation ids.
    by_qn: BTreeMap<String, BTreeSet<CxId>>,
    /// short name -> resolved candidates (file + constellation).
    by_name: BTreeMap<String, Vec<NameCandidate>>,
}

impl SymbolResolver {
    fn from_snapshot(snapshot: &CbmGraphSnapshot) -> Self {
        let mut by_qn: BTreeMap<String, BTreeSet<CxId>> = BTreeMap::new();
        let mut by_name: BTreeMap<String, Vec<NameCandidate>> = BTreeMap::new();
        for node in &snapshot.nodes {
            // Only real (non-structural) nodes that resolved to a constellation can
            // carry grounded evidence.
            let Some(cx) = node.cx_id else { continue };
            if node.structural {
                continue;
            }
            if !node.qualified_name.is_empty() {
                by_qn
                    .entry(node.qualified_name.clone())
                    .or_default()
                    .insert(cx);
            }
            if !node.name.is_empty() {
                by_name
                    .entry(node.name.clone())
                    .or_default()
                    .push(NameCandidate {
                        file_path: node.file_path.clone(),
                        cx,
                    });
            }
        }
        SymbolResolver { by_qn, by_name }
    }

    /// Resolves a CBM impacted symbol `(name, file)` to a constellation.
    ///
    /// Strategies, in order (first that produces any candidate decides):
    /// 1. **exact_qualified_name** — the CBM name already equals a vault FQN.
    /// 2. **short_name** — the CBM name equals one or more nodes' short name; the
    ///    reported file disambiguates when several nodes share the short name.
    /// 3. **fqn_suffix** — the CBM name is the trailing segment of exactly one FQN.
    ///
    /// A strategy that yields more than one distinct constellation returns
    /// [`SymbolResolution::Ambiguous`] (labeled), never a guessed match.
    fn resolve(&self, name: &str, file: &str) -> SymbolResolution {
        // 1. Exact qualified-name match.
        if let Some(cxs) = self.by_qn.get(name) {
            return decide(cxs.iter().copied(), "exact_qualified_name");
        }

        // 2. Short-name match, disambiguated by the reported file when present.
        if let Some(candidates) = self.by_name.get(name) {
            let file = file.trim();
            let file_matched: Vec<&NameCandidate> = if file.is_empty() {
                Vec::new()
            } else {
                candidates
                    .iter()
                    .filter(|candidate| file_paths_match(&candidate.file_path, file))
                    .collect()
            };
            let chosen: Vec<&NameCandidate> = if file_matched.is_empty() {
                candidates.iter().collect()
            } else {
                file_matched
            };
            return decide(chosen.iter().map(|candidate| candidate.cx), "short_name");
        }

        // 3. FQN-suffix match: qualified names whose trailing segment is `name`.
        let mut suffix_cxs: BTreeSet<CxId> = BTreeSet::new();
        for (qn, cxs) in &self.by_qn {
            if qn_ends_with_segment(qn, name) {
                suffix_cxs.extend(cxs.iter().copied());
            }
        }
        if !suffix_cxs.is_empty() {
            return decide(suffix_cxs, "fqn_suffix");
        }

        SymbolResolution::Unresolved
    }
}

/// Collapses a set of candidate constellations into a resolution: exactly one
/// distinct id resolves, more than one is a labeled ambiguity, none is unresolved.
fn decide(cxs: impl IntoIterator<Item = CxId>, how: &'static str) -> SymbolResolution {
    let distinct: BTreeSet<CxId> = cxs.into_iter().collect();
    match distinct.len() {
        0 => SymbolResolution::Unresolved,
        1 => SymbolResolution::Resolved {
            cx: *distinct.iter().next().expect("len==1"),
            how,
        },
        n => SymbolResolution::Ambiguous { how, candidates: n },
    }
}

/// True when the CBM `qualified_name` ends with `name` on a segment boundary
/// (`::`, `.`, `/`, or `#`) — i.e. `name` is the trailing symbol of the FQN.
fn qn_ends_with_segment(qn: &str, name: &str) -> bool {
    if !qn.ends_with(name) {
        return false;
    }
    let prefix = &qn[..qn.len() - name.len()];
    // Bare equality is handled by the exact-match strategy; here we require a
    // non-empty separator so `add` matches `calc.add` but not `readd`.
    matches!(
        prefix.chars().next_back(),
        Some(':') | Some('.') | Some('/') | Some('#')
    )
}

/// True when two repo-relative file paths name the same file: exact equality, one
/// a path-suffix of the other on a `/` boundary, or equal basenames.
fn file_paths_match(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    let (a, b) = (a.replace('\\', "/"), b.replace('\\', "/"));
    if a == b || a.ends_with(&format!("/{b}")) || b.ends_with(&format!("/{a}")) {
        return true;
    }
    let basename = |p: &str| p.rsplit('/').next().unwrap_or(p).to_string();
    !a.is_empty() && !b.is_empty() && basename(&a) == basename(&b)
}

/// A labeled fallback grounded-risk block for the ungrounded/unavailable path.
fn ungrounded_block(reason: &str) -> Value {
    json!({
        "grounded_risk": {
            "schema": DETECT_CHANGES_RISK_SCHEMA,
            "status": "ungrounded",
            "grounded_symbol_count": 0,
            "symbol_count": 0,
            "symbols": [],
            "trust": "provisional",
            "freshness": "fresh",
            "reason": reason,
            "provenance": ["fallback:no-grounded-evidence"],
        }
    })
}

/// One impacted symbol extracted from a CBM `detect_changes` result: its short
/// `name` and the `file` the CBM tool reported it in (used to disambiguate a short
/// name carried by several nodes, #339).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ImpactedSymbol {
    name: String,
    file: String,
}

/// Extracts the impacted symbols from a CBM `detect_changes` result.
///
/// The CBM tool returns an MCP text-result envelope whose `content[0].text` (or
/// `structuredContent`, when present) holds the inner object with the
/// `impacted_symbols` array; each element carries a short `name` and a `file`.
/// Entries are returned deduplicated and sorted so the augmentation is
/// deterministic.
fn impacted_symbols(raw: &str) -> Vec<ImpactedSymbol> {
    let Ok(value) = serde_json::from_str::<Value>(raw) else {
        return Vec::new();
    };
    let inner = value.get("structuredContent").cloned().or_else(|| {
        value
            .get("content")
            .and_then(Value::as_array)
            .and_then(|items| items.first())
            .and_then(|item| item.get("text"))
            .and_then(Value::as_str)
            .and_then(|text| serde_json::from_str::<Value>(text).ok())
    });
    let Some(inner) = inner else {
        return Vec::new();
    };
    let mut symbols = Vec::new();
    if let Some(array) = inner.get("impacted_symbols").and_then(Value::as_array) {
        for item in array {
            if let Some(name) = item.get("name").and_then(Value::as_str)
                && !name.is_empty()
            {
                let file = item
                    .get("file")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                symbols.push(ImpactedSymbol {
                    name: name.to_string(),
                    file,
                });
            }
        }
    }
    symbols.sort();
    symbols.dedup();
    symbols
}
