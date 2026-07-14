use super::*;

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
        vec![ColumnFamily::Kv, ColumnFamily::Graph, ColumnFamily::Base],
    )?;
    let evidence = OracleEvidence::from_vault(&vault)?;
    let snapshot = astrolabe_ingest::read_cbm_graph_snapshot(&vault, project)?;
    drop(vault);

    let resolver = SymbolResolver::from_snapshot(&snapshot);

    let config = PredictConfig::default();
    let fallback = config.provisional_fallback_risk();
    let ceiling = config.served_ceiling();

    let mut symbols = Vec::new();
    let mut grounded_count = 0usize;
    let mut ambiguous_count = 0usize;
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
            "trust": block_trust,
            "freshness": "fresh",
            "provenance": [
                format!("oracle-corpus:project={project}"),
                "vault:ColumnFamily::Kv+Graph+Base".to_string(),
                "resolver:cbm-name-vs-vault-fqn".to_string(),
            ],
        }
    }))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn cbm_result(impacted: &[&str]) -> String {
        let symbols: Vec<Value> = impacted
            .iter()
            .map(|name| json!({"name": name, "label": "Function", "file": "src/lib.rs"}))
            .collect();
        let inner = json!({
            "changed_files": ["src/lib.rs"],
            "changed_count": 1,
            "impacted_symbols": symbols,
            "depth": 2,
        });
        serde_json::to_string(&json!({
            "content": [{"type": "text", "text": serde_json::to_string(&inner).unwrap()}],
            "isError": false,
        }))
        .unwrap()
    }

    #[test]
    fn impacted_symbols_parses_and_dedups_from_text_envelope() {
        let raw = cbm_result(&["beta", "alpha", "alpha"]);
        let names: Vec<String> = impacted_symbols(&raw)
            .into_iter()
            .map(|symbol| symbol.name)
            .collect();
        assert_eq!(names, vec!["alpha", "beta"]);
        // Each impacted symbol carries the CBM-reported file for #339 disambiguation.
        assert!(
            impacted_symbols(&raw)
                .iter()
                .all(|symbol| symbol.file == "src/lib.rs")
        );
    }

    #[test]
    fn impacted_symbols_empty_when_no_symbols() {
        let raw = cbm_result(&[]);
        assert!(impacted_symbols(&raw).is_empty());
        assert!(impacted_symbols("not json").is_empty());
    }

    #[test]
    fn qn_suffix_match_respects_segment_boundary() {
        // `add` is the trailing segment of `calc.add` but not of `readd`.
        assert!(qn_ends_with_segment("calc.add", "add"));
        assert!(qn_ends_with_segment("pkg::mod::add", "add"));
        assert!(qn_ends_with_segment("a/b/add", "add"));
        assert!(!qn_ends_with_segment("readd", "add"));
        assert!(!qn_ends_with_segment("calc.add", "dd"));
    }

    #[test]
    fn resolver_grounds_short_name_against_fqn() {
        // #339 regression: a CBM short name whose vault FQN differs must resolve,
        // not fall silently to the provisional path.
        let snapshot = CbmGraphSnapshot {
            project: "calc".to_string(),
            panel_version: None,
            projects: Vec::new(),
            nodes: vec![
                CbmGraphNode {
                    source_node_id: 1,
                    project: "calc".to_string(),
                    label: "Function".to_string(),
                    name: "add".to_string(),
                    qualified_name: "calc.add".to_string(),
                    file_path: "src/calc.py".to_string(),
                    start_line: 1,
                    end_line: 3,
                    properties_json: "{}".to_string(),
                    node_vector: None,
                    cx_id: Some(CxId::from_bytes([0x11; 16])),
                    structural: false,
                },
                CbmGraphNode {
                    source_node_id: 2,
                    project: "calc".to_string(),
                    label: "Function".to_string(),
                    name: "sub".to_string(),
                    qualified_name: "calc.sub".to_string(),
                    file_path: "src/calc.py".to_string(),
                    start_line: 5,
                    end_line: 7,
                    properties_json: "{}".to_string(),
                    node_vector: None,
                    cx_id: Some(CxId::from_bytes([0x22; 16])),
                    structural: false,
                },
            ],
            edges: Vec::new(),
            file_hashes: Vec::new(),
            project_summaries: Vec::new(),
            token_vectors: Vec::new(),
        };
        let resolver = SymbolResolver::from_snapshot(&snapshot);
        assert_eq!(
            resolver.resolve("add", "src/calc.py"),
            SymbolResolution::Resolved {
                cx: CxId::from_bytes([0x11; 16]),
                how: "short_name",
            }
        );
        // Exact FQN input still resolves directly.
        assert_eq!(
            resolver.resolve("calc.sub", ""),
            SymbolResolution::Resolved {
                cx: CxId::from_bytes([0x22; 16]),
                how: "exact_qualified_name",
            }
        );
        // A name that appears in no node is genuinely unresolved.
        assert_eq!(
            resolver.resolve("mul", "src/calc.py"),
            SymbolResolution::Unresolved
        );
    }

    #[test]
    fn resolver_labels_ambiguous_short_name() {
        // Two distinct constellations share the short name `handler` in different
        // files; with no file to disambiguate this is a labeled ambiguity, never a
        // silent guess.
        let snapshot = CbmGraphSnapshot {
            project: "svc".to_string(),
            panel_version: None,
            projects: Vec::new(),
            nodes: vec![
                CbmGraphNode {
                    source_node_id: 1,
                    project: "svc".to_string(),
                    label: "Function".to_string(),
                    name: "handler".to_string(),
                    qualified_name: "svc.orders.handler".to_string(),
                    file_path: "src/orders.py".to_string(),
                    start_line: 1,
                    end_line: 3,
                    properties_json: "{}".to_string(),
                    node_vector: None,
                    cx_id: Some(CxId::from_bytes([0xAA; 16])),
                    structural: false,
                },
                CbmGraphNode {
                    source_node_id: 2,
                    project: "svc".to_string(),
                    label: "Function".to_string(),
                    name: "handler".to_string(),
                    qualified_name: "svc.users.handler".to_string(),
                    file_path: "src/users.py".to_string(),
                    start_line: 1,
                    end_line: 3,
                    properties_json: "{}".to_string(),
                    node_vector: None,
                    cx_id: Some(CxId::from_bytes([0xBB; 16])),
                    structural: false,
                },
            ],
            edges: Vec::new(),
            file_hashes: Vec::new(),
            project_summaries: Vec::new(),
            token_vectors: Vec::new(),
        };
        let resolver = SymbolResolver::from_snapshot(&snapshot);
        assert_eq!(
            resolver.resolve("handler", ""),
            SymbolResolution::Ambiguous {
                how: "short_name",
                candidates: 2,
            }
        );
        // The reported file disambiguates the same short name to one constellation.
        assert_eq!(
            resolver.resolve("handler", "src/users.py"),
            SymbolResolution::Resolved {
                cx: CxId::from_bytes([0xBB; 16]),
                how: "short_name",
            }
        );
    }

    #[test]
    fn ungrounded_block_is_labeled_provisional() {
        let block = ungrounded_block("shadow vault missing");
        let risk = &block["grounded_risk"];
        assert_eq!(risk["status"], "ungrounded");
        assert_eq!(risk["trust"], "provisional");
        assert_eq!(risk["schema"], DETECT_CHANGES_RISK_SCHEMA);
        assert_eq!(risk["reason"], "shadow vault missing");
    }

    #[test]
    fn ungrounded_block_merges_and_preserves_legacy_shape() {
        // The augmentation is additive: legacy detect_changes fields survive.
        let raw = cbm_result(&["alpha"]);
        let augmented = augment_tool_result(&raw, ungrounded_block("no evidence")).unwrap();
        let value: Value = serde_json::from_str(&augmented).unwrap();
        let text = value["content"][0]["text"].as_str().unwrap();
        let inner: Value = serde_json::from_str(text).unwrap();
        // Legacy shape preserved.
        assert_eq!(inner["changed_count"], 1);
        assert!(inner["impacted_symbols"].is_array());
        // Grounded-risk block layered on, labeled provisional.
        assert_eq!(inner["grounded_risk"]["status"], "ungrounded");
        assert_eq!(inner["grounded_risk"]["trust"], "provisional");
    }
}
