//! `get_architecture` aspects that were genuinely missing on main (#43).
//!
//! `kernel_context`, `agreement_graph`, and `n_eff`/`redundancy` already serve
//! from [`super::dispatch::handle_get_architecture`]; the residual two aspects are:
//!
//! - **`grounding_gaps`** — the kernel members that carry weight but no grounding
//!   anchor, ranked by persisted kernel weight. This reuses the exact grounding-gap
//!   report the `get_kernel` mode=gaps surface already builds
//!   ([`gap_members_from_kernel_context`] + [`gap_report_value`]), so the aspect and
//!   the dedicated tool never diverge.
//! - **`signal_ranking`** — the per-axis signal-bits cards the assay lane persists
//!   (`measure_bits` mode=signals), enumerated from the config store and surfaced
//!   both per-axis (as the assay builder ranked them) and as one flattened
//!   cross-axis ranking by bits.
//!
//! The underlying readers retain their labeled state payloads for internal
//! consumers. The public architecture dispatcher validates those states and
//! converts absent, corrupt, or partial data into an MCP tool error rather than
//! returning an unusable aspect as a successful result.

use astrolabe_kernel::GROUNDING_GAP_SCHEMA;

use super::*;

/// Exact legacy selector set owned by CBM's `get_architecture` implementation.
pub(crate) const CBM_ARCHITECTURE_ASPECTS: [&str; 13] = [
    "all",
    "overview",
    "structure",
    "dependencies",
    "routes",
    "languages",
    "packages",
    "entry_points",
    "hotspots",
    "boundaries",
    "layers",
    "file_tree",
    "clusters",
];

/// Public Astrolabe selectors. `kernel`/`kernel_context` and
/// `n_eff`/`redundancy` are explicit aliases for one physical read each.
pub(crate) const ASTROLABE_ARCHITECTURE_ASPECTS: [&str; 12] = [
    "skill_tree",
    "bridges",
    "kernel",
    "kernel_context",
    "anomalies",
    "provenance",
    "agreement_graph",
    "redundancy",
    "n_eff",
    "layout_map",
    "grounding_gaps",
    "signal_ranking",
];

const ASTROLABE_ARCHITECTURE_OUTPUTS: [&str; 10] = [
    "skill_tree",
    "bridges",
    "kernel_context",
    "anomalies",
    "provenance",
    "agreement_graph",
    "redundancy",
    "layout_map",
    "grounding_gaps",
    "signal_ranking",
];

pub(crate) struct ArchitectureRequestPlan {
    pub(crate) cbm_args_json: Option<String>,
    pub(crate) astrolabe_outputs: BTreeSet<&'static str>,
}

impl ArchitectureRequestPlan {
    pub(crate) fn parse(args: &Map<String, Value>) -> Result<Self, ToolFault> {
        for (name, value) in args {
            if !matches!(name.as_str(), "project" | "path" | "aspects") {
                return Err(ToolFault::new(
                    "ASTRO_ARCHITECTURE_ARGUMENT_UNKNOWN",
                    format!("get_architecture received unknown argument {name:?}"),
                    "remove the unknown field or use project, path, and aspects exactly as advertised by tools/list",
                )
                .with_argument(name, "project|path|aspects", value));
            }
        }
        let project = args.get("project").ok_or_else(|| {
            ToolFault::new(
                "ASTRO_ARCHITECTURE_PROJECT_REQUIRED",
                "get_architecture requires project",
                "pass the exact project name returned by list_projects",
            )
        })?;
        if project.as_str().is_none_or(str::is_empty) {
            return Err(argument_type_fault(
                "ASTRO_ARCHITECTURE_PROJECT_INVALID",
                "get_architecture",
                "project",
                "a non-empty JSON string",
                project,
            ));
        }
        if let Some(path) = args.get("path")
            && path.as_str().is_none()
        {
            return Err(argument_type_fault(
                "ASTRO_ARCHITECTURE_PATH_INVALID",
                "get_architecture",
                "path",
                "a JSON string",
                path,
            ));
        }

        let Some(aspects_value) = args.get("aspects") else {
            // The legacy omission contract remains CBM's complete architecture,
            // but Astrolabe-only reads are opt-in so the default never opens
            // unrelated Config/Vault families or recomputes agreement edges.
            return Ok(Self {
                cbm_args_json: Some(serde_json::to_string(&Value::Object(args.clone())).map_err(
                    |error| {
                        ToolFault::new(
                            "ASTRO_ARCHITECTURE_ARGUMENT_SERIALIZE_FAILED",
                            error.to_string(),
                            "repair the server JSON serializer before retrying the unchanged request",
                        )
                    },
                )?),
                astrolabe_outputs: BTreeSet::new(),
            });
        };
        let aspects = aspects_value.as_array().ok_or_else(|| {
            argument_type_fault(
                "ASTRO_ARCHITECTURE_ASPECTS_INVALID",
                "get_architecture",
                "aspects",
                "an array of advertised aspect strings",
                aspects_value,
            )
        })?;

        let mut cbm_aspects = Vec::new();
        let mut astrolabe_outputs = BTreeSet::new();
        for aspect in aspects {
            let Some(aspect) = aspect.as_str().filter(|aspect| !aspect.is_empty()) else {
                return Err(argument_type_fault(
                    "ASTRO_ARCHITECTURE_ASPECT_INVALID",
                    "get_architecture",
                    "aspects[]",
                    "a non-empty advertised aspect string",
                    aspect,
                ));
            };
            if CBM_ARCHITECTURE_ASPECTS.contains(&aspect) {
                if !cbm_aspects.contains(&aspect) {
                    cbm_aspects.push(aspect);
                }
                if aspect == "all" {
                    astrolabe_outputs.extend(ASTROLABE_ARCHITECTURE_OUTPUTS);
                }
                continue;
            }
            let output = match aspect {
                "skill_tree" => "skill_tree",
                "bridges" => "bridges",
                "kernel" | "kernel_context" => "kernel_context",
                "anomalies" => "anomalies",
                "provenance" => "provenance",
                "agreement_graph" => "agreement_graph",
                "redundancy" | "n_eff" => "redundancy",
                "layout_map" => "layout_map",
                "grounding_gaps" => "grounding_gaps",
                "signal_ranking" => "signal_ranking",
                other => {
                    return Err(ToolFault::new(
                        "ASTRO_ARCHITECTURE_ASPECT_UNKNOWN",
                        format!("get_architecture received unknown aspect {other:?}"),
                        format!(
                            "use one of: {}",
                            CBM_ARCHITECTURE_ASPECTS
                                .iter()
                                .chain(ASTROLABE_ARCHITECTURE_ASPECTS.iter())
                                .copied()
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    )
                    .with_detail("observed_aspect", other));
                }
            };
            astrolabe_outputs.insert(output);
        }

        if !astrolabe_outputs.is_empty()
            && args
                .get("path")
                .and_then(Value::as_str)
                .is_some_and(|path| !path.is_empty())
        {
            return Err(ToolFault::new(
                "ASTRO_ARCHITECTURE_SCOPE_UNSUPPORTED",
                "Astrolabe architecture aspects are project-scoped and cannot truthfully honor path",
                "remove path for project-wide Calyx aspects, or request only legacy CBM aspects when using path",
            )
            .with_detail("path", args.get("path").cloned().unwrap_or(Value::Null))
            .with_detail(
                "astrolabe_aspects",
                astrolabe_outputs.iter().copied().collect::<Vec<_>>(),
            ));
        }

        let cbm_args_json = if cbm_aspects.is_empty() && !astrolabe_outputs.is_empty() {
            None
        } else {
            let mut sanitized = args.clone();
            sanitized.insert("aspects".to_string(), json!(cbm_aspects));
            Some(
                serde_json::to_string(&Value::Object(sanitized)).map_err(|error| {
                    ToolFault::new(
                        "ASTRO_ARCHITECTURE_ARGUMENT_SERIALIZE_FAILED",
                        error.to_string(),
                        "repair the server JSON serializer before retrying the unchanged request",
                    )
                })?,
            )
        };
        Ok(Self {
            cbm_args_json,
            astrolabe_outputs,
        })
    }
}

/// Execute only explicitly requested Astrolabe reads, in a stable output order.
pub(crate) fn read_astrolabe_architecture_aspects(
    cache_dir: &Path,
    project: &str,
    outputs: &BTreeSet<&'static str>,
) -> Result<Value, DynError> {
    let mut result = Map::new();
    for output in ASTROLABE_ARCHITECTURE_OUTPUTS {
        if !outputs.contains(output) {
            continue;
        }
        let value = match output {
            "skill_tree" => read_skill_tree_metadata(cache_dir, project)?,
            "bridges" => read_bridges_metadata(cache_dir, project)?,
            "kernel_context" => read_kernel_context_metadata(cache_dir, project)?,
            "anomalies" => read_anomaly_report(cache_dir, project)?,
            "provenance" => read_provenance_metadata(cache_dir, project)?,
            "agreement_graph" => read_agreement_graph_aspect(cache_dir, project)?,
            "redundancy" => read_redundancy_neff_aspect(cache_dir, project),
            "layout_map" => read_layout_map_aspect(cache_dir, project)?,
            "grounding_gaps" => read_grounding_gaps_aspect(cache_dir, project)?,
            "signal_ranking" => read_signal_ranking_aspect(cache_dir, project)?,
            _ => unreachable!("canonical Astrolabe architecture output"),
        };
        validate_architecture_aspect_state(output, &value)?;
        result.insert(output.to_string(), value);
    }
    Ok(Value::Object(result))
}

/// Accept only complete physical states for each public aspect. Empty-but-valid
/// measurements are explicit successes for anomaly and agreement graphs; every
/// absence, corruption, partial build, or unknown status is a tool failure.
fn validate_architecture_aspect_state(output: &str, value: &Value) -> Result<(), DynError> {
    let status = value.get("status").and_then(Value::as_str).ok_or_else(|| -> DynError {
        format!(
            "ASTRO_ARCHITECTURE_ASPECT_STATE_INVALID: {output} has no string status; remediation: preserve the persisted generation and repair its canonical aspect producer"
        )
        .into()
    })?;
    let complete = match output {
        "skill_tree" | "bridges" | "kernel_context" | "provenance" | "layout_map" => {
            status == "built"
        }
        "anomalies" | "agreement_graph" => matches!(status, "built" | "empty"),
        "redundancy" => status == "measured",
        "grounding_gaps" | "signal_ranking" => status == "served",
        _ => false,
    };
    if complete {
        return Ok(());
    }
    let reason = value
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("the persisted aspect did not report a complete physical state");
    let remediation = value
        .get("remediation")
        .and_then(Value::as_str)
        .unwrap_or("rerun the owning producer and inspect its persisted source before retrying");
    Err(format!(
        "ASTRO_ARCHITECTURE_ASPECT_UNAVAILABLE: aspect={output}, status={status}, reason={reason}; remediation: {remediation}"
    )
    .into())
}

/// Schema tag for the `signal_ranking` architecture aspect envelope.
pub(crate) const SIGNAL_RANKING_ASPECT_SCHEMA: &str =
    "astrolabe.get_architecture.signal_ranking.v1";

/// Builds the `grounding_gaps` architecture aspect from the persisted kernel
/// context. Returns the same grounding-gap report `get_kernel` mode=gaps serves, or
/// a labeled `unavailable` payload when the kernel-context scope summaries are
/// absent/corrupt.
pub(crate) fn read_grounding_gaps_aspect(
    cache_dir: &Path,
    project: &str,
) -> Result<Value, DynError> {
    let kernel_context = read_kernel_context_metadata(cache_dir, project)?;
    match gap_members_from_kernel_context(&kernel_context) {
        Ok(members) => Ok(gap_report_value(project, &members)),
        Err(reason) => Ok(grounding_gaps_unavailable_json(&reason)),
    }
}

/// Labeled fail-closed payload for a `grounding_gaps` aspect whose kernel-context
/// scope summaries could not be read.
fn grounding_gaps_unavailable_json(reason: &str) -> Value {
    json!({
        "schema": GROUNDING_GAP_SCHEMA,
        "mode": "gaps",
        "status": "unavailable",
        "freshness": "not_evaluated",
        "trust": "provisional",
        "provenance": ["kernel_context.scope_summaries", "metadata:kernel_context_json"],
        "reason": reason,
        "remediation": "rerun index_repository with calyx=\"shadow\" so the kernel-context scope summaries (with per-member grounded flags and kernel weights) are persisted before requesting the grounding_gaps aspect",
    })
}

/// One cross-axis signal row flattened out of the per-axis cards.
struct FlatSignal {
    axis: String,
    slot: String,
    bits: f64,
    trust: String,
}

/// Builds the `signal_ranking` architecture aspect from the exact committed
/// #885 transaction. A bare row, prepared marker, missing ledger line, or hash
/// divergence is a hard read failure and is never served as a partial ranking.
pub(crate) fn read_signal_ranking_aspect(
    cache_dir: &Path,
    project: &str,
) -> Result<Value, DynError> {
    let Some(state) = read_committed_signal_card_state(cache_dir, project)? else {
        return Ok(signal_ranking_unavailable_json(
            "no committed signals-card transaction for this project",
        ));
    };
    let transaction_id = state
        .marker
        .get("transaction_id")
        .and_then(Value::as_str)
        .ok_or_else(|| -> DynError {
            "ASTRO_ARCHITECTURE_SIGNAL_TRANSACTION_INVALID: committed marker has no string transaction_id"
                .into()
        })?
        .to_string();

    let mut axes: Vec<Value> = Vec::new();
    let mut flat: Vec<FlatSignal> = Vec::new();
    for (key, raw) in &state.rows {
        let doc: Value = serde_json::from_str(raw).map_err(|error| -> DynError {
            format!(
                "ASTRO_ARCHITECTURE_SIGNAL_CARD_CORRUPT: persisted card {key:?} is not JSON: {error}; remediation: preserve the row and rerun the assay signal-card producer"
            )
            .into()
        })?;
        if let Some(reason) = measure_bits_card_doc_invalid(&doc) {
            return Err(format!(
                "ASTRO_ARCHITECTURE_SIGNAL_CARD_INVALID: persisted card {key:?} failed its assay envelope contract: {reason}; remediation: preserve the row and rerun the assay signal-card producer"
            )
            .into());
        }
        let card: astrolabe_assay::SignalRankingCard = serde_json::from_value(
            doc.get("card")
                .cloned()
                .ok_or_else(|| -> DynError {
                    format!(
                        "ASTRO_ARCHITECTURE_SIGNAL_CARD_INVALID: persisted card {key:?} has no card payload"
                    )
                    .into()
                })?,
        )
        .map_err(|error| -> DynError {
            format!(
                "ASTRO_ARCHITECTURE_SIGNAL_CARD_INVALID: persisted card {key:?} is not a SignalRankingCard: {error}; remediation: preserve the row and rerun the assay signal-card producer"
            )
            .into()
        })?;
        if card.axis.is_empty() || card.signals.iter().any(|signal| signal.slot.is_empty()) {
            return Err(format!(
                "ASTRO_ARCHITECTURE_SIGNAL_CARD_INVALID: persisted card {key:?} has an empty axis or slot identity; remediation: preserve the row and rerun the assay signal-card producer"
            )
            .into());
        }
        let axis = card.axis;
        let expected_key = measure_bits_card_key(project, "signals", Some(&axis), None);
        if key != &expected_key
            || doc.get("mode").and_then(Value::as_str) != Some("signals")
            || doc.get("project").and_then(Value::as_str) != Some(project)
            || doc.get("axis").and_then(Value::as_str) != Some(axis.as_str())
            || !doc.get("scope").is_some_and(Value::is_null)
        {
            return Err(format!(
                "ASTRO_ARCHITECTURE_SIGNAL_CARD_IDENTITY_MISMATCH: committed row {key:?} does not encode its exact project/mode/axis/scope identity; remediation: preserve the transaction and reindex through the #885 producer"
            )
            .into());
        }
        let card_trust = doc.get("trust").cloned().ok_or_else(|| -> DynError {
            format!("ASTRO_ARCHITECTURE_SIGNAL_CARD_INVALID: row {key:?} has no trust").into()
        })?;
        let card_freshness = doc.get("freshness").cloned().ok_or_else(|| -> DynError {
            format!("ASTRO_ARCHITECTURE_SIGNAL_CARD_INVALID: row {key:?} has no freshness").into()
        })?;
        let seq = doc.get("seq").cloned().ok_or_else(|| -> DynError {
            format!("ASTRO_ARCHITECTURE_SIGNAL_CARD_INVALID: row {key:?} has no seq").into()
        })?;
        let mut axis_signals: Vec<Value> = Vec::new();
        for signal in card.signals {
            let trust_value = serde_json::to_value(signal.trust)?;
            let trust = trust_value
                .as_str()
                .ok_or_else(|| -> DynError {
                    format!(
                        "ASTRO_ARCHITECTURE_SIGNAL_CARD_INVALID: persisted card {key:?} encoded a non-string trust tag; remediation: preserve the row and repair the canonical assay serializer"
                    )
                    .into()
                })?
                .to_string();
            let slot = signal.slot;
            let bits = signal.bits;
            axis_signals.push(json!({
                "slot": slot.clone(),
                "bits": bits,
                "trust": trust.clone(),
            }));
            flat.push(FlatSignal {
                axis: axis.clone(),
                slot,
                bits,
                trust,
            });
        }
        axes.push(json!({
            "axis": axis,
            "source": format!("config:{key}"),
            "card_trust": card_trust,
            "card_freshness": card_freshness,
            "seq": seq,
            "signal_count": axis_signals.len(),
            "signals": axis_signals,
        }));
    }

    // Cross-axis flattened ranking: bits descending, then (axis, slot) ascending
    // for a deterministic tie-break.
    flat.sort_by(|left, right| {
        right
            .bits
            .total_cmp(&left.bits)
            .then_with(|| left.axis.cmp(&right.axis))
            .then_with(|| left.slot.cmp(&right.slot))
    });
    let ranked: Vec<Value> = flat
        .iter()
        .map(|signal| {
            json!({
                "axis": signal.axis,
                "slot": signal.slot,
                "bits": signal.bits,
                "trust": signal.trust,
            })
        })
        .collect();

    Ok(json!({
        "schema": SIGNAL_RANKING_ASPECT_SCHEMA,
        "status": "served",
        "project": project,
        "transaction_id": transaction_id,
        "transaction": state.marker,
        "axis_count": axes.len(),
        "axes": axes,
        "ranked_signal_count": ranked.len(),
        "ranked_signals": ranked,
        "corrupt_card_count": 0,
        "corrupt_cards": [],
        "trust": "grounded",
        "freshness": "fresh",
        "provenance": [
            format!("config:{}", signal_card_transaction_key(project)),
            "assay:measure_bits.signals",
            "ledger:signal-cards.ndjson",
            "ranking=SignalBits.bits desc",
        ],
    }))
}

/// Labeled fail-closed payload for a `signal_ranking` aspect with no persisted
/// signals card.
fn signal_ranking_unavailable_json(reason: &str) -> Value {
    json!({
        "schema": SIGNAL_RANKING_ASPECT_SCHEMA,
        "status": "unavailable",
        "freshness": "not_evaluated",
        "trust": "provisional",
        "provenance": ["assay:measure_bits.signals"],
        "reason": reason,
        "remediation": "run the assay signals lane (measure_bits mode=\"signals\") for this project's axes so a per-slot signal-bits card is persisted before requesting the signal_ranking aspect",
    })
}
