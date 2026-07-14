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
//! Both aspects fail closed with a labeled `unavailable` payload (freshness
//! `not_evaluated`, trust `provisional`, reason + remediation) rather than a
//! fabricated or partial answer when their persisted source is absent or corrupt.

use astrolabe_kernel::GROUNDING_GAP_SCHEMA;

use super::*;

/// Schema tag for the `signal_ranking` architecture aspect envelope.
pub(crate) const SIGNAL_RANKING_ASPECT_SCHEMA: &str = "astrolabe.get_architecture.signal_ranking.v1";

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

/// The config-store key prefix under which the per-axis signals cards live.
fn signals_card_prefix(project: &str) -> String {
    metadata_key(project, "assay_card.signals")
}

/// One cross-axis signal row flattened out of the per-axis cards.
struct FlatSignal {
    axis: String,
    slot: String,
    bits: f64,
    trust: String,
}

/// Builds the `signal_ranking` architecture aspect from the persisted per-axis
/// signals cards. Returns a labeled `unavailable` payload when the assay lane has
/// persisted no signals card for the project.
pub(crate) fn read_signal_ranking_aspect(
    cache_dir: &Path,
    project: &str,
) -> Result<Value, DynError> {
    let prefix = signals_card_prefix(project);
    let rows = scan_config_prefix(cache_dir, &prefix)?;
    if rows.is_empty() {
        return Ok(signal_ranking_unavailable_json(
            "no persisted signals cards for this project",
        ));
    }

    let mut axes: Vec<Value> = Vec::new();
    let mut flat: Vec<FlatSignal> = Vec::new();
    let mut corrupt: Vec<String> = Vec::new();

    for (key, raw) in &rows {
        let doc: Value = match serde_json::from_str(raw) {
            Ok(doc) => doc,
            Err(error) => {
                corrupt.push(format!("{key}: {error}"));
                continue;
            }
        };
        let card = doc.get("card").cloned().unwrap_or(Value::Null);
        let axis = card
            .get("axis")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let signals = card
            .get("signals")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut axis_signals: Vec<Value> = Vec::new();
        for signal in &signals {
            let slot = signal
                .get("slot")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let bits = signal.get("bits").and_then(Value::as_f64).unwrap_or(0.0);
            let trust = signal
                .get("trust")
                .and_then(Value::as_str)
                .unwrap_or("provisional")
                .to_string();
            axis_signals.push(json!({
                "slot": slot,
                "bits": bits,
                "trust": trust,
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
            "card_trust": doc.get("trust").cloned().unwrap_or(Value::Null),
            "card_freshness": doc.get("freshness").cloned().unwrap_or(Value::Null),
            "seq": doc.get("seq").cloned().unwrap_or(Value::Null),
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

    // A card present but every card corrupt is fail-closed unavailable, not a
    // silent empty ranking.
    if axes.is_empty() {
        return Ok(signal_ranking_unavailable_json(&format!(
            "every persisted signals card was corrupt: {}",
            corrupt.join("; ")
        )));
    }

    Ok(json!({
        "schema": SIGNAL_RANKING_ASPECT_SCHEMA,
        "status": "served",
        "project": project,
        "axis_count": axes.len(),
        "axes": axes,
        "ranked_signal_count": ranked.len(),
        "ranked_signals": ranked,
        "corrupt_card_count": corrupt.len(),
        "corrupt_cards": corrupt,
        "trust": "grounded",
        "freshness": "fresh",
        "provenance": [
            format!("config:{prefix}*"),
            "assay:measure_bits.signals",
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

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_cache() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "astro-w14g-arch-aspects-{}-{}",
            std::process::id(),
            unix_epoch_millis(),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    // FSV: with a persisted kernel-context carrying an ungrounded high-weight
    // member, the grounding_gaps aspect surfaces that member (readback of the exact
    // report get_kernel mode=gaps serves).
    #[test]
    fn grounding_gaps_aspect_reports_ungrounded_members() {
        let cache = tmp_cache();
        let project = "demo";
        let kernel_context = json!({
            "scope_summaries": {
                "status": "served",
                "summaries": [{
                    "scope_id": "scope.a",
                    "members": [
                        {"symbol_id": "s.gap", "qualified_name": "m::gap", "kernel_weight": 42, "grounded": false, "provenance_ref": "r1"},
                        {"symbol_id": "s.ok",  "qualified_name": "m::ok",  "kernel_weight": 7,  "grounded": true,  "provenance_ref": "r2"}
                    ]
                }]
            }
        });
        write_config_value(
            &cache,
            &metadata_key(project, "kernel_context_json"),
            &serde_json::to_string(&kernel_context).unwrap(),
        )
        .unwrap();

        let aspect = read_grounding_gaps_aspect(&cache, project).unwrap();
        assert_eq!(aspect.get("status").and_then(Value::as_str), Some("served"));
        assert_eq!(aspect.get("member_count").and_then(Value::as_u64), Some(2));
        assert_eq!(aspect.get("gap_count").and_then(Value::as_u64), Some(1));
        let gaps = aspect.get("gaps").and_then(Value::as_array).unwrap();
        assert_eq!(gaps.len(), 1);
        assert_eq!(
            gaps[0].get("symbol_id").and_then(Value::as_str),
            Some("s.gap")
        );
        std::fs::remove_dir_all(&cache).ok();
    }

    // Absent kernel context -> labeled unavailable, never a fabricated gap list.
    #[test]
    fn grounding_gaps_aspect_unavailable_without_kernel_context() {
        let cache = tmp_cache();
        let aspect = read_grounding_gaps_aspect(&cache, "missing").unwrap();
        assert_eq!(
            aspect.get("status").and_then(Value::as_str),
            Some("unavailable")
        );
        assert_eq!(
            aspect.get("trust").and_then(Value::as_str),
            Some("provisional")
        );
        assert!(aspect.get("remediation").and_then(Value::as_str).is_some());
        std::fs::remove_dir_all(&cache).ok();
    }

    // FSV: with two persisted per-axis signals cards, the aspect surfaces both axes
    // and one flattened cross-axis ranking by bits descending (hand-computable).
    #[test]
    fn signal_ranking_aspect_ranks_persisted_signals_cards() {
        let cache = tmp_cache();
        let project = "demo";
        let defect_card = json!({
            "trust": "trusted",
            "freshness": "fresh",
            "seq": 3,
            "card": {
                "axis": "defect",
                "signals": [
                    {"slot": "S7",  "bits": 0.90, "trust": "trusted"},
                    {"slot": "S18", "bits": 0.20, "trust": "provisional"}
                ]
            }
        });
        let churn_card = json!({
            "trust": "provisional",
            "freshness": "fresh",
            "seq": 1,
            "card": {
                "axis": "churn",
                "signals": [
                    {"slot": "S20", "bits": 0.55, "trust": "trusted"}
                ]
            }
        });
        write_config_value(
            &cache,
            &metadata_key(project, "assay_card.signals.axis:defect"),
            &serde_json::to_string(&defect_card).unwrap(),
        )
        .unwrap();
        write_config_value(
            &cache,
            &metadata_key(project, "assay_card.signals.axis:churn"),
            &serde_json::to_string(&churn_card).unwrap(),
        )
        .unwrap();

        let aspect = read_signal_ranking_aspect(&cache, project).unwrap();
        assert_eq!(aspect.get("status").and_then(Value::as_str), Some("served"));
        assert_eq!(aspect.get("axis_count").and_then(Value::as_u64), Some(2));
        assert_eq!(aspect.get("trust").and_then(Value::as_str), Some("grounded"));

        let ranked = aspect.get("ranked_signals").and_then(Value::as_array).unwrap();
        let order: Vec<(&str, &str)> = ranked
            .iter()
            .map(|r| {
                (
                    r.get("axis").and_then(Value::as_str).unwrap(),
                    r.get("slot").and_then(Value::as_str).unwrap(),
                )
            })
            .collect();
        // bits: defect/S7=0.90 > churn/S20=0.55 > defect/S18=0.20
        assert_eq!(
            order,
            [("defect", "S7"), ("churn", "S20"), ("defect", "S18")]
        );
        std::fs::remove_dir_all(&cache).ok();
    }

    // No persisted signals card -> labeled unavailable.
    #[test]
    fn signal_ranking_aspect_unavailable_without_cards() {
        let cache = tmp_cache();
        let aspect = read_signal_ranking_aspect(&cache, "empty").unwrap();
        assert_eq!(
            aspect.get("status").and_then(Value::as_str),
            Some("unavailable")
        );
        assert_eq!(
            aspect.get("schema").and_then(Value::as_str),
            Some(SIGNAL_RANKING_ASPECT_SCHEMA)
        );
        std::fs::remove_dir_all(&cache).ok();
    }

    // A corrupt-only card set fails closed rather than serving an empty ranking.
    #[test]
    fn signal_ranking_aspect_corrupt_only_is_unavailable() {
        let cache = tmp_cache();
        let project = "corrupt";
        write_config_value(
            &cache,
            &metadata_key(project, "assay_card.signals.axis:defect"),
            "{not json",
        )
        .unwrap();
        let aspect = read_signal_ranking_aspect(&cache, project).unwrap();
        assert_eq!(
            aspect.get("status").and_then(Value::as_str),
            Some("unavailable")
        );
        std::fs::remove_dir_all(&cache).ok();
    }
}
