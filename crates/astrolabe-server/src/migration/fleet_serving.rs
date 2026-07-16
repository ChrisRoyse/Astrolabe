//! Fleet-scope serving (#459): `get_kernel` + `kernel_answer` over the composed
//! fleet kernel (`fleet:<language>:<version>`, built by #456) with per-repo
//! provenance citations, honest labels, and refusal-with-deficit.
//!
//! A `scope` argument starting with `fleet:` routes here instead of the
//! per-project surface: fleet scope is cross-project, so `project` and the
//! migration dial are not required. Serving reads through the #456 verified
//! readback path ([`astrolabe_fleet::read_fleet_kernel`]: members-hash
//! re-derivation plus Kernel-ledger pairing, fail-closed) and the persisted
//! `fleet-kernel` sidecar for per-member provenance (repo, path, qualified
//! name, content key, grounded flag, score).
//!
//! Honesty gates (invariants 1–3):
//! - The sidecar's measured per-repo recall gate decides the served label: a
//!   below-gate fleet kernel serves `provisional`, never trusted.
//! - `kernel_answer` at fleet scope is **deterministic, declared exemplar
//!   retrieval**: token containment over member occurrence qualified names and
//!   paths — no semantic inference is claimed. A query no member grounds
//!   refuses with a structured deficit ([`ASTRO_FLEET_ANSWER_DEFICIT`]),
//!   never a guess.
//! - Unknown scope, malformed scope, and missing catalog root each refuse with
//!   their own stable code.

use super::*;

use astrolabe_fleet::{FLEET_KERNEL_REPORT_KIND, FleetCatalog};

/// Refusal: the `fleet:` scope names no scope id (malformed).
pub(crate) const ASTRO_FLEET_SCOPE_INVALID: &str = "ASTRO_FLEET_SCOPE_INVALID";
/// Refusal: the fleet catalog root does not exist or failed to open.
pub(crate) const ASTRO_FLEET_CATALOG_MISSING: &str = "ASTRO_FLEET_CATALOG_MISSING";
/// Refusal: no fleet kernel is persisted at the requested scope.
pub(crate) const ASTRO_FLEET_SCOPE_UNKNOWN: &str = "ASTRO_FLEET_SCOPE_UNKNOWN";
/// Refusal: no fleet kernel member grounds the query (honest deficit).
pub(crate) const ASTRO_FLEET_ANSWER_DEFICIT: &str = "ASTRO_FLEET_ANSWER_DEFICIT";
/// Refusal: the `limit` argument is outside its declared bounds.
pub(crate) const ASTRO_FLEET_ANSWER_LIMIT_RANGE: &str = "ASTRO_FLEET_ANSWER_LIMIT_RANGE";

/// Declared bounds for the `kernel_answer` fleet citation limit argument.
const FLEET_ANSWER_LIMIT_DEFAULT: u64 = 8;
const FLEET_ANSWER_LIMIT_MIN: u64 = 1;
const FLEET_ANSWER_LIMIT_MAX: u64 = 64;

/// Whether a scope id addresses the fleet serving surface.
pub(crate) fn is_fleet_scope(scope: &str) -> bool {
    scope.starts_with("fleet:")
}

fn refusal(code: &str, scope: &str, message: String, remediation: &str) -> Value {
    json!({
        "schema": "astrolabe.get_kernel.v1",
        "status": "refused",
        "fleet": true,
        "scope": scope,
        "code": code,
        "message": message,
        "remediation": remediation,
        "trust": "provisional",
        "freshness": "not_evaluated",
    })
}

/// The verified fleet-kernel readback plus its provenance sidecar.
struct FleetKernelServing {
    /// `read_fleet_kernel` summary — produced only after the members-hash
    /// re-derivation and ledger pairing passed fail-closed.
    summary: Value,
    /// Full `fleet-kernel` sidecar (members with per-repo occurrences, gate).
    sidecar: Value,
    /// Catalog root the kernel was served from (provenance).
    catalog_root: String,
}

fn load_fleet_kernel(
    args_obj: &Map<String, Value>,
    scope: &str,
) -> Result<FleetKernelServing, Box<Value>> {
    let tail = &scope["fleet:".len()..];
    if tail.trim().is_empty() {
        return Err(Box::new(refusal(
            ASTRO_FLEET_SCOPE_INVALID,
            scope,
            format!("fleet scope {scope:?} names no scope id after the fleet: prefix"),
            "pass a full fleet scope id such as \"fleet:rust:v1\"",
        )));
    }
    let root = string_arg(args_obj, "fleet_catalog_root")
        .unwrap_or(astrolabe_fleet::DEFAULT_CATALOG_ROOT)
        .to_string();
    if !Path::new(&root).exists() {
        return Err(Box::new(refusal(
            ASTRO_FLEET_CATALOG_MISSING,
            scope,
            format!("fleet catalog root {root:?} does not exist"),
            "compose a fleet kernel first (astrolabe-fleet compose) or pass fleet_catalog_root",
        )));
    }
    let catalog = FleetCatalog::open(Path::new(&root)).map_err(|error| {
        Box::new(refusal(
            ASTRO_FLEET_CATALOG_MISSING,
            scope,
            format!(
                "fleet catalog at {root:?} failed to open: [{}] {}",
                error.code, error.message
            ),
            "repair or re-create the fleet catalog vault, then retry",
        ))
    })?;
    let (summary, _raw) = astrolabe_fleet::read_fleet_kernel(&catalog, scope).map_err(|error| {
        if error.code == astrolabe_fleet::ASTRO_FLEET_KERNEL_MISSING {
            Box::new(refusal(
                ASTRO_FLEET_SCOPE_UNKNOWN,
                scope,
                format!("no fleet kernel is persisted at scope {scope:?} in catalog {root:?}"),
                "compose the fleet kernel for this scope (astrolabe-fleet compose --scope <id>), then retry",
            ))
        } else {
            Box::new(refusal(
                error.code,
                scope,
                format!("fleet kernel readback failed: {}", error.message),
                "recompose the fleet kernel; readback is fail-closed and found divergence",
            ))
        }
    })?;
    let sidecar_bytes = catalog
        .read_fleet_report(FLEET_KERNEL_REPORT_KIND, scope)
        .ok()
        .flatten()
        .ok_or_else(|| {
            Box::new(refusal(
                ASTRO_FLEET_SCOPE_UNKNOWN,
                scope,
                format!("fleet kernel at {scope:?} has no provenance sidecar"),
                "recompose the fleet kernel so the sidecar is persisted",
            ))
        })?;
    let sidecar: Value = serde_json::from_slice(&sidecar_bytes).map_err(|error| {
        Box::new(refusal(
            ASTRO_FLEET_SCOPE_UNKNOWN,
            scope,
            format!("fleet kernel sidecar did not parse: {error}"),
            "recompose the fleet kernel so the sidecar is persisted",
        ))
    })?;
    Ok(FleetKernelServing {
        summary,
        sidecar,
        catalog_root: root,
    })
}

fn gate_label(sidecar: &Value) -> &str {
    sidecar
        .get("gate")
        .and_then(|gate| gate.get("label"))
        .and_then(Value::as_str)
        .unwrap_or("provisional")
}

fn member_citation(member: &Value) -> Value {
    json!({
        "fleet_cx": member.get("fleet_cx"),
        "node_kind": member.get("node_kind"),
        "content_key": member.get("content_key"),
        "repo_count": member.get("repo_count"),
        "grounded": member.get("grounded"),
        "score_permille": member.get("score_permille"),
        "occurrences": member.get("occurrences"),
    })
}

/// `get_kernel` at fleet scope: serves the verified fleet kernel members with
/// per-repo provenance. `mode="read"` (default) serves every member;
/// `mode="gaps"` serves the ungrounded members. `build`/`quadrant` are
/// per-project surfaces and refuse at fleet scope.
pub(crate) fn handle_get_kernel_fleet(
    args_obj: &Map<String, Value>,
    scope: &str,
) -> Result<String, DynError> {
    let mode = string_arg(args_obj, "mode").unwrap_or("read");
    if mode != "read" && mode != "gaps" {
        return tool_json_error_result(refusal(
            ASTRO_GET_KERNEL_MODE_UNSUPPORTED,
            scope,
            format!(
                "get_kernel mode {mode:?} is not available at fleet scope; fleet serves mode=\"read\" and mode=\"gaps\""
            ),
            "use mode=\"read\" or mode=\"gaps\" for a fleet scope; build/quadrant are per-project surfaces",
        ));
    }
    let serving = match load_fleet_kernel(args_obj, scope) {
        Ok(serving) => serving,
        Err(refusal) => return tool_json_error_result(*refusal),
    };
    let members: Vec<&Value> = serving
        .sidecar
        .get("members")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|member| {
            mode != "gaps" || member.get("grounded").and_then(Value::as_bool) != Some(true)
        })
        .collect();
    let label = gate_label(&serving.sidecar);
    tool_json_result(json!({
        "schema": "astrolabe.get_kernel.v1",
        "status": "served",
        "mode": mode,
        "fleet": true,
        "scope": scope,
        "member_count": serving.summary.get("member_count"),
        "served_member_count": members.len(),
        "node_count": serving.summary.get("node_count"),
        "members_hash": serving.summary.get("members_hash_persisted"),
        "ledger_paired": serving.summary.get("ledger_paired"),
        "recall_permille": serving.summary.get("recall_permille"),
        "gate": serving.sidecar.get("gate"),
        "verdict": serving.sidecar.get("verdict"),
        "members": members.iter().map(|member| member_citation(member)).collect::<Vec<_>>(),
        // Invariant 1: the measured per-repo recall gate decides the label —
        // a below-gate fleet kernel is never served trusted.
        "trust": if label == "trusted" { "verified" } else { "provisional" },
        "freshness": "as_of_compose",
        "compose_input_hash": serving.sidecar.get("compose_input_hash"),
        "provenance": [
            format!(
                "fleet-catalog:{} Kernel CF scope={scope} (members-hash + ledger pairing verified at read)",
                serving.catalog_root
            ),
            format!("fleet-kernel sidecar {FLEET_KERNEL_REPORT_KIND}:{scope}"),
        ],
    }))
}

/// `kernel_answer` at fleet scope: deterministic, declared exemplar retrieval —
/// token containment over member occurrence qualified names and paths, ranked
/// by (full match, matched tokens, kernel score, id). A query no member grounds
/// refuses with a structured deficit; nothing is inferred or fabricated.
pub(crate) fn handle_kernel_answer_fleet(
    args_obj: &Map<String, Value>,
    scope: &str,
) -> Result<String, DynError> {
    let query = string_arg(args_obj, "query").unwrap_or("").trim();
    if query.is_empty() {
        return tool_error_result(format!(
            "{ASTRO_KERNEL_ANSWER_QUERY_REQUIRED}: kernel_answer requires a non-empty query; remediation: pass the question to answer from the fleet kernel"
        ));
    }
    let limit = match args_obj.get("limit") {
        None => FLEET_ANSWER_LIMIT_DEFAULT,
        Some(value) => match value.as_u64() {
            Some(limit) if (FLEET_ANSWER_LIMIT_MIN..=FLEET_ANSWER_LIMIT_MAX).contains(&limit) => {
                limit
            }
            _ => {
                return tool_json_error_result(refusal(
                    ASTRO_FLEET_ANSWER_LIMIT_RANGE,
                    scope,
                    format!(
                        "limit {value} is outside the declared bounds {FLEET_ANSWER_LIMIT_MIN}..={FLEET_ANSWER_LIMIT_MAX}"
                    ),
                    "pass an integer limit within the declared bounds",
                ));
            }
        },
    };
    let serving = match load_fleet_kernel(args_obj, scope) {
        Ok(serving) => serving,
        Err(refusal) => return tool_json_error_result(*refusal),
    };

    let tokens: Vec<String> = query
        .to_lowercase()
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|token| token.len() >= 2)
        .map(str::to_string)
        .collect();
    let members: Vec<&Value> = serving
        .sidecar
        .get("members")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .collect();
    if tokens.is_empty() {
        return tool_json_error_result(json!({
            "schema": KERNEL_ANSWER_SCHEMA,
            "status": "refused",
            "fleet": true,
            "scope": scope,
            "code": ASTRO_FLEET_ANSWER_DEFICIT,
            "query": query,
            "deficit": {
                "query_tokens": 0,
                "members_scanned": members.len(),
                "matched_members": 0,
                "reason": "the query yields no usable tokens (>= 2 alphanumeric chars)",
            },
            "message": "the fleet kernel cannot support this query: no usable query tokens",
            "remediation": "ask about a concrete symbol, module, or concept name",
            "trust": "provisional",
            "freshness": "not_evaluated",
        }));
    }

    // Deterministic token-containment match over occurrence names and paths.
    let mut matched: Vec<(bool, usize, u64, String, &Value)> = Vec::new();
    for member in &members {
        let haystacks: Vec<String> = member
            .get("occurrences")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .flat_map(|occurrence| {
                ["qualified_name", "rel_file_path"]
                    .into_iter()
                    .filter_map(|field| {
                        occurrence
                            .get(field)
                            .and_then(Value::as_str)
                            .map(str::to_lowercase)
                    })
            })
            .collect();
        let matched_tokens = tokens
            .iter()
            .filter(|token| haystacks.iter().any(|haystack| haystack.contains(*token)))
            .count();
        if matched_tokens == 0 {
            continue;
        }
        let score = member
            .get("score_permille")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let id = member
            .get("fleet_cx")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        matched.push((
            matched_tokens == tokens.len(),
            matched_tokens,
            score,
            id,
            member,
        ));
    }
    if matched.is_empty() {
        return tool_json_error_result(json!({
            "schema": KERNEL_ANSWER_SCHEMA,
            "status": "refused",
            "fleet": true,
            "scope": scope,
            "code": ASTRO_FLEET_ANSWER_DEFICIT,
            "query": query,
            "deficit": {
                "query_tokens": tokens.len(),
                "members_scanned": members.len(),
                "matched_members": 0,
                "reason": "no fleet kernel member's qualified names or paths contain any query token",
            },
            "message": "the fleet kernel cannot support this query; refusing rather than guessing",
            "remediation": "broaden the fleet (compose more repos) or query a symbol the fleet corpus covers",
            "trust": "provisional",
            "freshness": "not_evaluated",
        }));
    }
    matched.sort_by(|left, right| {
        right
            .0
            .cmp(&left.0)
            .then_with(|| right.1.cmp(&left.1))
            .then_with(|| right.2.cmp(&left.2))
            .then_with(|| left.3.cmp(&right.3))
    });
    let total_matched = matched.len();
    matched.truncate(limit as usize);

    let mut distinct_repos: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for (_, _, _, _, member) in &matched {
        for occurrence in member
            .get("occurrences")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(project) = occurrence.get("project").and_then(Value::as_str) {
                distinct_repos.insert(project.to_string());
            }
        }
    }
    let label = gate_label(&serving.sidecar);
    tool_json_result(json!({
        "schema": KERNEL_ANSWER_SCHEMA,
        "status": "served",
        "fleet": true,
        "scope": scope,
        "query": query,
        "answer_basis": "deterministic token containment over fleet member qualified names and paths (declared; no semantic inference)",
        "query_tokens": tokens,
        "matched_members_total": total_matched,
        "citations": matched
            .iter()
            .map(|(full, matched_tokens, _, _, member)| {
                let mut citation = member_citation(member);
                citation["matched_tokens"] = json!(matched_tokens);
                citation["full_match"] = json!(full);
                citation
            })
            .collect::<Vec<_>>(),
        "distinct_repos_cited": distinct_repos.len(),
        "repos_cited": distinct_repos,
        "gate": serving.sidecar.get("gate"),
        // Invariant 1: below-gate fleet kernels answer provisional, never trusted.
        "trust": if label == "trusted" { "verified" } else { "provisional" },
        "freshness": "as_of_compose",
        "compose_input_hash": serving.sidecar.get("compose_input_hash"),
        "provenance": [
            format!(
                "fleet-catalog:{} Kernel CF scope={scope} (members-hash + ledger pairing verified at read)",
                serving.catalog_root
            ),
            format!("fleet-kernel sidecar {FLEET_KERNEL_REPORT_KIND}:{scope}"),
        ],
    }))
}
