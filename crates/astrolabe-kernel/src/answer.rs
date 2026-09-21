//! Grounded kernel answer paths (#40, blueprint 09 §4).
//!
//! A kernel answer walks association edges outward from an anchored kernel
//! member (the entry point selected by kernel-first search) along the strongest
//! outgoing edge at each step, attenuating each hop's contribution by a pinned
//! `0.9` per hop: `hop_score = edge_weight · 0.9^hop`. The served answer is
//! assembled from the path nodes; every hop carries the ledger reference of the
//! edge it traversed and every node carries its provenance reference. The engine
//! is fail-closed on provenance: a multi-hop answer whose traversed edge or
//! destination node cannot attach a ledger/provenance reference is refused with
//! [`CALYX_KERNEL_ANSWER_LEDGER_REQUIRED`] and never served unprovenanced.
//!
//! Every value that reaches the persisted answer is an integer permille, so the
//! answer artifact is byte-identical across runs and worker counts (invariant 5)
//! and re-derives bit-for-bit from the same inputs (the reproduce path). The
//! attenuation factor, hop budget, and hop-score floor are registry-declared
//! knobs (invariant 4).
//!
//! When the query cannot be anchored — no candidate matched the query, or no
//! matched candidate is a grounded (Trusted-anchored) kernel member — the engine
//! returns an honest [`AnswerRefusal`] carrying a per-lens deficit rather than a
//! confident guess or an empty answer (invariant 2).

use std::collections::{BTreeMap, BTreeSet};

use astrolabe_domain::calyx::{CxId, content_address};
use astrolabe_domain::{DomainError, Result, TrustTag, rollup_trust};

use crate::U64KnobDeclaration;
use crate::kernel_build::KernelArtifact;

/// Schema tag for a served kernel answer.
pub const KERNEL_ANSWER_SCHEMA: &str = "astrolabe.kernel_answer.v1";
/// Schema tag for an honest answer refusal (deficit card).
pub const KERNEL_ANSWER_REFUSAL_SCHEMA: &str = "astrolabe.kernel_answer_refusal.v1";
/// Schema tag for a kernel gap report.
pub const KERNEL_GAP_REPORT_SCHEMA: &str = "astrolabe.kernel_gap_report.v1";
/// Knob registry version for the answer-path knobs.
pub const KERNEL_ANSWER_KNOB_REGISTRY_VERSION: &str = "astro.kernel.answer_knobs.v1";
/// Framing tag for the answer hash preimage.
pub const KERNEL_ANSWER_HASH_TAG: &[u8] = b"astro.kernel.answer.v1";

/// Retained refusal code: a multi-hop answer without complete ledger wiring
/// (a traversed edge missing its ledger reference, or a path node missing its
/// provenance reference) fails closed rather than serving an unprovenanced hop.
pub const CALYX_KERNEL_ANSWER_LEDGER_REQUIRED: &str = "CALYX_KERNEL_ANSWER_LEDGER_REQUIRED";
/// Refusal raised when an answer knob is outside its declared bounds.
pub const ASTRO_KERNEL_ANSWER_KNOB_RANGE: &str = "ASTRO_KERNEL_ANSWER_KNOB_RANGE";
/// Refusal raised when a served answer's trace does not re-derive its path.
pub const ASTRO_KERNEL_ANSWER_TRACE_MISMATCH: &str = "ASTRO_KERNEL_ANSWER_TRACE_MISMATCH";
/// Honesty-gate refusal code: the query matched no candidate entry point.
pub const ASTRO_KERNEL_ANSWER_NO_ENTRY: &str = "ASTRO_KERNEL_ANSWER_NO_ENTRY";
/// Honesty-gate refusal code: no matched candidate is a grounded anchor.
pub const ASTRO_KERNEL_ANSWER_UNGROUNDED: &str = "ASTRO_KERNEL_ANSWER_UNGROUNDED";

const SOURCE: &str = "docs/astrolabe-blueprint.md#09-the-kernel--context-engine";

/// Knob name: per-hop answer-path attenuation in permille (pinned `0.9`).
pub const KNOB_ANSWER_ATTENUATION_PERMILLE: &str = "kernel.answer.hop_attenuation_permille";
/// Knob name: maximum answer-path hop budget.
pub const KNOB_ANSWER_MAX_HOPS: &str = "kernel.answer.max_hops";
/// Knob name: minimum hop score (permille) below which a hop is pruned.
pub const KNOB_ANSWER_MIN_HOP_SCORE_PERMILLE: &str = "kernel.answer.min_hop_score_permille";
/// Knob name: maximum exact member-index generations retained per server process.
pub const KNOB_ANSWER_INDEX_CACHE_ENTRIES: &str = "kernel.answer.index_cache_entries";

/// Full permille scale: `1000` permille denotes `1.0` (an unattenuated hop 0).
pub const ANSWER_PERMILLE_SCALE: u64 = 1_000;

/// All answer-path knobs with their declared bounds.
pub const KERNEL_ANSWER_KNOBS: &[U64KnobDeclaration] = &[
    U64KnobDeclaration {
        registry_version: KERNEL_ANSWER_KNOB_REGISTRY_VERSION,
        name: KNOB_ANSWER_ATTENUATION_PERMILLE,
        default: 900,
        min: 1,
        max: 1000,
        unit: "permille",
        source: SOURCE,
        rationale: "per-hop answer-path attenuation; pinned at 0.9 (900 permille) so hop_score = edge_weight * 0.9^hop (blueprint 09 §4)",
    },
    U64KnobDeclaration {
        registry_version: KERNEL_ANSWER_KNOB_REGISTRY_VERSION,
        name: KNOB_ANSWER_MAX_HOPS,
        default: 4,
        min: 1,
        max: 16,
        unit: "hops",
        source: SOURCE,
        rationale: "answer-path hop budget from the anchored entry point before the walk stops",
    },
    U64KnobDeclaration {
        registry_version: KERNEL_ANSWER_KNOB_REGISTRY_VERSION,
        name: KNOB_ANSWER_MIN_HOP_SCORE_PERMILLE,
        default: 1,
        min: 1,
        max: 1000,
        unit: "permille",
        source: SOURCE,
        rationale: "hop-score floor; a hop attenuated below this permille adds no grounded signal and truncates the path",
    },
    U64KnobDeclaration {
        registry_version: KERNEL_ANSWER_KNOB_REGISTRY_VERSION,
        name: KNOB_ANSWER_INDEX_CACHE_ENTRIES,
        default: 16,
        min: 1,
        max: 128,
        unit: "exact index generations",
        source: "issue #996 one-PC 4-5 concurrent-project operating target",
        rationale: "retains multiple current and just-retired project generations without unbounded HNSW memory growth; replace the seed with a measured byte-budget policy after real fleet peak-memory telemetry is accumulated",
    },
];

/// Fully resolved answer-path knobs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnswerConfig {
    /// Per-hop attenuation in permille (pinned `900` = `0.9`).
    pub attenuation_permille: u64,
    /// Maximum hop budget.
    pub max_hops: u64,
    /// Minimum hop score in permille below which the path truncates.
    pub min_hop_score_permille: u64,
}

impl AnswerConfig {
    /// Returns the registry-default answer configuration.
    pub fn with_registry_defaults() -> Self {
        Self {
            attenuation_permille: knob_default(KNOB_ANSWER_ATTENUATION_PERMILLE),
            max_hops: knob_default(KNOB_ANSWER_MAX_HOPS),
            min_hop_score_permille: knob_default(KNOB_ANSWER_MIN_HOP_SCORE_PERMILLE),
        }
    }

    /// Validates every knob against its declared bounds, fail-closed.
    pub fn validate(&self) -> Result<()> {
        check_range(KNOB_ANSWER_ATTENUATION_PERMILLE, self.attenuation_permille)?;
        check_range(KNOB_ANSWER_MAX_HOPS, self.max_hops)?;
        check_range(
            KNOB_ANSWER_MIN_HOP_SCORE_PERMILLE,
            self.min_hop_score_permille,
        )?;
        Ok(())
    }
}

fn knob_default(name: &str) -> u64 {
    KERNEL_ANSWER_KNOBS
        .iter()
        .find(|knob| knob.name == name)
        .expect("answer knob is declared")
        .default
}

fn check_range(name: &str, value: u64) -> Result<()> {
    let knob = KERNEL_ANSWER_KNOBS
        .iter()
        .find(|knob| knob.name == name)
        .expect("answer knob is declared");
    if value < knob.min || value > knob.max {
        return Err(DomainError::new(
            ASTRO_KERNEL_ANSWER_KNOB_RANGE,
            format!(
                "{}={} is outside declared bounds {}..={}",
                knob.name, value, knob.min, knob.max
            ),
            "set the answer-path knob within its registered bounds",
        ));
    }
    Ok(())
}

/// One node available to the answer walk: a current symbol version with its
/// grounding and provenance metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnswerNode {
    /// Symbol version identity.
    pub id: CxId,
    /// Fully-qualified name surfaced in the answer.
    pub qualified_name: String,
    /// Whether the node carries a Trusted grounding anchor (kernel-grounded).
    pub grounded: bool,
    /// The node's provenance reference. `None`/empty makes a multi-hop answer
    /// through this node fail closed ([`CALYX_KERNEL_ANSWER_LEDGER_REQUIRED`]).
    pub provenance_ref: Option<String>,
    /// The node's kernel member weight in permille (its answer relevance as an
    /// entry point; the unattenuated hop-0 score).
    pub kernel_weight_permille: u64,
}

impl AnswerNode {
    /// Builds an answer node.
    pub fn new(
        id: CxId,
        qualified_name: impl Into<String>,
        grounded: bool,
        provenance_ref: Option<String>,
        kernel_weight_permille: u64,
    ) -> Self {
        Self {
            id,
            qualified_name: qualified_name.into(),
            grounded,
            provenance_ref,
            kernel_weight_permille,
        }
    }
}

/// One directed, weighted association edge with its per-hop ledger reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnswerEdge {
    /// Source node identity.
    pub src: CxId,
    /// Destination node identity.
    pub dst: CxId,
    /// Edge weight in permille `[0, 1000]`.
    pub weight_permille: u64,
    /// The ledger reference proving this hop. `None`/empty makes a multi-hop
    /// answer traversing it fail closed ([`CALYX_KERNEL_ANSWER_LEDGER_REQUIRED`]).
    pub ledger_ref: Option<String>,
}

impl AnswerEdge {
    /// Builds an answer edge.
    pub fn new(src: CxId, dst: CxId, weight_permille: u64, ledger_ref: Option<String>) -> Self {
        Self {
            src,
            dst,
            weight_permille,
            ledger_ref,
        }
    }
}

/// One traversed hop of a served answer path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnswerHop {
    /// Hop depth from the entry (`1` is the first edge out of the entry).
    pub depth: u64,
    /// Source node identity of the traversed edge.
    pub from_id: CxId,
    /// Destination node identity of the traversed edge.
    pub to_id: CxId,
    /// Destination node's qualified name.
    pub to_qualified_name: String,
    /// Traversed edge weight in permille.
    pub edge_weight_permille: u64,
    /// Attenuation applied at this depth (`0.9^depth` in permille).
    pub attenuation_permille: u64,
    /// Attenuated hop score = `floor(edge_weight · attenuation / 1000)`.
    pub hop_score_permille: u64,
    /// Whether the destination node is kernel-grounded.
    pub to_grounded: bool,
    /// The ledger reference proving this hop (always non-empty on a served answer).
    pub ledger_ref: String,
    /// The destination node's provenance reference (always non-empty when served).
    pub node_provenance_ref: String,
}

/// A fully assembled, grounded kernel answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KernelAnswer {
    /// Answer schema tag.
    pub schema: &'static str,
    /// Knob registry version in force.
    pub knob_registry_version: &'static str,
    /// Per-hop attenuation used (permille).
    pub attenuation_permille: u64,
    /// The query this answer was assembled for.
    pub query: String,
    /// Anchored entry point identity.
    pub entry_id: CxId,
    /// Entry point qualified name.
    pub entry_qualified_name: String,
    /// Entry point kernel weight in permille (the unattenuated hop-0 score).
    pub entry_weight_permille: u64,
    /// Entry point provenance reference (always non-empty when served).
    pub entry_provenance_ref: String,
    /// Traversed hops in path order.
    pub hops: Vec<AnswerHop>,
    /// Answer node identities in path order (entry first).
    pub answer_node_ids: Vec<CxId>,
    /// Total score = entry weight + sum of hop scores (permille).
    pub total_score_permille: u64,
    /// Ordered provenance references: entry provenance then each hop's ledger ref.
    pub provenance_refs: Vec<String>,
    /// Trust label rolled up over the grounded flags of every path node.
    pub trust: &'static str,
    /// Freshness label.
    pub freshness: &'static str,
    /// Hex answer hash over the canonical answer bytes.
    pub answer_hash: String,
}

/// A per-requirement deficit in an honest answer refusal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnswerDeficit {
    /// The requirement ("lens") this deficit reports.
    pub lens: String,
    /// Whether the requirement was satisfied.
    pub satisfied: bool,
    /// Human-readable detail of the deficit.
    pub detail: String,
}

/// An honest refusal carrying a per-lens deficit — served instead of a guess or
/// an empty answer when the query cannot be grounded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnswerRefusal {
    /// Refusal schema tag.
    pub schema: &'static str,
    /// Stable refusal code.
    pub code: &'static str,
    /// The query that could not be answered.
    pub query: String,
    /// Per-lens deficit list (always covers `entry_point` and `grounded_anchor`).
    pub deficits: Vec<AnswerDeficit>,
    /// Refusal message.
    pub message: String,
    /// Operator-facing remediation.
    pub remediation: &'static str,
    /// Trust label (always provisional — a refusal grounds nothing).
    pub trust: &'static str,
    /// Freshness label.
    pub freshness: &'static str,
}

/// Either a served answer or an honest deficit refusal. The [`Result`] wrapping
/// this enum is reserved for hard fail-closed integrity errors (knob range, and
/// the ledger-required provenance gate).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnswerResolution {
    /// A grounded answer was assembled and served.
    Answered(Box<KernelAnswer>),
    /// The query was refused with a per-lens deficit (honesty gate).
    Refused(AnswerRefusal),
}

/// Projects a finite edge weight in `[0, 1]` to permille `[0, 1000]` at the
/// engine boundary. The engine itself is integer-only so the persisted answer is
/// byte-stable; this is the single projection point callers use.
pub fn weight_to_permille(weight: f32) -> u64 {
    let clamped = weight.clamp(0.0, 1.0) as f64;
    (clamped * ANSWER_PERMILLE_SCALE as f64).round() as u64
}

/// Attenuation at a hop depth: `0.9^depth` on the permille scale, computed by the
/// same iterated per-hop floor the served hop scores use, so a recompute from the
/// stored attenuation reproduces the served value exactly.
pub fn attenuation_at(depth: u64, attenuation_permille: u64) -> u64 {
    let mut value = ANSWER_PERMILLE_SCALE;
    for _ in 0..depth {
        value = value.saturating_mul(attenuation_permille) / ANSWER_PERMILLE_SCALE;
    }
    value
}

/// Applies one hop's attenuation to an edge weight: `floor(weight · att / 1000)`.
fn hop_score(edge_weight_permille: u64, attenuation_permille: u64) -> u64 {
    edge_weight_permille.saturating_mul(attenuation_permille) / ANSWER_PERMILLE_SCALE
}

/// Assembles a grounded kernel answer for `query` by walking the strongest
/// association edge outward from the best grounded matched entry point, one hop
/// at a time up to the hop budget.
///
/// `matched_ids` is **order-significant** (#880): it is the caller's kernel-first
/// ranking for this query, best candidate first. The entry point is the first
/// grounded, provenanced candidate in that order, so the answer is anchored in
/// what the query actually reached rather than in a query-independent global
/// weight. Callers that cannot rank must not substitute the whole member set.
///
/// Fail-closed behavior:
/// - `Err(ASTRO_KERNEL_ANSWER_KNOB_RANGE)` when a knob is out of bounds.
/// - `Err(CALYX_KERNEL_ANSWER_LEDGER_REQUIRED)` when the entry or any traversed
///   hop cannot attach a ledger/provenance reference — the answer is never served
///   unprovenanced.
/// - `Ok(AnswerResolution::Refused)` (honesty gate) when no candidate matched, or
///   no matched candidate is a grounded anchor.
pub fn answer_query(
    nodes: &[AnswerNode],
    edges: &[AnswerEdge],
    matched_ids: &[CxId],
    query: &str,
    config: &AnswerConfig,
) -> Result<AnswerResolution> {
    config.validate()?;

    let node_by_id: BTreeMap<CxId, &AnswerNode> =
        nodes.iter().map(|node| (node.id, node)).collect();

    // `matched_ids` is the caller's kernel-first ranking, BEST FIRST (#880). The
    // order is the query's evidence, so it is preserved rather than sorted away:
    // resolve to the candidates that actually have a node row, collapsing a
    // repeated id to its first (best) occurrence. The result is total and
    // deterministic for a given ranking.
    let mut seen: BTreeSet<CxId> = BTreeSet::new();
    let mut matched: Vec<CxId> = Vec::with_capacity(matched_ids.len());
    for id in matched_ids {
        if node_by_id.contains_key(id) && seen.insert(*id) {
            matched.push(*id);
        }
    }

    if matched.is_empty() {
        return Ok(AnswerResolution::Refused(refusal(
            ASTRO_KERNEL_ANSWER_NO_ENTRY,
            query,
            false,
            false,
            format!("no candidate matched query {query:?} in the kernel-first search entry set",),
            "widen the kernel scope or refine the query so kernel-first search returns at least one member",
        )));
    }

    // Entry = the best-RANKED grounded candidate, i.e. the first grounded member
    // the caller's query ranking reached (#880). Selecting by global
    // `kernel_weight_permille` instead made every query over one kernel resolve to
    // the same entry, so two unrelated questions produced the same "answer"; the
    // caller's ranking is the only signal that carries what was actually asked.
    // Ties cannot occur — a ranking is a total order. An ungrounded-only match
    // still refuses the honesty gate.
    let entry = matched
        .iter()
        .filter_map(|id| node_by_id.get(id).copied())
        .find(|node| node.grounded);
    let Some(entry) = entry else {
        return Ok(AnswerResolution::Refused(refusal(
            ASTRO_KERNEL_ANSWER_UNGROUNDED,
            query,
            true,
            false,
            format!(
                "query {query:?} matched {} candidate(s) but none is a grounded (Trusted-anchored) kernel member",
                matched.len()
            ),
            "ground the scope (anchor an outcome onto a matched member) before requesting a kernel answer",
        )));
    };

    // The entry itself must be provenanced or the answer would be unprovenanced.
    let entry_provenance = non_empty_ref(entry.provenance_ref.as_deref()).ok_or_else(|| {
        DomainError::new(
            CALYX_KERNEL_ANSWER_LEDGER_REQUIRED,
            format!(
                "anchored entry {} ({}) carries no provenance reference",
                entry.id, entry.qualified_name
            ),
            "attach a provenance reference to the kernel member before serving it as an answer entry point",
        )
    })?;

    // Adjacency: strongest edge first (weight desc, then dst id asc).
    let mut out_edges: BTreeMap<CxId, Vec<&AnswerEdge>> = BTreeMap::new();
    for edge in edges {
        out_edges.entry(edge.src).or_default().push(edge);
    }
    for list in out_edges.values_mut() {
        list.sort_by(|left, right| {
            right
                .weight_permille
                .cmp(&left.weight_permille)
                .then_with(|| left.dst.cmp(&right.dst))
        });
    }

    let mut visited: BTreeSet<CxId> = BTreeSet::new();
    visited.insert(entry.id);
    let mut hops: Vec<AnswerHop> = Vec::new();
    let mut current = entry.id;

    for depth in 1..=config.max_hops {
        let Some(candidates) = out_edges.get(&current) else {
            break;
        };
        // Strongest edge to an unvisited node that has a node row.
        let chosen = candidates
            .iter()
            .find(|edge| !visited.contains(&edge.dst) && node_by_id.contains_key(&edge.dst));
        let Some(edge) = chosen else {
            break;
        };
        let attenuation = attenuation_at(depth, config.attenuation_permille);
        let score = hop_score(edge.weight_permille, attenuation);
        if score < config.min_hop_score_permille {
            // Attenuated below the floor — the path adds no grounded signal.
            break;
        }
        // Ledger-required gate: the traversed edge and its destination node must
        // both attach a reference, or the whole multi-hop answer fails closed.
        let ledger_ref = non_empty_ref(edge.ledger_ref.as_deref()).ok_or_else(|| {
            DomainError::new(
                CALYX_KERNEL_ANSWER_LEDGER_REQUIRED,
                format!(
                    "answer hop {} -> {} at depth {depth} carries no ledger reference",
                    edge.src, edge.dst
                ),
                "attach the association edge's ledger reference before serving a multi-hop answer through it",
            )
        })?;
        let dst = node_by_id
            .get(&edge.dst)
            .copied()
            .expect("chosen edge destination has a node row");
        let node_provenance = non_empty_ref(dst.provenance_ref.as_deref()).ok_or_else(|| {
            DomainError::new(
                CALYX_KERNEL_ANSWER_LEDGER_REQUIRED,
                format!(
                    "answer path node {} ({}) at depth {depth} carries no provenance reference",
                    dst.id, dst.qualified_name
                ),
                "attach a provenance reference to every path node before serving a multi-hop answer",
            )
        })?;

        hops.push(AnswerHop {
            depth,
            from_id: edge.src,
            to_id: edge.dst,
            to_qualified_name: dst.qualified_name.clone(),
            edge_weight_permille: edge.weight_permille,
            attenuation_permille: attenuation,
            hop_score_permille: score,
            to_grounded: dst.grounded,
            ledger_ref: ledger_ref.to_string(),
            node_provenance_ref: node_provenance.to_string(),
        });
        visited.insert(edge.dst);
        current = edge.dst;
    }

    // Assemble the served answer.
    let mut answer_node_ids = Vec::with_capacity(hops.len() + 1);
    answer_node_ids.push(entry.id);
    let mut provenance_refs = Vec::with_capacity(hops.len() + 1);
    provenance_refs.push(entry_provenance.to_string());
    let mut total = entry.kernel_weight_permille;
    let mut trust_tags = Vec::with_capacity(hops.len() + 1);
    trust_tags.push(grounded_trust(entry.grounded));
    for hop in &hops {
        answer_node_ids.push(hop.to_id);
        provenance_refs.push(hop.ledger_ref.clone());
        total = total.saturating_add(hop.hop_score_permille);
        trust_tags.push(grounded_trust(hop.to_grounded));
    }
    let trust = rollup_trust(trust_tags).as_str();

    let mut answer = KernelAnswer {
        schema: KERNEL_ANSWER_SCHEMA,
        knob_registry_version: KERNEL_ANSWER_KNOB_REGISTRY_VERSION,
        attenuation_permille: config.attenuation_permille,
        query: query.to_string(),
        entry_id: entry.id,
        entry_qualified_name: entry.qualified_name.clone(),
        entry_weight_permille: entry.kernel_weight_permille,
        entry_provenance_ref: entry_provenance.to_string(),
        hops,
        answer_node_ids,
        total_score_permille: total,
        provenance_refs,
        trust,
        freshness: "fresh",
        answer_hash: String::new(),
    };
    answer.answer_hash = hex_lower(&answer_content_address(&answer));
    Ok(AnswerResolution::Answered(Box::new(answer)))
}

fn grounded_trust(grounded: bool) -> TrustTag {
    if grounded {
        TrustTag::Trusted
    } else {
        TrustTag::Provisional
    }
}

fn non_empty_ref(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

#[allow(clippy::too_many_arguments)]
fn refusal(
    code: &'static str,
    query: &str,
    entry_point_found: bool,
    grounded_anchor_found: bool,
    message: String,
    remediation: &'static str,
) -> AnswerRefusal {
    AnswerRefusal {
        schema: KERNEL_ANSWER_REFUSAL_SCHEMA,
        code,
        query: query.to_string(),
        deficits: vec![
            AnswerDeficit {
                lens: "entry_point".to_string(),
                satisfied: entry_point_found,
                detail: if entry_point_found {
                    "kernel-first search matched at least one candidate".to_string()
                } else {
                    "kernel-first search matched no candidate for the query".to_string()
                },
            },
            AnswerDeficit {
                lens: "grounded_anchor".to_string(),
                satisfied: grounded_anchor_found,
                detail: if grounded_anchor_found {
                    "a matched candidate is a grounded (Trusted-anchored) kernel member".to_string()
                } else {
                    "no matched candidate is a grounded (Trusted-anchored) kernel member"
                        .to_string()
                },
            },
        ],
        message,
        remediation,
        trust: "provisional",
        freshness: "not_evaluated",
    }
}

/// Canonical deterministic serialization of a served answer, hashed into the
/// [`KernelAnswer::answer_hash`] and used as the reproduce/FSV artifact.
pub fn answer_artifact_bytes(answer: &KernelAnswer) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("schema=");
    out.push_str(answer.schema);
    out.push('\n');
    out.push_str("knobs=");
    out.push_str(answer.knob_registry_version);
    out.push('\n');
    out.push_str("attenuation=");
    out.push_str(&answer.attenuation_permille.to_string());
    out.push('\n');
    out.push_str("query=");
    out.push_str(&answer.query);
    out.push('\n');
    out.push_str("entry=");
    out.push_str(&answer.entry_id.to_string());
    out.push('\t');
    out.push_str(&answer.entry_qualified_name);
    out.push('\t');
    out.push_str(&answer.entry_weight_permille.to_string());
    out.push('\t');
    out.push_str(&answer.entry_provenance_ref);
    out.push('\n');
    for hop in &answer.hops {
        out.push_str("hop\t");
        out.push_str(&hop.depth.to_string());
        out.push('\t');
        out.push_str(&hop.from_id.to_string());
        out.push('\t');
        out.push_str(&hop.to_id.to_string());
        out.push('\t');
        out.push_str(&hop.to_qualified_name);
        out.push('\t');
        out.push_str(&hop.edge_weight_permille.to_string());
        out.push('\t');
        out.push_str(&hop.attenuation_permille.to_string());
        out.push('\t');
        out.push_str(&hop.hop_score_permille.to_string());
        out.push('\t');
        out.push_str(if hop.to_grounded {
            "grounded"
        } else {
            "ungrounded"
        });
        out.push('\t');
        out.push_str(&hop.ledger_ref);
        out.push('\t');
        out.push_str(&hop.node_provenance_ref);
        out.push('\n');
    }
    out.push_str("total=");
    out.push_str(&answer.total_score_permille.to_string());
    out.push('\n');
    out.push_str("trust=");
    out.push_str(answer.trust);
    out.push('\n');
    out.into_bytes()
}

fn answer_content_address(answer: &KernelAnswer) -> [u8; 16] {
    content_address([
        KERNEL_ANSWER_HASH_TAG.to_vec(),
        answer_artifact_bytes(answer),
    ])
}

/// Re-derives a served answer's path from its own stored hops and verifies it
/// matches exactly (FSV pairing for `answer_trace`).
///
/// Recomputes every hop's attenuation and score from the stored per-hop inputs,
/// checks the node chain is continuous (each hop starts where the previous
/// ended), checks the answer hash re-derives, and checks every hop is
/// ledger-referenced and every node provenanced. Fails closed with
/// [`ASTRO_KERNEL_ANSWER_TRACE_MISMATCH`] on any divergence, or
/// [`CALYX_KERNEL_ANSWER_LEDGER_REQUIRED`] on a missing reference.
pub fn verify_answer_trace(answer: &KernelAnswer) -> Result<()> {
    if non_empty_ref(Some(&answer.entry_provenance_ref)).is_none() {
        return Err(DomainError::new(
            CALYX_KERNEL_ANSWER_LEDGER_REQUIRED,
            "served answer entry carries no provenance reference",
            "never serve an answer whose entry point is unprovenanced",
        ));
    }
    let mut expected_total = answer.entry_weight_permille;
    let mut expected_from = answer.entry_id;
    let mut expected_node_ids = vec![answer.entry_id];
    let mut expected_provenance = vec![answer.entry_provenance_ref.clone()];
    for (index, hop) in answer.hops.iter().enumerate() {
        let expected_depth = index as u64 + 1;
        if hop.depth != expected_depth {
            return Err(trace_mismatch(format!(
                "hop depth {} out of order; expected {expected_depth}",
                hop.depth
            )));
        }
        if hop.from_id != expected_from {
            return Err(trace_mismatch(format!(
                "hop at depth {} starts at {} but the previous node ended at {expected_from}",
                hop.depth, hop.from_id
            )));
        }
        let attenuation = attenuation_at(hop.depth, answer.attenuation_permille);
        if attenuation != hop.attenuation_permille {
            return Err(trace_mismatch(format!(
                "hop at depth {} stored attenuation {} but 0.9^{} = {attenuation}",
                hop.depth, hop.attenuation_permille, hop.depth
            )));
        }
        let score = hop_score(hop.edge_weight_permille, attenuation);
        if score != hop.hop_score_permille {
            return Err(trace_mismatch(format!(
                "hop at depth {} stored score {} but weight {} · att {attenuation} / 1000 = {score}",
                hop.depth, hop.hop_score_permille, hop.edge_weight_permille
            )));
        }
        if non_empty_ref(Some(&hop.ledger_ref)).is_none()
            || non_empty_ref(Some(&hop.node_provenance_ref)).is_none()
        {
            return Err(DomainError::new(
                CALYX_KERNEL_ANSWER_LEDGER_REQUIRED,
                format!("served answer hop at depth {} is unreferenced", hop.depth),
                "never serve an answer hop without its ledger and node provenance references",
            ));
        }
        expected_total = expected_total.saturating_add(hop.hop_score_permille);
        expected_from = hop.to_id;
        expected_node_ids.push(hop.to_id);
        expected_provenance.push(hop.ledger_ref.clone());
    }
    if expected_total != answer.total_score_permille {
        return Err(trace_mismatch(format!(
            "served total {} but the trace sums to {expected_total}",
            answer.total_score_permille
        )));
    }
    if expected_node_ids != answer.answer_node_ids {
        return Err(trace_mismatch(
            "served answer node ids do not match the traced path".to_string(),
        ));
    }
    if expected_provenance != answer.provenance_refs {
        return Err(trace_mismatch(
            "served provenance refs do not match the traced path".to_string(),
        ));
    }
    let rederived = hex_lower(&answer_content_address(answer));
    if rederived != answer.answer_hash {
        return Err(trace_mismatch(format!(
            "served answer hash {} does not re-derive ({rederived})",
            answer.answer_hash
        )));
    }
    Ok(())
}

fn trace_mismatch(detail: String) -> DomainError {
    DomainError::new(
        ASTRO_KERNEL_ANSWER_TRACE_MISMATCH,
        detail,
        "the served answer path and its trace disagree; do not trust the answer",
    )
}

/// A gap in a kernel: an ungrounded member with no Trusted anchor in reach.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KernelGap {
    /// Member identity.
    pub id: CxId,
    /// Member score in permille.
    pub score_permille: u64,
    /// Member groundedness in permille.
    pub groundedness_permille: u64,
}

/// A gap report over a built kernel: which members are ungrounded, and the
/// grounded fraction and diagnostic graph coverage the kernel achieves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KernelGapReport {
    /// Report schema tag.
    pub schema: &'static str,
    /// Scope the kernel was built for.
    pub scope_id: String,
    /// Total kernel members.
    pub member_count: usize,
    /// Grounded member count.
    pub grounded_count: usize,
    /// Gap (ungrounded) member count.
    pub gap_count: usize,
    /// Grounded fraction in permille.
    pub grounded_fraction_permille: u64,
    /// Diagnostic graph coverage the kernel achieves in permille.
    pub graph_coverage_permille: u64,
    /// Whether the kernel has any Trusted anchor in scope at all.
    pub anchor_grounded: bool,
    /// The ungrounded members, ascending by id.
    pub gaps: Vec<KernelGap>,
    /// Trust label.
    pub trust: &'static str,
    /// Freshness label.
    pub freshness: &'static str,
}

/// Builds the gap report for a persisted kernel artifact (the `get_kernel`
/// gaps mode): every member whose grounded flag is false is a gap.
pub fn kernel_gap_report(artifact: &KernelArtifact) -> KernelGapReport {
    let mut gaps: Vec<KernelGap> = artifact
        .members
        .iter()
        .filter(|member| !member.grounded)
        .map(|member| KernelGap {
            id: member.id,
            score_permille: member.score_permille,
            groundedness_permille: member.groundedness_permille,
        })
        .collect();
    gaps.sort_by_key(|gap| gap.id);
    let member_count = artifact.members.len();
    let gap_count = gaps.len();
    let grounded_count = member_count - gap_count;
    let grounded_fraction_permille = (grounded_count as u64)
        .saturating_mul(ANSWER_PERMILLE_SCALE)
        .checked_div(member_count as u64)
        .unwrap_or(0);
    KernelGapReport {
        schema: KERNEL_GAP_REPORT_SCHEMA,
        scope_id: artifact.scope_id.clone(),
        member_count,
        grounded_count,
        gap_count,
        grounded_fraction_permille,
        graph_coverage_permille: artifact.graph_coverage.permille,
        anchor_grounded: artifact.anchor_grounded,
        gaps,
        trust: if artifact.anchor_grounded && gap_count == 0 {
            "trusted"
        } else {
            "provisional"
        },
        freshness: "fresh",
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit((byte >> 4) as u32, 16).expect("nibble"));
        out.push(char::from_digit((byte & 0x0f) as u32, 16).expect("nibble"));
    }
    out
}
