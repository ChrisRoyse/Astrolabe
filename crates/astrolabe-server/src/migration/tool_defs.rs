use super::*;

/// The immutable Rust-native MCP registry, constructed once per process.
///
/// `tools/list`, native CLI help, public-name membership, and runtime argument
/// validation all borrow these exact values. Keeping one process-scope instance
/// prevents both schema drift and per-request reconstruction of the 24 schema
/// trees (#1120; #1064 PC-03/PC-43).
pub(crate) fn astrolabe_tool_definitions() -> &'static [Value; 24] {
    static DEFINITIONS: OnceLock<[Value; 24]> = OnceLock::new();
    DEFINITIONS.get_or_init(|| {
        [
            get_provenance_tool_definition(),
            detect_anomalies_tool_definition(),
            optimizer_status_tool_definition(),
            get_readiness_tool_definition(),
            impute_fields_tool_definition(),
            anchor_outcome_tool_definition(),
            predict_impact_tool_definition(),
            coverage_ingest_tool_definition(),
            team_artifact_tool_definition(),
            guard_calibrate_tool_definition(),
            guard_check_tool_definition(),
            measure_bits_tool_definition(),
            find_similar_tool_definition(),
            guard_lock_tool_definition(),
            guard_commit_ood_tool_definition(),
            guard_advisory_hook_tool_definition(),
            assay_gate_tool_definition(),
            abduce_cause_tool_definition(),
            forecast_tool_definition(),
            // #39 + #40 + #353: unified get_kernel (modes read|gaps|quadrant|build),
            // kernel_answer, and anchor_erase, appended after the base roster.
            get_kernel_tool_definition(),
            kernel_answer_tool_definition(),
            anchor_erase_tool_definition(),
            // #1009: L5 latent (indirect) associations.
            discover_latent_links_tool_definition(),
            // #1012/#1097: composed, association-contextualized discovery generation.
            discover_associations_tool_definition(),
        ]
    })
}

pub(crate) fn discover_associations_tool_definition() -> Value {
    json!({
        "name": "discover_associations",
        "title": "Discover Grounded Associations",
        "description": "Runs Astrolabe's complete retained-generation discovery pipeline: deterministic concept normalization contextualized by every incident typed association without identity merging; the full typed structural/semantic/temporal relationship multigraph; Swanson corpus mining with Resource Allocation, Adamic-Adar, direct-link exclusion and disclosed hub gates; sparse spectral community and cross-community bridge measurement; bounded cycle-safe typed multi-hop walks; citation-bound independent AI evaluation; leakage-free grouped held-out validation with precision/recall/MRR, separate candidate and held-out coverage, complete-universe binary Brier@K, cross-fold stability, and null evidence; and a separately fingerprinted compact reasoning kernel. Resource Allocation is disclosed as an uncalibrated rank score, never a probability. prepare persists exact provisional candidate/evidence stages. publish requires independent evaluator receipts tied to that physical hash and atomically publishes every Assay/Kernel stage plus a ledger record. read independently decodes and hashes the physical generation. No stage silently falls back or reconstructs per query.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {"type": "string", "description": "Exact indexed project name."},
                "mode": {"type": "string", "enum": ["prepare", "publish", "read"], "description": "prepare mines/persists provisional evidence; publish validates evaluator receipts and publishes a compact kernel; read physically reads a published generation."},
                "prepared_artifact_sha256": {"type": "string", "description": "prepare hash required by publish; for read, omit to follow the current final pointer or pass a final artifact hash."},
                "section": {"type": "string", "enum": ["all", "manifest", "evaluator", "ranked", "kernel"], "description": "Focused physical read section."},
                "workers": {"type": "integer", "minimum": 1, "maximum": 256},
                "cross_validation_folds": {"type": "integer", "minimum": 2, "maximum": 32},
                "top_k": {"type": "integer", "minimum": 1},
                "max_intermediary_degree": {"type": "integer", "minimum": 2},
                "min_shared_intermediaries": {"type": "integer", "minimum": 1},
                "evaluator_runs": {
                    "type": "object",
                    "description": "publish only: map hypothesis_id to independent evaluator run arrays. Every run scores plausibility, novelty, testability, falsifiability, supplies a falsification test, and cites prepared evidence ids."
                }
            },
            "required": ["project"],
            "additionalProperties": false
        }
    })
}

pub(crate) fn discover_latent_links_tool_definition() -> Value {
    json!({
        "name": "discover_latent_links",
        "title": "Discover Latent Links",
        "description": "\"What is this related to that nothing records?\" — L5 latent association discovery over the persisted composite association graph, on Swanson's ABC model. Every other layer reports a pair because direct evidence for that pair exists (an extracted edge, close slot vectors, co-occurring series); this one proposes pairs precisely where the direct edge is ABSENT but many shared intermediaries are present, which is the hidden-coupling / duplicated-concept / missing-abstraction finding that blast radius structurally cannot reach because blast radius only walks edges that exist. Shared intermediaries are weighted by rarity, never counted raw: an intermediary reached by hundreds of symbols (a logger, an error constructor) carries almost no evidence and would emit C(degree,2) spurious pairs on its own, so scoring is Resource-Allocation (sum 1/degree, the primary rank, best on sparse code graphs) plus Adamic-Adar (sum 1/ln degree) plus Swanson's raw linking-term count, and intermediaries above the declared breadth ceiling are gated out AND counted. Modes: \"open\" (seeded — what is this symbol implicitly related to), \"closed\" (given two symbols, the ranked linking intermediaries that explain them), \"sweep\" (the repo's top latent pairs). Every served pair is trust=\"provisional\" without exception: a latent link is a hypothesis about a missing association, never an observed one, and each pair carries the intermediaries that produced it so the caller judges the evidence rather than the score. A sweep that would exceed the declared pair budget refuses with the breadth ceiling that would fit rather than silently truncating the ranking; an absent kernel_graph projection refuses rather than ranking absences over a partial graph. Fails closed with {code,message,remediation} on a missing/unresolved symbol, an unsupported mode/relation, or an out-of-bounds gate override.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {
                    "type": "string",
                    "description": "CBM project name for a project indexed with calyx=\"shadow\"."
                },
                "mode": {
                    "type": "string",
                    "enum": ["open", "closed", "sweep"],
                    "description": "open (default): ranked latent partners of one seed. closed: the linking intermediaries explaining a given pair. sweep: the repo's top latent pairs under the pair budget."
                },
                "relation": {
                    "type": "string",
                    "enum": ["coupling", "co_citation", "undirected"],
                    "description": "Which arc makes an intermediary shared, and therefore which degree is the rarity denominator. coupling (default): shared successors, A->B<-C — the 'these two do the same work' signal. co_citation: shared predecessors, A<-B->C — 'these two are used by the same work'. undirected: either direction."
                },
                "seed": {
                    "type": "string",
                    "description": "mode=\"open\": qualified name of the symbol whose implicit relationships you want. Must resolve in this project's indexed graph or the call refuses fail-closed."
                },
                "a": {
                    "type": "string",
                    "description": "mode=\"closed\": qualified name of the first endpoint."
                },
                "c": {
                    "type": "string",
                    "description": "mode=\"closed\": qualified name of the second endpoint."
                },
                "max_intermediary_degree": {
                    "type": "integer",
                    "description": "Breadth ceiling: an intermediary reached by more symbols than this is over-broad, gated out, and counted in disclosure.intermediaries_over_broad. Default 50. Raising it admits hubs and inflates spurious pairs quadratically; lowering it is how you make an over-budget sweep fit."
                },
                "min_shared_intermediaries": {
                    "type": "integer",
                    "description": "Fewest linking intermediaries a pair needs to be reported. Default 2 — a pair joined through a single intermediary is a coincidence of one call site."
                },
                "pair_budget": {
                    "type": "integer",
                    "description": "mode=\"sweep\": ceiling on candidate pairs the sweep may materialize. Exceeding it refuses with the remediation rather than truncating the ranking. Default 4000000."
                },
                "top_k": {
                    "type": "integer",
                    "description": "How many ranked pairs to serve. Default 100. The pre-truncation count is always disclosed as disclosure.pairs_truncated."
                },
                "listed_intermediaries": {
                    "type": "integer",
                    "description": "How many of each pair's linking intermediaries to list as evidence, rarest first. Default 8. The pair's full shared_count is always served alongside."
                }
            },
            "required": ["project"],
            "additionalProperties": false
        }
    })
}

pub(crate) fn get_kernel_tool_definition() -> Value {
    json!({
        "name": "get_kernel",
        "title": "Get Kernel",
        "description": "Serve the persisted kernel for a shadow-indexed project. Four modes over the persisted kernel context (scope-summary members: qualified name, kernel weight/score in permille, grounded flag, provenance, recall metrics). mode=\"read\" (default) serves every kernel member per scope with recall metrics and grounded fraction. mode=\"gaps\" serves the \"here be dragons\" grounding-gap report — kernel members whose persisted grounded flag is false — ranked by persisted kernel weight (importance), with a labeled degradation because the change-frequency churn term and the exact 3-hop grounding boundary live in the persisted kernel artifact, not this metadata surface. mode=\"quadrant\" serves the coverage-vs-importance scatter, classifying every member into critical/peripheral × verified/unverified with the kernel crate's registry-knob split; the critical-and-unverified quadrant is the actionable QA target that feeds readiness and the UI overlay. mode=\"build\" recomputes the anchor-trust-grounded feedback-vertex-set kernel over the vault association graph on demand — opening the shadow vault read-write and running the same build_and_persist_kernel the shadow import runs at index time — and persists the KernelArtifact + projection into the vault Kernel CF, serving status=\"built\" with the measured member/node counts, recall, and readback/ledger evidence; a graph that yields no kernel (empty graph, no typed edges, an unreachable recall gate) fails closed with ASTRO_KERNEL_BUILD_UNAVAILABLE and the real reason. Optionally scoped by scope id. Every response carries trust/freshness/provenance and fails closed with {code,message,remediation} when the project is not shadow-indexed, its kernel context is unavailable, the scope is absent, or the mode is unknown.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {
                    "type": "string",
                    "description": "CBM project name for a project indexed with calyx=\"shadow\". Required unless scope is a fleet scope (fleet:*)."
                },
                "mode": {
                    "type": "string",
                    "enum": ["read", "gaps", "quadrant", "build"],
                    "description": "read (default): kernel members + recall per scope. gaps: ranked grounding-gap report of ungrounded kernel members. quadrant: coverage-vs-importance scatter with per-quadrant counts. build: recompute the anchor-trust-grounded FVS kernel over the vault association graph on demand and persist the KernelArtifact + projection into the vault Kernel CF, serving status:\"built\" (or a coded fail-closed refusal when the graph yields no kernel)."
                },
                "scope": {
                    "type": "string",
                    "description": "Optional scope id to restrict the kernel to (read/gaps modes). Omit for every persisted scope. An unknown scope refuses fail-closed. A fleet scope (e.g. \"fleet:rust:v1\") serves the composed fleet kernel from the fleet catalog vault with per-repo provenance citations (#459); project is not required for fleet scopes."
                },
                "fleet_catalog_root": {
                    "type": "string",
                    "description": "Fleet catalog vault root for fleet scopes. Defaults to the declared production catalog root."
                },
                "budget": {
                    "type": "integer",
                    "description": "Optional member budget hint for mode=build. The on-demand build currently uses the registry-default kernel budget; a per-request budget override is a future refinement (this hint is not yet applied)."
                }
            },
            "required": [],
            "additionalProperties": false
        }
    })
}

pub(crate) fn kernel_answer_tool_definition() -> Value {
    json!({
        "name": "kernel_answer",
        "title": "Kernel Answer",
        "description": "Grounded kernel-first Q&A for a shadow-indexed project: kernel-first search resolves an anchored (Trusted-grounded) entry point, then a hop-attenuated answer path walks association edges outward with hop_score = edge_weight * 0.9^hop, every hop carrying its ledger reference and every node its provenance. The answer is assembled from the path nodes with a total score, ordered provenance, and a rolled-up trust tag; an ungrounded scope or an unanswerable query refuses with a per-lens deficit rather than an empty answer, and a multi-hop answer without complete ledger wiring fails closed with CALYX_KERNEL_ANSWER_LEDGER_REQUIRED (never served unprovenanced). The answer-path algorithm is implemented in astrolabe_kernel::answer; the association graph is assembled from the persisted GraphProjectionCsr->KernelGraph projection and kernel artifact read back out of the vault. When neither is persisted the tool fails closed and directs the caller to build the kernel first with get_kernel mode=\"build\". Fails closed with {code,message,remediation} on a missing project/query or a non-shadow project. A fleet scope (fleet:*) serves cross-repo exemplar citations from the composed fleet kernel instead (see scope).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {
                    "type": "string",
                    "description": "CBM project name for a project indexed with calyx=\"shadow\". Required unless scope is a fleet scope (fleet:*)."
                },
                "query": {
                    "type": "string",
                    "description": "The question to answer from the kernel. An empty query refuses fail-closed."
                },
                "scope": {
                    "type": "string",
                    "description": "Optional scope id to restrict the kernel-first search to. A fleet scope (e.g. \"fleet:rust:v1\") answers from the composed fleet kernel via declared token-containment exemplar retrieval with per-repo citations, refusing with a structured deficit when no member grounds the query (#459); project is not required for fleet scopes."
                },
                "fleet_catalog_root": {
                    "type": "string",
                    "description": "Fleet catalog vault root for fleet scopes. Defaults to the declared production catalog root."
                },
                "limit": {
                    "type": "integer",
                    "description": "Fleet scopes only: maximum citations served (declared bounds 1..=64, default 8)."
                }
            },
            "required": ["query"],
            "additionalProperties": false
        }
    })
}

pub(crate) fn anchor_erase_tool_definition() -> Value {
    json!({
        "name": "anchor_erase",
        "title": "Anchor Erase",
        "description": "Retract every grounded outcome anchor attributed to one catalog source for a shadow-indexed project. Erasure is append-only at the physical layer (the original anchor rows are never rewritten) but destructive to the serving view: an erased source leaves every active query, so this tool requires an explicit confirm=true. It writes a single AnchorTombstoneV1 into the vault's Kv column family paired with a Grounding ledger entry in one atomic group commit, and (when a fresh tombstone is committed) returns a full-readback FSV witness. Idempotent: re-erasing an already-retracted source, or a source with no anchors, is a ledger-only noop with no new tombstone. Erasure retracts the source's anchors only; it does NOT un-justify append-only AnchorPromotionV1 facts (open owner decision #354) — the boundary is labeled, never silently crossed. Fails closed with {code,message,remediation} on an unconfirmed request, a non-shadow project, a missing vault, an unclassifiable source, or an invalid/zero timestamp; no tombstone is written on any refusal.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {
                    "type": "string",
                    "description": "CBM project name for a project indexed with calyx=\"shadow\"."
                },
                "source": {
                    "type": "string",
                    "description": "The catalog source to retract: the exact value the anchors were sourced under (e.g. ci:github:owner/repo:run-42). Every anchor whose source matches is tombstoned. An unclassifiable source refuses fail-closed."
                },
                "confirm": {
                    "type": "boolean",
                    "description": "Required destructive-operation gate. Must be true: erased anchors leave every active query. Absent or false refuses without writing a tombstone."
                },
                "observed_at": {
                    "type": "integer",
                    "description": "Server-observed epoch (seconds or ms) recorded as the retraction timestamp. Defaults to the server wall clock; pass an explicit value for reproducible erasure. 0 refuses."
                }
            },
            "required": ["project", "source", "confirm"],
            "additionalProperties": false
        }
    })
}

pub(crate) fn guard_commit_ood_tool_definition() -> Value {
    json!({
        "name": "guard_commit_ood",
        "title": "Guard Commit Out-of-Distribution Scoring",
        "description": "Score a commit's changed symbols through the guard panel instrument in a secondary tick (P7.4, #48 DoD 3): each changed symbol's candidate + enclosing-scope exemplars are measured through the SAME libcbm+panel #341 instrument as indexing/guard_check, then routed against the calibrated profile. A symbol that does not conform to its trusted region (any verdict other than accept) makes the commit out-of-distribution and raises a new_region reactive trigger carrying the commit ref; a commit whose symbols all conform raises no alarm. Verdicts are appended to a durable, readback-verified review surface surfaced (labeled) on optimizer_status.commit_ood and get_readiness.commit_ood. This is the watcher/review-surface plumbing: the incremental watcher tick consumes a pending request and scores it through this same core. Every response carries trust/freshness. Fails closed with {code,message,remediation} on not-shadow, no calibrated profile, a missing commit_ref, an empty symbols set, a missing comparison region, or a panel measurement fault (an unscored change is never treated as conforming).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {
                    "type": "string",
                    "description": "CBM project name for a project indexed with calyx=\"shadow\"."
                },
                "commit_ref": {
                    "type": "string",
                    "description": "The commit ref that introduced the changed symbols (carried on every OOD trigger to the review surface)."
                },
                "panel_version": {
                    "type": "integer",
                    "description": "Panel version to measure through (1 = S0-S22, 2 = S0-S23). Defaults to the server default."
                },
                "symbols": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "The commit's changed symbols, each {cx, candidate:{panel inputs}, exemplars:[{cx, kernel_near, panel inputs}], identity_locked?}."
                }
            },
            "required": ["project", "commit_ref", "symbols"],
            "additionalProperties": false
        }
    })
}

pub(crate) fn guard_advisory_hook_tool_definition() -> Value {
    json!({
        "name": "guard_advisory_hook",
        "title": "Guard PostToolUse Advisory Hook",
        "description": "Advisory quick guard check for an edited candidate under a strict wall-clock budget (P7.4, #48 DoD 4). Scores only the two cheapest, highest-signal slots (S18 code-semantic, S4 api-callees) of the edited candidate against its enclosing-scope exemplars, measured through the SAME libcbm+panel #341 instrument as indexing. Strictly advisory: it never blocks the agent flow and never refuses a valid candidate. The pure per-slot scoring runs on a worker bounded by the registry-declared ADVISORY_HOOK_BUDGET_MS (300ms) deadline; on timeout or scoring fault it goes silent and the skip is labeled and COUNTED in the persisted, readback-verified outcome surface (never a silent swallow). The candidate/exemplars are measured on the caller thread (the reparse handle is !Send) and bounded by the reparse timeout. Fails closed with {code,message,remediation} only at the tool boundary (not-shadow, no calibrated profile, malformed args, missing candidate); a candidate that measures but cannot be scored in budget is a labeled silent skip, not a refusal.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {
                    "type": "string",
                    "description": "CBM project name for a project indexed with calyx=\"shadow\"."
                },
                "candidate": {
                    "type": "object",
                    "description": "The edited candidate's panel inputs (source, symbol_name, qualified_name, rel_file_path, language, signature, properties, label)."
                },
                "exemplars": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "The enclosing scope's trusted exemplars, each {cx, kernel_near, panel inputs}."
                },
                "panel_version": {
                    "type": "integer",
                    "description": "Panel version to measure through (1 = S0-S22, 2 = S0-S23). Defaults to the server default."
                },
                "budget_ms": {
                    "type": "integer",
                    "description": "Optional per-call deadline override in milliseconds; defaults to the registry-declared ADVISORY_HOOK_BUDGET_MS. TIGHTENING-ONLY (min(call, knob)): a value <= the registry default shortens the deadline (0 = never wait, always go silent); a value that widens it beyond the default is refused fail-closed with {code,message,remediation}, because widening the agent-facing advisory wait past the product cadence is a governance defect."
                }
            },
            "required": ["project", "candidate"],
            "additionalProperties": false
        }
    })
}

pub(crate) fn assay_gate_tool_definition() -> Value {
    json!({
        "name": "assay_gate",
        "title": "Assay Lens Capability Gate",
        "description": "Per-repo lens capability gate (P5.5): Admit/Park/Retire each candidate lens from its measured capability card, ledgered to the real Assay column family and reversible. Three modes: decide (gate one lens from a measured LensCapabilityCard + its max admitted correlation + sole-critical-carrier flag, persisting an Admit/Park/Retire verdict as a hash-chained Ledger row and re-folding the serving state), revert (neutralize a prior decision by its Ledger seq, restoring the prior serving state byte-for-byte), status (serve the current Admit/Park/Retire buckets and the serving_view mask note, optionally reading any journal entry back by Ledger seq via as_of_seq). Parked/retired lenses are masked out of serving paths non-destructively; the frozen roster and historical slot bytes are untouched. Every response carries trust/freshness/provenance and is read-back verified against the persisted CF bytes. Fails closed with {code,message,remediation} on a malformed card, an unknown mode, an invalid/already-reverted seq, or a readback mismatch.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {
                    "type": "string",
                    "description": "CBM project name for a project indexed with calyx=\"shadow\"."
                },
                "mode": {
                    "type": "string",
                    "enum": ["decide", "revert", "status"],
                    "description": "decide: gate one lens; revert: reverse a prior decision by Ledger seq; status: serve the current serving state. Defaults to status."
                },
                "card": {
                    "type": "object",
                    "description": "mode=decide: the measured LensCapabilityCard (lens, axis_bits, signal_bits, coverage, spread, separation, cost_units, n)."
                },
                "max_admitted_correlation": {
                    "type": "number",
                    "description": "mode=decide: measured max absolute correlation of the candidate with any admitted lens (0.0..=1.0)."
                },
                "sole_critical_carrier": {
                    "type": "boolean",
                    "description": "mode=decide: whether the candidate is the sole carrier of a rare-but-critical stratum (stratified override)."
                },
                "reverts_seq": {
                    "type": "integer",
                    "description": "mode=revert: the Ledger seq of the decision to reverse (from mode=status)."
                },
                "as_of_seq": {
                    "type": "integer",
                    "description": "mode=status: optionally read one journal entry back by its Ledger seq (CF-level as_of)."
                }
            },
            "required": ["project"],
            "additionalProperties": false
        }
    })
}

pub(crate) fn guard_lock_tool_definition() -> Value {
    json!({
        "name": "guard_lock",
        "title": "Guard Identity-Lock Inventory",
        "description": "Identity-lock inventory for public APIs (P7.4): exported/public symbols are identity-locked so guard_check enforces their public-API signature slot AllRequired at the identity FAR (breaking-change drift on a locked surface refuses). Four modes: lock (identity-lock an exported/public symbol; refuses a non-exported symbol fail-closed), unlock (reversible; returns the inventory byte-for-byte to its pre-lock state), inventory (serve the locked set), rebuild (rebuild the inventory from extraction export flags, the parity source of truth). Lock/unlock mutations are persisted to the config store and ledgered to the real Guard column family, read-back verified. Every response carries trust/freshness/provenance. Fails closed with {code,message,remediation} on a non-exported lock target, an unlocked unlock target, an unknown mode, or a readback mismatch.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {
                    "type": "string",
                    "description": "CBM project name for a project indexed with calyx=\"shadow\"."
                },
                "mode": {
                    "type": "string",
                    "enum": ["lock", "unlock", "inventory", "rebuild"],
                    "description": "lock/unlock a symbol, serve the inventory, or rebuild from extraction flags. Defaults to inventory."
                },
                "cx": {
                    "type": "string",
                    "description": "mode=lock/unlock: the target symbol's CxId hex."
                },
                "qualified_name": {
                    "type": "string",
                    "description": "mode=lock: the target's fully-qualified name (surfaced in the inventory)."
                },
                "exported": {
                    "type": "boolean",
                    "description": "mode=lock: whether extraction flagged the symbol exported/public (only exported symbols can be identity-locked)."
                },
                "symbols": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "mode=rebuild: the extraction symbol set, each {cx, qualified_name, exported}."
                }
            },
            "required": ["project"],
            "additionalProperties": false
        }
    })
}

pub(crate) fn abduce_cause_tool_definition() -> Value {
    json!({
        "name": "abduce_cause",
        "title": "Abduce Cause",
        "description": "\"This failed — what most plausibly caused it?\" — grounded root-cause abduction for a shadow-indexed project, the inverse of predict_impact. Reverse-walks the composite consequence graph backward from an observed failure (depth <= 3, x0.7 per-hop attenuation) through the persisted change->outcome corpus (astrolabe_oracle), scoring each candidate cause against the recency- and credit-weighted failing occurrences it has actually preceded. A candidate with grounded failing history is scored s/(s+1) (always < 1.0); a structural-only candidate is a labeled provisional leaf capped at 0.35. Two cross-checks (membership in recent_changes, a DRIVES edge into the failure region) can only rank a grounded cause UP; every hypothesis is capped strictly below certainty and names its disconfirming test. When the failure's reverse-reachable region carries too little grounded failing history the tool refuses with a per-sensor deficit card rather than abducing from a coincidence (HONEST invariant 2). Fails closed with {code,message,remediation} on a missing/unresolved failure symbol or a malformed observed_at.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {
                    "type": "string",
                    "description": "CBM project name for a project indexed with calyx=\"shadow\"."
                },
                "failure": {
                    "type": "string",
                    "description": "Qualified name of the failing symbol to reason back from. Must resolve in this project's indexed graph or the call refuses fail-closed."
                },
                "observed_at": {
                    "type": "integer",
                    "description": "Server-observed epoch (seconds or ms) at which the failure was observed — the recency and causality reference. Defaults to the server wall clock; pass an explicit value for reproducible abduction. 0 refuses."
                },
                "recent_changes": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Qualified names of symbols changed in the caller's recent window. A grounded candidate in this set is ranked up (the recent-change cross-check). Names that do not resolve are labeled and ignored, never guessed."
                }
            },
            "required": ["project", "failure"],
            "additionalProperties": false
        }
    })
}

pub(crate) fn forecast_tool_definition() -> Value {
    json!({
        "name": "forecast",
        "title": "Forecast Recurrence",
        "description": "\"When will this fail again?\" — a grounded recurrence forecast for a shadow-indexed project, answered from the subject's persisted failure series in the change->outcome corpus (astrolabe_oracle). mode=\"recurrence\" (default) forecasts the next-failure cadence: a robust median inter-arrival interval, a credible interval widened (and labeled provisional) for a small sample, a renewal overdue hazard, and CUSUM-detected cadence regime changes; the confidence is regularity*support, strictly < 1.0. mode=\"flaky\" forecasts a test's clean failure-recurrence window but REFUSES with ASTRO_FLAKY_EVIDENCE when the pass/fail series is self-inconsistent — forecasting a cadence from flaky noise would be a confident guess. Too few failure events refuses with ASTRO_NO_RECURRENCE. Every interval is labeled with its trust; fails closed with {code,message,remediation} on a missing/unresolved subject, a malformed now, or an unsupported mode.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {
                    "type": "string",
                    "description": "CBM project name for a project indexed with calyx=\"shadow\"."
                },
                "subject": {
                    "type": "string",
                    "description": "Qualified name of the symbol/test whose failure recurrence to forecast. Must resolve in this project's indexed graph or the call refuses fail-closed."
                },
                "mode": {
                    "type": "string",
                    "enum": ["recurrence", "flaky"],
                    "description": "recurrence (default): forecast the subject's failure-recurrence cadence. flaky: forecast a test's clean failure window, refusing on flaky (self-inconsistent) evidence."
                },
                "now": {
                    "type": "integer",
                    "description": "Server-observed epoch (seconds or ms) used as the reference instant for the overdue hazard. Defaults to the server wall clock; pass an explicit value for reproducible forecasts. 0 refuses."
                }
            },
            "required": ["project", "subject"],
            "additionalProperties": false
        }
    })
}

pub(crate) fn measure_bits_tool_definition() -> Value {
    json!({
        "name": "measure_bits",
        "title": "Measure Bits",
        "description": "Serve per-repo measured assay cards for a shadow-indexed project, replacing CBM's fixed constants with measured values. Six modes: signals (per-slot bits ± CI ranked about an axis), sufficiency (I(panel;axis) vs H(axis) with the deficit breakdown), redundancy (total correlation + effective rank n_eff + the pairwise redundancy map), synergy (three-way interaction information over designed triples), causality (transfer-entropy DRIVES edges with a lag sweep), and calibration (each edge-resolution strategy's measured empirical precision vs its CBM prior, with a Wilson CI; measured supersedes the prior above quorum, the prior is retained as a labeled fallback below it). Every response carries trust/freshness/provenance. signals also diagnoses an exact validated preserved failed Assay publication when its live shadow dial is absent, returning the prepared/unpublished/corrupt cause as a structured tool error rather than hiding it behind the generic admission failure. refresh:true recomputes the calibration card on demand from persisted observations (re-persisted with an incremented seq and reset freshness, write-then-readback verified); other modes' recompute is owned by the background assay lane and refresh is labeled accordingly. Fails closed with {code,message,remediation} on an unknown mode, a malformed axis, or an absent/corrupt card.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {
                    "type": "string",
                    "description": "CBM project name for a project indexed with calyx=\"shadow\"."
                },
                "mode": {
                    "type": "string",
                    "enum": ["signals", "sufficiency", "redundancy", "synergy", "causality", "calibration"],
                    "description": "Which assay card to serve."
                },
                "axis": {
                    "type": "string",
                    "description": "Outcome axis for per-axis modes (signals, sufficiency, synergy, causality). Omit for the panel-wide modes (redundancy, calibration). A present-but-empty axis is refused."
                },
                "scope": {
                    "type": "string",
                    "description": "Optional scope id to partition the card by. If omitted, the project-level card is served."
                },
                "refresh": {
                    "type": "boolean",
                    "description": "If true, recompute on demand. Wired for mode=\"calibration\" (recomputes from persisted observations, bumps the card seq, resets freshness); other modes serve the cached card and label refresh as lane-owned."
                }
            },
            "required": ["project", "mode"],
            "additionalProperties": false
        }
    })
}

pub(crate) fn predict_impact_tool_definition() -> Value {
    json!({
        "name": "predict_impact",
        "title": "Predict Impact",
        "description": "\"If I change X, what breaks?\" — a grounded change-impact prediction for a shadow-indexed project, answered from the persisted change→outcome corpus (astrolabe_oracle), never from raw topology. Builds a composite consequence graph from the persisted CBM graph edges (CALLS/DATA_FLOWS/service/TESTS, direction-corrected to impact flow) and grounds each node in the vault's occurrence rows; a cycle-guarded butterfly walk (×0.7 per hop, prune <0.05, depth ≤4) expands the tree, three independent ceilings keep every probability strictly below 1.0, and consequences that intersect TESTS edges become a ranked test-selection set. Grounded confidence is advertised ONLY when this repo's persisted backtest gate passed; otherwise every consequence is labeled provisional (never a silent grounded default). When the seeds carry no grounded history the tool refuses with a per-sensor deficit card rather than guessing. mode=\"backtest\" runs the grounded-vs-topology backtest over cases derived from the corpus and persists (with FSV readback) the per-repo gate.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {
                    "type": "string",
                    "description": "CBM project name for a project indexed with calyx=\"shadow\"."
                },
                "seeds": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Qualified name(s) of the symbol(s) you intend to change. Required for mode=\"predict\"; any seed absent from the indexed graph refuses fail-closed."
                },
                "mode": {
                    "type": "string",
                    "enum": ["predict", "backtest"],
                    "description": "predict (default): ranked consequences + test-selection, or an Insufficient deficit card. backtest: run the grounded-vs-topology backtest and persist this repo's grounded-mode gate."
                }
            },
            "required": ["project"],
            "additionalProperties": false
        }
    })
}

pub(crate) fn guard_check_tool_definition() -> Value {
    json!({
        "name": "guard_check",
        "title": "Guard Check",
        "description": "Route a candidate symbol/diff through the guard: measure it via the SAME instruments as indexing, resolve its comparison region (kernel-near trusted exemplars first, peripheral fallback), score every fixed guard slot's cosine against the persisted calibrated tau, and combine the per-slot outcomes into accept / new_region / quarantine / refuse (never a flattened average). The verdict is ledgered (kind=Guard, subject=Cx(target)) with the full per-slot cos/tau/pass detail; a new_region verdict records an AwaitingGrounding lifecycle entry. The guard measures distributional conformance to trusted exemplars, not correctness. Fails closed on an uncalibrated profile, an unparseable target CxId, a candidate/exemplar missing a guard slot or carrying a degenerate vector, or an empty comparison region.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {
                    "type": "string",
                    "description": "CBM project name for a project indexed with calyx=\"shadow\" and guard_calibrate'd."
                },
                "target": {
                    "type": "string",
                    "description": "Candidate symbol CxId hex; the verdict ledger entry's subject."
                },
                "candidate": {
                    "type": "object",
                    "description": "The candidate's measured per-slot lens vectors.",
                    "properties": {
                        "slots": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "slot": {
                                        "type": "string",
                                        "enum": ["code_semantic", "struct_trigrams", "api_callees", "name_semantic", "complexity_profile", "error_surface", "public_api_signature"]
                                    },
                                    "vector": {"type": "array", "items": {"type": "number"}}
                                },
                                "required": ["slot", "vector"],
                                "additionalProperties": false
                            }
                        }
                    },
                    "required": ["slots"],
                    "additionalProperties": false
                },
                "exemplars": {
                    "type": "array",
                    "description": "The enclosing scope's trusted exemplars, each measured on every guard slot. kernel_near exemplars form the primary comparison region.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "cx": {"type": "string"},
                            "kernel_near": {"type": "boolean"},
                            "slots": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "slot": {"type": "string"},
                                        "vector": {"type": "array", "items": {"type": "number"}}
                                    },
                                    "required": ["slot", "vector"],
                                    "additionalProperties": false
                                }
                            }
                        },
                        "required": ["slots"],
                        "additionalProperties": false
                    }
                }
            },
            "required": ["project", "target", "candidate", "exemplars"],
            "additionalProperties": false
        }
    })
}

pub(crate) fn coverage_ingest_tool_definition() -> Value {
    json!({
        "name": "coverage_ingest",
        "title": "Coverage Ingest",
        "description": "Ground outcome anchors for a shadow-indexed project from a direct coverage report plus a suite run. Assembles propagation inputs from the live CBM graph (symbol line ranges + TESTS/TESTS_FILE edges), maps executed lines to the containing symbols line-exact (resolved, confidence 1.0), and — bounded to the changed-files impact set — propagates passing tests one hop along TESTS edges to covered symbols (proxy, confidence 0.6). Coverage supersedes propagation for any symbol it covers. Reports anchored / excluded_by_fanout / unmatched counts. Malformed reports, a non-resolved coverage_source, or an empty graph refuse fail-closed with no partial anchor.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {
                    "type": "string",
                    "description": "CBM project name for a project indexed with calyx=\"shadow\"."
                },
                "coverage_format": {
                    "type": "string",
                    "enum": ["lcov", "coverage_py_json", "cobertura_xml"],
                    "description": "Direct-coverage report format."
                },
                "coverage_report": {
                    "type": "string",
                    "description": "Full coverage report text in the declared format. Partial or malformed reports refuse fail-closed."
                },
                "test_format": {
                    "type": "string",
                    "enum": ["junit_xml", "cargo_test_json", "pytest_verbose", "go_test_json", "vitest_json"],
                    "description": "Suite-run report format, used to determine which tests passed for propagation."
                },
                "test_report": {
                    "type": "string",
                    "description": "Full suite-run report text in the declared test_format."
                },
                "coverage_source": {
                    "type": "string",
                    "description": "Resolved catalog source for coverage anchors: ci:/trace:/review:/git:revert: (Trusted, confidence 1.0). A proxy source refuses fail-closed."
                },
                "run_id": {
                    "type": "string",
                    "description": "Opaque run identifier; propagation anchors are sourced propagation:<run_id>."
                },
                "impact_files": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Changed files' impact set (repo-relative). Propagation anchors are confined to symbols in these files. Empty (default) means no diff: only direct coverage grounds."
                },
                "observed_at": {
                    "type": "integer",
                    "description": "Server-observed epoch (seconds or ms). Defaults to the server wall clock; pass an explicit value for reproducible anchoring. 0 refuses."
                }
            },
            "required": ["project", "coverage_format", "coverage_report", "test_format", "test_report", "coverage_source", "run_id"],
            "additionalProperties": false
        }
    })
}

pub(crate) fn guard_calibrate_tool_definition() -> Value {
    json!({
        "name": "guard_calibrate",
        "title": "Guard Calibrate",
        "description": "Build/refresh a per-domain guard profile by split (inductive) conformal calibration. Three declared modes: generated (auto-generate the bad calibration population from the indexed corpus itself — mutation of real HEAD source, revert records, the vulnerability registry, and alien constellations from other indexed projects — and read the trusted/good population from persisted indexed slot vectors, so NO caller-supplied class tags are needed); auto (score caller-supplied sources through the real panel/lens stack S18/S1/S4/S20/S2/S15/S5+S17 with an explicit good/bad class tag); and supplied (operator-supplied per-slot cosine arrays). Each fixed guard slot's per-slot tau is set on a calibration half of its measured bad-cosine population (binomial-bounded), the achieved FAR is measured on a held-out validation half and checked against a finite-sample ceiling, and the FRR is measured on the good population. The calibration is ledgered (kind=Guard, subject=Guard(profile_hash)) and the astrolabe.optimizer_guard_health.v1 profile is persisted. Generated mode enforces the R16 mix policy (>=50 bad cases, >=3 generators, <=60% per generator) and fails closed on an under-mixed corpus. Fails closed on an unknown/ambiguous mode, a missing slot, a panel that lacks a required slot, a thin (<2) or single-source population, or a slot whose held-out FAR breaches its bound; a generated/auto panel failure never falls back to caller tags or supplied cosines.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {
                    "type": "string",
                    "description": "CBM project name for a project indexed with calyx=\"shadow\"."
                },
                "mode": {
                    "type": "string",
                    "enum": ["generated", "auto", "supplied"],
                    "description": "Population-source mode. generated auto-generates the bad corpus from the indexed corpus and reads the trusted population from persisted slot vectors; auto scores caller sources through the real panel with class tags; supplied consumes operator cosine arrays. Inferred from mutation_sources/sources/slots when omitted; ambiguous (more than one) or absent (none) is refused."
                },
                "panel_version": {
                    "type": "integer",
                    "description": "Frozen panel roster version used to measure sources/mutants (1=S0-S22, 2=S0-S23; auto defaults to 1, generated defaults to the shadow panel version 2 so it matches persisted vectors)."
                },
                "mutation_sources": {
                    "type": "array",
                    "description": "generated mode: real HEAD source-text strings to mutate (per-language token mutators produce the guaranteed-wrong bad cases). Required for generated mode.",
                    "items": {"type": "string"}
                },
                "revert_records": {
                    "type": "array",
                    "description": "generated mode (optional): reverted-code records (real historical rejections). Each carries reverted_code plus optional introduced_commit/revert_commit provenance.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "reverted_code": {"type": "string"},
                            "introduced_commit": {"type": "string"},
                            "revert_commit": {"type": "string"}
                        },
                        "required": ["reverted_code"],
                        "additionalProperties": true
                    }
                },
                "aliens": {
                    "type": "array",
                    "description": "generated mode (optional): other shadow-indexed projects whose persisted, non-vendored symbol slot vectors become the alien bad population (valid code, wrong distribution). Each is {\"project\": \"<other-indexed-project>\"}.",
                    "items": {
                        "type": "object",
                        "properties": {"project": {"type": "string"}},
                        "required": ["project"],
                        "additionalProperties": true
                    }
                },
                "good_project": {
                    "type": "string",
                    "description": "generated mode (optional): the shadow-indexed project whose persisted indexed symbols form the trusted (good) population. Defaults to project."
                },
                "seed": {
                    "type": "integer",
                    "description": "generated mode (optional): deterministic corpus shuffle seed (default 0). The same inputs + seed produce a byte-identical corpus_hash. Also seeds the deterministic good/alien population sampling (#367)."
                },
                "good_sample_cap": {
                    "type": "integer",
                    "description": "generated mode (optional): registry-declared cap (astro.guard.calibration_sampling.v1) on the trusted (good) symbols reparsed through the panel, bounding the panel-read count on M-scale corpora. Selection is deterministic + seeded. Out-of-bounds values are refused fail-closed; omit for the registry default."
                },
                "alien_sample_cap": {
                    "type": "integer",
                    "description": "generated mode (optional): registry-declared cap (astro.guard.calibration_sampling.v1) on the alien bad cases drawn per referenced project (seeded, deterministic). The R16 mix policy is still enforced AFTER sampling. Out-of-bounds values are refused fail-closed; omit for the registry default."
                },
                "sources": {
                    "type": "array",
                    "description": "auto mode: source symbols scored through the panel. Each object carries panel-encoder inputs (symbol_name, qualified_name, rel_file_path, language, signature, source, parsed CBM properties, optional label) and a class of \"good\" (in-distribution) or \"bad\" (out-of-distribution).",
                    "items": {
                        "type": "object",
                        "properties": {
                            "class": {"type": "string", "enum": ["good", "bad"]},
                            "symbol_name": {"type": "string"},
                            "qualified_name": {"type": "string"},
                            "rel_file_path": {"type": "string"},
                            "language": {"type": "string"},
                            "signature": {"type": "string"},
                            "label": {"type": "string"},
                            "source": {"type": "string"},
                            "properties": {"type": "object"}
                        },
                        "required": ["class"],
                        "additionalProperties": true
                    }
                },
                "domain": {
                    "type": "object",
                    "description": "Calibration domain = language x scope-class.",
                    "properties": {
                        "language": {
                            "type": "string",
                            "enum": ["rust", "python", "javascript", "typescript", "go", "java", "c", "cpp", "csharp", "ruby"]
                        },
                        "scope_class": {
                            "type": "string",
                            "description": "Non-empty scope class such as core, frontend, or test."
                        }
                    },
                    "required": ["language", "scope_class"],
                    "additionalProperties": false
                },
                "alpha": {
                    "type": "number",
                    "description": "Binomial confidence level for the per-slot tau bound (default 0.05)."
                },
                "slots": {
                    "type": "array",
                    "description": "supplied mode: one object per fixed guard slot with measured good_scores and bad_scores cosine arrays.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "slot": {
                                "type": "string",
                                "enum": ["code_semantic", "struct_trigrams", "api_callees", "name_semantic", "complexity_profile", "error_surface", "public_api_signature"]
                            },
                            "good_scores": {"type": "array", "items": {"type": "number"}},
                            "bad_scores": {"type": "array", "items": {"type": "number"}}
                        },
                        "required": ["slot", "good_scores", "bad_scores"],
                        "additionalProperties": false
                    }
                }
            },
            "required": ["project", "domain"],
            "additionalProperties": false
        }
    })
}

pub(crate) fn anchor_outcome_tool_definition() -> Value {
    json!({
        "name": "anchor_outcome",
        "title": "Anchor Outcome",
        "description": "Ground real-world outcome anchors for a shadow-indexed project. The test_run kind parses a JUnit/cargo/pytest/go/vitest report and writes one grounded TestPass anchor per resolved subject, paired with a Grounding ledger entry. Catalog sources are ci:/trace:/review:/git:revert: (Trusted, confidence 1.0) and git:fix:/agent:/survival: (Provisional, confidence in (0,1)).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {
                    "type": "string",
                    "description": "CBM project name for a project indexed with calyx=\"shadow\"."
                },
                "kind": {
                    "type": "string",
                    "enum": ["test_run"],
                    "description": "Outcome kind. Only test_run is wired with a built-in payload."
                },
                "source": {
                    "type": "string",
                    "description": "Catalog source: ci:/trace:/review:/git:revert: for resolved evidence, or git:fix:/agent:/survival: for proxy evidence. ci: and agent: require owner plus observation components."
                },
                "format": {
                    "type": "string",
                    "enum": ["junit_xml", "cargo_test_json", "pytest_verbose", "go_test_json", "vitest_json"],
                    "description": "Test-report format for the report payload."
                },
                "report": {
                    "type": "string",
                    "description": "Full test-report text in the declared format. Partial or malformed reports refuse fail-closed."
                },
                "confidence": {
                    "type": "number",
                    "description": "Optional confidence. Resolved sources require exactly 1.0; proxy sources require a finite value in (0,1) and default to 0.8."
                },
                "observed_at": {
                    "type": "integer",
                    "description": "Server-observed epoch (seconds or ms) at which the outcome was observed. Defaults to the server wall clock; pass an explicit value for reproducible CI anchoring. 0 refuses."
                }
            },
            "required": ["project", "source", "format", "report"],
            "additionalProperties": false
        }
    })
}

pub(crate) fn get_provenance_tool_definition() -> Value {
    json!({
        "name": "get_provenance",
        "title": "Get Provenance",
        "description": "Return labeled Astrolabe provenance for a shadow-indexed project. Modes are lineage, answer_trace (the recorded kernel answer's lineage; legs the answer does not carry — fusion weights, guard verdict — are reported as explicit unprovenanced warnings, never fabricated links), verify_chain, reproduce, and inter_agent_trust (one-call verification of a context pack claimed by another agent). reproduce live-re-executes the recorded kernel answer with its frozen lenses and recorded seeds against the current vault graph: an unchanged vault reproduces bit-for-bit, and a perturbed vault fails closed with REPRODUCE_DRIFT_EXCEEDED naming the drift magnitude when the measured drift exceeds the registry-pinned 1e-3 bound.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {
                    "type": "string",
                    "description": "CBM project name for a project indexed with calyx=\"shadow\"."
                },
                "mode": {
                    "type": "string",
                    "enum": ["lineage", "answer_trace", "verify_chain", "reproduce", "inter_agent_trust"]
                },
                "subject_id": {
                    "type": "string",
                    "description": "Symbol id or answer id required by lineage, answer_trace, and reproduce."
                },
                "drift_bound_microunits": {
                    "type": "integer",
                    "description": "reproduce: optional tightening-only override of the 1e-3 (1000-microunit) drift bound. A value above the pinned default is refused; omit to use 1e-3."
                },
                "manifest": {
                    "type": "object",
                    "description": "inter_agent_trust: the claimed context-pack manifest to verify against this serving vault (pack_id, ledger_ref{seq,chain_hash}, vault_fingerprint, member_hash)."
                },
                "attestation": {
                    "type": "string",
                    "description": "inter_agent_trust: a self-describing pack-manifest attestation artifact string handed over by the serving agent, verified in place of an inline manifest object."
                }
            },
            "required": ["project", "mode"],
            "additionalProperties": false
        }
    })
}

pub(crate) fn detect_anomalies_tool_definition() -> Value {
    json!({
        "name": "detect_anomalies",
        "title": "Detect Anomalies",
        "description": "Return calibrated Astrolabe anomaly findings for a shadow-indexed project, optionally filtered by kind.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {
                    "type": "string",
                    "description": "CBM project name for a project indexed with calyx=\"shadow\"."
                },
                "kind": {
                    "type": "string",
                    "enum": ["doc_drift", "name_truth", "drift", "ood_commit", "prompt_injection"]
                }
            },
            "required": ["project"],
            "additionalProperties": false
        }
    })
}

pub(crate) fn optimizer_status_tool_definition() -> Value {
    json!({
        "name": "optimizer_status",
        "title": "Optimizer Status",
        "description": "Return labeled Astrolabe optimizer readiness for a shadow-indexed project, including Calyx Loom's physical Ledger+Reactive subscription/event state; durably acknowledge pending Loom trigger events for a subscription; or generate pending proposals from measured deficits.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {
                    "type": "string",
                    "description": "CBM project name for a project indexed with calyx=\"shadow\"."
                },
                "mode": {
                    "type": "string",
                    "enum": ["status", "ack_triggers", "propose"],
                    "description": "Use status for readback, ack_triggers to append a durable acknowledgement for one subscription, or propose to turn measured deficits into a persisted proposal queue."
                },
                "subscription_id": {
                    "type": "string",
                    "description": "Required when mode is ack_triggers; use a subscription_id returned by optimizer_status.reactive_triggers.subscriptions."
                }
            },
            "required": ["project"],
            "additionalProperties": false
        }
    })
}

pub(crate) fn get_readiness_tool_definition() -> Value {
    json!({
        "name": "get_readiness",
        "title": "Get Readiness",
        "description": "Return Astrolabe's six-tier readiness predicate for a shadow-indexed project/scope. Tiers fail closed unless their measured source state is present.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {
                    "type": "string",
                    "description": "CBM project name for a project indexed with calyx=\"shadow\"."
                },
                "scope": {
                    "type": "string",
                    "description": "Optional scope id to evaluate. If omitted, project-level readiness is reported."
                },
                "axis": {
                    "type": "string",
                    "description": "Optional readiness axis label; currently used only for labeled remediation."
                }
            },
            "required": ["project"],
            "additionalProperties": false
        }
    })
}

pub(crate) fn impute_fields_tool_definition() -> Value {
    json!({
        "name": "impute_fields",
        "title": "Impute Fields",
        "description": "Return persisted Astrolabe imputation proposals for a target field. Proposals are always inferred/provisional and are never written as trusted data.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {
                    "type": "string",
                    "description": "CBM project name for a project indexed with calyx=\"shadow\"."
                },
                "target": {
                    "type": "string",
                    "description": "Stable target id whose missing field should be proposed."
                },
                "field": {
                    "type": "string",
                    "enum": ["doc", "types", "callees", "tests"],
                    "description": "Missing field to impute."
                },
                "write_as_trusted": {
                    "type": "boolean",
                    "description": "If true, the tool refuses; imputed values cannot be merged as trusted data."
                }
            },
            "required": ["project", "target", "field"],
            "additionalProperties": false
        }
    })
}

pub(crate) fn team_artifact_tool_definition() -> Value {
    json!({
        "name": "team_artifact",
        "title": "Team Artifact",
        "description": "Export or import the chain-verified Astrolabe team artifact. Use repo_path to target <repo>/.codebase-memory, or pass artifact_dir explicitly.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "mode": {
                    "type": "string",
                    "enum": ["export", "import"],
                    "description": "export writes graph.db.zst, vault.export.zst, and artifact.json; import verifies before adopting graph bytes."
                },
                "project": {
                    "type": "string",
                    "description": "CBM project name. Required for export; import uses it to default adopted_graph_path to the local CBM cache DB."
                },
                "repo_path": {
                    "type": "string",
                    "description": "Repository path whose .codebase-memory directory contains or receives the team artifact."
                },
                "artifact_dir": {
                    "type": "string",
                    "description": "Explicit artifact directory. Overrides repo_path/.codebase-memory."
                },
                "adopted_graph_path": {
                    "type": "string",
                    "description": "Import destination for verified graph bytes. Defaults to the local CBM cache DB for project."
                },
                "signing_key_hex": {
                    "type": "string",
                    "description": "Optional 32-byte hex Ed25519 signing seed for export."
                },
                "expected_signer_pubkey_hex": {
                    "type": "string",
                    "description": "Optional 32-byte hex signer public key required during import."
                }
            },
            "required": ["mode"],
            "additionalProperties": false
        }
    })
}
