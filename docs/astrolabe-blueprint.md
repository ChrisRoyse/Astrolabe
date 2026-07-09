
# 00_INDEX.md

# ASTROLABE â€” Calyx Ã— codebase-memory-mcp Integration Plan

**Codename:** ASTROLABE (an astrolabe is the instrument for navigating by constellations â€” this system navigates codebases whose atomic records *are* constellations). Placeholder name; rename freely.

**What this is.** The complete planning suite for fusing **Calyx** (the association-native database and grounded-intelligence engine, Rust, ~24 crates) with **codebase-memory-mcp** (the 158-language codebase knowledge-graph MCP server, C, single static binary) into one system: *the ultimate coding MCP for AI agents* â€” a code-intelligence substrate that measures, grounds, distills, guards, predicts, and self-optimizes over any codebase, with provenance for every claim.

**The one-line thesis.** codebase-memory-mcp already performs steps â‘  DECOMPOSE and â‘¡ ASSOCIATE of the Calyx method for the code domain â€” it atomizes a repository into symbols and extracts every base association (calls, imports, types, usage, data flow, routes, channels, co-change, similarity). Calyx is the engine for steps â‘¢ DIFFERENTIATE and â‘£ DISTILLâ†’COMPOSE â€” bits, sufficiency, kernel, guard, oracle, ledger, self-optimization. **Neither project needs the other to be rewritten; each is the missing half of the other.**

```
codebase-memory-mcp                          Calyx
â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€                       â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
â‘  DECOMPOSE: 158-lang tree-sitter      â†’     Measure: constellations
   + Hybrid LSP â†’ atoms (symbols)            (panel of code lenses)
â‘¡ ASSOCIATE: 40+ edge types,           â†’     Count: cross-terms, agreement
   cross-service, cross-repo, git            graph, between-record graph
                                             â‘¢ DIFFERENTIATE: bits, sufficiency,
                                                redundancy, synergy, causality
                                             â‘£ COMPOSE: kernel, guard, oracle,
                                                ledger, anneal, fused search
```

---

## Document series

| # | Document | Covers |
|---|---|---|
| 00 | **00_INDEX.md** | This index. Executive summary, reading order, decision log. |
| 01 | [01_VISION.md](01_VISION.md) | The fusion thesis, the intelligence flywheel, what changes for AI agents, headline outcomes. |
| 02 | [02_CAPABILITY_CATALOG.md](02_CAPABILITY_CATALOG.md) | **The exhaustive catalog** â€” every capability the combined system delivers, in 12 tiers, ~80 entries. The "no blind spots" document. |
| 03 | [03_ARCHITECTURE.md](03_ARCHITECTURE.md) | System architecture: process model, Rustâ†”C boundary, storage (Aster primary / SQLite lowered), crate layout, threading, memory. |
| 04 | [04_DATA_MODEL.md](04_DATA_MODEL.md) | Exact mapping: CBM nodes/edges/properties â†’ constellations/anchors/graph; identity scheme (QN series vs. content-addressed versions). |
| 05 | [05_LENS_PANEL.md](05_LENS_PANEL.md) | The code lens panel: ~24 lenses (deterministic encoders + embedders), shapes, frozen contracts, embed-vs-encode audit of every CBM signal. |
| 06 | [06_ANCHORS.md](06_ANCHORS.md) | Grounding: every anchor source (tests, CI, git archaeology, traces, agent outcomes, reviews, incidents), trust lifecycle, cold start. |
| 07 | [07_ASSOCIATIONS.md](07_ASSOCIATIONS.md) | The weave: cross-terms over code slots, between-record graph from CBM edges, agreement graph, temporal lead/lag, materialization budgets. |
| 08 | [08_ASSAY.md](08_ASSAY.md) | Measurement: bits per signal per repo, sufficiency, redundancy/effective rank, synergy, transfer entropy â€” replacing every fixed constant with a measured value. |
| 09 | [09_KERNEL_CONTEXT.md](09_KERNEL_CONTEXT.md) | The kernel as context engine: codebase kernels at any scope, kernel answers, token-budgeted context packs, grounding gaps, blast radius. |
| 10 | [10_GUARD.md](10_GUARD.md) | Guarded generation: per-slot conformal validation of agent-written code, calibration data strategy, identity-lock, drift monitoring. |
| 11 | [11_ORACLE.md](11_ORACLE.md) | Prediction: change-impact (butterfly), root-cause abduction, honesty gate, imputation, flaky-test forecasting, readiness predicate. |
| 12 | [12_SEARCH.md](12_SEARCH.md) | Search unification: per-slot indexes + RRF fusion replacing ad-hoc paths, guarded search, Cypher's fate, temporal boosts. |
| 13 | [13_PROVENANCE.md](13_PROVENANCE.md) | Ledger: hash-chained provenance for every graph mutation and answer, answer_trace, reproduce, verify_chain, agent trust model. |
| 14 | [14_SELF_OPTIMIZATION.md](14_SELF_OPTIMIZATION.md) | Anneal: per-repo tuning of fusion/thresholds/quantization, tripwires, shadow tests, deficit-driven lens proposal, mistake closure. |
| 15 | [15_MCP_SURFACE.md](15_MCP_SURFACE.md) | The full MCP tool surface (~30 tools): retained, upgraded, new. Schemas, hooks, skills, CLI parity, backward compatibility. |
| 16 | [16_INCREMENTAL_REACTIVE.md](16_INCREMENTAL_REACTIVE.md) | Incremental indexing, watcher â†’ reactive triggers, MVCC time-travel over code history, recurrence series. |
| 17 | [17_PERFORMANCE_SCALE.md](17_PERFORMANCE_SCALE.md) | Budgets and complexity: Linux-kernel-scale numbers, sampling strategies, quantization, lowering, memory discipline. |
| 18 | [18_MIGRATION_COMPAT.md](18_MIGRATION_COMPAT.md) | Shadow â†’ flip â†’ native migration (the Leapable pattern), SQLite as lowered artifact, existing-user compatibility. |
| 19 | [19_BUILD_TOOLCHAIN.md](19_BUILD_TOOLCHAIN.md) | Building C+Rust as one binary: FFI design, `libcbm` static library, allocator unification, cross-platform matrix, packaging. |
| 20 | [20_TESTING_VERIFICATION.md](20_TESTING_VERIFICATION.md) | Test strategy: parity harnesses, determinism probes, FSV byte-verification, invariants, soak, agent-level evals. |
| 21 | [21_RISKS_BLINDSPOTS.md](21_RISKS_BLINDSPOTS.md) | The risk register: ~30 risks (licensing, scale, flaky anchors, cold start, allocators, nondeterminismâ€¦) with mitigations. |
| 22 | [22_ROADMAP.md](22_ROADMAP.md) | Phased delivery P0â€“P10, milestone gates, effort estimates, the ASTROLABE_DONE predicate. |

## Reading order

- **Decision-maker:** 01 â†’ 02 â†’ 22 â†’ 21.
- **Architect:** 03 â†’ 04 â†’ 05 â†’ 19 â†’ 18 â†’ 17.
- **Intelligence design:** 05 â†’ 06 â†’ 07 â†’ 08 â†’ 09 â†’ 10 â†’ 11.
- **Agent/tooling design:** 15 â†’ 09 â†’ 12 â†’ 13.
- **Implementer starting P0:** 22 â†’ 19 â†’ 03 â†’ 04 â†’ 20.

## Executive summary (10 claims)

1. **CBM is the world's best code decomposer/instrumenter** (158 languages, 9-family type-aware LSP, cross-service and cross-repo linking). Calyx is the world's only association-native grounded-intelligence database. CBM produces exactly the input Calyx's doctrine demands: *atoms + all base associations, computed from the ground up*.
2. Every code symbol becomes a **constellation** measured through a ~24-lens panel built almost entirely from signals CBM *already extracts* (AST profiles, complexity, MinHash, API/type/decorator signatures, nomic embeddings, git temporal data, graph position). Near-zero new inference cost.
3. **Grounding comes from real developer outcomes**: test results, CI runs, bug-fix archaeology (SZZ), reverts, runtime traces (completing CBM's stubbed `ingest_traces`), review verdicts, and â€” critically â€” **AI-agent task outcomes**, closing the flywheel.
4. **Assay replaces every guessed constant with a measured value.** CBM's 11 semantic signals, fixed thresholds (0.75, 0.95), and fixed edge confidences (0.5â€“0.95) become per-repo measured bits, calibrated thresholds, and annealed weights.
5. **The kernel is the context engine.** The ~1% of symbols that provably (recall â‰¥ 0.95) explain the codebase becomes token-budgeted context packs â€” turning CBM's "99% fewer tokens" marketing claim into a measured, gated guarantee.
6. **The guard makes autonomous coding safe.** Agent-generated code is conformally validated per-slot (semantics, structure, API usage, naming, conventions) against the repo's own trusted region, with calibrated false-accept rates â€” accept / new-region / quarantine / refuse.
7. **The oracle predicts consequences.** "If I change X, what breaks?" answered from grounded changeâ†’outcome history via hop-attenuated consequence trees; root-cause abduction runs the same walk backwards; the honesty gate refuses questions the panel can't support.
8. **Every answer carries provenance.** Hash-chained ledger, answer traces, bit-for-bit reproduction, tamper-evident graph â€” the first MCP whose claims an agent (or auditor) can verify.
9. **Architecture: Rust host, C engine.** A new Rust binary embeds Calyx crates natively and links CBM's extraction pipeline as a static C library (`libcbm`). Migration follows Calyx's own proven Leapable pattern: shadow â†’ flip â†’ native, with SQLite retained as a *lowered artifact* for the Cypher engine and UI.
10. **Both codebases are ~production-grade.** CBM: MIT, ~201K LOC C, 5,900+ tests. Calyx: BSL 1.1 standalone, with an Astrolabe-specific owner grant recorded in the root LICENSE/NOTICE for the combined binary, ~540K LOC Rust, ~3,500+ tests. The integration is additive: no rewrite of either engine's core.

## Decision log (headline decisions made in these documents)

| # | Decision | Where |
|---|---|---|
| D1 | Rust host binary; CBM linked as `libcbm.a` behind a narrow FFI; Calyx crates native | 03, 19 |
| D2 | Phase A uses **zero-FFI import** (CBM CLI â†’ SQLite â†’ Rust importer), FFI streaming comes later | 18, 19 |
| D3 | Aster vault becomes source of truth; SQLite `.db` becomes a regenerable **lowered artifact** (Cypher + UI keep working unchanged) | 03, 18 |
| D4 | Identity: qualified name = stable *series* identity; content-address of (project, QN, source bytes) = *version* identity (CxId) | 04 |
| D5 | Panel v1 = ~24 lenses derived from existing CBM signals; heavy model lenses (TEI/ONNX/candle) optional plug-ins via Calyx registry | 05 |
| D6 | Anchors: tests/CI first-class; SZZ bug archaeology; agent task outcomes as Reward anchors; survival anchors provisional-only | 06 |
| D7 | CBM's `SIMILAR_TO`/`SEMANTICALLY_RELATED` passes retained as candidate generators; *scoring/admission* moves to measured (Assay + Anneal) | 07, 08 |
| D8 | MCP tool surface: 14 legacy tools retained (behavior-compatible), ~16 new tools, consolidated via modes | 15 |
| D9 | mimalloc unified as the global allocator for both C and Rust halves | 19 |
| D10 | Ship CPU-only by default (nomic vectors are lookup tables; Calyx CPU paths); GPU strictly opt-in | 03, 17 |

## Terminology bridge (both projects' words for the same things)

| Concept | CBM term | Calyx term | ASTROLABE term |
|---|---|---|---|
| Atomic code unit | node (Function/Class/â€¦) | constellation | symbol constellation |
| Stable symbol identity | qualified_name (QN) | â€” (series key) | series id |
| Version identity | node id (per-index) | CxId (content address) | version id |
| Relationship | edge (CALLS/â€¦) | association / graph edge | association |
| Signal extractor | pass / extractor | lens | lens |
| Signal value | property / vector | slot | slot |
| Extractor set | (implicit) | panel | code panel |
| Real outcome | (absent; stub traces) | anchor | anchor |
| Signal usefulness | fixed weight constant | bits (measured MI) | bits |
| Core of the corpus | hotspots/clusters (heuristic) | kernel (measured, gated) | kernel |
| Output validation | (absent) | Ward guard | guard |
| Prediction | detect_changes hop-risk | oracle | oracle |
| Audit trail | (absent) | ledger | ledger |
| Auto-tuning | (absent; fixed constants) | anneal | anneal |


---

# 01_VISION.md

# 01 â€” Vision & Thesis

## 1. The problem with every coding MCP today (including codebase-memory-mcp as it stands)

codebase-memory-mcp (CBM) is the best code *decomposer* in the open-source world: 158 languages, type-aware resolution reverse-engineered from nine real language servers, cross-service and cross-repo linking, sub-millisecond graph queries. But its *intelligence layer* is heuristic:

- **Every weight is guessed.** The 11-signal semantic score uses hand-set weights (`w_tfidf=0.20, w_ri=0.25, â€¦`) that are identical for a Haskell compiler and a React storefront. Two of the eleven signals are dead code (`w_dataflow` never applied; graph diffusion implemented but never called).
- **Every threshold is fixed.** `SEMANTICALLY_RELATED â‰¥ 0.75`, `SIMILAR_TO â‰¥ 0.95`, edge confidences pinned at 0.5/0.55/0.75/0.90/0.95 â€” none measured against anything real.
- **Nothing is grounded.** The graph knows *that* `f` calls `g`; it does not know whether that fact ever mattered â€” no connection to test failures, bugs, incidents, or agent success.
- **Nothing is validated.** `detect_changes` maps hop-distance to risk (1 hop = CRITICAL) â€” topology, not evidence. `ingest_traces` is a stub. There is no way to check an answer, reproduce it, or audit how it was formed.
- **Nothing improves.** The system is exactly as smart on day 400 as on day 1, no matter how many bugs, tests, and agent sessions flow past it.

Calyx is the precise complement: an engine whose entire purpose is to take *atoms + all base associations* and produce **measured, grounded, distilled, guarded, predictive, self-improving** intelligence â€” but which has no code-domain front end. CBM **is** that front end, already built, already at Linux-kernel scale.

## 2. The fusion thesis

> **CBM turns a repository into atoms and associations. Calyx turns atoms and associations into intelligence. Wire the output of the first into the input of the second, ground the result in real developer outcomes, and the loop closes: an MCP that gets measurably smarter about *your* codebase every day it is used.**

The Calyx handbook's foundational principle â€” *"atoms â†’ all base associations â†’ differentiate â†’ kernel â†’ compose; never shortcut it"* â€” is satisfied by CBM more completely than by any hand-built ingestion pipeline in any domain:

| Calyx method step | Who does it | With what |
|---|---|---|
| â‘  Decompose to atoms | **CBM** | tree-sitter over 158 langs â†’ Function/Method/Class/Struct/Interface/Enum/Field/Variable/Module/File/Route/Channel/Resource/Package/Macroâ€¦ with signatures, docstrings, ranges, decorators, params |
| â‘¡ Associate at the base | **CBM** | 40+ edge types: CALLS (LSP-resolved), IMPORTS, INHERITS, IMPLEMENTS, USAGE, READS/WRITES, THROWS, USES_TYPE, INSTANTIATES, TESTS, HTTP/ASYNC/GRPC/GRAPHQL/TRPC_CALLS, EMITS/LISTENS_ON, HANDLES, DATA_FLOWS, INFRA_MAPS, CONFIGURES, DEPENDS_ON, FILE_CHANGES_WITH, SIMILAR_TO, SEMANTICALLY_RELATED, CROSS_* |
| â‘¢ Differentiate (bits) | **Calyx Assay** | KSG mutual information about grounded anchors; sufficiency; redundancy; synergy; transfer entropy |
| â‘£ Distill â†’ Compose | **Calyx Lodestar/Ward/Oracle/Sextant/Ledger/Anneal** | kernel, guard, prediction, fused search, provenance, self-optimization |

## 3. The intelligence flywheel (why this compounds)

```
        agent asks â†’ context pack (kernel-ranked, token-budgeted, provenanced)
              â”‚                                              â–²
              â–¼                                              â”‚
        agent edits code â”€â”€â–º guard validates diff            â”‚ anneal re-tunes
              â”‚                (per-slot, calibrated)        â”‚ fusion weights,
              â–¼                                              â”‚ thresholds, Ï„
        CI runs, tests pass/fail, PR reviewed, ships         â”‚
              â”‚                                              â”‚
              â–¼                                              â”‚
        outcomes become ANCHORS (test/CI/review/revert/      â”‚
        incident/agent-task-result) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
              â”‚                                              â”‚
              â–¼                                              â”‚
        Assay re-measures bits; kernel re-distills;          â”‚
        guard re-calibrates; oracle evidence grows â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

Every unit of real work â€” a test run, a review, a revert, an agent task â€” makes the next context pack better ranked, the next guard verdict better calibrated, the next impact prediction better grounded. No other coding-assistant substrate has this property, because no other substrate has (a) anchors, (b) measured bits, and (c) a reversible self-optimizer.

## 4. What changes for an AI agent (before â†’ after)

| Agent need | CBM today | ASTROLABE |
|---|---|---|
| "What context do I need for this task?" | `search_graph` + manual assembly; agent guesses relevance | `get_context_pack(task, token_budget)` â€” kernel-ranked, bits-weighted, recall-gated â‰¥0.95, content-hashed, reproducible |
| "Is my generated code okay?" | Nothing â€” agent self-reviews | `guard_check` â€” per-slot conformal verdict vs. the repo's trusted region, calibrated FAR (e.g. 1â€“5%), accept / new-region / quarantine / refuse |
| "What breaks if I change this?" | `trace_path` BFS + hop-based risk labels | `predict_impact` â€” grounded consequence tree from observed changeâ†’failure history, confidence capped by self-consistency and DPI ceilings |
| "Why did this test fail?" | grep + trace_path, manual | `abduce_cause` â€” reverse walk from the failure anchor, causes ranked n/(n+1) |
| "Which signals matter here?" | Fixed global weights | `measure_bits` â€” per-repo measured bits per lens/feature about real outcomes |
| "Can I trust this answer?" | No | `answer_trace` + `reproduce` + `verify_chain` â€” provenance to the byte |
| "What don't we know?" | No concept | grounding-gap report â€” the unanchored (untested/unverified) regions, named |
| "Is the system ready for questions about X?" | No concept | `get_readiness` â€” falsifiable multi-tier predicate per scope |
| "When will this flaky test bite again?" | No concept | `forecast` â€” cadence + overdue hazard + next-occurrence interval |
| Convention adherence | Instructions file prose | The trusted region *is* the convention, measured; identity-lock on public API |

## 5. What each project contributes, unduplicated

**CBM brings (kept, not rewritten):** tree-sitter extraction engine + 158 grammars; Hybrid LSP (9 families, ~30K lines of resolver + stdlib seed data); discovery/ignore/language detection; git context + watcher; incremental indexing; route/channel/infra/config extraction; cross-repo matching; the 14-tool MCP surface and agent installers (13 agents), hooks, skills; the 3D graph UI; the packaging network (npm/PyPI/Homebrew/Scoop/Winget/AUR/â€¦).

**Calyx brings (kept, not rewritten):** Aster (LSM store, MVCC snapshots/time-travel, column families, crash-safe manifest, WAL, tiering, dedup, erasure); Loom (cross-terms, agreement graph, reactive triggers, recurrence, lead/lag); Assay (KSG MI, sufficiency, redundancy, TC/n_eff, transfer entropy, interaction information, periodicity, CUSUM, MMD, Bayesian posteriors); Lodestar (kernel discovery, kernel index/answer, scopes, label propagation, grounding gaps); Ward (per-slot conformal guard, calibration, novelty routing, drift); Oracle (butterfly, reverse query, honesty gate, completion, time prediction, readiness); Sextant (HNSW/DiskANN/SPANN, BM25, MaxSim, RRF fusion, planner, funnel); Ledger (hash chain, Merkle checkpoints, reproduce); Anneal (shadow-tested reversible tuning, tripwires, lens proposal, mistake closure); Forge (SIMD/GPU math, measured quantization); Registry (frozen lens contracts, capability gate, hot-swap, backfill).

**Removed/replaced (the honest deletions):**
- CBM's fixed 11-signal weights and 0.75/0.95 thresholds â†’ measured bits + annealed fusion (candidate generation via MinHash/LSH is *kept* as a performance primitive).
- CBM's fixed edge-confidence constants â†’ retained as priors, recalibrated per-repo by Assay.
- CBM's hopâ†’risk mapping in `detect_changes` â†’ oracle-grounded impact.
- CBM's `dump_verify` plausibility gate â†’ subsumed by ledger + FSV verification (kept during transition).
- Calyx's Polymarket layer (`calyx-poly`) â†’ not used (but its patterns â€” canonical input bytes, admission gates, FSV readback â€” are the reference implementation style for ASTROLABE's code domain crate).

## 6. Success criteria (measurable, falsifiable)

1. **Token economy:** context packs achieve â‰¥ 0.95 kernel recall on held-out agent queries at â‰¤ 20% of the tokens of naive file dumping (measured on â‰¥ 3 real repos).
2. **Guard quality:** calibrated FAR â‰¤ 5% (content) / â‰¤ 1% (identity slots) on held-out bad cases (mutations + reverted code), FRR low enough that < 20% of accepted-in-history diffs are flagged.
3. **Prediction lift:** `predict_impact` ranks the actually-failing test in the top 5 for â‰¥ 60% of historical bug-fix commits (backtested per repo), beating hop-distance baseline by a measured margin.
4. **Bits over guesses:** per-repo measured signal ranking differs from CBM's fixed weights (demonstrating the fixed weights were leaving intelligence on the table) and fused search wins A/B on recall@10 vs. the legacy path.
5. **Provenance:** 100% of tool answers carry a ledger-backed trace; `reproduce` re-derives context packs bit-for-bit; `verify_chain` intact in CI.
6. **No regressions:** all 14 legacy tools behave compatibly (parity harness), full-index wall-time within 1.3Ã— of baseline CBM, incremental within 1.5Ã—.
7. **Flywheel proof:** after N weeks of anchor accrual on a live repo, context-pack recall and guard calibration measurably improve versus the day-1 snapshot (ledger-verifiable).


---

# 02_CAPABILITY_CATALOG.md

# 02 â€” The Exhaustive Capability Catalog

**Purpose.** Every capability the combined system delivers â€” the "no blind spots" inventory. Each entry names the mechanism (which CBM + Calyx subsystems), the inputs it needs, and the roadmap phase (see 22_ROADMAP) where it lands. Capabilities marked â˜… are impossible in either project alone â€” they are emergent from the fusion.

**Legend.** `[CBM]` = exists in codebase-memory-mcp today. `[CX]` = exists in Calyx today. `[FUSE]` = new glue. Phase = P0â€¦P10.

---

## Tier 1 â€” Decomposition & measurement (the atoms)

| # | Capability | Mechanism | Phase |
|---|---|---|---|
| 1.1 | 158-language symbol extraction (Function/Method/Class/Struct/Interface/Enum/Field/Variable/Module/File/Route/Channel/Resource/Package/Macro/Sectionâ€¦) with signatures, docstrings, ranges, params, decorators | [CBM] tree-sitter engine + lang_specs | P0 (exists) |
| 1.2 | Type-aware call/usage resolution for 9 language families (Go, Py, TS/JS, C/C++, C#, Java, Kotlin, PHP, Rust) â€” imports, generics, inheritance, traits, extension methods, macros | [CBM] Hybrid LSP + stdlib seeds | P0 (exists) |
| 1.3 | Every symbol becomes a **constellation**: one record, ~24 typed slots (structural, semantic, temporal, relational), exact scalars, verbatim metadata, anchors, provenance | [FUSE] libcbm extraction â†’ panel measurement â†’ Aster `put` | P1 |
| 1.4 | Content-addressed idempotent ingestion: identical (project, QN, source) â‡’ identical version id; re-index is a no-op per unchanged symbol | [CX] `CxId::from_input` + Aster dedup; [FUSE] canonical_input_bytes for code | P1 |
| 1.5 | â˜… Version-series identity: QN = stable series, CxId = immutable version; the full edit history of a symbol is a first-class recurrence series | [CX] recurrence CF + MVCC; [FUSE] QNâ†’series registry | P2 |
| 1.6 | Exact scalar preservation alongside vectors: complexity, cognitive, loop depth, param count, LOC, degrees â€” auditable, filterable, never embedded away | [CX] constellation `scalars`; [CBM] metrics already computed | P1 |
| 1.7 | Hot-swappable panel: add a new code lens in one call; new symbols measurable immediately; old symbols lazily backfilled in the background | [CX] Registry SwapController + BackfillScheduler | P3 |
| 1.8 | Lens capability cards & admission gate: every candidate lens profiled (signal/spread/separation/cost/coverage) and Admitted/Parked/Retired per repo by measured value | [CX] Registry profile + capability gate | P5 |
| 1.9 | Deterministic re-measurement: determinism probes require byte-identical repeat output; drift â‡’ new lens id, never silent reuse | [CX] frozen contracts + determinism probe | P1 |
| 1.10 | Multi-modal repo coverage: config (YAML/TOML/INI/dotenv), IaC (Docker/K8s/Kustomize/Helm/Terraform), SQL, Markdown sections, proto/GraphQL schemas â€” all first-class atoms | [CBM] infra/k8s/config extractors | P0 (exists) |

## Tier 2 â€” Associations (the raw material of intelligence)

| # | Capability | Mechanism | Phase |
|---|---|---|---|
| 2.1 | The complete between-record association graph: 40+ typed, directed, weighted edge kinds imported as the Calyx graph CF | [CBM] all passes; [FUSE] edge importer | P2 |
| 2.2 | Within-record cross-terms between slots: agreement / delta / interaction / concat between any two lenses of one symbol | [CX] Loom cross_term | P3 |
| 2.3 | â˜… Doc-drift detector: agreement(doc_embedding, code_embedding) per symbol â€” low agreement = documentation lies about the code | [FUSE] Loom agreement on S_doc Ã— S_code | P3 |
| 2.4 | â˜… Name-truth detector: agreement(name_semantic, api_signature/body_semantic) â€” misleading identifiers surfaced, ranked | [FUSE] cross-term | P3 |
| 2.5 | Agreement graph over lenses: which signals co-vary in this repo (the redundancy map, feeds effective-rank) | [CX] Loom agreement_graph | P3 |
| 2.6 | Between-record kNN graph per slot: "structurally similar", "semantically similar", "API-similar", "co-changed" as separate, queryable graphs | [CX] Sextant per-slot indexes; [CBM] MinHash/LSH candidates | P3 |
| 2.7 | Temporal lead/lag between symbol change-series: `median(t_b âˆ’ t_a)` â€” "changes to A precede changes to B by ~2 days" (directional co-change, beyond CBM's symmetric FILE_CHANGES_WITH) | [CX] Loom temporal cross-terms; [CBM] git history | P4 |
| 2.8 | Derived-data abundance accounting: honest `N + C(N,2) + 1` signal reports with n_eff and DPI ceiling â€” never oversell derived signal | [CX] Loom abundance | P3 |
| 2.9 | Materialization policy at scale: agreement eager; interaction eager only when pair-gain â‰¥ 0.05 bits; delta/concat lazy + LRU | [CX] Loom materialization + Assay pair-gain gate | P3/P5 |
| 2.10 | Cross-service linking: HTTP/gRPC/GraphQL/tRPC/queue/topic route rendezvous, DATA_FLOWS callerâ†’handler | [CBM] route nodes + service patterns | P0 (exists) |
| 2.11 | Cross-repo association: Routes/Channels matched across separately-indexed repos (CROSS_* edges), imported into per-repo vaults with cross-vault bridge chains | [CBM] pass_cross_repo; [CX] lodestar cross-vault chains | P2/P8 |
| 2.12 | Blind-spot detection: symbols where one lens is confident while neighbors disagree beyond threshold â€” "this looks like X structurally but nothing like X semantically" | [CX] Loom blind_spot; calibrated per lens pair | P5 |

## Tier 3 â€” Grounding (anchors: what makes it real)

| # | Capability | Mechanism | Phase |
|---|---|---|---|
| 3.1 | â˜… Test-outcome anchors: per-symbol TestPass anchors from CI/test-runner ingestion, linked through TESTS edges | [FUSE] anchor pipeline; [CBM] TESTS edges | P4 |
| 3.2 | â˜… Bug archaeology anchors (SZZ): fix-commits identified (message heuristics + issue links); blamed symbols anchored `bug_touch` (provisional, confidence < 1) | [FUSE] git mining; [CBM] gitdiff parsers | P4 |
| 3.3 | Revert anchors: reverted commits anchor their symbols as rejected outcomes, confidence 1.0 | [FUSE] git mining | P4 |
| 3.4 | â˜… Runtime-trace anchors: OTLP spans confirm HTTP_CALLS/DATA_FLOWS edges (completing CBM's stubbed `ingest_traces`); confirmed edges promoted Provisionalâ†’Trusted with latency evidence | [CBM] traces.c helpers (exist, unused!); [FUSE] wire to anchor+edge promotion | P4 |
| 3.5 | â˜… Agent-task anchors: every agent session outcome (task succeeded/failed/abandoned, tests-after-change) anchored to the symbols in its context pack â€” the flywheel input | [FUSE] new `anchor_outcome` tool + hooks | P4 |
| 3.6 | Review anchors: PR approve / request-changes / comment density as Thumbs anchors on touched symbols | [FUSE] optional GH ingestion | P6 |
| 3.7 | Incident anchors: postmortem/alert ingestion marks implicated symbols/routes | [FUSE] optional ingestion | P6 |
| 3.8 | Survival anchors (weak, provisional-only): symbol unchanged N months under passing CI = weak positive; never "trusted" | [FUSE] policy in anchor pipeline | P4 |
| 3.9 | Trust lifecycle: every anchor is Provisional until a resolved, confidence-1.0 source confirms; roll-ups Trusted only if all constituents trusted (Poly's grounding.rs pattern) | [CX] TrustTag discipline | P4 |
| 3.10 | Flakiness handling: per-test self-consistency measured from recurrence (pairwise agreement of outcomes); flaky anchors cap downstream confidence instead of poisoning it | [CX] oracle self-consistency ceiling | P6 |
| 3.11 | Cold-start honesty: zero-anchor repos run in explicit provisional mode (cold-start guard); all bits/kernels labeled provisional until â‰¥1 grounded anchor | [CX] cold_start guard | P4 |

## Tier 4 â€” Differentiation (measured intelligence, in bits)

| # | Capability | Mechanism | Phase |
|---|---|---|---|
| 4.1 | â˜… Bits per signal per repo: how much does complexity/churn/semantic-similarity/graph-position *actually* predict test failure / bugginess *in this repo* â€” KSG MI, base-2, CI'd, sample floor 50 | [CX] Assay ksg_mi | P5 |
| 4.2 | â˜… Per-repo signal ranking replaces global fixed weights: the 11 CBM semantic signals + all panel lenses ranked by measured bits; dead weight parked automatically | [CX] Assay + capability gate | P5 |
| 4.3 | Panel sufficiency: `I(panel; outcome) â‰¥ H(outcome)`? If not, the deficit names which lens is short and by how many bits â€” a concrete to-do list for instrumentation | [CX] Assay sufficiency + deficit routing | P5 |
| 4.4 | Redundancy pruning: pairwise MI/correlation among lenses; total correlation; effective rank n_eff â€” "you have 24 lenses but only 9 independent ones" | [CX] Assay TC/n_eff | P5 |
| 4.5 | Synergy discovery (interaction information): signal *pairs* that predict outcomes when neither does alone (e.g. complexity Ã— churn â†’ defects) | [CX] Assay interaction information | P5 |
| 4.6 | â˜… Directed change causality (transfer entropy): which module's changes *drive* changes/failures elsewhere, with lag sweep â€” correlation becomes an arrow | [CX] Assay transfer_entropy; [CBM] git series | P5 |
| 4.7 | Marginal value per lens: bits lost if removed â€” objective grounds for retiring instrumentation | [CX] Assay marginal_value | P5 |
| 4.8 | Stratified admission: a globally-weak lens kept if it is the sole carrier of a rare-but-critical stratum (e.g. the only signal that fires on security-sensitive code) | [CX] Assay stratified override | P5 |
| 4.9 | Periodicity detection on event series: Lombâ€“Scargle + autocorrelation + permutation FAP â€” release cadences, weekly failure rhythms | [CX] Assay periodicity | P6 |
| 4.10 | Change-point & overdue hazard: CUSUM rate shifts ("this module's churn regime changed at commit X"), renewal hazard ("this flaky test is overdue") | [CX] Assay recurrence_hazard | P6 |
| 4.11 | Distribution drift alarms: kernel MMD two-sample tests per slot ("the code being written this month is OOD vs. the codebase") | [CX] Assay mmd | P6 |
| 4.12 | Small-sample honesty: Gamma-Poisson / Beta-Bernoulli posteriors with credible intervals when history is thin | [CX] Assay bayesian | P5 |
| 4.13 | DPI ceiling enforcement: derived C(N,2) signal is never claimed beyond I(panel;outcome) â€” structurally impossible to oversell | [CX] Assay dpi_ceiling | P5 |

## Tier 5 â€” The kernel (distillation & context)

| # | Capability | Mechanism | Phase |
|---|---|---|---|
| 5.1 | â˜… The codebase kernel: the ~1% of symbols (approx. feedback-vertex-set over the association graph, scored 0.40Â·degree + 0.40Â·betweenness + 0.20Â·groundedness) from which the corpus is reconstructable â€” the measured "load-bearing core" | [CX] Lodestar pipeline (proven at 199K nodes / 2.44M edges) | P6 |
| 5.2 | Kernel recall gate: held-out queries must reach â‰¥ 0.95 recall through the kernel index or the kernel is refined â€” a *proof* the core explains the repo | [CX] kernel_recall_test + refine | P6 |
| 5.3 | Kernel at any scope: per-directory, per-package, per-domain (anchor kind), per-subgraph (radius around a symbol), per-time-window; union/intersect scopes; cached with invalidation | [CX] Lodestar scopes + scope cache | P6 |
| 5.4 | Hierarchical kernels for monorepos: region graph (packages) â†’ kernel of regions â†’ drill-down kernels | [CX] Lodestar hierarchical | P8 |
| 5.5 | â˜… Token-budgeted context packs: given (task, budget) â†’ fused-search seeds â†’ kernel answer-path coverage â†’ greedy bits-weighted selection â†’ manifest with content hashes + provenance; reproducible bit-for-bit | [FUSE] pack composer over kernel+sextant+ledger | P6 |
| 5.6 | Kernel answers: grounded Q&A over the codebase â€” answer paths walk association edges from anchored kernel nodes, `hop_score = weight Â· 0.9^hop`, every hop ledger-referenced | [CX] kernel_answer_with_ledger | P6 |
| 5.7 | Grounding-gap report: the regions of the codebase with no anchors within reach â€” the "here be dragons" map (untested / unverified territory), actionable | [CX] grounding_gaps | P6 |
| 5.8 | â˜… Kernel-based onboarding: "explain this repo" = the kernel + its agreement structure + ADR, sized to a token budget â€” measured, not curated | [FUSE] context pack preset | P6 |
| 5.9 | Label propagation: grounded labels (e.g. "security-sensitive", "deprecated") harmonically extended over the association graph with decayed confidence | [CX] lodestar label_propagation | P7 |
| 5.10 | Universal summarization: any scope â†’ its kernel = its structural summary, with recall + grounded fraction attached | [CX] lodestar summarize | P7 |
| 5.11 | Cross-domain bridges: symbols that ground two scopes at once (the shared core of frontend+backend, or repo A + repo B) | [CX] lodestar bridges | P8 |
| 5.12 | Dead-code & hotspot analysis upgraded: CBM's per-node status enriched with kernel membership + measured bits ("dead but load-bearing in the kernel" vs. "alive but explains nothing") | [FUSE] | P6 |

## Tier 6 â€” The guard (validating generated code)

| # | Capability | Mechanism | Phase |
|---|---|---|---|
| 6.1 | â˜… Guarded generation: an agent's proposed diff is measured through the panel and checked per-slot (semantic, structural, API-usage, naming, doc-style) against the repo's trusted region â€” accept / new-region / quarantine / refuse, never a flattened average | [CX] Ward guard (A3 no-flatten) | P7 |
| 6.2 | Conformal calibration: per-slot Ï„ set so empirical false-accept â‰¤ target (identity 0.01 / content 0.03 / style 0.05) with a binomial confidence bound; requires â‰¥50 real bad cases | [CX] Ward calibrate | P7 |
| 6.3 | â˜… Principled bad-case generation: mutation testing (cargo-mutants-style) + reverted commits + cross-repo alien code + known-vuln patterns = the calibration "bad" corpus; survived HEAD code = "good" | [FUSE] calibration data pipeline | P7 |
| 6.4 | The trusted region *is* the convention: style/naming/API-usage conformance measured against the repo itself â€” no config files, no linter rules to write | [CX] Ward + panel | P7 |
| 6.5 | Identity-lock: exported/public API symbols identity-locked; generated changes that drift a locked signature/behavior slot are refused (canonical entities can't drift) | [CX] Ward identity | P7 |
| 6.6 | New-region learning: novel-but-valid code routes to "new region" (quarantine list + acknowledgment flow) instead of silent acceptance or false rejection | [CX] Ward novelty routing | P7 |
| 6.7 | Injection & supply-chain screening: new dependencies' code checked OOD vs. its claimed purpose; prompt-injection-shaped content in docstrings/comments flagged | [CX] Ward + [FUSE] dependency scan | P8 |
| 6.8 | Drift monitoring: rolling per-slot rejection rates vs. calibrated FAR bound (1.5Ã— multiplier) â€” alerts when the repo's distribution shifts and recalibration is due, feeding Anneal | [CX] Ward drift â†’ Anneal hook | P7 |
| 6.9 | Commit OOD alarm: every incoming commit (human or agent) optionally scored; wildly-OOD commits for their area surfaced in review | [FUSE] watcher hook â†’ guard | P7 |
| 6.10 | Guard verdict provenance: every verdict ledgered with per-slot cos/Ï„ breakdown â€” auditably explain *why* code was refused | [CX] Ward ledger writers | P7 |

## Tier 7 â€” The oracle (prediction, causality, honesty)

| # | Capability | Mechanism | Phase |
|---|---|---|---|
| 7.1 | â˜… Change-impact prediction: "if I change X" â†’ grounded consequence tree over calls/data-flow/co-change edges seeded by observed changeâ†’outcome history; depth â‰¤4, per-hop Ã—0.7 attenuation, prune <0.05 | [CX] oracle butterfly; [FUSE] evidence mining | P7 |
| 7.2 | â˜… Root-cause abduction: failing test / incident â†’ reverse walk (depth â‰¤3) to ranked causes, grounded confidence n/(n+1); structural causes marked provisional | [CX] oracle reverse_query | P7 |
| 7.3 | â˜… The honesty gate: any prediction/answer is refused with a per-lens deficit when `panel_bits < H(outcome)` â€” the MCP that says "I don't know, and here is exactly what data would fix that" | [CX] oracle honesty gate | P7 |
| 7.4 | Confidence ceilings everywhere: `min(raw, self-consistency, DPI)` â€” flaky evidence and information-theoretic limits cap every confidence; never reaches 1.0 | [CX] oracle ceiling (Poly forecast_ceiling pattern) | P7 |
| 7.5 | Imputation / completion: fill missing metadata (types for dynamic code, missing docstrings, unresolved callees) by energy descent from trusted-region attractors; every filled value tagged inferred/provisional | [CX] oracle complete | P8 |
| 7.6 | Flaky-test forecasting: next-occurrence time (median cadence + MAD interval), overdue hazard, periodicity fit per test | [CX] oracle time_prediction + assay hazard | P7 |
| 7.7 | Test-selection oracle: given a diff, the minimal test set with grounded failure-probability ranking (impact tree âˆ© TESTS edges) | [FUSE] | P7 |
| 7.8 | Readiness predicate: per scope, the falsifiable conjunction â€” oracle-clean â‰¥0.7, panel sufficient, kernel recall â‰¥0.95, calibrated, Goodhart-defended, mistakes closed â€” "is ASTROLABE ready to be trusted on this subsystem?" | [CX] super_intelligence predicate | P8 |
| 7.9 | What-if on architecture: consequence trees over INFRA_MAPS/DATA_FLOWS ("if this service's route changes, which consumers break, with what confidence") including cross-repo | P8 |
| 7.10 | Reviewer routing: abduction + ownership lens â†’ who has grounded history with the implicated region | [FUSE] | P10 |

## Tier 8 â€” Search & navigation (unified, fused, guarded)

| # | Capability | Mechanism | Phase |
|---|---|---|---|
| 8.1 | Multi-lens fused search: one query â†’ per-slot searches (BM25 identifiers, dense semantic, structural, API-signature, MaxSim tokens) â†’ RRF (K=60) fusion; deterministic intent classifier + planner caps | [CX] Sextant | P6 |
| 8.2 | Per-lens neighbors: "similar by structure" / "by meaning" / "by API usage" / "by co-change" as distinct queries; agree (all lenses concur) & disagree (max spread = anomaly) | [CX] sextant navigation/consensus | P6 |
| 8.3 | Clone taxonomy: structural-only similar = copy-paste; semantic-only = reimplementation; both = true clone; each actionable differently | [FUSE] agree/disagree over S_struct Ã— S_sem | P6 |
| 8.4 | Guarded search: results filtered to the trusted region (in-region-only mode) with dropped-hit accounting â€” for high-stakes retrieval | [CX] sextant guarded | P7 |
| 8.5 | `define`: the grounded definition of a symbol assembled from its association neighborhood, not just its source text | [CX] sextant define | P6 |
| 8.6 | Association traversal: weighted best-first walks with hop attenuation Ã—0.9, directional (forward/backward/both), replacing plain BFS with scored reach | [CX] paths reach_scored; upgrade of trace_path | P6 |
| 8.7 | Temporal boosts: recently-changed / periodically-relevant code nudged post-retrieval, bounded (never dominant, AP-60) | [CX] sextant temporal | P6 |
| 8.8 | Skills discovery: HDBSCAN clustering of constellations into a named capability tree; search-within-skill | [CX] sextant skills | P8 |
| 8.9 | Kernel-first funnel for giant monorepos: probe kernel â†’ expand regions â†’ search within regions (sublinear) | [CX] sextant funnel | P8 |
| 8.10 | Cypher queries retained: the existing read-only Cypher engine keeps working against the lowered SQLite artifact (zero breakage), plus as_of time-travel parameter via MVCC snapshots | [CBM] cypher; [CX] MVCC | P2/P6 |
| 8.11 | Reranking hook: optional cross-encoder reranker lens (TEI :8089-style) for pipeline fusion, request-scoped, never persisted | [CX] sextant reranker | P8 |
| 8.12 | grep stays grep: `search_code` (text search over indexed files) retained untouched â€” raw text is raw | [CBM] | P0 (exists) |

## Tier 9 â€” Provenance, trust & audit

| # | Capability | Mechanism | Phase |
|---|---|---|---|
| 9.1 | Hash-chained ledger of every mutation: index runs, anchor attachments, assay results, kernel builds, guard verdicts, answers, anneal changes â€” each entry seals the previous (BLAKE3), Merkle checkpoints every 1000, optional Ed25519 signing | [CX] Ledger | P2 |
| 9.2 | `answer_trace`: how any answer/pack was formed â€” the kernel entry, the hops, the fusion weights, the guard verdict, freshness; incomplete lineage yields explicit `unprovenanced` warnings, never fabricated links | [CX] ledger audit | P6 |
| 9.3 | `reproduce`: re-derive any recorded answer with frozen lenses + recorded seeds; drift bound 1e-3; the regression detector for the intelligence layer | [CX] ledger reproduce | P6 |
| 9.4 | `verify_chain`: tamper-evidence for the whole graph â€” run in CI; a broken chain quarantines the range and fails closed | [CX] ledger verify | P2 |
| 9.5 | â˜… Inter-agent trust: agent B can verify the provenance of context agent A claimed â€” multi-agent workflows with checkable citations | [FUSE] | P6 |
| 9.6 | Erasure with tombstones: lawful deletion (proprietary code removal) recorded as append-only erasure tombstones; redaction policies keep secrets out of the ledger (hashes only) | [CX] ledger tombstone + redaction; [CBM] secret filters | P8 |
| 9.7 | Time-travel audit: MVCC as_of reads â€” "what did the graph believe about this symbol on date X" | [CX] Aster timetravel | P6 |
| 9.8 | Team-shared trusted artifact: the `.codebase-memory/graph.db.zst` team artifact extended with chain-verified vault export â€” pull a colleague's index *and prove it untampered* | [CBM] artifact; [CX] merkle export | P8 |

## Tier 10 â€” Self-optimization (the system that improves)

| # | Capability | Mechanism | Phase |
|---|---|---|---|
| 10.1 | Per-repo annealed fusion weights: RRF profile weights tuned on held-out replay of *real agent queries*, shadow-tested, promoted only on non-regression, reversible one-swap rollback | [CX] Anneal tune | P8 |
| 10.2 | Tripwired safety: recall@k <0.90, guard FAR >0.01, FRR >0.05, search p99 >200ms, ingest p95 >500ms â€” any crossing auto-reverts the change (5% hysteresis) | [CX] Anneal tripwires | P8 |
| 10.3 | Deficit-driven lens proposal: sufficiency gaps automatically synthesize candidate lenses (new derived metrics, new hashed-set encoders, new cross-field interactions), gate-checked (â‰¥0.05 bits, â‰¤0.6 corr), hot-added on win | [CX] Anneal propose | P8 |
| 10.4 | Threshold calibration loop: SIMILAR_TO/SEMANTICALLY_RELATED admission, guard Ï„, edge-confidence floors â€” all recalibrated on drift alarms | [CX] Anneal heal/recalibrate | P8 |
| 10.5 | Mistake closure: wrong predictions/answers recorded, replay-buffered (surprise-prioritized), online heads updated with no-regression assertion â€” "wrong only once" | [CX] Anneal learn | P9 |
| 10.6 | Measured quantization: embedding slots compressed (4-bit/3.5-bit) only while recall/bits/FAR hold; fails closed to raw on intelligence loss | [CX] Forge quant + registry compression | P8 |
| 10.7 | Goodhart defense: gaming detection on the objective (g(Ï„) â‰¥ 0.95, cross-lens dominance â‰¤ 0.8) before any promotion | [CX] Anneal j/goodhart | P9 |
| 10.8 | Janitor & budgets: background optimization strictly budgeted (CPU fraction, VRAM cap, cooperative ticks) â€” never starves serving | [CX] Anneal budget | P8 |

## Tier 11 â€” Operations, lifecycle & ecosystem

| # | Capability | Mechanism | Phase |
|---|---|---|---|
| 11.1 | Incremental everything: file change â†’ re-extract changed files only â†’ new constellation versions â†’ dirty-region re-weave â†’ reactive triggers â†’ scoped invalidation (assay rows by panel version, kernel by dirty SCC) | [CBM] incremental pipeline; [CX] MVCC/reactive/incremental kernel | P3 |
| 11.2 | Watcher â†’ reactive engine: git polling (adaptive 5â€“60s) feeds bounded, audited triggers â€” new-region / recurs / drift â€” with subscriptions | [CBM] watcher; [CX] loom reactive | P3 |
| 11.3 | Crash-isolated indexing preserved: the supervised worker-subprocess model (crash/hang containment, quarantine of culprit files, RSS return) wraps the combined pipeline | [CBM] index_supervisor | P1 |
| 11.4 | 13-agent installer network preserved: Claude Code, Codex, Gemini, Cursor, Zed, VS Code, etc. â€” config, skills, hooks, instructions â€” updated for the new tool surface | [CBM] cli installer | P6 |
| 11.5 | Hooks upgraded: PreToolUse Grep/Glob augmenter returns kernel-ranked hits + hazard notes; optional PostToolUse Edit/Write advisory guard check; SessionStart injects readiness + kernel summary + ADR | [CBM] hook_augment; [FUSE] | P7 |
| 11.6 | 3D graph UI upgraded: kernel membership as size/glow, trust/provenance colors, grounding-gap overlay, agreement-graph view, satellite galaxies for cross-repo (existing) | [CBM] graph-ui | P10 |
| 11.7 | ADR grounded: the Architecture Decision Record becomes anchored â€” decisions link to the kernel members they govern; drift between ADR text and measured architecture flagged | [CBM] manage_adr; [FUSE] | P8 |
| 11.8 | Full CLI parity: every MCP tool invokable as `astrolabe cli <tool> '<json>'`; progress sink; `--json` | [CBM] cli runner | P6 |
| 11.9 | Memory discipline preserved: RAM-first with budgets (mimalloc RSS tracking, retention caps, backpressure naps) + Calyx bounded allocators/caches â€” one allocator, one budget | [CBM] mem.c; [CX] alloc/cache; unified | P1 |
| 11.10 | Diagnostics & health: NDJSON trajectory + Prometheus-style metrics + chain-verify gauge + readiness â€” one health surface | [CBM] diagnostics; [CX] daemon metrics patterns | P9 |

## Tier 12 â€” Emergent / moonshot (possible once Tiers 1â€“10 exist)

| # | Capability | Mechanism | Phase |
|---|---|---|---|
| 12.1 | â˜… The org-wide code brain: hierarchical kernel over all repos; cross-repo transfer entropy ("api-gateway changes drive checkout-service failures 3 days later"); org grounding-gap map | Lodestar hierarchical + cross-vault + Assay | P10 |
| 12.2 | â˜… Autonomy dial: agents earn autonomy per-scope from the readiness predicate + guard calibration â€” "auto-merge allowed where readiness=green and guard FAR<1%" | readiness + guard + policy | P10 |
| 12.3 | â˜… Grounded refactoring advisor: disagree-clones + synergy analysis + kernel membership â†’ ranked refactor candidates with predicted blast radius and grounded payoff | Tiers 4+5+7 composed | P10 |
| 12.4 | â˜… Self-healing docs: doc-drift detector (2.3) + imputation (7.5) â†’ proposed docstring updates, guard-checked, provenance-attached | Tiers 2+6+7 | P10 |
| 12.5 | â˜… Historical counterfactuals: time-travel + oracle â€” "would this bug have been predicted by the panel as of the commit before it shipped?" (the honest self-evaluation loop) | MVCC + oracle backtest (Poly backtest.rs pattern) | P10 |
| 12.6 | â˜… Security posture from associations: label-propagated sensitivity + guard OOD + supply-chain screening + injection lenses = measured attack-surface map | Tiers 5.9+6.7 | P10 |
| 12.7 | â˜… Benchmark-grade honest evals: backtesting harness (held-outåŽ†å² commits) proving context-pack/impact-prediction lift, admission-gated like Poly's `beats_market` rule: the system must beat the naive baseline or it says so | Poly backtest pattern | P9 |

---

## Coverage cross-check (nothing left behind)

**Every CBM subsystem mapped:** extraction engine â†’ Tier 1; LSP â†’ 1.2; registry/resolution â†’ edges (2.1) + priors (8.x); pipeline passes â†’ 1.x/2.x; semantic/simhash â†’ 2.6/8.3 (candidates) + 4.2 (measured); store â†’ lowered artifact (18); cypher â†’ 8.10; MCP server â†’ 15; supervisor â†’ 11.3; watcher/git â†’ 11.2/3.2; discovery â†’ 1.10; CLI/installer/hooks â†’ 11.4/11.5; UI â†’ 11.6; traces â†’ 3.4; ADR â†’ 11.7; artifact â†’ 9.8; foundation â†’ 11.9/19.

**Every Calyx crate mapped:** core â†’ identity/data model (04); aster â†’ storage (03) + time-travel (9.7); ledger â†’ Tier 9; forge â†’ 10.6 + math; registry â†’ 1.7â€“1.9; sextant â†’ Tier 8; search â†’ 12; loom â†’ Tier 2; assay â†’ Tier 4; lodestar â†’ Tier 5; ward â†’ Tier 6; oracle â†’ Tier 7; anneal â†’ Tier 10; paths/mincut â†’ 8.6/kernel; testkit/hazard-soak â†’ 20; buildinfo/fsv â†’ 19/20; calyxd patterns â†’ 11.10; calyx-poly â†’ not integrated, used as the reference pattern for admission gates, canonical bytes, FSV readback, backtesting (12.7).


---

# 03_ARCHITECTURE.md

# 03 â€” System Architecture

## 1. Architecture decision: Rust host, C engine

Three options were evaluated:

| Option | Shape | Verdict |
|---|---|---|
| A. C host + `libcalyx` bridge | Keep CBM's binary; expose Calyx via a hand-written C ABI staticlib | Fastest first demo, but every Calyx feature (traits, MVCC handles, iterators, scoped kernels, lens registry) needs bespoke FFI plumbing; Rust panics across FFI; the surface grows unboundedly. Caps maximum extraction. **Rejected as target** (acceptable as an interim expedient â€” not needed given Option B's cheap on-ramp). |
| B. **Rust host + `libcbm` engine** | New Rust binary embeds Calyx crates natively; CBM's extraction/pipeline/tools linked as a static C library | Full native access to Calyx (the whole point: *maximum* extraction). CBM's C API is already designed for embedding (`internal/cbm/cbm.h` was built for CGo). One killer detail makes migration cheap: **`cbm_mcp_handle_tool(srv, tool, args_json)` is a single C entry point that executes any of the 14 existing tools and returns JSON** â€” the Rust host exposes all legacy tools through one FFI function on day one. **Chosen.** |
| C. Two processes (sidecar/IPC) | calyxd + cbm talking over loopback | Violates both projects' single-binary doctrine, adds latency/ops surface, splits the source of truth. **Rejected.** |

Decision **D1**: Option B. Decision **D2** (de-risking): Phase A needs *zero FFI* â€” the Rust host shells out to the unmodified `codebase-memory-mcp` binary (`cli index_repository`), then imports the resulting SQLite `.db` into the vault (Calyx already ships a SQLite importer pattern: `calyx migrate`). FFI linking begins in Phase B for streaming and tool pass-through. See 18 & 19.

## 2. Process model

One binary, `astrolabe`, four modes (mirroring CBM's dispatch):

```
astrolabe                      # MCP stdio server (default) â€” JSON-RPC 2.0, stdout=protocol, stderr=logs
astrolabe cli <tool> '<json>'  # one-shot tool invocation (parity with CBM cli)
astrolabe install|uninstall|update|config â€¦   # agent installer network (inherited)
astrolabe --ui=true --port=N   # embedded graph UI thread (inherited, UI variant)
```

Threads inside the server process:

| Thread | Origin | Role |
|---|---|---|
| Main MCP loop | CBM pattern | single-threaded JSON-RPC serving; per-project store cache; idle eviction |
| Indexing (supervised subprocess) | CBM `index_supervisor` | `astrolabe cli --index-worker â€¦` child; crash/hang containment; quarantine; RSS return via `_Exit` |
| Worker pool (inside indexer) | CBM `worker_pool` | parallel extraction/resolution, 8 MB stacks, atomic work-stealing |
| Watcher | CBM `watcher` | git polling 5sâ†’60s adaptive; routes re-index through the supervisor; feeds **reactive triggers** |
| Background intelligence lane | Calyx `anneal` budget | assay batches, kernel rebuilds, calibration, anneal ticks â€” strictly budgeted (default 15% CPU), cooperative ticks, never starves serving |
| Reactive dispatcher | Calyx `loom::reactive` | bounded trigger queue (4096), audited, subscriptions |
| Ledger verify loop | calyxd pattern | periodic `verify_chain` + health surface |
| HTTP UI (optional) | CBM `ui` | localhost-only graph UI; reads vault via lowered artifact + new provenance endpoints |
| Parent-death watchdog | CBM | `getppid` poll; orphan cleanup |

Multiple MCP server processes may exist for one repo because users routinely run
several agents at once. At the pinned Calyx revision, Aster durable vaults allow
concurrent open; write commits are serialized by the per-vault OS file lock
`locks/durable.commit.lock`, and recurrence writes use
`locks/recurrence.write.lock`. Shadow-stage Astrolabe therefore permits every
process to keep serving legacy tools from SQLite while vault imports serialize
through Aster's durable commit lock. Shadow-stage vault-backed background lane
activation is gated by a per-project `.astrolabe-background-lane.lock`: exactly
one process is elected owner, followers report `stale_ok`/`provisional` with
remediation, and watcher/anneal workers remain explicitly inactive until those
lanes are enabled.

## 3. Storage architecture (D3)

**Aster vault = source of truth. SQLite `.db` = lowered, regenerable artifact.**

```
~/.cache/astrolabe/
  <project>.vault/                 â† Aster vault (SOURCE OF TRUTH)
    cf/ base|slot_NN|anchors|xterm|graph|ledger|assay|kernel|guard|recurrence|reactive|anneal_*/â€¦
    wal/  manifest-*.json  CURRENT  idx/ (HNSW/kernel indexes)
  <project>.db                     â† LOWERED SQLite artifact (regenerable):
                                     the exact CBM schema (nodes/edges/FTS5/node_vectors),
                                     regenerated after each index/weave; serves the Cypher
                                     engine, the legacy tool paths during migration, and the UI
  _config.db                       â† runtime settings (inherited)
  config.json                      â† UI settings (inherited)
<repo>/.codebase-memory/
  graph.db.zst                     â† team artifact (inherited; later: + chain-verified vault export)
```

Why this split is doctrine-clean: Calyx's "single source of truth / no side store" rule is satisfied because the SQLite file is not a *store* â€” it is **lowered intelligence** (Calyx handbook Â§recipe 7: freeze needed intelligence into fingerprinted, reproducible artifacts for deterministic consumers). The Cypher engine and 3D UI are exactly such consumers. The artifact carries the vault's ledger head hash + content fingerprint in `projects`-adjacent metadata so staleness is detectable. Storage-tier classification:

| Tier | Contents |
|---|---|
| Sacred | WAL, ledger CF, base + slot CFs (constellations), anchors, manifest, recurrence series |
| Regenerable | ANN indexes, kernel/guard artifacts, assay rows, xterm CF, **the entire SQLite .db**, FTS index, team artifact |
| Ephemeral | memtables, caches, per-file arenas, extraction result cache |

## 4. Component architecture

```
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  astrolabe-server (Rust)                                               â”‚
â”‚  MCP JSON-RPC loop Â· tool registry (~30 tools) Â· CLI Â· installer glue  â”‚
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚  DECOMPOSER (C, libcbm)  â”‚  INTELLIGENCE (Rust, Calyx crates)          â”‚
â”‚  Â· discovery/ignore/lang â”‚  Â· astrolabe-panel   (code lenses)          â”‚
â”‚  Â· tree-sitter Ã—158      â”‚  Â· astrolabe-ingest  (constellation builder)â”‚
â”‚  Â· Hybrid LSP Ã—9         â”‚  Â· astrolabe-anchors (grounding pipelines)  â”‚
â”‚  Â· pipeline passes       â”‚  Â· astrolabe-weave   (edge import + Loom)   â”‚
â”‚  Â· registry resolution   â”‚  Â· astrolabe-assay   (measurement jobs)     â”‚
â”‚  Â· route/channel/infra   â”‚  Â· astrolabe-kernel  (kernel + packs)       â”‚
â”‚  Â· git history/diff      â”‚  Â· astrolabe-guard   (calibration + checks) â”‚
â”‚  Â· MinHash/AST profile   â”‚  Â· astrolabe-oracle  (impact/abduce/impute) â”‚
â”‚  Â· legacy tool handlers  â”‚  Â· astrolabe-lower   (SQLite artifact gen)  â”‚
â”‚    (via cbm_mcp_handle_  â”‚  â”€â”€ native deps: calyx-{core,aster,ledger,  â”‚
â”‚     tool FFI)            â”‚     loom,assay,lodestar,ward,oracle,sextant,â”‚
â”‚                          â”‚     search,registry,anneal,forge,paths,     â”‚
â”‚                          â”‚     mincut,buildinfo,fsv,testkit}           â”‚
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚  FOUNDATION: mimalloc (unified allocator) Â· worker pool Â· logging      â”‚
â”‚  (stderr, structured) Â· limits/budgets Â· subprocess supervisor         â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

New Rust crates (workspace `astrolabe/`):

| Crate | Responsibility | Key deps |
|---|---|---|
| `cbm-sys` | bindgen over `cbm.h`, `pipeline.h`, `mcp.h`, `store.h` (subset); links `libcbm.a` | cc/bindgen |
| `astrolabe-bridge` | safe wrappers: `ExtractedFile`, `CbmToolRunner` (wraps `cbm_mcp_handle_tool`), panic/error mapping to `{code,message,remediation}` | cbm-sys |
| `astrolabe-domain` | the code data model: `SymbolRecord`, canonical input bytes, QN series registry, label/edge vocabularies (mirrors `calyx-poly/src/model.rs` style) | calyx-core |
| `astrolabe-panel` | lens implementations + frozen seed registry + panel versions (mirrors `calyx-poly/src/lenses.rs`, `seed_registry.rs`, `encode.rs`) | calyx-core, calyx-registry |
| `astrolabe-ingest` | SQLite importer (Phase A) / streaming FFI consumer (Phase B) â†’ constellations into Aster; idempotency; recurrence linking | calyx-aster, rusqlite |
| `astrolabe-anchors` | test/CI/git/trace/agent anchor ingestion; SZZ mining; trust lifecycle | calyx-core, calyx-ledger |
| `astrolabe-weave` | edge import to graph CF; cross-terms; agreement graph; kNN graphs; lead/lag | calyx-loom, calyx-aster |
| `astrolabe-assay` | measurement job scheduler (sampling, budgets); sufficiency reports; signal ranking | calyx-assay |
| `astrolabe-kernel` | kernel builds (scoped/hierarchical); recall gating; context-pack composer; grounding gaps | calyx-lodestar, calyx-sextant |
| `astrolabe-guard` | calibration corpus builder (mutations/reverts/alien); guard profiles; diff checking | calyx-ward |
| `astrolabe-oracle` | evidence mining (changeâ†’outcome); impact/abduction/imputation/forecast tools; readiness | calyx-oracle |
| `astrolabe-lower` | vault â†’ SQLite artifact regeneration (CBM schema-exact); team artifact export | rusqlite, calyx-ledger |
| `astrolabe-server` | MCP loop, tool registry, CLI, config, watcher wiring, supervisor | all above |

## 5. Data flow â€” full index

```
repo â”€â”€discoverâ”€â”€â–º files â”€â”€parallel extract (libcbm)â”€â”€â–º CBMFileResult*
                                                          â”‚ defs/calls/imports/usages/rw/throws/
                                                          â”‚ type_refs/channels/routes/fp/sp/â€¦
      â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
      â–¼
  [C side] registry build â†’ resolve (LSP+registry) â†’ routes/infra/tests/git passes
      â”‚                        (unchanged CBM pipeline, in supervised worker)
      â–¼
  graph buffer â”€â”€(Phase A: SQLite dump â†’ import)â”€â”€â–º astrolabe-ingest
               â”€â”€(Phase B: streaming FFI callback)â”€â”€â–º
      â–¼
  PANEL MEASUREMENT (Rust): per symbol â†’ ~24 slots (mostly re-encodings of
      already-extracted CBM signals; embeddings via frozen nomic table)
      â–¼
  Aster vault: constellations (base+slot CFs) Â· edges (graph CF) Â· ledger rows
      â–¼
  WEAVE: cross-terms, agreement graph, per-slot kNN graphs, lead/lag      [background lane]
  ANCHOR: test/CI/git/trace ingestion â†’ anchors + grounding ledger        [event-driven]
  ASSAY: bits/sufficiency/redundancy/TE batches                           [background lane]
  KERNEL: scoped kernels + recall gates + gaps                            [background lane]
  GUARD: calibration when bad-corpus â‰¥ 50                                 [background lane]
      â–¼
  LOWER: regenerate SQLite artifact (nodes/edges/FTS/vectors) + fingerprint + ledger entry
```

Serving-path reads (tools) hit: Aster (MVCC snapshot reads), Sextant indexes, kernel index, guard profiles, and the lowered SQLite for Cypher/legacy paths. Nothing on the serving path blocks on the background lane (Freshness policy: `StaleOk{lag}` default, `Fresh` on request).

## 6. FFI boundary (summary â€” full spec in 19)

Narrow, C-to-Rust-safe, versioned:

| FFI surface | Direction | Phase |
|---|---|---|
| `cbm_extract_file(...) -> CBMFileResult*` + result accessors + `cbm_free_result` | Rustâ†’C | B |
| `cbm_pipeline_new/run/cancel/free` with a **row-sink callback** (new: `cbm_pipeline_set_sink(cb, ctx)` streaming nodes/edges instead of/alongside SQLite dump) | Rustâ†’C (+Câ†’Rust callback) | B |
| `cbm_mcp_server_new/handle_tool/free` (legacy tool pass-through) | Rustâ†’C | B |
| `cbm_discover_ex`, `cbm_git_context_resolve`, `cbm_githistory_compute` | Rustâ†’C | B/C |
| Allocator: both sides bound to mimalloc (`cbm_alloc_init` + Rust `mimalloc` global) | â€” | B |
| Error/panic policy: C returns status codes (already); Rust callbacks are `catch_unwind`-wrapped, abort-on-double-panic | â€” | B |

## 7. Cross-cutting policies

- **Fail-closed everywhere.** Every tool error returns `{code, message, remediation}`. CBM's C statuses are mapped into the same envelope. New `ASTRO_*` codes namespaced beside `CALYX_*` ones.
- **Determinism.** Seeded RNG only, injected clocks, content-addressed ids. The vault layer is order-independent (content addressing absorbs CBM's known parallel-vs-sequential graph divergence â€” same symbols â‡’ same CxIds regardless of worker interleave; edge sets still parity-checked, see 20).
- **Memory.** One budget: CBM's `cbm_mem` RSS budget (tiered 25/35/50% of RAM) governs extraction; Calyx bounded allocators/caches govern the intelligence lane; both on mimalloc. Backpressure naps preserved.
- **Security.** stdio MCP unauthenticated by design (agent-local), loopback-only UI, secrets never ledgered (redaction), CBM secret filters retained, `cbm_validate_shell_arg` discipline retained for all subprocess spawns.
- **GPU strictly optional (D10).** Default build: CPU-only â€” nomic vectors are a lookup table; Assay/kernels/guard are CPU. Optional features: `cuda` (Forge kernels), `tei` (resident embedder endpoints), `onnx` (real model lenses). Fail-loud when enabled but unavailable; never silent fallback.
- **Platforms.** macOS (arm64/x64), Linux (arm64/x64, musl static), Windows (x64). Windows is a first-class target (both parents support it; cuVS/Linux-only paths excluded from default).

## 8. What is intentionally NOT built

- No embedded LLM; the MCP client remains the reasoning layer (CBM doctrine).
- No network egress from the intelligence path (update check stays the only network touch; TEI endpoints are explicit opt-in loopback).
- No write-Cypher; mutations flow only through tools with ledger entries.
- No second vector DB / graph DB / search engine â€” Calyx's universality claim is the point (anti-pattern: "bolting on a separate search/graph/vector DB").
- No mandatory cloud/telemetry of any kind.


---

# 04_DATA_MODEL.md

# 04 â€” Data Model & Mapping Specification

The exact, field-level mapping from CBM's SQLite graph to Calyx's constellation model. This document is the contract `astrolabe-ingest` implements.

## 1. Identity scheme (D4) â€” the most important design choice

CBM identity: `(project, qualified_name)` unique per index run; integer `id` reassigned every full reindex. Calyx identity: `CxId = content_address(input_bytes, panel_version, vault_salt)` â€” immutable, content-derived.

**Resolution: two-level identity.**

| Level | Key | Properties |
|---|---|---|
| **Series** (the symbol through time) | `series_id = blake3_16("astro-series-v1" â€– project â€– qualified_name â€– label)` | Stable across edits & reindexes. Owns: the recurrence series (change/failure events), anchors that outlive versions, lead/lag analysis, forecasting. |
| **Version** (one state of the symbol) | `CxId = content_address(canonical_input_bytes, panel_version, vault_salt)` | Immutable. Owns: slots, scalars, per-version anchors, graph edges (edges connect versions; series-level projections derived). |

**Canonical input bytes** (mirrors `calyx-poly`'s `MarketSnapshot::canonical_input_bytes` â€” frame every observed field, fail closed on non-finite/missing invariants):

```
canonical_input_bytes(symbol) =
  frame("astro-symbol-v1") â€– frame(project) â€– frame(qualified_name) â€– frame(label)
  â€– frame(rel_file_path) â€– frame(language) â€– frame(source_snippet_bytes)
  â€– frame(signature) â€– frame(be_u32(start_line)) â€– frame(be_u32(end_line))
```
(`frame(x) = be_u64(len(x)) â€– x`.) Line numbers included deliberately: a moved-but-identical function is a distinct *version* (its context changed) while remaining the same *series*; pure re-index of unchanged file â‡’ byte-identical â‡’ same CxId â‡’ idempotent no-op (Aster dedup). `vault_salt = "astrolabe-v1:" + project`.

**Series registry** â€” a small CF (or `metadata` convention + secondary index): `series_id â†’ { qualified_name, label, current_cx_id, version_count, first_seen, last_seen }`, plus reverse `cx_id â†’ series_id` in each constellation's metadata (`metadata["series_id"]`). Version succession is recorded as a recurrence occurrence on the series (kind `Recurrence`, context = `{commit, prev_cx, new_cx}`).

## 2. Node â†’ Constellation mapping

| CBM `nodes` column / property | Constellation field |
|---|---|
| `label` (Function/Method/Class/â€¦) | `metadata["label"]` + modality (below) + one-hot component in the role lens |
| `name` | `metadata["name"]` |
| `qualified_name` | `metadata["qn"]`; part of canonical bytes; series key |
| `file_path`, `start_line`, `end_line` | `metadata["file"]`, `scalars["start_line"/"end_line"]` |
| `properties` JSON: `signature`, `return_type`, `receiver`, `parent_class`, `docstring` | `metadata[â€¦]` verbatim (docstring also feeds S_doc lens) |
| `properties`: `complexity`, `cognitive`, `loop_count`, `loop_depth`, `max_access_depth`, `param_count`, `body_lines`, `body_tokens` | `scalars[â€¦]` (exact) + inputs to the complexity lens |
| `properties`: `fp` (MinHash 512-hex) | input to structural-trigram lens; kept verbatim in `metadata["fp"]` |
| `properties`: `sp` (AST profile, 25 uints) | input to S_ast lens; kept in `metadata["sp"]` |
| `properties`: `decorators`, `base_classes`, `param_names`, `param_types`, `return_types` | `metadata[â€¦]` (JSON) + hashed-set lens inputs |
| `properties`: `is_entry_point`, `is_test`, `is_exported`, `is_abstract`, `route_path`, `route_method`, recursion/loop flags | `scalars` (0/1) + role-flags lens; route fields also `metadata` |
| `properties`: `decorator_tags`, `change_count`, `last_modified`, `extension` | `scalars`/`metadata`; temporal lens inputs |
| `node_vectors` (768-d int8 RI embedding) | S_code_semantic slot (dequantized/renormalized, or re-derived from tokens â€” see 05 Â§S17) |
| dead-code status (derived) | `scalars["in_calls"]`, `scalars["in_usage"]` + role lens |
| **Modality** | `Code` for symbol labels; `Text` for Section/docs; `Structured` for Resource/Chart/Package/EnvVar/config Variables |

**Node labels that become constellations:** Function, Method, Class, Struct, Interface, Enum, EnumMember, Trait, Type/TypeAlias, Field, Variable, Constant, Module, File, Route, Channel, Resource, Chart, Package, Macro, Section, Namespace, Property, Union, Protocol, Mixin, Object, Impl, Annotation, EnvVar.
**Structural-only labels** (Project, Branch, Folder) become graph-CF nodes + metadata rows only (no panel measurement; they'd pollute assay/kernel with non-atoms) â€” with Folder/Project aggregates available as scoped views.

## 3. Edge â†’ association mapping

All CBM edges import into the Aster **plain-graph CF** as typed, directed, weighted edges with provenance:

```
edge_row = { src: CxId, dst: CxId, etype: u16 (vocabulary below), weight: f32âˆˆ[0,1],
             props: { confidence, strategy, candidates, line, args?, url_path?, broker?,
                      coupling_score?, jaccard?, score?, via?, validated? },
             provenance: ledger_ref }
```

| CBM edge type | etype class | weight source (v1 prior) | Later (measured) |
|---|---|---|---|
| CALLS | call | `confidence` (0.4â€“0.95 from strategy) | recalibrated per-strategy by Assay (8 Â§5) |
| RESOLVED via LSP | call | LSP confidence (0.6â€“0.95) | same |
| IMPORTS, DEFINES, DEFINES_METHOD, CONTAINS_* , HAS_BRANCH | structure | 1.0 | fixed |
| INHERITS, IMPLEMENTS, OVERRIDE, DECORATES, INSTANTIATES, USES_TYPE | type | 0.9 | measured |
| USAGE, READS, WRITES, THROWS | dataflow | 0.7 | measured |
| TESTS, TESTS_FILE | test | 0.9 | validated by CI anchors |
| HTTP_CALLS, ASYNC_CALLS, GRPC_CALLS, GRAPHQL_CALLS, TRPC_CALLS | service | 0.5 (`service_pattern`) | **promoted by trace anchors** (3.4) |
| HANDLES, DATA_FLOWS, INFRA_MAPS, CONFIGURES, DEPENDS_ON | service/infra | 0.6â€“0.9 by source | measured |
| EMITS, LISTENS_ON | channel | 0.7 | trace-promoted |
| FILE_CHANGES_WITH | temporal | `coupling_score` | superseded by lead/lag + TE (7 Â§5) |
| SIMILAR_TO | derived | `jaccard` | recomputed as Loom cross-record agreement |
| SEMANTICALLY_RELATED | derived | `score` | re-admitted via measured bits (8) |
| CROSS_* | cross-repo | inherit + `target_project` props | trace-promoted |

Edge identity/dedup follows CBM's key `(src, dst, etype, local_name_gen)` â€” preserved so IMPORTS multi-edges survive. Edges reference **version CxIds**; when a symbol gets a new version, the incremental weave re-points live edges (CBM's inbound-edge snapshot pattern) and the old version's edges remain for time-travel.

## 4. Anchors (full spec in 06)

`Anchor { kind, value, source, observed_at, confidence }` per Calyx core. Code-domain source-prefix conventions (mirroring Poly's `uma:`/`proxy:` discipline):

| Source prefix | Meaning | Trust |
|---|---|---|
| `ci:<provider>:<run_id>` | test/CI resolved outcome | Trusted (confidence 1.0) |
| `trace:<trace_id>` | runtime confirmation | Trusted |
| `git:revert:<sha>` / `git:fix:<sha>` | archaeology | fix=Provisional (0.7â€“0.9), revert=Trusted |
| `agent:<agent>:<session>` | agent task outcome | Provisional until CI confirms |
| `review:<pr>` | human review verdict | Trusted (thumbs) |
| `survival:<window>` | unchanged-under-green-CI | Provisional only, cap 0.5 |

## 5. Column-family layout (vault)

| CF | Contents (code domain) |
|---|---|
| `base` | constellation headers/bodies (symbols) |
| `slot_NN` (+ `.raw`) | panel slots (quantized + raw sidecars for guard-critical slots) |
| `anchors` | per-version anchors |
| `graph` | the typed association graph (nodes = CxIds, typed edges, CSR projection for kernel/paths) |
| `xterm` | materialized cross-terms (agreement eager; gated interactions) |
| `recurrence` | per-series event series (changes, failures, agent touches) |
| `assay` | bits/sufficiency rows keyed (vault, anchor kind, panel_version, corpus_shard, subject) |
| `kernel` | kernel reports/indexes per scope |
| `guard` | calibrated guard profiles per domain (lang/scope) |
| `ledger` | hash chain |
| `reactive` | trigger audit + fired rows |
| `anneal_*` | optimizer state |
| `time_index` | wall-clock â†’ seq map (as_of queries) |

## 6. Lowered SQLite artifact (schema-exact with CBM)

`astrolabe-lower` regenerates the CBM schema byte-compatibly: `projects`, `file_hashes`, `nodes` (id remap: dense ints in QN order for determinism), `edges` (+ `url_path_gen`/`local_name_gen` generated columns), `project_summaries` (ADR), `nodes_fts` (contentless FTS5, `cbm_camel_split` semantics), `node_vectors`, `token_vectors`. Additions (backward-compatible): `astro_meta` table `{vault_fingerprint, ledger_head_hash, panel_version, lowered_at}`. Consumers unchanged: Cypher engine, UI, legacy tools, team artifact export.

## 7. Validation (fail-closed, Poly-style)

Ingest refuses (with `ASTRO_*` codes): non-finite scalars (`ASTRO_SYMBOL_NON_FINITE`), empty QN/label (`ASTRO_SYMBOL_IDENTITY_EMPTY`), snippet hash mismatch vs file (`ASTRO_SOURCE_DRIFT`), edge endpoints unresolvable (`ASTRO_EDGE_DANGLING` â€” logged + skipped with counter, never silently dropped without accounting), panel version 0, anchor confidence âˆ‰ (0,1]. Every ingest batch writes a ledger entry (kind Ingest) with counts + input fingerprint; readback verification compares persisted vs committed counts (replaces CBM's `dump_verify` with an exact, ledgered check).

## 8. Mapping invariants (pinned by tests)

1. Same repo state â‡’ same CxId set, regardless of worker count/order (content addressing).
2. Node count parity: lowered SQLite nodes == CBM-native nodes for the same commit (Â± documented structural-label differences).
3. Edge parity: typed-edge multiset matches CBM's within the known seq/parallel divergence classes; divergences accounted, never silent.
4. Round-trip: vault â†’ lowered SQLite â†’ re-import â‡’ identical CxIds (idempotency).
5. Every mutation has a ledger row; `verify_chain` Intact after any pipeline run.


---

# 05_LENS_PANEL.md

# 05 â€” The Code Lens Panel

The panel is the heart of the integration: every code symbol measured through ~22 frozen, typed lenses. Design follows the handbook's core rule â€” **embed what is latent, encode what is explicit** â€” and its implementation mirrors `calyx-poly`'s panel machinery (`lenses.rs`, `seed_registry.rs`, `encode.rs`): frozen seeds, deterministic encoders, `SlotVector::Absent` for missing inputs, a versioned `default_panel()`.

## 1. The embed-vs-encode audit of every CBM signal

Every signal CBM already extracts, classified. Nothing is discarded; nothing explicit is embedded; nothing latent is left unembedded.

| CBM signal | Nature | Disposition |
|---|---|---|
| AST structural profile (`sp`, 25 dims) | explicit, structural | **encode** â†’ S0 |
| MinHash trigram stream (`fp` + underlying trigrams) | explicit, structural | **encode** â†’ S1 (hashing trick); raw fp kept for LSH candidate gen |
| complexity / cognitive / loops / nesting / params / LOC / tokens | explicit numeric | **encode** â†’ S2 (log), S3 (thermometer); exact values in `scalars` |
| resolved callee set (+ counts) | explicit set | **encode** â†’ S4 (hashed multi-hot) |
| param/return/used types | explicit set | **encode** â†’ S5 |
| decorators / annotations | explicit set | **encode** â†’ S6 |
| identifier tokens (camelCase-split name/QN) | lexical | **encode** â†’ S7 (sparse BM25 lens) |
| graph degrees / centrality / neighbor labels | explicit, relational | **encode** â†’ S8 (structural-signature encoder, handbook #15) |
| file path / directory | explicit hierarchy | **encode** â†’ S9 (handbook #16) |
| git churn / age / cadence / co-change | explicit temporal aggregates | **encode** â†’ S10 |
| last-modified recency | temporal | **encode** â†’ S11 (decay lens; retrieval-only, per AP-60) |
| is_test / is_entry / is_exported / route flags / recursion flags / dead status | explicit booleans | **encode** â†’ S12 (multi-hot) |
| language + label | categorical | **encode** â†’ S13 (hashed one-hot) |
| TESTS coverage topology | explicit relational | **encode** â†’ S14 |
| throws/raises exception types | explicit set | **encode** â†’ S15 |
| env vars + config keys touched | explicit set | **encode** â†’ S16 |
| route method/path, channel topic/broker | explicit | **encode** â†’ S17 |
| function body (the code itself) | **latent** | **embed** â†’ S18 (nomic token-vector sum) |
| docstring + comments | **latent** prose | **embed** â†’ S19 (same encoder; `Absent` if none) â€” the handbook Â§5.4 dual-encode rule |
| identifier semantics ("what the name means") | **latent** | **embed** â†’ S20 |
| all numeric scalars as one profile | explicit assembly | **encode** â†’ S21 (record vector, handbook #11) |
| per-token vectors (late interaction) | latent | **embed** â†’ S22 `Multi` (optional feature) |
| commit messages touching the symbol | latent prose | candidate lens (series-level), Phase 8+ |
| `node_vectors` RRI-enriched embedding | latent, corpus-dependent | S18-alt commissioned lens per index epoch (corpus_hash in contract) â€” optional |

## 2. Panel v1 specification

Schema id: `astro.panel.v1`. All lenses frozen with content-addressed contracts; seeds/dims/Ïƒ pinned in `astro_seed_registry` (Poly `seed_registry.rs` pattern). Shapes use Calyx `SlotShape`; missing input â‡’ `Absent{NotApplicable|LensUnavailable}` â€” **never zero**.

| Slot | Key | Shape | Encoder | Inputs (CBM) | Norm | Flags |
|---|---|---|---|---|---|---|
| 0 | `ast_profile` | Dense(25) | fixed-maxima normalization (ast_profile.c maxima) | `sp` | Finite | â€” |
| 1 | `struct_trigrams` | Sparse(65536) | signed feature-hash of structurally-weighted AST-node-type trigrams (weight 1â€“3, zero-weight skipped) | trigram stream | Finite | â€” |
| 2 | `complexity_log` | Dense(8) | `signed_log` of [cyclomatic, cognitive, loop_count, loop_depth, max_access_depth, param_count, body_lines, body_tokens] | def metrics | Finite | â€” |
| 3 | `complexity_ple` | Dense(56) | 7-bin piecewise-linear thermometer per metric, frozen edges on log scale (Poly `QuantileEncoder` pattern) | same | L2 | â€” |
| 4 | `api_callees` | Sparse(262144) | hashed multi-hot of resolved callee QNs, weight = log1p(call count); unresolved callees hashed by bare name with 0.5 weight | calls + resolved_calls | Finite | â€” |
| 5 | `type_surface` | Sparse(65536) | hashed set: param types âˆª return types âˆª USES_TYPE âˆª INSTANTIATES targets | type refs | Finite | â€” |
| 6 | `decorators` | Sparse(4096) | hashed set of decorators/annotations + decorator_tags | defs | Finite | â€” |
| 7 | `identifier_lexical` | Sparse(131072) | camelCase/snake-split tokens of name+QN (+ optional body identifiers), tf-weighted | tokens | Finite | â€” (BM25-indexed) |
| 8 | `graph_position` | Dense(16) | structural signature; frozen dimension order below | woven graph | Finite | backfilled post-weave |
| 9 | `path_hierarchy` | Sparse(16384) | hashed dir segments (each ancestor prefix) + depth | file_path | Finite | â€” |
| 10 | `churn_profile` | Dense(8) | log1p change_count, log age_days, log days_since, co-change degree, cadence median, cadence MAD, revert count, fix-touch count | git pass | Finite | backfilled |
| 11 | `recency` | Dense(1) | exp decay, half-life 30d (frozen) | last_modified | Finite | **retrieval_only, excluded_from_dedup** |
| 12 | `role_flags` | Dense(12) | multi-hot: test/entry/exported/abstract/async/generator/route/handler/dead/recursive/generated/documented | flags | Finite | â€” |
| 13 | `lang_label` | Sparse(256) | hashed one-hot (language, label) | lang, label | Finite | â€” |
| 14 | `test_topology` | Dense(4) | tests-covering count, hop-distance to nearest test (capped 5), distinct test files, covered flag | TESTS edges | Finite | backfilled |
| 15 | `error_surface` | Sparse(4096) | hashed set of thrown/raised/caught exception types | throws | Finite | â€” |
| 16 | `config_env_surface` | Sparse(4096) | hashed set of env keys + config keys (CONFIGURES) | env_accesses | Finite | â€” |
| 17 | `route_surface` | Sparse(4096) | hashed (METHOD, canonical path segments) / (broker, topic) | routes/channels | Finite | â€” |
| 18 | `code_semantic` | Dense(768) | **nomic-embed-code lookup**: sum of per-token static vectors (int8 table, 40,856 tokens) over body tokens, OOV via sparse random-index fallback, L2-normalized. Deterministic, corpus-independent, zero-inference | body tokens | **Unit** | â€” |
| 19 | `doc_semantic` | Dense(768) | same encoder over docstring + adjacent comments | docstring | Unit | `Absent` when no prose |
| 20 | `name_semantic` | Dense(768) | same encoder over split identifier tokens (name + QN tail) | name | Unit | â€” |
| 21 | `record_vec` | Dense(24) | unit-normed assembly of all scalar fields (handbook #11: the weightless "tabular embedding") | scalars | Unit | â€” |
| 22 | `token_multi` | Multi(128) | per-token nomic vectors, random-projected 768â†’128, MaxSim late interaction | tokens | Finite | optional feature `multi-vector` |

**Optional plug-in lenses** (off by default; registered via Calyx registry runtimes when the user enables them): `tei_semantic` (TeiHttpLens â†’ real transformer, e.g. full nomic-embed-code or Qwen3), `splade_sparse` (FastembedSparseLens), `colbert_multi` (FastembedBgem3Lens), `reranker` (FastembedRerankerLens; retrieval-only, request-scoped, never persisted). These slot in with zero engine changes â€” the "plug-in lens is THE key" property.

S8 `graph_position` Dense(16) dimension order is frozen as:

| Dim | Quantity |
|---|---|
| 0 | `log1p(call_in)` |
| 1 | `log1p(call_out)` |
| 2 | `log1p(dataflow_in)` |
| 3 | `log1p(dataflow_out)` |
| 4 | `log1p(type_in)` |
| 5 | `log1p(type_out)` |
| 6 | `log1p(service_in)` |
| 7 | `log1p(service_out)` |
| 8 | `sampled_betweenness` |
| 9 | `pagerank` |
| 10 | `clustering_coeff` |
| 11 | `neighbor_label_entropy` |
| 12 | `log1p(total_in_degree)` |
| 13 | `log1p(total_out_degree)` |
| 14 | `log1p(total_degree)` |
| 15 | `direction_balance = (total_out_degree - total_in_degree) / max(total_degree, 1)` |

## 3. Per-label applicability matrix

Not every lens applies to every atom kind. `Absent{NotApplicable}` is the mechanism; this matrix is enforced by the panel driver:

| Label class | Applicable slots |
|---|---|
| Function/Method/Macro | all |
| Class/Struct/Interface/Enum/Trait/Impl | all except S22; complexity = aggregate over members |
| Field/Variable/Constant/Property/EnumMember | S5â€“S7, S9â€“S13, S18(initializer), S20, S21 |
| Module/File | S1, S7â€“S13, S16, S18(whole-file capped), S21; complexity = aggregates |
| Route/Channel | S9, S11â€“S13, S17; + inherited from handler via HANDLES |
| Resource/Chart/Package/EnvVar (Structured modality) | S7, S9, S12, S13, S16, S17, S21; metadata-driven |
| Section (docs) | S7, S9, S11, S13, S19 |

## 4. Frozen-contract discipline

- Every lens registered with `FrozenLensContract{name, weights_sha, corpus_hash, shape, modality, dtype, norm}`; `lens_id = content_address(...)`. Weights hash for S18â€“S20/S22 = SHA-256 of the nomic vector blob (already shipped as `code_vectors.bin`); for deterministic encoders = SHA-256 of the spec string + seed constants.
- **Determinism probes at registration** (measure twice, byte-identical) â€” CBM's extraction feeding a lens must itself be deterministic per file; the probe catches violations.
- Encoder changes â‡’ **new lens id + panel version bump + lazy backfill** (Calyx SwapController). Never mutate in place.
- The corpus-dependent variants (RRI-enriched embeddings, per-repo quantile edges) are **commissioned lenses**: their `corpus_hash` pins the corpus snapshot; re-commissioning creates a new lens id. Default panel avoids them (frozen absolute edges instead) to keep idempotency simple.

## 5. Quantization policy (measured, per Forge/Registry compression)

| Slot class | Policy |
|---|---|
| S18â€“S20 dense 768 | TurboQuant 3.5 bpc with recall gate (fallback raw on intelligence loss); raw sidecar retained for guard-critical use |
| S0â€“S3, S8, S10â€“S14, S21 small dense | raw f32 (tiny) |
| Sparse slots | native sparse encoding |
| S22 Multi | 4-bit rotated SQ (rotsq is CBM's own; Calyx TurboQuant equivalent) |
| Guard-designated slots (see 10) | **raw always** (gentler levels for identity/guard slots, per handbook Â§11) |

## 6. Capability gating (what survives per repo)

At assay time (08), each lens gets a capability card and the gate runs per repo: **Retire** if max pairwise correlation with an existing admitted lens > 0.6 (redundant â€” e.g., in some repos `complexity_log` and `complexity_ple` will collapse into one); **Park** if no grounded signal or < 0.05 bits about every anchor axis; **Admit** otherwise; **stratified override** keeps sole carriers of rare-critical strata (e.g. `error_surface` may be globally weak but the only carrier for incident-anchored symbols). Gate decisions are ledgered and reversible. Expected steady state: 12â€“18 active lenses per repo out of 22 â€” *measured*, not guessed, and different per repo. Effective-rank (`n_eff`) reported in `get_architecture` so redundancy is visible.

## 7. Cross-slot cross-terms of designed interest (feeds 07)

| Pair | Cross-term | Meaning |
|---|---|---|
| S19 Ã— S18 | agreement | **doc-drift**: does the documentation match the code |
| S20 Ã— S4 | agreement | **name-truth**: does the name match the behavior (API usage) |
| S18 Ã— S1 | agreement | semantic-vs-structural clone taxonomy |
| S2 Ã— S10 | interaction | complexityÃ—churn hotspot signal (classic defect predictor â€” now measured in bits) |
| S8 Ã— S14 | interaction | centralityÃ—coverage: load-bearing-but-untested detector |
| S18 Ã— S17 | agreement | does the implementation match the route it serves |

## 8. Panel evolution

`astro.panel.v1` ships as above. Version bumps: v1â†’v2 when the gate + deficit loop (14) proposes new lenses (e.g. dataflow-graph signature, ownership lens, security-pattern lens). Old slots retire non-destructively (history remains readable). The sufficiency report per anchor axis is the roadmap for what lens to add next â€” instrumentation guided by measured deficits, not intuition.


---

# 06_ANCHORS.md

# 06 â€” Anchor Strategy (Grounding)

Anchors are what elevate the system from "a graph of code" to "grounded intelligence about code." Without them, every bit measurement, kernel, guard verdict, and prediction is **provisional** â€” Calyx enforces this. This document specifies every anchor source, its ingestion pipeline, and the trust lifecycle. Doctrine: *grounding is mandatory; ungrounded â‡’ provisional, never "trusted"; anchors are never synthetic.*

## 1. Anchor taxonomy for the code domain

| Anchor kind (Calyx) | Code meaning | Value | Attached to |
|---|---|---|---|
| `TestPass` | a test governing this symbol passed/failed in a resolved run | Bool | version CxId (+ series) |
| `Label("bug_touch")` | symbol implicated in a bug (SZZ archaeology) | Bool/Enum | version at the blamed commit |
| `Label("reverted")` | symbol's change was reverted | Bool | the reverted version |
| `Label("incident")` | symbol/route implicated in a production incident | Enum(severity) | version + Route |
| `Label("vulnerability")` | CVE/security finding touched this symbol | Enum | version |
| `Reward` | agent task outcome using this symbol in context | Number [0,1] | versions in the context pack |
| `Thumbs` | human review verdict on the change touching this symbol | Bool | version |
| `Recurrence` | repeated events: changes, failures, hotfixes | occurrence series | **series** |
| `StyleHold` / `SpeakerMatch` | conformance exemplars for guard calibration (identity slots) | Bool | version |

## 2. Anchor sources & ingestion pipelines

### 2.1 Test & CI outcomes (the primary axis) â€” Phase 4
- **Ingestion paths:** (a) new `anchor_outcome` MCP tool â€” agents/CI post results; (b) CLI `astrolabe cli anchor_outcome` from CI scripts; (c) parsers for JUnit XML / `cargo test` JSON / pytest / go test / vitest output (drop-in for the common 90%); (d) optional GitHub Actions ingestion.
- **Mapping:** test result â†’ the test symbol (by QN match) â†’ propagate along `TESTS`/`TESTS_FILE` edges to covered symbols. Direct coverage data (lcov/coverage.py), when supplied, replaces edge-propagation with exact line-rangeâ†’symbol mapping (higher confidence).
- **Trust:** resolved CI run â‡’ source `ci:<provider>:<run_id>`, confidence 1.0, `Trusted`. Local uncommitted runs â‡’ `Provisional` (0.8).
- **Fan-out control:** a passing run anchors only symbols in the changed files' impact set + direct coverage, not the whole repo (prevents anchor inflation making everything look grounded).

### 2.2 Git archaeology (SZZ) â€” Phase 4
- Identify **fix commits**: message heuristics (`fix|bug|closes #N|hotfix|patch` + issue-tracker refs), configurable.
- Blame the fix's deleted/modified lines backward (`git blame` on parent) â†’ the **bug-introducing commits** â†’ the symbol versions they created get `Label("bug_touch")`, source `git:fix:<sha>`, confidence 0.7â€“0.9 (heuristic strength), **Provisional**.
- **Reverts:** `git revert` commits + force-removed changes â†’ `Label("reverted")`, confidence 1.0, Trusted. These double as guard bad-cases (10).
- Runs incrementally on watcher ticks; full pass at index time over `--max-count=10000, since 1 year` (CBM's existing githistory window).

### 2.3 Runtime traces â€” Phase 4 (completes CBM's stub)
- CBM's `ingest_traces` handler is a stub, but its OTLP helpers (`cbm_extract_service_name`, `cbm_extract_http_info`, path/duration/p99 extraction) exist and are tested. Wire them:
  1. OTLP span batch â†’ `(service, METHOD, path, duration, status)` via existing helpers; also accept CBM's declared simple format `{caller, callee, count}`.
  2. Match to Route QN `__route__<METHOD>__<canon-path>` (CBM's deterministic canonicalization).
  3. **Edge promotion:** matching `HTTP_CALLS`/`DATA_FLOWS`/`CROSS_*` edges get `props.validated=true`, weight â†’ measured (call count/total), Provisionalâ†’**Trusted**.
  4. **Anchors:** handler symbols get `Recurrence` occurrences (traffic) and `Label("incident")` when status â‰¥ 500 rates spike; latency scalars attach as evidence.
- This makes the static graph *empirically confirmed* â€” the single highest-leverage unfinished feature in CBM.

### 2.4 Agent task outcomes (the flywheel) â€” Phase 4
- Convention: when an agent completes a task, it (or a PostToolUse/Stop hook) calls `anchor_outcome{kind:"agent_task", success, session, context_pack_id}`.
- Every symbol in the served context pack receives `Reward` (success=1/failure=0, confidence 0.5 **Provisional** â€” the agent's self-report), upgraded to Trusted when CI subsequently passes on the change (`promote_on_resolution`, Poly's proxyâ†’resolved pattern).
- This measures **which context actually helps agents succeed** â€” the signal that anneals pack composition (14).

### 2.5 Review outcomes â€” Phase 6
- PR approved / changes-requested â†’ `Thumbs` on touched symbol versions, source `review:<pr>`, Trusted.
- Optional; requires forge (GitHub/GitLab) ingestion adapter.

### 2.6 Incidents & security â€” Phase 6
- Postmortem/alert adapters (PagerDuty/Sentry webhook JSON, or manual `anchor_outcome`) â†’ `Label("incident", severity)` on implicated routes/symbols.
- CVE/audit findings â†’ `Label("vulnerability")`; these seed label propagation (security-sensitivity spreads over the association graph with decayed confidence).

### 2.7 Survival anchors (weak prior) â€” Phase 4
- Symbol unchanged â‰¥ N months while CI stayed green in its area â‡’ weak positive `Label("stable")`, confidence â‰¤ 0.5, **permanently Provisional** (never promoted â€” it's absence-of-evidence, not evidence). Used only to enrich guard "good" corpora and cold-start ranking; excluded from sufficiency claims.

## 3. Trust lifecycle (Poly's grounding discipline, ported)

```
source prefix â”€â–º GroundingKind â”€â–º TrustTag
ci:/trace:/review:/git:revert:   Resolved   Trusted   (confidence must be 1.0)
git:fix:/agent:/survival:        Proxy      Provisional (confidence âˆˆ (0,1))
```
- `rollup_trust`: any aggregate (bits, kernel groundedness, readiness) is Trusted **iff every contributing anchor is Trusted**; else Provisional â€” surfaced in every tool response as `trust: "trusted"|"provisional"`.
- `promote_on_resolution`: a Provisional anchor is promoted only by a real resolved confirmation; **contradiction refuses promotion** and flags the pair (`ASTRO_ANCHOR_CONTRADICTION`) â€” e.g., agent claimed success but CI failed.
- Confidence bounds enforced fail-closed: Resolved â‡’ exactly 1.0; Proxy â‡’ strictly (0,1). (Poly `grounding.rs` invariants, verbatim.)

## 4. Flakiness (self-consistency)

Per test series, compute **oracle self-consistency** from recurrence: pairwise agreement of outcomes across occurrences (â‰¥10 pairs required). `flakiness = 1 âˆ’ agreement`; `ceiling = validityÂ·(1âˆ’flakiness)`. Effects: (a) flaky tests' anchors get their confidence capped by the ceiling instead of poisoning bits; (b) prediction confidence for consequences observed only via flaky tests is capped (7.4); (c) a `forecast` surface exposes flake cadence + overdue hazard. Beta-Bernoulli posteriors give credible intervals when occurrence counts are small.

## 5. Cold start (no anchors yet)

- Vault opens with Calyx's **cold-start guard**: searchable immediately; every bits/kernel/prediction response carries `trust: provisional` and `grounding: {anchored: 0, â€¦}` until â‰¥1 grounded anchor exists.
- Bootstrap ladder (fastest first): â‘  run the repo's test suite once through the CI adapter (minutes, yields thousands of TestPass anchors via TESTS edges); â‘¡ SZZ archaeology over existing history (free, immediate, Provisional); â‘¢ enable trace ingestion if the service runs anywhere; â‘£ let agent sessions accrue Reward anchors.
- The `get_readiness` tool names exactly which anchor axes are missing per scope â€” the operator's onboarding checklist.

## 6. Storage & provenance

- Anchors live in the `anchors` CF keyed (CxId, kind); occurrence streams in `recurrence` keyed (series_id, occurrence). Every anchor write = same-commit ledger entry (`EntryKind::Grounding`-equivalent) with source, hash-only payload (no raw code, no secrets â€” redaction policy enforced).
- Anchor ingestion is idempotent: `(cx_id, kind, source, observed_at)` dedup key.
- Erasure: anchors from a retracted source (e.g. a yanked CI run) erased via tombstones, never silent deletion.

## 7. Anchor-axis catalog for Assay (what bits are measured *about*)

| Axis | Anchor kinds | Primary consumers |
|---|---|---|
| **Defect-proneness** | bug_touch, reverted | signal ranking, hotspot bits, guard bad-cases |
| **Test outcome** | TestPass | impact prediction, test selection, sufficiency |
| **Runtime reality** | trace recurrence, incident | edge promotion, service-level readiness |
| **Agent utility** | Reward | context-pack ranking, anneal replay objective |
| **Human quality** | Thumbs | conventions, guard good-cases |
| **Stability** | stable (survival), Recurrence(change) | churn forecasting, kernel groundedness |
| **Security** | vulnerability | label propagation, guard strictness per region |

Minimum sample discipline: Assay's 50-sample floor applies per (slot, axis); below it, results are Provisional with the Bayesian small-sample path. The sufficiency deficit report tells the operator which axis needs more anchors â€” grounding investment is *directed*, never generic.


---

# 07_ASSOCIATIONS.md

# 07 â€” The Association Weave

Doctrine: *"The complete web of associations among the atoms is the raw material of intelligence. Never shortcut it."* CBM supplies the between-record associations from static analysis; this document specifies how they are woven into Calyx, what new association layers are added, and how the combinatorics stay bounded.

## 1. The three association layers

| Layer | What | Source |
|---|---|---|
| **L1: Between-record, typed (the code graph)** | 40+ CBM edge kinds between symbol versions | imported (04 Â§3) |
| **L2: Between-record, derived (similarity graphs)** | per-slot kNN edges: structural, semantic, API, metric-profile | Sextant indexes + MinHash/LSH candidates |
| **L3: Within-record (cross-terms)** | agreement/delta/interaction/concat between slot pairs of one symbol | Loom |

Plus the **temporal dimension**: per-series event streams (changes, failures, traffic) and their lead/lag/TE relationships (L4).

## 2. L1 â€” importing the CBM graph (Phase 2)

- All edges â†’ Aster plain-graph CF with types, weights, props, ledger provenance (mapping table in 04 Â§3).
- **Graph projections** (views for downstream consumers), each a weighted `AssocGraph` (CSR) built by filtering/weighting edge types:
  - `call_graph`: CALLS (+ resolved), weight = confidence.
  - `dependency_graph`: IMPORTS + DEPENDS_ON + USES_TYPE + INSTANTIATES.
  - `dataflow_graph`: READS/WRITES/USAGE/THROWS + DATA_FLOWS.
  - `service_graph`: HTTP/ASYNC/GRPC/GRAPHQL/TRPC/EMITS/LISTENS_ON/HANDLES/INFRA_MAPS (+ CROSS_*).
  - `evolution_graph`: FILE_CHANGES_WITH â†’ superseded by L4 lead/lag when available.
  - `kernel_graph` (the composite for Lodestar): weighted union â€” v1 weights {call 1.0, dataflow 0.7, type 0.6, service 0.9, structure 0.3, evolution 0.5}; **annealed later** (14). Node weight = frequency (change_count+1).
- Projections are regenerable (never sacred), rebuilt incrementally on dirty regions, persisted as CSR segments (Calyx-Dev's `materialize-graph-csr` pattern: binary CSR, range-scan built, staleness-aware rebuild).

## 3. L2 â€” similarity graphs (Phase 3)

- Per-slot ANN indexes (12) double as graph generators: for each symbol, k nearest neighbors per designated slot â†’ typed derived edges:
  - `SIM_STRUCT` from S1 (candidates via CBM's existing MinHash/LSH banding â€” kept as the O(n) candidate generator; exact scoring via cosine on S1).
  - `SIM_SEMANTIC` from S18.
  - `SIM_API` from S4 (symbols calling the same things).
  - `SIM_PROFILE` from S21 (similar metric shape).
- **Admission is measured, not fixed**: v1 keeps CBM's thresholds (0.95 Jaccard / 0.75 combined) as priors; once anchors exist, Assay computes the bits each similarity family carries about each axis and Anneal tunes per-family admission thresholds + per-node caps (replacing the guessed constants â€” the honest version of CBM's `SEMANTICALLY_RELATED`).
- Determinism: canonical pair ownership (lower QN owns), sorted admission, per-node cap (default 10) â€” CBM's own determinism fixes, retained.

## 4. L3 â€” cross-terms within a symbol (Phase 3)

`C(N,2)` for Nâ‰ˆ22 slots = 231 pairs/symbol â€” **not** all materialized (that is the DPI-honest move: derived signal is unlimited; storage isn't). Loom materialization policy:

| Cross-term | Policy |
|---|---|
| **Agreement** (scalar cosine) for the 6 designed pairs (05 Â§7: doc-drift, name-truth, clone-taxonomy, complexityÃ—churn, centralityÃ—coverage, route-match) | **eager** â€” persisted to `xterm` CF at weave time |
| Agreement for all other pairs | computed corpus-wide **lazily in the assay lane** to feed the agreement graph; LRU-cached, not persisted per-record |
| **Interaction** (Hadamard) | eager **iff** measured pair-gain â‰¥ 0.05 bits (Assay pair-gain gate); else lazy |
| **Delta / Concat** | lazy on demand (LRU) |

The **agreement graph** (slotÃ—slot edge list, weight = mean agreement) is computed per repo and exposed in `get_architecture` â€” it is the redundancy map that feeds effective-rank and the capability gate.

## 5. L4 â€” temporal associations (Phase 4)

- Every series (04 Â§1) owns recurrence streams: `change` (commits touching it), `failure` (test failures), `traffic` (trace occurrences), `agent_touch`.
- **Lead/lag cross-terms** (Loom): for series pairs with â‰¥3 co-occurrences within a window (default 7 days), `lead_lag = median(t_b âˆ’ t_a)` â†’ directed temporal edge `PRECEDES{lag}` â€” *"changes to A precede changes to B by ~2.1 days"*. Candidate pairs limited to: existing L1 neighbors + same-directory + top co-change (bounds the Cartesian).
- **Transfer entropy** (Assay) upgrades the strongest lead/lag pairs into directed *causal* claims with lag sweep (8 Â§6).
- CBM's symmetric `FILE_CHANGES_WITH` is retained as the candidate source and superseded as a claim.

## 6. Blind-spot sweep (Phase 5)

Loom's detector, calibrated per lens pair (Calyx-Dev's per-pair calibration): flag symbol where `lens_a_similarity âˆ’ neighbors' lens_b_mean > threshold` â€” e.g., *structurally identical to crypto code but semantically dissimilar* (obfuscation?), *semantically identical to a deprecated API but structurally novel* (reimplementation of a banned pattern). Severity tiers; surfaced via `detect_anomalies` and the UI overlay. This is CBM's `blind-spot-sweep` concept, generalized from one hardcoded comparison to any calibrated lens pair.

## 7. Scale budget (Linux-kernel envelope: ~500K symbols, ~5M L1 edges)

| Item | Cost control |
|---|---|
| L1 import | streaming, O(E); ~5M edges â‰ˆ minutes |
| L2 kNN | LSH/MinHash candidates (existing, O(n)) + HNSW build O(nÂ·efÂ·M) on quantized vectors; per-slot opt-out for giant repos |
| L3 eager agreements | 6 pairs Ã— n = O(n) scalars |
| L3 lazy corpus agreements | assay-lane batches, sampled (8 Â§7) |
| L4 lead/lag | candidate-bounded (â‰¤ ~50 pairs/series) |
| Graph CSR | binary segments, incremental rebuild on staleness |

Abundance report stays honest: reports raw yield `nÂ·(N + C(N,2) + 1)`, what was actually materialized, n_eff, and the DPI ceiling â€” "derived signal claimed" can never exceed measured `I(panel;outcome)`.

## 8. Reactive triggers on the weave (Phase 3)

Post-ingest, Loom's reactive engine evaluates bounded, audited triggers: `NewRegion` (a symbol lands outside all trusted regions â€” novel code pattern), `EventRecurs` (Nth failure of a test, Nth hotfix of a file), `DriftDetected` (slot drift beyond threshold for a watched symbol). Subscriptions feed: the watcher log, `optimizer_status`, optional agent notifications (SessionStart hook shows unacknowledged triggers). All queues bounded (registry 1024, queue 4096, audit 64K) â€” A26 discipline.


---

# 08_ASSAY.md

# 08 â€” Assay Plan: Measuring Everything in Bits

The differentiation layer: replace every guessed constant in CBM with a measured, confidence-intervaled, per-repo value, and expose "what actually matters in this codebase" as a first-class tool. All measurements are base-2, KSG k-NN MI (k=3), bootstrap CIs, 50-sample floor, provisional-below-floor via Bayesian posteriors.

## 1. The measurement matrix

For each **anchor axis** (defect, test-outcome, runtime, agent-utility, quality, stability, security â€” 06 Â§7) Ã— each **subject**:

| Subject | Question answered |
|---|---|
| each panel slot (22) | which lenses carry real signal about this outcome, in this repo |
| each designed cross-term (6) | e.g. does complexityÃ—churn beat either alone (pair gain) |
| each similarity family (L2) | do SEMANTICALLY_RELATED edges actually predict co-failure |
| each edge-type class (L1) | are service edges more predictive of incident propagation than call edges |
| whole panel | sufficiency: `I(panel;axis) â‰¥ H(axis)`? |
| scalars individually | classic feature ranking (complexity vs churn vs coverage vs centrality) |

Continuous slots â†’ KSG continuous; labels â†’ one-hot continuousâ†”discrete route; scalar fields â†’ direct MI. Deterministic random projection (Assay `projection.rs`) pre-reduces 768-d slots (target dim â‰ˆ 2Â·log2(n)).

## 2. Sufficiency & deficits (the instrumentation to-do list)

Per axis: `panel_bits` vs `H(axis)`. When insufficient, the deficit splits across slots inversely to marginal bits and routes to `DeficitSuggestedAction`: AddOutcomeAnchor (more grounding) / ProposeLens (new instrumentation, feeds 14 Â§4) / IncreaseSamples. Exposed in `measure_bits{mode:"sufficiency"}` and in `get_readiness`. Example output the agent sees: *"Defect prediction: panel carries 0.61 of 1.0 required bits (insufficient). Largest deficits: dataflow signature (missing lens, est. 0.2 bits), coverage anchors sparse in `services/billing` (0.15 bits)."*

## 3. Redundancy & effective rank

- Pairwise slot correlation/NMI matrix â†’ the agreement graph (07 Â§4).
- Total correlation `TC = Î£ H(slotâ‚–) âˆ’ H(Î¦)` (quorum 50/slot); `n_eff â‰ˆ nÂ·(1 âˆ’ TC/Î£H)`.
- Drives: capability gate retire decisions (05 Â§6), honest panel-diversity reporting, and pruning of CBM's 11 semantic sub-signals per repo (measured answer to "is graph diffusion worth anything here?" â€” the signal CBM computes but never applied).

## 4. Synergy (interaction information)

Three-way II over designed triples (complexity, churn, coverage), (semantic, structural, API), (centrality, churn, incident) â€” sign classifies redundant/synergistic; synergistic pairs get their interaction cross-term promoted to eager (07 Â§4) and become named features in reports. Quorum 150.

## 5. Recalibrating CBM's fixed constants (the honesty upgrade)

| CBM constant (today) | Measured replacement |
|---|---|
| resolution-strategy confidences (import_map .95, same_module .90, unique .75, suffix .55, service_pattern .5, LSP .6â€“.95) | per-strategy empirical precision, measured against LSP-confirmed + trace-confirmed ground truth per repo; becomes the edge-weight prior with CI |
| `SEMANTICALLY_RELATED â‰¥ 0.75` | per-repo admission threshold tuned by Anneal to maximize bits-about-co-failure at bounded edge budget |
| `SIMILAR_TO â‰¥ 0.95` | same treatment (clone-claim precision measured against co-change/co-failure) |
| 11-signal weights (.20/.25/.10/.15/.10/.05/.10) | per-repo bits â†’ annealed fusion weights (12) |
| hopâ†’risk in detect_changes | replaced by oracle-grounded impact probabilities (11) |
| `coupling_score â‰¥ 0.3` | lead/lag + TE significance (below) |

## 6. Transfer entropy & temporal structure

- TE over change/failure series pairs (candidates from L4): `T(Aâ†’B) = I(B_f; A_p, B_p) âˆ’ I(B_f; B_p)`, lag sweep {1,2,4,8} windows; direction = larger TE; emits `DRIVES{lag, te_bits}` edges above significance.
- Periodicity (Lombâ€“Scargle + FAP) on failure/change series â†’ release rhythms, flaky cadences.
- CUSUM change-points on churn/complexity streams â†’ "regime changed at commit X" annotations.
- MMD two-sample drift per slot: this-month's new symbols vs corpus â†’ drift alarms feeding guard recalibration (10 Â§6).

## 7. Execution model (never on the serving path)

- All assay work runs in the **background intelligence lane** (anneal budget: default 15% CPU, cooperative ticks) or on-demand via `measure_bits{refresh:true}`.
- **Sampling:** KSG is O(nÂ²) â€” per (subject, axis) estimate uses stratified samples â‰¤ 4096 (stratify by label Ã— directory Ã— anchored/not), deterministic seed. CI width reported; agent-visible.
- **Caching/invalidation:** results in `assay` CF keyed (vault, axis, panel_version, corpus_shard=commit-epoch, subject); invalidated by panel bump or shard change; served stale-ok with freshness tag.
- **Budget:** nightly full sweep target â‰¤ 30 min CPU at 500K-symbol scale (17); incremental re-assay only for dirty strata.

## 8. Deliverable reports (tool-facing)

1. **Signal ranking** per axis: slot â†’ bits Â± CI, trust tag, sample count.
2. **Sufficiency card** per axis: sufficient?, deficit breakdown, suggested actions.
3. **Redundancy card**: n_eff, top redundant pairs, gate decisions taken.
4. **Synergy card**: synergistic pairs/triples with gains.
5. **Causality card**: DRIVES edges with lag + TE bits.
6. **Calibration card**: measured precision of every edge strategy vs priors.
All cards are ledgered (assay entries), carry `estimator`, `n`, `ci`, `trust`, and are reproducible (`reproduce` re-derives within tolerance).


---

# 09_KERNEL_CONTEXT.md

# 09 â€” The Kernel & Context Engine

The kernel is the payoff: the minimal set of symbols from which the codebase's intelligence is reconstructable â€” *measured* (recall-gated), grounded (anchor-aware), scoped, and turned into the primary agent-facing product: **token-budgeted context packs**.

## 1. Building the codebase kernel (Phase 6)

- Input: the composite `kernel_graph` projection (07 Â§2) â€” nodes = symbol versions (current), node weight = frequency (change_count+1), edges weighted by (annealed) type weights Ã— confidence.
- Pipeline (Lodestar, proven at 199K nodes / 2.44M edges): iterative Tarjan SCC â†’ `betweenness_auto` (exact â‰¤2K nodes, else 512 sampled pivots) â†’ candidate scoring `0.40Â·degree + 0.40Â·betweenness + 0.20Â·groundedness` â†’ top ~10% kernel graph â†’ approximate directed FVS (~1%) â†’ grounding-gap report.
- **Groundedness for code** = BFS distance (â‰¤3 hops) to any Trusted anchor (test-covered, trace-confirmed, review-approved). Frequency bonus: `ln(min(freq,10â´)+1)/ln(10â´+1) Ã— 0.15` â€” hot symbols are stronger kernel candidates.
- **Recall gate:** held-out query set (real agent queries logged + synthetic QN lookups) must reach â‰¥ 0.95 recall@10 through the kernel index vs. the full index; below gate â‡’ `refine_kernel_with_recall_support` adds exact-support members and re-measures. The persisted kernel always carries **measured** recall â€” CBM's "99% fewer tokens" claim becomes a gated number.
- Artifacts: `kernel.json` + `index.json` (HNSW over kernel members) per scope, atomic write + readback verify, ledger entry with members-hash + recall metrics.

## 2. Scoped & hierarchical kernels

- **Scopes** (Lodestar scope algebra): `Collection(directory/package)`, `Domain(anchor kind â€” e.g. the incident-explaining kernel)`, `Subgraph(symbol, radius)`, `TimeWindow(t0,t1)`, `Tenant(repo)`, unions/intersections. Cache keyed (scope_hash, panel_version, anchor_identity, corpus_identity); invalidated on panel bump / dirty region.
- **Hierarchical (monorepos):** region graph over packages (inter-region weight = normalized cross-edges) â†’ kernel of regions â†’ drill-down kernels per selected region. Serves the org-brain (Tier 12) and keeps mega-repo builds tractable.
- Standing kernels maintained by the background lane: whole-repo, per-top-level-package, per-service. On-demand scoped kernels built at tool time (seconds at package scale).

## 3. Context packs (the flagship tool â€” `get_context_pack`)

**Contract:** `(task_text, token_budget, scope?, focus_symbols?) â†’ pack` where pack âŠ† corpus, `tokens(pack) â‰¤ budget`, recall-gated, reproducible.

Composition algorithm:
1. **Seed:** fused multi-lens search (12) over task_text (+ focus symbols' neighborhoods) â†’ top-k seeds with per-lens contributions.
2. **Cover:** for each seed, kernel answer-paths (BFS from anchored kernel members, `hop_score = wÂ·0.9^hop`) â†’ the connecting skeleton; collect {kernel members âˆª seeds âˆª path nodes}.
3. **Rank:** score each candidate = Î±Â·seed relevance (fused score) + Î²Â·kernel score + Î³Â·bits-weighted axis relevance (e.g. defect-heavy task â†’ defect-bit-heavy symbols) + Î´Â·recency boost (bounded). Î±..Î´ annealed (14) against agent-outcome anchors.
4. **Select under budget:** greedy by score/token-cost with structural closure rules â€” include signatures of direct callees of any included body; include the file header/imports of any included symbol; include governing ADR sections; prefer *signatures-only* representation for periphery (3â€“10Ã— cheaper than bodies).
5. **Emit:** ordered pack: (a) architecture preamble (scope kernel summary + agreement highlights), (b) task-relevant bodies, (c) periphery signatures, (d) grounding notes (trust tags, gaps touching the pack), (e) provenance manifest â€” `pack_id = blake3(members âˆª hashes)`, per-item CxId + content hash + ledger refs, freshness tags.
6. **Ledger:** the pack is recorded (Answer entry, recorded members + fusion weights + seeds) â‡’ `reproduce(pack_id)` re-derives it bit-for-bit; `answer_trace(pack_id)` explains it.

**Degrade honestly:** if the budget cannot fit gate-passing coverage, the pack says so (`coverage: 0.72, gated: false`) rather than silently truncating â€” the honesty-gate ethos applied to context.

Preset packs: `onboarding` (whole-repo kernel narrative), `subsystem(dir)`, `change(diff)` (impact-tree-driven â€” 11), `debug(failure)` (abduction-driven).

## 4. Kernel answers (`kernel_answer`)

Grounded Q&A: query â†’ kernel-first search â†’ anchored entry point â†’ hop-attenuated answer path â†’ answer assembled from path nodes with per-hop ledger refs. Multi-hop answers require ledger wiring (fail-closed if provenance can't be attached â€” `CALYX_KERNEL_ANSWER_LEDGER_REQUIRED` semantics retained). Returns: answer nodes, path, total score, provenance, trust tag, and â€” when the honesty gate trips â€” a refusal with the deficit.

## 5. Grounding-gap & coverage products

- **Gap report:** kernel members (and regions) with no Trusted anchor within 3 hops â€” the untested/unverified load-bearing code, ranked by kernel score Ã— churn. The single most actionable QA artifact the system emits.
- **Coverage-vs-importance quadrant:** kernel-score Ã— anchor-density scatter â†’ "critical & unverified" quadrant feeds `get_readiness` and the UI overlay.
- **Blast radius (upgraded detect_changes):** changed symbols â†’ impact = answer-path reach through kernel graph with measured edge weights (+ oracle probabilities when available, 11) â€” replaces hopâ†’risk labels; `risk = f(grounded consequence probability, kernel membership, gap exposure)`.

## 6. Incremental kernel maintenance

Dirty-SCC tracking (Lodestar incremental): edge-weight changes mark affected SCCs; node add/remove escalates to full rebuild when SCC structure shifts; `rebuild_dirty` re-runs the pipeline in the background lane; scope cache invalidated per panel/corpus identity. Standing kernels refresh on: N dirty symbols (default 200), panel bump, nightly tick â€” whichever first. Kernel staleness surfaces in freshness tags (`StaleOk{lag}` served by default; `fresh:true` forces rebuild).

## 7. Failure modes (fail-closed)

`ASTRO_KERNEL_UNGROUNDED` (no anchored nodes in scope â€” kernel still built, tagged provisional, gaps=all); recall below gate after refinement â‡’ served with `gated:false` + warning; empty scope â‡’ structured error; budget < minimum viable pack â‡’ explicit refusal with minimum stated.


---

# 10_GUARD.md

# 10 â€” The Guard: Validating Generated Code

Ward, applied to the code domain: every agent-proposed diff is measured through the panel and checked **per-slot** against the repo's own trusted region, with conformally calibrated false-accept rates. This is what makes higher agent autonomy defensible. Doctrine: per-slot, never averaged (A3); fail closed; provisional until calibrated; every verdict ledgered.

## 1. Guard profile design (per repo, per domain)

Domains = (language Ã— scope-class); e.g. `rust/core`, `ts/frontend`. Each domain gets a `GuardProfile` with required slots and per-slot Ï„:

| Guard slot | Panel source | SlotKind | Default target FAR | Catches |
|---|---|---|---|---|
| `code_semantic` | S18 | Content | 0.03 | semantically alien code for this area |
| `struct_trigrams` | S1 | Content | 0.03 | structurally alien constructs |
| `api_callees` | S4 | Content | 0.03 | API misuse / calling things this area never calls |
| `name_semantic` | S20 | Stylistic | 0.05 | naming-convention drift |
| `complexity_profile` | S2 | Stylistic | 0.05 | complexity regime violations (a 400-line function in a small-function repo) |
| `error_surface` | S15 | Content | 0.03 | novel/incorrect error-handling patterns |
| `public_api_signature` | S5+S17 on exported symbols | **Identity** | **0.01** | breaking-change drift on locked APIs |

Combination: `AllRequired` for identity-locked checks; `KofN` (default k = nâˆ’1) for advisory content/style checks. Guard-designated slots stored **raw** (no quantization). Cold-start Ï„ = 0.7 until calibrated; verdicts carry `provisional: true` until then â€” high-stakes mode refuses on uncalibrated (Ward's `validate_high_stakes_profile`).

## 2. Calibration corpus (the â‰¥50 bad-cases problem, solved principledly)

Conformal calibration needs real good/bad cosine populations per slot:

**Good scores** (in-distribution): current HEAD symbols with Trusted anchors (test-covered, survived â‰¥N months, review-approved) vs. their region exemplars â€” thousands available immediately.

**Bad scores** (out-of-distribution / rejected), four independent generators:
1. **Mutation corpus** â€” mutate real symbols (operator swaps, off-by-one, inverted conditions, removed guards â€” cargo-mutants-style, per-language mutators over tree-sitter); mutants are *guaranteed-wrong* code that looks locally plausible: the ideal conformal bad population.
2. **Reverted code** â€” symbol versions from reverted commits (06 Â§2.2): real, historical, repo-specific rejections. Trusted bad-cases.
3. **Alien corpus** â€” same-language symbols sampled from *other* indexed repos: valid code, wrong distribution â€” calibrates "not how we do it here."
4. **Vulnerability patterns** â€” curated known-bad snippets (injection, path traversal, unsafe deserialization) per language: security bad-cases for the strictest slots.

Mix policy: â‰¥50 per slot per domain (Ward MIN_BAD_SCORES), stratified across generators; provenance recorded per calibration set (corpus_hash into `CalibrationMeta`). Recalibration triggers: MMD drift alarm (08 Â§6), rejection-rate drift > 1.5Ã— calibrated FAR (Ward drift monitor), panel bump, quarterly tick.

## 3. The check flow (`guard_check`)

Input: a diff (or candidate file/symbol text) + target location.
1. Parse the diff through libcbm extraction (same tree-sitter path as indexing â€” the candidate is measured by the *identical* instruments).
2. Measure panel slots for each changed/new symbol.
3. Resolve the comparison region: the enclosing scope's trusted exemplars (kernel members + Trusted-anchored neighbors in the same domain), kernel-near first, peripheral fallback (Ward `guard_query_kernel_first`).
4. Per-slot cosine vs. per-slot Ï„ â†’ `SlotVerdict{slot, cos, Ï„, pass}`; combine per policy.
5. Verdict + novelty routing: **accept** / **new-region** (novel-but-plausible: recorded `AwaitingGrounding`, surfaced for human ack) / **quarantine** (hold; e.g. identity-slot near-miss) / **refuse** (OOD with per-slot breakdown: *"api_callees cos 0.31 < Ï„ 0.78 â€” this file never touches the network; proposed code imports reqwest"*).
6. Ledger the verdict (subject = target CxId, full per-slot detail).

Response contract includes: per-slot table, overall, provisional flag, nearest exemplar (for the agent to imitate), and remediation text.

Prompt-injection prose screening uses `astro.guard.prompt_injection_patterns.v1`
and emits provisional `detect_anomalies.kind=prompt_injection` findings plus
context-pack grounding notes. Dependency OOD screening stays explicitly skipped
with `guard_calibration_unavailable` accounting until guard profiles and
purpose slots exist.

## 4. Integration points

- **Tool:** `guard_check` (agent calls before finalizing an edit); `guard_calibrate` (operator/auto).
- **Hook (advisory):** optional PostToolUse on Edit/Write â€” non-blocking, 300ms-budget quick check (S18+S4 only) that annotates the session (CBM hook_augment pattern: never blocks, silent on timeout).
- **Watcher:** each new commit's symbols scored in the background; OOD commits raise a reactive trigger (`NewRegion`) â†’ review surface.
- **Identity lock:** exported/public symbols get identity profiles (locked signature+behavior slots); `guard_check` on a diff touching them enforces Identity FAR 0.01 â€” breaking-change protection measured, not linted.
- **Autonomy dial (Tier 12):** policy hook â€” `auto-apply allowed iff readiness(scope)=green âˆ§ guard verdict=accept âˆ§ FAR(domain) â‰¤ threshold`.

## 5. Drift & lifecycle

Rolling per-slot rejection rates monitored (window 500); drift events â†’ Anneal recalibration proposals (shadow-tested; Ï„ changes are reversible pointer swaps with tripwires GuardFAR > 0.01, GuardFRR > 0.05). Guard health (per-slot FAR/FRR/drift/last-calibrated) surfaces in `optimizer_status` and `get_readiness`.

## 6. Honest limits (stated, not hidden)

The guard measures *distributional conformance*, not correctness â€” it catches alien/unsafe/convention-violating code, not subtle logic bugs (that's the oracle's impact prediction + tests). False-reject friction is tunable per team via target FAR; `new-region` (not refusal) is the default for novel-but-plausible code, so innovation isn't punished â€” it's *recorded and confirmable*.


---

# 11_ORACLE.md

# 11 â€” The Oracle: Prediction, Abduction, Honesty

Grounded foresight over code: what breaks, why it broke, what's missing, when it recurs â€” every claim capped by measured ceilings and refused when the panel can't carry it.

## 1. Evidence substrate (what predictions are grounded IN)

The oracle consumes **recurrence evidence**: per-series occurrence streams with outcome contexts (Poly/Calyx `oracle_predict` pattern). The anchor pipeline (06) writes, per commit:

```
occurrence(series=symbol S, t=commit_time, context={
  action: "change" | "add" | "delete" | "rename",
  commit, diff_stats, agent?: bool,
  outcomes: [ {kind: test_fail, test: QN, run: ci_ref, lag_s},
              {kind: incident, sev, lag_s},
              {kind: revert, lag_s}, â€¦ ]   // outcomes observed within the attribution window
})
```
Attribution window default 14 days, decayed; multi-cause commits split credit across touched symbols (uniform v1, bits-weighted later). This is the mined **changeâ†’consequence corpus** â€” the single new data structure the oracle needs; everything else is stock Calyx.

## 2. Change-impact prediction (`predict_impact`)

Input: symbol(s) + change kind (or a concrete diff).
1. **Direct evidence:** bucket historical outcomes of changes to this series (and its L2-similar peers when thin â€” clearly marked cohort evidence): `raw_confidence = support Â· separation Â· sample_support`.
2. **Butterfly expansion:** consequence tree over the composite graph (calls + DATA_FLOWS + DRIVES + service edges), depth â‰¤ 4, per-hop attenuation Ã—0.7, prune < 0.05, cycle-guarded; children are **data-driven** â€” only consequence edges observed in the evidence corpus expand (grounded), structural-only edges emit provisional leaves.
3. **Ceilings:** every branch confidence = `min(raw, self_consistency(test), dpi_ceiling(panel))` â€” flaky tests can't inflate certainty; never reaches 1.0.
4. Output: ranked consequences `{target (test/route/service), p, hop path, evidence n, trust}`, + the **test-selection set** (consequences âˆ© TESTS edges, ranked by p â€” "run these 12 tests, they carry 91% of observed failure mass for this area").
5. Honesty: insufficient evidence â‡’ explicit `Insufficient{per-sensor deficit}` â€” *"No grounded change history for this module; 0.8 bits short. Run the suite once via anchor_outcome to bootstrap."*

Backtest gate (Poly `backtest.rs` pattern, capability 12.7): before the tool advertises grounded confidence for a repo, a held-out backtest over historical fix-commits must beat the hop-distance baseline (`beats_baseline` or the report says so). Honest by construction.

## 3. Root-cause abduction (`abduce_cause`)

Input: a failing test / incident / anomalous symbol. Reverse walk (depth â‰¤ 3) over inverted consequence evidence + structural edges: candidate causes ranked by grounded confidence `n/(n+1)` (observed cause-count), recency-weighted; structural-only candidates marked provisional (0.35 default). Cross-checks: recent-change intersection (candidates that changed within the window rank up), lead/lag arrows (a DRIVES edge into the failure region is strong evidence). Output: ranked causes with paths, commits, and the *disconfirming test* to run per hypothesis.

## 4. Imputation & completion (`impute_fields`)

Energy-descent completion from trusted-region attractors, honesty-gated:
- missing/weak docstrings â†’ proposed from nearest trusted exemplars' doc slots (tagged `inferred`, guard-checked before suggestion â€” capability 12.4);
- unresolved dynamic callees â†’ most-probable targets with confidence (improves graph completeness; edges written as provisional);
- missing types (dynamic langs) â†’ inferred type surface;
- untested symbol â†’ the most similar tested exemplar (test-writing aid).
Every filled value carries `inferred|provisional` tags; never silently merged into trusted data.

## 5. Forecasting (`forecast`)

Per series: next-occurrence time (median cadence + MAD interval, regularityÂ·support-weighted confidence), overdue hazard (renewal), periodicity fits, CUSUM regime changes. Products: flaky-test next-failure windows; hotspot re-churn predictions ("this file's cadence says it changes again within ~9 days â€” schedule the refactor now"); dependency-update rhythm; stale-area detection.

## 6. Readiness predicate (`get_readiness`)

Per scope, the falsifiable conjunction (super_intelligence pattern, code-domain thresholds):
1. **oracle-clean** â‰¥ 0.7 â€” anchor self-consistency ceiling (flakiness under control)
2. **panel-sufficient** â€” `I(panel;axis) â‰¥ H(axis)` for the axis in question
3. **kernel-exists** â€” scope kernel recall â‰¥ 0.95, tested
4. **calibrated** â€” guard Ï„ calibrated within ceiling
5. **Goodhart-defended** â€” gaming checks pass (g(Ï„) â‰¥ 0.9)
6. **mistakes-closed** â€” no recurring closed-mistake regressions
Output: per-tier pass/fail + measured value + **cheapest fix** for the first failing tier. This is the trust dial for agent autonomy and the operator's investment guide.

## 7. Failure modes

All fail-closed with remediations: `ASTRO_ORACLE_INSUFFICIENT` (+deficit), `ASTRO_NO_RECURRENCE` (no history â€” bootstrap instructions), `ASTRO_FLAKY_EVIDENCE` (ceiling collapsed below usefulness; names the flaky tests), backtest-not-beaten (grounded mode disabled, structural mode offered). The oracle never emits an ungated confident answer â€” that property, verbatim from Calyx, is the product.


---

# 12_SEARCH.md

# 12 â€” Search Unification

Today CBM has four disjoint search paths (FTS5/BM25, regex scan, int8-cosine vector scan, grep subprocess) with a fixed first-keyword-sorts quirk and separate CLI/MCP behaviors. Target: **one Sextant-fused engine** over per-slot indexes, with the legacy paths preserved as compatibility modes during migration.

## 1. Per-slot index plan

| Slot | Index | Notes |
|---|---|---|
| S7 identifier_lexical | inverted + BM25 (k1=1.2, b=0.75) | replaces FTS5 semantics incl. camelCase splitting (tokenizer parity tested) |
| S18 code_semantic / S19 doc / S20 name | HNSW (M=32, deterministic levels) on quantized vectors | replaces the `cbm_cosine_i8` full-scan; per-keyword min-cosine semantics preserved as a fusion mode |
| S1 struct_trigrams / S4 api_callees / other sparse | SPANN (centroids + posting lists) or inverted | MinHash/LSH retained as candidate accelerator |
| S21 record_vec / S2 metrics | HNSW small | "find similar metric profile" |
| S22 token_multi (optional) | MaxSim late interaction | precision reranking |
| kernel members | kernel HNSW | kernel-first funnel entry |

All indexes carry `built_at_seq`/`base_seq` freshness (StaleOk default, Fresh on demand); rebuilt incrementally; regenerable tier.

## 2. Query pipeline

`search_graph` (upgraded, backward-compatible):
1. **Intent classification** (deterministic keyword classifier + explicit `fusion` override): lexical / semantic / structural / api / general â†’ RRF profile.
2. **Planner caps:** k â‰¤ 100, ef â‰¤ 512, slots â‰¤ 16, cost cap, timeout â€” planner-enforced, fail-closed (`PLAN_COST_EXCEEDED`), replacing unbounded scans.
3. **Per-slot search** (only slots in the profile) â†’ **RRF fusion** `Î£ w_slot/(60 + rank)`; profile weights start uniform, annealed per repo (14).
4. **Filters:** label/file/degree/scalar predicates (exact-value filtering on `scalars` â€” the structured half never went through an embedding, so filters stay exact).
5. **Temporal boost** (bounded Î± â‰¤ 0.10, never dominant) â€” recency nudges only.
6. Optional **guard mode** (`in_region_only`): Ward-filtered results with dropped-hit accounting (high-stakes retrieval).
7. Optional **rerank** (cross-encoder lens if enabled): pipeline strategy, request-scoped candidate text, never persisted.
8. Hits carry: per-lens contributions (explain mode), provenance refs, freshness tags, trust tags.

## 3. Path-by-path disposition of existing search

| Existing | Disposition |
|---|---|
| FTS5 BM25 (`query`) | â†’ S7 BM25 lens; FTS5 kept in lowered artifact for legacy/UI |
| `name_pattern`/`qn_pattern` regex | kept as exact-scan filter stage (regex over metadata; bounded by planner) |
| `semantic_query` min-cosine | â†’ fusion mode `semantic` with min-cosine aggregation preserved |
| `search_code` grep | **unchanged** (raw text is raw; graph-augmented dedup/rank retained) |
| Cypher `query_graph` | unchanged against lowered SQLite (8.10); gains `as_of` (time-travel) param resolved via MVCC snapshot â†’ temporally-consistent lowered view |
| `trace_path` BFS | upgraded: weighted best-first with Ã—0.9 hop attenuation + measured edge weights; plain-BFS mode kept for compat |
| hook-augment quick lookup | switched to kernel-first probe (cheap, most-relevant-first) |

## 4. Navigation additions

`find_similar{by: structural|semantic|api|profile|co_change}`, `agree`/`disagree` (cross-lens consensus/anomaly â€” clone taxonomy 8.3), `define` (association-derived definition), `traverse` (scored walks, direction-aware), `skills` (HDBSCAN capability tree) â€” all direct Sextant features exposed once slots exist.

Skill discovery artifacts use `astrolabe.skill_tree.v1` and
`astro.kernel.skill_discovery_knobs.v1`: cluster membership is deterministic,
singleton/noise symbols remain outside skills, each skill has a membership hash,
and `skills` search is a scope/filter mode rather than a new top-level tool.
The current seed implementation uses registry-declared token-overlap knobs for
artifact/search contract tests; HDBSCAN/vector clustering replaces only the
cluster producer, not the artifact contract.

## 5. Scale posture

Default in-RAM HNSW at repo scale (â‰¤1M symbols fine); DiskANN/SPANN builds offered for monorepos; kernel-first funnel activates > 10M records (org-vault). Quantized (3.5-bit) vectors in indexes with measured-recall gate; raw rescoring for top-k.

Scale posture is planned through `astro.kernel.search_scale_knobs.v1`, not an
inline threshold: `search.funnel.activation_records` defaults to 10M records,
activation is surfaced in explain output, DiskANN/SPANN are explicit config
opt-ins, and estimated per-slot index RSS must fit the CBM master budget before
an index load proceeds. Over-budget plans fail closed with
`ASTRO_SEARCH_INDEX_BUDGET_EXCEEDED` and remediation.


---

# 13_PROVENANCE.md

# 13 â€” Provenance & Trust

The ledger makes ASTROLABE the first coding MCP whose answers are *verifiable claims* rather than assertions. Everything below is stock Calyx Ledger wired to the code domain.

## 1. What gets ledgered (append-only BLAKE3 hash chain, Merkle checkpoints @1000, optional Ed25519)

| EntryKind | Written when | Payload (hashes/ids only â€” never source text, never secrets) |
|---|---|---|
| Ingest | index/incremental batch | counts, input fingerprint, commit sha, panel version |
| Measure | slot backfills / lens swaps | lens id, weights sha, slot, cx count |
| Grounding | every anchor attach | anchor kind/source/confidence, cx/series ids |
| Assay | every bits/sufficiency card | subject, axis, bits, ci, estimator, n |
| Kernel | kernel build/refresh | scope hash, members hash, recall metrics |
| Guard | calibration + every verdict | profile hash, per-slot cos/Ï„, verdict |
| Answer | packs, kernel answers, predictions | recorded seeds/slots/weights, member hashes (reproduce inputs) |
| Anneal | every promote/revert | change id, prior/candidate ptr hashes, metric snapshot |
| Admin | checkpoints, erasures, lowered-artifact exports | Merkle root, artifact fingerprint |

## 2. Verification surfaces

- **`verify_chain`** â€” re-walk + re-hash; Intact/Broken{seq}/Corrupt{seq}. Runs: on open (fast tail check), scheduled loop (calyxd pattern), in CI (`astrolabe cli verify_chain`), before team-artifact export/import. Broken â‡’ quarantine range, fail closed, reindex guidance.
- **`answer_trace(answer_id)`** â€” the full lineage of any pack/answer/prediction: kernel entry, hops with ledger seqs, fusion weights, guard verdict, freshness; incomplete lineage returns explicit `unprovenanced` warnings â€” never fabricated links.
- **`reproduce(answer_id)`** â€” re-derive with frozen lenses + recorded seeds; drift bound 1e-3; `REPRODUCE_DRIFT_EXCEEDED` on failure. This is the intelligence layer's regression test: run nightly over a sample of recent answers.
- **Inter-agent trust:** pack manifests embed `(pack_id, ledger_ref, vault fingerprint)`; a second agent (or reviewer) verifies a claimed context with one tool call. Multi-agent pipelines get checkable citations.

## 3. Trust surfaces in every response

Every tool response carries: `trust: trusted|provisional` (anchor roll-up), `freshness: {built_at_seq, stale_by}`, `provenance: ledger_ref`, and confidence values that are *ceilinged* (11). No unlabeled claims anywhere in the surface â€” the response schema makes dishonesty a type error.

## 4. Team artifact, upgraded (9.8)

`.codebase-memory/graph.db.zst` (lowered SQLite) continues for zero-friction sharing; adds sibling `vault.export.zst` + `artifact.json{schema_version, ledger_head, merkle_root, signature?}`. Import verifies: chain intact â†’ root matches â†’ optional signature â†’ then adopt; any failure â‡’ refuse + local reindex (CBM's existing fallback). Result: pull a teammate's pre-built index *with tamper evidence*.

Team artifact status: `astrolabe.team_artifact.v1` lives in `astrolabe-lower`. Export retains `graph.db.zst`, writes `vault.export.zst`, records compressed/uncompressed graph hashes, ledger head, Merkle root, and optional Calyx Ed25519 root signature in `artifact.json`. Import delays adoption until graph bytes, vault export bytes, chain continuity, ledger head, Merkle root, and optional expected signer all verify; each refusal carries a stable `ASTRO_TEAM_ARTIFACT_*` component code. Plain legacy `graph.db.zst` imports are still accepted and labeled `legacy_unverified`. Remaining #62 work is live server wiring, local reindex fallback invocation, and the unified diagnostics/health surface with periodic `verify_chain`.

## 5. Erasure & redaction

- Redaction policy on every payload writer (secret-shaped keys/tokens rejected â€” CALYX_LEDGER_SECRET_IN_PAYLOAD; CBM's secret filters remain upstream at extraction).
- Lawful/user erasure (proprietary snippet, leaked credential in history): erase scope (cx/series/vault) via append-only erasure tombstones; derived artifacts (indexes, lowered SQLite, packs) regenerate without the erased content; the tombstone itself is the audit record.

Redaction audit status: `ci/redaction-writers.json` plus `scripts/check-redaction-writers.py` enumerate all Astrolabe production ledger writer call sites and require a payload contract plus coverage note for each new writer. `astrolabe-ingest` now proves both direct append and batch-with-ledger writes reject secret-shaped payloads before ledger/data rows land. Remaining #61 work is the end-to-end erasure byte sweep, derived artifact regeneration after tombstones, egress-denying harness, subprocess shell-arg static audit, and loopback UI binding verification.

## 6. MVCC time-travel audit (9.7)

`as_of(t)` reads pin a snapshot: "what did the graph believe when the agent made that change?" â€” pairs with the ledger to reconstruct any historical decision context; retention horizon configurable (default: keep all â€” code vaults are small relative to media).


---

# 14_SELF_OPTIMIZATION.md

# 14 â€” Self-Optimization (Anneal)

The subsystem that makes the flywheel spin: per-repo, reversible, shadow-tested tuning of everything that is currently a guessed constant. Nothing promotes without beating the incumbent on held-out replay; everything is one-swap reversible; every change is ledgered.

## 1. What gets tuned (the knob inventory)

| Knob family | Initial value | Tuned against |
|---|---|---|
| RRF fusion weights per intent profile (12) | uniform | recall@k on held-out replay of **real agent queries** (logged, anonymized to query-shape) + Reward anchors on packs |
| Context-pack scoring Î±/Î²/Î³/Î´ (09 Â§3) | 0.4/0.3/0.2/0.1 | agent-outcome anchors (task success given pack) |
| Similarity admission thresholds + per-node caps (07 Â§3) | CBM's 0.95/0.75/10 | bits-about-co-failure per edge budget |
| Edge-type weights in kernel_graph (07 Â§2) | v1 table | kernel recall + grounded-answer hit rate |
| Guard Ï„ per slot/domain (10) | conformal calibration | FAR/FRR targets (recalibration, not free tuning) |
| Quantization levels per slot (05 Â§5) | 3.5 bpc dense | recall/bits/FAR non-regression (measured compression) |
| HNSW ef/M, index params | 64/32 | p99 vs recall tripwires |
| Assay sampling sizes / refresh cadences | 4096 / nightly | CI width targets vs budget |
| Oracle attribution window, cohort widths (11 Â§1) | 14d | backtest lift |

## 2. The loop (stock Anneal, code-domain replay)

prepare (reserve rollback: prior artifact pointer kept) â†’ budget (background lane only: 15% CPU default, cooperative ticks, VRAM 0 in CPU builds) â†’ **shadow-test** on held-out replay â†’ gate (tripwires + per-metric non-regression) â†’ promote (single pointer swap + ledger `AnnealLedgerAction::Promote`) or revert (automatic, ledgered). Bandit (Îµ-greedy default) over candidate configs with 3-consecutive-win hysteresis; A/B runner for live-traffic comparisons of search configs.

**Replay corpus:** (a) logged agent queries with judged relevance (Reward-anchored packs give labels for free); (b) synthetic QN/lookup probes; (c) historical backtest tasks (fix-commit â†’ did the pack contain the fix location?). Deterministic sampling (ChaCha8, seeded).

## 3. Tripwires (auto-revert, 5% hysteresis)

`recall@k < 0.90` Â· `guard FAR > 0.01` Â· `guard FRR > 0.05` Â· `search p99 > 200ms` Â· `ingest p95 > 500ms` â€” any crossing reverts the change and logs it. Plus Goodhart defense before promotion: g(Ï„) gaming check â‰¥ 0.9, single-lens dominance â‰¤ 0.8 (no degenerate "optimize by collapsing to one signal"), held-out gain â‰¥ 1%.

## 4. Deficit-driven lens proposal (the growth loop)

Sufficiency deficits (08 Â§2) â†’ `propose_lens`: localize the gap (which axis, which stratum) â†’ synthesize candidates from the code-domain template library: new derived-metric lenses (ratios/aggregates over existing scalars), new hashed-set lenses over unexploited fields (e.g. lock/atomic usage set, SQL-table-touch set, feature-flag set), interaction lenses for measured-synergistic pairs, PCA/frequency lenses over existing slots â†’ differentiation gate (â‰¥0.05 bits, â‰¤0.6 corr, profile timeout 30s) â†’ shadow â†’ hot-add with lazy backfill on win â†’ re-measure sufficiency; no gain â‡’ rollback + record. Terminal states all ledgered (Admitted / GateRejected / NoSufficiencyGain / SubstrateReverted).

## 5. Mistake closure ("wrong only once")

Wrong predictions (impact said safe â†’ test failed; abduction ranked wrong cause; pack missed the fix file) become mistake records: surprise-weighted replay buffer (cap 4096) â†’ sleep-pass updates to small online heads (pack-ranker head, impact-adjustment head; â‰¤1024 params â€” frozen lenses never touched) â†’ regression assertion: replayed mistakes must not recur (strict 0% in sleep pass) or the head update rolls back. The system provably does not repeat a recorded mistake.

## 6. Ops surface

`optimizer_status`: tripwire states, budget usage, recent changes (last 16 ledger entries), pending proposals, guard health, drift alarms. Janitor bounds artifact buildup (100 MiB/tick). Kill switch: `ASTRO_ANNEAL=0` freezes all tuning (serving unaffected); per-knob freeze supported. Everything reversible via `rollback(change_id)` until explicitly committed.


---

# 15_MCP_SURFACE.md

# 15 â€” The MCP Tool Surface

Design constraints: (a) 100% behavioral compatibility for the 14 existing CBM tools (agents already installed keep working); (b) new capabilities consolidated by *mode parameters* to keep tool-count/token-cost sane (~29 total, paginated `tools/list` already supported); (c) every response carries `trust`, `freshness`, `provenance`; (d) every tool also invokable via `astrolabe cli <tool> '<json>'`.

## 1. Retained tools (14) â€” compatibility + upgrades

| Tool | Compatibility | Upgrade (additive params/fields) |
|---|---|---|
| `index_repository` | args/return unchanged | + `calyx: off\|shadow\|primary` (migration dial, 18); builds constellations/weave/anchors per phase; returns `vault_fingerprint`, `grounding_summary` |
| `list_projects` | unchanged | + per-project `trust`, `anchored_pct`, `readiness_lite` |
| `delete_project` | unchanged | also removes vault + tombstoned ledger close-out |
| `index_status` | unchanged | + vault/ledger head, panel version, background-lane queue depths |
| `search_graph` | all existing params honored | + `fusion_profile`, `guarded`, `explain` (per-lens contributions), `as_of` |
| `trace_path` | unchanged default | + `scored: true` (attenuated best-first), measured edge weights, trust tags |
| `detect_changes` | unchanged shape | + `grounded_risk` (oracle-backed probabilities replacing hopâ†’risk when evidence exists; falls back with `trust: provisional`) |
| `query_graph` | Cypher subset unchanged (runs on lowered SQLite) | + `as_of` (time-travel snapshot lowering) |
| `get_graph_schema` | unchanged | + slot/lens inventory, anchor-axis counts |
| `get_code_snippet` | unchanged | + `cx_id`/`series_id`, trust/anchor summary per symbol |
| `get_architecture` | unchanged aspects | + aspects: `kernel`, `agreement_graph`, `grounding_gaps`, `signal_ranking`, `n_eff` |
| `search_code` | unchanged (grep is grep) | â€” |
| `manage_adr` | unchanged | + `link` mode: bind ADR sections to kernel members; drift flag when architecture moves |
| `ingest_traces` | **implemented** (was a stub) | OTLP + simple format â†’ edge promotion + anchors (06 Â§2.3); returns promoted-edge counts |

## 2. New tools (15)

### Grounding & measurement
**`anchor_outcome`** â€” the feedback intake. Params: `project`, `kind` (`test_run|agent_task|review|incident|manual_label`), payload per kind (JUnit/pytest/cargo/go-test parsers built in; `{caller,callee,count}` traces go to `ingest_traces`), `source`, `confidence?`. Returns: anchors written, promotions triggered, grounding delta. *The single most important new tool â€” everything downstream feeds on it.*

**`measure_bits`** â€” modes: `signals` (ranking per axis), `sufficiency` (+deficits), `redundancy` (n_eff, gate decisions), `synergy`, `causality` (DRIVES/TE), `calibration` (edge-strategy precision). Params: `project`, `mode`, `axis?`, `scope?`, `refresh?`. Returns the corresponding assay card (08 Â§8) with CIs and trust tags.

### Kernel & context
**`get_kernel`** â€” modes: `read|build|gaps|bridges|summarize`. Params: `project`, `scope?` (dir/domain/subgraph/time-window expr), `budget?`; for `bridges`, `scope_a` and `scope_b` are required. Returns members (QN + kernel score + grounded flag), recall metrics, gap report, bridge members ranked by combined kernel weight, or a structural scope summary.

Bridge substrate status: `astrolabe.bridge.v1` lives in `astrolabe-kernel` as the P8.7 contract. It returns symbols present in both scope kernels, carries per-scope ledger provenance, labels ungrounded scopes `trust: provisional`, and uses `astrolabe.bridge_cache_key.v1` derived from both scope dirty-region hashes so either side invalidates the cache. Direct `CROSS_*` route/channel edges resolve as cross-vault bridge chains with per-hop provenance; unresolved counterpart vaults fail closed with `ASTRO_BRIDGE_MISSING_COUNTERPART_VAULT` instead of returning a silent empty result. Declared-vs-measured boundary diffs are produced from bridge reports and are consumed by `get_architecture`, not exposed as a new top-level tool.

Label/summarization substrate status: `astrolabe.label_propagation.v1` and `astrolabe.scope_summary.v1` live in `astrolabe-kernel` as the P7.10 contract. Label propagation uses the registered `astro.kernel.label_propagation_knobs.v1` decay knob, returns only inferred labels as `trust: provisional`, records seed and graph provenance, treats zero-seed scopes as explicit empty results, and supports exact label filters for search integration. Scope summaries are `get_kernel` mode `summarize`: the summary is the scope kernel members plus measured recall, grounded fraction, deterministic summary hash, and cold-start provisional trust. Live Lodestar harmonic propagation, ledger writes, background-lane scheduling, and search_graph/server wiring remain the next integration layer.

**`get_context_pack`** â€” the flagship (09 Â§3). Params: `project`, `task`, `token_budget`, `scope?`, `focus?`, `preset?` (`onboarding|subsystem|change|debug`). Returns the ordered pack + manifest (`pack_id`, hashes, coverage, gated flag, trust).

**`kernel_answer`** â€” grounded Q&A. Params: `project`, `query`, `scope?`. Returns answer nodes, hop path with ledger refs, confidence (ceilinged), or honest refusal with deficit.

### Navigation & anomaly
**`find_similar`** â€” modes: `structural|semantic|api|profile|co_change|agree|disagree|define`. Params: `project`, `symbol` (QN/cx), `k?`. Clone-taxonomy classification included for `agree/disagree`.

**`detect_anomalies`** â€” blind-spot sweep + drift alarms + doc-drift/name-truth mismatches + OOD commits + `prompt_injection` prose findings. Params: `project`, `scope?`, `kind?`. Returns ranked findings with severities and per-lens evidence.

Anomaly aggregation status: `astrolabe.detect_anomalies.v1` lives in `astrolabe-weave` as the P7.9 contract for the remaining kinds: `doc_drift`, `name_truth`, `drift`, and `ood_commit`. Severity thresholds are supplied as per-kind calibration rows with provenance, not fixed globally. Aggregation is deterministic across kinds, clean rows below calibrated severity are not emitted, missing calibration is reported as a skipped substrate rather than silently guessed, invalid `kind` filters fail closed with `ASTRO_ANOMALY_INVALID_KIND`, and cold-start vaults still run with `trust: provisional`. Live server wiring still has to read real xterm/assay/reactive CF rows and merge this contract with `blind_spot`/`prompt_injection` producers.

### Guard
**`guard_check`** â€” validate a diff/candidate (10 Â§3). Params: `project`, `diff|content+path`, `high_stakes?`. Returns per-slot verdict table, overall, nearest exemplar, remediation.
**`guard_calibrate`** â€” build/refresh calibration (operator). Params: `project`, `domain?`, `sources?`. Returns per-slot Ï„/FAR/FRR + corpus provenance.

### Oracle
**`predict_impact`** â€” params: `project`, `symbols|diff`, `depth?`. Returns consequence tree, test-selection set, confidence + ceilings, or refusal (11 Â§2).
**`abduce_cause`** â€” params: `project`, `failure` (test QN/incident ref/symbol). Returns ranked causes + disconfirming tests (11 Â§3).
**`impute_fields`** â€” params: `project`, `target`, `field` (`doc|types|callees|tests`). Returns proposals tagged inferred/provisional (11 Â§4).
**`forecast`** â€” params: `project`, `series` (test/file/symbol), `kind?`. Returns next-occurrence interval, hazard, periodicity, regime changes (11 Â§5).

### Trust & ops
**`get_provenance`** â€” modes: `lineage` (symbol history), `answer_trace(answer_id)`, `verify_chain(range?)`, `reproduce(answer_id)`. One tool, four verifications (13).

Provenance surface status: `astrolabe.get_provenance.v1` and `astrolabe.inter_agent_trust.v1` live in `astrolabe-provenance` as the P6.9 contract. The contract pins the four modes, `{trust,freshness,provenance,warnings}` envelope, unknown-mode and missing-subject refusals, explicit `unprovenanced` answer-trace warnings, `REPRODUCE_DRIFT_EXCEEDED`, and one-call pack manifest verification across `(pack_id, ledger_ref, vault_fingerprint, member_hash)`. Live MCP/CLI wiring still has to scan persisted ledger/series rows, wrap the existing `verify_chain`, and run the inter-agent round-trip through separate server processes.

**`get_readiness`** â€” params: `project`, `scope?`, `axis?`. Returns the six-tier predicate with measured values + cheapest fix (11 Â§6).
**`optimizer_status`** â€” anneal state: tripwires, recent changes, proposals, guard health, budget (14 Â§6). (Also: `propose_lens` folded here as mode `propose` â€” runs the deficitâ†’candidate pipeline on demand.)

## 3. Response envelope (uniform)

```json
{ "content": [{"type":"text","text":"<json>"}], "structuredContent": {...}, "isError": false }
```
Inner JSON always includes: `trust`, `freshness {seq, stale_by}`, `provenance {ledger_seq, chain_hash}`, `warnings []`. Errors: `{code, message, remediation}` with `ASTRO_*`/`CALYX_*` codes; tool errors are `isError:true` results (never protocol errors) â€” both conventions inherited and unified.

## 4. Hooks & agent integration (inherited network, upgraded)

- **PreToolUse (Grep|Glob)** augmenter: kernel-first probe (top graph hits + kernel membership + hazard notes), same 300ms/never-blocks contract.
- **PostToolUse (Edit|Write)** *(new, optional, advisory)*: quick guard check (S18+S4), non-blocking, annotates session context; full check only via explicit `guard_check`.
- **SessionStart**: readiness summary + kernel one-pager + ADR + unacknowledged reactive triggers ("2 new-region events since yesterday").
- **Stop/afterTask** *(new, optional)*: prompts the `anchor_outcome{agent_task}` call â€” the flywheel closer.
- **Skills**: `codebase-memory` skill rewritten for the new surface: the decomposeâ†’groundâ†’measureâ†’distillâ†’compose usage doctrine, tool selection guide, the honesty-gate etiquette ("when refused, run the suggested anchor bootstrap").
- Installer (13 agents) unchanged mechanically; instructions/skills content updated.

## 5. Deprecations & aliases

`trace_call_path` alias retained. Legacy `search_graph.semantic_query` array semantics preserved verbatim. No tool removed. Tools added = 15; total â‰ˆ 29. `tools/list` pagination (8/page) already handles the count.


---

# 16_INCREMENTAL_REACTIVE.md

# 16 â€” Incremental Indexing, Watcher, Reactivity & Time-Travel

The steady-state loop: a file changes; within seconds the graph, the vault, the associations, and the derived intelligence converge â€” incrementally, with bounded work, and with history preserved.

## 1. The incremental pipeline (change â†’ convergence)

```
watcher detects (HEAD move / dirty tree, adaptive 5â€“60s poll)
  â†’ supervised incremental index (CBM: mtime+size classify â†’ re-extract changed files only,
    registry re-seed from survivors, inbound-edge snapshot/restore)         [seconds]
  â†’ ingest delta: new symbol versions (new CxIds), unchanged symbols no-op (content address),
    series registry updated, recurrence(change) occurrences appended        [sub-second]
  â†’ weave delta: re-point live edges to new versions (CBM snapshot pattern),
    dirty-region L2 re-kNN, eager cross-terms recomputed for changed symbols
  â†’ reactive triggers evaluate (new-region / recurs / drift) â†’ subscriptions
  â†’ invalidations: assay strata marked dirty; kernel dirty-SCC marked; guard drift counters
  â†’ background lane (budgeted): re-assay dirty strata, kernel rebuild_dirty when threshold hit,
    lowered SQLite artifact refresh (debounced), pack caches invalidated by scope
```

Key inherited mechanics, unchanged: CBM's mtime+size classification, deleted-vs-mode-skipped distinction, inbound-edge snapshot keyed by QN (survives re-parse), incremental parallel threshold (>50 files), watcher stale-root pruning, pipeline global lock with watcher try-lock/skip. Key Calyx mechanics: content-address idempotency (unchanged symbols are free), MVCC (readers never blocked by the writer), lazy backfill queues for new lenses.

## 2. Versioning semantics on change

- Changed symbol â‡’ new **version** (CxId), same **series**; old version's constellation, slots, anchors, and edges remain (MVCC + append-only), enabling as_of reads and evolution analysis.
- Live graph projections and indexes reference *current* versions; historical edges retrievable by snapshot.
- Renames: CBM rename detection (git R-status) links series (`renamed_from` metadata + series continuity) instead of forking a new series.
- Version GC policy: raw slot payloads of superseded versions may be cold-tiered/pruned by retention policy (default: keep everything; code is cheap); anchors and ledger are sacred, never pruned.

## 3. Reactive triggers (Loom engine, bounded & audited)

| Trigger | Fires when | Consumers |
|---|---|---|
| `NewRegion` | new/changed symbol lands outside trusted regions (guard novelty) | review surface, SessionStart hook note, quarantine list |
| `EventRecurs{series,n}` | Nth failure of a test / Nth hotfix of a file (threshold crossing, exactly-once) | forecast refresh, "chronic offender" report |
| `DriftDetected{slot,Î¸}` | watched symbol's slot drifts â‰¥ Î¸ vs prior version | doc-drift alerts, guard recalibration counters |

All registry/queue/audit caps bounded (1024/4096/64K); every evaluation audited; subscriptions drainable via `optimizer_status` and hooks.

## 4. Time-travel & historical analysis

- `as_of(t)`: MVCC snapshot reads over the vault; `query_graph{as_of}` lowers a temporally-consistent SQLite view (cached per t-bucket).
- Backtesting (11 Â§2, 12.5 counterfactuals) runs entirely on this substrate: rebuild "the graph as of commit C" cheaply (snapshot, not reindex), ask the oracle, compare with what actually happened.
- Retention: `time_index` CF maps wall-clockâ†’seq; default retention unlimited; configurable horizon with fail-closed `BEFORE_HORIZON` errors.

## 5. Consistency & freshness contract

- Serving reads default `StaleOk{lag}` with explicit freshness tags; `fresh: true` forces synchronous convergence of the touched scope (bounded wait, else honest timeout).
- The lowered SQLite artifact carries its vault fingerprint; legacy tools reading a stale artifact surface `stale_by` in responses.
- Invariant: no tool ever serves silently-stale *trusted* claims â€” staleness is always labeled (fail-closed on the labeling path, not on availability).


---

# 17_PERFORMANCE_SCALE.md

# 17 â€” Performance & Scale Budgets

Honest accounting: what the fusion costs, where the quadratic traps are, and the controls that keep a Linux-kernel-scale repo tractable on a laptop. Reference envelopes: **S** = 2K symbols/20K edges (typical service), **M** = 50K/500K (large app), **L** = 500K/5M (Linux-kernel class; CBM proven; Calyx kernel proven at 199K/2.44M).

## 1. Wall-time budgets (CPU-only, 8 workers)

| Stage | S | M | L | Controls |
|---|---|---|---|---|
| CBM extraction+resolve (existing baseline) | ~5s | ~2min | ~30min | unchanged (worker pool, LZ4, retention caps, supervisor) |
| Panel measurement (22 lenses, all deterministic/lookup) | +1s | +20s | +4min | vectorized encoders; nomic lookup is memory-bandwidth-bound; embarrassingly parallel |
| Vault ingest (constellations + edges) | +1s | +15s | +3min | Aster group-commit batching; single fsync per batch |
| L2 kNN + eager cross-terms | +1s | +30s | +6min | LSH candidates (existing), quantized HNSW build; per-slot opt-out at L |
| Lowered SQLite regen | +1s | +10s | +2min | streaming writer (CBM raw page writer reused) |
| **Full-index overhead target vs baseline** | **â‰¤1.3Ã—** | **â‰¤1.3Ã—** | **â‰¤1.5Ã—** | gate in CI benchmarks |
| Incremental (1 file) | <2s | <3s | <5s | dirty-scope only |
| Kernel build (background) | <5s | <60s | <8min | sampled betweenness (512 pivots), iterative SCC â€” proven numbers |
| Nightly assay sweep (background) | <2min | <15min | <45min | stratified sampling â‰¤4096/estimate, budgeted lane |
| Guard calibration (background) | <2min | <10min | <30min | per-domain, mutation corpus cached |

Serving targets: `search_graph` p99 â‰¤ 50ms warm (tripwire 200ms); `get_context_pack` â‰¤ 2s (standing kernels) / â‰¤ 15s (cold scoped kernel); `guard_check` (single diff) â‰¤ 1s; `predict_impact` â‰¤ 2s.

## 2. The quadratic traps & their controls

| Trap | Naive cost | Control |
|---|---|---|
| Cross-terms C(22,2)=231/symbol | O(231Â·n) vectors | 6 eager scalars + gated interactions + lazy rest (07 Â§4) |
| KSG MI O(nÂ²) | 500KÂ² â‡’ impossible | stratified sampling â‰¤4096 â‡’ ~16M dists/estimate â‰ˆ seconds; batched nightly |
| Exact betweenness O(VÂ·E) | weeks at L | `betweenness_auto`: exact â‰¤2K, else 512 deterministic pivots (proven) |
| All-pairs similarity | O(nÂ²) | MinHash/LSH banding (existing, O(n)) + per-node caps |
| Lead/lag Cartesian | O(seriesÂ²) | candidate-bounded: L1 neighbors + same-dir + top co-change (â‰¤50/series) |
| Transfer entropy | heavy per pair | only top lead/lag pairs; lag sweep {1,2,4,8}; quorum 50 |
| Butterfly explosion | branching^depth | depth 4, Ã—0.7 attenuation, 0.05 prune, cycle guard, data-driven children only |

## 3. Memory budget (one discipline, two engines)

- Global: mimalloc unified; CBM's tiered RSS budget (25/35/50% of RAM) remains the master budget; extraction retention caps + backpressure naps unchanged.
- Calyx side: bounded allocators (arena/slab), LRU-TTL caches (byte-capped), memtable caps, reader-lease GC (5s default), background lane 15% CPU / 512MiB.
- Vault sizing at L: ~500K constellations Ã— (~1.2KB header/meta + quantized slots ~1.6KB [768d @3.5bpc Ã—3 dense + small dense + sparse avg]) â‰ˆ **1.5â€“2.5 GB** + graph CF ~0.5GB + indexes ~1GB â‡’ ~3â€“4 GB on disk (vs ~0.5â€“1GB SQLite today). Quantization is the lever; raw sidecars only for guard slots.
- In-RAM serving: HNSW quantized (~700MB at L) â€” DiskANN option below 1/10th RAM if needed.

## 4. Determinism Ã— parallelism

Content addressing makes vault state order-independent (fixes the class of CBM's known seq/parallel divergence at the record level); edge-set determinism preserved by CBM's existing merge-order fixes; all sampling (assay/pivots/replay) seeded ChaCha8; clocks injected. Determinism probes are CI gates (20).

## 5. GPU posture (strictly optional)

Default CPU: nomic lookup + SIMD (wide/AVX) covers everything. Optional features: `tei` (real embedder endpoints for S23+), `cuda` (Forge GEMM/topk for massive re-embeds, cuVS Linux-only) â€” fail-loud, never silent fallback, never required for any Tier 1â€“11 capability.

## 6. Benchmark harness (CI-gated)

Repos: small OSS service (S), CBM itself (M-ish), linux/fs subset (L-class) â€” CBM's existing bench scripts extended. Metrics: wall time per stage, RSS peak, vault size, search p99, recall@10 vs legacy path, kernel recall, incremental latency. Regression gates: overhead ratios above + no serving-path regression >10%. Published per release (honest numbers doctrine).


---

# 18_MIGRATION_COMPAT.md

# 18 â€” Migration & Compatibility

Strategy: **the Leapable pattern** â€” Calyx's own proven three-stage store migration (shadow â†’ flip â†’ native), applied to CBM's SQLite. Zero user-visible breakage at every stage; every stage independently shippable and reversible.

## 1. The migration dial: `calyx: off | shadow | primary`

### Stage V0 â€” `off` (today)
Unmodified CBM behavior. The dial exists so one binary serves all stages.

### Stage V1 â€” `shadow` (Phases 1â€“5)
- CBM pipeline runs exactly as today â†’ SQLite `.db` (still the serving store for all 14 tools).
- **Post-index import** (zero-FFI, D2): `astrolabe-ingest` reads the freshly-dumped SQLite â†’ builds constellations, edges, series, recurrence into the vault; ledger records the import with the SQLite content fingerprint.
- New tools (`anchor_outcome`, `measure_bits`, `get_kernel`, `get_context_pack`, â€¦) serve **from the vault**; legacy tools serve from SQLite. Two stores, one writer each, clearly labeled.
- Multi-agent/process behavior: all processes may serve legacy SQLite reads; shadow imports share one Aster vault and serialize durable commits through `locks/durable.commit.lock`; lowered SQLite sidecar regeneration serializes through a per-project `.astrolabe-lowered.lock`; background-lane ownership is elected through `.astrolabe-background-lane.lock`, with followers labeled `stale_ok`/`provisional` and watcher/anneal workers explicitly inactive in shadow stage.
- **Parity harness** runs continuously (20 Â§3): node/edge counts, search-overlap metrics, spot symbol equality. Divergence â‡’ shadow flagged, never silent.
- Rollback = ignore the vault. Cost: disk (vault alongside SQLite), one extra import pass (~minutes at L).

### Stage V2 â€” `primary` flip (Phases 6â€“9)
- Read paths flip tool-by-tool to the vault (search first, then schema/status/snippets); SQLite becomes the **lowered artifact**, regenerated from the vault after each index (04 Â§6) â€” Cypher, UI, and any straggler tools keep working unchanged against it.
- Write path: streaming FFI sink from the pipeline replaces the dump-then-import hop (single parse, single write); SQLite regeneration becomes a lowering pass.
- Guard: per-tool flip flags + tripwired A/B (search results, latency) before each tool's flip is defaulted.
- Rollback per tool = flip the flag back (SQLite is still complete).

### Stage V3 â€” native steady state (Phase 9+)
- Vault is the sole source of truth; SQLite artifact retained **permanently** as the lowering product (doctrine-clean: deterministic consumers read frozen artifacts). Optional `--no-lower` for headless setups that use no legacy surface.
- Team artifact: lowered SQLite `.zst` (existing) + chain-verified vault export (13 Â§4).

## 2. Compatibility commitments

| Surface | Commitment |
|---|---|
| 14 MCP tools | arg/return schemas unchanged; only additive fields; `trace_call_path` alias kept |
| CLI | `cli <tool> '<json>'`, flags, `--progress`, `--json` unchanged; binary name aliasing (`codebase-memory-mcp` â†’ `astrolabe` symlink/shim) so existing agent configs keep working |
| Agent installs | existing 13-agent configs untouched by upgrade; `update` refreshes instructions/skills content only |
| Hooks | existing hook scripts' contracts unchanged (never-block, silent-fail); new hooks opt-in |
| `.codebase-memory/graph.db.zst` | format retained (artifact schema v2); vault export additive |
| `_config.db` / UI config | inherited as-is; new keys additive (`calyx_mode`, `anneal`, budgets) |
| Cypher | full read subset preserved (runs on lowered artifact); `as_of` additive |
| Data location | `~/.cache/codebase-memory-mcp/` honored (or migrated with symlink + config note) |

## 3. Upgrade/downgrade paths

- Upgrade: install new binary â†’ first index run creates the vault (shadow) â†’ operator (or default rollout schedule) advances the dial. No data-format break at any point; the vault is always reconstructable from a reindex.
- Downgrade: any stage â†’ run legacy CBM against the (always-current) SQLite; vault directory is inert extra data.
- Schema evolution: vault manifests version-gated (Aster `ManifestVersion`); panel versions hot-swap with backfill; lowered-SQLite keeps CBM's compat-probe discipline (incompatible â‡’ regenerate, which is now cheap since SQLite is derived).

## 4. Rollout sequencing (per-repo, not per-fleet)

The dial is **per project** (`_config.db` key + `index_repository.calyx` param). Recommended: new projects â†’ shadow immediately; projects with CI anchors flowing â†’ primary for new tools after first parity-clean week; conservative repos stay shadow indefinitely at ~zero risk. Fleet defaults advance only after the parity dashboard (20) is clean across the beta cohort.


---

# 19_BUILD_TOOLCHAIN.md

# 19 â€” Build, Toolchain & Packaging

Making one binary from ~201K lines of C11 (+157 grammar TUs + vendored tree-sitter/SQLite/mimalloc) and ~540K lines of Rust 2024 â€” without breaking either project's build story.

## 1. Repository & workspace layout

```
astrolabe/
  Cargo.toml                  # Rust workspace
  rust-toolchain.toml         # pinned (Calyx needs recent stable, edition 2024)
  vendor/
    codebase-memory-mcp/      # git subtree (pinned SHA) â€” unmodified upstream + patches/
    calyx/                    # git subtree (pinned SHA) â€” the engine crates
  crates/
    cbm-sys/                  # bindgen + build.rs driving the C build
    astrolabe-bridge/         # safe wrappers over cbm-sys
    astrolabe-{domain,panel,ingest,anchors,weave,assay,kernel,guard,oracle,lower,server}/
  patches/cbm/                # minimal upstream diffs (see Â§3) â€” upstreamable
  scripts/ â€¦                  # build/test/bench/release
```
Pin both upstreams by SHA (pre-1.0 interfaces, per both projects' own warnings). Subtree over submodule for hermetic builds.

## 2. Building `libcbm.a`

New make target in a thin overlay (patch): `make -f Makefile.cbm libcbm` = all `PROD_SRCS`/`EXISTING_C_SRCS` objects **minus `main.c`**, archived. This is CBM's existing object set (extraction engine, grammars, ts_runtime, LSP unity, pipeline, store, mcp, cli, discover, semantic, simhash, git, watcher, traces, ui-stub, vendored sqlite3/mimalloc/yyjson/xxhash/tre/nomic blob) â€” everything the handlers need, headless.

`cbm-sys/build.rs`: invoke make (honoring `CC/AR/ARCHFLAGS`), emit link directives (`static=cbm`, `z`, `stdc++`/`c++`, platform libs `ws2_32/psapi/shell32` on Windows), run bindgen over a curated `astro_ffi.h` that `#include`s: `cbm.h` (extraction), `mcp.h` (`cbm_mcp_server_new/handle_tool/free`), `pipeline.h`, `store.h` (subset), `discover.h`, `git_context.h`. Allowlist bindings to the `cbm_` prefix.

## 3. Minimal upstream patches (kept small, upstreamable)

1. `Makefile.cbm`: `libcbm` target (+ `-fvisibility=hidden` with explicit `CBM_API` exports).
2. `cbm_embed.h` (new): stable embedding API â€” init (`cbm_alloc_init`, log sink, supervisor host-mark opt-out), version string, plus the **row-sink hook** `cbm_pipeline_set_sink(node_cb, edge_cb, ctx)` for Phase-B streaming (a ~200-line addition to `graph_buffer.c` dump path, guarded by NULL default = current behavior).
3. Log sink already pluggable (`cbm_log_set_sink_ex`) â€” route C logs into Rust `tracing`.
4. Nothing else. All other integration lives on the Rust side.

## 4. FFI safety rules

- **Ownership:** every `CBMFileResult*`/JSON string crossing the boundary has an explicit `cbm_free_*`; Rust wrappers are RAII (`Drop` calls free); no Rust-allocated memory ever freed by C or vice versa (mimalloc-unified but still disciplined).
- **Panics:** every Rust callback passed into C is `catch_unwind`-wrapped â†’ error status; panic = abort in release for the sink path (no unwinding across FFI).
- **Threads:** libcbm's per-thread parser/slab TLS respected â€” extraction FFI called only from the C-managed worker pool (Phase B streams from inside the pipeline), or from a dedicated Rust thread per `cbm_mcp_server_t` (the struct is documented not-thread-safe; one server handle per thread).
- **Strings:** UTF-8 both sides; Windows wide-path handling stays inside libcbm (it already owns it).
- **Errors:** C status codes + `isError` JSON envelopes mapped to `{code,message,remediation}`; unknown C failures become `ASTRO_CBM_INTERNAL` with stderr capture attached.

## 5. Allocator unification (D9)

C side already binds tree-sitter/SQLite to mimalloc (`cbm_alloc_init`, must run first). Rust side sets `#[global_allocator] static A: MiMalloc` (mimalloc crate pinned to the **same vendored mimalloc version** â€” build both from the one vendored source to avoid two arenas). Result: one heap, one RSS accounting (`mi_process_info` remains truthful), CBM's budget/pressure logic governs the whole process.

## 6. Platform matrix

| Platform | C toolchain | Rust target | Notes |
|---|---|---|---|
| Linux x64/arm64 | gcc/clang | `*-unknown-linux-gnu` | primary CI; musl static variant (Alpine image exists upstream) for the portable asset |
| macOS arm64/x64 | clang | `aarch64/x86_64-apple-darwin` | ad-hoc codesign step inherited from CBM installer |
| Windows x64 | **MinGW** (CBM's supported path) | `x86_64-pc-windows-gnu` | ABI-consistent with MinGW-built C. MSVC target deferred (mixing MSVC Rust + MinGW C is the classic trap â€” explicitly out of scope v1; document `-gnu` toolchain requirement) |

CUDA/TEI/ONNX features excluded from default builds on all platforms.

## 7. CI pipeline

Stages: (1) C gate â€” upstream CBM lint/tests (clang-tidy -Werror, cppcheck, 5.9K tests, ASan/UBSan) unchanged; (2) Rust gate â€” fmt, clippy -D warnings, nextest (Calyx crates + astrolabe crates); (3) FFI gate â€” bindgen drift check, link test all platforms, LSan on bridge tests; (4) parity + determinism suites (20); (5) bench gate (17 Â§6); (6) release â€” cross-builds, checksums, VirusTotal scan (CBM's release discipline inherited).

## 8. Packaging & distribution

Same channel network as CBM (npm/PyPI/Homebrew/Scoop/Winget/Chocolatey/AUR/`go install` shims download the platform binary). Binary named `astrolabe` with `codebase-memory-mcp` compat shim. Size estimate: CBM ~(grammars-dominated) + Rust engine â‡’ target < 150MB static (strip + LTO both halves; grammar set is the floor). UI variant unchanged (embed script + Node build). `server.json` MCP registry manifest updated.

**Licensing gate:** CBM is MIT; Calyx remains BSL 1.1 as a standalone project, and the Astrolabe combined binary carries a self-issued owner grant recorded in the root LICENSE/NOTICE files. `scripts/check-license-notices.py` verifies the release-critical notice manifest for Calyx, CBM, tree-sitter, SQLite, mimalloc, compression/json libraries, and nomic assets. Full package-channel notice generation remains a release packaging task. Tracked as R1 documentation/gate work (21).


---

# 20_TESTING_VERIFICATION.md

# 20 â€” Testing & Verification Strategy

Both parents bring strong, different testing cultures: CBM's 5,900+ gating cases + red-by-design repro suite + sanitizers; Calyx's FSV byte-verification doctrine + determinism probes + pinned-invariant tests + hazard/soak. ASTROLABE inherits **both** and adds the fusion-specific layers.

## 1. Inherited gates (unchanged)

- CBM: full `make test` (ASan/UBSan), lint gates, repro runner (status board), Windows suite, shell guards.
- Calyx crates: nextest suites, proptests, pinned invariants (error catalogs, CF counts), fuzz targets.
- Both run in CI as-is against the vendored SHAs â€” upstream regressions caught at the pin.

## 2. Fusion test layers (new)

### L1 â€” FFI/bridge correctness
Bindgen drift gate; RAII/leak tests (LSan) over every wrapper; panic-across-FFI tests (injected callback panics â†’ clean error, no UB); thread-model tests (parser TLS, one-server-per-thread); allocator unification test (single mi heap, RSS accounting sane).

### L2 â€” Mapping parity (the shadow-stage harness, 18)
For a corpus of pinned repos (S/M/L, multi-language):
- node parity: lowered-SQLite nodes â‰¡ CBM-native nodes (labels, QNs, ranges, properties) â€” byte-diffed;
- edge parity: typed multiset diff with a whitelist of documented divergence classes; any unlisted divergence fails;
- FTS parity: `cbm_camel_split` tokenization equivalence on the S7 lens;
- search parity: legacy vs fused path â€” overlap@10 tracked, regressions gated;
- idempotency: reindex-unchanged â‡’ zero new CxIds, zero ledger mutations beyond the run record.

### L3 â€” Determinism probes (CI-blocking)
Same repo, 1 vs 8 workers, three runs: identical CxId sets, identical eager cross-terms, identical kernel membership (given same seed), identical pack for identical (task, budget, seed). All randomness enumerated and seeded (assay sampling, pivots, bandit, replay).

### L4 â€” FSV byte-verification (Calyx doctrine, applied)
For each subsystem, scripted *read-the-actual-bytes* checks (not green-checkmark harnesses): constellation rows decoded from the base CF and field-compared to extraction output; anchor rows + same-commit ledger entries verified as a pair; kernel artifact readback (members hash, recall figures) vs reported; guard verdict ledger rows vs returned verdicts; lowered SQLite fingerprint vs manifest. Shipped as `astrolabe verify --deep` (doubles as user-facing integrity tool alongside `verify_chain`).

### L5 â€” Intelligence-quality gates (honest-numbers suite)
- **Backtest gate** per pinned repo (11 Â§2): impact prediction must beat hop-baseline (or grounded mode stays off) â€” the Poly `beats_market` discipline.
- **Pack quality:** held-out fix-commit tasks â€” does the pack contain the fix location within budget? tracked vs naive-context baseline; regression-gated once established.
- **Guard ROC:** mutation/revert corpora â€” calibrated FAR within target Â±CI; FRR tracked.
- **Assay sanity:** planted-signal synthetic repos (a field constructed to carry known bits) â€” estimator recovers it within CI; planted-redundant lens gets retired; planted-synergy detected.
- **Sufficiency honesty:** panels measured insufficient must refuse via honesty gate in oracle paths (negative tests).

### L6 â€” Soak & hazards
Adapted hazard probes: watcher+incremental churn soak (10K synthetic commits â€” RSS bounded, no oscillation via anneal hysteresis, ledger intact); crash-injection during ingest (WAL/torn-tail recovery â‡’ vault opens Intact, supervisor quarantines the culprit); disk-pressure fail-closed; reactive-queue overflow accounting.

Hazard suite status: `ci/hazard-suite.json` plus `scripts/check-hazard-suite.py` name the current short L6 gate and write `target/astrolabe-release-predicate/verify-chain-soak.json` for the release predicate. The suite currently covers same-commit rollback under backpressure, disk tamper fail-closed behavior, WAL crash recovery with `verify_chain`, exact reactive queue overflow warning rows, and the Linux 4096-event queue soak/RSS bound. Remaining #60 work is the 10K watcher+incremental churn soak, full ingest-stage crash matrix, disk-full artifact recovery, scheduled CI publishing, and trend artifacts.

### L7 â€” Agent-level evals (the product truth)
Scripted MCP sessions (rapid-init + tool-sequence scripts, extending CBM's `test_mcp_rapid_init.py`): SWE-bench-lite-style tasks driven with (a) legacy CBM tools vs (b) ASTROLABE packs+oracle â€” measure tokens consumed, task success, wrong-file rate. Published per release; this is success-criterion #1 (01 Â§6) made executable.

Release predicate status: `scripts/release-predicate.sh` / `scripts/release-predicate.py` now evaluates `astrolabe.release_predicate.v1` from JSON artifacts in a fixed conjunct order: L7 agent evals, inherited gates, L1-L4, L5 baselines, bench ratios, verify_chain soak, parity dashboard, license gate, and nightly reproduce sample. It exits nonzero naming the first failing conjunct, reports missing artifacts instead of guessing, prints active L5 waivers verbatim with published numbers, and names `REPRODUCE_DRIFT_EXCEEDED` answer ids from reproduce-sample artifacts. `scripts/test-release-predicate.py` forces every conjunct red and is part of `scripts/check.sh`; the remaining work is producing those artifacts from live CI/eval jobs rather than fixtures.

## 3. Test infrastructure

Pinned-corpus repos vendored as fixtures (small) + cloned-by-script (large, checksum-pinned); the parity dashboard aggregates L2/L3/L5 across the beta cohort; nightly = full assay sweep + reproduce-sample + soak-short; weekly = L-scale bench + backtests. Red-by-design repro convention adopted for fusion bugs (a failing repro is a permanent regression guard, exit-status board not gate).

## 4. Release predicate (ships only whenâ€¦)

All inherited gates green âˆ§ L1â€“L4 green âˆ§ L5 baselines met (or explicitly waived with published numbers) âˆ§ bench overhead ratios within 17 Â§1 âˆ§ `verify_chain` Intact across soak âˆ§ parity dashboard clean for the cohort âˆ§ license gate (R1) resolved for public artifacts.


---

# 21_RISKS_BLINDSPOTS.md

# 21 â€” Risk Register & Blind Spots

Every identified risk, honestly stated, with mitigation and owner-phase. Severity: ðŸ”´ project-threatening Â· ðŸŸ  major Â· ðŸŸ¡ manageable.

## Legal & strategic

| # | Risk | Sev | Mitigation |
|---|---|---|---|
| R1 | License/notice completeness for combined distribution | ðŸŸ¡ | External grant blocker resolved by Calyx ownership; root LICENSE/NOTICE records the Astrolabe-specific Calyx grant; `scripts/check-license-notices.py` gates release-critical vendored notices; full package-channel notice aggregation still required before public release |
| R2 | Upstream drift: both parents are pre-1.0, actively developed; pinned SHAs rot | ðŸŸ  | subtree pins + small patch set (19 Â§3) designed for upstreaming; quarterly rebase budget; interface-invariant tests catch breakage at the pin bump |
| R3 | Scope explosion (this plan is large) | ðŸŸ  | phase gates (22) each independently shippable & valuable; Tier 1â€“5 alone justify the project; Tiers 6â€“12 are optional extensions |

## Technical â€” build & runtime

| # | Risk | Sev | Mitigation |
|---|---|---|---|
| R4 | Câ†”Rust link matrix (esp. Windows MinGW vs MSVC) | ðŸŸ  | `-gnu` toolchain mandate v1 (19 Â§6); CI link tests all platforms from P0; two-binary fallback mode (Rust shells to cbm CLI) always works |
| R5 | Two allocators / RSS blindness | ðŸŸ  | single vendored mimalloc for both halves (D9); allocator unification test (20 L1) |
| R6 | Panic/UB across FFI | ðŸŸ  | catch_unwind wrappers, abort-on-unwind at sink boundary, LSan/ASan bridge suites |
| R7 | Binary size (grammars + Rust engine) | ðŸŸ¡ | LTO+strip both halves; grammar set already dominates CBM (~baseline); target <150MB; optional slim build (top-40 grammars) |
| R8 | Index-time overhead breaks the "fast" promise | ðŸŸ  | hard overhead gates â‰¤1.3Ã—/1.5Ã— (17); panel is lookup/encode-only by design; lowering debounced; shadow stage lets users opt out |
| R9 | Vault disk footprint (3â€“4Ã— SQLite) | ðŸŸ¡ | quantization gates, cold-tiering of superseded versions, `--no-history` retention option |
| R10 | mcp server single-thread + background lane contention | ðŸŸ¡ | anneal budget enforcer (15% CPU), StaleOk serving, budget tripwires |

## Technical â€” intelligence quality

| # | Risk | Sev | Mitigation |
|---|---|---|---|
| R11 | **Anchor scarcity/cold start** â€” without outcomes the system is "just CBM + overhead" | ðŸ”´ | explicit provisional mode with honest labeling; bootstrap ladder (06 Â§5: one CI run yields thousands of anchors); SZZ works on any repo with history; value floor: Tier 5 kernels/packs work ungrounded (labeled provisional) and are already better context than raw search |
| R12 | Anchor pollution (wrong attribution: multi-cause commits, flaky tests, agent misreporting) | ðŸŸ  | attribution windows + credit splitting; self-consistency ceilings cap flaky influence; agent anchors Provisional until CI confirms; contradiction detection refuses promotion (06 Â§3) |
| R13 | SZZ heuristics mislabel bug-introducing changes | ðŸŸ¡ | confidence <1 Provisional forever unless confirmed; bits measured on Trusted-only subsets reported separately |
| R14 | Small repos never reach assay quorums (50+) | ðŸŸ¡ | Bayesian small-sample path with credible intervals; provisional labels; cohort evidence clearly marked |
| R15 | Guard false-reject friction alienates users | ðŸŸ  | advisory-by-default (new-region, not refusal); per-team FAR targets; FRR tracked and published; identity-lock only on exported API |
| R16 | Mutation-based bad-cases teach the guard "mutations" not "bad code" | ðŸŸ¡ | 4-source calibration mix (mutations+reverts+alien+vulns); per-source ablations in L5 tests |
| R17 | Oracle overfits to history / evidence sparsity | ðŸŸ  | backtest gate before grounded mode advertises (11 Â§2); ceilings; honest refusals; structural fallback clearly labeled |
| R18 | Goodhart: anneal optimizes the replay metric, not user value | ðŸŸ¡ | Goodhart defense gates (g(Ï„), dominance), held-out gain floors, tripwires, one-change-at-a-time ledger |
| R19 | Generated/vendored/minified code pollutes panels & kernels | ðŸŸ¡ | CBM's discovery filters already skip most; `is_generated` role flag lens; kernel excludes flagged nodes; guard alien-corpus draws from non-vendored only |
| R20 | Embedding lens (nomic static vectors) too weak for semantic claims in exotic languages | ðŸŸ¡ | measured, not assumed: bits will show it (that's the point); optional real-model lenses plug in; lexical/structural lenses carry the load where semantics are weak |
| R21 | Multi-language repos: one panel, heterogeneous distributions | ðŸŸ¡ | guard domains per language; assay stratification by language; per-language calibration |

## Technical â€” correctness & data

| # | Risk | Sev | Mitigation |
|---|---|---|---|
| R22 | CBM's known seq/parallel graph divergence leaks into vault claims | ðŸŸ¡ | content addressing absorbs record-level divergence; edge divergences whitelisted+accounted (L2 parity); upstream fix remains desirable |
| R23 | QN instability (renames, generated QNs, collisions >255 chars) breaks series continuity | ðŸŸ  | rename linking via git R-status; series fork-on-ambiguity with explicit `series_split` records; QN-hash fallback (CBM's FNV tail cap) respected |
| R24 | Snippet/source drift between index and pack serve time | ðŸŸ¡ | content hashes in pack manifests; `ASTRO_SOURCE_DRIFT` fail-closed on mismatch; freshness tags |
| R25 | Ledger growth unbounded on busy monorepos | ðŸŸ¡ | checkpoints + Merkle export; ledger is hashes-only (tiny rows); measured: ~1KB/mutation â‡’ GBs/year at extreme scale â€” acceptable; archival tiering available |
| R26 | Lowered-SQLite staleness confuses legacy consumers | ðŸŸ¡ | vault fingerprint + `stale_by` surfaced; debounced regen; `fresh` force option |
| R27 | Erasure/PII: proprietary code in vaults, secrets in history | ðŸŸ  | CBM secret filters upstream + Calyx redaction + erasure tombstones (13 Â§5); vaults are local-only by default (no egress) |
| R31 | Multiple agent MCP processes contend for one Aster vault | ðŸŸ  | Aster durable commits are OS-file-lock serialized; lowered SQLite sidecar writes use a per-project sidecar lock; shadow legacy reads stay on SQLite; background-lane ownership uses a per-project OS file lock with labeled followers and inactive shadow-stage watcher/anneal workers; cross-process harness verifies no corruption/deadlock and exactly one owner |

## Product & ecosystem

| # | Risk | Sev | Mitigation |
|---|---|---|---|
| R28 | Tool-count/token bloat degrades agent tool-selection | ðŸŸ¡ | consolidation via modes (29 total), pagination, skill doc teaches selection; hooks carry the ambient value without tool calls |
| R29 | Agents ignore trust/provenance fields (honesty theater) | ðŸŸ¡ | skill doctrine + refusal behaviors force engagement (honesty gate returns actionable remediation, not walls); hooks inject readiness state |
| R30 | Complexity intimidates adopters vs. plain CBM | ðŸŸ  | default experience unchanged (shadow mode invisible); intelligence features reveal progressively as anchors accrue; "it's still one binary, one command" |

## Blind-spot checklist (things plans habitually miss â€” verified addressed)

â˜‘ licensing (R1) Â· â˜‘ cold start (R11) Â· â˜‘ flaky tests (R12, 06 Â§4) Â· â˜‘ monorepo scale (17) Â· â˜‘ generated code (R19) Â· â˜‘ multi-language (R21) Â· â˜‘ renames (R23) Â· â˜‘ nondeterminism (R22, 20 L3) Â· â˜‘ Windows (R4) Â· â˜‘ allocators (R5) Â· â˜‘ memory budgets (17 Â§3) Â· â˜‘ disk (R9) Â· â˜‘ privacy/erasure (R27) Â· â˜‘ backward compat (18) Â· â˜‘ downgrade path (18 Â§3) Â· â˜‘ agent misreporting (R12) Â· â˜‘ Goodhart (R18) Â· â˜‘ dead upstream features relied upon (traces stub â†’ implemented; diffusion/dataflow weights â†’ measured or dropped) Â· â˜‘ GPU absence (D10) Â· â˜‘ air-gapped use (no egress) Â· â˜‘ token budgets (09 Â§3) Â· â˜‘ UI continuity (11.6) Â· â˜‘ team sharing (13 Â§4) Â· â˜‘ CI cost (20 Â§3 tiered cadence).


---

# 22_ROADMAP.md

# 22 â€” Roadmap: Phases, Gates, Estimates

Eleven phases, each independently shippable, each with a falsifiable exit gate. Effort in engineer-weeks (ew) assumes 1â€“2 senior engineers fluent in both Rust and C; ranges reflect unknowns discovered in P0. Dependency spine: P0â†’P1â†’P2â†’(P3âˆ¥P4)â†’P5â†’P6â†’(P7âˆ¥P8)â†’P9â†’P10.

## P0 â€” Foundations & proof of link (3â€“5 ew)
Workspace + subtrees pinned; `libcbm.a` target + `cbm-sys` bindgen; Rust binary that (a) links both halves on Linux/macOS/Windows-gnu, (b) passes all legacy tools through `cbm_mcp_handle_tool` FFI, (c) unified mimalloc, logs routed.
**Gate:** all 14 legacy tools byte-parity vs upstream binary on the parity corpus; CI green on 3 platforms; ASan/LSan clean bridge.

## P1 â€” Constellations (shadow ingest) (4â€“6 ew)
`astrolabe-domain` (canonical bytes, series registry) + `astrolabe-panel` (panel v1, S0â€“S21, frozen seed registry) + `astrolabe-ingest` (SQLiteâ†’vault importer) + ledger wiring + `verify_chain`.
**Gate:** L-scale repo imports â‰¤ 5 min post-index; idempotent reindex (zero new CxIds); determinism probe (1 vs 8 workers â‡’ identical CxId set); FSV readback of sampled constellations.

## P2 â€” The graph in the vault (3â€“4 ew)
Edge import (typed graph CF + projections + CSR), series/recurrence linking, lowered-artifact regeneration (`astrolabe-lower`), migration dial `off|shadow`.
**Gate:** edge parity dashboard clean (documented divergences only); lowered SQLite passes CBM's own test queries; Cypher + UI run unmodified against lowered artifact.

## P3 â€” Weave & reactivity (3â€“5 ew)
L2 kNN graphs (LSH candidates + quantized HNSW), 6 eager cross-terms, agreement graph, reactive triggers wired to watcher, incremental delta path end-to-end (16 Â§1).
**Gate:** incremental single-file change â†’ vault convergence < 5s at M; doc-drift/name-truth reports produce sane output on the corpus; bounded-queue soak clean.

## P4 â€” Grounding (4â€“6 ew)
`anchor_outcome` + CI parsers (JUnit/pytest/cargo/go), TESTS-edge propagation, SZZ archaeology, revert anchors, **`ingest_traces` implemented** (edge promotion), agent-task anchors + hooks, trust lifecycle, survival anchors, flakiness self-consistency.
**Gate:** on a real repo with CI: one suite run yields anchors on >30% of non-test symbols (via propagation); trace batch promotes HTTP edges; contradiction detection demo; all anchors ledgered + FSV-verified.

## P5 â€” Assay (4â€“6 ew)
Measurement job scheduler (sampling, budgets, background lane), signal/sufficiency/redundancy/synergy/causality/calibration cards, `measure_bits` tool, capability gate live (park/retire per repo), planted-signal test suite.
**Gate:** planted-signal recovery within CI; nightly sweep â‰¤ 45 min at L; per-repo signal ranking demonstrably differs across 3 corpora (the "fixed weights were wrong" exhibit); n_eff reported.

## P6 â€” Kernel & context packs (5â€“7 ew) â† the headline release
Kernel builds (scoped, standing, incremental), recall gating + refinement, grounding gaps, `get_kernel`/`kernel_answer`/`get_context_pack`, pack composer + manifests + reproduce, search unification behind `search_graph` (fusion profiles, planner), `find_similar`, upgraded `trace_path`/`get_architecture`, primary-flip for search-class tools.
**Gate:** pack quality baseline: fix-location containment â‰¥ naive baseline at â‰¤ 20% tokens on the backtest corpus; kernel recall â‰¥ 0.95 gated; `reproduce(pack_id)` bit-exact; search A/B non-regression.

## P7 â€” Guard & oracle (6â€“8 ew)
Calibration corpus builders (mutations per top-10 languages, reverts, alien, vulns), guard profiles + `guard_check`/`guard_calibrate`, identity-lock, drift monitors; evidence mining (changeâ†’outcome corpus), `predict_impact` + backtest gate, `abduce_cause`, `forecast`, honesty gate surfaces, upgraded `detect_changes` grounded risk.
**Gate:** guard ROC targets on held-out bad cases (FAR â‰¤ target Â± CI); impact backtest beats hop-baseline on â‰¥ 2 of 3 corpora (else grounded mode stays off â€” honestly); refusal paths tested.

## P8 â€” Self-optimization & growth (4â€“6 ew)
Anneal wiring: fusion/pack-weight tuning on logged replay, tripwires, bandit/A-B, threshold recalibration loops, `propose_lens` pipeline, mistake closure heads, quantization gates, `optimizer_status`, readiness predicate (`get_readiness`), imputation (`impute_fields`).
**Gate:** shadow-tested promotion demonstrably improves recall@k on replay with all tripwires quiet; a deficit-proposed lens survives the gate end-to-end on a test corpus; readiness renders per scope.

## P9 â€” Native steady state & hardening (4â€“6 ew)
Streaming FFI sink (single-parse path), primary-by-default dial, full soak/hazard suite, performance gates locked, security pass (erasure, redaction audit), diagnostics/health surface, docs, skills, installer content, agent-level eval suite (L7) published.
**Gate:** release predicate (20 Â§4) fully green; overhead ratios met at L; two-binary fallback retired from default path.

## P10 â€” Frontier (ongoing)
Cross-repo org vault + hierarchical kernels + cross-repo TE; autonomy-dial policy hooks; reviewer routing/ownership lens; refactoring advisor; self-healing docs; historical counterfactual evals; UI intelligence overlays (kernel glow, trust colors, gap map); team vault exchange with signatures; optional real-model lens packs (TEI/ONNX).
Capability 7.10 lives here, not P8: reviewer routing depends on the P7 oracle surfaces and a privacy/erasure-ready ownership substrate; until those exist, emitting author rankings would be a provisional standalone claim rather than a grounded oracle field.
Capability 11.6 lives here, not P9: the overlay truth claims require kernel, trust/provenance, grounding-gap, agreement, and cross-repo products to exist first; P9 only hardens and releases the established substrate.
**Gate:** per-feature; each rides the established substrate.

## Cumulative estimate

Core (P0â€“P6, the "insanely useful" milestone): **26â€“39 ew**. Full vision (P0â€“P9): **40â€“59 ew**. With 2 engineers: core in ~4â€“6 months, full in ~7â€“10 months. P10 is a product line, not a phase.

## ASTROLABE_DONE (the project's BUILD_DONE predicate)

`LINKED âˆ§ CONSTELLATED âˆ§ GROUNDED âˆ§ MEASURED âˆ§ DISTILLED âˆ§ GUARDED âˆ§ PREDICTIVE âˆ§ PROVENANCED âˆ§ SELF-OPTIMIZING âˆ§ COMPATIBLE âˆ§ HONEST` â€” where each conjunct is the corresponding phase gate above, and **HONEST** is the standing invariant verified by every release: *no unlabeled claim, no ungated confidence, no silent fallback, no constant that could be a measurement.*

---

## First week of work (concrete kickoff list)

1. Create repo, subtree both upstreams at pinned SHAs, stand up 3-platform CI running both parents' native test suites.
2. Write `Makefile.cbm` `libcbm` patch + `astro_ffi.h`; get `cbm-sys` linking + one FFI call (`cbm_extract_file` on a fixture) green everywhere.
3. Pass-through server: Rust MCP loop delegating all 14 tools; run CBM's MCP tests against it.
4. Draft `canonical_input_bytes` + golden tests (the identity spine everything hangs on).
5. Import one small repo end-to-end into a vault by hand; FSV-read the first constellation's bytes. *(A return value is a claim; the bytes are the verdict.)*


---
