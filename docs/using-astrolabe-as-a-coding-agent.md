# Using ASTROLABE as a coding agent

> **Audience:** an AI coding agent (or the human wiring one up) that has ASTROLABE connected as an MCP server and wants to use it to write, change, and validate code far better than it could with `grep` + `read file`.
>
> **Scope:** this is a *usage* document. It describes the 36 tools the server actually advertises, what each one is for, the argument shapes that matter, and the sequences ("playbooks") that compound them into capability. It is not a design document (`docs/astrolabe-blueprint.md`) and it is not a progress record (GitHub issues are the only progress record — see `CLAUDE.md`).
>
> **Honesty note up front:** ASTROLABE is under active construction. Several surfaces below refuse rather than answer until the state they depend on exists. That is the design, not a bug — a refusal with a deficit is worth more than a confident guess. Read [§12 Honest limits](#12-honest-limits--what-is-not-live-yet) before you build a workflow that assumes an answer.

---

## Table of contents

1. [The mental model](#1-the-mental-model)
2. [The honesty contract (read this before trusting any answer)](#2-the-honesty-contract-read-this-before-trusting-any-answer)
3. [Setup: index once, then everything works](#3-setup-index-once-then-everything-works)
4. [The complete tool surface (36 tools)](#4-the-complete-tool-surface-36-tools)
5. [Playbook A — orient in an unfamiliar codebase](#5-playbook-a--orient-in-an-unfamiliar-codebase)
6. [Playbook B — find the right code (stop grepping)](#6-playbook-b--find-the-right-code-stop-grepping)
7. [Playbook C — plan a change before writing it](#7-playbook-c--plan-a-change-before-writing-it)
8. [Playbook D — write code that fits the codebase](#8-playbook-d--write-code-that-fits-the-codebase)
9. [Playbook E — debug a failure backwards](#9-playbook-e--debug-a-failure-backwards)
10. [Playbook F — review, refactor, and hunt performance](#10-playbook-f--review-refactor-and-hunt-performance)
11. [The compounding loop — how ASTROLABE gets smarter about *your* repo](#11-the-compounding-loop--how-astrolabe-gets-smarter-about-your-repo)
12. [Honest limits — what is not live yet](#12-honest-limits--what-is-not-live-yet)
13. [Harness integration (hooks, CLI, refusal handling)](#13-harness-integration-hooks-cli-refusal-handling)
14. [Cost, latency, and token discipline](#14-cost-latency-and-token-discipline)
15. [Anti-patterns](#15-anti-patterns)
16. [Quick reference card](#16-quick-reference-card)

---

## 1. The mental model

An ordinary coding agent works from **text**: it greps, reads files, and infers structure from what it happens to have read. Its context is a sample, its confidence is uncalibrated, and it has no memory of what was true last week or what actually broke last time.

ASTROLABE gives you three things text cannot:

| Layer | What it is | What it buys you |
|---|---|---|
| **Atoms + associations** (CBM half, C) | Every symbol in the repo parsed into a graph node with a stable identity, connected by typed edges: `CALLS`, `DATA_FLOWS`, `TESTS`, `IMPORTS`, HTTP/async route edges, cross-repo edges | Exact callers/callees/data flow instead of guessed ones; structure that survives renames and reformatting |
| **Grounding** (anchors) | Real-world outcomes attached to symbols: test passes, CI runs, runtime traces, git reverts, SZZ bug archaeology | The difference between "this looks related" and "this has actually broken together before" |
| **Measured intelligence** (Calyx half, Rust) | A distilled *kernel* of the codebase, a conformal *guard*, an *oracle* for impact/cause/forecast, and a hash-chained provenance ledger | Answers that carry a trust label, refuse when the evidence is thin, and can be replayed and audited |

The practical rule that follows:

> **Use the graph for anything structural. Use grounding for anything predictive. Use text search only for literals the graph does not model** (a magic string, a config value, a comment).

A single `trace_path` call replaces a dozen speculative greps *and is correct*, because the edges came from tree-sitter + type-aware LSP resolution, not from a regex that matched a similarly-named function in a different module.

---

## 2. The honesty contract (read this before trusting any answer)

Every ASTROLABE-native response carries labels. Your agent logic should branch on them, not ignore them.

### 2.1 The three labels on every grounded response

- **`trust`** — how well-grounded this claim is. Common values: `verified` (read back from persisted state), `trusted` (grounded in resolved evidence), `provisional` (inferred, or grounded in proxy evidence), `inferred`.
- **`freshness`** — whether the underlying index still matches reality (`fresh`, `stale`, or a refusal code when freshness itself cannot be asserted).
- **`provenance`** — where the claim came from: ledger sequence, chain hash, source label, vault fingerprint.

**Rule:** never present a `provisional` result to a user as fact, and never act destructively on one. Escalate: ground it first (§11), or say what would ground it.

### 2.2 Refusals are answers

ASTROLABE fails **closed**. When the evidence is insufficient, you get a structured error, not a guess:

```json
{ "code": "ASTRO_NO_RECURRENCE",
  "message": "…too few failure events to forecast a cadence…",
  "remediation": "ingest more outcome anchors for this subject via anchor_outcome" }
```

Always read `remediation` — it names the exact next call. A refusal usually means *"do this one thing first"*, not *"this is broken"*.

Refusal families you will meet in practice:

| Code family | Meaning | Usual fix |
|---|---|---|
| `ASTRO_SHADOW_*` | The project is not shadow-indexed, or the index is stale / out-of-band | Re-run `index_repository` with `calyx:"shadow"` |
| `ASTRO_SOURCE_DRIFT`, `ASTRO_SHADOW_SOURCE_OUT_OF_BAND` | The working tree changed since indexing | Re-index; do not reason on the stale graph |
| `ASTRO_KERNEL_BUILD_UNAVAILABLE` | No kernel could be distilled (empty/untyped graph, recall gate unmet) | Check the reason it names; often the repo needs a fuller index mode |
| `CALYX_KERNEL_ANSWER_LEDGER_REQUIRED` | A multi-hop answer lacks complete ledger wiring — refused rather than served unprovenanced | Build the kernel (`get_kernel mode:"build"`) |
| `ASTRO_NO_RECURRENCE`, `ASTRO_FLAKY_EVIDENCE` | Not enough (or self-inconsistent) failure history | Ingest outcomes; for flaky tests, fix the flake first |
| `*_DEFICIT` / "Insufficient" deficit cards | The tool measured its own evidence and found it thin, per sensor | The card tells you which sensor is starved |
| `CALYX_LENS_FROZEN_VIOLATION` | Something tried to change a frozen measurement contract | Never work around this; it protects comparability |

### 2.3 Verification doctrine

ASTROLABE's own project rule is **manual Full State Verification**: build the real artifact, exercise it against real data, then *independently read back the persisted state* and compare it with the claim. Apply the same instinct to your own work when you use ASTROLABE on someone else's repo: a tool's return value is a claim; the persisted store is the truth. `get_provenance mode:"verify_chain"` and `mode:"reproduce"` exist precisely so you can check a claim instead of believing it.

> Note the distinction: ASTROLABE's *own* repository has no test suite by owner directive, but ASTROLABE the *product* ingests **your** repository's test and CI reports as grounding evidence (§11). Those are different things — don't confuse the two.

---

## 3. Setup: index once, then everything works

### 3.1 The one call that unlocks the whole surface

```json
{ "tool": "index_repository",
  "arguments": {
    "repo_path": "C:/code/my-service",
    "mode": "full",
    "calyx": "shadow"
  } }
```

**`calyx: "shadow"` is the master switch.** Without it you get plain CBM: a good code graph, and nothing else. With it, indexing additionally builds the Calyx vault, the lens panel measurements, the graph projections, the lowered artifact, provenance, skill tree, bridges, kernel context, anomaly surfaces, and git archaeology. Every Astrolabe-native tool in §4.2 requires a shadow-indexed project and refuses fail-closed otherwise.

The dial is **persisted per project** — you pass `calyx:"shadow"` once and later re-indexes inherit it.

### 3.2 Choosing `mode`

| `mode` | What it does | When |
|---|---|---|
| `full` | All files + similarity/semantic edges | Default. Required for `semantic_query` and richest similarity |
| `moderate` | Filtered files + similarity/semantic | Large repos where full is too slow |
| `fast` | Filtered files, no similarity/semantic | First-pass orientation; `semantic_query` will be unavailable |
| `cross-repo-intelligence` | No extraction — matches Routes/Channels **across** already-indexed projects to create `CROSS_HTTP_CALLS` / `CROSS_ASYNC_CALLS` / `CROSS_CHANNEL` edges | Microservice fleets. Index each service first, then run this with `target_projects: ["*"]` |

All modes run type-aware LSP call/usage resolution, per-file and cross-file. That is why the edges are trustworthy.

### 3.3 Other `index_repository` arguments worth knowing

- **`persistence: true`** — writes a compressed artifact to `<repo>/.codebase-memory/graph.db.zst` so teammates (or a fresh agent session) can bootstrap without re-indexing. Pairs with `team_artifact`.
- **`target_projects`** — required for `cross-repo-intelligence`; `["*"]` means every indexed project (`list_projects` shows them).
- **`calyx_search`** — shadow-only object selecting the vector index backend: `{"index_backend": "in_memory_hnsw" | "diskann" | "spann", …}`. Only meaningful at M-scale corpora.
- **`calyx_skills`** — shadow-only `{"max_symbols": N}` bound on skill-tree discovery.
- **`name`** — **refused.** Project storage identity is derived only from the canonical repository root. Use the `project` value that `index_repository` returns.

### 3.4 Keeping the index honest

```json
{ "tool": "index_status", "arguments": { "project": "my-service" } }
```

On a shadow project this returns far more than "done": `vault_fingerprint`, `vault_ledger_head`, `panel_version`, `shadow_import` freshness verdict, `background_lane`, `periodic_verify`, `health`, idempotency counters (`new_cx_ids` / `reused_cx_ids`), `security_screen`, `search_scale`, `skill_tree`, `bridges`, `kernel_context`, `anomalies`, `provenance`, `invalidations`, `lowered_sqlite`, and the vault's `verify_chain` result.

**Make `index_status` your first call in any session that will lean on grounded tools.** If freshness is anything but current, everything downstream is reasoning about a codebase that no longer exists. Re-index; `index_status` will not silently reconcile a stale import for you (it has no CBM runner and would have to blank the derived surfaces to pretend).

The incremental watcher (`auto_watch` config key) can keep projects fresh automatically; when it is off, re-index after significant edits.

---

## 4. The complete tool surface (36 tools)

### 4.1 The CBM half — structure and text (14 tools)

These work with or without the shadow dial. Several gain Astrolabe extensions when the dial is on (marked ✨).

| Tool | Purpose | Key arguments |
|---|---|---|
| **`index_repository`** | Build/refresh the graph (§3) | `repo_path`, `mode`, `calyx`, `persistence`, `target_projects` |
| **`search_graph`** ✨ | The primary discovery tool. Three exclusive modes: BM25 `query`, regex `name_pattern`/`qn_pattern`, vector `semantic_query` | `project`, `query`, `name_pattern`, `qn_pattern`, `file_pattern`, `label`, `relationship`, `min_degree`/`max_degree`, `exclude_entry_points`, `include_connected`, `semantic_query` (**array**), `limit` (200), `offset` |
| **`query_graph`** ✨ | Arbitrary Cypher for multi-hop patterns, aggregations, complexity mining | `query`, `project`, `max_rows` (100k ceiling) |
| **`trace_path`** ✨ | Callers/callees, data flow, cross-service hops | `function_name`, `project`, `direction` (`inbound`/`outbound`/`both`), `depth` (3), `mode` (`calls`/`data_flow`/`cross_service`), `parameter_name`, `edge_types`, `risk_labels`, `include_tests` |
| **`get_code_snippet`** | Read a symbol's source. **Find `atom_id` via `search_graph` first** | `atom_id` (preferred), `qualified_name` (only if unique), `project`, `include_neighbors` |
| **`get_architecture`** | High-level map: packages, services, dependencies, routes, layers, boundaries, entry points, hotspots, and **Leiden clusters** (the de-facto modules, which often cut across folders) | `project`, `path`, `aspects`; selecting `clusters` also requires `resolution`, `cluster_max_nodes`, `cluster_max_edges`, `cluster_max_move_visits`, and `cluster_max_result_bytes` |
| **`search_code`** | Graph-augmented grep: text match, deduplicated into containing functions, ranked by structural importance | `pattern`, `project`, `file_pattern`, `path_filter`, `mode` (`compact`/`full`/`files`), `context`, `regex`, `limit` (10) |
| **`get_graph_schema`** | Node labels and edge types available in this project | `project` |
| **`detect_changes`** ✨ | What changed vs a base ref, and what it impacts | `project`, `scope`, `depth` (1..16), `base_branch`, `since`, plus required positive `changed_file_max`, `impact_max_symbols`, `reach_max_nodes_per_symbol`, and `result_max_bytes` bounds |
| **`list_projects`** | Every indexed project | — |
| **`index_status`** ✨ | Index + vault health (§3.4) | `project` |
| **`delete_project`** | Remove a project and its Astrolabe sidecars | `project` |
| **`manage_adr`** | Read/write Architecture Decision Records | `project`, `mode` (`get`/`update`/`sections`), `content`, `sections` |
| **`ingest_traces`** | Ingest runtime traces (OTLP protobuf/JSON, or simple `{caller,callee,count}`) to **promote matching graph edges to Trusted**, attach runtime anchors, flag 5xx incidents | `project`, `traces`, `resourceSpans`, `otlp_protobuf_base64` |

#### ✨ Shadow-dial extensions on CBM tools

| Tool | Extension | Effect |
|---|---|---|
| `search_graph` | `fusion: true` | Serves the Sextant-fused engine instead of legacy BM25: deterministic intent classification, per-slot indexes (lexical BM25 + code-semantic and name-semantic HNSW over the shadow vault), RRF fusion, bounded temporal boost. Planner caps fail closed (`k≤100`, `ef≤512`, `slots≤16`) |
| `search_graph` | `fusion_override` | Explicit per-slot milli-weights (`{"S7": 1000, "S18": 600}`; `1000 = 1.0`). Naming a slot the corpus cannot serve refuses (`ASTRO_SEARCH_FUSION_SLOT_UNAVAILABLE`) rather than silently dropping it |
| `search_graph` | `temporal_alpha_millis` | Recency boost, 0 disables, capped at 100 (alpha 0.10). Larger values refuse |
| `search_graph` | `propagated_label` | Intersect hits with the project's inferred propagated labels (provisional trust) |
| `trace_path` | `scored: true` | Re-ranks the BFS into weighted best-first: ×0.9 per-hop attenuation, measured promoted-edge weights break equal-depth ties, callers and callees ranked independently, every hop tagged with trust + score. **Use this by default on shadow projects** |
| `query_graph` | `as_of: <epoch_ms>` | Time-travel Cypher: resolves the vault to the greatest committed MVCC snapshot at or before that instant. Fails closed if there is no state that old |
| `detect_changes` | *(automatic)* | Adds a `grounded_risk` block per impacted symbol from the change→outcome corpus; symbols with no evidence are labeled `provisional`, never silently defaulted |
| `index_status`, `get_architecture` | *(automatic)* | Augmented with vault/kernel/provenance/anomaly surfaces |

Omitting an extension selects the declared CBM-only mode and keeps its bytes stable. This is an explicit operating mode, not an error-recovery fallback; a requested Astrolabe extension either completes with its full persisted contract or returns a coded refusal.

### 4.2 The Astrolabe half — grounded intelligence (22 tools)

**All of these require `calyx:"shadow"`.** Grouped by what you would reach for them for.

#### Kernel and context — "what actually matters here"

| Tool | Use it to |
|---|---|
| **`get_kernel`** | Serve one atomically selected kernel generation: deterministic full-graph DFS feedback set plus residual-DAG proof, complete universal-S20 member index, and real external-query graph-routed recall. Project scopes support `read`, `gaps`, `quadrant`, and explicit-admission `build`. A `fleet:*` scope selects the atomic fleet generation for `read`/`gaps`/`quadrant`; serving rechecks its current pointer plus every repository generation/provenance header, while historical fixed-row fleet artifacts and in-tool fleet builds refuse. Any source/index/query/Ledger/lineage mismatch fails closed |
| **`kernel_answer`** | Grounded Q&A: resolves an anchored entry point, then walks association edges outward with `hop_score = edge_weight × 0.9^hop`, every hop carrying its ledger reference. Refuses with a per-lens deficit rather than answering ungrounded, and refuses rather than serving a multi-hop answer without complete ledger wiring |

#### Oracle — prediction, causation, forecasting

| Tool | Use it to |
|---|---|
| **`predict_impact`** | *"If I change X, what breaks?"* Composite consequence graph from real edges, grounded in the vault's occurrence rows, cycle-guarded butterfly walk (×0.7/hop, prune <0.05, depth ≤4), three independent ceilings keeping probability strictly < 1.0. Consequences intersecting `TESTS` edges become a **ranked test-selection set**. `mode:"backtest"` reads the exact gate attestation created automatically by the current shadow generation |
| **`abduce_cause`** | *"This failed — what most plausibly caused it?"* The inverse of `predict_impact`: reverse-walks the consequence graph (depth ≤3, ×0.7/hop) scoring candidates against failing occurrences they have actually preceded. Structural-only candidates are capped at 0.35 and labeled provisional. Every hypothesis names its **disconfirming test** |
| **`forecast`** | *"When will this fail again?"* `mode:"recurrence"` gives median inter-arrival, a credible interval, an overdue hazard, and CUSUM-detected regime changes. `mode:"flaky"` refuses on self-inconsistent pass/fail evidence rather than forecasting from noise |
| **`get_readiness`** | Six-tier readiness predicate for a project/scope. Tiers fail closed unless their measured source state exists |
| **`impute_fields`** | Proposals for a missing `doc` / `types` / `callees` / `tests` field. Always provisional; `write_as_trusted: true` is **refused by design** |

#### Guard — validating code before it lands

| Tool | Use it to |
|---|---|
| **`guard_calibrate`** | Build the per-domain conformal profile. `mode:"generated"` is the one to use: it auto-generates the bad population from the repo itself (mutating real HEAD source, revert records, the vulnerability registry, alien constellations from other indexed projects) and reads the good population from persisted slot vectors — **no hand-labeled data needed**. Enforces a mix policy (≥50 bad cases, ≥3 generators, ≤60% per generator) and fails closed on an under-mixed corpus. `domain` is `{language, scope_class}` |
| **`guard_check`** | Route a candidate symbol through the guard: measured on the **same instruments as indexing**, compared against kernel-near trusted exemplars, per-slot cosine vs calibrated tau, combined into `accept` / `new_region` / `quarantine` / `refuse` — never a flattened average. Ledgered with full per-slot detail |
| **`guard_advisory_hook`** | The fast path: two cheapest high-signal slots, hard 300 ms budget, **strictly advisory — never blocks and never refuses a valid candidate**. On timeout it goes silent and the skip is counted. `budget_ms` is tightening-only |
| **`guard_lock`** | Identity-lock exported/public symbols so `guard_check` enforces their public-API signature at the identity FAR — i.e. **breaking changes to a locked public surface refuse**. Modes `lock`/`unlock`/`inventory`/`rebuild` |
| **`guard_commit_ood`** | Score a whole commit's changed symbols; any non-`accept` verdict makes the commit out-of-distribution and raises a `new_region` trigger carrying the commit ref |

Guard slots (fixed): `code_semantic`, `struct_trigrams`, `api_callees`, `name_semantic`, `complexity_profile`, `error_surface`, `public_api_signature`.

> **What the guard is and is not:** it measures *distributional conformance to trusted exemplars*. It tells you "this does not look like the code that works here." It does not tell you the code is correct.

#### Grounding — feeding reality back in

| Tool | Use it to |
|---|---|
| **`anchor_outcome`** | Ground outcomes from a test report. `format`: `junit_xml`, `cargo_test_json`, `pytest_verbose`, `go_test_json`, `vitest_json`. `source` determines trust: `ci:` / `trace:` / `review:` / `git:revert:` are **Trusted** (confidence exactly 1.0); `git:fix:` / `agent:` / `survival:` are **Provisional** (0 < c < 1) |
| **`coverage_ingest`** | Stronger grounding: a coverage report (`lcov`, `coverage_py_json`, `cobertura_xml`) **plus** a suite run. Maps executed lines to containing symbols line-exact (resolved, confidence 1.0) and propagates passing tests one hop along `TESTS` edges within the changed-files impact set (proxy, 0.6). Coverage supersedes propagation |
| **`anchor_erase`** | Retract every anchor from one catalog source. Requires `confirm: true` — erased anchors leave every active query. Append-only physically (writes a tombstone + ledger entry), destructive to the serving view. Idempotent |

#### Measurement and self-optimization

| Tool | Use it to |
|---|---|
| **`measure_bits`** | Per-repo measured assay cards, replacing fixed constants with measured values. Modes: `signals` (per-slot bits ± CI about an axis), `sufficiency` (I(panel;axis) vs H(axis) + deficit breakdown), `redundancy` (total correlation, effective rank, pairwise map), `synergy` (three-way interaction information), `causality` (transfer-entropy DRIVES edges with lag sweep), `calibration` (each edge-resolution strategy's measured precision vs its prior, Wilson CI) |
| **`assay_gate`** | Admit/Park/Retire candidate lenses from measured capability cards. Ledgered and **reversible** (`mode:"revert"` restores prior serving state byte-for-byte) |
| **`optimizer_status`** | `status` (readiness readback), `ack_triggers` (durably acknowledge reactive triggers for a subscription), `propose` (turn measured deficits into a persisted proposal queue). `ASTRO_ANNEAL=0` in the environment is a global freeze on optimizer mutations |
| **`detect_anomalies`** | Calibrated findings by `kind`: `doc_drift` (docs no longer describe the code), `name_truth` (name lies about behavior), `drift`, `ood_commit`, `prompt_injection` |

#### Similarity, provenance, sharing

| Tool | Use it to |
|---|---|
| **`find_similar`** | Neighbors of an anchor symbol by signal: `structural`, `api`, `semantic`, `clone`, `agree`, `disagree`. `k` (10, cap 100), `ef` (64, cap 512). **`clone` finds copy-paste debt; `disagree` finds the places where two signals conflict — often exactly where a bug hides** |
| **`get_provenance`** | `lineage`, `answer_trace` (an answer's lineage, with legs it does not carry reported as explicit unprovenanced warnings rather than fabricated), `verify_chain` (hash-chain integrity), `reproduce` (live re-execute a recorded answer with frozen lenses + recorded seeds; unchanged vault reproduces bit-for-bit, drift beyond 1e-3 fails closed), `inter_agent_trust` (verify a context pack another agent handed you) |
| **`team_artifact`** | `export` writes `graph.db.zst` + `vault.export.zst` + `artifact.json`; `import` **verifies before adopting** graph bytes. Optional Ed25519 signing (`signing_key_hex` / `expected_signer_pubkey_hex`). This is how a second agent or teammate bootstraps in seconds instead of re-indexing |

---

## 5. Playbook A — orient in an unfamiliar codebase

**Goal:** go from zero knowledge to a correct mental model in a handful of bounded calls instead of 40 file reads.

```
1. index_repository { repo_path, mode: "full", calyx: "shadow" }
2. get_architecture  { project, aspects: ["overview", "entry_points", "boundaries"] }
3. get_architecture  { project, aspects: ["clusters"], resolution: <finite-positive>,
                       cluster_max_nodes: <measured-positive-bound>,
                       cluster_max_edges: <measured-positive-bound>,
                       cluster_max_move_visits: <explicit-positive-work-cap>,
                       cluster_max_result_bytes: <explicit-positive-byte-cap> }
4. get_kernel        { project, mode: "read" }
5. get_kernel        { project, mode: "quadrant" }
```

**How to read the results:**

- `get_architecture.clusters` is the highest-value block most agents skip. Leiden community detection over the call/import graph surfaces the **de-facto modules** — which routinely disagree with the folder layout. It has no implicit policy defaults: read the narrow overview first, then supply all five controls from the measured graph and the operation budget. A folder/cluster disagreement is measured coupling evidence worth reporting, not authority to ignore a declared source boundary.
- `get_kernel mode:"read"` gives you the ~small set of symbols that dominate the association graph. **Read these first.** Reading the 20 kernel members teaches you more than reading 200 random files.
- `get_kernel mode:"quadrant"` classifies every member into critical/peripheral × verified/unverified. The **critical-and-unverified** quadrant is where risk lives — it is your test-writing target list and the place to be most careful when editing.
- `get_kernel mode:"gaps"` ranks ungrounded kernel members by importance: "here be dragons."

Then, for any specific question:

```
6. kernel_answer { project, query: "how does request authentication work?" }
```

If it refuses with a deficit, that is informative: the codebase has no grounded path for that question yet. Report the exact deficit and stop that grounded operation. `search_graph` + `trace_path` may be run as a separately requested, explicitly ungrounded analysis; they are never substituted under the refused claim. If the refusal names a missing kernel, `get_kernel mode:"build"` requires a real external operator-query corpus and every explicit routing/admission parameter—never synthesized graph-node queries.

**Also worth one call each on a new repo:**
- `get_graph_schema` — tells you which edge types this project actually has, so you do not write Cypher against edges that were never extracted.
- `detect_anomalies { kind: "doc_drift" }` — where the documentation is lying to you before you believe it.

---

## 6. Playbook B — find the right code (stop grepping)

### The decision table

| You are looking for | Use | Why |
|---|---|---|
| A concept, described in words | `search_graph { query: "update user settings" }` | BM25 with camelCase splitting (`updateCloudClient` → update, cloud, client) and symbol-category boosting (Functions/Methods +10, Routes +8, Classes/Interfaces/Types/Enums +5) |
| A concept whose vocabulary you do not know | `search_graph { semantic_query: ["send", "publish", "emit"] }` | Vector search bridges vocabulary — finds `publish` when you searched `send`. **Must be an array**; each keyword scored independently by per-keyword min-cosine, results returned in `semantic_results` (separate from `results`). Requires `moderate`/`full` index |
| The best hits across all signals at once | `search_graph { query: "...", fusion: true }` | RRF-fused lexical + code-semantic + name-semantic with intent classification. Shadow only |
| A name pattern | `search_graph { name_pattern: ".*Handler$" }` or `qn_pattern` | Exact regex over persisted names |
| A literal string, magic number, config key, or comment | `search_code { pattern, mode: "compact" }` | Grep, then deduplicated into containing functions and ranked by structural importance (definitions first, popular functions next, tests last) |
| Who calls this / what does this call | `trace_path { mode: "calls", scored: true }` | Never grep for callers |
| Where a value flows | `trace_path { mode: "data_flow", parameter_name: "userId" }` | Follows `CALLS` + `DATA_FLOWS` with argument expressions at each hop |
| Across services | `trace_path { mode: "cross_service" }` | Follows HTTP/async edges through Route nodes and `CROSS_*` cross-repo edges |
| Code like this code | `find_similar { symbol, mode: "structural" \| "api" \| "clone" }` | Pattern discovery and copy-paste debt |
| A complex structural pattern | `query_graph { query: "<Cypher>" }` | Multi-hop, aggregation, property filters |

### Pagination — the trap that silently loses results

- `search_graph`: `limit` default **200**; response carries exact `total` and deterministic `has_more`. Page with `offset += limit` **until `has_more` is false**. Narrow by `label` / `file_pattern` before paginating a large set.
- `search_code`: `limit` default **10**, and **there is no `offset`**. Compare `total_grep_matches` and `total_results` against your limit to detect truncation; to see more, raise `limit` or narrow with `file_pattern` / `path_filter`.
- `query_graph`: hard **100k row ceiling**, no offset. Put `LIMIT` in the Cypher itself for broad queries.

Ignoring `has_more` is the single most common way an agent draws a confident conclusion from a truncated result set.

### Reading source correctly

```
search_graph → take the stable atom_id → get_code_snippet { atom_id, project }
```

`get_code_snippet` is a **read** tool, not a search tool. A `qualified_name` lookup works only when it resolves to exactly one atom. Every `search_graph` node also carries authoritative persisted `start_line`, `end_line`, `start_byte`, `end_byte` (genuinely spanless structural nodes carry explicit zeroes) — so you can slice files precisely instead of reading whole ones.

---

## 7. Playbook C — plan a change before writing it

This is where ASTROLABE most changes an agent's behavior. **Before editing, ask what breaks.**

```
1. search_graph  { project, query: "<the thing to change>" }        → resolve exact qualified_name
2. predict_impact{ project, seeds: ["crate::module::function"] }
3. trace_path    { project, function_name, direction: "inbound", depth: 3, scored: true, risk_labels: true }
4. get_kernel    { project, mode: "quadrant" }                       → is your target critical-and-unverified?
5. guard_lock    { project, mode: "inventory" }                      → is your target an identity-locked public API?
```

**How to act on it:**

- `predict_impact` returns ranked consequences **and a test-selection set** (consequences intersecting `TESTS` edges). Run *those* tests, not the whole suite. That is often the difference between a 20-second and a 20-minute verification loop.
- Grounded confidence is served **only** when the current corpus/graph/kernel generation carries its exact passing chronological gate attestation. An absent, failed, corrupt, or stale gate refuses without fallback. `predict_impact mode:"backtest"` reads the automatic attestation and its source-proven cases; it does not create or approve one.
- If `predict_impact` refuses with a deficit card, the seeds have no grounded history. Do not read that as "safe to change"—report "no evidence either way" and stop the grounded operation. A topology-only `trace_path` is a separate, explicitly ungrounded request, never the refused result under another name.
- If your target is identity-locked, a breaking signature change will be refused by `guard_check`. Plan a compatible change or an explicit deprecation, not a surprise break.

**For a diff you already have:**

```
detect_changes { project, since: "HEAD~5", depth: 2,
                 changed_file_max: <positive-file-bound>,
                 impact_max_symbols: <positive-symbol-bound>,
                 reach_max_nodes_per_symbol: <positive-node-bound>,
                 result_max_bytes: <positive-byte-bound> }
```

On a shadow project this comes back with a `grounded_risk` block per impacted symbol, sourced from the change→outcome corpus. Symbols with no grounded evidence are explicitly labeled provisional. Rank your review attention by that block.

---

## 8. Playbook D — write code that fits the codebase

The failure mode of a generic coding agent is writing code that is *correct in isolation and alien in context* — wrong error handling idiom, wrong logging, wrong layering, wrong naming. ASTROLABE fixes this in three moves.

**1. Learn the local idiom before writing.**

```
find_similar { project, symbol: "<the nearest existing symbol>", mode: "structural", k: 5 }
→ get_code_snippet on each
```

Five real neighbors of the thing you are about to write are worth more than any style guide. `mode:"api"` finds symbols with the same call surface; `mode:"semantic"` finds the same purpose with different structure.

**2. Check your candidate against the guard before you commit to it.**

One-time per repo/domain:

```json
{ "tool": "guard_calibrate",
  "arguments": {
    "project": "my-service",
    "mode": "generated",
    "domain": { "language": "rust", "scope_class": "core" },
    "mutation_sources": ["<real HEAD source text>", "..."],
    "aliens": [{ "project": "some-other-indexed-project" }],
    "seed": 0
  } }
```

Then per candidate:

```
guard_check { project, target: "<CxId hex>", candidate: {slots}, exemplars: [...] }
```

Verdicts and what to do:

| Verdict | Meaning | Action |
|---|---|---|
| `accept` | Conforms to the trusted region | Proceed |
| `new_region` | Legitimately novel — outside the known distribution | Proceed **with justification**; an `AwaitingGrounding` lifecycle entry is recorded. Ground it with a test |
| `quarantine` | Substantially off-distribution | Rework before landing |
| `refuse` | Violates a locked contract (e.g. identity-locked public API signature) | Do not land. Redesign |

**3. Use the advisory hook for the inner loop.** `guard_advisory_hook` scores only two slots under a 300 ms budget and never blocks. It is designed to run on every edit — wire it into your harness's post-edit path (§13) so you get a nudge in real time and reserve the full `guard_check` for pre-commit.

**Complementary check — is your change consistent with what the code says about itself?**

```
detect_anomalies { project, kind: "doc_drift" }   → docs that no longer match code
detect_anomalies { project, kind: "name_truth" }  → names that lie about behavior
```

Run these after a substantial refactor. Fixing the doc drift you introduced is cheap now and expensive later.

---

## 9. Playbook E — debug a failure backwards

```
1. abduce_cause { project,
                  failure: "crate::module::failing_symbol",
                  recent_changes: ["<qualified names you just touched>"],
                  observed_at: <epoch> }
2. trace_path   { project, function_name: "<top candidate>", mode: "data_flow", direction: "both", scored: true }
3. get_code_snippet on the candidate
4. forecast     { project, subject: "<the failing test>", mode: "flaky" }
```

**Reading `abduce_cause` correctly:**

- Candidates with grounded failing history score `s/(s+1)` — always strictly below 1.0. **Nothing is ever certain.**
- Structural-only candidates (no failing history, just reachable) are labeled provisional leaves capped at **0.35**. Do not chase these first.
- Two cross-checks — membership in your `recent_changes` and a `DRIVES` edge into the failure region — can only rank a grounded cause **up**, never manufacture one.
- **Every hypothesis names its disconfirming test.** Run that test. This is the highest-leverage line in the whole response: it converts a ranked guess into a decidable experiment.
- Names in `recent_changes` that do not resolve are labeled and ignored, never guessed at.

**The flaky check matters.** Before you spend an hour debugging, `forecast mode:"flaky"` will refuse with `ASTRO_FLAKY_EVIDENCE` if the test's pass/fail series is self-inconsistent. That refusal is telling you the test is the problem, not the code.

**`forecast mode:"recurrence"`** answers "when will this bite again?" with a median inter-arrival interval, a credible interval (widened and labeled provisional on small samples), an overdue hazard, and CUSUM-detected regime changes. Confidence is `regularity × support`, strictly < 1.0. Use it to decide whether a flake is worth fixing now.

---

## 10. Playbook F — review, refactor, and hunt performance

### Performance: the complexity properties are queryable

Every `Function` and `Method` node carries measured complexity properties. This turns performance archaeology into one query:

```cypher
MATCH (f:Function)
WHERE f.transitive_loop_depth >= 3 OR f.linear_scan_in_loop >= 1
RETURN f.qualified_name, f.transitive_loop_depth, f.linear_scan_in_loop,
       f.alloc_in_loop, f.recursion_in_loop
ORDER BY f.transitive_loop_depth DESC
```

The full property set:

| Property | Signal |
|---|---|
| `complexity` (cyclomatic), `cognitive` | Classic complexity |
| `loop_count`, `loop_depth` | Nested-loop degree — a polynomial-degree proxy |
| `transitive_loop_depth` | **Interprocedural** worst-case nesting propagated along `CALLS`. Catches the O(n²) that is split across two functions |
| `linear_scan_in_loop` | find/contains/indexOf-style scans inside a loop — **the hidden O(n²) that `loop_depth` misses** |
| `alloc_in_loop` | Allocations/appends inside a loop |
| `recursion_in_loop`, `recursive`, `unguarded_recursion` | Recursion hazards; `unguarded_recursion` = no conditionally-guarded base case |
| `param_count`, `max_access_depth` | Structure smells (long parameter lists, Law-of-Demeter violations) |

### Refactoring: find the duplication and the disagreement

```
find_similar { project, symbol, mode: "clone" }     → copy-paste debt to consolidate
find_similar { project, symbol, mode: "disagree" }  → where two signals disagree about this symbol
```

`mode:"disagree"` is subtle and valuable: it surfaces symbols where, say, the structural signal and the semantic signal point different directions. That mismatch is frequently where a misleading abstraction or a latent bug lives.

### Review: rank attention by grounded risk

```
1. detect_changes    { project, since: "<base>", depth: 2,
                       changed_file_max: <positive-file-bound>,
                       impact_max_symbols: <positive-symbol-bound>,
                       reach_max_nodes_per_symbol: <positive-node-bound>,
                       result_max_bytes: <positive-byte-bound> }
                     → grounded_risk per impacted symbol, or an exact generation/gate refusal
2. predict_impact    { project, seeds: [<changed symbols>] }  → blast radius + test selection
3. guard_commit_ood  { project, commit_ref, symbols: [...] }  → is the commit as a whole off-distribution?
4. get_kernel        { project, mode: "gaps" }                → did the change touch an important, ungrounded symbol?
```

A commit whose symbols all conform raises no alarm; any non-`accept` symbol makes the commit out-of-distribution and raises a `new_region` trigger carrying the commit ref, visible on `optimizer_status.commit_ood` and `get_readiness.commit_ood`.

### Time travel: what did this look like before?

```json
{ "tool": "query_graph",
  "arguments": { "project": "my-service", "as_of": 1750000000000,
                 "query": "MATCH (f:Function {name:'handle_request'}) RETURN f" } }
```

Resolves the vault to the greatest committed MVCC snapshot at or before that epoch-millisecond instant. Fails closed if the vault has no state that old. Useful for "when did this function acquire that dependency?"

---

## 11. The compounding loop — how ASTROLABE gets smarter about *your* repo

This is the part most agents never reach, and it is where the leverage is. A freshly indexed repo has structure but little grounding, so the oracle and guard surfaces refuse a lot. Every outcome you feed back makes them answer more and refuse less.

### 11.1 After every test run

```json
{ "tool": "anchor_outcome",
  "arguments": {
    "project": "my-service",
    "kind": "test_run",
    "source": "ci:github:owner/repo:run-4211",
    "format": "cargo_test_json",
    "report": "<full report text>",
    "observed_at": 1750000000
  } }
```

Source prefix decides trust, and it is not negotiable:

| Prefix | Trust | Confidence |
|---|---|---|
| `ci:` `trace:` `review:` `git:revert:` | **Trusted** (resolved evidence) | exactly `1.0` |
| `git:fix:` `agent:` `survival:` | **Provisional** (proxy evidence) | finite value in (0,1), default 0.8 |

Pass an explicit `observed_at` for reproducible anchoring. `ci:` and `agent:` sources require owner plus observation components.

### 11.2 When you have coverage, use `coverage_ingest` instead

It is strictly stronger: executed lines map to containing symbols **line-exact** (resolved, confidence 1.0), and passing tests propagate one hop along `TESTS` edges — but only within `impact_files`, so the fan-out cannot manufacture grounding. Coverage supersedes propagation wherever both apply. Reports `anchored` / `excluded_by_fanout` / `unmatched` counts, and refuses fail-closed with **no partial anchor** on a malformed report.

### 11.3 When you have production telemetry

```json
{ "tool": "ingest_traces",
  "arguments": { "project": "my-service", "otlp_protobuf_base64": "<...>" } }
```

Runtime traces **promote matching graph edges to Trusted** — the difference between "the parser says A can call B" and "A calls B in production 40,000 times a day" — attach runtime anchors, and flag 5xx incidents. This is the single highest-value grounding source for a live service.

### 11.4 Establish the gates, once per repo

```
predict_impact { project, mode: "backtest" }   → reads the current automatic gate attestation
guard_calibrate{ project, mode: "generated", domain: {...} }  → persists the conformal profile
get_kernel     { project, mode: "build" }      → distills and persists the kernel
```

Without a passing exact-generation gate attestation, `predict_impact` refuses grounded serving. Without the calibrated profile, every guard tool refuses. Without a kernel, `kernel_answer` refuses and tells you to build one.

### 11.5 Watch the system watch itself

```
get_readiness    { project }              → six-tier readiness, fail-closed per tier
optimizer_status { project, mode: "status" }
optimizer_status { project, mode: "propose" }   → turn measured deficits into a proposal queue
measure_bits     { project, mode: "sufficiency", axis: "<outcome axis>" }
```

`measure_bits mode:"sufficiency"` is the instrumentation to-do list: it reports I(panel;axis) against H(axis) with a deficit breakdown — literally "here is how much of the outcome your measurements can explain, and what is missing."

### 11.6 Share the result

```
team_artifact { mode: "export", project, repo_path }
team_artifact { mode: "import", repo_path }     → verifies before adopting graph bytes
```

Another agent (or the same agent in a fresh session, or a teammate) bootstraps from a chain-verified artifact instead of paying full indexing cost. If you received a context pack from another agent and want to verify its claims against your own vault: `get_provenance mode:"inter_agent_trust"` with the pack manifest or attestation.

---

## 12. Honest limits — what is not live yet

Per `docs/status/current-state.md` and `docs/status/delivered.md` (2026-07-25 snapshot). Live project state is on GitHub issues, not here — re-check before depending on any of this.

- **`get_context_pack` does not exist yet.** The flagship one-call context assembler is tracked and not started ([#41]). Compose it yourself today: `get_kernel` + `search_graph fusion:true` + `trace_path scored:true` + `get_code_snippet`.
- **Unified search primary-flip is not done** ([#42] / [#44]). `fusion:true` is opt-in; the legacy BM25 path remains the byte-identical default.
- **Several surfaces are read paths ahead of their producers.** `optimizer_status`, `get_readiness`, `impute_fields`, skills, bridges, and anomaly surfaces have partial contracts while their producer/lifecycle issues remain open. Expect labeled `provisional` and honest refusals rather than rich answers.
- **`kernel_answer` is wired, but a real multi-hop Trusted-grounded demonstration is still tracked** ([#407]). Treat multi-hop answers as promising, not proven.
- **Incremental convergence is unfinished** ([#23]). After large edits, prefer an explicit re-index over trusting the watcher.
- **Ingestion correctness is under active audit.** A large 2026-07-23–25 wave found source-byte, identity, snapshot, durability, concurrency, and language-semantic defects. Wrong atoms contaminate every downstream measurement — so check `index_status` health and `get_provenance mode:"verify_chain"` before betting a large refactor on a grounded claim.
- **Windows only.** Cross-platform is a deliberate final phase; there is no Linux/macOS support today.
- **Non-goals:** no security tooling (ASTROLABE is a single-operator local system by owner directive), no CI/CD integration on ASTROLABE's own side, no test suite in ASTROLABE's own repo.

**The general rule:** if a tool answers, the answer carries its own trust label and you can act on it accordingly. If it refuses, believe the refusal — it is measuring its own evidence, and reading `remediation` tells you exactly what to do next.

---

## 13. Harness integration (hooks, CLI, refusal handling)

### 13.0 Which binary

`crates/astrolabe-server` builds two entrypoints that share one implementation: **`codebase-memory-mcp`** (the shim the installed MCP server and CLI drivers execute) and **`astrolabe`**. Both dispatch identically — stdio MCP server with no arguments, `cli <tool>` for command-line use, `hook-augment` for the hook. Use whichever name your installation exposes; the examples below use each once deliberately.

### 13.1 The PreToolUse augmentation hook — free context on every grep

The server binary has a built-in hook mode. When your agent runs a `Grep` or `Glob`, it extracts the longest identifier-like token from the pattern, resolves the enclosing indexed project by walking up from `cwd`, and returns graph context as `additionalContext` — under a 300 ms budget, silent on timeout, capped at 5 results and 256 KiB of stdin.

```jsonc
// .claude/settings.json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "Grep|Glob",
      "hooks": [{ "type": "command",
                  "command": "path/to/codebase-memory-mcp hook-augment" }]
    }]
  }
}
```

Effect: every time the agent reaches for text search out of habit, it gets the graph's view of that symbol for free. It is the cheapest possible upgrade to an existing agent loop.

### 13.2 CLI mode — scripts, hooks, and CI drivers

Every MCP tool is also reachable from the command line:

```bash
astrolabe cli <tool_name> --args-file <path-to-json>
echo '<json>' | astrolabe cli <tool_name>
astrolabe cli <tool_name> --help          # prints the tool's arguments, runs nothing
astrolabe cli <tool_name> --json ...      # raw result JSON on stdout; exit 1 on isError
```

- `--json` makes exit code meaningful (`1` when the tool result is `isError: true`), so shell drivers see failures.
- `--help` / `-h` anywhere after the tool name prints help and exits **without opening or mutating any store**.
- Raw JSON as a bare argv argument is no longer supported — use `--args-file` or stdin.
- CLI mode raises the stderr log floor so the supported forms emit clean stderr.

### 13.3 Environment and configuration

| Knob | Effect |
|---|---|
| `CBM_CACHE_DIR` | Where project stores live. **Do not set this globally without understanding the consequences** — it relocates every project's store |
| `ASTRO_ANNEAL=0` | Global freeze on optimizer mutations (`optimizer_status mode:"propose"` refuses with `ASTRO_OPTIMIZER_PROPOSE_FROZEN`) |
| `ASTROLABE_VERIFY_CHAIN_LOOP`, `ASTROLABE_VERIFY_CHAIN_INTERVAL_MS` | Background ledger chain verification loop |
| `auto_watch` (persisted config key) | Enables the incremental watcher lane that re-indexes on file changes |

### 13.4 Handling refusals programmatically

A durable agent loop should implement this ladder:

```
call tool
├── isError: false
│   ├── trust ∈ {verified, trusted} → act
│   └── trust = provisional         → act cautiously, disclose the label to the user
└── isError: true
    ├── code ∈ ASTRO_SHADOW_*       → re-index, retry once
    ├── code names a missing Oracle gate → publish a new source-grounded shadow generation; never approve it manually
    ├── code = *DEFICIT / Insufficient → do NOT retry; report the deficit and stop this
    │                                     grounded operation without substituting another result
    └── otherwise                    → surface {code, message, remediation} verbatim
```

Retry **once** after a remediation. Never loop on a refusal — ASTROLABE refuses because the evidence is not there, and calling again will not create evidence.

---

## 14. Cost, latency, and token discipline

| Operation | Cost | Guidance |
|---|---|---|
| `index_repository mode:"full"` + shadow | Expensive (minutes on a large repo) | Once per repo, then incremental. Use `persistence:true` and `team_artifact` so it is paid once across agents |
| `get_architecture aspects:["all"]` | Large response (includes `file_tree`) | Prefer `["overview"]` (everything except `file_tree`) or name exactly the aspects you need |
| `search_graph` | Cheap | Default `limit:200` is often more than you need; lower it and use `label`/`file_pattern` to narrow |
| `search_code mode:"full"` | Token-heavy (returns source) | Use `compact` (signatures + metadata) to triage, then `get_code_snippet` on the few that matter |
| `query_graph` | Varies wildly | Always put `LIMIT` in broad Cypher; the 100k ceiling is a backstop, not a plan |
| `trace_path depth:5+` | Fan-out explodes | Start at `depth:2–3`; add `scored:true` so the useful hops rank first; set `include_tests:false` (the default) unless you need them |
| `guard_check` | Moderate (measures through the real panel) | Pre-commit |
| `guard_advisory_hook` | ≤300 ms by construction | Per-edit |
| `get_kernel mode:"build"` | Expensive (recomputes over the whole association graph) | Once per significant index generation |
| `guard_calibrate mode:"generated"` | Expensive on M-scale corpora | Once per domain; bound it with `good_sample_cap` / `alien_sample_cap` |

**Token discipline in one line:** search wide and cheap (`search_graph`, `search_code mode:"compact"`), then read narrow and deep (`get_code_snippet` by `atom_id`). Never dump `mode:"full"` search results into context to "have a look."

---

## 15. Anti-patterns

| ❌ Don't | ✅ Do | Why |
|---|---|---|
| Grep for callers of a function | `trace_path direction:"inbound"` | Grep finds same-named symbols in unrelated modules and misses dynamic/aliased calls the LSP resolved |
| Index without `calyx:"shadow"` and then wonder why every Astrolabe tool refuses | Pass `calyx:"shadow"` on the first index | The dial is the master switch for 22 of 36 tools |
| Treat a `provisional` label as fact | Disclose it, or ground it first | Invariant 1: no unlabeled claim |
| Retry a refusal in a loop | Read `remediation`, do that one thing, retry once | Refusals are measurements, not transient errors |
| Pass `semantic_query: "send"` | `semantic_query: ["send", "publish"]` | It must be an array; each keyword is scored independently |
| Ignore `has_more` / `total_grep_matches` | Paginate or narrow until complete | Truncated results produce confidently wrong conclusions |
| Call `get_code_snippet` with a `qualified_name` you guessed | `search_graph` first, pass the stable `atom_id` | Name lookup only works when it resolves to exactly one atom |
| Edit first, check impact after | `predict_impact` before writing | The whole point |
| Run the full test suite | Run `predict_impact`'s test-selection set | Ranked by grounded consequence, not by folder |
| Take a `guard_check` `accept` as proof of correctness | Treat it as "conforms to this codebase's distribution" | The guard measures conformance, not correctness |
| Treat `abduce_cause`'s top candidate as the answer | Run its named disconfirming test | Every hypothesis is capped strictly below certainty for a reason |
| Reason on a stale index | `index_status` first; re-index on drift | `ASTRO_SOURCE_DRIFT` exists so the system never lies about what it read |
| Pass `name` to `index_repository` | Use the returned `project` | Storage identity derives only from the canonical repo root; the override is refused |
| Set `write_as_trusted:true` on `impute_fields` | Accept the proposal as provisional | Imputed values can never be merged as trusted data — the tool refuses |
| Call `anchor_erase` without thinking | Confirm deliberately | Erased anchors leave every active query; `confirm:true` is required for that reason |

---

## 16. Quick reference card

**Session start (shadow project):**
```
index_status → get_kernel mode:"read" → get_architecture aspects:["overview"]
→ get_architecture aspects:["clusters"] + all five explicit cluster controls
```

**Find something:**
```
concept  → search_graph query:"..." (add fusion:true)
unknown vocabulary → search_graph semantic_query:["a","b"]
literal  → search_code pattern:"..." mode:"compact"
read it  → get_code_snippet atom_id:"..."
```

**Before changing something:**
```
predict_impact seeds:[...] → trace_path direction:"inbound" scored:true → guard_lock mode:"inventory"
```

**While writing:**
```
find_similar mode:"structural" → guard_advisory_hook (≤300ms) → guard_check (pre-commit)
```

**When something breaks:**
```
abduce_cause failure:"..." recent_changes:[...] → run the named disconfirming test → forecast mode:"flaky"
```

**After it works:**
```
anchor_outcome / coverage_ingest / ingest_traces → the system gets better at your repo
```

**When you doubt an answer:**
```
get_provenance mode:"verify_chain" | mode:"reproduce" | mode:"answer_trace"
```

---

### Related documents

| Document | Role |
|---|---|
| [`README.md`](../README.md) | What ASTROLABE is; native Windows build instructions |
| [`CLAUDE.md`](../CLAUDE.md) | Agent operating manual for *developing* ASTROLABE (workflow, launcher, hygiene) |
| [`docs/astrolabe-blueprint.md`](astrolabe-blueprint.md) | Plan of record — the full 23-part design and capability catalog |
| [`docs/BUILDING_ON_CALYX.md`](BUILDING_ON_CALYX.md) | Binding upstream doctrine (embed-vs-encode, the anti-pattern list) |
| [`docs/status/`](status/) | Snapshot of delivered vs remaining scope |
| [EPIC #65](https://github.com/ChrisRoyse/Astrolabe/issues/65) | Live master tracker — the only authority on project state |

**Source of truth for this document:** `crates/astrolabe-server/src/migration/tool_defs.rs` (22 Astrolabe tools), `cbm/src/mcp/mcp.c` `TOOLS[]` (14 CBM tools), and the schema overlays in `dispatch.rs`, `search_fusion.rs`, `trace_path.rs`, `query_graph_as_of.rs`. When those disagree with this guide, they win — and this guide should be corrected.
