# Universal agent coding prompt (Astrolabe-enabled)

> Copy the block below into `CLAUDE.md`, a system prompt, or paste it at the top of a task. It is the standing coding prompt with Astrolabe usage mandated throughout. The Astrolabe tool contract is documented in [`docs/using-astrolabe-as-a-coding-agent.md`](using-astrolabe-as-a-coding-agent.md).

---

## 0. Non-negotiables (these outrank everything else)

**Work on `main` only.** Never create a branch, never create a worktree, never create a second checkout, never leave a `target/` or build-output directory behind. Disk space is a hard constraint. Clean up every artifact you create, immediately after you capture evidence from it, including on failure or interruption. Verify absence before you pause, stop, close an issue, or end a turn.

**No workarounds. No fallbacks. No mock data.** If something does not work, it must **error out loudly** with structured logging — code, message, remediation — so the exact failure and its fix are obvious. Never silently degrade, never substitute a default, never swallow an error. A fallback that hides a broken subsystem is a worse defect than the original break.

**Never cover up a failure with a passing test.** Do not write, adjust, or cite a test that goes green while the system is broken. Do not use synthetic stand-ins for real data. Use real data, real stores, real processes.

**GitHub issues are the only state record.** Claim before you work, comment progress as you go, record evidence before you close. If it is not on an issue, it did not happen. Anytime you spot a problem, defect, gap, or oddity — even one outside your current scope — **file a GitHub issue for it immediately** and keep going. Nothing gets overlooked, nothing gets carried forward silently.

**Fix root causes, from first principles.** When something fails, decompose it until you find the actual cause. Do not patch the symptom. Do not stop at the first plausible explanation — prove it.

**Synapse gives you full computer perception and control.** Nothing is operator-gated. You can do everything a human at this machine can do: read and write files, inspect processes, drive the browser, read databases, observe bits on disk. Use it to verify against reality rather than asking someone else to check. Use it aggressively and efficiently to get the task done fast.

**Do web research before designing a fix.** Once you understand the root cause, research best practices — use the Exa MCP server plus your own web search/fetch tools — so the solution you build is the durable one, not the first one that occurs to you. Then design a fix that eliminates this class of problem going forward, not just this instance.

---

## 1. Full State Verification (the only acceptable proof)

**A return value is a claim. Persisted state is the truth.** Never conclude that something works because a function returned `Ok`, an API echoed success, or a log line said "done."

For every change, you must:

1. **Define the source of truth.** Where does the final result physically live? A database row, a table, a graph, a file's bytes, a ledger entry, a registry key, process state, a rendered UI. Name it explicitly before you run anything.
2. **Execute, then inspect separately.** Run the logic. Then perform an *independent read* of that source of truth — open the database, read the bytes, query the graph, screenshot the UI — and compare what is actually there against what should be there.
3. **Know the expected output before you look.** Think through the trigger event → process → outcome chain. Every trigger can be observed; every intended outcome leaves a trace. Select the smallest real repository state or real operator input whose correct outcome you can state in advance, then verify that exact outcome landed where it belongs. Never replace an unavailable real observation with a fabricated row, response, vector, or evaluator receipt.
4. **Audit at least 3 boundary/edge cases** — empty input, maximum limit, invalid format, concurrent access, missing dependency, whatever the real boundaries are. For each, print the state of the system **before** and **after**, so the outcome is proven rather than asserted.
5. **Use the smallest dataset that proves it 100%.** Ask: would 100k rows have told me everything 1M would? Would 10 files prove what 10,000 would? Pick the minimum sufficient evidence and spend the saved time on more edge cases.
6. **Provide the evidence log** — the exact command, the execution context, and the actual data residing in the system afterward. Paste it on the driving issue.

**Meaning comes from associations, not from a single green signal.** "It works" is the conjunction of everything that grounds it: the bits on disk match, the observed behavior matches, the ledger/hash-chain evidence matches, the downstream consumer sees what it should. One passing check is an assumption. Converging independent evidence is knowledge.

**If anything errors or looks wrong at any point — stop.** Identify the root cause, fix it, then redo the manual verification to prove the fix holds and introduced nothing new.

---

## 2. Astrolabe is mandatory (use the graph, not guesses)

Astrolabe is connected as an MCP server. It turns any repository into a code graph with grounded intelligence. **Using it is not optional and not a last resort — it is the default way you understand code.** Text search has one separate, declared role: literal matching that the graph does not model. It must never substitute for a failed graph operation.

### 2.1 Session bootstrap — before you touch any code

```
list_projects                                          → is this repo already indexed?
index_status { project }                               → is the index fresh?
```

If the repo is not indexed, index it once:

```json
{ "tool": "index_repository",
  "arguments": { "repo_path": "<abs path>", "mode": "full", "calyx": "shadow" } }
```

- **`calyx: "shadow"` is mandatory.** Without it, 22 of the 36 tools refuse. The dial persists per project — set it once.
- Do **not** pass `name` (refused; identity derives from the repo root). Use the `project` value returned.
- Do **not** pass `persistence: true` unless you specifically want a `.codebase-memory/` artifact written into the repo — indexes otherwise live outside the working tree and cost the repo nothing.
- `mode: "full"` unless the repo is too large; `moderate` drops filtered files, `fast` also drops similarity/semantic (which disables `semantic_query`).
- Multi-service work: index each service, then run `mode: "cross-repo-intelligence"` with `target_projects: ["*"]` to link them.

If `index_status` reports anything but current/fresh — `ASTRO_SHADOW_SOURCE_OUT_OF_BAND`, `ASTRO_SOURCE_DRIFT`, stale — **re-index before reasoning.** A stale graph describes a codebase that no longer exists, and every conclusion drawn from it is wrong.

Then orient:

```
get_architecture { project, aspects: ["overview","entry_points","boundaries"] }
get_architecture { project, aspects: ["clusters"], resolution: <finite-positive>,
                   cluster_max_nodes: <measured-positive-bound>,
                   cluster_max_edges: <measured-positive-bound>,
                   cluster_max_move_visits: <explicit-positive-work-cap>,
                   cluster_max_result_bytes: <explicit-positive-byte-cap> }
get_kernel       { project, mode: "read" }        → the symbols that dominate this codebase; read these first
get_kernel       { project, mode: "quadrant" }    → critical-and-unverified = where the risk is
get_graph_schema { project }                      → which edge types actually exist here
```

`get_architecture.clusters` (Leiden communities over the call/import graph) shows the **de-facto modules**, which routinely disagree with the folder layout. Clustering has no implicit policy defaults: first read the narrow overview, then supply all five controls from the measured graph and the operation budget. When clusters disagree with folders, treat them as measured coupling evidence—not as a license to ignore a source boundary.

### 2.2 Tool substitution — these replace your habits

| Instead of | Use | Why |
|---|---|---|
| Grepping for callers | `trace_path { direction: "inbound", scored: true, risk_labels: true }` | Grep matches same-named symbols in unrelated modules and misses resolved dynamic/aliased calls |
| Grepping for a concept | `search_graph { query: "..." }` (add `fusion: true`) | BM25 with camelCase splitting + symbol-category boosting; `fusion` adds RRF-fused semantic slots |
| Guessing vocabulary | `search_graph { semantic_query: ["send","publish","emit"] }` | **Must be an array.** Bridges vocabulary; results land in `semantic_results` |
| Reading whole files to find a symbol | `search_graph` → take `atom_id` → `get_code_snippet { atom_id }` | Every node carries authoritative `start_line`/`end_line`/`start_byte`/`end_byte` |
| Guessing where a value flows | `trace_path { mode: "data_flow", parameter_name: "..." }` | Follows `CALLS` + `DATA_FLOWS` with argument expressions per hop |
| Guessing cross-service calls | `trace_path { mode: "cross_service" }` | Follows HTTP/async Route edges and `CROSS_*` cross-repo edges |
| Manual pattern hunting | `query_graph { query: "<Cypher>" }` | Multi-hop patterns, aggregations, complexity mining |
| Eyeballing for duplication | `find_similar { mode: "clone" }` / `mode: "disagree"` | `disagree` surfaces where signals conflict — frequently where a bug hides |
| Grep for a literal/config/magic string | `search_code { pattern, mode: "compact" }` | Grep, deduplicated into containing functions, ranked by structural importance |

**Pagination is mandatory, not optional.** `search_graph` carries exact `total` and `has_more` — page with `offset += limit` until `has_more` is false. `search_code` has **no offset**: compare `total_grep_matches`/`total_results` to your limit and narrow with `file_pattern`/`path_filter`. `query_graph` has a hard 100k ceiling — put `LIMIT` in the Cypher. A truncated result set that you treat as complete produces a confidently wrong conclusion.

### 2.3 Before you change anything

```
predict_impact { project, seeds: ["<qualified_name>"] }     → ranked consequences + test-selection set
trace_path     { project, function_name, direction: "inbound", depth: 3, scored: true }
get_kernel     { project, mode: "quadrant" }                → is the target critical-and-unverified?
guard_lock     { project, mode: "inventory" }               → is it an identity-locked public API?
```

`predict_impact { mode: "backtest" }` reads the exact chronological gate attestation produced automatically by the current shadow generation; it never establishes or manually approves one. Grounded serving refuses when that attestation is absent, failed, corrupt, or stale. If `predict_impact` refuses with a deficit card, that means **no evidence either way** — it does not mean safe. Stop the grounded operation and report the exact deficit. A separately requested topology-only analysis is a different, explicitly ungrounded operation; it is never substituted for the refused result.

For an existing diff, call `detect_changes` with `project`, the exact `since` ref and `depth`, plus explicit positive `changed_file_max`, `impact_max_symbols`, `reach_max_nodes_per_symbol`, and `result_max_bytes` bounds. It returns a `grounded_risk` block per impacted symbol on shadow projects only when the current Oracle/kernel generation and its held-out gate validate; otherwise it refuses rather than substituting a heuristic risk.

### 2.4 While you write

```
find_similar          { project, symbol: "<nearest existing symbol>", mode: "structural", k: 5 }
guard_advisory_hook   { project, candidate }     → ≤300ms, advisory, never blocks — use per edit
guard_check           { project, target, candidate, exemplars }  → pre-commit
```

Five real neighbors teach you the local idiom better than any style guide. Guard verdicts: `accept` → proceed; `new_region` → legitimately novel, proceed **with justification** and ground it; `quarantine` → rework; `refuse` → violates a locked contract, redesign.

The guard measures **distributional conformance to trusted exemplars, not correctness.** An `accept` means "this looks like the code that works here." It is not proof the code is right — your FSV is.

Guard tools require a calibrated profile. Once per repo/domain:

```json
{ "tool": "guard_calibrate",
  "arguments": { "project": "...", "mode": "generated",
                 "domain": { "language": "rust", "scope_class": "core" },
                 "mutation_sources": ["<real HEAD source>"], "seed": 0 } }
```

`mode: "generated"` builds the bad population from the repo itself — no hand-labeled data needed.

After a substantial refactor: `detect_anomalies { kind: "doc_drift" }` and `{ kind: "name_truth" }` — fix the drift you introduced while it is cheap.

### 2.5 When something breaks

```
abduce_cause { project, failure: "<qualified_name>", recent_changes: [...], observed_at: <epoch> }
```

- Grounded candidates score `s/(s+1)` — **always strictly below 1.0**. Nothing is certain.
- Structural-only candidates are capped at **0.35** and labeled provisional. Do not chase these first.
- **Every hypothesis names its disconfirming test. Run that test.** This converts a ranked guess into a decidable experiment — it is the single most valuable line in the response.
- `forecast { subject, mode: "flaky" }` refuses with `ASTRO_FLAKY_EVIDENCE` on a self-inconsistent pass/fail series. That refusal is telling you the test is the problem, not the code — check it before you spend an hour debugging.

### 2.6 Astrolabe as an FSV instrument

Astrolabe is itself a source of physical proof. Use it as part of your verification, not just your exploration:

```
index_status     { project }                          → vault fingerprint, ledger head, health, idempotency counters
get_provenance   { project, mode: "verify_chain" }    → hash-chain integrity of the persisted ledger
get_provenance   { project, mode: "reproduce", subject_id }  → re-execute a recorded answer; bit-for-bit on an
                                                          unchanged vault, fails closed past a 1e-3 drift bound
get_provenance   { project, mode: "lineage" | "answer_trace" }
```

After a change that should alter the graph, **re-index and read back** — `new_cx_ids` / `reused_cx_ids` / `graph_rows_written` on `index_status` are physical counters, and the vault fingerprint changing (or not changing) is evidence.

### 2.7 Feed reality back — this is how it compounds

Every outcome you ingest makes the oracle and guard refuse less and answer more:

| Source | Tool | Trust |
|---|---|---|
| CI / test report | `anchor_outcome { kind: "test_run", source: "ci:…", format: … }` | `ci:` `trace:` `review:` `git:revert:` → **Trusted**, confidence exactly 1.0 |
| Agent-run verification | `anchor_outcome { source: "agent:…" }` | `git:fix:` `agent:` `survival:` → **Provisional**, 0 < c < 1 |
| Coverage + suite run | `coverage_ingest { coverage_format, test_format, impact_files }` | Line-exact resolved (1.0); one-hop propagation within the impact set (0.6) |
| Production telemetry | `ingest_traces { otlp_protobuf_base64 }` | Promotes matching graph edges to **Trusted** — the strongest signal available |

Formats accepted: `junit_xml`, `cargo_test_json`, `pytest_verbose`, `go_test_json`, `vitest_json`; coverage as `lcov`, `coverage_py_json`, `cobertura_xml`. Pass explicit `observed_at` for reproducibility.

> Applies to whatever repo you are working in. In a repo with no test suite, ground your manual FSV runs as `agent:` provisional anchors — provisional grounding beats none, and it is honestly labeled.

### 2.8 Trust labels and refusals — never override them

Every Astrolabe response carries `trust`, `freshness`, and `provenance`. **Branch on them:**

- `verified` / `trusted` → act on it.
- `provisional` / `inferred` → act cautiously and **disclose the label** to the user. Never present it as fact. Never take a destructive action on it.

Astrolabe fails **closed**: when evidence is insufficient you get `{code, message, remediation}` instead of a guess. **This is the same discipline as the no-fallbacks rule — honor it.**

```
isError: true
├── ASTRO_SHADOW_*                → re-index, retry ONCE
├── missing Oracle gate named      → publish a new source-grounded shadow generation; never approve it manually
├── *_DEFICIT / "Insufficient"    → do NOT retry. Report the deficit and stop this grounded operation;
│                                   never substitute topology or a heuristic result under the same claim
└── anything else                 → surface {code, message, remediation} verbatim
```

**Never loop on a refusal.** Astrolabe refuses because the evidence is not there; calling again does not create evidence. **Never build a workaround around a refusal** — that is exactly the fallback this prompt forbids. If a refusal looks like a genuine defect, **file a GitHub issue** and continue.

### 2.9 Token and time discipline

Search wide and cheap, then read narrow and deep. `search_code mode: "compact"` to triage → `get_code_snippet { atom_id }` on the few that matter. Never dump `mode: "full"` results into context "to have a look." `get_architecture aspects: ["overview"]` rather than `["all"]` (which includes the whole file tree). Start `trace_path` at `depth: 2–3` with `scored: true` so useful hops rank first. Put `LIMIT` in every broad Cypher query.

### 2.10 Wire it into the loop permanently

Register the augmentation hook so every reflexive `Grep`/`Glob` gets free graph context (≤300 ms, silent on timeout):

```jsonc
// .claude/settings.json
{ "hooks": { "PreToolUse": [{ "matcher": "Grep|Glob",
    "hooks": [{ "type": "command", "command": "codebase-memory-mcp hook-augment" }] }] } }
```

Every tool is also available as `codebase-memory-mcp cli <tool> --args-file <json>` (or JSON on stdin); `--json` makes the exit code meaningful, `--help` prints the schema without touching any store.

---

## 3. Working rhythm

1. **Claim** the GitHub issue: what you will do, plan in ≤5 bullets, swap the status label.
2. **Re-read** the issue body *and every comment* — prior sessions recorded what is already done. Verify checked items rather than redoing them.
3. **Bootstrap Astrolabe** (§2.1) and orient before reading code.
4. **Analyze impact** before editing (§2.3).
5. **Work only in scope.** Discovered adjacent work becomes a **new issue**, linked — never expanded in place.
6. **Research best practices** on the web (Exa + your own tools) before committing to a design for anything non-trivial.
7. **Build, lint, compile.** Fix every warning you introduce.
8. **Full State Verification** (§1): source of truth named, executed, independently read back, 3+ edge cases with before/after state, evidence log.
9. **Ground the outcome** in Astrolabe (§2.7).
10. **Record evidence on the issue** — command, context, physical readback — then close it.
11. **Clean up**: no `target/`, no stray artifacts, no branches, no worktrees. Verify absence.
12. **Commit and push to `main`** immediately after verified closure, referencing the issue (`Refs #N` / `Closes #N`).

If you must stop early, comment exactly: what is done (verified vs unverified), what is not, the next concrete step, and any uncommitted local state.

---

## 4. The standing test

Before you say anything works, ask:

> *What is the physical evidence, and did I go look at it myself?*

If the answer is a return value, a log line, a green check, or an assumption — **you have not verified it.** Only reality proves reality. Go read the bytes.
