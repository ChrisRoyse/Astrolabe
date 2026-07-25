# Open issue inventory

> Snapshot: 2026-07-25T18:03:44Z. GitHub issues are authoritative; this file is a dated reading aid. Follow each issue link for newer comments, state, dependencies, and evidence.

This snapshot contains **696 issues: 515 closed and 181 open**. An open issue may be an umbrella, a partially delivered capability, a correctness finding, a decision, or this status-document task; it does not necessarily mean “no implementation exists.” Conversely, a closed issue proves only its recorded scope, not overall release readiness.

Useful live views: [all open issues](https://github.com/ChrisRoyse/Astrolabe/issues?q=is%3Aissue%20is%3Aopen), [ready](https://github.com/ChrisRoyse/Astrolabe/issues?q=is%3Aissue%20is%3Aopen%20label%3Astatus%3Aready), [in progress](https://github.com/ChrisRoyse/Astrolabe/issues?q=is%3Aissue%20is%3Aopen%20label%3Astatus%3Ain-progress), [blocked](https://github.com/ChrisRoyse/Astrolabe/issues?q=is%3Aissue%20is%3Aopen%20label%3Astatus%3Ablocked), and [critical](https://github.com/ChrisRoyse/Astrolabe/issues?q=is%3Aissue%20is%3Aopen%20label%3Asev%3Acritical).

## Ledger summary

| Milestone | Closed | Open | Total |
|---|---:|---:|---:|
| P0 — Foundations & proof of link | 87 | 3 | 90 |
| P1 — Constellations (shadow ingest) | 19 | 0 | 19 |
| P2 — The graph in the vault | 15 | 0 | 15 |
| P3 — Weave & reactivity | 75 | 32 | 107 |
| P4 — Grounding (anchors) | 7 | 2 | 9 |
| P5 — Assay (measurement) | 6 | 1 | 7 |
| P6 — Kernel & context packs | 19 | 4 | 23 |
| P7 — Guard & oracle | 13 | 1 | 14 |
| P8 — Self-optimization & growth | 14 | 10 | 24 |
| P9 — Native steady state & hardening | 22 | 4 | 26 |
| KF — Kernel farming (fleet layer) | 13 | 3 | 16 |
| (none) | 225 | 121 | 346 |

| Workflow label | Open issues |
|---|---:|
| `status:in-progress` | 87 |
| `status:ready` | 37 |
| `status:blocked` | 34 |
| `status:needs-spec` | 1 |
| no `status:*` label | 23 |
| multiple `status:*` labels | 1 |

| Severity label | Open issues |
|---|---:|
| `sev:critical` | 13 |
| `sev:high` | 100 |
| `sev:medium` | 16 |
| `sev:low` | 6 |
| no `sev:*` label | 46 |

Status and severity counts preserve the ledger as sampled. In particular, [#479](https://github.com/ChrisRoyse/Astrolabe/issues/479) carries both `status:in-progress` and `status:blocked`, and several epics/protocol records intentionally carry no workflow label.

## Critical issues

- [#486](https://github.com/ChrisRoyse/Astrolabe/issues/486) — [panel][gpu] Restore a local gate-proven multi-domain constellation instead of a single semantic lens (P3 — Weave & reactivity)
- [#521](https://github.com/ChrisRoyse/Astrolabe/issues/521) — [gpu][contracts] Reject missing learned-slot placement instead of serde-defaulting to CPU (P3 — Weave & reactivity)
- [#550](https://github.com/ChrisRoyse/Astrolabe/issues/550) — [calyx][compression] Make every codec truthful, readable, and performance-real (P3 — Weave & reactivity)
- [#557](https://github.com/ChrisRoyse/Astrolabe/issues/557) — [calyx][compression][critical] Derive reports and autotune admission from physical truth (P8 — Self-optimization & growth)
- [#564](https://github.com/ChrisRoyse/Astrolabe/issues/564) — [calyx][compression][critical] Route all production reads and search through compressed context (P8 — Self-optimization & growth)
- [#573](https://github.com/ChrisRoyse/Astrolabe/issues/573) — [calyx][onnx-int8][critical] Attest quantized graph semantics before commissioning (P3 — Weave & reactivity)
- [#630](https://github.com/ChrisRoyse/Astrolabe/issues/630) — [launcher][archive][critical] Pair archiver can end without discoverable source or archive evidence ((none))
- [#676](https://github.com/ChrisRoyse/Astrolabe/issues/676) — [cbm][store][durability] Direct SQLite page writer ignores write, flush, and close failures ((none))
- [#679](https://github.com/ChrisRoyse/Astrolabe/issues/679) — [cbm][store][memory] Direct SQLite writer emits known-broken oversized cells on OOM ((none))
- [#682](https://github.com/ChrisRoyse/Astrolabe/issues/682) — [cbm][store][concurrency] Parallel direct-writer sorts race through global corpus pointers ((none))
- [#688](https://github.com/ChrisRoyse/Astrolabe/issues/688) — [cbm][ingest][rust] macro_rules resolver uses semantic fallbacks, truncation, and shared matcher state ((none))
- [#690](https://github.com/ChrisRoyse/Astrolabe/issues/690) — [cbm][ingest][rust] known macro argument resolver silently skips valid non-tuple grammars ((none))
- [#695](https://github.com/ChrisRoyse/Astrolabe/issues/695) — [cbm][ingest][identity] File qualified names collapse same-stem polyglot paths ((none))

## Every open issue

### P0 — Foundations & proof of link (3)

| Issue | Workflow | Severity | Areas | Title |
|---:|---|---|---|---|
| [#719](https://github.com/ChrisRoyse/Astrolabe/issues/719) | in-progress | medium | provenance | [codebase-memory][integrity] Astrolabe project binds obsolete launcher-temporary schema-0 store |
| [#721](https://github.com/ChrisRoyse/Astrolabe/issues/721) | ready | low | — | [tracker][milestones] Reconcile milestone descriptions with manual-FSV and no-CI doctrine |
| [#734](https://github.com/ChrisRoyse/Astrolabe/issues/734) | ready | — | — | [docs] Replace root README references to deleted gates and test workflow |

### P3 — Weave & reactivity (32)

| Issue | Workflow | Severity | Areas | Title |
|---:|---|---|---|---|
| [#23](https://github.com/ChrisRoyse/Astrolabe/issues/23) | in-progress | — | ingest, performance | P3.4: Incremental delta path end-to-end — change to vault convergence <5s at M scale |
| [#354](https://github.com/ChrisRoyse/Astrolabe/issues/354) | needs-spec | — | grounding | [anchors] Owner decision: should erasing a resolving source un-justify its promotions? (promotion-tombstone semantics) |
| [#384](https://github.com/ChrisRoyse/Astrolabe/issues/384) | blocked | medium | — | [server][provenance] Persist the reproduce fixture at kernel_answer serve time (activates live server-side reproduce) |
| [#482](https://github.com/ChrisRoyse/Astrolabe/issues/482) | in-progress | high | lens-panel, performance | [gpu][resident] Keep embedders warm through work and evict VRAM after 60 seconds idle |
| [#483](https://github.com/ChrisRoyse/Astrolabe/issues/483) | in-progress | high | lens-panel, performance | [gpu][onnx] Enforce real no-CPU-fallback placement for FastEmbed and Ward |
| [#484](https://github.com/ChrisRoyse/Astrolabe/issues/484) | in-progress | high | performance | [gpu][windows] Pin and attest the CUDA 13 ONNX Runtime and cuDNN dependency closure |
| [#485](https://github.com/ChrisRoyse/Astrolabe/issues/485) | unlabeled | high | lens-panel, performance | [gpu][artifacts] Commission all-CUDA half-precision embedding graph variants with frozen dtype contracts |
| [#486](https://github.com/ChrisRoyse/Astrolabe/issues/486) | blocked | critical | lens-panel, grounding | [panel][gpu] Restore a local gate-proven multi-domain constellation instead of a single semantic lens |
| [#490](https://github.com/ChrisRoyse/Astrolabe/issues/490) | blocked | high | lens-panel, performance | [gpu][adapters] Fix false CPU placement and cold-after-prime multimodal worker lifecycle |
| [#491](https://github.com/ChrisRoyse/Astrolabe/issues/491) | blocked | high | lens-panel, performance | [gpu][runtime] Share identical model loads and batch each neural lens without serial singleton forwards |
| [#508](https://github.com/ChrisRoyse/Astrolabe/issues/508) | blocked | high | lens-panel, mcp-surface, performance | [gpu][routing] Route MCP and web neural measurement through the resident lifecycle |
| [#521](https://github.com/ChrisRoyse/Astrolabe/issues/521) | blocked | critical | data-model, lens-panel, ingest | [gpu][contracts] Reject missing learned-slot placement instead of serde-defaulting to CPU |
| [#522](https://github.com/ChrisRoyse/Astrolabe/issues/522) | in-progress | high | graph-weave, assay, kernel-context | [weave][kernel][correctness] Complete active-panel associations and include similarity edges in the kernel graph |
| [#525](https://github.com/ChrisRoyse/Astrolabe/issues/525) | ready | medium | build-ffi | [build] Restore clean pinned native formatter baseline |
| [#533](https://github.com/ChrisRoyse/Astrolabe/issues/533) | ready | medium | performance | [gpu][onnx] Make provider-placement trace evidence durable and lifecycle-clean |
| [#538](https://github.com/ChrisRoyse/Astrolabe/issues/538) | ready | high | performance | [gpu][nvml] Route Forge power probes through the attested runtime boundary |
| [#545](https://github.com/ChrisRoyse/Astrolabe/issues/545) | blocked | high | lens-panel, performance | [gpu][adapters] Remove CudaPreferred CPU fallback and prove synchronized resident completion |
| [#549](https://github.com/ChrisRoyse/Astrolabe/issues/549) | ready | high | lens-panel | [gpu][onnx] Bind custom and ColBERT sessions to immutable in-memory artifact bytes |
| [#550](https://github.com/ChrisRoyse/Astrolabe/issues/550) | unlabeled | critical | search, performance | [calyx][compression] Make every codec truthful, readable, and performance-real |
| [#573](https://github.com/ChrisRoyse/Astrolabe/issues/573) | blocked | critical | lens-panel, security | [calyx][onnx-int8][critical] Attest quantized graph semantics before commissioning |
| [#575](https://github.com/ChrisRoyse/Astrolabe/issues/575) | in-progress | high | search, performance | [calyx][multivector][high] Add truthful packed ColBERT storage and direct MaxSim scoring |
| [#576](https://github.com/ChrisRoyse/Astrolabe/issues/576) | in-progress | high | ingest, provenance | [ingest][windows] Atomically replace and read back repeated session status updates |
| [#581](https://github.com/ChrisRoyse/Astrolabe/issues/581) | ready | low | performance | [build][calyx] Restore clean warnings-denied Forge Clippy baseline |
| [#585](https://github.com/ChrisRoyse/Astrolabe/issues/585) | ready | medium | data-model | [calyx] Modularize pre-existing Rust files above the 500-line source limit |
| [#602](https://github.com/ChrisRoyse/Astrolabe/issues/602) | in-progress | high | build-ffi | [calyx][onnx][high] Isolate CUDA stream evidence from CPU ml-runtime builds |
| [#604](https://github.com/ChrisRoyse/Astrolabe/issues/604) | ready | low | build-ffi | [calyx][runtime][low] Feature-gate CUDA-only runtime authorities in CPU builds |
| [#605](https://github.com/ChrisRoyse/Astrolabe/issues/605) | in-progress | high | lens-panel | [calyx][onnx][high] Attest CPU shape metadata separately from CUDA compute fallback |
| [#606](https://github.com/ChrisRoyse/Astrolabe/issues/606) | blocked | high | guard | [calyx][ward][high] Share the proven ONNX placement contract with Registry |
| [#607](https://github.com/ChrisRoyse/Astrolabe/issues/607) | ready | high | build-ffi | [tooling][fsv][high] Bind staged artifact execution to the exact launcher PID |
| [#608](https://github.com/ChrisRoyse/Astrolabe/issues/608) | ready | high | lens-panel | [calyx][persistence][high] Persist and physically verify ONNX execution receipt CAS references |
| [#609](https://github.com/ChrisRoyse/Astrolabe/issues/609) | ready | high | lens-panel | [calyx][onnx][high] Bind generic ORT sessions to the exact hashed model bytes |
| [#610](https://github.com/ChrisRoyse/Astrolabe/issues/610) | ready | high | lens-panel | [calyx][onnx] Persist exact generic ONNX output contracts for multi-output models |

### P4 — Grounding (anchors) (2)

| Issue | Workflow | Severity | Areas | Title |
|---:|---|---|---|---|
| [#29](https://github.com/ChrisRoyse/Astrolabe/issues/29) | in-progress | — | grounding, provenance | P4.6: Trust lifecycle enforcement — TrustTag discipline, rollup_trust, erasure tombstones for anchors |
| [#30](https://github.com/ChrisRoyse/Astrolabe/issues/30) | blocked | — | grounding, oracle | P4.7: Flakiness self-consistency ceilings, survival anchors, cold-start guard |

### P5 — Assay (measurement) (1)

| Issue | Workflow | Severity | Areas | Title |
|---:|---|---|---|---|
| [#520](https://github.com/ChrisRoyse/Astrolabe/issues/520) | blocked | high | graph-weave, assay, search, performance | [gpu][assay][association] Execute large association and similarity kernels on the RTX 5090 |

### P6 — Kernel & context packs (4)

| Issue | Workflow | Severity | Areas | Title |
|---:|---|---|---|---|
| [#41](https://github.com/ChrisRoyse/Astrolabe/issues/41) | blocked | — | kernel-context, mcp-surface | P6.5: get_context_pack — token-budgeted pack composer with manifests, honest degradation, bit-exact reproduce |
| [#42](https://github.com/ChrisRoyse/Astrolabe/issues/42) | in-progress | — | search | P6.6: Search unification — per-slot indexes, RRF fusion, deterministic intent classifier, fail-closed planner |
| [#44](https://github.com/ChrisRoyse/Astrolabe/issues/44) | in-progress | — | search, migration | P6.8: Primary flip for search-class tools — per-tool flags, tripwired A/B, rollback |
| [#705](https://github.com/ChrisRoyse/Astrolabe/issues/705) | ready | high | kernel-context, migration | [kernel][lowering][atomicity] get_kernel build leaves the published lowered artifact stale |

### P7 — Guard & oracle (1)

| Issue | Workflow | Severity | Areas | Title |
|---:|---|---|---|---|
| [#312](https://github.com/ChrisRoyse/Astrolabe/issues/312) | blocked | — | guard | P7: layout_conformance guard rung + dependency-direction rule + calibration corpus (#180c) |

### P8 — Self-optimization & growth (10)

| Issue | Workflow | Severity | Areas | Title |
|---:|---|---|---|---|
| [#53](https://github.com/ChrisRoyse/Astrolabe/issues/53) | blocked | — | self-opt | P8.1: Anneal loop — shadow-tested reversible tuning with tripwires, bandit selection, Goodhart defense |
| [#54](https://github.com/ChrisRoyse/Astrolabe/issues/54) | blocked | — | search, self-opt | P8.2: Knob wiring — fusion weights, pack scoring, similarity admission, kernel edge weights, threshold recalibration |
| [#55](https://github.com/ChrisRoyse/Astrolabe/issues/55) | blocked | — | lens-panel, self-opt | P8.3: propose_lens — deficit-driven lens synthesis with differentiation gate and hot-add backfill |
| [#56](https://github.com/ChrisRoyse/Astrolabe/issues/56) | blocked | — | oracle, self-opt | P8.4: Mistake closure — surprise-prioritized replay buffer, online heads, wrong-only-once regression assertion |
| [#57](https://github.com/ChrisRoyse/Astrolabe/issues/57) | blocked | — | oracle, self-opt, mcp-surface | P8.5: Measured quantization gates + readiness predicate (get_readiness) + impute_fields |
| [#58](https://github.com/ChrisRoyse/Astrolabe/issues/58) | blocked | — | self-opt, mcp-surface | P8.6: optimizer_status — anneal ops surface with janitor budgets |
| [#182](https://github.com/ChrisRoyse/Astrolabe/issues/182) | blocked | — | self-opt, performance | P8.11: Verification-loop latency is the prime objective — near-instant FSV, anneal continuously optimizes it |
| [#557](https://github.com/ChrisRoyse/Astrolabe/issues/557) | in-progress | critical | self-opt, performance | [calyx][compression][critical] Derive reports and autotune admission from physical truth |
| [#564](https://github.com/ChrisRoyse/Astrolabe/issues/564) | in-progress | critical | graph-weave, search | [calyx][compression][critical] Route all production reads and search through compressed context |
| [#582](https://github.com/ChrisRoyse/Astrolabe/issues/582) | ready | medium | search, performance | [calyx][diskann][windows] Eliminate transient active-pointer AccessDenied during publication |

### P9 — Native steady state & hardening (4)

| Issue | Workflow | Severity | Areas | Title |
|---:|---|---|---|---|
| [#61](https://github.com/ChrisRoyse/Astrolabe/issues/61) | in-progress | — | provenance, security | P9.3: Security & privacy pass — erasure tombstones end-to-end, redaction audit, secret filters, egress audit |
| [#63](https://github.com/ChrisRoyse/Astrolabe/issues/63) | in-progress | — | mcp-surface, migration | P9.5: Ecosystem finalization — installer network, hooks, skill content, CLI parity, packaging + license gate |
| [#177](https://github.com/ChrisRoyse/Astrolabe/issues/177) | blocked | — | guard, oracle, mcp-surface | P9.7: Zero-touch verification loop — verification moves inside the system; the human verifies nothing |
| [#595](https://github.com/ChrisRoyse/Astrolabe/issues/595) | ready | low | — | [docs] calyx/docs still references removed calyx-testkit crate + deleted test suite (wave-2 cleanup residue) |

### KF — Kernel farming (fleet layer) (3)

| Issue | Workflow | Severity | Areas | Title |
|---:|---|---|---|---|
| [#453](https://github.com/ChrisRoyse/Astrolabe/issues/453) | blocked | medium | performance | [fleet] Throughput umbrella — measured repos/hour profile, fleet wall-clock budget, absorbs perf spine |
| [#460](https://github.com/ChrisRoyse/Astrolabe/issues/460) | in-progress | high | — | [fleet] Scale waves — gated 10 → 100 → 1,159 rollout with go/no-go evidence |
| [#461](https://github.com/ChrisRoyse/Astrolabe/issues/461) | unlabeled | high | — | EPIC: Kernel farming — grow Astrolabe's own code kernels from all >2k-star GitHub repos (Rust first) |

### (none) (121)

| Issue | Workflow | Severity | Areas | Title |
|---:|---|---|---|---|
| [#65](https://github.com/ChrisRoyse/Astrolabe/issues/65) | unlabeled | — | — | EPIC: ASTROLABE build tracker — dependency spine and manual-FSV completion criteria |
| [#68](https://github.com/ChrisRoyse/Astrolabe/issues/68) | blocked | — | graph-weave, assay, mcp-surface | P7.9: detect_anomalies completion — doc_drift / name_truth / drift / ood_commit kinds + aggregation |
| [#69](https://github.com/ChrisRoyse/Astrolabe/issues/69) | in-progress | — | kernel-context | P7.10: Label propagation + universal scope summarization (capabilities 5.9 / 5.10) |
| [#70](https://github.com/ChrisRoyse/Astrolabe/issues/70) | blocked | — | graph-weave, kernel-context | P8.7: Cross-domain & cross-repo bridges — shared-kernel interface discovery (capabilities 5.11 / 2.11-P8) |
| [#71](https://github.com/ChrisRoyse/Astrolabe/issues/71) | blocked | — | kernel-context, search | P8.8: Skills discovery — HDBSCAN capability tree + search-within-skill (capability 8.8) |
| [#72](https://github.com/ChrisRoyse/Astrolabe/issues/72) | blocked | — | search, performance | P8.9: Monorepo scale posture — kernel-first funnel + DiskANN/SPANN opt-in + RAM fail-closed (capability 8.9, 12 §5) |
| [#73](https://github.com/ChrisRoyse/Astrolabe/issues/73) | blocked | — | guard, security | P8.10: Prompt-injection & supply-chain screening (capability 6.7) |
| [#139](https://github.com/ChrisRoyse/Astrolabe/issues/139) | unlabeled | — | — | [protocol] Agent operating protocol — issues are the single source of truth |
| [#140](https://github.com/ChrisRoyse/Astrolabe/issues/140) | unlabeled | — | — | [audit] 2026-07-09 master audit summary — coverage, priorities, all findings |
| [#286](https://github.com/ChrisRoyse/Astrolabe/issues/286) | unlabeled | — | — | EPIC: Absorb both parent codebases as owned first-class source — dissolve the vendoring doctrine (owner directive 2026-07-12) |
| [#337](https://github.com/ChrisRoyse/Astrolabe/issues/337) | blocked | — | grounding, mcp-surface | [server] Wire agent_task reward intake + promote-on-resolution into MCP (gated on #41 pack manifests) |
| [#404](https://github.com/ChrisRoyse/Astrolabe/issues/404) | blocked | low | guard | [guard][testing] Demonstrate an end-to-end PASSING generated guard_calibrate on a structurally-rich multi-project corpus (thin single-project corpus can't satisfy R16 cap + sparse-slot floor together) |
| [#407](https://github.com/ChrisRoyse/Astrolabe/issues/407) | blocked | medium | grounding, kernel-context | [kernel][grounding] Demonstrate a served multi-hop kernel_answer end-to-end (needs a Trusted-anchored grounded entry — #29/#40 anchor lifecycle) |
| [#473](https://github.com/ChrisRoyse/Astrolabe/issues/473) | ready | medium | build-ffi, ingest | [cbm][ingest] Retain raw symbol source bytes — dedup census runs on a property-fingerprint proxy (File atoms content-free, cross-repo equality undercounted at 58%) |
| [#479](https://github.com/ChrisRoyse/Astrolabe/issues/479) | in-progress, blocked | medium | kernel-context | [kernel][determinism] Per-repo kernel members_hash is path-dependent: incremental refresh vs fresh rebuild diverge at identical HEAD |
| [#498](https://github.com/ChrisRoyse/Astrolabe/issues/498) | blocked | high | lens-panel | [lens-catalog] Migrate pre-device frozen contracts without silent identity drift |
| [#499](https://github.com/ChrisRoyse/Astrolabe/issues/499) | unlabeled | high | lens-panel, performance | [gpu][embeddings] Use measured resident and peak VRAM for panel budgets |
| [#500](https://github.com/ChrisRoyse/Astrolabe/issues/500) | blocked | — | — | [ingest][embeddings] Pass real CBM chunk text through the learned embedder constellation — source_snippet_bytes is a fingerprint proxy, not code |
| [#501](https://github.com/ChrisRoyse/Astrolabe/issues/501) | unlabeled | high | data-model, ingest | [cbm][ingest] Persist byte-exact symbol source spans through supervised indexing into Calyx |
| [#504](https://github.com/ChrisRoyse/Astrolabe/issues/504) | ready | — | — | EPIC: Calyx-native information home — retire SQLite as interchange, Rust-native table engine baked into Calyx |
| [#510](https://github.com/ChrisRoyse/Astrolabe/issues/510) | ready | — | — | [domain][identity] Owner decision: body-faithful canonical identity — shared root of #497/#479 (migration-scale) |
| [#515](https://github.com/ChrisRoyse/Astrolabe/issues/515) | in-progress | — | — | [server][fail-closed] index_repository exits rc=127 with empty stdout deep in post-CBM processing (rtk) |
| [#524](https://github.com/ChrisRoyse/Astrolabe/issues/524) | ready | high | lens-panel, provenance | [registry][integrity] Enforce immutable artifact snapshot across hash, profile, and load |
| [#526](https://github.com/ChrisRoyse/Astrolabe/issues/526) | ready | — | — | [gpu][qwen] Full-state verify real multi-shard safetensors loading on RTX 5090 |
| [#536](https://github.com/ChrisRoyse/Astrolabe/issues/536) | in-progress | — | — | [launcher][toolchain] CUDA-13 attestation fail-closes all builds under pwsh-polluted PSModulePath (PS5.1 Security module unloadable) |
| [#537](https://github.com/ChrisRoyse/Astrolabe/issues/537) | in-progress | high | performance | [gpu][candle] Remove Candle eager CUDA imports and share the pinned process runtime |
| [#541](https://github.com/ChrisRoyse/Astrolabe/issues/541) | in-progress | — | — | [fleet][robustness] Killed git/pipeline children are misclassified as repo defects - false quarantines with empty diagnostics |
| [#542](https://github.com/ChrisRoyse/Astrolabe/issues/542) | in-progress | — | — | [fleet][lifecycle] No reconcile/adopt path for a verified-complete store whose catalog row is wrong - full recompute forced |
| [#543](https://github.com/ChrisRoyse/Astrolabe/issues/543) | in-progress | — | — | [launcher][toolchain] Unconditional CUDA-runtime attestation dies under Windows PowerShell 5.1 when the host Security module is wedged - fault misnamed as bundle fault |
| [#544](https://github.com/ChrisRoyse/Astrolabe/issues/544) | in-progress | — | — | [fleet][grow] grow --once --force-repo on a discovered repo silently skips it (skipped_state) instead of cloning - verdict reads ok |
| [#546](https://github.com/ChrisRoyse/Astrolabe/issues/546) | unlabeled | high | lens-panel, performance | [gpu][resident] Make saved-template slot/modality scope truthful end to end |
| [#548](https://github.com/ChrisRoyse/Astrolabe/issues/548) | ready | — | — | [fleet][performance] zed-industries/zed exceeds the 7200s pipeline timeout in import_raw_total (peak RSS 17.6 GiB) — giant-monorepo class blocked on perf spine |
| [#569](https://github.com/ChrisRoyse/Astrolabe/issues/569) | in-progress | high | lens-panel, performance | [gpu][onnx] Make generic ONNX and ColBERT placement attestation mandatory and physical |
| [#579](https://github.com/ChrisRoyse/Astrolabe/issues/579) | ready | — | build-ffi | [cbm][robustness] Indexer AVs (0xC0000005) under memory pressure instead of failing closed — unguarded alloc path upstream of #487/#505 guards |
| [#590](https://github.com/ChrisRoyse/Astrolabe/issues/590) | in-progress | — | — | [calyx][gpu][performance] Eliminate per-inference overhead in custom ONNX CUDA path |
| [#592](https://github.com/ChrisRoyse/Astrolabe/issues/592) | unlabeled | high | provenance | [calyx-aster][high] Erase stale-intent recovery runs handler abort under the durable commit lock (#561 contract violation) |
| [#593](https://github.com/ChrisRoyse/Astrolabe/issues/593) | unlabeled | high | provenance | [calyx-aster][high] Erase resume misclassifies post-commit crash on durable ledgerless vaults -> core/derived split-brain (#561) |
| [#599](https://github.com/ChrisRoyse/Astrolabe/issues/599) | ready | medium | build-ffi, provenance | [build][reproducibility] Identical clean native CUDA tree produces different artifact hashes |
| [#601](https://github.com/ChrisRoyse/Astrolabe/issues/601) | ready | medium | data-model | [calyx-cli] Generic CF readback omits the compression column family |
| [#621](https://github.com/ChrisRoyse/Astrolabe/issues/621) | in-progress | high | build-ffi, provenance | [launcher][build] Remove production dependency on retired no-escape gate registry |
| [#624](https://github.com/ChrisRoyse/Astrolabe/issues/624) | in-progress | high | build-ffi, provenance | [launcher][attribution][correctness] Align and terminate FILE_RENAME_INFO refresh buffers |
| [#626](https://github.com/ChrisRoyse/Astrolabe/issues/626) | unlabeled | high | build-ffi, provenance | [launcher][archive][correctness] Exact TEMP inventory degrades to opaque on zero default-stream observation |
| [#628](https://github.com/ChrisRoyse/Astrolabe/issues/628) | in-progress | high | build-ffi, provenance | [native-fsv][launcher] Runner cannot read the live exact-owner lease it is required to bind |
| [#630](https://github.com/ChrisRoyse/Astrolabe/issues/630) | in-progress | critical | build-ffi, provenance | [launcher][archive][critical] Pair archiver can end without discoverable source or archive evidence |
| [#631](https://github.com/ChrisRoyse/Astrolabe/issues/631) | in-progress | high | ingest | [cbm][store] Immutable query fallback can ignore committed WAL state |
| [#632](https://github.com/ChrisRoyse/Astrolabe/issues/632) | in-progress | high | ingest | [cbm][mcp] Project discovery scans open unverified stores and silently skip failures |
| [#635](https://github.com/ChrisRoyse/Astrolabe/issues/635) | in-progress | high | ingest | [cbm][incremental][correctness] file_hashes persists empty digests and can miss same-size/same-mtime content changes |
| [#636](https://github.com/ChrisRoyse/Astrolabe/issues/636) | in-progress | high | ingest | [cbm][mcp] Query handlers overwrite verified store failures with project-not-found |
| [#637](https://github.com/ChrisRoyse/Astrolabe/issues/637) | in-progress | high | ingest | [cbm][search] search_code silently expands to recursive filesystem grep when graph scope fails |
| [#638](https://github.com/ChrisRoyse/Astrolabe/issues/638) | in-progress | high | ingest | [cbm][ingest][correctness] Multi-pass extraction rereads paths and can persist a mixed-revision graph |
| [#639](https://github.com/ChrisRoyse/Astrolabe/issues/639) | in-progress | high | ingest | [cbm][ingest] index_repository reports success/degraded when persisted store verification fails |
| [#640](https://github.com/ChrisRoyse/Astrolabe/issues/640) | in-progress | high | ingest | [cbm][search] Graph enrichment failures degrade to plausible raw grep results |
| [#641](https://github.com/ChrisRoyse/Astrolabe/issues/641) | in-progress | high | ingest | [cbm][search] Invalid path filters and pattern-file failures are silently reinterpreted |
| [#642](https://github.com/ChrisRoyse/Astrolabe/issues/642) | unlabeled | high | — | [launcher][recovery] Pair archive succeeds with opaque TEMP inventory after default-stream count mismatch |
| [#644](https://github.com/ChrisRoyse/Astrolabe/issues/644) | in-progress | high | ingest | [cbm][search] search_code silently truncates long lines and match sets |
| [#645](https://github.com/ChrisRoyse/Astrolabe/issues/645) | in-progress | high | ingest | [cbm][search] search_code silently destroys non-ASCII source bytes |
| [#646](https://github.com/ChrisRoyse/Astrolabe/issues/646) | in-progress | high | ingest | [cbm][search] invalid mode and numeric arguments are silently reinterpreted |
| [#647](https://github.com/ChrisRoyse/Astrolabe/issues/647) | in-progress | high | ingest | [cbm][ingest] discovery allocation failures silently drop or corrupt file records |
| [#648](https://github.com/ChrisRoyse/Astrolabe/issues/648) | in-progress | high | ingest | [cbm][ingest] discovery path, traversal, and I/O limits silently omit source subtrees |
| [#649](https://github.com/ChrisRoyse/Astrolabe/issues/649) | in-progress | high | ingest | [cbm][ingest] auxiliary config walkers cap and silently omit source-interpretation inputs |
| [#650](https://github.com/ChrisRoyse/Astrolabe/issues/650) | in-progress | high | ingest | [cbm][ingest] extension config errors silently change the discovered corpus |
| [#651](https://github.com/ChrisRoyse/Astrolabe/issues/651) | unlabeled | — | — | [launcher][target][blocker] Canonical target can appear with no exact lease owner or legal reclaim path |
| [#652](https://github.com/ChrisRoyse/Astrolabe/issues/652) | in-progress | high | ingest | [cbm][ingest] FQN and import resolution silently truncate deep or long source identities |
| [#653](https://github.com/ChrisRoyse/Astrolabe/issues/653) | in-progress | high | ingest | [cbm][ingest] hash-table insertion failures are indistinguishable from successful first inserts |
| [#654](https://github.com/ChrisRoyse/Astrolabe/issues/654) | unlabeled | high | build-ffi, provenance | [launcher][cleanup] Exact empty-directory disposition fails during access-time suppression |
| [#655](https://github.com/ChrisRoyse/Astrolabe/issues/655) | unlabeled | high | build-ffi, provenance | [launcher][archive] Launcher-owned CUDA junctions force every nontrivial TEMP inventory opaque |
| [#656](https://github.com/ChrisRoyse/Astrolabe/issues/656) | unlabeled | high | build-ffi, provenance | [launcher][target] Preserved-target recovery rejects normal Cargo hard links |
| [#657](https://github.com/ChrisRoyse/Astrolabe/issues/657) | unlabeled | high | — | [launcher][cleanup][correctness] Exact tree deletion rejects parent-directory metadata changed by its own child removals |
| [#658](https://github.com/ChrisRoyse/Astrolabe/issues/658) | in-progress | high | ingest | [cbm][incremental][correctness] Failure cleanup frees deleted-path storage twice and omits registry cleanup |
| [#659](https://github.com/ChrisRoyse/Astrolabe/issues/659) | in-progress | high | ingest | [cbm-sys][build][correctness] Binding refresh command mutates tracked source inside frozen native launcher lease |
| [#660](https://github.com/ChrisRoyse/Astrolabe/issues/660) | in-progress | high | ingest | [cbm][ingest] dynamic-array growth failures silently drop authoritative graph data |
| [#661](https://github.com/ChrisRoyse/Astrolabe/issues/661) | in-progress | high | ingest | [cbm-sys][build] Nested GNU Make ignores Cargo jobserver and exhausts Windows commit/process resources |
| [#662](https://github.com/ChrisRoyse/Astrolabe/issues/662) | in-progress | high | ingest | [cbm][ingest][production] Shipped environment switches intentionally crash or hang extraction |
| [#663](https://github.com/ChrisRoyse/Astrolabe/issues/663) | in-progress | high | ingest | [cbm][ingest][production] Debug environment hook intentionally aborts the real index worker |
| [#664](https://github.com/ChrisRoyse/Astrolabe/issues/664) | in-progress | high | ingest | [cbm][ingest][correctness] Crash recovery quarantines source files and returns a partial graph as success |
| [#665](https://github.com/ChrisRoyse/Astrolabe/issues/665) | in-progress | high | ingest | [cbm][search][concurrency] Pattern and file-list temp names collide across simultaneous searches |
| [#666](https://github.com/ChrisRoyse/Astrolabe/issues/666) | in-progress | high | ingest | [cbm][memory][correctness] safe_realloc frees authoritative state and callers continue through NULL |
| [#667](https://github.com/ChrisRoyse/Astrolabe/issues/667) | in-progress | high | ingest | [cbm][ingest][concurrency] Supervisor PID-scoped handoff files collide across concurrent indexing requests |
| [#668](https://github.com/ChrisRoyse/Astrolabe/issues/668) | in-progress | high | ingest | [cbm][ingest][memory] TSNodeStack silently drops AST subtrees when arena growth fails |
| [#669](https://github.com/ChrisRoyse/Astrolabe/issues/669) | in-progress | high | search | [cbm][search][grounding] Vector search invents random geometry for missing persisted keyword vectors |
| [#670](https://github.com/ChrisRoyse/Astrolabe/issues/670) | in-progress | high | ingest | [cbm][store][durability] WAL checkpoint result is ignored during store lifecycle |
| [#671](https://github.com/ChrisRoyse/Astrolabe/issues/671) | unlabeled | high | graph-weave | [cbm][ui][correctness] Layout edge arrays split ownership and return partial graphs on allocation/query failure |
| [#672](https://github.com/ChrisRoyse/Astrolabe/issues/672) | in-progress | high | ingest | [cbm][store][config] Malformed SQLite mmap configuration silently falls back to a different value |
| [#673](https://github.com/ChrisRoyse/Astrolabe/issues/673) | ready | medium | build-ffi | [build][cbm] Repository-wide clang-format audit fails on committed baseline headers |
| [#674](https://github.com/ChrisRoyse/Astrolabe/issues/674) | in-progress | high | ingest | [cbm][ingest][correctness] Embedded import extraction silently omits missing grammars and blocks after 16 |
| [#675](https://github.com/ChrisRoyse/Astrolabe/issues/675) | in-progress | high | ingest | [cbm][ingest][correctness] LSP depth and work budgets return incomplete call graphs as success |
| [#676](https://github.com/ChrisRoyse/Astrolabe/issues/676) | in-progress | critical | ingest | [cbm][store][durability] Direct SQLite page writer ignores write, flush, and close failures |
| [#677](https://github.com/ChrisRoyse/Astrolabe/issues/677) | in-progress | high | ingest | [cbm][windows][ingest] UTF-8 command-line reconstruction silently falls back to ANSI paths |
| [#678](https://github.com/ChrisRoyse/Astrolabe/issues/678) | in-progress | high | build-ffi, ingest | [cbm][allocator][correctness] Allocator binding marks success before SQLite accepts configuration |
| [#679](https://github.com/ChrisRoyse/Astrolabe/issues/679) | in-progress | critical | ingest | [cbm][store][memory] Direct SQLite writer emits known-broken oversized cells on OOM |
| [#680](https://github.com/ChrisRoyse/Astrolabe/issues/680) | in-progress | high | ingest | [cbm][ingest][correctness] Go/Kotlin/PHP LSP walkers silently truncate at depth bounds |
| [#681](https://github.com/ChrisRoyse/Astrolabe/issues/681) | in-progress | high | ingest | [cbm][store][threads] Direct-writer sort ignores Windows thread-creation failure |
| [#682](https://github.com/ChrisRoyse/Astrolabe/issues/682) | in-progress | critical | ingest | [cbm][store][concurrency] Parallel direct-writer sorts race through global corpus pointers |
| [#683](https://github.com/ChrisRoyse/Astrolabe/issues/683) | in-progress | high | ingest | [cbm][ingest][java] Java LSP silently truncates calls at hard-coded walk depth |
| [#684](https://github.com/ChrisRoyse/Astrolabe/issues/684) | in-progress | high | ingest | [cbm][ingest][typescript] Type analysis exhaustion is silently persisted as complete |
| [#685](https://github.com/ChrisRoyse/Astrolabe/issues/685) | in-progress | high | ingest | [cbm][ingest][correctness] Semantic evaluator depth guards silently publish partial graphs |
| [#686](https://github.com/ChrisRoyse/Astrolabe/issues/686) | in-progress | high | ingest | [cbm][store][validation] Direct SQLite writer trusts invalid FFI counts and arrays |
| [#687](https://github.com/ChrisRoyse/Astrolabe/issues/687) | in-progress | high | ingest | [cbm][ingest][kotlin] Smart-cast resolver is a shipped NULL stub |
| [#688](https://github.com/ChrisRoyse/Astrolabe/issues/688) | in-progress | critical | ingest | [cbm][ingest][rust] macro_rules resolver uses semantic fallbacks, truncation, and shared matcher state |
| [#689](https://github.com/ChrisRoyse/Astrolabe/issues/689) | in-progress | high | ingest | [cbm][ingest][correctness] Fixed semantic arrays silently truncate wide valid source |
| [#690](https://github.com/ChrisRoyse/Astrolabe/issues/690) | in-progress | critical | ingest | [cbm][ingest][rust] known macro argument resolver silently skips valid non-tuple grammars |
| [#692](https://github.com/ChrisRoyse/Astrolabe/issues/692) | unlabeled | high | build-ffi, provenance | [git][launcher][correctness] Mutation-lease classifier can abort worktree registration with opaque OutOfMemoryException |
| [#693](https://github.com/ChrisRoyse/Astrolabe/issues/693) | unlabeled | — | — | [CBM] source_snapshot fails closed on actively-changing trees (NAMESPACE_DRIFT) and mislabels drift as native_error=1006 |
| [#694](https://github.com/ChrisRoyse/Astrolabe/issues/694) | ready | medium | performance | [launcher][toolchain] Obsolete CUDA bundle retirement is unreachable under the mandatory live lease |
| [#695](https://github.com/ChrisRoyse/Astrolabe/issues/695) | in-progress | critical | ingest | [cbm][ingest][identity] File qualified names collapse same-stem polyglot paths |
| [#696](https://github.com/ChrisRoyse/Astrolabe/issues/696) | ready | high | ingest | [cbm][ingest][fqn] File-QN derivation failures can degrade into missing edges |
| [#698](https://github.com/ChrisRoyse/Astrolabe/issues/698) | blocked | high | ingest | [ingest][row-sink] Project/summary/token metadata is omitted or synthesized |
| [#699](https://github.com/ChrisRoyse/Astrolabe/issues/699) | ready | high | ingest | [cbm][publication] Artifact export failure occurs after live SQLite replacement |
| [#700](https://github.com/ChrisRoyse/Astrolabe/issues/700) | ready | medium | build-ffi | [launcher][diagnostics] Dead complete-pair refusal omits sanctioned archive remediation |
| [#702](https://github.com/ChrisRoyse/Astrolabe/issues/702) | ready | high | ingest | [cbm][ingest][lsp] Cross-file LSP preparation silently degrades after authoritative failures |
| [#703](https://github.com/ChrisRoyse/Astrolabe/issues/703) | ready | high | ingest | [cbm][ingest][limits] Invalid traversal-limit configuration silently reverts to default |
| [#720](https://github.com/ChrisRoyse/Astrolabe/issues/720) | ready | low | build-ffi | [launcher] detach-run fails with an opaque ACL diagnostic when PSModulePath is inherited from PowerShell 7 |
| [#723](https://github.com/ChrisRoyse/Astrolabe/issues/723) | unlabeled | high | ingest | [cbm][ingest][c] Compilation database include roots are parsed but never bound to import resolution |
| [#724](https://github.com/ChrisRoyse/Astrolabe/issues/724) | ready | high | build-ffi | [cbm][lint] Full Cppcheck production scan has unsuppressed baseline findings |
| [#725](https://github.com/ChrisRoyse/Astrolabe/issues/725) | ready | high | build-ffi | [cbm][build] Patch-glue Makefile advertises a broken duplicate production binary target |
| [#726](https://github.com/ChrisRoyse/Astrolabe/issues/726) | in-progress | high | ingest | [cbm][rust][ingest] Valid macro token trees fail authoritative extraction |
| [#727](https://github.com/ChrisRoyse/Astrolabe/issues/727) | in-progress | high | ingest | [cbm][identity] Semantic edges lose atom identity through non-unique qualified names |
| [#728](https://github.com/ChrisRoyse/Astrolabe/issues/728) | in-progress | high | ingest | [cbm][rust][imports] Valid multiple glob imports collide as one alias |
| [#731](https://github.com/ChrisRoyse/Astrolabe/issues/731) | ready | high | ingest | [cbm][rust][imports] Import alias is unparsed and a conflicting alias is silently dropped |
| [#732](https://github.com/ChrisRoyse/Astrolabe/issues/732) | in-progress | — | — | [docs] Publish issue-derived project status and remaining-roadmap snapshot |
| [#733](https://github.com/ChrisRoyse/Astrolabe/issues/733) | ready | medium | ingest | [cbm][json] Truncated JSON is silently admitted as partial graph facts |
