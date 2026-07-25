# What has been delivered

> This is a synthesis of closed issues and inspected source at the 2026-07-25 snapshot. “Delivered” means the issue’s recorded scope is closed. It does not upgrade a partial subsystem into an end-to-end release claim.

## Foundation and ownership

- Repository/workspace scaffolding, `libcbm.a`, the Rust FFI layer, allocator boundary, and the pass-through MCP host are closed in the P0 tracker ([#1–#6 summarized by #65](https://github.com/ChrisRoyse/Astrolabe/issues/65)).
- Calyx and CBM now live as owned, editable, top-level source trees. EPIC [#286](https://github.com/ChrisRoyse/Astrolabe/issues/286) records the ownership change and completed relocation; the epic remains open for residual doctrine/build-glue cleanup.
- The native Windows launcher has accumulated strong exact-owner, frozen-tree, target-cleanup, detached-run, attribution, and artifact-lifecycle protections. Recent foundation work includes [#618](https://github.com/ChrisRoyse/Astrolabe/issues/618), [#620](https://github.com/ChrisRoyse/Astrolabe/issues/620), [#717](https://github.com/ChrisRoyse/Astrolabe/issues/717), and tracker reconciliation [#718](https://github.com/ChrisRoyse/Astrolabe/issues/718). Open launcher findings remain, so this is not a claim that tooling hardening is finished.
- Verification doctrine is now manual Full State Verification only: native build, real behavior, independent physical readback, and edge cases. Hosted CI, test suites, and the old gate/check infrastructure have been retired.

## Core phase delivery

| Phase | Closed core scope | Important boundary |
|---|---|---|
| P0 | 12 of 13 tracker issues: native link/bridge/server foundation plus modern launcher/tracker work. | [#719](https://github.com/ChrisRoyse/Astrolabe/issues/719) keeps P0 open because the Astrolabe project alias points at an obsolete launcher-temporary store; its latest chain names [#727](https://github.com/ChrisRoyse/Astrolabe/issues/727) as the remaining blocker. |
| P1 | All 8 tracker issues: canonical identity/series registry, panel infrastructure and lenses, SQLite-to-vault importer, ledger and chain verification. | Later identity/source-fidelity findings such as [#473](https://github.com/ChrisRoyse/Astrolabe/issues/473), [#501](https://github.com/ChrisRoyse/Astrolabe/issues/501), and decision [#510](https://github.com/ChrisRoyse/Astrolabe/issues/510) show that a closed foundation can still need migration-scale correction. |
| P2 | All 7 tracker issues: typed edge import, graph projections/CSR, lowering, `off|shadow` migration, parity behavior, cross-process access, and self-verifying mutation work. | [#705](https://github.com/ChrisRoyse/Astrolabe/issues/705) tracks a remaining atomicity defect in kernel-triggered lowering. |
| P3 | Similarity graphs, eager cross-terms/agreement graph, and reactive triggers are closed. | End-to-end incremental convergence [#23](https://github.com/ChrisRoyse/Astrolabe/issues/23) remains open, and P3 has the largest milestoned backlog (32 open). |
| P4 | Outcome intake/parsers, propagation, SZZ/reverts, real trace ingestion, and agent-task reward anchors are closed. | Trust/tombstone completion [#29](https://github.com/ChrisRoyse/Astrolabe/issues/29) and flakiness/survival/cold-start [#30](https://github.com/ChrisRoyse/Astrolabe/issues/30) remain. |
| P5 | All 6 core tracker issues: scheduler, MI/sufficiency, redundancy/synergy/temporal measures, calibration/`measure_bits`, capability gate, and blind-spot sweep. | GPU association execution [#520](https://github.com/ChrisRoyse/Astrolabe/issues/520) is an open P5 milestone extension. |
| P6 | Kernel pipeline, scoped/incremental kernel work, gaps/blast radius, `get_kernel`, `kernel_answer`, navigation/as-of, and provenance are closed issue scopes. | The flagship pack [#41](https://github.com/ChrisRoyse/Astrolabe/issues/41), unified search [#42](https://github.com/ChrisRoyse/Astrolabe/issues/42), and primary flip [#44](https://github.com/ChrisRoyse/Astrolabe/issues/44) remain. |
| P7 | Calibration corpus builders, guard profiles/checks, identity lock/drift/hooks, change-outcome mining, impact prediction, abduction/forecast, and honesty/grounded change detection are closed tracker scopes. | Anomaly completion [#68](https://github.com/ChrisRoyse/Astrolabe/issues/68) and label propagation/summarization [#69](https://github.com/ChrisRoyse/Astrolabe/issues/69) remain open; real-corpus demonstration gaps include [#404](https://github.com/ChrisRoyse/Astrolabe/issues/404) and [#407](https://github.com/ChrisRoyse/Astrolabe/issues/407). |
| P8 | The reviewer-routing phase decision [#74](https://github.com/ChrisRoyse/Astrolabe/issues/74) is closed, and several issues contain landed contract/read surfaces. | 10 of 11 tracker items remain open; the anneal loop and composed self-improvement are not complete. |
| P9 | Streaming row sink, hazard behavior, diagnostics/team artifacts, historical release-evaluation scope, and the UI-phase decision are closed. | Security [#61](https://github.com/ChrisRoyse/Astrolabe/issues/61), ecosystem/packaging [#63](https://github.com/ChrisRoyse/Astrolabe/issues/63), and zero-touch verification [#177](https://github.com/ChrisRoyse/Astrolabe/issues/177) remain. |

## Source-visible product surface

The Rust server currently declares 22 Astrolabe-owned tool definitions in [`tool_defs.rs`](../../crates/astrolabe-server/src/migration/tool_defs.rs) and delegates other requests to the owned CBM runner through [`dispatch.rs`](../../crates/astrolabe-server/src/migration/dispatch.rs). Source-visible native tools include grounding, measurement, guard, oracle, provenance, readiness, optimizer, kernel, and anomaly surfaces.

This is substantial product code, but tool presence is not equivalent to full completion. For example:

- `get_context_pack` is not in the declared set and remains not-started/blocked in [#41](https://github.com/ChrisRoyse/Astrolabe/issues/41).
- `optimizer_status`, `get_readiness`, `impute_fields`, skills, bridges, and anomaly surfaces have partial contracts/read paths while their producer or composed lifecycle issues remain open ([#55](https://github.com/ChrisRoyse/Astrolabe/issues/55), [#57](https://github.com/ChrisRoyse/Astrolabe/issues/57), [#58](https://github.com/ChrisRoyse/Astrolabe/issues/58), [#68](https://github.com/ChrisRoyse/Astrolabe/issues/68), [#70](https://github.com/ChrisRoyse/Astrolabe/issues/70), [#71](https://github.com/ChrisRoyse/Astrolabe/issues/71)).
- `kernel_answer` is wired, but a real multi-hop Trusted-grounded demonstration remains tracked by [#407](https://github.com/ChrisRoyse/Astrolabe/issues/407).

## Kernel farming

The kernel-farming EPIC [#461](https://github.com/ChrisRoyse/Astrolabe/issues/461) has 11 of 13 atomic boxes checked. Delivered scopes include fleet cataloging, GitHub discovery, cloning, resumable orchestration, storage layout, dedup, kernel-of-kernels composition, fleet serving, and continuous growth scheduling. Remaining work is the measured throughput umbrella [#453](https://github.com/ChrisRoyse/Astrolabe/issues/453) and the unfinished 10→100→1,159 rollout [#460](https://github.com/ChrisRoyse/Astrolabe/issues/460); wave 2 and the published/queryable Rust fleet kernel gate are still unchecked.

## Recent correctness hardening

A large 2026-07-23–25 audit wave moved from broad feature construction into CBM ingestion, store, identity, language-semantic, launcher, compression, and GPU correctness. Many findings have already closed; for example [#730](https://github.com/ChrisRoyse/Astrolabe/issues/730) corrected main-thread stack sizing and large-frame behavior. The same wave produced a large remaining backlog, so recent closures should be read as active hardening rather than evidence that the input substrate is finished.
