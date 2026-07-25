# Remaining roadmap

> This is a dependency reading of the open issue ledger, not a new priority authority. Issue state, labels, blockers, and owner decisions on GitHub supersede it.

## How much further is left?

Numerically, 22 of 83 core tracker issues and 181 of 696 total issues were open at the cutoff. Those counts cannot be converted into a trustworthy calendar percentage: issue scopes vary enormously, many large blockers sit late in the dependency spine, and the recent audits added foundation corrections that the blueprint’s original estimate did not include.

The honest qualitative answer is:

- The single-binary architecture, identity/vault/graph foundation, measurement layer, and many guard/oracle/kernel surfaces are largely built.
- The headline context product and automatic reality-verification loop are not complete.
- The largest remaining risk is not sheer feature count; it is whether the underlying atoms, associations, persisted bytes, search quality, GPU/compression claims, and lifecycle tooling are physically truthful under real failure conditions.

## Dependency-ordered path

### 1. Restore a trustworthy P0/P1 truth base

Finish [#719](https://github.com/ChrisRoyse/Astrolabe/issues/719) and its current blocker [#727](https://github.com/ChrisRoyse/Astrolabe/issues/727), so the named Astrolabe project resolves to a current provenance-valid store. Reconcile tracker/milestone/README doctrine in [#721](https://github.com/ChrisRoyse/Astrolabe/issues/721) and [#734](https://github.com/ChrisRoyse/Astrolabe/issues/734) without treating documentation repair as product evidence.

Then close the active ingestion truth gaps that can poison every downstream layer:

- Persist and use byte-exact source content ([#473](https://github.com/ChrisRoyse/Astrolabe/issues/473), [#501](https://github.com/ChrisRoyse/Astrolabe/issues/501), owner decision [#510](https://github.com/ChrisRoyse/Astrolabe/issues/510)).
- Make store open/publication/durability behavior truthful ([#631](https://github.com/ChrisRoyse/Astrolabe/issues/631), [#632](https://github.com/ChrisRoyse/Astrolabe/issues/632), [#670](https://github.com/ChrisRoyse/Astrolabe/issues/670), [#676](https://github.com/ChrisRoyse/Astrolabe/issues/676), [#699](https://github.com/ChrisRoyse/Astrolabe/issues/699)).
- Eliminate incremental, snapshot, allocation, and concurrency corruption paths ([#635](https://github.com/ChrisRoyse/Astrolabe/issues/635), [#638](https://github.com/ChrisRoyse/Astrolabe/issues/638), [#658](https://github.com/ChrisRoyse/Astrolabe/issues/658), [#666](https://github.com/ChrisRoyse/Astrolabe/issues/666), [#676](https://github.com/ChrisRoyse/Astrolabe/issues/676), [#679](https://github.com/ChrisRoyse/Astrolabe/issues/679), [#682](https://github.com/ChrisRoyse/Astrolabe/issues/682)).
- Finish language-semantic correctness for C, Rust, and other deep resolvers ([#688](https://github.com/ChrisRoyse/Astrolabe/issues/688), [#690](https://github.com/ChrisRoyse/Astrolabe/issues/690), [#695](https://github.com/ChrisRoyse/Astrolabe/issues/695), [#702](https://github.com/ChrisRoyse/Astrolabe/issues/702), [#723](https://github.com/ChrisRoyse/Astrolabe/issues/723), [#726](https://github.com/ChrisRoyse/Astrolabe/issues/726), [#728](https://github.com/ChrisRoyse/Astrolabe/issues/728), [#729](https://github.com/ChrisRoyse/Astrolabe/issues/729), [#733](https://github.com/ChrisRoyse/Astrolabe/issues/733)).

### 2. Finish P3 convergence and physical compute truth

Close the end-to-end incremental path [#23](https://github.com/ChrisRoyse/Astrolabe/issues/23): real warm-vault latency, equivalence with fresh rebuild, MVCC history, edge re-pointing, no-op behavior, and recovery.

In parallel where dependencies allow, resolve the P3 GPU/panel/compression cluster. The key outcome is a truthful multi-domain panel with explicit placement and physical execution—not a CPU fallback wearing a CUDA label, and not a codec/report that measures declarations instead of stored bytes. Umbrellas and critical nodes include [#486](https://github.com/ChrisRoyse/Astrolabe/issues/486), [#521](https://github.com/ChrisRoyse/Astrolabe/issues/521), [#550](https://github.com/ChrisRoyse/Astrolabe/issues/550), and [#573](https://github.com/ChrisRoyse/Astrolabe/issues/573).

### 3. Complete grounding

Finish [#29](https://github.com/ChrisRoyse/Astrolabe/issues/29) so trust vocabulary, promotion-aware rollups, confidence bounds, erasure tombstones, and every grounded response surface agree. Then complete [#30](https://github.com/ChrisRoyse/Astrolabe/issues/30) for flakiness ceilings, survival-anchor immutability, and honest cold-start behavior.

This is the evidence substrate for later pack, guard, oracle, and self-improvement claims; moving downstream before trust lifecycle is real would create confident but ungrounded outputs.

### 4. Reach the P6 headline release

The near-term P6 sequence is:

1. Fix and remeasure unified search [#42](https://github.com/ChrisRoyse/Astrolabe/issues/42) until fused quality no longer regresses against legacy and warm-query cost is within the declared envelope.
2. Build and reality-verify `get_context_pack` [#41](https://github.com/ChrisRoyse/Astrolabe/issues/41): budget closure, content integrity, honest degradation, pack-quality containment, manifests, and bit-exact reproduction.
3. Complete the per-tool primary flip/rollback [#44](https://github.com/ChrisRoyse/Astrolabe/issues/44) only after the new serving path has real non-regression evidence.
4. Fix lowering publication atomicity [#705](https://github.com/ChrisRoyse/Astrolabe/issues/705) so on-demand kernel builds cannot leave stale published compatibility state.

This is the shortest path to the project’s “insanely useful” headline: trusted, economical context rather than just a large graph and many individual tools.

### 5. Close P7 composition gaps

Complete anomaly production and aggregation [#68](https://github.com/ChrisRoyse/Astrolabe/issues/68), then finish positive-seed label propagation and universal summarization [#69](https://github.com/ChrisRoyse/Astrolabe/issues/69). Demonstrate the real guard and multi-hop kernel-answer paths on sufficiently rich corpora ([#404](https://github.com/ChrisRoyse/Astrolabe/issues/404), [#407](https://github.com/ChrisRoyse/Astrolabe/issues/407)) rather than accepting structure-only or empty-seed evidence.

### 6. Build P8 in dependency order

P8 is not one feature; it is a chain:

1. Anneal replay/promotion/revert and Goodhart defenses ([#53](https://github.com/ChrisRoyse/Astrolabe/issues/53)).
2. Real knob wiring and recalibration ([#54](https://github.com/ChrisRoyse/Astrolabe/issues/54)).
3. Deficit-driven lens proposal through differentiation, shadow admission, hot-add, backfill, and rollback ([#55](https://github.com/ChrisRoyse/Astrolabe/issues/55)).
4. Mistake closure and wrong-only-once behavior ([#56](https://github.com/ChrisRoyse/Astrolabe/issues/56)).
5. Physical quantization gates, produced readiness tiers, and safe imputation ([#57](https://github.com/ChrisRoyse/Astrolabe/issues/57)).
6. Complete optimizer operations and janitor behavior ([#58](https://github.com/ChrisRoyse/Astrolabe/issues/58)).
7. Compose bridges, skills, monorepo search posture, and injection/supply-chain screening ([#70](https://github.com/ChrisRoyse/Astrolabe/issues/70), [#71](https://github.com/ChrisRoyse/Astrolabe/issues/71), [#72](https://github.com/ChrisRoyse/Astrolabe/issues/72), [#73](https://github.com/ChrisRoyse/Astrolabe/issues/73)).

Compression truth [#557](https://github.com/ChrisRoyse/Astrolabe/issues/557) and production compressed reads [#564](https://github.com/ChrisRoyse/Astrolabe/issues/564) must be resolved before optimization can safely tune those surfaces.

### 7. Finish P9 and prove the promise

Complete the security/erasure/redaction pass [#61](https://github.com/ChrisRoyse/Astrolabe/issues/61), resolve packaging/installer/license/binary-size decisions [#63](https://github.com/ChrisRoyse/Astrolabe/issues/63), and then demonstrate [#177](https://github.com/ChrisRoyse/Astrolabe/issues/177): agent edit to native artifact to physical outcome to guard/oracle decision to anchored evidence, without a human verification step and with readiness-gated refusal when proof is insufficient.

Only after that composed evidence should the project claim the `ASTROLABE_DONE` conjunction.

### 8. Finish operational growth and later platform work

Kernel farming still needs the measured throughput budget [#453](https://github.com/ChrisRoyse/Astrolabe/issues/453) and remaining scale rollout [#460](https://github.com/ChrisRoyse/Astrolabe/issues/460). The Calyx-native information-home EPIC [#504](https://github.com/ChrisRoyse/Astrolabe/issues/504) is a strategic follow-on that removes SQLite from the ingestion/interchange path and proves a no-`.db` store at wave scale.

Cross-platform porting begins only after the Windows end state is operational. The deferred port milestone currently has no decomposed issues; this is intentional deferral, not completion.

## Exit criteria for the roadmap

The roadmap is complete only when:

- all 22 currently open core tracker issues are closed with current manual-FSV evidence;
- open correctness issues that invalidate core truth claims are resolved or explicitly incorporated into a revised completion predicate;
- the flagship pack/search path wins its real measurements;
- the guard/oracle/readiness/self-improvement loop operates on grounded real outcomes;
- security, provenance, packaging, and autonomous verification are physically read back; and
- #65 can truthfully establish every `ASTROLABE_DONE` conjunct.
