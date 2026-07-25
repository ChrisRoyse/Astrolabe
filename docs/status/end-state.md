# Desired end state

> Design is described by the [Astrolabe blueprint](../astrolabe-blueprint.md); current product intent and completion state are governed by [EPIC #65](https://github.com/ChrisRoyse/Astrolabe/issues/65) and later issue decisions.

## Mission

Astrolabe is intended to be the full-state-verification and grounded-intelligence layer for AI coding agents: the system that tells an agent whether its code works in reality, why that verdict is justified, what is likely to break, and what evidence is missing. It should refuse when the evidence cannot support a claim.

The target closed loop is:

```text
agent task
  -> kernel-ranked, token-budgeted context
  -> code change
  -> format + lint + native compile
  -> exercise the real artifact on real data
  -> independently read physical outcomes
  -> guard verdict + impact prediction
  -> outcome anchors + ledger provenance
  -> re-measure, re-distill, and improve the next decision
```

[#177](https://github.com/ChrisRoyse/Astrolabe/issues/177) is the zero-touch agent-code loop capstone. Closed [#178](https://github.com/ChrisRoyse/Astrolabe/issues/178) supplies the complementary self-verifying-store foundation. The product promise is reached only when the composed loop is demonstrated against reality, not when its pieces merely compile or return plausible API responses.

## Intended system

### One owned native system

A Rust host binary embeds Calyx and statically links the owned CBM C engine as `libcbm.a`. CBM decomposes real repositories across its broad language/semantic surface into symbols and typed associations. Calyx persists, measures, distills, grounds, guards, predicts, and audits that graph. Both parent trees are first-class Astrolabe source under `calyx/` and `cbm/`; the old vendoring/pin model is retired, although cleanup EPIC [#286](https://github.com/ChrisRoyse/Astrolabe/issues/286) remains open.

Windows is the only active shipping/evidence target until the complete local system works. Cross-platform work is deliberately deferred under [#238](https://github.com/ChrisRoyse/Astrolabe/issues/238) and the `Port — cross-platform (deferred)` milestone; a zero-issue deferred milestone does not mean the port is complete.

### A trustworthy information home

Every code symbol has stable series identity, content/version identity, measured slots, typed graph edges, history, and ledger provenance. The Aster vault is the durable intelligence source. The blueprint retains SQLite as a regenerable compatibility artifact for legacy Cypher/UI paths; the newer Calyx-native-home EPIC [#504](https://github.com/ChrisRoyse/Astrolabe/issues/504) goes further and plans to remove SQLite from the ingestion/interchange path. That newer issue is the live direction; on-demand compatibility export must be reconciled there rather than inferred from the older blueprint.

### Grounded, measured intelligence

The intended stack is built from the bottom up:

1. CBM extracts atoms and all base associations.
2. A versioned lens panel measures each symbol without confusing structured facts with learned embeddings.
3. Real outcomes—runs, failures, traces, changes, reviews, incidents, and agent results—become trust-scoped anchors.
4. Assay measures signal usefulness, redundancy, synergy, causality, and calibration instead of relying on guessed global weights.
5. A recall-gated kernel distills the smallest explanatory core.
6. Search and context packs compose that core into economical agent context.
7. Guard and Oracle validate generated code, predict impact, abduce causes, forecast recurrence, and refuse unsupported questions.
8. Provenance makes every claim traceable and reproducible.
9. Anneal and mistake closure improve the system reversibly without Goodharting the target metrics.

### Agent-facing outcome

The 14 legacy CBM tools remain compatible while Astrolabe adds grounded tools such as `anchor_outcome`, `measure_bits`, `get_kernel`, `get_context_pack`, `kernel_answer`, `find_similar`, `detect_anomalies`, `guard_check`, `predict_impact`, `abduce_cause`, `get_provenance`, `get_readiness`, and `optimizer_status`. Every meaningful result carries trust, freshness, provenance, warnings, and fail-closed `{code, message, remediation}` errors.

The flagship outcome is `get_context_pack(task, token_budget)`: a content-hashed, recall-gated, reproducible pack that contains the needed fix context at a small fraction of naive file-dump tokens. It is still open under [#41](https://github.com/ChrisRoyse/Astrolabe/issues/41).

## Measurable success

The blueprint makes the vision falsifiable. The current completion process must restate these under the manual-FSV doctrine, but the product targets remain useful:

| Outcome | Intended measure |
|---|---|
| Context economy | Kernel/context packs reach at least 0.95 recall on real held-out agent tasks at no more than 20% of naive file-dump tokens across at least three real repositories. |
| Guard quality | False-accept rates remain within calibrated content/identity bounds, with a usable false-reject rate on historically accepted changes. |
| Prediction lift | Grounded impact prediction ranks actually failing checks above the hop-distance baseline across multiple real corpora. |
| Measured intelligence | Per-repository signal ranking and fused search demonstrably outperform or differ usefully from fixed CBM weights and legacy search. |
| Provenance | Every tool answer has a ledger-backed trace; reproduction is bit-exact where promised; chain verification is intact. |
| Compatibility/performance | Legacy tools remain behavior-compatible and the native integrated path stays within measured full/incremental overhead budgets. |
| Flywheel | Accumulated real anchors measurably improve context recall and guard calibration versus the initial snapshot. |

## Definition of done

[EPIC #65](https://github.com/ChrisRoyse/Astrolabe/issues/65) defines:

```text
ASTROLABE_DONE =
  LINKED
  ∧ CONSTELLATED
  ∧ GROUNDED
  ∧ MEASURED
  ∧ DISTILLED
  ∧ GUARDED
  ∧ PREDICTIVE
  ∧ PROVENANCED
  ∧ SELF-OPTIMIZING
  ∧ COMPATIBLE
  ∧ HONEST
```

Every conjunct requires native Windows buildability, the real artifact exercised on real data, independent physical-state readback, and relevant edge probes recorded on the driving issue. Tests, mocks, hosted CI, and retired gate scripts are not evidence.

P10/frontier ideas—organization-wide vaults, reviewer routing, intelligence UI overlays, counterfactual evaluation, and other product-line extensions—come after the P0–P9 completion predicate and are not required to call the current core build done.
