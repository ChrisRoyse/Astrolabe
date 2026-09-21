# Kernel Farm Readiness — what stands between here and mining all of GitHub

**Assessment date:** 2026-08-12
**Question:** what must be done before Astrolabe can farm code kernels from every GitHub repository above 2,000 stars, as fast as this machine allows — and what becomes possible once it has.

Everything in §1–§5 is read from the tracker, the disk, and recorded measurements. §6 is projection and is labeled as such. §7 is speculation and is labeled as such.

---

## 0. Verdict

**Not ready.** The per-repository pipeline works and has produced a real 105-store fleet, but three of the four walls below are not throughput problems — they are correctness and robustness problems, and two of them would force a **full re-run of the entire corpus** if you started today.

The order that matters:

1. **Do not start Wave 2 before #980 lands.** It redefines what "kerneled" means. Every repo farmed before it is a partial intelligence surface that must be redone.
2. **The 74% Wave-1 failure rate is an abort-class problem, not a perf problem.** One bad file in a third-party repo currently kills an entire corpus. At 1,135 arbitrary repos this is the dominant failure mode.
3. **Memory, not CPU, caps your parallelism today.** One Bevy-class repo peaked at 52.2 GiB. You have 125.6 GiB. That is two concurrent lanes.
4. **Throughput is fixable and well-understood.** 74.5% of the measured Bevy wall sits in exactly two phases, both with open, unblocked, fully-specified issues.

---

## 1. Where the system actually stands

### Tracker (read 2026-08-12)

| | Count |
|---|---:|
| Open issues | 332 |
| `status:ready` | 224 |
| `status:in-progress` | 45 |
| `status:blocked` | 49 |
| `bug` | 239 |
| `sev:critical` | 22 |
| `sev:high` | 195 |
| `area:ingest` | 148 |
| `area:performance` | 100 |

Milestone `KF — Kernel farming (fleet layer)`: **54 open / 54 closed**. The foundation half of EPIC #461 (catalog, acquisition, discovery, orchestration, dedup, composition, serving, growth scheduler — #446, #449–#459) is **closed and proven**. The completion half is open.

### Fleet on disk (`D:\astrolabe-fleet`)

| Path | Contents |
|---|---|
| `store/` | **105 project stores**, 1,689,792 files, **116.3 GB** |
| `repos/` | **116 clones**, 410,243 files, **16.6 GB** |
| `catalog/` | Calyx vault (cf, ledger_head, MANIFEST, farm.lock) |

Composed fleet kernel `fleet:rust:v1`: **32 repo claims / 168 members**, members hash `b69b5726…c6873`, paired ledger, provenance readback verified.

So: acquisition and per-repo kerneling demonstrably work at ~100 repos. Cumulative composition is proven at 32.

### The target corpus

GitHub API readback 2026-08-03 (complete, `incomplete_results=false`):

- **1,183** Rust repositories at `stars:>=2000`
- **1,135** with `archived:false`
- **32,580** repositories across all languages at `stars:>=2000`

The manifest is the **admission-time query result**, not a frozen constant (#961). Rust is 3.6% of the full-ecosystem target.

### The machine

| | |
|---|---|
| CPU | AMD Ryzen 9 9950X3D — 16 cores / 32 threads |
| RAM | 134,909,595,648 B (**125.6 GiB**) |
| GPU | NVIDIA RTX 5090 (32 GB; WMI's 4 GB reading is the 32-bit `AdapterRAM` artifact) |
| C: | 1,862 GB total / **170.4 GB free** |
| D: | 7,452 GB total / **3,625.4 GB free** |

### Wave 1 (100 repos) — recorded verdict: **FAILED**

- **21 of 95** successful outcomes (20 kerneled + 1 refreshed) — a **22% success rate**
- **2.27 repos/hour** against a **7.97 repos/hour** threshold

That verdict stands on the issue and has not been superseded.

---

## 2. Measured per-repository cost

### Bevy, real native Windows run r5 (`c7fe6fa8`, Bevy HEAD `30462dd3`)

| Phase | ms | Share |
|---|---:|---:|
| `git_archaeology` | 1,931,166 | **44.6%** |
| `label_propagation` | 1,297,473 | **29.9%** |
| `import_raw` | 286,103 | 6.6% |
| `drift` | 195,780 | 4.5% |
| `weave` | 147,254 | 3.4% |
| `signal` | 128,754 | 3.0% |
| **Complete product call** | **4,334,672** | **72.2 min** |

- Archaeology spawned **3,512 sequential `git blame` children + 5,364 historical `cat-file` children** (#892).
- **Peak working set 56,041,811,968 B (52.2 GiB)**; peak private 57,416,335,360 B — transient simultaneous materialization inside one process generation, not a leak (#855).
- Product: 56,247 source nodes / 117,532 source edges; 56,247 lowered nodes / 451,444 lowered edges; vault chain intact.

### Astrolabe self-index (g25/g26 canonical runs)

- CBM pass **77.6–96.7 min**
- `compiler_preprocess` = **57.2%** of it, **serial over 266 translation units**
- `parallel_resolve` = **34.5%**, at **2.58 of 32 effective workers**
- Post-CBM import/publication stretch ≈ **50–60% of the full leg**
- Cross-run load noise measured at **±36–52%** on parallel phases — wall time alone is not a valid metric; use effective-worker ratio

### The size outlier

`zed-industries/zed`: exceeded the **7,200 s** pipeline timeout inside `import_raw_total` alone, **peak RSS 17,592 MiB**, 455 MB clone → quarantined (#548). Every other repo in that pass kerneled. `servo/servo`, `xlang-ai/x-algorithm`, `zama-ai/fhevm` are excluded by a fixed **2 GiB clone cap** (#962) — a capacity policy currently masquerading as a permanent verdict.

---

## 3. The four walls

### Wall 1 — Semantic completeness. **Start here or redo everything.**

`#980` (sev:critical, in-progress) is the wall that decides whether the farm is worth running.

Today a repo is marked `kerneled` when CBM SQLite rows are copied into Calyx and a partial panel runs. That is **preservation, not measurement**. The audit of the healthy canonical Astrolabe store (427,884,544 B, 93,656 nodes / 181,641 edges / 3,458 file hashes / 31,892 node vectors / 12,440 token vectors) found **62 distinct node-property names and 31 edge-property names**, and:

- `shadow_encoder_input` selects a **hard-coded subset** of CBM properties — many persisted atoms never become slots
- `Project | Branch | Folder` are partitioned as **structural-only** and never become constellations
- `node_vectors` / `token_vectors` are side families, **not frozen provenance-bound panel slots**
- S18 reads capped body-token text, not the exact source BLOB
- Uncovered present atoms include loop-risk flags, structured-classification/span/provenance facts, diagnostics, Git/worktree facts, import binding facts, call arguments/candidates/strategy/confidence, and co-change metrics

`#522` (now closed) can only enumerate pairs over slots that exist. **It cannot discover associations for facts the panel never measured.**

`#460`'s own dependency line was amended 2026-08-04 to record exactly this: Wave 2 cannot certify a partial intelligence surface. The dependency set is `#486 / #500 / #501 / #522 / #980`.

And #486 (multi-domain constellation) is blocked behind the whole GPU/ONNX panel-commissioning cluster: **#481, #482, #483, #484, #485, #501**, with #490/#491/#521/#545/#549/#569/#573/#605–#610 in the same neighborhood. Several are `status:blocked` and `sev:critical`. **This is the longest pole in the entire program and it is not a performance pole.**

> **Consequence:** every repository kerneled before #980 must be reprocessed. At 1,135 repos that is the difference between one run and two.

### Wall 2 — Abort-class robustness. This is what actually killed Wave 1.

A 22% success rate is not a throughput result. It is a robustness result. The recurring shape: **one malformed file, one ambiguous symbol, one allocation failure aborts an entire repository — or an entire corpus — often without recording its cause.**

Representative open issues:

| Issue | Failure |
|---|---|
| #1004 (crit) | File extension leaks into import identifier map → **aborts entire repo**; pkgmap never records its fatal error |
| #1024 (crit) | Dangling Rust module declaration (zero candidate files) → **aborts the entire corpus** |
| #1022 (crit) | Location-ambiguity refusal aborts corpus without recording cause; `(file,line)` identity collides on minified bundles |
| #1027 | Sibling-resolve allocation failure cancels the corpus with no refusal record |
| #869 (crit) | Publishes partial graphs on allocation failure instead of failing closed |
| #870 (crit) | Cross-LSP skips relationships when retained source unavailable |
| #982 | SQLite B-tree corruption in full graph dump |
| #979 | Failed first index leaves a partial canonical DB while the transition reports absent |
| #1037 | Publication abort **destroys the staged CBM store** |
| #579 | Indexer access-violates (0xC0000005) under memory pressure instead of failing closed |
| #515 | `index_repository` exits rc=127 with empty stdout deep in post-CBM processing |

`#1020` is the design fix for the whole class and is still **`status:needs-spec`**: *adopt a deliberate two-class error taxonomy — infrastructure-fatal vs per-file content defect.* Until that exists, every one of the 1,135 repos is a chance for an unknown third-party file to abort a multi-hour run.

**This is the highest-leverage work in the program per hour spent.** Third-party Rust at ecosystem scale contains every input shape the parsers have never seen.

### Wall 3 — Throughput and memory.

`#453` is the umbrella and is blocked by `#892, #69, #855, #515, #548, #961, #962, #964, #981, #983`.

**The two dominant terms are 74.5% of the Bevy wall and both are unblocked:**

- **#892 — archaeology.** Replace 3,512 serial blame children with deterministic bounded-worker concurrency, and 5,364 `cat-file` children with one pass-owned `git cat-file --batch-command --buffer -Z` session. `Blocked by: none.`
- **#69 — label propagation.** One immutable generation-bound `IndexTimeKernelView` over verified compact CSR, replacing whole-graph identity/snapshot work and an independent flood per seed. `Blocked by: none.`

**#855 is the single most load-bearing node in the entire graph.** It is a direct blocker of #453, and transitively of #815 → #807 through #854 and #852. It is the 52.2 GiB peak: `shadow_import` retains several complete corpus representations simultaneously — owned slot maps, decoded node vectors, live chunk results, candidate/family vectors, a complete edge plan, dump/new-row/existing-SIM/write-batch representations, a full cross-term batch, and the complete `after_snapshot` with reassembled exact source bytes. Plus `seeded_peer_indices` doing O(n²) index initialization behind an O(n·cap) contract.

**Until #855 lands, memory is your parallelism ceiling: 125.6 GiB ÷ 52.2 GiB = 2 Bevy-class lanes.** No amount of CPU work changes that.

Wave-28 (EPIC #1041) adds the measured CBM-side program: #1042 instrumentation (the profiler structurally could not see 92% of the run — `sub=TOTAL ms=362,094` against `elapsed_ms=4,657,061`), #1043 parallelize `compiler_preprocess`, #1044–#1047 resolve hot path, #1048–#1056 publication/config/watcher/cold-load, #1057 GPU.

**On GPU:** the measurement is honest and unflattering for the C half — **the CBM pass is 0.10% GPU-amenable** (6.0 s of 5,819 s; preprocessing and resolution are pointer-chasing and irreducibly serial). The real GPU surface is the Rust weave/assay side: `ann_generate` 137.0 + 121.6 s at n≈45k, dim 768, running at **9.8 GFLOP/s scalar CPU** where an RTX 5090 SGEMM does the same work in **~22 ms**; plus `kernel_artifact` 83.2 s, `label_propagation` 43.7 s, KSG bootstrap, MMD drift. `calyx-forge` already ships attested CUDA kernels with **bit-parity measured on this exact machine** (sm_120a, CUDA 13.3.33) — and **no Astrolabe crate uses it**. A 12 GB VRAM soft cap is hardcoded at `vram/budget.rs:13` on a 32 GB card. This is ~6.4 min/repo today, growing **quadratically** with corpus size — it is not the current bottleneck but it becomes one at Wave-2 scale.

### Wall 4 — Fleet lifecycle, determinism, and scale ceilings.

**The composition path is currently wedged.** `#815`: `fleet:rust:v1` is a healthy 32-repo kernel, but a correct cumulative recompose must reopen every input and **refuses on the first legacy Graph row** — `BurntSushi/ripgrep`, digest `fc594a6f…48c98`, `astrolabe-node-map-v2`, missing `atom_id`. Only zoxide is on the current v4 contract. So retirement (#807) is correctly blocked, and the fleet cannot legally recompose. #815 is itself blocked by `#841, #849, #856, #855, #854, #852` — and #854/#852 are blocked, #856 waits on #956.

**Narrow reads are unusable at scale.** `#817`: a read-only `kernel-read --verify-provenance` spent **>600 wall seconds** inside its first provenance read, consuming ~3 CPU seconds — because every verb opens the catalog **write-capable with `restore_ledger_hook=true`**, then opens a project vault with **default all-CF routing** and scans the **full Blob input-store prefix** to verify one sampled occurrence. Multiply that by 1,135.

**No source retirement exists.** `#807`: `kerneled` rows still carry live `clone_path`/`clone_bytes`; there is no lawful acquire → derive → compose → release loop and no rehydration path.

**Determinism is not yet established, and PC-38 says it is a prerequisite for parallelization, not a follow-up:**

- **#799 — the project name alone changes the full-index edge set.** A repo indexed under a different name produces different edges.
- **#479** — per-repo kernel `members_hash` is path-dependent: incremental refresh and fresh rebuild diverge at identical HEAD.
- **#1095** — a parallel insertion schedule is leaking into edge identity/readback.

**Hard scale ceilings that will be hit during Wave 2, not before:**

| Issue | Ceiling |
|---|---|
| #952 | SQLite graph counts **silently truncate at signed 32-bit** |
| #948 | Export truncates/overflows stores at **2 GiB** |
| #854 | >2 GiB graph stages need checked 64-bit offsets (blocked) |
| #962 | Fixed **2 GiB** clone cap permanently quarantines giants |
| #548 | 7,200 s pipeline timeout kills the giant-monorepo class |
| #884 | One-project resident cache; needs a measured multi-project generation LRU |
| #1008 | No Rayon CPU/memory budget coordination across concurrent MCP processes |

**Operational liveness** is a live concern: #1098 (sev:critical, in progress) — *publish inner resolver progress so full indexing is not killed as hung* — is precisely the class of defect that turns a 20-day unattended run into 20 days of babysitting. Alongside it: #801 (92-second launcher startup dominates no-op commands), #901/#911/#913/#921 (launcher stalls and hangs), #835 (self-host activation).

---

## 4. The critical path, as a graph

```
#460  Wave 2 — full dynamic Rust stars:>=2000
  ├── #453  throughput umbrella
  │     ├── #892  archaeology            [ready, unblocked]  ← 44.6% of Bevy wall
  │     ├── #69   label propagation      [ready, unblocked]  ← 29.9% of Bevy wall
  │     ├── #855  materialization RSS    [in-progress]       ← 52.2 GiB peak; the keystone
  │     ├── #515  rc=127 fail-closed     [ready]
  │     ├── #964  bounded mutation readback
  │     ├── #981  parallel TU expansion  [blocked by #969]
  │     ├── #983  QN buckets + resolution cache
  │     ├── #548  zed / giant-monorepo class
  │     ├── #961  atomic discovery manifest
  │     └── #962  measured disk admission
  ├── #807  source retirement + rehydration
  │     ├── #815  upgrade legacy fleet inputs   ← WEDGED on ripgrep v2 Graph row
  │     │     └── #841, #849, #856←#956, #855, #854, #852
  │     └── #817  narrow read-only opens        ← 600 s cold read
  ├── #479  kernel members_hash determinism
  ├── #980  semantic atom→lens coverage   [CRITICAL — redefines "kerneled"]
  ├── #486  multi-domain constellation    [blocked: #481 #482 #483 #484 #485 #501]
  ├── #500  measure atoms through commissioned panel  [blocked]
  └── #501  byte-exact source spans       [in-progress]
```

Roughly **25 named issues on the formal spine**, plus the **~15-issue panel/GPU commissioning cluster** behind #486/#500, plus the **abort-class robustness set** (~15–20 issues) that is not formally on the spine but is what actually produced the 22% Wave-1 success rate.

---

## 5. Throughput math

**Measured:**

| Scenario | Rate | 1,135 repos |
|---|---:|---:|
| Wave-1 actual | 2.27 repos/hr | **500 h ≈ 20.8 days** continuous |
| Wave-1 threshold | 7.97 repos/hr | **142 h ≈ 5.9 days** |
| Bevy-class, single lane | 0.83 repos/hr | — |
| **Memory-bound lanes today** | **2** (125.6 GiB ÷ 52.2 GiB) | — |

**Disk projection** (from the real 105-store fleet): 116.3 GB ÷ 105 = **1.11 GB store per repo** → ≈ **1.26 TB** for 1,135. Clones at 143 MB average (with giants excluded by the 2 GiB cap) → ≈ 162 GB, higher once #962 admits giants. Against 3,625 GB free on D:, **disk is not the binding constraint** — which also means #807 retirement is a capacity optimization for Wave 2, not a precondition for finishing Rust. It becomes a precondition for the 32,580-repo full-ecosystem target.

**Projection, not measurement** — if #892 and #69 remove ~85% of their two phases (they are 74.5% of the Bevy wall) and #855 bounds peak RSS to single-digit GiB:

- Bevy-class per-repo: 72.2 min → **≈ 26 min** (≈ 2.3 repos/hr/lane)
- Lanes admissible at ~8 GiB peak: **≈ 12**
- Fleet rate: **≈ 20–27 repos/hr** → **42–57 h ≈ 2 days** for the full Rust corpus

That is the prize: **20.8 days → 2 days**, from two unblocked issues and one in-progress one. Every number in that projection needs a real receipt before it is quoted as fact.

---

## 6. Recommended sequence

**Phase A — make a run survivable (highest leverage per hour).**
Spec #1020's two-class error taxonomy, then land the corpus-abort set: #1004, #1024, #1022, #1027, #869, #870, #979, #1037, #982, #579, #515. Add #1098 so a long run is not killed as hung. *Exit criterion: a 100-repo pass where no single file aborts a corpus and every skip is labeled and counted.*

**Phase B — settle what "kerneled" means, before spending 1,135 repos of wall clock.**
#980, then #501 → #486's blocking cluster → #500. This is the long pole; start it in parallel with Phase A, not after. *Exit criterion: the coverage witness reconstructs `present atoms = encoded + embedded + imported-vector` with an uncovered-present count of exactly zero.*

**Phase C — determinism, because PC-38 makes it a prerequisite.**
#799 (project name changes the edge set), #1095, #479. *Exit criterion: two runs at identical HEAD, byte-compared.*

**Phase D — throughput.**
#855 first (it unwedges #453 *and* #854/#852 → #815 → #807), then #892 and #69 in parallel, then #983/#981/#964, then #1041's mechanical batches. Instrument first (#1042) — the profiler cannot currently see 92% of the run, so nothing measured before it is trustworthy.

**Phase E — fleet lifecycle.**
#817 (600 s reads), then #815 (unwedge composition), then #807 (retirement/rehydration), #961 (atomic manifest), #962 (measured disk admission), #548 + #952/#948/#854 (giant class and 32-bit/2 GiB ceilings).

**Phase F — gate, then run.**
Post-fix Wave 1 (100 repos) must **pass** its gate. Then Wave 2. #835 self-host activation should land somewhere in A–C so Astrolabe is building Astrolabe while the rest proceeds.

**Phase G — GPU (#1057), after Wave 2 is running.**
`ann_generate` grows quadratically with corpus size; it is ~6.4 min/repo today and becomes structural at fleet scale. The kernels exist, bit-parity is already measured on this card, and nothing consumes them.

---

## 7. What the kernel makes possible — speculation, clearly labeled

### Designed and blueprint-backed (this is the plan, not a guess)

1. **The Rust canon.** The load-bearing ~1% of the entire >2k-star Rust ecosystem — approximate feedback-vertex-set over the association graph, scored `0.40·degree + 0.40·betweenness + 0.20·groundedness`, with a **≥0.95 held-out recall gate** proving the core actually explains the corpus. `fleet:rust:v1` already does this for 32 repos at 168 members.
2. **Token-budgeted, bit-reproducible context packs** for any Rust task, with content hashes and provenance on every element (5.5). The flagship product.
3. **Cross-repo bridges** (5.11) — symbols that ground two repos at once. The measured shared core of the ecosystem, rather than the dependency graph's claim about it.
4. **Universal scope summarization** — any scope returns its kernel as its structural summary, with recall and grounded fraction attached.

### The biggest unlock, and it is not the kernel itself

5. **Guard calibration at ecosystem scale.** `guard_check` — measuring an agent's proposed diff per-slot against a repo's trusted region — is today **blocked** (#404, #312) for a mundane reason: a thin single-project corpus cannot supply the ≥50 bad cases calibration needs while also satisfying the sparse-slot floor. 1,135 repos of full-history git archaeology with SZZ bug-inducing-commit detection produces **tens of thousands of grounded bad-case anchors** as a byproduct of work already in the pipeline. That converts the guard from a demo into a calibrated instrument with a real false-accept rate, and it converts the oracle's predictions from priors into base rates measured on real history.

This is the argument for farming the corpus that has nothing to do with having a big kernel: **the fleet is an anchor factory.** Grounding is the scarce input in this whole architecture, and archaeology at fleet scale manufactures it.

### Probable, given what the substrate already does

6. **A measured idiom canon.** #455 already proved cross-repo content equivalence works (#473 notes the census currently runs on a property-fingerprint proxy that undercounts equality at 58% — worth fixing before the census is quoted). Which implementations independently recur across N unrelated codebases is then a *measurement*, not a style opinion.
7. **API-usage priors with counts.** How the ecosystem actually calls tokio/serde/clap — argument shapes, error handling, lifetimes — as frequencies over real code, not scraped prose.
8. **Cross-repo transfer entropy** (12.1): "changes in crate A drive failures in dependents k days later," measured from real history across the whole graph.
9. **A novelty measure for any new repo:** what fraction is recomposition of known ecosystem idioms versus genuinely new. An honest originality and blast-radius signal.
10. **A deprecation/decay map** — label propagation over the association graph with decayed confidence, plus time-windowed kernels, gives you what is dying and what is rising, measured rather than announced.
11. **Grounded refactoring advisor** (12.3): disagree-clones + synergy analysis + kernel membership → ranked refactor candidates with predicted blast radius and grounded payoff.
12. **Honest backtesting** (12.7): "would the panel have flagged this bug at the commit before it shipped?" — run across the entire ecosystem's real history, admission-gated so the system must beat the naive baseline or say so. Very few systems can make this claim; the MVCC time-travel and ledger machinery to do it already exists.

### Genuinely speculative

13. **A curriculum function for model training.** Selecting code by *measured load-bearingness and measured bits* rather than by stars or heuristics is a different and defensible selection criterion for a training or distillation corpus. The kernel is, structurally, an importance-sampling function over all public code.
14. **The autonomy dial** (12.2): per-scope auto-merge permission earned from the readiness predicate plus guard calibration — "auto-merge allowed where readiness is green and guard FAR < 1%." This only becomes real once #5 above is done.
15. **The other 31,397 repos.** Rust is 3.6% of the 32,580-repo target. Whatever throughput you prove on Rust, the full-ecosystem target is ~28× the work — and the language-specific abort classes (Wall 2) reset for each new language's extraction path. Rust first is the right call precisely because it bounds that risk.
16. **Astrolabe as its own first customer.** #835 gates it. Self-index → self-kernel → context packs used to build Astrolabe is the flywheel the blueprint is named for, and it is closer than Wave 2 is.

### Honest ceilings — what this will not do

- **The data-processing inequality caps derived signal.** No amount of cross-term enumeration exceeds `I(panel; outcome)`. More lenses is not more information, and the substrate refuses below a 0.05-bit floor and above a 0.6 correlation ceiling for exactly this reason.
- **Mutual information below ~50 paired samples is provisional by construction.** Thin anchor coverage in a region means the answer there is "insufficient," and the system is built to say so rather than guess.
- **The kernel measures structure and grounding. It does not write code.** It tells an agent what matters, what is load-bearing, what is grounded, and what is unknown territory. Generation stays with the model.
- **Scale is an unproven regime.** ~34M nodes projected across 1,135 repos is roughly **170× Calyx's documented 199k-node / 2.44M-edge production corpus**. The mitigation is architectural and already chosen — per-repo kernels composed into a kernel-of-kernels, never one giant graph — but it is untested at that multiple, and #952's signed-32-bit count truncation is a reminder that the ceilings are real and are hit in order.
- **Security analysis is out of scope** by owner directive (#740). Blueprint capability 12.6 does not apply here.
- **Windows-only** until the system is operational; porting is a deliberate final phase (#238).

---

## 8. The one-sentence answer

**Before you start:** land the abort-class taxonomy so a run survives 1,135 arbitrary repos, land #980 so "kerneled" means something you will not have to redo, prove determinism, and fix #855 so you can run more than two lanes — then #892 and #69 turn a 20-day run into a 2-day one.

**Once you have it:** the kernel is the headline, but the anchor corpus is the prize — full-history archaeology across the ecosystem is what finally makes the guard, the oracle, and honest backtesting calibratable, and those are the capabilities that change what an agent is allowed to do unsupervised.

---

### Provenance

Tracker counts, milestone state, issue bodies and dependency edges read from GitHub 2026-08-12. Fleet disk state measured on `D:\astrolabe-fleet` the same day. Hardware read via `Win32_Processor` / `Win32_ComputerSystem` / `Win32_LogicalDisk`. All per-phase timings, RSS peaks, throughput rates, and corpus counts are quoted from the recorded measurements on their issues (#453, #460, #855, #892, #69, #980, #1041, #1057, #548) and are timestamped observations, not constants. Projections in §5 and §6 are labeled and carry no receipt yet.
