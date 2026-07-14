//! Full State Verification for agent-task Reward anchors, promote-on-resolution,
//! and the opt-in hook contract (issue #28, blueprint 06 §2.4 / 15 §4).
//!
//! Every test drives the real durable-vault path, then reopens the vault and
//! reads persisted bytes back independently of the mutation return values.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use astrolabe_anchors::{
    AGENT_TASK_REWARD_CONFIDENCE, ASTRO_ANCHOR_CONTRADICTION, ASTRO_ANCHOR_PACK_INPUT_INVALID,
    ASTRO_ANCHOR_PACK_UNKNOWN, HookOutcome, OutcomeAnchorRequest, OutcomeKind, OutcomeSubject,
    TrustTag, effective_anchor_trust, erase_anchors_by_source, ingest_agent_task_outcome,
    ingest_outcome_anchors, is_anchor_promoted, promote_on_resolution, read_agent_task_pack,
    read_all_anchor_rows, read_anchor_contradictions, read_anchor_promotions, read_anchor_rows,
    read_anchor_tombstones, record_agent_task_pack, rollup_anchor_trust,
    rollup_effective_anchor_trust, run_hook_process,
};
use calyx_aster::cf::{ColumnFamily, ledger_key};
use calyx_aster::vault::{AsterVault, VaultOptions};
use calyx_core::VaultStore;
use calyx_core::{AnchorKind, AnchorValue, CxId, SystemClock, VaultId};

static NEXT: AtomicU64 = AtomicU64::new(0);
const ACTOR: &str = "astrolabe-agent-task-test";
const SALT: &[u8] = b"astrolabe-agent-task-fsv";

struct TempVault(PathBuf);
impl Drop for TempVault {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
impl AsRef<Path> for TempVault {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

fn temp_dir(name: &str) -> TempVault {
    let dir = std::env::temp_dir().join(format!(
        "astrolabe-agent-task-{name}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create vault dir");
    TempVault(dir)
}

fn open(dir: &Path) -> AsterVault<SystemClock> {
    AsterVault::new_durable(
        dir,
        "01ARZ3NDEKTSV4RRFFQ69G5FAV".parse::<VaultId>().unwrap(),
        SALT.to_vec(),
        VaultOptions::default(),
    )
    .expect("open durable vault")
}

fn cx(byte: u8) -> CxId {
    CxId::from_bytes([byte; 16])
}

/// Seeds a resolved `ci:*` TestPass outcome (pass/fail) on the given symbols.
fn seed_ci_testpass(
    vault: &AsterVault<SystemClock>,
    source: &str,
    observed_at: u64,
    cases: &[(CxId, bool)],
) {
    let subjects = cases
        .iter()
        .map(|(cx_id, passed)| OutcomeSubject {
            subject_id: cx_id.to_string(),
            anchor_kind: AnchorKind::TestPass,
            value: AnchorValue::Bool(*passed),
        })
        .collect();
    let request =
        OutcomeAnchorRequest::new(OutcomeKind::TestRun, source, observed_at, None, subjects)
            .expect("ci request");
    let cx_ids = cases
        .iter()
        .map(|(cx_id, _)| (cx_id.to_string(), *cx_id))
        .collect();
    ingest_outcome_anchors(vault, &request, &cx_ids, ACTOR).expect("seed ci testpass");
}

/// Independent raw readback of the whole Anchors CF (sorted), for append-only
/// byte-equality assertions across a tombstone commit.
fn raw_anchor_cf(vault: &AsterVault<SystemClock>) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut rows: Vec<(Vec<u8>, Vec<u8>)> = vault
        .scan_cf_at(vault.snapshot(), ColumnFamily::Anchors)
        .expect("scan anchors cf")
        .into_iter()
        .collect();
    rows.sort();
    rows
}

fn reward_cx_ids_for_source(vault: &AsterVault<SystemClock>, source: &str) -> Vec<CxId> {
    let mut out: Vec<CxId> = read_anchor_rows(vault)
        .expect("read rows")
        .into_iter()
        .filter(|row| row.row.kind == AnchorKind::Reward)
        .filter(|row| row.row.anchors.iter().any(|a| a.source == source))
        .map(|row| row.row.cx_id)
        .collect();
    out.sort();
    out
}

#[test]
fn agent_task_anchors_land_on_exactly_the_pack_members() {
    let dir = temp_dir("attribution");
    let vault = open(dir.as_ref());
    let members = [cx(1), cx(2), cx(3)];
    // A second, disjoint pack that must stay untouched proves "no more".
    let other_members = [cx(9)];

    record_agent_task_pack(&vault, "pack-A", &members, 1_786_000_000, ACTOR)
        .expect("record pack A");
    record_agent_task_pack(&vault, "pack-B", &other_members, 1_786_000_000, ACTOR)
        .expect("record pack B");

    let report = ingest_agent_task_outcome(
        &vault,
        "pack-A",
        "codex",
        "session-1",
        true,
        1_786_000_100,
        ACTOR,
    )
    .expect("ingest agent task");
    assert_eq!(report.anchors_written, 3, "one Reward per pack-A member");
    assert!(report.unmapped_subjects.is_empty(), "every member mapped");
    assert_eq!(
        report.trust,
        TrustTag::Provisional,
        "agent evidence is proxy"
    );
    drop(vault);

    // FSV: reopen and read persisted rows back.
    let vault = open(dir.as_ref());
    let landed = reward_cx_ids_for_source(&vault, "agent:codex:session-1");
    assert_eq!(
        landed,
        vec![cx(1), cx(2), cx(3)],
        "Reward anchors land on exactly pack-A members, no more, no less"
    );
    for row in read_anchor_rows(&vault).expect("rows") {
        if row.row.kind == AnchorKind::Reward {
            let anchor = &row.row.anchors[0];
            assert_eq!(anchor.source, "agent:codex:session-1");
            assert_eq!(anchor.value, AnchorValue::Number(1.0));
            assert_eq!(
                anchor.confidence.to_bits(),
                AGENT_TASK_REWARD_CONFIDENCE.to_bits()
            );
        }
    }
    // Idempotent re-post writes zero new anchors.
    let again = ingest_agent_task_outcome(
        &vault,
        "pack-A",
        "codex",
        "session-1",
        true,
        1_786_000_100,
        ACTOR,
    )
    .expect("idempotent re-post");
    assert_eq!(again.anchors_written, 0);
    assert_eq!(again.anchors_deduplicated, 3);
    drop(vault);
}

#[test]
fn ci_pass_promotes_reward_anchors_and_unrelated_ci_does_not() {
    let dir = temp_dir("promotion");
    let vault = open(dir.as_ref());
    let members = [cx(1), cx(2)];
    record_agent_task_pack(&vault, "pack-P", &members, 1_786_100_000, ACTOR).expect("record pack");
    ingest_agent_task_outcome(&vault, "pack-P", "codex", "s2", true, 1_786_100_100, ACTOR)
        .expect("agent task success");
    // CI passes on exactly the changed symbols.
    seed_ci_testpass(
        &vault,
        "ci:gh:100",
        1_786_100_200,
        &[(cx(1), true), (cx(2), true)],
    );
    // An unrelated CI run passes on a symbol outside the pack.
    seed_ci_testpass(&vault, "ci:gh:unrelated", 1_786_100_300, &[(cx(9), true)]);

    let promoted =
        promote_on_resolution(&vault, "agent:codex:s2", "ci:gh:100", 1_786_100_400, ACTOR)
            .expect("promote on ci pass");
    assert_eq!(promoted.promotions_written, 2, "both members promoted");
    assert_eq!(promoted.contradictions_written, 0);
    assert!(
        promoted.fsv.is_some(),
        "row-writing commit earns an FSV witness"
    );

    // Unrelated CI run promotes nothing on the pack members.
    let unrelated = promote_on_resolution(
        &vault,
        "agent:codex:s2",
        "ci:gh:unrelated",
        1_786_100_500,
        ACTOR,
    )
    .expect("promote against unrelated ci");
    assert_eq!(
        unrelated.promotions_written, 0,
        "an unrelated CI run does not promote the pack's anchors"
    );
    assert!(
        unrelated.fsv.is_none(),
        "no rows written => labeled FSV absence"
    );
    drop(vault);

    // FSV: reopen and read promotion rows independently.
    let vault = open(dir.as_ref());
    let promotions = read_anchor_promotions(&vault).expect("read promotions");
    assert_eq!(
        promotions.len(),
        2,
        "exactly the two member promotions persisted"
    );
    let promoted_cx: Vec<CxId> = promotions.iter().map(|p| p.cx_id).collect();
    assert_eq!(promoted_cx, vec![cx(1), cx(2)]);
    for promotion in &promotions {
        assert_eq!(promotion.promoted_source, "agent:codex:s2");
        assert_eq!(promotion.resolving_source, "ci:gh:100");
    }
    // Effective trust rises to Trusted; the stored anchor source is unchanged.
    assert_eq!(
        effective_anchor_trust(cx(1), "agent:codex:s2", &promotions).unwrap(),
        TrustTag::Trusted
    );
    assert!(is_anchor_promoted(&promotions, cx(2), "agent:codex:s2"));
    assert!(!is_anchor_promoted(&promotions, cx(9), "agent:codex:s2"));

    // Idempotent: re-running the same resolution writes nothing new.
    let again = promote_on_resolution(&vault, "agent:codex:s2", "ci:gh:100", 1_786_100_600, ACTOR)
        .expect("idempotent promote");
    assert_eq!(again.promotions_written, 0);
    assert_eq!(again.promotions_deduplicated, 2);
    assert_eq!(read_anchor_promotions(&vault).unwrap().len(), 2);
    drop(vault);
}

#[test]
fn agent_success_with_ci_failure_is_a_contradiction_that_refuses_promotion() {
    let dir = temp_dir("contradiction");
    let vault = open(dir.as_ref());
    record_agent_task_pack(&vault, "pack-C", &[cx(1)], 1_786_200_000, ACTOR).expect("record pack");
    ingest_agent_task_outcome(&vault, "pack-C", "codex", "s3", true, 1_786_200_100, ACTOR)
        .expect("agent claimed success");
    // CI fails on the same symbol.
    seed_ci_testpass(&vault, "ci:gh:200", 1_786_200_200, &[(cx(1), false)]);

    let report = promote_on_resolution(&vault, "agent:codex:s3", "ci:gh:200", 1_786_200_300, ACTOR)
        .expect("reconcile");
    assert_eq!(report.promotions_written, 0, "promotion refused");
    assert_eq!(report.contradictions_written, 1, "contradiction flagged");
    drop(vault);

    // FSV: reopen; contradiction is persisted and queryable, no promotion exists.
    let vault = open(dir.as_ref());
    let contradictions = read_anchor_contradictions(&vault).expect("read contradictions");
    assert_eq!(contradictions.len(), 1);
    assert_eq!(contradictions[0].code, ASTRO_ANCHOR_CONTRADICTION);
    assert_eq!(contradictions[0].cx_id, cx(1));
    assert_eq!(contradictions[0].agent_source, "agent:codex:s3");
    assert_eq!(contradictions[0].resolving_source, "ci:gh:200");
    assert!(read_anchor_promotions(&vault).unwrap().is_empty());

    // Both anchors retained at their original trust.
    let promotions = read_anchor_promotions(&vault).unwrap();
    assert_eq!(
        effective_anchor_trust(cx(1), "agent:codex:s3", &promotions).unwrap(),
        TrustTag::Provisional,
        "the agent Reward anchor keeps its provisional trust"
    );
    let rows = read_anchor_rows(&vault).expect("rows");
    let has_agent = rows.iter().any(|r| {
        r.row.kind == AnchorKind::Reward
            && r.row.anchors.iter().any(|a| a.source == "agent:codex:s3")
    });
    let has_ci = rows.iter().any(|r| {
        r.row.kind == AnchorKind::TestPass && r.row.anchors.iter().any(|a| a.source == "ci:gh:200")
    });
    assert!(has_agent && has_ci, "both anchors are retained");
    drop(vault);
}

#[test]
fn unknown_pack_id_refuses_fail_closed_with_no_orphan_anchors() {
    let dir = temp_dir("unknown-pack");
    let vault = open(dir.as_ref());
    // No pack recorded at all: before-state is empty.
    assert!(read_anchor_rows(&vault).unwrap().is_empty());

    let error = ingest_agent_task_outcome(
        &vault,
        "ghost-pack",
        "codex",
        "s4",
        true,
        1_786_300_000,
        ACTOR,
    )
    .expect_err("unknown pack refused");
    assert_eq!(error.code, ASTRO_ANCHOR_PACK_UNKNOWN);
    drop(vault);

    // FSV: after-state still has zero anchors — no orphan was written.
    let vault = open(dir.as_ref());
    assert!(
        read_anchor_rows(&vault).unwrap().is_empty(),
        "a refused unknown pack leaves zero anchor rows"
    );
    assert!(
        read_agent_task_pack(&vault, "ghost-pack")
            .unwrap()
            .is_none()
    );

    // Edge: invalid pack recordings refuse fail-closed.
    assert_eq!(
        record_agent_task_pack(&vault, "", &[cx(1)], 1_786_300_000, ACTOR)
            .expect_err("empty pack_id")
            .code,
        ASTRO_ANCHOR_PACK_INPUT_INVALID
    );
    assert_eq!(
        record_agent_task_pack(&vault, "pack-empty", &[], 1_786_300_000, ACTOR)
            .expect_err("empty members")
            .code,
        ASTRO_ANCHOR_PACK_INPUT_INVALID
    );
    assert_eq!(
        record_agent_task_pack(&vault, "pack-dup", &[cx(1), cx(1)], 1_786_300_000, ACTOR)
            .expect_err("duplicate members")
            .code,
        ASTRO_ANCHOR_PACK_INPUT_INVALID
    );
    drop(vault);
}

/// The agent-task flywheel reaches the #29 aggregate trust lifecycle end to end:
/// a promoted proxy anchor lifts the promotion-aware aggregate from Provisional
/// to Trusted while the promotion-blind catalog rollup never moves, and source
/// erasure then recomputes the aggregate over the tombstone-excluded active rows
/// with the original Anchor CF bytes never rewritten.
#[test]
fn promotion_lifts_aggregate_trust_and_erasure_recomputes_it() {
    let dir = temp_dir("aggregate-lifecycle");
    let vault = open(dir.as_ref());
    let members = [cx(1), cx(2)];
    record_agent_task_pack(&vault, "pack-agg", &members, 1_786_500_000, ACTOR)
        .expect("record pack");
    ingest_agent_task_outcome(
        &vault,
        "pack-agg",
        "codex",
        "agg",
        true,
        1_786_500_100,
        ACTOR,
    )
    .expect("agent success");

    // Before any resolved evidence the only anchors are proxy agent Rewards: both
    // the catalog rollup and the promotion-aware rollup are Provisional.
    let rows = read_anchor_rows(&vault).expect("rows before ci");
    let promotions = read_anchor_promotions(&vault).expect("promotions before");
    assert!(promotions.is_empty());
    assert_eq!(
        rollup_anchor_trust(rows.iter()).unwrap(),
        TrustTag::Provisional
    );
    assert_eq!(
        rollup_effective_anchor_trust(rows.iter(), &promotions).unwrap(),
        TrustTag::Provisional
    );

    // A resolved CI pass lands on the same symbols but is not yet reconciled.
    seed_ci_testpass(
        &vault,
        "ci:gh:agg",
        1_786_500_200,
        &[(cx(1), true), (cx(2), true)],
    );
    let rows = read_anchor_rows(&vault).expect("rows after ci");
    let promotions = read_anchor_promotions(&vault).expect("promotions after ci");
    // The agent anchor is still an unpromoted proxy, so one proxy contributor
    // poisons both rollups fail-closed even though a Trusted ci anchor co-exists.
    assert_eq!(
        rollup_anchor_trust(rows.iter()).unwrap(),
        TrustTag::Provisional
    );
    assert_eq!(
        rollup_effective_anchor_trust(rows.iter(), &promotions).unwrap(),
        TrustTag::Provisional
    );

    // Reconcile: CI confirms the agent claim, promoting both proxy anchors.
    let report =
        promote_on_resolution(&vault, "agent:codex:agg", "ci:gh:agg", 1_786_500_300, ACTOR)
            .expect("promote");
    assert_eq!(report.promotions_written, 2);
    drop(vault);

    // FSV: reopen; the promotion-aware aggregate is now Trusted (every active
    // anchor is Trusted: ci by catalog, agent by promotion) while the
    // promotion-blind catalog rollup still reports Provisional — the wiring, not
    // a return value, carries the promotion into the aggregate.
    let vault = open(dir.as_ref());
    let rows = read_anchor_rows(&vault).expect("rows after promote");
    let promotions = read_anchor_promotions(&vault).expect("promotions after promote");
    assert_eq!(promotions.len(), 2);
    assert!(is_anchor_promoted(&promotions, cx(1), "agent:codex:agg"));
    assert_eq!(
        rollup_effective_anchor_trust(rows.iter(), &promotions).unwrap(),
        TrustTag::Trusted,
        "promotion lifts the aggregate to Trusted"
    );
    assert_eq!(
        rollup_anchor_trust(rows.iter()).unwrap(),
        TrustTag::Provisional,
        "the promotion-blind catalog rollup never sees the promotion"
    );
    // The persisted agent anchor source is unchanged — trust rose without a rewrite.
    for row in &rows {
        if row.row.kind == AnchorKind::Reward {
            for anchor in &row.row.anchors {
                assert_eq!(anchor.source, "agent:codex:agg");
                assert_eq!(
                    anchor.confidence.to_bits(),
                    AGENT_TASK_REWARD_CONFIDENCE.to_bits()
                );
            }
        }
    }

    // --- Erase the resolved ci source: aggregate recomputes over active rows. ---
    let raw_before = raw_anchor_cf(&vault);
    let erased = erase_anchors_by_source(&vault, "ci:gh:agg", 1_786_500_400, ACTOR)
        .expect("erase ci source");
    assert_eq!(erased.anchors_retracted, 2);
    assert!(erased.tombstone_written);
    let fsv = erased.fsv.as_ref().expect("tombstone earns FSV witness");
    assert_eq!(
        fsv.ledger_seq(),
        erased.ledger_ref.seq,
        "erasure commit carries its paired ledger entry"
    );
    // Original Anchor CF bytes are not rewritten by the append-only tombstone.
    assert_eq!(raw_anchor_cf(&vault), raw_before);
    drop(vault);

    // FSV: reopen; tombstone CF row + paired ledger entry read back independently.
    let reopened = open(dir.as_ref());
    assert_eq!(
        raw_anchor_cf(&reopened),
        raw_before,
        "durable bytes survive"
    );
    let tombstones = read_anchor_tombstones(&reopened).expect("tombstones");
    assert_eq!(tombstones.len(), 1);
    assert_eq!(tombstones[0].source, "ci:gh:agg");
    let ledger_bytes = reopened
        .read_cf_at(
            reopened.snapshot(),
            ColumnFamily::Ledger,
            &ledger_key(erased.ledger_ref.seq),
        )
        .expect("ledger read")
        .expect("paired erasure ledger row present");
    assert!(!ledger_bytes.is_empty(), "erasure ledger entry persisted");
    // The erased ci anchors survive in raw history but are gone from active queries.
    assert!(
        read_all_anchor_rows(&reopened)
            .unwrap()
            .iter()
            .flat_map(|r| &r.row.anchors)
            .any(|a| a.source == "ci:gh:agg"),
        "erased anchors remain in append-only history"
    );
    let active = read_anchor_rows(&reopened).expect("active after erase");
    assert!(
        active
            .iter()
            .flat_map(|r| &r.row.anchors)
            .all(|a| a.source == "agent:codex:agg"),
        "only the promoted agent anchors remain active"
    );
    let promotions = read_anchor_promotions(&reopened).unwrap();
    // Aggregate after erase: active rows are the promoted agent anchors alone =>
    // promotion-aware rollup is Trusted (the promotion is an append-only fact,
    // unaffected by erasing the resolving source), catalog rollup Provisional.
    assert_eq!(
        rollup_effective_anchor_trust(active.iter(), &promotions).unwrap(),
        TrustTag::Trusted
    );
    assert_eq!(
        rollup_anchor_trust(active.iter()).unwrap(),
        TrustTag::Provisional
    );

    // Edge: erase the agent source too => no active anchors => both aggregates
    // fail closed to Provisional (empty evidence is never Trusted).
    let erased_agent = erase_anchors_by_source(&reopened, "agent:codex:agg", 1_786_500_500, ACTOR)
        .expect("erase agent source");
    assert_eq!(erased_agent.anchors_retracted, 2);
    assert_ne!(
        erased.ledger_ref.seq, erased_agent.ledger_ref.seq,
        "each erasure appends its own ledger entry"
    );
    drop(reopened);
    let reopened = open(dir.as_ref());
    let active = read_anchor_rows(&reopened).expect("active after both erased");
    assert!(
        active.is_empty(),
        "both sources erased => no active anchors"
    );
    let promotions = read_anchor_promotions(&reopened).unwrap();
    assert_eq!(
        rollup_effective_anchor_trust(active.iter(), &promotions).unwrap(),
        TrustTag::Provisional
    );
    assert_eq!(
        rollup_anchor_trust(active.iter()).unwrap(),
        TrustTag::Provisional
    );
    drop(reopened);
}

// ---- Opt-in hook contract (scripted harness) ----

#[cfg(windows)]
fn fast_hook() -> (&'static str, Vec<&'static str>) {
    ("cmd", vec!["/C", "exit", "0"])
}
#[cfg(windows)]
fn slow_hook() -> (&'static str, Vec<&'static str>) {
    // ping -n 6 loopback sleeps ~5s without needing an interactive console.
    ("cmd", vec!["/C", "ping", "127.0.0.1", "-n", "6"])
}
#[cfg(not(windows))]
fn fast_hook() -> (&'static str, Vec<&'static str>) {
    ("sh", vec!["-c", "exit 0"])
}
#[cfg(not(windows))]
fn slow_hook() -> (&'static str, Vec<&'static str>) {
    ("sh", vec!["-c", "sleep 5"])
}

#[test]
fn hook_exits_within_budget_never_blocks_and_is_silent_on_timeout() {
    // Fast hook: exits on its own, non-blocking, within budget.
    let (prog, args) = fast_hook();
    let outcome = run_hook_process(prog, args, Duration::from_secs(2));
    assert!(
        !outcome.blocked(),
        "an advisory hook never blocks the agent"
    );
    assert!(
        outcome.completed_ok(),
        "fast hook completes successfully: {outcome:?}"
    );

    // Slow hook: exceeds a tight budget => timed out, silent, and the harness
    // returns near the budget rather than waiting the full sleep.
    let (prog, args) = slow_hook();
    let budget = Duration::from_millis(300);
    let started = Instant::now();
    let outcome = run_hook_process(prog, args, budget);
    let elapsed = started.elapsed();
    assert!(!outcome.blocked(), "timed-out hook still never blocks");
    assert_eq!(
        outcome,
        HookOutcome::TimedOut,
        "over-budget hook is timed out"
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "harness returns near the budget ({elapsed:?}), not the full hook runtime"
    );

    // Launch failure is a silent non-blocking no-op, not an error.
    let missing = run_hook_process(
        "astrolabe-nonexistent-hook-binary-xyz",
        Vec::<&str>::new(),
        Duration::from_secs(1),
    );
    assert!(!missing.blocked());
    assert!(
        missing.launch_failed(),
        "missing hook is a labeled launch failure: {missing:?}"
    );
}
