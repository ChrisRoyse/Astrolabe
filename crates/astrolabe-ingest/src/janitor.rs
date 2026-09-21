//! Always-on FSV janitor runtime lane (#249, the runtime half of #178 DoD item 2).
//!
//! # What this builds on
//!
//! #178 landed the *primitive* for continuous self-verification:
//! [`verify_chain_slice`] re-hashes only the bounded ledger suffix past a
//! persisted [`JanitorCheckpoint`], fails closed at the exact corrupt seq, and is
//! tamper-tested. This module wires the *runtime* that drives that primitive:
//!
//! 1. **Persisted, resumable checkpoint.** The janitor's progress
//!    (`verified_through`) is stored as a real vault row
//!    ([`ColumnFamily::Kv`], [`JANITOR_CHECKPOINT_KEY`]) so it survives a restart
//!    and the lane resumes where it stopped rather than re-walking from genesis.
//! 2. **Ledgered scrub results.** Each non-empty scrub is recorded as an
//!    [`EntryKind::Measure`] ledger entry, and the checkpoint row + that ledger
//!    entry are committed together and then **read back** through the witnessed
//!    [`VaultMutationPlan`] path, so the scrub-progress mutation earns a real
//!    [`FsvAck`] (write-ack-after-readback) exactly like every other Astrolabe
//!    mutation — never an ad-hoc write.
//! 3. **Startup verify.** [`janitor_startup_verify`] re-hashes the whole
//!    persisted chain once at boot and fails closed on any on-disk damage before
//!    the server serves reads.
//!
//! # #96 (no full-ledger rewalk per call)
//!
//! The steady-state lane ([`run_janitor_scrub_step`]) requests only
//! `[checkpoint.verified_through, +budget)` plus one predecessor and an exact
//! durable-head tip check. Each report exposes the actual copied-row and
//! point-read counts. [`janitor_startup_verify`] deliberately repeats those
//! bounded slices from genesis during the one-time boot integrity gate.
//!
//! # Self-observation convergence
//!
//! Each scrub appends its own Measure entry, which grows the ledger tail by one.
//! To keep the lane from chasing its own tail forever, a scrub that catches up to
//! the live tail advances the persisted checkpoint **past** the Measure entry it
//! just wrote — that entry was itself read back and FSV-verified in the same
//! commit, so trusting it is consistent with the transparent-log checkpoint model
//! the primitive already follows (verify the new tail once, trust the verified
//! prefix). A subsequent idle step then verifies nothing and writes nothing,
//! reaching a fixed point instead of emitting an unbounded stream of self-records.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use calyx_aster::cf::ColumnFamily;
use calyx_aster::vault::AsterVault;
use calyx_core::{CalyxError, Clock};
use calyx_ledger::{ActorId, EntryKind, SubjectId};
use serde_json::json;

use crate::fsv::VaultMutationPlan;
use crate::ledger_verify::{JanitorCheckpoint, JanitorSliceReport, verify_chain_slice};
use crate::registry::{IngestError, IngestResult};

use astrolabe_domain::fsv::FsvAck;

/// Fail-closed refusal: the janitor found the persisted ledger chain damaged
/// (broken or corrupt) at a named sequence. The lane persists nothing and does
/// not advance its checkpoint past the damage.
pub const ASTRO_FSV_JANITOR_CHAIN_DAMAGE: &str = "ASTRO_FSV_JANITOR_CHAIN_DAMAGE";
/// Fail-closed refusal: the persisted janitor checkpoint row does not decode.
pub const ASTRO_FSV_JANITOR_CHECKPOINT_CORRUPT: &str = "ASTRO_FSV_JANITOR_CHECKPOINT_CORRUPT";
/// Fail-closed refusal: the requested always-on scrub cadence is outside the
/// declared knob bounds.
pub const ASTRO_FSV_JANITOR_INTERVAL_INVALID: &str = "ASTRO_FSV_JANITOR_INTERVAL_INVALID";
/// Fail-closed refusal: the OS refused to spawn the background janitor thread.
pub const ASTRO_FSV_JANITOR_LANE_SPAWN_FAILED: &str = "ASTRO_FSV_JANITOR_LANE_SPAWN_FAILED";

const CHAIN_DAMAGE_REMEDIATION: &str = "Quarantine the reported ledger sequence, restore or rebuild the vault from source bytes, then restart so the janitor re-verifies from a clean chain.";
const CHECKPOINT_CORRUPT_REMEDIATION: &str = "The persisted FSV janitor checkpoint row is unreadable; delete it (or rebuild the vault) so the janitor resumes from genesis, then restart.";

/// Service actor recorded on every janitor scrub ledger entry.
pub const ASTROLABE_FSV_JANITOR_ACTOR: &str = "astrolabe-fsv-janitor";
/// Schema tag stamped on the janitor scrub's Measure ledger payload.
pub const FSV_JANITOR_SCRUB_LEDGER_SCHEMA: &str = "astrolabe-fsv-janitor-scrub-v2";
/// Ledger subject bytes identifying the janitor scrub series.
const JANITOR_SUBJECT: &[u8] = b"astrolabe:fsv-janitor:scrub";

/// The stable [`ColumnFamily::Kv`] key holding the persisted janitor checkpoint.
///
/// A single global row per vault: the janitor's `verified_through` watermark.
pub const JANITOR_CHECKPOINT_KEY: &[u8] = b"astrolabe:fsv-janitor:checkpoint:v1";

/// The persisted-scrub outcome of a single [`run_janitor_scrub_step`] call.
#[derive(Debug, Clone)]
pub enum JanitorStepReport {
    /// The lane had nothing new to verify: the checkpoint already covers the
    /// live tail. No mutation was made and no ledger entry was written — a
    /// labeled no-op, never a silent success.
    CaughtUp {
        /// The checkpoint (unchanged) after this idle step.
        checkpoint: JanitorCheckpoint,
    },
    /// The lane verified a non-empty bounded slice, persisted the advanced
    /// checkpoint, and ledgered the scrub as a witnessed Measure entry.
    Scrubbed {
        /// The bounded slice this step re-hashed. Boxed to keep the enum small,
        /// since the idle [`Self::CaughtUp`] variant is by far the common case.
        slice: Box<JanitorSliceReport>,
        /// The checkpoint persisted by this step.
        checkpoint: JanitorCheckpoint,
        /// The write-ack proving the checkpoint row + Measure entry were read
        /// back byte-identical from the committed snapshot.
        ack: Box<FsvAck>,
    },
}

impl JanitorStepReport {
    /// The persisted checkpoint after this step, whether idle or scrubbing.
    pub fn checkpoint(&self) -> JanitorCheckpoint {
        match self {
            Self::CaughtUp { checkpoint } | Self::Scrubbed { checkpoint, .. } => *checkpoint,
        }
    }

    /// True when this step performed and ledgered a scrub.
    pub fn scrubbed(&self) -> bool {
        matches!(self, Self::Scrubbed { .. })
    }
}

/// Reads the persisted janitor checkpoint from the vault, or [`JanitorCheckpoint::GENESIS`]
/// when the lane has never run against this vault.
///
/// This is an independent readback against the [`ColumnFamily::Kv`] row — the same
/// read the lane uses to resume after a restart.
///
/// # Errors
///
/// Fails closed with [`ASTRO_FSV_JANITOR_CHECKPOINT_CORRUPT`] if the persisted row
/// exists but does not decode, rather than silently resuming from genesis and
/// re-doing (or worse, skipping) verification.
pub fn read_janitor_checkpoint<C>(vault: &AsterVault<C>) -> IngestResult<JanitorCheckpoint>
where
    C: Clock,
{
    match vault.read_cf_at(vault.latest_seq(), ColumnFamily::Kv, JANITOR_CHECKPOINT_KEY)? {
        Some(bytes) => serde_json::from_slice::<JanitorCheckpoint>(&bytes).map_err(|error| {
            IngestError::refused(
                ASTRO_FSV_JANITOR_CHECKPOINT_CORRUPT,
                format!(
                    "persisted FSV janitor checkpoint ({} bytes) does not decode: {error}",
                    bytes.len()
                ),
                CHECKPOINT_CORRUPT_REMEDIATION,
            )
        }),
        None => Ok(JanitorCheckpoint::GENESIS),
    }
}

/// Runs one bounded janitor scrub step against the persisted ledger.
///
/// Loads the persisted checkpoint, re-hashes the bounded suffix past it
/// ([`verify_chain_slice`], budget = the registry knob unless `budget_override`
/// narrows/widens it within the declared bounds), and:
///
/// - **damage** → fails closed with [`ASTRO_FSV_JANITOR_CHAIN_DAMAGE`] naming the
///   exact seq; persists nothing and does not advance the checkpoint;
/// - **nothing new** → returns [`JanitorStepReport::CaughtUp`] with no mutation;
/// - **a non-empty verified slice** → commits the advanced checkpoint row plus a
///   Measure ledger entry in one group commit, reads both back through
///   [`VaultMutationPlan::verify_committed_with_ledger_ref`], and returns the
///   resulting [`FsvAck`].
///
/// # Errors
///
/// Propagates the fail-closed refusals above, an invalid budget knob
/// ([`crate::ASTRO_FSV_JANITOR_BUDGET_INVALID`]), or a store/ledger error.
pub fn run_janitor_scrub_step<C>(
    vault: &AsterVault<C>,
    budget_override: Option<u64>,
) -> IngestResult<JanitorStepReport>
where
    C: Clock,
{
    let checkpoint = read_janitor_checkpoint(vault)?;
    let slice = verify_chain_slice(vault, checkpoint, budget_override)?;
    if !slice.is_intact() {
        return Err(chain_damage_error(&slice));
    }
    if slice.entries_verified == 0 {
        // Caught up to the live tail: no work, no mutation, no ledger entry.
        return Ok(JanitorStepReport::CaughtUp {
            checkpoint: slice.checkpoint,
        });
    }

    // A scrub appends exactly one Measure entry at the current tail. When this
    // slice reached the live tail, that new entry (read back and FSV-verified in
    // this same commit) is trusted, so the checkpoint advances past it and the
    // next step is idle; otherwise the checkpoint advances only to the verified
    // data range and later steps continue draining the remaining real tail.
    let new_checkpoint = if slice.caught_up {
        JanitorCheckpoint {
            verified_through: slice.slice_end.checked_add(1).ok_or_else(|| {
                CalyxError::ledger_corrupt("FSV janitor checkpoint overflow after scrub append")
            })?,
        }
    } else {
        JanitorCheckpoint {
            verified_through: slice.slice_end,
        }
    };

    let checkpoint_bytes = serde_json::to_vec(&new_checkpoint)?;
    let subject = SubjectId::Query(JANITOR_SUBJECT.to_vec());
    let actor = ActorId::Service(ASTROLABE_FSV_JANITOR_ACTOR.to_string());
    let payload = scrub_ledger_payload(&slice, &new_checkpoint)?;

    // Build the FSV plan from the exact checkpoint row the commit will persist,
    // before committing, so verification re-reads persisted bytes rather than the
    // write set. The paired Measure ledger entry is the scrub record itself.
    let mut plan =
        VaultMutationPlan::new("fsv_janitor_scrub", EntryKind::Measure, &actor, &subject);
    plan.push_content(
        ColumnFamily::Kv,
        JANITOR_CHECKPOINT_KEY.to_vec(),
        &checkpoint_bytes,
    );

    let (commit_seq, ledger_ref) = vault.write_cf_batch_with_ledger_entry_if_seq(
        slice.snapshot_seq,
        [(
            ColumnFamily::Kv,
            JANITOR_CHECKPOINT_KEY.to_vec(),
            checkpoint_bytes,
        )],
        EntryKind::Measure,
        subject,
        payload,
        actor,
    )?;

    // Write-ack-after-readback: re-read the persisted checkpoint row and the
    // paired Measure entry at the commit snapshot. Any divergence fails closed
    // and the step never reports a scrub.
    let ack = plan.verify_committed_with_ledger_ref(vault, commit_seq, &ledger_ref)?;

    Ok(JanitorStepReport::Scrubbed {
        slice: Box::new(slice),
        checkpoint: new_checkpoint,
        ack: Box::new(ack),
    })
}

/// One-time boot integrity gate: re-hashes the whole persisted ledger chain from
/// genesis in bounded slices and fails closed on the first damaged slice.
///
/// This is read-only — it makes no mutation and writes no ledger entry — and is
/// the deliberate one-time full sweep that the steady-state lane
/// ([`run_janitor_scrub_step`]) never performs (#96). Run it at startup before
/// serving reads; a clean return proves the persisted chain re-hashes end to end.
///
/// # Errors
///
/// Fails closed with [`ASTRO_FSV_JANITOR_CHAIN_DAMAGE`] naming the exact bad seq
/// on any broken/corrupt slice.
pub fn janitor_startup_verify<C>(
    vault: &AsterVault<C>,
    budget_override: Option<u64>,
) -> IngestResult<JanitorSliceReport>
where
    C: Clock,
{
    let mut checkpoint = JanitorCheckpoint::GENESIS;
    loop {
        let slice = verify_chain_slice(vault, checkpoint, budget_override)?;
        if !slice.is_intact() {
            return Err(chain_damage_error(&slice));
        }
        if slice.caught_up {
            return Ok(slice);
        }
        checkpoint = slice.checkpoint;
    }
}

fn chain_damage_error(slice: &JanitorSliceReport) -> IngestError {
    IngestError::refused(
        ASTRO_FSV_JANITOR_CHAIN_DAMAGE,
        format!(
            "FSV janitor: ledger chain {} at seq {} in slice [{}, {}) of the {} CF{}",
            slice.status,
            slice.at_seq.unwrap_or_default(),
            slice.slice_start,
            slice.slice_end,
            ColumnFamily::Ledger.name(),
            slice
                .reason
                .as_ref()
                .map(|reason| format!("; reason: {reason}"))
                .unwrap_or_default(),
        ),
        CHAIN_DAMAGE_REMEDIATION,
    )
}

fn scrub_ledger_payload(
    slice: &JanitorSliceReport,
    checkpoint: &JanitorCheckpoint,
) -> IngestResult<Vec<u8>> {
    // Counts and sequence bounds only: the scrub record describes verification
    // coverage without duplicating the payload bytes it verified.
    Ok(serde_json::to_vec(&json!({
        "schema": FSV_JANITOR_SCRUB_LEDGER_SCHEMA,
        "status": slice.status,
        "slice_start": slice.slice_start,
        "slice_end": slice.slice_end,
        "entries_verified": slice.entries_verified,
        "snapshot_seq": slice.snapshot_seq,
        "ledger_head_height": slice.ledger_head_height,
        "ledger_head_tip_hash": slice.ledger_head_tip_hash,
        "range_rows_copied": slice.range_rows_copied,
        "predecessor_copied": slice.predecessor_copied,
        "tip_point_read": slice.tip_point_read,
        "verified_through": checkpoint.verified_through,
        "caught_up": slice.caught_up,
    }))?)
}

const INTERVAL_INVALID_REMEDIATION: &str = "Set the janitor scrub interval inside the declared FSV knob bounds, or use JanitorLaneConfig::from_registry_defaults() for the declared default cadence.";
const LANE_SPAWN_REMEDIATION: &str = "The OS refused a new thread for the always-on FSV janitor; free thread resources or lower concurrency, then restart the lane.";

/// Registry-declared configuration for the always-on [`JanitorLane`].
///
/// Both tunables are declared FSV knobs (standing invariant 4): the scrub cadence
/// is [`astrolabe_domain::knobs::FSV_JANITOR_SCRUB_INTERVAL_MS_KNOB`] and the
/// per-slice ledger-entry budget is
/// [`astrolabe_domain::knobs::FSV_JANITOR_LEDGER_ENTRIES_PER_SLICE_KNOB`].
#[derive(Debug, Clone)]
pub struct JanitorLaneConfig {
    /// Sleep between bounded scrub slices.
    scrub_interval: Duration,
    /// Per-slice ledger-entry budget override; `None` uses the registry default.
    budget_override: Option<u64>,
    /// Run a one-time [`janitor_startup_verify`] boot sweep before the lane
    /// starts; a damaged chain refuses the spawn (fail closed at boot).
    startup_verify: bool,
}

impl JanitorLaneConfig {
    /// The declared-default configuration: default cadence, default per-slice
    /// budget, and the startup boot-verify hook enabled.
    #[must_use]
    pub fn from_registry_defaults() -> Self {
        Self {
            scrub_interval: Duration::from_millis(
                astrolabe_domain::knobs::FSV_DEFAULT_JANITOR_SCRUB_INTERVAL_MS,
            ),
            budget_override: None,
            startup_verify: true,
        }
    }

    /// Sets the scrub cadence from a millisecond value validated against the
    /// declared knob bounds.
    ///
    /// # Errors
    ///
    /// [`ASTRO_FSV_JANITOR_INTERVAL_INVALID`] when `interval_ms` is outside the
    /// declared bounds.
    pub fn with_interval_ms(mut self, interval_ms: u64) -> IngestResult<Self> {
        let knob = astrolabe_domain::knobs::fsv_knob(
            astrolabe_domain::knobs::FSV_JANITOR_SCRUB_INTERVAL_MS_KNOB,
        )
        .expect("janitor scrub-interval knob is declared in the FSV knob registry");
        if !knob.accepts(interval_ms) {
            return Err(IngestError::refused(
                ASTRO_FSV_JANITOR_INTERVAL_INVALID,
                format!(
                    "janitor scrub interval {interval_ms}ms is outside the declared knob bounds [{}, {}]",
                    knob.min, knob.max
                ),
                INTERVAL_INVALID_REMEDIATION,
            ));
        }
        self.scrub_interval = Duration::from_millis(interval_ms);
        Ok(self)
    }

    /// Narrows or widens the per-slice ledger-entry budget; `run_janitor_scrub_step`
    /// validates it against the declared knob bounds on every step.
    #[must_use]
    pub fn with_budget_override(mut self, budget: Option<u64>) -> Self {
        self.budget_override = budget;
        self
    }

    /// Enables or disables the one-time startup boot-verify hook.
    #[must_use]
    pub fn with_startup_verify(mut self, enabled: bool) -> Self {
        self.startup_verify = enabled;
        self
    }
}

/// A snapshot of the always-on lane's runtime state, suitable for surfacing in a
/// server status envelope (e.g. `index_status`).
///
/// Every field is a labeled fact, never a bare green flag: a halted lane names the
/// exact refusal that stopped it, so the server surface can report *why*
/// self-verification stopped rather than a silent "not running".
#[derive(Debug, Clone)]
pub struct JanitorLaneState {
    /// Total scrub steps the lane has completed (idle or scrubbing).
    pub steps_run: u64,
    /// Steps that verified a non-empty slice and ledgered a witnessed scrub.
    pub scrubs_committed: u64,
    /// The persisted checkpoint watermark after the most recent step.
    pub last_checkpoint: JanitorCheckpoint,
    /// True once the lane stopped itself because a step failed closed; it makes
    /// no further mutations until restarted against a repaired store.
    pub halted: bool,
    /// The refusal code that halted the lane, if any (e.g.
    /// [`ASTRO_FSV_JANITOR_CHAIN_DAMAGE`]).
    pub halt_code: Option<String>,
    /// The human-readable message of the halting refusal, if any.
    pub halt_message: Option<String>,
}

impl JanitorLaneState {
    fn genesis() -> Self {
        Self {
            steps_run: 0,
            scrubs_committed: 0,
            last_checkpoint: JanitorCheckpoint::GENESIS,
            halted: false,
            halt_code: None,
            halt_message: None,
        }
    }

    /// True while the lane is running and has not failed closed.
    #[must_use]
    pub fn healthy(&self) -> bool {
        !self.halted
    }
}

/// The always-on FSV janitor lane: a background thread that repeatedly runs a
/// bounded [`run_janitor_scrub_step`] on the registry-declared cadence, so the
/// store continuously re-verifies its own persisted ledger without any external
/// harness (#178 DoD item 2, runtime half).
///
/// The lane is **fail-closed**: the first step that returns a structured refusal
/// (chain damage, corrupt checkpoint, ...) stops the lane, records the exact
/// code/message in [`JanitorLaneState`], and makes no further mutation — it never
/// spins on a persistent fault and never silently continues past damage.
///
/// Dropping the lane (or calling [`JanitorLane::stop`]) signals the thread and
/// joins it, so no scrub thread outlives its handle.
#[derive(Debug)]
pub struct JanitorLane {
    stop: Arc<AtomicBool>,
    steps: Arc<AtomicU64>,
    state: Arc<Mutex<JanitorLaneState>>,
    handle: Option<JoinHandle<()>>,
}

impl JanitorLane {
    /// Spawns the background scrub lane against a shared vault.
    ///
    /// When `config.startup_verify` is set, a one-time [`janitor_startup_verify`]
    /// boot sweep runs synchronously first; a damaged chain refuses the spawn
    /// (returns the refusal and spawns no thread) so the lane never begins
    /// serving atop an already-corrupt store.
    ///
    /// # Errors
    ///
    /// Propagates a startup boot-verify refusal (e.g.
    /// [`ASTRO_FSV_JANITOR_CHAIN_DAMAGE`]) when the hook is enabled and the
    /// persisted chain is damaged, or [`ASTRO_FSV_JANITOR_LANE_SPAWN_FAILED`] if
    /// the OS refuses the thread.
    pub fn spawn<C>(vault: Arc<AsterVault<C>>, config: JanitorLaneConfig) -> IngestResult<Self>
    where
        C: Clock + Send + Sync + 'static,
    {
        if config.startup_verify {
            // Fail closed at boot: a corrupt persisted chain refuses the spawn.
            janitor_startup_verify(vault.as_ref(), config.budget_override)?;
        }

        let stop = Arc::new(AtomicBool::new(false));
        let steps = Arc::new(AtomicU64::new(0));
        let state = Arc::new(Mutex::new(JanitorLaneState::genesis()));

        let thread_stop = Arc::clone(&stop);
        let thread_steps = Arc::clone(&steps);
        let thread_state = Arc::clone(&state);
        let interval = config.scrub_interval;
        let budget = config.budget_override;

        let handle = std::thread::Builder::new()
            .name("astrolabe-fsv-janitor".to_string())
            .spawn(move || {
                lane_loop(
                    &vault,
                    &thread_stop,
                    &thread_steps,
                    &thread_state,
                    interval,
                    budget,
                );
            })
            .map_err(|error| {
                IngestError::refused(
                    ASTRO_FSV_JANITOR_LANE_SPAWN_FAILED,
                    format!("could not spawn the FSV janitor lane thread: {error}"),
                    LANE_SPAWN_REMEDIATION,
                )
            })?;

        Ok(Self {
            stop,
            steps,
            state,
            handle: Some(handle),
        })
    }

    /// Returns a snapshot of the lane's current runtime state.
    #[must_use]
    pub fn state(&self) -> JanitorLaneState {
        self.state.lock().expect("janitor lane state mutex").clone()
    }

    /// Returns the total number of scrub steps completed so far (idle or
    /// scrubbing). Monotonic; usable to wait for the lane to make progress.
    #[must_use]
    pub fn steps_completed(&self) -> u64 {
        self.steps.load(Ordering::Acquire)
    }

    /// Blocks until the lane has completed at least `target` steps or `timeout`
    /// elapses. Returns true if the step count was reached.
    pub fn wait_for_steps(&self, target: u64, timeout: Duration) -> bool {
        wait_until(timeout, || self.steps_completed() >= target)
    }

    /// Blocks until the lane has committed at least `target` witnessed scrubs or
    /// `timeout` elapses. Returns true if the scrub count was reached.
    pub fn wait_for_scrubs(&self, target: u64, timeout: Duration) -> bool {
        wait_until(timeout, || self.state().scrubs_committed >= target)
    }

    /// Blocks until the lane has halted fail-closed or `timeout` elapses. Returns
    /// true if the lane halted.
    pub fn wait_for_halt(&self, timeout: Duration) -> bool {
        wait_until(timeout, || self.state().halted)
    }

    /// Signals the background thread to stop and joins it. Idempotent.
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for JanitorLane {
    fn drop(&mut self) {
        self.stop();
    }
}

fn lane_loop<C>(
    vault: &AsterVault<C>,
    stop: &AtomicBool,
    steps: &AtomicU64,
    state: &Mutex<JanitorLaneState>,
    interval: Duration,
    budget: Option<u64>,
) where
    C: Clock,
{
    while !stop.load(Ordering::Acquire) {
        match run_janitor_scrub_step(vault, budget) {
            Ok(report) => {
                {
                    let mut guard = state.lock().expect("janitor lane state mutex");
                    guard.steps_run += 1;
                    if report.scrubbed() {
                        guard.scrubs_committed += 1;
                    }
                    guard.last_checkpoint = report.checkpoint();
                }
                steps.fetch_add(1, Ordering::Release);
            }
            Err(error) => {
                // Fail closed: record the exact refusal and stop the lane. It
                // makes no further mutation until restarted against a repaired
                // store — never a spin on a persistent fault.
                {
                    let mut guard = state.lock().expect("janitor lane state mutex");
                    guard.steps_run += 1;
                    guard.halted = true;
                    guard.halt_code = error.code().map(str::to_string);
                    guard.halt_message = Some(error.to_string());
                }
                steps.fetch_add(1, Ordering::Release);
                return;
            }
        }
        sleep_interruptible(stop, interval);
    }
}

/// Sleeps up to `interval`, waking early to observe a stop signal so shutdown
/// stays responsive regardless of the configured cadence.
fn sleep_interruptible(stop: &AtomicBool, interval: Duration) {
    const SLICE: Duration = Duration::from_millis(20);
    let deadline = Instant::now() + interval;
    while Instant::now() < deadline {
        if stop.load(Ordering::Acquire) {
            return;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        std::thread::sleep(remaining.min(SLICE));
    }
}

fn wait_until(timeout: Duration, mut done: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if done() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}
