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
//! The steady-state lane ([`run_janitor_scrub_step`]) never re-walks the whole
//! ledger: it verifies only `[checkpoint.verified_through, +budget)` per call, so
//! its per-call cost is bounded by the registry knob, not by ledger height. The
//! one deliberate full sweep is [`janitor_startup_verify`], a **one-time** boot
//! integrity gate — not a per-call cost of the running lane.
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
use calyx_core::Clock;
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
pub const FSV_JANITOR_SCRUB_LEDGER_SCHEMA: &str = "astrolabe-fsv-janitor-scrub-v1";
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
///   [`VaultMutationPlan::verify_committed`], and returns the resulting
///   [`FsvAck`].
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
            verified_through: slice.slice_end.saturating_add(1),
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

    vault.write_cf_batch_with_ledger_entry(
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
    let ack = plan.verify_committed(vault, vault.latest_seq())?;

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
    // Counts and sequence bounds only — never any ledger payload bytes — so the
    // scrub record can never re-embed a secret from the entries it verified.
    Ok(serde_json::to_vec(&json!({
        "schema": FSV_JANITOR_SCRUB_LEDGER_SCHEMA,
        "status": slice.status,
        "slice_start": slice.slice_start,
        "slice_end": slice.slice_end,
        "entries_verified": slice.entries_verified,
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

#[cfg(test)]
mod tests {
    use super::*;
    use calyx_aster::cf::ledger_key;
    use calyx_aster::vault::{AsterVault, VaultOptions};
    use calyx_core::{FixedClock, VaultId};
    use calyx_ledger::{ActorId, EntryKind, SubjectId, decode};
    use std::fs;
    use std::path::PathBuf;

    fn vault_id() -> VaultId {
        "01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().expect("vault id")
    }

    fn mem_vault() -> AsterVault<FixedClock> {
        AsterVault::with_clock(vault_id(), b"fsv-janitor-test", FixedClock::new(7))
    }

    fn test_dir(name: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "astrolabe-fsv-janitor-{name}-{}",
            std::process::id()
        ));
        fs::remove_dir_all(&dir).ok();
        dir
    }

    fn append_entry<C: Clock>(vault: &AsterVault<C>, subject: &[u8]) {
        vault
            .append_ledger_entry(
                EntryKind::Ingest,
                SubjectId::Query(subject.to_vec()),
                br#"{"schema":"fsv-janitor-test-ledger-v1"}"#.to_vec(),
                ActorId::Service("astrolabe-test".to_string()),
            )
            .expect("append ledger entry");
    }

    /// The persisted checkpoint is absent before the lane runs and becomes the
    /// live-tail height after it catches up — read back independently.
    #[test]
    fn scrub_persists_checkpoint_and_ledgers_measure_entry() {
        let vault = mem_vault();
        for index in 0..4 {
            append_entry(&vault, format!("entry-{index}").as_bytes());
        }
        // No janitor row yet: resume defaults to genesis.
        assert_eq!(
            read_janitor_checkpoint(&vault).expect("read genesis checkpoint"),
            JanitorCheckpoint::GENESIS
        );

        let step = run_janitor_scrub_step(&vault, Some(16)).expect("scrub step");
        let JanitorStepReport::Scrubbed { slice, ack, .. } = &step else {
            panic!("expected a scrub, got {step:?}");
        };
        // Verified all four real entries [0,4); the Measure entry lands at seq 4,
        // so the checkpoint advances past it to 5.
        assert_eq!(slice.slice_start, 0);
        assert_eq!(slice.slice_end, 4);
        assert_eq!(slice.entries_verified, 4);
        assert_eq!(ack.label(), astrolabe_domain::fsv::FSV_LABEL_VERIFIED);
        assert_eq!(ack.rows_read_back(), 1);

        // Independent readback of the persisted checkpoint row.
        let persisted = read_janitor_checkpoint(&vault).expect("read persisted checkpoint");
        assert_eq!(persisted.verified_through, 5);

        // Independent readback proving a Measure entry with the janitor schema was
        // persisted to the ledger.
        let measure = newest_measure_scrub(&vault);
        assert_eq!(
            measure.get("schema").and_then(|v| v.as_str()),
            Some(FSV_JANITOR_SCRUB_LEDGER_SCHEMA)
        );
        assert_eq!(
            measure.get("entries_verified").and_then(|v| v.as_u64()),
            Some(4)
        );

        // A second step is idle: nothing new to verify, no further mutation.
        let idle = run_janitor_scrub_step(&vault, Some(16)).expect("idle step");
        assert!(!idle.scrubbed(), "expected idle, got {idle:?}");
        assert_eq!(idle.checkpoint().verified_through, 5);
    }

    /// FSV restart: persist the checkpoint on a durable vault, drop it (simulating
    /// a kill), reopen, and prove the persisted checkpoint row survived so the
    /// lane resumes where it stopped — read back from disk, not from an API echo.
    #[test]
    fn checkpoint_survives_restart_and_resumes() {
        let dir = test_dir("restart");
        fs::create_dir_all(&dir).expect("create durable vault dir");

        let persisted_through;
        {
            let vault = AsterVault::new_durable(
                &dir,
                vault_id(),
                b"fsv-janitor-restart",
                VaultOptions::default(),
            )
            .expect("open durable vault");
            for index in 0..5 {
                append_entry(&vault, format!("entry-{index}").as_bytes());
            }
            let step = run_janitor_scrub_step(&vault, Some(3)).expect("bounded scrub step");
            // Budget 3 over 5 real entries: not caught up, checkpoint = slice_end = 3.
            assert!(step.scrubbed());
            persisted_through = step.checkpoint().verified_through;
            assert_eq!(persisted_through, 3);
            vault.flush().expect("flush durable vault");
        } // vault dropped: simulates a mid-scrub kill.

        // Reopen the same directory and read the checkpoint back from disk.
        let reopened = AsterVault::new_durable(
            &dir,
            vault_id(),
            b"fsv-janitor-restart",
            VaultOptions::default(),
        )
        .expect("reopen durable vault");
        let resumed = read_janitor_checkpoint(&reopened).expect("read checkpoint after restart");
        assert_eq!(
            resumed.verified_through, persisted_through,
            "checkpoint must survive restart byte-identical"
        );

        // Resume: the next step continues from the persisted point (does not
        // re-verify [0,3)) and drains the rest of the tail.
        let resume = run_janitor_scrub_step(&reopened, Some(3)).expect("resume scrub step");
        if let JanitorStepReport::Scrubbed { slice, .. } = &resume {
            assert_eq!(
                slice.slice_start, 3,
                "must resume at the persisted checkpoint"
            );
        } else {
            panic!("expected a resuming scrub, got {resume:?}");
        }

        fs::remove_dir_all(&dir).ok();
    }

    /// Startup verify re-hashes the whole chain and fails closed at the exact seq
    /// of a seeded on-disk corruption (tamper-negative).
    #[test]
    fn startup_verify_fails_closed_on_tampered_ledger_at_exact_seq() {
        let vault = mem_vault();
        for index in 0..6 {
            append_entry(&vault, format!("entry-{index}").as_bytes());
        }
        // Clean chain verifies end to end.
        let clean = janitor_startup_verify(&vault, Some(4)).expect("clean startup verify");
        assert!(clean.is_intact());

        // Independent readback + one-byte flip of a persisted ledger row.
        let mut tampered = vault
            .read_cf_at(vault.latest_seq(), ColumnFamily::Ledger, &ledger_key(3))
            .expect("read persisted ledger row")
            .expect("ledger row 3 exists");
        tampered[18] ^= 0xff;
        vault
            .write_cf(ColumnFamily::Ledger, ledger_key(3), tampered)
            .expect("persist tampered ledger row");

        let err = janitor_startup_verify(&vault, Some(4))
            .expect_err("startup verify must fail closed on tamper");
        assert_eq!(err.code(), Some(ASTRO_FSV_JANITOR_CHAIN_DAMAGE));
        assert!(err.to_string().contains("seq 3"), "{err}");
    }

    /// The steady-state lane never re-walks the whole ledger: a single step
    /// verifies at most `budget` entries regardless of ledger height (#96).
    #[test]
    fn scrub_step_respects_budget_and_never_full_rewalks() {
        let vault = mem_vault();
        for index in 0..50 {
            append_entry(&vault, format!("entry-{index}").as_bytes());
        }
        let step = run_janitor_scrub_step(&vault, Some(4)).expect("bounded scrub step");
        if let JanitorStepReport::Scrubbed { slice, .. } = &step {
            assert!(
                slice.entries_verified <= 4,
                "one step must not exceed the budget: {slice:?}"
            );
            assert_eq!(slice.slice_end, 4);
        } else {
            panic!("expected a bounded scrub, got {step:?}");
        }
    }

    /// A corrupt persisted checkpoint row fails closed rather than silently
    /// resuming from genesis.
    #[test]
    fn corrupt_checkpoint_row_fails_closed() {
        let vault = mem_vault();
        append_entry(&vault, b"entry");
        vault
            .write_cf(
                ColumnFamily::Kv,
                JANITOR_CHECKPOINT_KEY.to_vec(),
                b"not-json".to_vec(),
            )
            .expect("persist corrupt checkpoint row");
        let err = read_janitor_checkpoint(&vault).expect_err("corrupt checkpoint must refuse");
        assert_eq!(err.code(), Some(ASTRO_FSV_JANITOR_CHECKPOINT_CORRUPT));
    }

    /// Empty ledger: startup verify and a scrub step both no-op cleanly.
    #[test]
    fn empty_ledger_is_caught_up() {
        let vault = mem_vault();
        let startup = janitor_startup_verify(&vault, Some(4)).expect("startup on empty ledger");
        assert!(startup.caught_up);
        let step = run_janitor_scrub_step(&vault, Some(4)).expect("step on empty ledger");
        assert!(!step.scrubbed());
        assert_eq!(step.checkpoint(), JanitorCheckpoint::GENESIS);
    }

    /// The always-on background lane runs real scrub ticks, and the checkpoint it
    /// advanced survives a durable drop+reopen — read back from disk bytes, not
    /// from the running lane's in-memory state (#178 DoD item 2, runtime half).
    #[test]
    fn background_lane_persists_checkpoint_after_scrub_tick() {
        let dir = test_dir("lane-persist");
        fs::create_dir_all(&dir).expect("create durable vault dir");

        {
            let vault = AsterVault::new_durable(
                &dir,
                vault_id(),
                b"fsv-janitor-lane",
                VaultOptions::default(),
            )
            .expect("open durable vault");
            for index in 0..4 {
                append_entry(&vault, format!("entry-{index}").as_bytes());
            }
            let vault = Arc::new(vault);

            let config = JanitorLaneConfig::from_registry_defaults()
                .with_budget_override(Some(16))
                .with_interval_ms(1)
                .expect("1ms cadence is inside the declared knob bounds");
            let mut lane = JanitorLane::spawn(Arc::clone(&vault), config).expect("spawn lane");

            assert!(
                lane.wait_for_scrubs(1, Duration::from_secs(5)),
                "lane must commit at least one witnessed scrub"
            );
            let observed = lane.state();
            assert!(observed.scrubs_committed >= 1);
            // Four real entries [0,4); the Measure entry lands at seq 4, so the
            // checkpoint advances past it to 5 and the lane then goes idle.
            assert_eq!(observed.last_checkpoint.verified_through, 5);
            assert!(observed.healthy(), "clean chain must not halt the lane");

            lane.stop();
            vault.flush().expect("flush durable vault");
        } // lane joined, all vault handles dropped: simulates process exit.

        // Reopen the same directory and read the checkpoint back from disk.
        let reopened = AsterVault::new_durable(
            &dir,
            vault_id(),
            b"fsv-janitor-lane",
            VaultOptions::default(),
        )
        .expect("reopen durable vault");
        let persisted =
            read_janitor_checkpoint(&reopened).expect("read persisted checkpoint after lane run");
        assert_eq!(
            persisted.verified_through, 5,
            "the background lane's checkpoint must survive restart byte-identical"
        );

        fs::remove_dir_all(&dir).ok();
    }

    /// A running lane that meets on-disk chain damage halts fail-closed: it names
    /// the exact refusal, stops mutating, and never advances its checkpoint past
    /// the damage (#178 DoD item 2, fail-closed runtime).
    #[test]
    fn background_lane_halts_fail_closed_on_chain_damage() {
        let vault = mem_vault();
        for index in 0..6 {
            append_entry(&vault, format!("entry-{index}").as_bytes());
        }
        // One-byte flip of a persisted ledger row (independent readback + rewrite).
        let mut tampered = vault
            .read_cf_at(vault.latest_seq(), ColumnFamily::Ledger, &ledger_key(3))
            .expect("read persisted ledger row")
            .expect("ledger row 3 exists");
        tampered[18] ^= 0xff;
        vault
            .write_cf(ColumnFamily::Ledger, ledger_key(3), tampered)
            .expect("persist tampered ledger row");

        let vault = Arc::new(vault);
        // startup_verify disabled so the lane starts and meets the damage inside a
        // running step, proving the runtime loop (not just the boot hook) halts.
        let config = JanitorLaneConfig::from_registry_defaults()
            .with_startup_verify(false)
            .with_budget_override(Some(4))
            .with_interval_ms(1)
            .expect("1ms cadence inside bounds");
        let lane = JanitorLane::spawn(Arc::clone(&vault), config).expect("spawn lane");

        assert!(
            lane.wait_for_halt(Duration::from_secs(5)),
            "lane must halt on chain damage"
        );
        let state = lane.state();
        assert!(!state.healthy());
        assert_eq!(
            state.halt_code.as_deref(),
            Some(ASTRO_FSV_JANITOR_CHAIN_DAMAGE)
        );
        assert!(
            state
                .halt_message
                .as_deref()
                .unwrap_or_default()
                .contains("seq 3"),
            "halt message must name the damaged seq: {:?}",
            state.halt_message
        );

        // Fail-closed: the checkpoint never advanced past the damage.
        let checkpoint = read_janitor_checkpoint(&vault).expect("read checkpoint");
        assert_eq!(checkpoint, JanitorCheckpoint::GENESIS);
    }

    /// The startup boot-verify hook detects a byte-corrupted persisted ledger and
    /// refuses to start the lane (fail closed at boot; no thread spawned, no
    /// mutation).
    #[test]
    fn startup_verify_hook_refuses_boot_on_tampered_artifact() {
        let vault = mem_vault();
        for index in 0..6 {
            append_entry(&vault, format!("entry-{index}").as_bytes());
        }
        let mut tampered = vault
            .read_cf_at(vault.latest_seq(), ColumnFamily::Ledger, &ledger_key(2))
            .expect("read persisted ledger row")
            .expect("ledger row 2 exists");
        tampered[18] ^= 0xff;
        vault
            .write_cf(ColumnFamily::Ledger, ledger_key(2), tampered)
            .expect("persist tampered ledger row");

        let vault = Arc::new(vault);
        // startup_verify defaults to true.
        let config = JanitorLaneConfig::from_registry_defaults().with_budget_override(Some(4));
        let err = JanitorLane::spawn(Arc::clone(&vault), config)
            .expect_err("boot hook must refuse a corrupt chain");
        assert_eq!(err.code(), Some(ASTRO_FSV_JANITOR_CHAIN_DAMAGE));
        assert!(err.to_string().contains("seq 2"), "{err}");
        // No lane started, so no mutation occurred: checkpoint stays at genesis.
        assert_eq!(
            read_janitor_checkpoint(&vault).expect("read checkpoint"),
            JanitorCheckpoint::GENESIS
        );
    }

    /// A lane over a clean chain runs multiple steps, stays healthy, and stops+
    /// joins cleanly (idempotent stop, no leaked thread).
    #[test]
    fn background_lane_runs_and_stops_cleanly() {
        let vault = mem_vault();
        for index in 0..3 {
            append_entry(&vault, format!("entry-{index}").as_bytes());
        }
        let vault = Arc::new(vault);
        let config = JanitorLaneConfig::from_registry_defaults()
            .with_budget_override(Some(8))
            .with_interval_ms(1)
            .expect("1ms cadence inside bounds");
        let mut lane = JanitorLane::spawn(Arc::clone(&vault), config).expect("spawn lane");

        assert!(
            lane.wait_for_steps(2, Duration::from_secs(5)),
            "lane must complete multiple steps"
        );
        assert!(lane.state().healthy());
        assert!(lane.steps_completed() >= 2);
        lane.stop();
        // Idempotent: a second stop is a no-op.
        lane.stop();
    }

    /// The scrub cadence is a registry-declared knob: an out-of-bounds interval is
    /// refused, and the declared default is accepted (standing invariant 4).
    #[test]
    fn janitor_scrub_interval_outside_knob_bounds_is_refused() {
        let err = JanitorLaneConfig::from_registry_defaults()
            .with_interval_ms(0)
            .expect_err("zero cadence must refuse");
        assert_eq!(err.code(), Some(ASTRO_FSV_JANITOR_INTERVAL_INVALID));

        let too_big = JanitorLaneConfig::from_registry_defaults()
            .with_interval_ms(astrolabe_domain::knobs::FSV_MAX_JANITOR_SCRUB_INTERVAL_MS + 1)
            .expect_err("above-max cadence must refuse");
        assert_eq!(too_big.code(), Some(ASTRO_FSV_JANITOR_INTERVAL_INVALID));

        JanitorLaneConfig::from_registry_defaults()
            .with_interval_ms(astrolabe_domain::knobs::FSV_DEFAULT_JANITOR_SCRUB_INTERVAL_MS)
            .expect("the declared default cadence is accepted");
    }

    fn newest_measure_scrub<C: Clock>(vault: &AsterVault<C>) -> serde_json::Value {
        vault
            .scan_cf_at(vault.latest_seq(), ColumnFamily::Ledger)
            .expect("scan ledger")
            .into_iter()
            .filter_map(|(_, bytes)| {
                let entry = decode(&bytes).expect("decode ledger row");
                if entry.kind != EntryKind::Measure {
                    return None;
                }
                let value: serde_json::Value =
                    serde_json::from_slice(&entry.payload).expect("decode measure payload");
                (value.get("schema").and_then(|v| v.as_str())
                    == Some(FSV_JANITOR_SCRUB_LEDGER_SCHEMA))
                .then_some(value)
            })
            .next_back()
            .expect("a janitor Measure scrub entry exists")
    }
}
