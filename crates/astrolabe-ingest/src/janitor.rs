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
