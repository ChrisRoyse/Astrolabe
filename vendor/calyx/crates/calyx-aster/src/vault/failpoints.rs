//! Crash-injection failpoints for durable-commit FSV and the production guard
//! that keeps them out of shipped builds (Astrolabe #276, #60).
//!
//! The durable commit path has three observable crash boundaries. Each has a
//! named, env-armed failpoint compiled in only under `cfg(test)` or the opt-in
//! `crash-fsv` feature:
//!
//! - **post-WAL-append** — `crash_fsv_after_wal_append` (defined in `commit.rs`,
//!   armed by `CALYX_ASTER_CRASH_FSV_AFTER_WAL_APPEND_MARKER`);
//! - **post-MVCC-commit / pre-checkpoint** — [`crash_fsv_after_mvcc_commit`]
//!   (armed by `CALYX_ASTER_CRASH_FSV_AFTER_MVCC_COMMIT_MARKER`);
//! - **post-checkpoint / post-manifest-advance** — [`crash_fsv_after_checkpoint`]
//!   (armed by `CALYX_ASTER_CRASH_FSV_AFTER_CHECKPOINT_MARKER`).
//!
//! When a failpoint's marker env var is set, it records the seq it reached to
//! the marker path and then parks the process forever so an external supervisor
//! can kill it at exactly that boundary and drive recovery FSV. With the marker
//! unset the failpoint is a no-op, so an armed failpoint never fires unless a
//! test deliberately arms it.
//!
//! ## Production guard (#276 DoD)
//!
//! Armed failpoints must be impossible in a shipped build. Two fail-closed
//! layers enforce that:
//!
//! - a build-time [`compile_error!`] that refuses to compile the `crash-fsv`
//!   feature into an optimized (release) build, and
//! - a startup [`guard_against_production_failpoints`] that refuses to open a
//!   durable vault if failpoints are somehow compiled into an optimized,
//!   non-test build, returning the named `CALYX_CRASH_FSV_ARMED_IN_PRODUCTION`
//!   error rather than running with live crash injection.

#[cfg(any(test, feature = "crash-fsv"))]
use calyx_core::Seq;
use calyx_core::{CalyxError, Result};

/// Build-time guard (#276): the `crash-fsv` failpoint feature must never be
/// compiled into an optimized (release) build. `cfg(test)` unit and integration
/// builds use the debug profile (`debug_assertions` on), so this never blocks
/// the crash-FSV suite; it fires only for `--release`/`--profile release` builds
/// that carry the feature, exactly the "armed failpoint in a shipped build"
/// case the DoD forbids.
#[cfg(all(feature = "crash-fsv", not(debug_assertions)))]
compile_error!(
    "CALYX_CRASH_FSV_RELEASE_BUILD: the `crash-fsv` failpoint feature must not be compiled \
     into an optimized (release) build; crash-injection failpoints are test-only. \
     Remediation: build without `--features crash-fsv`, or use the debug profile for \
     crash-FSV harnesses."
);

/// Named error a production build raises when crash failpoints are armed
/// (subsystem-local `CALYX_*` code; not part of the PRD 18 cross-surface
/// catalog, so it is built as a direct [`CalyxError`]).
pub const CRASH_FSV_ARMED_IN_PRODUCTION: &str = "CALYX_CRASH_FSV_ARMED_IN_PRODUCTION";

/// Env marker path that arms the post-MVCC-commit / pre-checkpoint failpoint.
#[cfg(any(test, feature = "crash-fsv"))]
pub(crate) const CRASH_FSV_AFTER_MVCC_COMMIT_MARKER: &str =
    "CALYX_ASTER_CRASH_FSV_AFTER_MVCC_COMMIT_MARKER";

/// Env marker path that arms the post-checkpoint / post-manifest-advance
/// failpoint.
#[cfg(any(test, feature = "crash-fsv"))]
pub(crate) const CRASH_FSV_AFTER_CHECKPOINT_MARKER: &str =
    "CALYX_ASTER_CRASH_FSV_AFTER_CHECKPOINT_MARKER";

/// Records `seq` to the path named by `marker_env` and parks forever, so an
/// external supervisor can kill the process at this exact commit boundary. A
/// no-op when the env var is unset.
#[cfg(any(test, feature = "crash-fsv"))]
fn park_at_failpoint(marker_env: &str, seq: Seq) -> Result<()> {
    let Some(marker) = std::env::var_os(marker_env) else {
        return Ok(());
    };
    std::fs::write(&marker, format!("{seq}\n")).map_err(|error| {
        CalyxError::disk_pressure(format!("write crash FSV marker {marker:?}: {error}"))
    })?;
    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}

/// Post-MVCC-commit / pre-checkpoint crash boundary (#276). Fires after a batch
/// has been appended to the WAL and committed to the MVCC memtable but before
/// its checkpoint SST + manifest advance. A crash here leaves the manifest
/// behind the committed seq, so recovery must replay the batch from the WAL.
#[cfg(any(test, feature = "crash-fsv"))]
pub(crate) fn crash_fsv_after_mvcc_commit(seq: Seq) -> Result<()> {
    park_at_failpoint(CRASH_FSV_AFTER_MVCC_COMMIT_MARKER, seq)
}

/// Post-checkpoint / post-manifest-advance crash boundary (#276). Fires after
/// the pending batch's durable-batch SSTs are written and the manifest has
/// advanced to cover them. A crash here leaves an advanced manifest, so
/// recovery must reconcile the manifest + durable-batch SSTs (checkpoint
/// replay), not WAL replay.
#[cfg(any(test, feature = "crash-fsv"))]
pub(crate) fn crash_fsv_after_checkpoint(seq: Seq) -> Result<()> {
    park_at_failpoint(CRASH_FSV_AFTER_CHECKPOINT_MARKER, seq)
}

/// Pure guard decision (#276): fail closed with
/// [`CRASH_FSV_ARMED_IN_PRODUCTION`] iff crash failpoints are compiled in, the
/// build is optimized (release), and it is not a `cfg(test)` build. Kept as a
/// standalone, input-driven function so the exact refuse/permit boundary can be
/// proven by a control test without needing to produce a real release binary.
pub fn crash_fsv_guard_decision(
    failpoints_compiled: bool,
    optimized_build: bool,
    test_build: bool,
) -> Result<()> {
    if failpoints_compiled && optimized_build && !test_build {
        return Err(CalyxError {
            code: CRASH_FSV_ARMED_IN_PRODUCTION,
            message:
                "crash-injection failpoints are compiled into an optimized build; refusing to run"
                    .to_string(),
            remediation: "rebuild without the `crash-fsv` feature; crash failpoints are test-only",
        });
    }
    Ok(())
}

/// Startup guard called on every durable-vault open. Reads this build's real
/// compile configuration and applies [`crash_fsv_guard_decision`], so an
/// optimized build that somehow carries armed failpoints refuses to run rather
/// than serving traffic with live crash injection. A no-op in normal builds
/// (no `crash-fsv` feature) and in debug/test builds.
pub fn guard_against_production_failpoints() -> Result<()> {
    crash_fsv_guard_decision(
        cfg!(any(test, feature = "crash-fsv")),
        !cfg!(debug_assertions),
        cfg!(test),
    )
}
