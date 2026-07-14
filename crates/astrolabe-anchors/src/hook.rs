//! Opt-in Stop / afterTask hook harness (blueprint 06 §2.4, 15 §4).
//!
//! An agent runtime may install an opt-in post-task hook that prompts the
//! `anchor_outcome{kind:"agent_task"}` call recording whether the session
//! succeeded. The hook is *advisory*: it must follow CBM's never-block /
//! silent-fail contract so it can never wedge the agent. This harness enforces
//! that contract structurally — it runs the hook under a wall-clock budget and
//! maps every outcome (fast exit, timeout, or launch failure) to a
//! non-blocking [`HookOutcome`], never surfacing an error and never waiting past
//! the budget. The shipped reference script is
//! `assets/hooks/agent_task_aftertask_hook.sh`.

use std::ffi::OsStr;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Poll interval while waiting for an opt-in hook to finish.
const HOOK_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// The terminal state of an opt-in hook run. Every variant is non-blocking:
/// [`HookOutcome::blocked`] is always `false`, because an advisory hook is never
/// allowed to hold up the agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookOutcome {
    /// The hook exited on its own within the budget.
    Completed {
        /// True iff the process reported success (exit status 0).
        success: bool,
        /// Raw exit code when the OS reported one.
        code: Option<i32>,
    },
    /// The hook exceeded its budget and was terminated. Silent: no error is
    /// propagated to the agent.
    TimedOut,
    /// The hook could not be launched (missing script, permission, ...). Silent:
    /// treated as a no-op, never an error the agent must handle.
    LaunchFailed {
        /// Operator-facing reason string; never shown to the agent loop.
        reason: String,
    },
}

impl HookOutcome {
    /// An advisory hook never blocks the agent: always `false`.
    pub const fn blocked(&self) -> bool {
        false
    }

    /// True iff the hook completed on its own with a success exit status.
    pub const fn completed_ok(&self) -> bool {
        matches!(self, HookOutcome::Completed { success: true, .. })
    }

    /// True iff the hook was terminated for exceeding its budget.
    pub const fn timed_out(&self) -> bool {
        matches!(self, HookOutcome::TimedOut)
    }

    /// True iff the hook could not be launched at all.
    pub const fn launch_failed(&self) -> bool {
        matches!(self, HookOutcome::LaunchFailed { .. })
    }
}

/// Runs an opt-in hook process under a wall-clock `budget`, enforcing the
/// never-block / silent-fail contract.
///
/// The hook's stdio is discarded (an advisory hook must not contend for the
/// agent's streams). The call returns as soon as the hook exits, or at the
/// budget when it does not — whichever is first — and never returns an error:
/// a launch failure or a timeout is a labeled non-blocking [`HookOutcome`], not
/// something the agent loop has to catch. `budget` is clamped to at least one
/// poll interval so a zero budget still makes forward progress.
pub fn run_hook_process<S, I, A>(program: S, args: I, budget: Duration) -> HookOutcome
where
    S: AsRef<OsStr>,
    I: IntoIterator<Item = A>,
    A: AsRef<OsStr>,
{
    let budget = budget.max(HOOK_POLL_INTERVAL);
    let mut child = match Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            return HookOutcome::LaunchFailed {
                reason: format!("hook could not be launched: {error}"),
            };
        }
    };

    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return HookOutcome::Completed {
                    success: status.success(),
                    code: status.code(),
                };
            }
            Ok(None) => {
                if started.elapsed() >= budget {
                    // Silent-fail: kill the overrunning hook and move on. Kill and
                    // reap errors are swallowed deliberately — an advisory hook
                    // must never surface a failure to the agent.
                    let _ = child.kill();
                    let _ = child.wait();
                    return HookOutcome::TimedOut;
                }
                std::thread::sleep(HOOK_POLL_INTERVAL);
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return HookOutcome::LaunchFailed {
                    reason: "hook process wait failed".to_string(),
                };
            }
        }
    }
}
