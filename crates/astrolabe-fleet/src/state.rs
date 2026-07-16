//! Repository lifecycle state machine (issues #449, #450).
//!
//! The lifecycle is a straight pipeline with two escape hatches:
//!
//! ```text
//! discovered → cloned → indexed → kerneled → serving
//!      \_________\________\_________\____________\→ quarantined
//!      \_________\________\_________\____________\→ departed → discovered
//! ```
//!
//! A legal transition is exactly one forward step along the pipeline, a jump
//! to [`RepoState::Quarantined`] from any non-quarantined/non-departed state
//! (with a recorded reason), a jump to [`RepoState::Departed`] from any
//! pipeline state (issue #450: a repo absent from a complete discovery
//! re-enumeration — deleted, private, renamed, or fallen below the star floor
//! — is labeled, never silently dropped), `departed → discovered` when a
//! departed repo reappears in a later complete enumeration, or
//! `quarantined → discovered` as the deliberate retry release owned by the
//! growth scheduler (issue #457: the repo re-enters the pipeline from the
//! start; the quarantine reason stays in the ledger history). Everything else
//! refuses fail-closed with [`ASTRO_FLEET_ILLEGAL_TRANSITION`].

use calyx_core::CalyxError;
use serde::{Deserialize, Serialize};

/// Refusal code for a transition that is not a legal edge of the lifecycle.
pub const ASTRO_FLEET_ILLEGAL_TRANSITION: &str = "ASTRO_FLEET_ILLEGAL_TRANSITION";
/// Refusal code for a state string that names no known [`RepoState`].
pub const ASTRO_FLEET_UNKNOWN_STATE: &str = "ASTRO_FLEET_UNKNOWN_STATE";

/// Lifecycle state of one catalogued repository.
///
/// Serialized (serde and [`RepoState::as_str`]) as stable snake_case strings;
/// unknown strings refuse with [`ASTRO_FLEET_UNKNOWN_STATE`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepoState {
    /// Known from GitHub discovery; nothing on disk yet.
    Discovered,
    /// Full-history clone exists at the record's `clone_path`.
    Cloned,
    /// The repo has been indexed through the CBM → Calyx pipeline.
    Indexed,
    /// A per-repo kernel artifact has been mined and persisted.
    Kerneled,
    /// The repo's kernel participates in fleet-scope serving.
    Serving,
    /// Pulled out of the pipeline for a recorded reason; released only by the
    /// deliberate `quarantined → discovered` retry edge (#457).
    Quarantined,
    /// Absent from a complete discovery re-enumeration (deleted, private,
    /// renamed, or below the star floor); returns to `discovered` if it
    /// reappears (issue #450).
    Departed,
}

/// The forward pipeline, in order. `Quarantined` is deliberately absent: it is
/// reachable from every other state but never advanced out of.
pub const PIPELINE: [RepoState; 5] = [
    RepoState::Discovered,
    RepoState::Cloned,
    RepoState::Indexed,
    RepoState::Kerneled,
    RepoState::Serving,
];

/// Every state, for exhaustive listings such as per-state counts.
pub const ALL_STATES: [RepoState; 7] = [
    RepoState::Discovered,
    RepoState::Cloned,
    RepoState::Indexed,
    RepoState::Kerneled,
    RepoState::Serving,
    RepoState::Quarantined,
    RepoState::Departed,
];

impl RepoState {
    /// Stable snake_case name used in vault metadata, ledger payloads, and CLI.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Discovered => "discovered",
            Self::Cloned => "cloned",
            Self::Indexed => "indexed",
            Self::Kerneled => "kerneled",
            Self::Serving => "serving",
            Self::Quarantined => "quarantined",
            Self::Departed => "departed",
        }
    }

    /// Parses a state name, refusing anything unknown fail-closed.
    pub fn parse(raw: &str) -> Result<Self, CalyxError> {
        match raw.trim() {
            "discovered" => Ok(Self::Discovered),
            "cloned" => Ok(Self::Cloned),
            "indexed" => Ok(Self::Indexed),
            "kerneled" => Ok(Self::Kerneled),
            "serving" => Ok(Self::Serving),
            "quarantined" => Ok(Self::Quarantined),
            "departed" => Ok(Self::Departed),
            other => Err(CalyxError {
                code: ASTRO_FLEET_UNKNOWN_STATE,
                message: format!(
                    "unknown fleet repo state {other:?}; expected one of discovered|cloned|indexed|kerneled|serving|quarantined|departed"
                ),
                remediation: "pass a state name from the declared lifecycle; see astrolabe-fleet::state::RepoState",
            }),
        }
    }

    /// The single legal forward successor along the pipeline, if any.
    pub fn pipeline_successor(self) -> Option<Self> {
        PIPELINE
            .iter()
            .position(|state| *state == self)
            .and_then(|idx| PIPELINE.get(idx + 1))
            .copied()
    }
}

/// Validates that `from → to` is a legal lifecycle edge, refusing fail-closed
/// otherwise. Legal edges: exactly one forward pipeline step, any pipeline
/// state → [`RepoState::Quarantined`], any pipeline state →
/// [`RepoState::Departed`], `departed → discovered` (reappearance), or
/// `quarantined → discovered` (deliberate retry release, #457).
pub fn check_transition(from: RepoState, to: RepoState) -> Result<(), CalyxError> {
    let from_pipeline = PIPELINE.contains(&from);
    if to == RepoState::Quarantined && from_pipeline {
        return Ok(());
    }
    if to == RepoState::Departed && from_pipeline {
        return Ok(());
    }
    if from == RepoState::Departed && to == RepoState::Discovered {
        return Ok(());
    }
    if from == RepoState::Quarantined && to == RepoState::Discovered {
        // Deliberate retry release (#457): the repo re-enters the pipeline
        // from the start; the quarantine reason survives in the ledger.
        return Ok(());
    }
    if from.pipeline_successor() == Some(to) {
        return Ok(());
    }
    Err(CalyxError {
        code: ASTRO_FLEET_ILLEGAL_TRANSITION,
        message: format!(
            "illegal fleet lifecycle transition {} → {}; legal from {} are: {}",
            from.as_str(),
            to.as_str(),
            from.as_str(),
            legal_targets(from),
        ),
        remediation: "advance one pipeline step at a time (discovered→cloned→indexed→kerneled→serving), quarantine or depart with a reason, re-discover a departed repo, or release a quarantined repo to discovered for a retry (#457)",
    })
}

fn legal_targets(from: RepoState) -> String {
    let mut targets = Vec::new();
    if let Some(next) = from.pipeline_successor() {
        targets.push(next.as_str());
    }
    if PIPELINE.contains(&from) {
        targets.push(RepoState::Quarantined.as_str());
        targets.push(RepoState::Departed.as_str());
    }
    if from == RepoState::Departed || from == RepoState::Quarantined {
        targets.push(RepoState::Discovered.as_str());
    }
    if targets.is_empty() {
        "none (terminal state)".to_string()
    } else {
        targets.join(", ")
    }
}
