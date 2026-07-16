//! Repository lifecycle state machine (issue #449).
//!
//! The lifecycle is a straight pipeline with one escape hatch:
//!
//! ```text
//! discovered → cloned → indexed → kerneled → serving
//!      \_________\________\_________\____________\→ quarantined
//! ```
//!
//! A legal transition is exactly one forward step along the pipeline, or a
//! jump to [`RepoState::Quarantined`] from any non-quarantined state (with a
//! recorded reason). Everything else refuses fail-closed with
//! [`ASTRO_FLEET_ILLEGAL_TRANSITION`]. Quarantine is terminal in v1: releasing
//! a quarantined repo is a deliberate operator action that belongs to a future
//! atom, not an implicit edge here.

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
    /// Pulled out of the pipeline for a recorded reason; terminal in v1.
    Quarantined,
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
pub const ALL_STATES: [RepoState; 6] = [
    RepoState::Discovered,
    RepoState::Cloned,
    RepoState::Indexed,
    RepoState::Kerneled,
    RepoState::Serving,
    RepoState::Quarantined,
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
            other => Err(CalyxError {
                code: ASTRO_FLEET_UNKNOWN_STATE,
                message: format!(
                    "unknown fleet repo state {other:?}; expected one of discovered|cloned|indexed|kerneled|serving|quarantined"
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
/// otherwise. Legal edges: exactly one forward pipeline step, or any
/// non-quarantined state → [`RepoState::Quarantined`].
pub fn check_transition(from: RepoState, to: RepoState) -> Result<(), CalyxError> {
    if to == RepoState::Quarantined && from != RepoState::Quarantined {
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
        remediation: "advance one pipeline step at a time (discovered→cloned→indexed→kerneled→serving) or quarantine with a reason; quarantined is terminal in v1",
    })
}

fn legal_targets(from: RepoState) -> String {
    let mut targets = Vec::new();
    if let Some(next) = from.pipeline_successor() {
        targets.push(next.as_str());
    }
    if from != RepoState::Quarantined {
        targets.push(RepoState::Quarantined.as_str());
    }
    if targets.is_empty() {
        "none (terminal state)".to_string()
    } else {
        targets.join(", ")
    }
}
