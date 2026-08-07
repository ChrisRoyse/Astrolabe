//! Registry-declared knobs owned by the Aster storage engine.
//!
//! Standing invariant 4 ("no constant that could be a measurement") requires
//! every threshold, weight, budget, or rate that a shipped path depends on to be
//! a *declared* knob with explicit bounds, a unit, a source, and a rationale —
//! never a bare `const` in a module body.
//!
//! `astrolabe-domain::knobs` carries a structurally identical
//! [`U64KnobDeclaration`], as does `astrolabe-kernel`. Those crates depend on
//! Calyx, not the other way round, so the type is mirrored here rather than
//! imported; the three can converge once a shared spine crate owns it.
//!
//! # The snapshot-pin stall window
//!
//! Before #980 the reader-lease duration was two independent 5 s constants
//! (`vault::DEFAULT_LEASE_MS`, `gc::snapshot_gc::DEFAULT_READER_LEASE_MS`) that
//! behaved as an *operation budget*: stamped into an immutable
//! [`crate::mvcc::ReaderLease`] copy at pin time and compared against wall clock
//! forever after, so a legitimately long readback expired mid-flight and aborted
//! a publication whose work had completed clean. 13a7e5c8 made the lease
//! registry the authoritative deadline and redefined the duration as a **stall
//! window**: the maximum time a holder may pin a sequence *without demonstrating
//! forward progress*. This module declares that window once (#1038). No other
//! module in the tree may declare a lease duration of its own.

/// A single registry-declared unsigned-integer knob.
///
/// A knob is only legitimate if a reader can answer, from the declaration alone:
/// what it means (`unit`), what values are legal (`min`..=`max`), what it is if
/// nobody sets it (`default`), where the number came from (`source`), and why
/// that value rather than another (`rationale`).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct U64KnobDeclaration {
    /// Version tag of the registry this declaration belongs to.
    pub registry_version: &'static str,
    /// Stable knob name, used in reports and operator-facing config.
    pub name: &'static str,
    /// Value used when the caller does not set the knob.
    pub default: u64,
    /// Smallest legal value (inclusive).
    pub min: u64,
    /// Largest legal value (inclusive).
    pub max: u64,
    /// Unit of the value (`ms`, `rows`, `bytes`, ...).
    pub unit: &'static str,
    /// Where the value came from: a document section, a measurement, or an issue.
    pub source: &'static str,
    /// Why this default is the right seed, and what would replace it.
    pub rationale: &'static str,
}

impl U64KnobDeclaration {
    /// Returns true when `value` is inside the declared closed interval.
    pub const fn accepts(&self, value: u64) -> bool {
        value >= self.min && value <= self.max
    }
}

/// Registry version tag for the snapshot-pin knobs.
pub const SNAPSHOT_PIN_KNOB_REGISTRY_VERSION: &str = "calyx-snapshot-pin-knobs-v1";

/// Name of the base snapshot-pin stall-window knob.
pub const SNAPSHOT_PIN_STALL_WINDOW_MS_KNOB: &str = "snapshot_pin_stall_window_ms";
/// Name of the held-read-session stall-window knob.
pub const SNAPSHOT_PIN_SESSION_STALL_WINDOW_MS_KNOB: &str = "snapshot_pin_session_stall_window_ms";
/// Name of the time-travel stall-window knob.
pub const SNAPSHOT_PIN_TIMETRAVEL_STALL_WINDOW_MS_KNOB: &str =
    "snapshot_pin_timetravel_stall_window_ms";
/// Name of the index-rebuild stall-window knob.
pub const SNAPSHOT_PIN_REBUILD_STALL_WINDOW_MS_KNOB: &str = "snapshot_pin_rebuild_stall_window_ms";

/// Smallest legal stall window. Below roughly 100 ms, whether a holder "made
/// progress" is decided by scheduler jitter and page-cache luck rather than by
/// whether it is actually stalled, so expiry stops meaning what it claims.
pub const MIN_SNAPSHOT_PIN_STALL_WINDOW_MS: u64 = 100;
/// Largest legal stall window: 24 h. A pin held a full day without a single
/// demonstrated step is an abandoned reader by any definition, and version GC
/// must eventually be allowed to reclaim it.
pub const MAX_SNAPSHOT_PIN_STALL_WINDOW_MS: u64 = 86_400_000;

/// The snapshot-pin knob registry (#1038).
///
/// Every reader-lease duration in the workspace resolves to exactly one of these
/// declarations. They are separate knobs rather than one number because they
/// bound structurally different holders: a scoped vault operation reads
/// continuously, an index rebuild spends most of its pin inside a CPU-bound
/// build phase that touches no row, and a held search session interleaves
/// engine-side ranking between vault reads. Collapsing them would let version GC
/// reclaim rows a legitimate holder still intends to read.
pub const SNAPSHOT_PIN_KNOBS: &[U64KnobDeclaration] = &[
    SNAPSHOT_PIN_STALL_WINDOW_MS,
    SNAPSHOT_PIN_SESSION_STALL_WINDOW_MS,
    SNAPSHOT_PIN_TIMETRAVEL_STALL_WINDOW_MS,
    SNAPSHOT_PIN_REBUILD_STALL_WINDOW_MS,
];

/// Base snapshot-pin stall window: how long one scoped vault operation may pin a
/// sequence without demonstrating forward progress.
///
/// This is the single declaration that replaced `vault::DEFAULT_LEASE_MS` and
/// `gc::snapshot_gc::DEFAULT_READER_LEASE_MS` (#1038). It is *not* a budget for
/// how long the operation may run: a progressing holder refreshes its registry
/// entry in place (see `VersionedCfStore::record_reader_progress`), so a
/// corpus-scale readback that runs for hours never expires while it keeps
/// resolving rows.
pub const SNAPSHOT_PIN_STALL_WINDOW_MS: U64KnobDeclaration = U64KnobDeclaration {
    registry_version: SNAPSHOT_PIN_KNOB_REGISTRY_VERSION,
    name: SNAPSHOT_PIN_STALL_WINDOW_MS_KNOB,
    default: 5_000,
    min: MIN_SNAPSHOT_PIN_STALL_WINDOW_MS,
    max: MAX_SNAPSHOT_PIN_STALL_WINDOW_MS,
    unit: "ms",
    source: "https://apple.github.io/foundationdb/known-limitations.html (FoundationDB bounds a read version at 5 s so old versions can be reclaimed) — the PH58 FoundationDB-style discipline the two retired constants encoded",
    rationale: "5 s is the interval after which a reader that has not resolved a single row is indistinguishable from an abandoned one; replace with a measured per-step p99 progress interval once corpus-scale ordered readback is profiled",
};

/// Stall window for a held read session that interleaves engine-side work
/// between vault reads (search hydration, the FSV grounding audit, a retained
/// SST read session whose caller builds a corpus-proportional plan).
pub const SNAPSHOT_PIN_SESSION_STALL_WINDOW_MS: U64KnobDeclaration = U64KnobDeclaration {
    registry_version: SNAPSHOT_PIN_KNOB_REGISTRY_VERSION,
    name: SNAPSHOT_PIN_SESSION_STALL_WINDOW_MS_KNOB,
    default: 300_000,
    min: MIN_SNAPSHOT_PIN_STALL_WINDOW_MS,
    max: MAX_SNAPSHOT_PIN_STALL_WINDOW_MS,
    unit: "ms",
    source: "carried forward unchanged from the retired SEARCH_READER_LEASE_MS and GROUNDING_READER_LEASE_MS constants (#1038)",
    rationale: "a session holder can spend minutes ranking, scoring, or auditing between vault reads, so it reaches a progress point far less often than a scoped operation; replace with a measured inter-read p99 once search hydration is profiled",
};

/// Stall window for an interactive time-travel pin.
pub const SNAPSHOT_PIN_TIMETRAVEL_STALL_WINDOW_MS: U64KnobDeclaration = U64KnobDeclaration {
    registry_version: SNAPSHOT_PIN_KNOB_REGISTRY_VERSION,
    name: SNAPSHOT_PIN_TIMETRAVEL_STALL_WINDOW_MS_KNOB,
    default: 60_000,
    min: MIN_SNAPSHOT_PIN_STALL_WINDOW_MS,
    max: MAX_SNAPSHOT_PIN_STALL_WINDOW_MS,
    unit: "ms",
    source: "carried forward unchanged from the retired TIMETRAVEL_LEASE_MS constant (#1038)",
    rationale: "a historical read session is driven by a caller that may pause between queries; the pin is released on drop regardless, so this bounds only an abandoned handle",
};

/// Stall window for a persisted search-index rebuild, which holds its pin across
/// CPU-bound index-build phases that touch no vault row.
pub const SNAPSHOT_PIN_REBUILD_STALL_WINDOW_MS: U64KnobDeclaration = U64KnobDeclaration {
    registry_version: SNAPSHOT_PIN_KNOB_REGISTRY_VERSION,
    name: SNAPSHOT_PIN_REBUILD_STALL_WINDOW_MS_KNOB,
    default: 60 * 60 * 1000,
    min: MIN_SNAPSHOT_PIN_STALL_WINDOW_MS,
    max: MAX_SNAPSHOT_PIN_STALL_WINDOW_MS,
    unit: "ms",
    source: "carried forward unchanged from the retired DEFAULT_REBUILD_READER_LEASE_MS constant; operator override remains CALYX_SEARCH_REBUILD_READER_LEASE_MS (#1038)",
    rationale: "a DiskANN build reads every row up front and then spends the rest of its pin building, reaching no vault progress point; replace with a measured build-phase p99 once slot rebuild throughput is benchmarked",
};

/// Looks up one declaration by its stable knob name.
///
/// Returns `None` for an unknown name rather than guessing a default — an
/// unrecognised knob is a configuration error, never a silent fallback.
pub fn snapshot_pin_knob(name: &str) -> Option<&'static U64KnobDeclaration> {
    let mut index = 0;
    while index < SNAPSHOT_PIN_KNOBS.len() {
        if SNAPSHOT_PIN_KNOBS[index].name == name {
            return Some(&SNAPSHOT_PIN_KNOBS[index]);
        }
        index += 1;
    }
    None
}
