//! Registry-declared knobs owned by the domain spine.
//!
//! Standing invariant 4 ("no constant that could be a measurement") requires
//! every threshold, weight, budget, or rate that a shipped path depends on to be
//! a *declared* knob with explicit bounds, a unit, a source, and a rationale —
//! never a bare constant buried in a function body. This module holds the
//! declaration type plus the FSV knob registry that `astrolabe-ingest` and
//! `astrolabe-lower` consume (see [`crate::fsv`]).
//!
//! `astrolabe-kernel` carries a structurally identical `U64KnobDeclaration` for
//! the search/skill/label registries it owns. That crate depends on this one, so
//! the two can converge on this declaration later; they are kept separate here
//! only so this change does not touch a crate another lane owns.

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
    /// Unit of the value (`permille`, `rows`, `entries`, ...).
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

/// Registry version tag for the engine-native FSV knobs.
pub const FSV_KNOB_REGISTRY_VERSION: &str = "astrolabe-fsv-knobs-v1";

/// Name of the readback sampling-rate knob.
pub const FSV_READBACK_SAMPLE_RATE_PERMILLE_KNOB: &str = "fsv_readback_sample_rate_permille";
/// Name of the janitor row-budget knob.
pub const FSV_JANITOR_ROWS_PER_SLICE_KNOB: &str = "fsv_janitor_rows_per_slice";
/// Name of the janitor ledger-entry budget knob.
pub const FSV_JANITOR_LEDGER_ENTRIES_PER_SLICE_KNOB: &str = "fsv_janitor_ledger_entries_per_slice";

/// Full readback: every mutated row is re-read and content-hash compared.
pub const FSV_SAMPLE_RATE_FULL_PERMILLE: u64 = 1_000;
/// Smallest legal sampling rate. Zero is illegal: a zero-rate "verification"
/// verifies nothing while still producing an ack, which is exactly the
/// unlabeled-claim failure this machinery exists to prevent.
pub const FSV_MIN_SAMPLE_RATE_PERMILLE: u64 = 1;
/// Default janitor row budget per slice.
pub const FSV_DEFAULT_JANITOR_ROWS_PER_SLICE: u64 = 4_096;
/// Smallest legal janitor row budget: a slice must make progress.
pub const FSV_MIN_JANITOR_ROWS_PER_SLICE: u64 = 1;
/// Largest legal janitor row budget per slice.
pub const FSV_MAX_JANITOR_ROWS_PER_SLICE: u64 = 1_000_000;
/// Default janitor ledger-entry budget per slice.
pub const FSV_DEFAULT_JANITOR_LEDGER_ENTRIES_PER_SLICE: u64 = 4_096;
/// Smallest legal janitor ledger-entry budget: a slice must make progress.
pub const FSV_MIN_JANITOR_LEDGER_ENTRIES_PER_SLICE: u64 = 1;
/// Largest legal janitor ledger-entry budget per slice.
pub const FSV_MAX_JANITOR_LEDGER_ENTRIES_PER_SLICE: u64 = 1_000_000;

/// The engine-native FSV knob registry (#178).
///
/// The defaults encode the RocksDB `paranoid_checks`/`verify_checksums` posture
/// (foreground verification on by default, correctness over availability) and
/// the ZFS scrub posture (background re-verification runs in bounded slices that
/// interleave with live I/O rather than as one unbounded stop-the-world pass).
pub const FSV_KNOBS: &[U64KnobDeclaration] = &[
    U64KnobDeclaration {
        registry_version: FSV_KNOB_REGISTRY_VERSION,
        name: FSV_READBACK_SAMPLE_RATE_PERMILLE_KNOB,
        default: FSV_SAMPLE_RATE_FULL_PERMILLE,
        min: FSV_MIN_SAMPLE_RATE_PERMILLE,
        max: FSV_SAMPLE_RATE_FULL_PERMILLE,
        unit: "permille",
        source: "https://github.com/facebook/rocksdb/blob/main/include/rocksdb/options.h (paranoid_checks defaults to true: 'most workloads value data correctness over availability')",
        rationale: "default is full readback of every mutated row; a lower rate is a deliberate throughput trade the operator makes, and any ack produced under it is labeled `fsv:verified-sampled`, never `fsv:verified`",
    },
    U64KnobDeclaration {
        registry_version: FSV_KNOB_REGISTRY_VERSION,
        name: FSV_JANITOR_ROWS_PER_SLICE_KNOB,
        default: FSV_DEFAULT_JANITOR_ROWS_PER_SLICE,
        min: FSV_MIN_JANITOR_ROWS_PER_SLICE,
        max: FSV_MAX_JANITOR_ROWS_PER_SLICE,
        unit: "rows",
        source: "https://openzfs.github.io/openzfs-docs/man/v2.4/8/zpool-scrub.8.html (scrub is resumable and checkpointed to disk, interleaving with live I/O)",
        rationale: "bounds the CF rows one background scrub slice re-reads so the janitor never becomes an unbounded stop-the-world pass; replace with a measured IO-budget policy once scrub throughput is benchmarked",
    },
    U64KnobDeclaration {
        registry_version: FSV_KNOB_REGISTRY_VERSION,
        name: FSV_JANITOR_LEDGER_ENTRIES_PER_SLICE_KNOB,
        default: FSV_DEFAULT_JANITOR_LEDGER_ENTRIES_PER_SLICE,
        min: FSV_MIN_JANITOR_LEDGER_ENTRIES_PER_SLICE,
        max: FSV_MAX_JANITOR_LEDGER_ENTRIES_PER_SLICE,
        unit: "entries",
        source: "https://research.swtch.com/tlog.pdf (a client caches the verified prefix and only verifies the suffix, rather than rewalking the whole log)",
        rationale: "bounds the hash-chain entries one slice re-hashes past the persisted checkpoint, so #96 (no full-ledger rewalk per status call) stays respected as the ledger grows",
    },
];

/// Returns the declaration for `name`, or `None` when the knob is not declared.
pub fn fsv_knob(name: &str) -> Option<&'static U64KnobDeclaration> {
    FSV_KNOBS.iter().find(|knob| knob.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_fsv_knob_declares_bounds_that_contain_its_default() {
        assert!(!FSV_KNOBS.is_empty());
        for knob in FSV_KNOBS {
            assert_eq!(knob.registry_version, FSV_KNOB_REGISTRY_VERSION, "{knob:?}");
            assert!(knob.min <= knob.max, "{knob:?}");
            assert!(knob.accepts(knob.default), "{knob:?}");
            assert!(!knob.unit.is_empty(), "{knob:?}");
            assert!(!knob.source.is_empty(), "{knob:?}");
            assert!(!knob.rationale.is_empty(), "{knob:?}");
        }
    }

    #[test]
    fn sample_rate_zero_is_not_a_legal_knob_value() {
        let knob = fsv_knob(FSV_READBACK_SAMPLE_RATE_PERMILLE_KNOB).expect("declared");
        assert!(!knob.accepts(0));
        assert!(knob.accepts(FSV_SAMPLE_RATE_FULL_PERMILLE));
        assert_eq!(knob.default, FSV_SAMPLE_RATE_FULL_PERMILLE);
    }
}
