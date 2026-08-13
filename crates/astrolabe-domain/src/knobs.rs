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
/// Name of the always-on janitor scrub-cadence knob.
pub const FSV_JANITOR_SCRUB_INTERVAL_MS_KNOB: &str = "fsv_janitor_scrub_interval_ms";

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
/// Default cadence between bounded background scrub slices, in milliseconds.
pub const FSV_DEFAULT_JANITOR_SCRUB_INTERVAL_MS: u64 = 250;
/// Smallest legal scrub cadence: the lane may run back-to-back slices (1 ms) so a
/// high-throughput store or a test can drain the tail promptly.
pub const FSV_MIN_JANITOR_SCRUB_INTERVAL_MS: u64 = 1;
/// Largest legal scrub cadence: a full day, so an operator can throttle the lane
/// to a once-daily background sweep on a quiet store.
pub const FSV_MAX_JANITOR_SCRUB_INTERVAL_MS: u64 = 86_400_000;

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
    U64KnobDeclaration {
        registry_version: FSV_KNOB_REGISTRY_VERSION,
        name: FSV_JANITOR_SCRUB_INTERVAL_MS_KNOB,
        default: FSV_DEFAULT_JANITOR_SCRUB_INTERVAL_MS,
        min: FSV_MIN_JANITOR_SCRUB_INTERVAL_MS,
        max: FSV_MAX_JANITOR_SCRUB_INTERVAL_MS,
        unit: "milliseconds",
        source: "https://openzfs.github.io/openzfs-docs/Performance%20and%20Tuning/Module%20Parameters.html (zfs_scan_vdev_limit / zfs_scrub_min_time_ms throttle scrub so it interleaves with live I/O rather than running as one stop-the-world pass)",
        rationale: "seed cadence between bounded background scrub slices so the always-on janitor interleaves with live I/O; a slice is already bounded by the entries-per-slice knob, so this caps how often those bounded slices fire, never their size; replace with a measured IO-budget policy once scrub throughput is benchmarked (#178 non-goal: measured, not theater)",
    },
];

/// Returns the declaration for `name`, or `None` when the knob is not declared.
pub fn fsv_knob(name: &str) -> Option<&'static U64KnobDeclaration> {
    FSV_KNOBS.iter().find(|knob| knob.name == name)
}

/// Registry version tag for the physical erasure-scrub knobs (#61).
pub const ERASURE_SCRUB_KNOB_REGISTRY_VERSION: &str = "astrolabe-erasure-scrub-knobs-v1";

/// Name of the WAL-scrub fsync-batch knob.
pub const ERASURE_SCRUB_SEGMENTS_PER_FSYNC_BATCH_KNOB: &str =
    "erasure_scrub_segments_per_fsync_batch";

/// Default number of WAL segments truncated-and-fsynced per scrub batch.
///
/// Seeded from the PH58 WAL recycler's `DEFAULT_FSYNC_BUDGET_PER_TICK` so the
/// erasure scrub reuses the storage engine's own anti-fsync-storm budget rather
/// than inventing a second number.
pub const ERASURE_SCRUB_DEFAULT_SEGMENTS_PER_FSYNC_BATCH: u64 = 8;
/// Smallest legal scrub batch: a batch must truncate at least one segment so the
/// scrub loop makes forward progress toward a zero-byte WAL.
pub const ERASURE_SCRUB_MIN_SEGMENTS_PER_FSYNC_BATCH: u64 = 1;
/// Largest legal scrub batch. An upper bound keeps the batch a bounded fsync
/// unit even on a pathologically segmented WAL; the scrub still loops until every
/// checkpointed segment is zeroed, so this caps burst size, never completeness.
pub const ERASURE_SCRUB_MAX_SEGMENTS_PER_FSYNC_BATCH: u64 = 65_536;

/// The physical erasure-scrub knob registry (#61).
///
/// The scrub adopts SQLite's `PRAGMA wal_checkpoint(TRUNCATE)` posture: WAL
/// content is checkpointed into the durable store, then the WAL is truncated to
/// zero bytes so erased plaintext cannot survive in the log. The batch knob
/// mirrors the WAL recycler's fsync budget so the truncation of a large WAL does
/// not become one unbounded fsync storm.
pub const ERASURE_SCRUB_KNOBS: &[U64KnobDeclaration] = &[U64KnobDeclaration {
    registry_version: ERASURE_SCRUB_KNOB_REGISTRY_VERSION,
    name: ERASURE_SCRUB_SEGMENTS_PER_FSYNC_BATCH_KNOB,
    default: ERASURE_SCRUB_DEFAULT_SEGMENTS_PER_FSYNC_BATCH,
    min: ERASURE_SCRUB_MIN_SEGMENTS_PER_FSYNC_BATCH,
    max: ERASURE_SCRUB_MAX_SEGMENTS_PER_FSYNC_BATCH,
    unit: "segments",
    source: "https://www.sqlite.org/pragma.html#pragma_wal_checkpoint (TRUNCATE truncates the WAL to zero bytes once content is checkpointed) and calyx-aster gc::wal_recycler::DEFAULT_FSYNC_BUDGET_PER_TICK",
    rationale: "bounds the WAL segments one scrub batch truncates+fsyncs so zeroing a large WAL interleaves with the disk instead of issuing one unbounded fsync storm; the scrub loops batches until every checkpointed segment is zero bytes, so this seed caps burst size, not completeness; replace with a measured fsync-latency budget once scrub throughput is benchmarked",
}];

/// Returns the erasure-scrub declaration for `name`, or `None` when undeclared.
pub fn erasure_scrub_knob(name: &str) -> Option<&'static U64KnobDeclaration> {
    ERASURE_SCRUB_KNOBS.iter().find(|knob| knob.name == name)
}

/// Registry version tag for the streaming CBM row-sink ingest knobs (#59).
pub const ROW_SINK_STREAM_KNOB_REGISTRY_VERSION: &str = "astrolabe-row-sink-stream-knobs-v1";

/// Name of the streaming row-sink drain-batch knob.
pub const ROW_SINK_STREAM_DRAIN_BATCH_ROWS_KNOB: &str = "row_sink_stream_drain_batch_rows";

/// Default number of CBM row-sink rows drained and structurally validated per
/// streaming batch before they are staged for the single ledger-paired write.
///
/// Seeded to mirror RocksDB/TiKV micro-batch write guidance (batch incoming
/// updates into ~100 KB micro-batches of sorted keys rather than one row at a
/// time). At the typical CBM node/edge JSON row size (a few hundred bytes to
/// ~1 KB) 1024 rows lands in that ~100 KB-per-batch window, which is also the
/// bounded-channel backpressure staging unit between the producing row-sink and
/// the validating consumer.
pub const ROW_SINK_STREAM_DEFAULT_DRAIN_BATCH_ROWS: u64 = 1_024;
/// Smallest legal drain batch: a batch must admit at least one row so the drain
/// loop makes forward progress toward a fully validated stream.
pub const ROW_SINK_STREAM_MIN_DRAIN_BATCH_ROWS: u64 = 1;
/// Largest legal drain batch. An upper bound keeps the drain a bounded staging
/// unit even on a pathologically large stream so the bounded-channel
/// backpressure window cannot grow without limit; the drain still loops until the
/// whole stream is validated, so this caps the burst window, never completeness.
pub const ROW_SINK_STREAM_MAX_DRAIN_BATCH_ROWS: u64 = 1_048_576;

/// The streaming CBM row-sink ingest knob registry (#59).
///
/// The default follows the RocksDB bulk-load posture (larger batches amortize
/// per-record overhead and cut write amplification) tempered by the
/// bounded-channel backpressure posture (too small a buffer applies backpressure
/// too early, too large a buffer wastes memory). The drain batch bounds only the
/// streaming validation/backpressure window; persistence is always one
/// ledger-paired write per import, so this knob never changes what is durably
/// written, only the size of the transient validation staging burst.
pub const ROW_SINK_STREAM_KNOBS: &[U64KnobDeclaration] = &[U64KnobDeclaration {
    registry_version: ROW_SINK_STREAM_KNOB_REGISTRY_VERSION,
    name: ROW_SINK_STREAM_DRAIN_BATCH_ROWS_KNOB,
    default: ROW_SINK_STREAM_DEFAULT_DRAIN_BATCH_ROWS,
    min: ROW_SINK_STREAM_MIN_DRAIN_BATCH_ROWS,
    max: ROW_SINK_STREAM_MAX_DRAIN_BATCH_ROWS,
    unit: "rows",
    source: "https://github.com/facebook/rocksdb/wiki/Basic-Operations (batch updates in a WriteBatch with consecutive sorted keys for higher write throughput), https://medium.com/@siddontang/how-we-optimize-rocksdb-in-tikv-write-batch-optimization-28751a4bdd8b (micro-batch incoming updates before writing), and bounded-channel backpressure guidance (size the ingest buffer for the expected burst; too small backpressures too early, too large wastes memory)",
    rationale: "bounds the CBM row-sink rows one streaming batch drains and validates before staging, so a large index stream backpressures the producer in bounded windows instead of buffering unboundedly; the drain loops batches until the whole stream is validated and persistence remains one ledger-paired write, so this seed caps the backpressure burst, not correctness; replace with a measured ingest throughput/latency budget once streaming ingest is benchmarked",
}];

/// Returns the row-sink-stream declaration for `name`, or `None` when undeclared.
pub fn row_sink_stream_knob(name: &str) -> Option<&'static U64KnobDeclaration> {
    ROW_SINK_STREAM_KNOBS.iter().find(|knob| knob.name == name)
}

/// Registry version tag for Git-archaeology persistence batching (#858).
pub const ARCHAEOLOGY_PERSIST_KNOB_REGISTRY_VERSION: &str =
    "astrolabe-archaeology-persist-knobs-v3";
/// Name of the ordered anchor-entry group-commit bound.
pub const ARCHAEOLOGY_ANCHOR_BATCH_ENTRIES_KNOB: &str = "archaeology_anchor_batch_entries";
/// Default logical anchor entries per ordered group commit.
///
/// The #858 Bevy baseline observed one already-extracted evidence group drive at
/// least 122,880 logical Grounding entries. The declared 65,536 ceiling cuts
/// that real group from at least 120 commits to at most two while retaining a
/// strict per-project bound.
pub const ARCHAEOLOGY_DEFAULT_ANCHOR_BATCH_ENTRIES: u64 = 65_536;
/// Smallest legal batch: every admitted group commit must make progress.
pub const ARCHAEOLOGY_MIN_ANCHOR_BATCH_ENTRIES: u64 = 1;
/// Largest legal batch: bounds each independently running project's staging
/// window while allowing a deliberately measured high-fanout repository.
pub const ARCHAEOLOGY_MAX_ANCHOR_BATCH_ENTRIES: u64 = 65_536;
/// Name of the historical snapshots coalesced into one ordered commit window.
pub const ARCHAEOLOGY_HISTORICAL_BATCH_GROUPS_KNOB: &str = "archaeology_historical_batch_groups";
/// Default historical groups per commit window. This matches the existing
/// measured extraction-worker recycle boundary and keeps each project bounded.
pub const ARCHAEOLOGY_DEFAULT_HISTORICAL_BATCH_GROUPS: u64 = 64;
/// Smallest legal historical window.
pub const ARCHAEOLOGY_MIN_HISTORICAL_BATCH_GROUPS: u64 = 1;
/// Largest legal explicit historical window.
pub const ARCHAEOLOGY_MAX_HISTORICAL_BATCH_GROUPS: u64 = 1_024;
/// Name of the Git `diff-tree --stdin` commit batch bound.
pub const ARCHAEOLOGY_DIFF_TREE_BATCH_COMMITS_KNOB: &str = "archaeology_diff_tree_batch_commits";
/// Default commits per Git `diff-tree --stdin` child.
///
/// The #858 Bevy readback saw 1,025 fix-like candidates in the one-year window.
/// A 128-commit stdin batch reduces the mine-side diff-count/content children
/// from roughly one per candidate to nine per pass while bounding per-project
/// stdout/request memory for the 4-5 concurrent local indexing sessions this
/// machine is expected to run.
pub const ARCHAEOLOGY_DEFAULT_DIFF_TREE_BATCH_COMMITS: u64 = 128;
/// Smallest legal diff-tree batch: every spawned child must make progress.
pub const ARCHAEOLOGY_MIN_DIFF_TREE_BATCH_COMMITS: u64 = 1;
/// Largest legal diff-tree batch: keeps one project from creating an unbounded
/// in-memory diff payload while still allowing a measured larger window.
pub const ARCHAEOLOGY_MAX_DIFF_TREE_BATCH_COMMITS: u64 = 1_024;

/// Git-archaeology persistence knob registry (#858).
pub const ARCHAEOLOGY_PERSIST_KNOBS: &[U64KnobDeclaration] = &[
    U64KnobDeclaration {
        registry_version: ARCHAEOLOGY_PERSIST_KNOB_REGISTRY_VERSION,
        name: ARCHAEOLOGY_ANCHOR_BATCH_ENTRIES_KNOB,
        default: ARCHAEOLOGY_DEFAULT_ANCHOR_BATCH_ENTRIES,
        min: ARCHAEOLOGY_MIN_ANCHOR_BATCH_ENTRIES,
        max: ARCHAEOLOGY_MAX_ANCHOR_BATCH_ENTRIES,
        unit: "logical_anchor_entries",
        source: "ASTROLABE #858 Bevy physical FSV: one high-fanout evidence group produced at least 122,880 logical Grounding transitions while the 1,024-entry seed created at least 120 commits",
        rationale: "the measured 65,536 ceiling reduces that real group to at most two ordered atomic commits without dropping an entry; the bound is independently owned by each indexing process so 4-5 concurrent projects cannot multiply an unbounded staging allocation",
    },
    U64KnobDeclaration {
        registry_version: ARCHAEOLOGY_PERSIST_KNOB_REGISTRY_VERSION,
        name: ARCHAEOLOGY_HISTORICAL_BATCH_GROUPS_KNOB,
        default: ARCHAEOLOGY_DEFAULT_HISTORICAL_BATCH_GROUPS,
        min: ARCHAEOLOGY_MIN_HISTORICAL_BATCH_GROUPS,
        max: ARCHAEOLOGY_MAX_HISTORICAL_BATCH_GROUPS,
        unit: "historical_commit_groups",
        source: "ASTROLABE #858 Bevy physical FSV and the existing measured 64-commit historical extraction-worker recycle boundary",
        rationale: "coalesces repeated Base/slot/Ledger fsync and SST publication across a bounded project-local window while preserving exact Ingest/Grounding order; 64 reuses the established per-process recycle boundary instead of introducing an unrelated memory multiplier",
    },
    U64KnobDeclaration {
        registry_version: ARCHAEOLOGY_PERSIST_KNOB_REGISTRY_VERSION,
        name: ARCHAEOLOGY_DIFF_TREE_BATCH_COMMITS_KNOB,
        default: ARCHAEOLOGY_DEFAULT_DIFF_TREE_BATCH_COMMITS,
        min: ARCHAEOLOGY_MIN_DIFF_TREE_BATCH_COMMITS,
        max: ARCHAEOLOGY_MAX_DIFF_TREE_BATCH_COMMITS,
        unit: "commits",
        source: "ASTROLABE #858 Bevy physical FSV: one-year mine window contained 1,025 fix-like candidates and live polling observed repeated short-lived git diff children before historical extraction",
        rationale: "uses Git's documented diff-tree --stdin protocol to amortize process startup across a bounded per-project commit window without changing diff/blame semantics; 128 keeps each local project independent and memory-bounded while cutting Bevy-scale cold diff process count by about two orders of magnitude",
    },
];

/// Returns the Git-archaeology persistence declaration for `name`, or `None`
/// when the knob is undeclared.
pub fn archaeology_persist_knob(name: &str) -> Option<&'static U64KnobDeclaration> {
    ARCHAEOLOGY_PERSIST_KNOBS
        .iter()
        .find(|knob| knob.name == name)
}

/// Registry version tag for the debounced lowered-SQLite regeneration knobs (#225).
pub const LOWER_DEBOUNCE_KNOB_REGISTRY_VERSION: &str = "astrolabe-lower-debounce-knobs-v1";

/// Name of the lowered-SQLite regeneration debounce-window knob.
pub const LOWER_DEBOUNCE_WINDOW_MS_KNOB: &str = "lower_debounce_window_ms";

/// Default debounce window, in milliseconds, before a burst of weave mutations
/// coalesces into one lowered-SQLite regeneration.
///
/// Seeded from `cargo-watch`/`watchexec`, whose file-change rebuild debounce
/// `--delay` defaults to 0.5s: a trailing-edge settle window that lets a burst of
/// changes land before it triggers one rebuild, rather than rebuilding per event.
pub const LOWER_DEBOUNCE_DEFAULT_WINDOW_MS: u64 = 500;
/// Smallest legal debounce window. Zero is illegal: a zero-width window fires a
/// full regeneration on every single weave mutation, which is exactly the
/// burst-amplification this knob exists to coalesce away — the same "a zero value
/// disables the protection this knob exists for" failure the FSV sampling knob
/// forbids.
pub const LOWER_DEBOUNCE_MIN_WINDOW_MS: u64 = 1;
/// Largest legal debounce window. An upper bound keeps a burst from starving the
/// lowered artifact indefinitely: after at most this long of quiet, the pending
/// regeneration must be allowed to fire.
pub const LOWER_DEBOUNCE_MAX_WINDOW_MS: u64 = 300_000;

/// The debounced lowered-SQLite regeneration knob registry (#225).
///
/// Coalescing bursts of weave mutations into one regeneration mirrors the
/// file-watch rebuild debouncers (`cargo-watch`/`watchexec`): a mutation arms a
/// trailing-edge timer, further mutations inside the window reset it, and one
/// regeneration fires once the window elapses quietly.
pub const LOWER_DEBOUNCE_KNOBS: &[U64KnobDeclaration] = &[U64KnobDeclaration {
    registry_version: LOWER_DEBOUNCE_KNOB_REGISTRY_VERSION,
    name: LOWER_DEBOUNCE_WINDOW_MS_KNOB,
    default: LOWER_DEBOUNCE_DEFAULT_WINDOW_MS,
    min: LOWER_DEBOUNCE_MIN_WINDOW_MS,
    max: LOWER_DEBOUNCE_MAX_WINDOW_MS,
    unit: "milliseconds",
    source: "https://github.com/watchexec/cargo-watch (the rebuild debounce --delay defaults to 0.5s) over watchexec's trailing-edge coalescing debounce",
    rationale: "trailing-edge debounce window that coalesces a burst of production-path weave mutations into one lowered-SQLite regeneration; 500ms mirrors cargo-watch's default file-change settle delay; zero is illegal because a zero window regenerates on every single mutation (no coalescing at all); replace with a measured value once weave mutation burst timing is benchmarked",
}];

/// Returns the lower-debounce declaration for `name`, or `None` when undeclared.
pub fn lower_debounce_knob(name: &str) -> Option<&'static U64KnobDeclaration> {
    LOWER_DEBOUNCE_KNOBS.iter().find(|knob| knob.name == name)
}

/// Registry version for the shipping incremental watcher cadence, retry budget,
/// and missing-root observation window (#23, #960, #1083).
pub const WATCHER_KNOB_REGISTRY_VERSION: &str = "astrolabe-watcher-knobs-v3";
/// Name of the server-owned Git watcher poll-cadence knob.
pub const WATCHER_POLL_INTERVAL_MS_KNOB: &str = "watcher_poll_interval_ms";
/// Name of the maximum number of worker attempts admitted for one unchanged,
/// explicitly retryable watcher observation.
pub const WATCHER_TRANSIENT_MAX_ATTEMPTS_KNOB: &str =
    "watcher_transient_max_attempts_per_observation";
/// Name of the project-scoped sustained-absence window. The watcher treats
/// absence as an observation and never as deletion authority.
pub const WATCHER_ROOT_MISSING_GRACE_MS_KNOB: &str = "watcher_root_missing_grace_ms";
/// Default watcher cadence. This reserves 95% of the five-second convergence
/// budget for extraction, ingest, weave, and lowering instead of spending the
/// entire budget waiting to notice the change.
pub const WATCHER_DEFAULT_POLL_INTERVAL_MS: u64 = 250;
/// Smallest legal cadence; lower values create an unbounded Git-process storm.
pub const WATCHER_MIN_POLL_INTERVAL_MS: u64 = 50;
/// Largest legal cadence. One second leaves four seconds of the hard five-second
/// product budget for the actual incremental work.
pub const WATCHER_MAX_POLL_INTERVAL_MS: u64 = 1_000;
/// Maximum worker attempts for one unchanged observation whose exact source code
/// is registered as transient. Twenty observations consume the existing
/// five-second resident coordination window at the 250 ms shipping cadence; the
/// final attempt durably parks the observation instead of retrying forever.
pub const WATCHER_DEFAULT_TRANSIENT_MAX_ATTEMPTS: u64 =
    PROJECT_TRANSITION_QUIESCENCE_TIMEOUT_MS / WATCHER_DEFAULT_POLL_INTERVAL_MS;
/// A transient registration must authorize at least the original worker attempt.
pub const WATCHER_MIN_TRANSIENT_MAX_ATTEMPTS: u64 = 1;
/// The hard five-second coordination budget at the fastest legal watcher cadence.
pub const WATCHER_MAX_TRANSIENT_MAX_ATTEMPTS: u64 =
    PROJECT_TRANSITION_QUIESCENCE_TIMEOUT_MS / WATCHER_MIN_POLL_INTERVAL_MS;
/// Compatibility default for the pre-#960 ten-minute missing-root window.
pub const WATCHER_DEFAULT_ROOT_MISSING_GRACE_MS: u64 = 600_000;
/// A persisted observation must span at least one shipping watcher cadence.
pub const WATCHER_MIN_ROOT_MISSING_GRACE_MS: u64 = WATCHER_DEFAULT_POLL_INTERVAL_MS;
/// Bound accidental indefinite stale-state delay while leaving room for slow
/// removable/network volumes. This is policy only; no artifact is ever deleted.
pub const WATCHER_MAX_ROOT_MISSING_GRACE_MS: u64 = 3_600_000;
/// Bounded writer-admission window for cooperative resident SQLite closure.
pub const PROJECT_TRANSITION_QUIESCENCE_TIMEOUT_MS: u64 = 5_000;

/// The server-owned incremental watcher knob registry (#23).
pub const WATCHER_KNOBS: &[U64KnobDeclaration] = &[
    U64KnobDeclaration {
        registry_version: WATCHER_KNOB_REGISTRY_VERSION,
        name: WATCHER_POLL_INTERVAL_MS_KNOB,
        default: WATCHER_DEFAULT_POLL_INTERVAL_MS,
        min: WATCHER_MIN_POLL_INTERVAL_MS,
        max: WATCHER_MAX_POLL_INTERVAL_MS,
        unit: "milliseconds",
        source: "ASTROLABE #23 five-second M-scale convergence budget",
        rationale: "server-owned detection cadence: 250ms spends 5% of the hard five-second convergence budget on detection and leaves 95% for changed-file extraction, vault convergence, derived projections, and lowered-SQLite readback; bounds prevent both process storms and budget exhaustion",
    },
    U64KnobDeclaration {
        registry_version: WATCHER_KNOB_REGISTRY_VERSION,
        name: "project_transition_quiescence_timeout_ms",
        default: PROJECT_TRANSITION_QUIESCENCE_TIMEOUT_MS,
        min: WATCHER_DEFAULT_POLL_INTERVAL_MS,
        max: 30_000,
        unit: "milliseconds",
        source: "ASTROLABE #753 resident-client cooperative SQLite quiescence contract",
        rationale: "allows twenty resident coordination observations at the 250ms shipping cadence before writer admission fails closed; it is bounded so a foreign or broken handle produces an exact diagnostic instead of an unbounded index request",
    },
    U64KnobDeclaration {
        registry_version: WATCHER_KNOB_REGISTRY_VERSION,
        name: WATCHER_TRANSIENT_MAX_ATTEMPTS_KNOB,
        default: WATCHER_DEFAULT_TRANSIENT_MAX_ATTEMPTS,
        min: WATCHER_MIN_TRANSIENT_MAX_ATTEMPTS,
        max: WATCHER_MAX_TRANSIENT_MAX_ATTEMPTS,
        unit: "worker attempts per unchanged observation",
        source: "ASTROLABE #1083 closed retry authority, bounded by the existing #753 five-second resident coordination window",
        rationale: "only exact registered transient codes consume this budget; twenty 250ms observations span the complete resident coordination window, after which the exact unchanged failure is durably parked instead of amplifying workers, logs, and config WAL forever; replace with a measured per-code condition signal when one is available",
    },
    U64KnobDeclaration {
        registry_version: WATCHER_KNOB_REGISTRY_VERSION,
        name: WATCHER_ROOT_MISSING_GRACE_MS_KNOB,
        default: WATCHER_DEFAULT_ROOT_MISSING_GRACE_MS,
        min: WATCHER_MIN_ROOT_MISSING_GRACE_MS,
        max: WATCHER_MAX_ROOT_MISSING_GRACE_MS,
        unit: "milliseconds of continuous exact-root absence",
        source: "ASTROLABE #960 compatibility with the retired ten-minute C prune window; this value controls durable fault publication only and never deletion",
        rationale: "a short transient move or mount interruption must not publish a durable root-missing fault, while a sustained absence must become explicit stale state; the project-scoped value is parsed strictly and bounded, and a malformed value refuses instead of silently selecting a default",
    },
];

/// Returns the watcher declaration for `name`, or `None` when undeclared.
pub fn watcher_knob(name: &str) -> Option<&'static U64KnobDeclaration> {
    WATCHER_KNOBS.iter().find(|knob| knob.name == name)
}

/// Registry version tag for the CBM pipeline host-thread stack knob (#364).
pub const CBM_PIPELINE_STACK_KNOB_REGISTRY_VERSION: &str = "astrolabe-cbm-pipeline-stack-knobs-v1";
/// Name of the CBM pipeline host-thread stack-reserve knob.
pub const CBM_PIPELINE_HOST_STACK_BYTES_KNOB: &str = "cbm_pipeline_host_stack_bytes";
/// Default stack reserve, in bytes, for any thread that enters the in-process
/// CBM pipeline (`cbm_pipeline_run` via `CbmToolRunner`/`CbmPipeline`).
///
/// The CBM pipeline consumes more than 2 MiB of stack **before it emits its
/// first log line**, even on a 6-file corpus (#364): the real-corpus bench
/// `bench_row_sink_overhead.rs` hit `STATUS_STACK_OVERFLOW` (0xC00000FD) on both
/// the default libtest 2 MiB thread and the default main-thread reserve, and
/// only completes on an explicitly sized 64 MiB worker. Any production thread
/// that runs the pipeline on a default stack is therefore at risk of a
/// diagnostic-free crash. 64 MiB is the measured-working reserve; sizing the
/// host thread explicitly turns a latent 0xC00000FD into an impossible state.
pub const CBM_PIPELINE_DEFAULT_HOST_STACK_BYTES: u64 = 64 * 1024 * 1024;
/// Smallest legal reserve. The measured floor is above 2 MiB (the default
/// libtest/main reserve overflows pre-log), so 8 MiB is the smallest value that
/// is not already known to fault; below it the knob would re-admit the crash.
pub const CBM_PIPELINE_MIN_HOST_STACK_BYTES: u64 = 8 * 1024 * 1024;
/// Largest legal reserve. 512 MiB bounds a misconfiguration from reserving an
/// unbounded per-thread address range while leaving ample headroom over 64 MiB.
pub const CBM_PIPELINE_MAX_HOST_STACK_BYTES: u64 = 512 * 1024 * 1024;

/// The CBM pipeline host-thread stack knob registry (#364).
pub const CBM_PIPELINE_STACK_KNOBS: &[U64KnobDeclaration] = &[U64KnobDeclaration {
    registry_version: CBM_PIPELINE_STACK_KNOB_REGISTRY_VERSION,
    name: CBM_PIPELINE_HOST_STACK_BYTES_KNOB,
    default: CBM_PIPELINE_DEFAULT_HOST_STACK_BYTES,
    min: CBM_PIPELINE_MIN_HOST_STACK_BYTES,
    max: CBM_PIPELINE_MAX_HOST_STACK_BYTES,
    unit: "bytes",
    source: "ASTROLABE #364 real-corpus bench_row_sink_overhead.rs stack measurement (#59)",
    rationale: "the in-process CBM pipeline overflows the default 2 MiB stack before its first log line even on a 6-file corpus; 64 MiB is the measured-working reserve, and every production spawn site that enters the pipeline supplies this sized stack so a diagnostic-free STATUS_STACK_OVERFLOW cannot occur",
}];

/// Returns the CBM pipeline stack declaration for `name`, or `None`.
pub fn cbm_pipeline_stack_knob(name: &str) -> Option<&'static U64KnobDeclaration> {
    CBM_PIPELINE_STACK_KNOBS
        .iter()
        .find(|knob| knob.name == name)
}

/// The CBM pipeline host-thread stack reserve, in bytes, as a `usize` ready for
/// [`std::thread::Builder::stack_size`]. This is the single accessor every
/// production spawn site entering the pipeline uses (#364).
pub fn cbm_pipeline_host_stack_bytes() -> usize {
    usize::try_from(CBM_PIPELINE_DEFAULT_HOST_STACK_BYTES).unwrap_or(usize::MAX)
}

/// Registry version tag for the structural bridge-scope derivation knobs (#388).
pub const BRIDGE_SCOPE_KNOB_REGISTRY_VERSION: &str = "astrolabe-bridge-scope-knobs-v1";

/// Name of the bridge-scope directory-depth knob.
pub const BRIDGE_SCOPE_PATH_DEPTH_KNOB: &str = "bridge_scope_path_depth";

/// Default number of root-relative directory components that define one bridge
/// "scope" when scopes are derived from graph structure rather than explicit
/// row-sink metadata (#388).
///
/// Two components is the granularity the blueprint's cross-domain-bridge example
/// (5.11, "the shared core of frontend+backend") assumes: a single top component
/// collapses a monorepo whose whole tree lives under one directory (`crates/…`,
/// `src/…`) into a single scope with no cross-domain bridges at all, while two
/// components resolves the per-crate / per-subsystem boundary (`crates/<crate>`,
/// `src/<subsystem>`) that real cross-domain references actually cross.
pub const BRIDGE_SCOPE_DEFAULT_PATH_DEPTH: u64 = 2;
/// Smallest legal depth. Zero would place every file in one root scope, which can
/// never yield a two-scope bridge; the scope must name at least one directory.
pub const BRIDGE_SCOPE_MIN_PATH_DEPTH: u64 = 1;
/// Largest legal depth. A deep bound keeps a pathologically nested tree from
/// fragmenting every file into its own singleton scope (which also yields no
/// cross-scope bridges); eight components is far past any real module boundary.
pub const BRIDGE_SCOPE_MAX_PATH_DEPTH: u64 = 8;

/// The structural bridge-scope derivation knob registry (#388).
pub const BRIDGE_SCOPE_KNOBS: &[U64KnobDeclaration] = &[U64KnobDeclaration {
    registry_version: BRIDGE_SCOPE_KNOB_REGISTRY_VERSION,
    name: BRIDGE_SCOPE_PATH_DEPTH_KNOB,
    default: BRIDGE_SCOPE_DEFAULT_PATH_DEPTH,
    min: BRIDGE_SCOPE_MIN_PATH_DEPTH,
    max: BRIDGE_SCOPE_MAX_PATH_DEPTH,
    unit: "path_components",
    source: "ASTROLABE blueprint 5.11 (cross-domain bridges: symbols that ground two scopes at once) and #388",
    rationale: "number of root-relative directory components that name one derived bridge scope; 1 collapses a single-top-dir monorepo into one scope with no cross-domain bridges, 2 resolves the crate/subsystem boundary real references cross; bounded so neither a flat root nor a pathologically deep tree degenerates into a single scope or per-file singletons; replace with a measured module-boundary detector once one exists",
}];

/// Returns the bridge-scope declaration for `name`, or `None` when undeclared.
pub fn bridge_scope_knob(name: &str) -> Option<&'static U64KnobDeclaration> {
    BRIDGE_SCOPE_KNOBS.iter().find(|knob| knob.name == name)
}

/// The root-relative directory depth that defines one derived bridge scope, as a
/// `usize` ready for path slicing. The single accessor every structural
/// bridge-scope derivation uses (#388).
pub fn bridge_scope_path_depth() -> usize {
    usize::try_from(BRIDGE_SCOPE_DEFAULT_PATH_DEPTH).unwrap_or(2)
}

/// Registry version tag for the CLI stderr log-floor knob (#392).
pub const CLI_LOG_KNOB_REGISTRY_VERSION: &str = "astrolabe-cli-log-knobs-v1";

/// Name of the CLI stderr log-level floor knob.
pub const CLI_STDERR_LOG_LEVEL_FLOOR_KNOB: &str = "cli_stderr_log_level_floor";

/// The minimum log-severity ordinal that reaches stderr for a `cli <tool>`
/// invocation, expressed on the libcbm `CBMLogLevel` scale (`0`=debug, `1`=info,
/// `2`=warn, `3`=error, `4`=none — see `cbm/src/foundation/log.h`).
///
/// For CLI invocations stderr is reserved for warnings and errors so the
/// supported argument forms (`--args-file` / piped stdin) emit **empty** stderr
/// (#392, unblocking #377's "empty stderr for supported CLI forms" clause).
/// Server (no-arg) dispatch keeps the default INFO floor and is unaffected: this
/// floor is applied only on the CLI branch. The single ordinal is consumed by
/// both the tracing subscriber (as a `LevelFilter`) and the libcbm log level (via
/// `cbm_log_set_level`) so exactly one number decides what CLI stderr carries.
pub const CLI_STDERR_LOG_LEVEL_FLOOR_WARN: u64 = 2;
/// Smallest legal CLI stderr floor. Below WARN (i.e. INFO=1 or DEBUG=0) libcbm's
/// `mem.init`/`vmem.init` INFO lines return to stderr, which is exactly the
/// per-call noise this knob exists to remove — the same "a lower value disables
/// the protection this knob exists for" bound the FSV sampling knob enforces.
pub const CLI_STDERR_LOG_LEVEL_FLOOR_MIN: u64 = 2;
/// Largest legal CLI stderr floor: `CBM_LOG_NONE` (4), a fully silent CLI stderr.
pub const CLI_STDERR_LOG_LEVEL_FLOOR_MAX: u64 = 4;

/// The CLI stderr log-floor knob registry (#392).
pub const CLI_LOG_KNOBS: &[U64KnobDeclaration] = &[U64KnobDeclaration {
    registry_version: CLI_LOG_KNOB_REGISTRY_VERSION,
    name: CLI_STDERR_LOG_LEVEL_FLOOR_KNOB,
    default: CLI_STDERR_LOG_LEVEL_FLOOR_WARN,
    min: CLI_STDERR_LOG_LEVEL_FLOOR_MIN,
    max: CLI_STDERR_LOG_LEVEL_FLOOR_MAX,
    unit: "cbm_log_level_ordinal",
    source: "ASTROLABE #392 / cbm/src/foundation/log.h CBMLogLevel enum (debug=0..none=4); stdout is reserved for JSON-RPC, so CLI stderr carries only warn/error",
    rationale: "reserves CLI stderr for warnings and errors so the supported `--args-file`/stdin forms emit empty stderr (#392, unblocks #377); WARN=2 is the floor because INFO=1 re-admits libcbm's per-call mem.init/vmem.init lines, and NONE=4 caps at a fully silent stderr; the same ordinal drives both the tracing subscriber and cbm_log_set_level so one number decides CLI stderr contents; server (no-arg) dispatch is unaffected and keeps INFO",
}];

/// Returns the CLI stderr log-floor declaration for `name`, or `None`.
pub fn cli_log_knob(name: &str) -> Option<&'static U64KnobDeclaration> {
    CLI_LOG_KNOBS.iter().find(|knob| knob.name == name)
}

/// The CLI stderr log-level floor as a libcbm `CBMLogLevel` ordinal
/// (`0`=debug..`4`=none). This is the single accessor both the server's tracing
/// init and the bridge's `cbm_log_set_level` call read so one declared number
/// decides what a `cli <tool>` invocation writes to stderr (#392).
pub fn cli_stderr_log_level_floor() -> u32 {
    u32::try_from(CLI_STDERR_LOG_LEVEL_FLOOR_WARN).unwrap_or(2)
}
