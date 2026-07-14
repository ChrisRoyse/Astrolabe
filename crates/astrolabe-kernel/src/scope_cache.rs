//! Scoped kernel builds, the scope cache, standing-kernel refresh triggers, and
//! freshness honesty (#38).
//!
//! A scoped kernel is a full kernel built over the induced subgraph a [`Scope`]
//! selects. The [`KernelCache`] keys artifacts by
//! `(scope_hash, panel_version, anchor_identity, corpus_identity)` and is
//! invalidated on a panel bump or a dirty region. [`StandingKernelPolicy`]
//! decides when a background-lane standing kernel refreshes — on N dirty
//! symbols, a panel bump, or a nightly tick, whichever fires first — and
//! [`decide_freshness`] governs honest StaleOk-vs-`fresh:true` serving.

use std::collections::BTreeMap;

use crate::U64KnobDeclaration;
use crate::kernel_build::{KernelArtifact, KernelBuildConfig, build_kernel};
use crate::kernel_graph::KernelGraph;
use crate::scope::{Scope, ScopeAttributes, induced_subgraph};

/// Knob registry version for standing-kernel refresh policy.
pub const STANDING_KERNEL_KNOB_REGISTRY_VERSION: &str = "astro.kernel.standing_knobs.v1";
/// Knob: dirty-symbol count that triggers a standing-kernel refresh.
pub const KNOB_STANDING_DIRTY_THRESHOLD: &str = "kernel.standing.dirty_threshold";
/// Knob: nightly-tick interval in seconds.
pub const KNOB_STANDING_NIGHTLY_SECS: &str = "kernel.standing.nightly_interval_secs";

const STANDING_SOURCE: &str = "docs/astrolabe-blueprint.md#09-the-kernel--context-engine";

/// Standing-kernel refresh-policy knobs.
pub const STANDING_KERNEL_KNOBS: &[U64KnobDeclaration] = &[
    U64KnobDeclaration {
        registry_version: STANDING_KERNEL_KNOB_REGISTRY_VERSION,
        name: KNOB_STANDING_DIRTY_THRESHOLD,
        default: 200,
        min: 1,
        max: 1_000_000_000,
        unit: "symbols",
        source: STANDING_SOURCE,
        rationale: "refresh a standing kernel after this many dirty symbols accumulate",
    },
    U64KnobDeclaration {
        registry_version: STANDING_KERNEL_KNOB_REGISTRY_VERSION,
        name: KNOB_STANDING_NIGHTLY_SECS,
        default: 86_400,
        min: 1,
        max: 1_000_000_000,
        unit: "seconds",
        source: STANDING_SOURCE,
        rationale: "nightly refresh cadence for a standing kernel absent other triggers",
    },
];

fn standing_knob_default(name: &str) -> u64 {
    STANDING_KERNEL_KNOBS
        .iter()
        .find(|knob| knob.name == name)
        .expect("standing kernel knob is declared")
        .default
}

/// Builds a scoped kernel over the subgraph a scope selects.
///
/// Returns the artifact (its `scope_id` is the scope hash) and the scope hash.
/// A scope selecting no symbols yields the empty-graph refusal from
/// [`build_kernel`], surfaced to the caller unchanged.
pub fn build_scoped_kernel(
    graph: &KernelGraph,
    attrs: &ScopeAttributes,
    scope: &Scope,
    config: &KernelBuildConfig,
) -> astrolabe_domain::Result<(KernelArtifact, String)> {
    let indexed = graph.compile()?;
    let members = scope.resolve(&indexed, attrs);
    let subgraph = induced_subgraph(graph, &members)?;
    let scope_hash = scope.scope_hash();
    let artifact = build_kernel(&subgraph, &scope_hash, config)?;
    Ok((artifact, scope_hash))
}

/// The full cache key for a persisted scoped kernel.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CacheKey {
    /// Stable scope-tree hash.
    pub scope_hash: String,
    /// Panel version in force at build time.
    pub panel_version: u32,
    /// Identity of the anchor set the kernel was grounded against.
    pub anchor_identity: String,
    /// Identity of the corpus the kernel was built from.
    pub corpus_identity: String,
}

/// An in-memory scope cache with hit/miss/invalidation instrumentation.
#[derive(Clone, Debug, Default)]
pub struct KernelCache {
    entries: BTreeMap<CacheKey, Vec<u8>>,
    hits: u64,
    misses: u64,
    invalidations: u64,
}

impl KernelCache {
    /// Creates an empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts (or replaces) the artifact bytes for a key.
    pub fn insert(&mut self, key: CacheKey, kernel_json: Vec<u8>) {
        self.entries.insert(key, kernel_json);
    }

    /// Fetches artifact bytes, counting the hit or miss. A hit always serves the
    /// exact bytes that were inserted.
    pub fn get(&mut self, key: &CacheKey) -> Option<Vec<u8>> {
        match self.entries.get(key) {
            Some(bytes) => {
                self.hits += 1;
                Some(bytes.clone())
            }
            None => {
                self.misses += 1;
                None
            }
        }
    }

    /// Number of cached entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Cache hit count.
    pub fn hits(&self) -> u64 {
        self.hits
    }

    /// Cache miss count.
    pub fn misses(&self) -> u64 {
        self.misses
    }

    /// Total entries evicted by invalidation.
    pub fn invalidations(&self) -> u64 {
        self.invalidations
    }

    /// Invalidates every entry whose panel version differs from the new bump,
    /// returning the count evicted. A panel bump changes symbol identity, so no
    /// prior-version entry can be served.
    pub fn invalidate_on_panel_bump(&mut self, new_panel_version: u32) -> usize {
        self.invalidate_where(|key| key.panel_version != new_panel_version)
    }

    /// Invalidates exactly the entries whose key matches `predicate` (e.g. a
    /// dirty region touching specific scope hashes), returning the count evicted.
    pub fn invalidate_where(&mut self, predicate: impl Fn(&CacheKey) -> bool) -> usize {
        let doomed: Vec<CacheKey> = self
            .entries
            .keys()
            .filter(|key| predicate(key))
            .cloned()
            .collect();
        for key in &doomed {
            self.entries.remove(key);
        }
        self.invalidations += doomed.len() as u64;
        doomed.len()
    }
}

/// Why a standing kernel refreshed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefreshReason {
    /// The panel version bumped since the last build.
    PanelBump,
    /// The dirty-symbol count reached the threshold.
    DirtyThreshold,
    /// The nightly cadence elapsed.
    NightlyTick,
}

impl RefreshReason {
    /// Stable label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PanelBump => "panel_bump",
            Self::DirtyThreshold => "dirty_threshold",
            Self::NightlyTick => "nightly_tick",
        }
    }
}

/// Refresh policy for a background-lane standing kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StandingKernelPolicy {
    /// Dirty-symbol count that forces a refresh.
    pub dirty_threshold: u64,
    /// Nightly cadence in seconds.
    pub nightly_interval_secs: u64,
    /// Panel version at the last refresh.
    pub last_panel_version: u32,
    /// Wall-clock (injected) of the last refresh.
    pub last_refresh_time: u64,
}

impl StandingKernelPolicy {
    /// Builds a policy with registry-default thresholds seeded at a build point.
    pub fn with_registry_defaults(last_panel_version: u32, last_refresh_time: u64) -> Self {
        Self {
            dirty_threshold: standing_knob_default(KNOB_STANDING_DIRTY_THRESHOLD),
            nightly_interval_secs: standing_knob_default(KNOB_STANDING_NIGHTLY_SECS),
            last_panel_version,
            last_refresh_time,
        }
    }

    /// Decides whether to refresh, given the current clock, panel version, and
    /// dirty count. Returns the first trigger that fires, checked panel-bump →
    /// dirty-threshold → nightly-tick.
    pub fn evaluate(
        &self,
        now: u64,
        panel_version: u32,
        dirty_count: u64,
    ) -> Option<RefreshReason> {
        if panel_version != self.last_panel_version {
            return Some(RefreshReason::PanelBump);
        }
        if dirty_count >= self.dirty_threshold {
            return Some(RefreshReason::DirtyThreshold);
        }
        if now.saturating_sub(self.last_refresh_time) >= self.nightly_interval_secs {
            return Some(RefreshReason::NightlyTick);
        }
        None
    }

    /// Records a completed refresh at `now` for `panel_version`, clearing the
    /// staleness clock.
    pub fn mark_refreshed(&mut self, now: u64, panel_version: u32) {
        self.last_refresh_time = now;
        self.last_panel_version = panel_version;
    }
}

/// Honest serving decision for a possibly-stale standing kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FreshnessDecision {
    /// The cached kernel is converged; serve it as fresh.
    Fresh,
    /// Served under the default StaleOk policy with a truthful staleness lag.
    StaleOk {
        /// Dirty symbols accumulated since the kernel was built.
        stale_by: u64,
    },
    /// `fresh:true` forced a synchronous rebuild that converged within budget.
    Rebuilt,
    /// `fresh:true` could not converge within the budget; an honest timeout.
    Timeout {
        /// Convergence budget that was exhausted.
        budget: u64,
    },
}

/// Governs StaleOk-by-default vs `fresh:true` serving.
///
/// A converged kernel (`dirty_count == 0`) is always [`FreshnessDecision::Fresh`].
/// While dirty, the default StaleOk path serves the cached kernel labelled with
/// the exact `stale_by` lag; `fresh:true` forces a rebuild, returning
/// [`FreshnessDecision::Rebuilt`] when the convergence budget allows and an
/// honest [`FreshnessDecision::Timeout`] when it does not.
pub fn decide_freshness(
    dirty_count: u64,
    request_fresh: bool,
    converge_budget: u64,
) -> FreshnessDecision {
    if dirty_count == 0 {
        return FreshnessDecision::Fresh;
    }
    if !request_fresh {
        return FreshnessDecision::StaleOk {
            stale_by: dirty_count,
        };
    }
    if converge_budget > 0 {
        FreshnessDecision::Rebuilt
    } else {
        FreshnessDecision::Timeout { budget: 0 }
    }
}
