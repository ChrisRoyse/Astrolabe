//! Cross-crate hook for scheduling a debounced lowered-SQLite regeneration.
//!
//! A production-path weave run (`astrolabe-weave`: similarity graphs #20,
//! cross-terms #21, reactive triggers #22) mutates vault state the lowered
//! SQLite artifact (`astrolabe-lower`) derives from. The weave crate must be
//! able to ask for a regeneration without depending on the lowering crate, and
//! the lowering coordinator must be able to receive that request without
//! depending on weave. This trait, owned by the identity spine both crates
//! already depend on, is the seam: weave calls it, `astrolabe-lower`'s debouncer
//! implements it. (#225)
//!
//! The contract is *debounced*: a single call does not force a regeneration.
//! Implementors coalesce a burst of calls into one regeneration within the
//! registry-declared window ([`crate::knobs::LOWER_DEBOUNCE_WINDOW_MS_KNOB`]),
//! so N rapid weave mutations settle into one lowered-SQLite rewrite.

/// A sink for "vault state the lowered artifact derives from just changed".
///
/// The weave mutation paths call [`LoweringTrigger::request_regeneration`] after
/// a commit that changed derived content. The implementor is responsible for
/// coalescing (debouncing) these requests; a caller must not assume one call
/// maps to one regeneration.
pub trait LoweringTrigger: Send + Sync {
    /// Records that a weave mutation changed vault state the lowered SQLite
    /// artifact derives from, arming a debounced regeneration.
    ///
    /// This is a non-blocking signal: it never performs the regeneration inline.
    /// The implementor coalesces a burst of these calls into one regeneration
    /// once the debounce window elapses quietly.
    fn request_regeneration(&self);
}
