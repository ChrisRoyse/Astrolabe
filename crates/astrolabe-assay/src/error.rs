//! Fail-closed error type for the assay job scheduler.
//!
//! Every failure path in this crate surfaces a stable machine-readable `code`,
//! a human `message`, and a `remediation` string (standing invariant 6). There
//! is no `From<io::Error>` blanket that would let an I/O fault leak as an opaque
//! string: each fallible boundary maps its cause into one of the declared codes
//! so a caller can branch on the code rather than parse prose.

use std::fmt;

/// A stable fail-closed assay error carrying a machine-readable code.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AssayError {
    code: &'static str,
    message: String,
    remediation: &'static str,
}

impl AssayError {
    /// Builds an error from a declared code, a dynamic message, and a static remediation.
    pub fn new(code: &'static str, message: impl Into<String>, remediation: &'static str) -> Self {
        Self {
            code,
            message: message.into(),
            remediation,
        }
    }

    /// The stable machine-readable error code.
    pub fn code(&self) -> &'static str {
        self.code
    }

    /// The human-readable message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The operator remediation string.
    pub fn remediation(&self) -> &'static str {
        self.remediation
    }
}

impl fmt::Display for AssayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} (remediation: {})",
            self.code, self.message, self.remediation
        )
    }
}

impl std::error::Error for AssayError {}

/// Crate result alias.
pub type Result<T> = std::result::Result<T, AssayError>;

/// The requested sample size was zero, which cannot produce a verifiable sample.
pub const ASTRO_ASSAY_SAMPLE_SIZE_ZERO: &str = "ASTRO_ASSAY_SAMPLE_SIZE_ZERO";
/// A subject carried an empty stratum label, so it could not be partitioned.
pub const ASTRO_ASSAY_EMPTY_STRATUM: &str = "ASTRO_ASSAY_EMPTY_STRATUM";
/// The population contained a duplicate `SeriesId`, so identity is ambiguous.
pub const ASTRO_ASSAY_DUPLICATE_SUBJECT: &str = "ASTRO_ASSAY_DUPLICATE_SUBJECT";
/// A knob value fell outside its registry-declared closed interval.
pub const ASTRO_ASSAY_KNOB_OUT_OF_BOUNDS: &str = "ASTRO_ASSAY_KNOB_OUT_OF_BOUNDS";
/// A store I/O operation failed.
pub const ASTRO_ASSAY_STORE_IO: &str = "ASTRO_ASSAY_STORE_IO";
/// Persisted bytes did not read back as the value that was written (FSV failure).
pub const ASTRO_ASSAY_READBACK_MISMATCH: &str = "ASTRO_ASSAY_READBACK_MISMATCH";
/// Persisted JSON could not be parsed back into a typed value.
pub const ASTRO_ASSAY_STORE_CORRUPT: &str = "ASTRO_ASSAY_STORE_CORRUPT";
/// The background lane refused a tick because the serving p99 tripwire was tripped.
pub const ASTRO_ASSAY_SERVING_TRIPWIRE: &str = "ASTRO_ASSAY_SERVING_TRIPWIRE";
/// A deficit measurement was structurally invalid for the optimizer contract.
pub const ASTRO_ASSAY_DEFICIT_INVALID: &str = "ASTRO_ASSAY_DEFICIT_INVALID";
/// A derived-signal claim exceeded the measured `I(panel;outcome)` ceiling, which
/// the Data Processing Inequality forbids (capability 4.13).
pub const ASTRO_ASSAY_DPI_VIOLATION: &str = "ASTRO_ASSAY_DPI_VIOLATION";
/// A measurement input was malformed: row counts disagreed, an axis carried no
/// variation, or a value was non-finite.
pub const ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID: &str = "ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID";
/// A card read back from the ledger did not re-derive to the recorded value
/// (reproduce/FSV failure).
pub const ASTRO_ASSAY_REPRODUCE_MISMATCH: &str = "ASTRO_ASSAY_REPRODUCE_MISMATCH";
/// An assay-card input identity was malformed instead of being a canonical
/// lowercase 256-bit content fingerprint.
pub const ASTRO_ASSAY_INPUT_FINGERPRINT_INVALID: &str = "ASTRO_ASSAY_INPUT_FINGERPRINT_INVALID";
/// One canonical assay-card input identity resolved to more than one durable
/// payload/seed, or was already duplicated in the append-only chain.
pub const ASTRO_ASSAY_INPUT_FINGERPRINT_COLLISION: &str = "ASTRO_ASSAY_INPUT_FINGERPRINT_COLLISION";
/// A lens capability-gate input was malformed: misaligned sample vectors, a
/// non-finite measured value, or an out-of-range correlation.
pub const ASTRO_ASSAY_GATE_INPUT_INVALID: &str = "ASTRO_ASSAY_GATE_INPUT_INVALID";
/// A ledgered gate reversal targeted a sequence that is not a reversible
/// decision (missing, already reverted, or itself a reversal).
pub const ASTRO_ASSAY_GATE_REVERT_INVALID: &str = "ASTRO_ASSAY_GATE_REVERT_INVALID";
/// A per-pair calibration input was malformed: a config knob fell outside its
/// declared bounds, a score exceeded the millipoint ceiling, or persisted
/// calibration bytes failed to parse.
pub const ASTRO_ASSAY_CALIBRATION_INPUT_INVALID: &str = "ASTRO_ASSAY_CALIBRATION_INPUT_INVALID";
/// Per-pair calibration refused because the score sample was below the floor
/// observation count (too few scores to pin a distribution).
pub const ASTRO_ASSAY_CALIBRATION_BELOW_FLOOR: &str = "ASTRO_ASSAY_CALIBRATION_BELOW_FLOOR";
/// Per-pair calibration refused because the score distribution had zero spread
/// (every observation identical), so no threshold can separate an anomaly from
/// the bulk — the zero-signal negative-control case.
pub const ASTRO_ASSAY_CALIBRATION_DEGENERATE: &str = "ASTRO_ASSAY_CALIBRATION_DEGENERATE";
