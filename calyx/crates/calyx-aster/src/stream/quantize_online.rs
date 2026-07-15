//! On-the-fly slot quantization for the streaming ingest pipeline.
//!
//! Each streamed slot vector is quantized through TurboQuant using a rotation
//! seed that is *content-addressed* per `LensId + CxId` — `blake3(lens_id ||
//! cx_id)` — and never random (A25). The seed is therefore reproducible across
//! restarts: the same `(LensId, CxId, level, raw)` always yields byte-identical
//! quantized output, which is the property the FSV re-run/`xxd`-diff gate checks.

use calyx_core::{CalyxError, CxId, LensId};
use calyx_forge::ForgeError;
use calyx_forge::quant::{QuantLevel, QuantizedVec, Quantizer, TurboQuantCodec, new_seed};

/// Module-local error code: a non-finite coefficient reached the on-the-fly
/// quantizer. Fail-closed *before* quantization; the event is never written.
pub const CALYX_FORGE_INPUT_NAN: &str = "CALYX_FORGE_INPUT_NAN";

const INPUT_NAN_REMEDIATION: &str =
    "reject NaN/Inf slot vectors before on-the-fly quantization; re-emit finite coefficients";

const FORGE_FAULT_REMEDIATION: &str = "fail-closed on Forge quantization fault: reject the input or re-encode with the current rotation seed";

/// Builds a `CALYX_FORGE_INPUT_NAN` error.
pub(crate) fn input_nan_error(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: CALYX_FORGE_INPUT_NAN,
        message: message.into(),
        remediation: INPUT_NAN_REMEDIATION,
    }
}

/// Maps a Forge fault into a Calyx error, preserving the stable Forge code.
pub(crate) fn forge_to_calyx(err: ForgeError) -> CalyxError {
    CalyxError {
        code: err.code(),
        message: err.to_string(),
        remediation: FORGE_FAULT_REMEDIATION,
    }
}

/// Configuration for on-the-fly slot quantization.
#[derive(Clone, Debug, PartialEq)]
pub struct QuantizeOnlineConfig {
    /// Lens identity mixed into the content-addressed rotation seed (A25).
    pub lens_id: LensId,
    /// TurboQuant level (must be `Bits3p5` or `Bits2p5`).
    pub level: QuantLevel,
}

impl QuantizeOnlineConfig {
    /// Creates a config for `lens_id` at `level`.
    pub fn new(lens_id: LensId, level: QuantLevel) -> Self {
        Self { lens_id, level }
    }
}

/// Content-addressed rotation-seed entropy: `blake3(lens_id || cx_id)`.
///
/// Deterministic across restarts; never random (A25).
pub fn rotation_seed_entropy(lens_id: LensId, cx_id: CxId) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(lens_id.as_bytes());
    hasher.update(cx_id.as_bytes());
    *hasher.finalize().as_bytes()
}

/// Quantizes one slot vector on the fly.
///
/// Fails closed with `CALYX_FORGE_INPUT_NAN` if any coefficient is non-finite —
/// before deriving a seed or touching Forge. Otherwise derives the
/// content-addressed seed for `(lens_id, cx_id)` and TurboQuant-encodes `raw`.
pub fn quantize_slot_online(
    raw: &[f32],
    config: &QuantizeOnlineConfig,
    cx_id: CxId,
) -> Result<QuantizedVec, CalyxError> {
    if let Some(idx) = raw.iter().position(|value| !value.is_finite()) {
        return Err(input_nan_error(format!(
            "non-finite slot coefficient at index {idx}"
        )));
    }
    if raw.is_empty() {
        return Err(input_nan_error("slot vector is empty; nothing to quantize"));
    }
    let entropy = rotation_seed_entropy(config.lens_id, cx_id);
    let seed = new_seed(raw.len(), &entropy);
    let codec = TurboQuantCodec::new(seed, config.level).map_err(forge_to_calyx)?;
    codec.encode(raw).map_err(forge_to_calyx)
}
