//! Reliability-weighted ensemble blend of forecast components → `p_model` (issue #85).
//!
//! The components (kNN base rate #81, bits vote #84, oracle #83, kernel #82, structural #89) are
//! pooled in **logit space** weighted by each component's held-out reliability (a Brier-derived
//! `[0,1]` weight). Logit pooling is the log-opinion-pool: it is the reliability-weighted geometric
//! mean of odds, which stays calibrated under independent evidence and never lets one component with
//! zero reliability move the answer. Fail closed if no component carries positive reliability.

use calyx_assay::TrustTag;
use serde::{Deserialize, Serialize};

use crate::error::{PolyError, Result};
use crate::forecast::{ForecastComponent, logit, sigmoid};

/// No component carried positive reliability, so there is nothing to blend.
pub const ERR_NO_RELIABLE_COMPONENTS: &str = "CALYX_POLY_FORECAST_NO_RELIABLE_COMPONENTS";
/// The blend received an empty component set.
pub const ERR_EMPTY_BLEND: &str = "CALYX_POLY_FORECAST_EMPTY_BLEND";

/// The pooled model probability and its provenance.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BlendResult {
    /// The reliability-weighted pooled probability of YES.
    pub p_model: f64,
    /// Sum of the reliability weights that contributed.
    pub total_weight: f64,
    /// Number of components with positive reliability.
    pub contributing: usize,
    /// Trusted only if **every** contributing component was grounded on Trusted evidence.
    pub trust: TrustTag,
    /// The pooled logit before the sigmoid (auditable).
    pub pooled_logit: f64,
}

/// Blends components into a single `p_model` by reliability-weighted logit pooling. Components with
/// zero reliability are dropped (they carry no held-out skill); if none remain, fail closed.
pub fn blend_components(components: &[ForecastComponent]) -> Result<BlendResult> {
    if components.is_empty() {
        return Err(PolyError::diagnostics(
            ERR_EMPTY_BLEND,
            "ensemble blend requires at least one component",
        ));
    }
    let mut weighted_logit = 0.0;
    let mut total_weight = 0.0;
    let mut contributing = 0usize;
    let mut all_trusted = true;
    for c in components {
        if c.reliability <= 0.0 {
            continue;
        }
        weighted_logit += c.reliability * logit(c.p);
        total_weight += c.reliability;
        contributing += 1;
        if c.trust != TrustTag::Trusted {
            all_trusted = false;
        }
    }
    if total_weight <= 0.0 || contributing == 0 {
        return Err(PolyError::diagnostics(
            ERR_NO_RELIABLE_COMPONENTS,
            "no forecast component carried positive held-out reliability",
        ));
    }
    let pooled_logit = weighted_logit / total_weight;
    Ok(BlendResult {
        p_model: sigmoid(pooled_logit),
        total_weight,
        contributing,
        trust: if all_trusted {
            TrustTag::Trusted
        } else {
            TrustTag::Provisional
        },
        pooled_logit,
    })
}
