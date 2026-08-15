//! Expected net gain for identified intervention effects.
//!
//! Loom's materialization `pair_gain_bits` measures information value. This
//! module is deliberately separate: it combines an identified outcome effect
//! with explicit outcome value and action cost in one declared unit.

use std::collections::BTreeSet;

use calyx_core::Result;
use serde::{Deserialize, Serialize};

use crate::error::{CALYX_LOOM_EXPECTED_GAIN_INVALID, loom_error};

/// Wire schema for the compact expected-gain kernel.
pub const EXPECTED_GAIN_SCHEMA: &str = "calyx.loom.expected_gain.v1";

/// One identified effect plus explicit decision economics.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExpectedGainInput {
    /// Stable causal-effect identity.
    pub effect_id: String,
    /// Binary treatment variable.
    pub treatment: String,
    /// Numeric outcome variable.
    pub outcome: String,
    /// Identified average treatment effect.
    pub effect: f64,
    /// Lower effect confidence bound.
    pub effect_lower: f64,
    /// Upper effect confidence bound.
    pub effect_upper: f64,
    /// Value of one outcome unit; must be positive and finite.
    pub outcome_value: f64,
    /// Cost of applying the treatment; must be nonnegative and finite.
    pub action_cost: f64,
    /// Non-empty shared unit for value, cost, and expected gain.
    pub unit: String,
}

/// One fully calculated expected-gain result.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExpectedGain {
    /// Result schema.
    pub schema: String,
    /// Stable causal-effect identity.
    pub effect_id: String,
    /// Binary treatment variable.
    pub treatment: String,
    /// Numeric outcome variable.
    pub outcome: String,
    /// Identified average treatment effect.
    pub effect: f64,
    /// Explicit value per outcome unit.
    pub outcome_value: f64,
    /// Explicit action cost.
    pub action_cost: f64,
    /// Expected gross gain (`effect * outcome_value`).
    pub expected_gross_gain: f64,
    /// Expected net gain (`gross gain - action cost`).
    pub expected_net_gain: f64,
    /// Lower net-gain confidence bound.
    pub expected_net_gain_lower: f64,
    /// Upper net-gain confidence bound.
    pub expected_net_gain_upper: f64,
    /// Treatment effect required to break even.
    pub break_even_effect: f64,
    /// Shared value/cost/gain unit.
    pub unit: String,
    /// Deterministic one-based rank by descending expected net gain among results
    /// carrying this exact unit. Values with different units are never compared.
    pub rank_within_unit: usize,
}

/// Calculates and deterministically ranks expected net gain for every input.
///
/// # Errors
///
/// Refuses duplicates, non-finite values, non-positive outcome values,
/// negative costs, inverted effect bounds, or empty identities/units.
pub fn calculate_expected_gains(inputs: &[ExpectedGainInput]) -> Result<Vec<ExpectedGain>> {
    if inputs.is_empty() {
        return Err(invalid("expected-gain inputs must not be empty"));
    }
    let mut identities = BTreeSet::new();
    let mut results = Vec::with_capacity(inputs.len());
    for input in inputs {
        if input.effect_id.trim().is_empty()
            || input.effect_id.trim() != input.effect_id
            || input.treatment.trim().is_empty()
            || input.treatment.trim() != input.treatment
            || input.outcome.trim().is_empty()
            || input.outcome.trim() != input.outcome
            || input.unit.trim().is_empty()
            || input.unit.trim() != input.unit
        {
            return Err(invalid(
                "effect, treatment, outcome, and unit must be non-empty and have no surrounding whitespace",
            ));
        }
        if !identities.insert(input.effect_id.clone()) {
            return Err(invalid(format!(
                "duplicate expected-gain effect_id {:?}",
                input.effect_id
            )));
        }
        if [
            input.effect,
            input.effect_lower,
            input.effect_upper,
            input.outcome_value,
            input.action_cost,
        ]
        .iter()
        .any(|value| !value.is_finite())
            || input.outcome_value <= 0.0
            || input.action_cost < 0.0
            || input.effect_lower > input.effect
            || input.effect > input.effect_upper
        {
            return Err(invalid(format!(
                "effect {:?} has non-finite/inverted bounds, non-positive outcome value, or negative action cost",
                input.effect_id
            )));
        }
        let gross = input.effect * input.outcome_value;
        results.push(ExpectedGain {
            schema: EXPECTED_GAIN_SCHEMA.to_string(),
            effect_id: input.effect_id.clone(),
            treatment: input.treatment.clone(),
            outcome: input.outcome.clone(),
            effect: input.effect,
            outcome_value: input.outcome_value,
            action_cost: input.action_cost,
            expected_gross_gain: gross,
            expected_net_gain: gross - input.action_cost,
            expected_net_gain_lower: input.effect_lower * input.outcome_value - input.action_cost,
            expected_net_gain_upper: input.effect_upper * input.outcome_value - input.action_cost,
            break_even_effect: input.action_cost / input.outcome_value,
            unit: input.unit.clone(),
            rank_within_unit: 0,
        });
    }
    results.sort_by(|left, right| {
        left.unit
            .cmp(&right.unit)
            .then_with(|| right.expected_net_gain.total_cmp(&left.expected_net_gain))
            .then_with(|| left.effect_id.cmp(&right.effect_id))
    });
    let mut previous_unit: Option<String> = None;
    let mut rank = 0usize;
    for result in &mut results {
        if previous_unit.as_deref() == Some(result.unit.as_str()) {
            rank += 1;
        } else {
            previous_unit = Some(result.unit.clone());
            rank = 1;
        }
        result.rank_within_unit = rank;
    }
    Ok(results)
}

fn invalid(message: impl Into<String>) -> calyx_core::CalyxError {
    loom_error(CALYX_LOOM_EXPECTED_GAIN_INVALID, message)
}
