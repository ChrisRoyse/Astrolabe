//! Expected net gain for identified intervention effects.
//!
//! Loom's materialization `pair_gain_bits` measures information value. This
//! module is deliberately separate: it combines an identified outcome effect
//! with explicit outcome value and action cost in one declared unit.

use std::collections::BTreeSet;

use calyx_core::Result;
use serde::{Deserialize, Serialize};

use crate::error::{
    CALYX_LOOM_EXPECTED_GAIN_INVALID, CALYX_LOOM_EXPECTED_GAIN_NUMERIC_INVALID, loom_error,
};

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
    /// Finite nonzero signed value of one outcome unit. Negative means lower is better.
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
    /// Explicit finite nonzero signed value per outcome unit.
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
/// Refuses duplicates, non-finite values, zero outcome values,
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
            || input.outcome_value == 0.0
            || input.action_cost < 0.0
            || input.effect_lower > input.effect
            || input.effect > input.effect_upper
        {
            return Err(invalid(format!(
                "effect {:?} has non-finite/inverted bounds, zero outcome value, or negative action cost",
                input.effect_id
            )));
        }
        let gross = finite_result(
            &input.effect_id,
            "effect * outcome_value",
            input.effect * input.outcome_value,
        )?;
        let net = finite_result(
            &input.effect_id,
            "expected_gross_gain - action_cost",
            gross - input.action_cost,
        )?;
        let first_bound = finite_result(
            &input.effect_id,
            "effect_lower * outcome_value",
            input.effect_lower * input.outcome_value,
        )?;
        let second_bound = finite_result(
            &input.effect_id,
            "effect_upper * outcome_value",
            input.effect_upper * input.outcome_value,
        )?;
        let first_net_bound = finite_result(
            &input.effect_id,
            "first transformed bound - action_cost",
            first_bound - input.action_cost,
        )?;
        let second_net_bound = finite_result(
            &input.effect_id,
            "second transformed bound - action_cost",
            second_bound - input.action_cost,
        )?;
        let (net_lower, net_upper) = if first_net_bound <= second_net_bound {
            (first_net_bound, second_net_bound)
        } else {
            (second_net_bound, first_net_bound)
        };
        if net_lower > net || net > net_upper {
            return Err(numeric_invalid(
                &input.effect_id,
                "normalized confidence bounds do not contain expected_net_gain",
            ));
        }
        let break_even = finite_result(
            &input.effect_id,
            "action_cost / outcome_value",
            input.action_cost / input.outcome_value,
        )?;
        results.push(ExpectedGain {
            schema: EXPECTED_GAIN_SCHEMA.to_string(),
            effect_id: input.effect_id.clone(),
            treatment: input.treatment.clone(),
            outcome: input.outcome.clone(),
            effect: input.effect,
            outcome_value: input.outcome_value,
            action_cost: input.action_cost,
            expected_gross_gain: gross,
            expected_net_gain: net,
            expected_net_gain_lower: net_lower,
            expected_net_gain_upper: net_upper,
            break_even_effect: break_even,
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

fn finite_result(effect_id: &str, operation: &str, value: f64) -> Result<f64> {
    if value.is_finite() {
        Ok(value)
    } else {
        Err(numeric_invalid(effect_id, operation))
    }
}

fn numeric_invalid(effect_id: &str, operation: &str) -> calyx_core::CalyxError {
    loom_error(
        CALYX_LOOM_EXPECTED_GAIN_NUMERIC_INVALID,
        format!("effect {effect_id:?} derived a non-finite value during {operation}"),
    )
}
