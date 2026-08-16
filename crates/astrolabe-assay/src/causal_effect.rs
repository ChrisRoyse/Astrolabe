//! Identifiable observational causal-effect estimation.
//!
//! This module deliberately separates association from causation. It enumerates
//! the caller's complete treatment/outcome universe, reports the unadjusted
//! association for every pair, and promotes an adjusted average treatment
//! effect only after the caller explicitly confirms the identifying assumptions
//! and every observed categorical stratum has both treatment arms with adequate
//! empirical propensity. The estimator is the saturated discrete-strata AIPW
//! estimator; no regression model, imputation, or extrapolating fallback exists.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::error::{
    ASTRO_ASSAY_CAUSAL_INPUT_INVALID, ASTRO_ASSAY_CAUSAL_NOT_IDENTIFIABLE,
    ASTRO_ASSAY_CAUSAL_NUMERIC_INVALID, AssayError, Result,
};
use crate::stats::inverse_standard_normal_cdf;

/// Wire schema for one persisted causal-effect artifact.
pub const CAUSAL_EFFECT_SCHEMA: &str = "astrolabe.assay.causal_effect.v1";

/// Identifying assumptions that must be explicitly confirmed for every effect.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CausalAssumption {
    /// Each observed outcome agrees with the potential outcome for the action received.
    Consistency,
    /// The declared adjustment set blocks treatment/outcome confounding.
    ConditionalExchangeability,
    /// Every adjustment stratum has nonzero probability of either treatment arm.
    Positivity,
    /// One observation's treatment does not change another observation's outcome.
    NoInterference,
}

impl CausalAssumption {
    fn required() -> BTreeSet<Self> {
        [
            Self::Consistency,
            Self::ConditionalExchangeability,
            Self::Positivity,
            Self::NoInterference,
        ]
        .into_iter()
        .collect()
    }
}

/// One real observational row supplied to the estimator.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CausalObservation {
    /// Stable non-empty identity used to canonicalize row order and reject duplicates.
    pub row_id: String,
    /// Numeric variables. Treatments must be exactly 0 or 1; outcomes must be finite.
    pub values: BTreeMap<String, f64>,
    /// Categorical adjustment variables. Values are exact labels, never embedded or binned.
    #[serde(default)]
    pub strata: BTreeMap<String, String>,
}

/// One treatment/outcome pair and the categorical backdoor adjustment set asserted for it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CausalPairSpec {
    /// Binary treatment variable name.
    pub treatment: String,
    /// Numeric outcome variable name.
    pub outcome: String,
    /// Exact categorical variables asserted to satisfy conditional exchangeability.
    pub adjustment_set: Vec<String>,
}

/// Caller-declared estimator controls; none is silently defaulted.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct CausalAnalysisConfig {
    /// Smallest admitted empirical propensity in any stratum, in `(0, 0.5]`.
    pub minimum_propensity: f64,
    /// Smallest admitted observation count per treatment arm and stratum; must be at least two.
    pub minimum_arm_count: usize,
    /// Two-sided normal confidence level in `[0.5, 0.999]`.
    pub confidence_level: f64,
}

/// Complete input for one deterministic all-pairs causal-effect generation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CausalAnalysisInput {
    /// Real observation rows. The implementation canonicalizes them by `row_id`.
    pub observations: Vec<CausalObservation>,
    /// Complete roster of binary treatment variables.
    pub treatments: Vec<String>,
    /// Complete roster of numeric outcome variables.
    pub outcomes: Vec<String>,
    /// Exactly one adjustment specification for every treatment × outcome pair.
    pub pairs: Vec<CausalPairSpec>,
    /// Explicit confirmation of every required identifying assumption.
    pub assumptions: Vec<CausalAssumption>,
    /// Strict overlap and confidence controls.
    pub config: CausalAnalysisConfig,
}

/// Empirical support and outcome means for one categorical adjustment stratum.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CausalStratumDiagnostic {
    /// Canonical `variable=value` labels in adjustment-set order.
    pub labels: Vec<String>,
    /// Total observations in the stratum.
    pub observations: usize,
    /// Untreated observations in the stratum.
    pub control_count: usize,
    /// Treated observations in the stratum.
    pub treated_count: usize,
    /// Empirical treatment propensity.
    pub propensity: f64,
    /// Mean outcome among untreated rows.
    pub control_mean: f64,
    /// Mean outcome among treated rows.
    pub treated_mean: f64,
}

/// One association plus its identified adjusted causal effect.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CausalEffectEstimate {
    /// Stable pair identity (`treatment=>outcome`).
    pub effect_id: String,
    /// Binary treatment variable.
    pub treatment: String,
    /// Numeric outcome variable.
    pub outcome: String,
    /// Exact categorical backdoor adjustment set.
    pub adjustment_set: Vec<String>,
    /// Unadjusted treated-minus-control mean difference: association, not causation.
    pub unadjusted_association: f64,
    /// Saturated discrete-strata AIPW average treatment effect.
    pub average_treatment_effect: f64,
    /// Difference between adjusted effect and unadjusted association.
    pub confounding_adjustment: f64,
    /// Influence-function standard error.
    pub standard_error: f64,
    /// Two-sided lower confidence bound.
    pub confidence_lower: f64,
    /// Two-sided upper confidence bound.
    pub confidence_upper: f64,
    /// Confidence level used for the bounds.
    pub confidence_level: f64,
    /// Smallest empirical propensity or complementary propensity observed.
    pub minimum_observed_overlap: f64,
    /// Per-stratum support readback.
    pub strata: Vec<CausalStratumDiagnostic>,
    /// Explicit identifiability verdict. Successful estimates are always `identified_backdoor`.
    pub identifiability: String,
    /// Evidence class separating an identified effect from predictive association.
    pub evidence_kind: String,
}

/// Canonical, reproducible result for the complete requested pair universe.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CausalEffectArtifact {
    /// Artifact schema.
    pub schema: String,
    /// Canonical observations sorted by row identity; this is the reproducibility source.
    pub observations: Vec<CausalObservation>,
    /// Canonical treatment roster.
    pub treatments: Vec<String>,
    /// Canonical outcome roster.
    pub outcomes: Vec<String>,
    /// Canonical required assumptions.
    pub assumptions: Vec<CausalAssumption>,
    /// Estimator controls.
    pub config: CausalAnalysisConfig,
    /// One estimate for every treatment × outcome pair.
    pub effects: Vec<CausalEffectEstimate>,
    /// Number of canonical observation rows.
    pub observation_count: usize,
    /// Number of requested and produced pairs.
    pub pair_count: usize,
}

#[derive(Default)]
struct StratumAccum {
    control_count: usize,
    treated_count: usize,
    control_sum: f64,
    treated_sum: f64,
}

/// Estimates every declared treatment × outcome pair without omission.
///
/// # Errors
///
/// Refuses malformed rosters/rows/assumptions and any pair whose empirical
/// adjustment strata cannot support the declared positivity boundary. No
/// partial artifact is returned.
pub fn estimate_causal_effects(input: &CausalAnalysisInput) -> Result<CausalEffectArtifact> {
    validate_config(input.config)?;
    let assumptions = canonical_assumptions(&input.assumptions)?;
    let observations = canonical_observations(&input.observations)?;
    let treatments = canonical_names("treatment", &input.treatments)?;
    let outcomes = canonical_names("outcome", &input.outcomes)?;
    let pairs = canonical_pairs(&treatments, &outcomes, &input.pairs)?;

    let mut effects = Vec::with_capacity(pairs.len());
    for pair in &pairs {
        effects.push(estimate_pair(&observations, pair, input.config)?);
    }
    Ok(CausalEffectArtifact {
        schema: CAUSAL_EFFECT_SCHEMA.to_string(),
        observation_count: observations.len(),
        pair_count: effects.len(),
        observations,
        treatments,
        outcomes,
        assumptions,
        config: input.config,
        effects,
    })
}

fn validate_config(config: CausalAnalysisConfig) -> Result<()> {
    if !config.minimum_propensity.is_finite()
        || config.minimum_propensity <= 0.0
        || config.minimum_propensity > 0.5
    {
        return Err(invalid("minimum_propensity must be finite and in (0, 0.5]"));
    }
    if config.minimum_arm_count < 2 {
        return Err(invalid(
            "minimum_arm_count must be at least 2 so within-arm uncertainty is observable",
        ));
    }
    if !config.confidence_level.is_finite() || !(0.5..=0.999).contains(&config.confidence_level) {
        return Err(invalid(
            "confidence_level must be finite and in [0.5, 0.999]",
        ));
    }
    Ok(())
}

fn canonical_assumptions(values: &[CausalAssumption]) -> Result<Vec<CausalAssumption>> {
    let actual = values.iter().copied().collect::<BTreeSet<_>>();
    if actual.len() != values.len() || actual != CausalAssumption::required() {
        return Err(invalid(
            "assumptions must contain consistency, conditional_exchangeability, positivity, and no_interference exactly once",
        ));
    }
    Ok(actual.into_iter().collect())
}

fn canonical_observations(values: &[CausalObservation]) -> Result<Vec<CausalObservation>> {
    if values.is_empty() {
        return Err(invalid("observations must not be empty"));
    }
    let mut canonical = values.to_vec();
    canonical.sort_by(|left, right| left.row_id.cmp(&right.row_id));
    for (ordinal, row) in canonical.iter().enumerate() {
        if row.row_id.trim().is_empty() || row.row_id.trim() != row.row_id {
            return Err(invalid(format!(
                "observation {ordinal} has an empty or whitespace-padded row_id"
            )));
        }
        if ordinal > 0 && canonical[ordinal - 1].row_id == row.row_id {
            return Err(invalid(format!(
                "duplicate observation row_id {:?}",
                row.row_id
            )));
        }
        if let Some((name, _)) = row.values.iter().find(|(name, value)| {
            name.trim().is_empty() || name.trim() != *name || !value.is_finite()
        }) {
            return Err(invalid(format!(
                "observation {:?} has an empty or non-finite numeric variable {:?}",
                row.row_id, name
            )));
        }
        if let Some((name, _)) = row.strata.iter().find(|(name, value)| {
            name.trim().is_empty()
                || name.trim() != *name
                || value.trim().is_empty()
                || value.trim() != *value
        }) {
            return Err(invalid(format!(
                "observation {:?} has an empty categorical variable or value at {:?}",
                row.row_id, name
            )));
        }
    }
    Ok(canonical)
}

fn canonical_names(kind: &str, values: &[String]) -> Result<Vec<String>> {
    if values.is_empty() {
        return Err(invalid(format!("{kind} roster must not be empty")));
    }
    let mut canonical = values.to_vec();
    canonical.sort();
    if canonical
        .iter()
        .any(|value| value.trim().is_empty() || value.trim() != value)
    {
        return Err(invalid(format!(
            "{kind} names must be non-empty and have no surrounding whitespace"
        )));
    }
    if canonical.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(invalid(format!("{kind} roster contains a duplicate")));
    }
    Ok(canonical)
}

fn canonical_pairs(
    treatments: &[String],
    outcomes: &[String],
    values: &[CausalPairSpec],
) -> Result<Vec<CausalPairSpec>> {
    let expected = treatments
        .len()
        .checked_mul(outcomes.len())
        .ok_or_else(|| invalid("treatment × outcome pair count overflows the platform size"))?;
    if values.len() != expected {
        return Err(invalid(format!(
            "pairs must cover every treatment × outcome combination exactly once: expected {expected}, received {}",
            values.len()
        )));
    }
    let treatment_set = treatments.iter().collect::<BTreeSet<_>>();
    let outcome_set = outcomes.iter().collect::<BTreeSet<_>>();
    let mut canonical = values.to_vec();
    for pair in &mut canonical {
        if pair.treatment == pair.outcome
            || !treatment_set.contains(&pair.treatment)
            || !outcome_set.contains(&pair.outcome)
        {
            return Err(invalid(format!(
                "pair {}=>{} is outside the declared treatment/outcome universe",
                pair.treatment, pair.outcome
            )));
        }
        pair.adjustment_set.sort();
        if pair.adjustment_set.iter().any(|name| {
            name.trim().is_empty()
                || name.trim() != name
                || name == &pair.treatment
                || name == &pair.outcome
        }) || pair
            .adjustment_set
            .windows(2)
            .any(|names| names[0] == names[1])
        {
            return Err(invalid(format!(
                "pair {}=>{} has an empty, duplicate, treatment, or outcome adjustment variable",
                pair.treatment, pair.outcome
            )));
        }
    }
    canonical.sort_by(|left, right| {
        (&left.treatment, &left.outcome).cmp(&(&right.treatment, &right.outcome))
    });
    if canonical.windows(2).any(|pairs| {
        pairs[0].treatment == pairs[1].treatment && pairs[0].outcome == pairs[1].outcome
    }) {
        return Err(invalid(
            "pairs contain a duplicate treatment/outcome combination",
        ));
    }
    let actual = canonical
        .iter()
        .map(|pair| (&pair.treatment, &pair.outcome))
        .collect::<BTreeSet<_>>();
    for treatment in treatments {
        for outcome in outcomes {
            if !actual.contains(&(treatment, outcome)) {
                return Err(invalid(format!("missing pair {treatment}=>{outcome}")));
            }
        }
    }
    Ok(canonical)
}

fn estimate_pair(
    observations: &[CausalObservation],
    pair: &CausalPairSpec,
    config: CausalAnalysisConfig,
) -> Result<CausalEffectEstimate> {
    let mut strata = BTreeMap::<Vec<String>, StratumAccum>::new();
    let mut control_sum = 0.0;
    let mut treated_sum = 0.0;
    let mut control_count = 0usize;
    let mut treated_count = 0usize;
    for row in observations {
        let treatment = row.values.get(&pair.treatment).ok_or_else(|| {
            invalid(format!(
                "observation {:?} is missing treatment {:?}",
                row.row_id, pair.treatment
            ))
        })?;
        if *treatment != 0.0 && *treatment != 1.0 {
            return Err(invalid(format!(
                "observation {:?} treatment {:?} must be exactly 0 or 1",
                row.row_id, pair.treatment
            )));
        }
        let outcome = *row.values.get(&pair.outcome).ok_or_else(|| {
            invalid(format!(
                "observation {:?} is missing outcome {:?}",
                row.row_id, pair.outcome
            ))
        })?;
        let key = pair
            .adjustment_set
            .iter()
            .map(|name| {
                row.strata
                    .get(name)
                    .map(|value| format!("{name}={value}"))
                    .ok_or_else(|| {
                        invalid(format!(
                            "observation {:?} is missing adjustment stratum {:?}",
                            row.row_id, name
                        ))
                    })
            })
            .collect::<Result<Vec<_>>>()?;
        let accumulator = strata.entry(key).or_default();
        if *treatment == 1.0 {
            accumulator.treated_count = checked_count(
                pair,
                "stratum treated count increment",
                || row_stratum_location(pair, row),
                accumulator.treated_count,
            )?;
            accumulator.treated_sum = finite_derived(
                pair,
                "stratum treated outcome accumulation",
                || row_stratum_location(pair, row),
                accumulator.treated_sum + outcome,
            )?;
            treated_count = checked_count(
                pair,
                "complete-sample treated count increment",
                || format!("row {:?}", row.row_id),
                treated_count,
            )?;
            treated_sum = finite_derived(
                pair,
                "complete-sample treated outcome accumulation",
                || format!("row {:?}", row.row_id),
                treated_sum + outcome,
            )?;
        } else {
            accumulator.control_count = checked_count(
                pair,
                "stratum control count increment",
                || row_stratum_location(pair, row),
                accumulator.control_count,
            )?;
            accumulator.control_sum = finite_derived(
                pair,
                "stratum control outcome accumulation",
                || row_stratum_location(pair, row),
                accumulator.control_sum + outcome,
            )?;
            control_count = checked_count(
                pair,
                "complete-sample control count increment",
                || format!("row {:?}", row.row_id),
                control_count,
            )?;
            control_sum = finite_derived(
                pair,
                "complete-sample control outcome accumulation",
                || format!("row {:?}", row.row_id),
                control_sum + outcome,
            )?;
        }
    }
    if control_count == 0 || treated_count == 0 {
        return Err(not_identifiable(
            pair,
            "the complete sample is missing one treatment arm",
        ));
    }

    let mut diagnostics = Vec::with_capacity(strata.len());
    let mut minimum_overlap = 0.5_f64;
    for (labels, accumulator) in &strata {
        if accumulator.control_count < config.minimum_arm_count
            || accumulator.treated_count < config.minimum_arm_count
        {
            return Err(not_identifiable(
                pair,
                format!(
                    "stratum {:?} has control={} treated={}, below minimum_arm_count={}",
                    labels,
                    accumulator.control_count,
                    accumulator.treated_count,
                    config.minimum_arm_count
                ),
            ));
        }
        let count = accumulator
            .control_count
            .checked_add(accumulator.treated_count)
            .ok_or_else(|| {
                numeric_error(pair, "stratum total count addition", || {
                    format!("stratum {labels:?}")
                })
            })?;
        let propensity = finite_derived(
            pair,
            "empirical propensity division",
            || format!("stratum {labels:?}"),
            accumulator.treated_count as f64 / count as f64,
        )?;
        let complementary_propensity = finite_derived(
            pair,
            "complementary propensity subtraction",
            || format!("stratum {labels:?}"),
            1.0 - propensity,
        )?;
        let overlap = finite_derived(
            pair,
            "minimum overlap selection",
            || format!("stratum {labels:?}"),
            propensity.min(complementary_propensity),
        )?;
        if overlap < config.minimum_propensity {
            return Err(not_identifiable(
                pair,
                format!(
                    "stratum {:?} empirical overlap {overlap} is below minimum_propensity {}",
                    labels, config.minimum_propensity
                ),
            ));
        }
        minimum_overlap = minimum_overlap.min(overlap);
        let control_mean = finite_derived(
            pair,
            "control mean division",
            || format!("stratum {labels:?}"),
            accumulator.control_sum / accumulator.control_count as f64,
        )?;
        let treated_mean = finite_derived(
            pair,
            "treated mean division",
            || format!("stratum {labels:?}"),
            accumulator.treated_sum / accumulator.treated_count as f64,
        )?;
        diagnostics.push(CausalStratumDiagnostic {
            labels: labels.clone(),
            observations: count,
            control_count: accumulator.control_count,
            treated_count: accumulator.treated_count,
            propensity,
            control_mean,
            treated_mean,
        });
    }

    let lookup = diagnostics
        .iter()
        .map(|diagnostic| (diagnostic.labels.clone(), diagnostic))
        .collect::<BTreeMap<_, _>>();
    let mut influence = Vec::with_capacity(observations.len());
    for row in observations {
        let labels = pair
            .adjustment_set
            .iter()
            .map(|name| format!("{name}={}", row.strata[name]))
            .collect::<Vec<_>>();
        let diagnostic = lookup[&labels];
        let treatment = row.values[&pair.treatment];
        let outcome = row.values[&pair.outcome];
        let location = || format!("row {:?}, stratum {labels:?}", row.row_id);
        let stratum_contrast = finite_derived(
            pair,
            "stratum treated-minus-control contrast",
            location,
            diagnostic.treated_mean - diagnostic.control_mean,
        )?;
        let treated_residual = finite_derived(
            pair,
            "treated outcome residual",
            location,
            outcome - diagnostic.treated_mean,
        )?;
        let treated_weighted_residual = finite_derived(
            pair,
            "treated residual weighting",
            location,
            treatment * treated_residual,
        )?;
        let treated_correction = finite_derived(
            pair,
            "treated inverse-propensity correction",
            location,
            treated_weighted_residual / diagnostic.propensity,
        )?;
        let control_residual = finite_derived(
            pair,
            "control outcome residual",
            location,
            outcome - diagnostic.control_mean,
        )?;
        let control_weight = finite_derived(
            pair,
            "control treatment complement",
            location,
            1.0 - treatment,
        )?;
        let control_weighted_residual = finite_derived(
            pair,
            "control residual weighting",
            location,
            control_weight * control_residual,
        )?;
        let control_propensity = finite_derived(
            pair,
            "control propensity subtraction",
            location,
            1.0 - diagnostic.propensity,
        )?;
        let control_correction = finite_derived(
            pair,
            "control inverse-propensity correction",
            location,
            control_weighted_residual / control_propensity,
        )?;
        let augmented_treated = finite_derived(
            pair,
            "stratum contrast plus treated correction",
            location,
            stratum_contrast + treated_correction,
        )?;
        let value = finite_derived(
            pair,
            "AIPW influence value",
            location,
            augmented_treated - control_correction,
        )?;
        influence.push(value);
    }
    let mut influence_sum = 0.0;
    for (ordinal, value) in influence.iter().enumerate() {
        influence_sum = finite_derived(
            pair,
            "influence-value accumulation",
            || format!("influence ordinal {ordinal}"),
            influence_sum + value,
        )?;
    }
    let ate = finite_derived(
        pair,
        "average treatment effect division",
        || "complete sample".to_string(),
        influence_sum / influence.len() as f64,
    )?;
    let mut squared_deviation_sum = 0.0;
    for (ordinal, value) in influence.iter().enumerate() {
        let centered = finite_derived(
            pair,
            "influence centering",
            || format!("influence ordinal {ordinal}"),
            value - ate,
        )?;
        let squared = finite_derived(
            pair,
            "squared influence deviation",
            || format!("influence ordinal {ordinal}"),
            centered * centered,
        )?;
        squared_deviation_sum = finite_derived(
            pair,
            "squared-deviation accumulation",
            || format!("influence ordinal {ordinal}"),
            squared_deviation_sum + squared,
        )?;
    }
    let sample_variance = finite_derived(
        pair,
        "sample variance division",
        || "complete sample".to_string(),
        squared_deviation_sum / (influence.len() - 1) as f64,
    )?;
    let mean_variance = finite_derived(
        pair,
        "mean variance division",
        || "complete sample".to_string(),
        sample_variance / influence.len() as f64,
    )?;
    let standard_error = finite_derived(
        pair,
        "standard error square root",
        || "complete sample".to_string(),
        mean_variance.sqrt(),
    )?;
    let confidence_probability = finite_derived(
        pair,
        "confidence probability calculation",
        || "complete sample".to_string(),
        0.5 + config.confidence_level / 2.0,
    )?;
    let z = finite_derived(
        pair,
        "normal critical value",
        || "complete sample".to_string(),
        inverse_standard_normal_cdf(confidence_probability),
    )?;
    let margin = finite_derived(
        pair,
        "confidence margin multiplication",
        || "complete sample".to_string(),
        z * standard_error,
    )?;
    let confidence_lower = finite_derived(
        pair,
        "lower confidence-bound subtraction",
        || "complete sample".to_string(),
        ate - margin,
    )?;
    let confidence_upper = finite_derived(
        pair,
        "upper confidence-bound addition",
        || "complete sample".to_string(),
        ate + margin,
    )?;
    let treated_mean = finite_derived(
        pair,
        "complete-sample treated mean division",
        || "complete sample".to_string(),
        treated_sum / treated_count as f64,
    )?;
    let control_mean = finite_derived(
        pair,
        "complete-sample control mean division",
        || "complete sample".to_string(),
        control_sum / control_count as f64,
    )?;
    let association = finite_derived(
        pair,
        "unadjusted association subtraction",
        || "complete sample".to_string(),
        treated_mean - control_mean,
    )?;
    let confounding_adjustment = finite_derived(
        pair,
        "confounding adjustment subtraction",
        || "complete sample".to_string(),
        ate - association,
    )?;
    Ok(CausalEffectEstimate {
        effect_id: format!("{}=>{}", pair.treatment, pair.outcome),
        treatment: pair.treatment.clone(),
        outcome: pair.outcome.clone(),
        adjustment_set: pair.adjustment_set.clone(),
        unadjusted_association: association,
        average_treatment_effect: ate,
        confounding_adjustment,
        standard_error,
        confidence_lower,
        confidence_upper,
        confidence_level: config.confidence_level,
        minimum_observed_overlap: minimum_overlap,
        strata: diagnostics,
        identifiability: "identified_backdoor".to_string(),
        evidence_kind: "identified_observational_effect".to_string(),
    })
}

fn checked_count<F>(
    pair: &CausalPairSpec,
    operation: &str,
    location: F,
    value: usize,
) -> Result<usize>
where
    F: FnOnce() -> String,
{
    value
        .checked_add(1)
        .ok_or_else(|| numeric_error(pair, operation, location))
}

fn row_stratum_location(pair: &CausalPairSpec, row: &CausalObservation) -> String {
    let labels = pair
        .adjustment_set
        .iter()
        .map(|name| format!("{name}={}", row.strata[name]))
        .collect::<Vec<_>>();
    format!("row {:?}, stratum {labels:?}", row.row_id)
}

fn finite_derived<F>(pair: &CausalPairSpec, operation: &str, location: F, value: f64) -> Result<f64>
where
    F: FnOnce() -> String,
{
    if value.is_finite() {
        Ok(value)
    } else {
        Err(numeric_error(pair, operation, location))
    }
}

fn numeric_error<F>(pair: &CausalPairSpec, operation: &str, location: F) -> AssayError
where
    F: FnOnce() -> String,
{
    AssayError::new(
        ASTRO_ASSAY_CAUSAL_NUMERIC_INVALID,
        format!(
            "causal effect {}=>{} derived a non-finite or overflowing value during {operation} at {}",
            pair.treatment,
            pair.outcome,
            location()
        ),
        "reduce or rescale the finite outcome magnitudes, then rerun the complete causal request; no partial artifact was published",
    )
}

fn invalid(message: impl Into<String>) -> AssayError {
    AssayError::new(
        ASTRO_ASSAY_CAUSAL_INPUT_INVALID,
        message,
        "supply a complete finite observation table, exact treatment/outcome universe, one adjustment set per pair, and every required identifying assumption",
    )
}

fn not_identifiable(pair: &CausalPairSpec, message: impl Into<String>) -> AssayError {
    AssayError::new(
        ASTRO_ASSAY_CAUSAL_NOT_IDENTIFIABLE,
        format!(
            "{}=>{} is not identifiable: {}",
            pair.treatment,
            pair.outcome,
            message.into()
        ),
        "collect both treatment arms in every declared adjustment stratum or revise the causal design; do not report the observational association as a causal effect",
    )
}
