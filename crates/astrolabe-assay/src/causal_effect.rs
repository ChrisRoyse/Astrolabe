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
    ASTRO_ASSAY_CAUSAL_INPUT_INVALID, ASTRO_ASSAY_CAUSAL_NOT_IDENTIFIABLE, AssayError, Result,
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
            accumulator.treated_count += 1;
            accumulator.treated_sum += outcome;
            treated_count += 1;
            treated_sum += outcome;
        } else {
            accumulator.control_count += 1;
            accumulator.control_sum += outcome;
            control_count += 1;
            control_sum += outcome;
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
        let count = accumulator.control_count + accumulator.treated_count;
        let propensity = accumulator.treated_count as f64 / count as f64;
        let overlap = propensity.min(1.0 - propensity);
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
        diagnostics.push(CausalStratumDiagnostic {
            labels: labels.clone(),
            observations: count,
            control_count: accumulator.control_count,
            treated_count: accumulator.treated_count,
            propensity,
            control_mean: accumulator.control_sum / accumulator.control_count as f64,
            treated_mean: accumulator.treated_sum / accumulator.treated_count as f64,
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
        let value = diagnostic.treated_mean - diagnostic.control_mean
            + treatment * (outcome - diagnostic.treated_mean) / diagnostic.propensity
            - (1.0 - treatment) * (outcome - diagnostic.control_mean)
                / (1.0 - diagnostic.propensity);
        influence.push(value);
    }
    let ate = influence.iter().sum::<f64>() / influence.len() as f64;
    let sample_variance = influence
        .iter()
        .map(|value| (value - ate).powi(2))
        .sum::<f64>()
        / (influence.len() - 1) as f64;
    let standard_error = (sample_variance / influence.len() as f64).sqrt();
    let z = inverse_standard_normal_cdf(0.5 + config.confidence_level / 2.0);
    let margin = z * standard_error;
    let association = treated_sum / treated_count as f64 - control_sum / control_count as f64;
    Ok(CausalEffectEstimate {
        effect_id: format!("{}=>{}", pair.treatment, pair.outcome),
        treatment: pair.treatment.clone(),
        outcome: pair.outcome.clone(),
        adjustment_set: pair.adjustment_set.clone(),
        unadjusted_association: association,
        average_treatment_effect: ate,
        confounding_adjustment: ate - association,
        standard_error,
        confidence_lower: ate - margin,
        confidence_upper: ate + margin,
        confidence_level: config.confidence_level,
        minimum_observed_overlap: minimum_overlap,
        strata: diagnostics,
        identifiability: "identified_backdoor".to_string(),
        evidence_kind: "identified_observational_effect".to_string(),
    })
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
