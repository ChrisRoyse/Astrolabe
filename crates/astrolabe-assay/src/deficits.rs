//! Producer for the `astrolabe.optimizer_deficits.v1` document (#115).
//!
//! The optimizer's proposal path
//! (`astrolabe-server/src/migration/optimizer/propose.rs`) reads a persisted
//! `optimizer_deficits_json` value and refuses fail-closed when it is missing or
//! malformed. Nothing wrote that document before this crate: the assay pipeline
//! is its producer. This module builds a schema-valid document from *measured*
//! deficits — it never fabricates the bits. `measured_bits` and `required_bits`
//! are supplied by the measurement stage (KSG MI, #32) that consumes the sampled
//! strata; this module only frames them into the contract the server validates.
//!
//! The document this builder emits is verified against the server's own
//! validation predicate in this crate's tests, so a shape drift on either side
//! is caught here rather than at the native server boundary.

use serde_json::{Value, json};

use crate::error::{ASTRO_ASSAY_DEFICIT_INVALID, AssayError, Result};

/// Schema tag the server's optimizer requires on the deficits document.
pub const OPTIMIZER_DEFICITS_SCHEMA: &str = "astrolabe.optimizer_deficits.v1";

/// One measured deficit produced by the assay measurement stage.
///
/// Every field the server's `optimizer_deficit_invalid` check requires is a
/// non-optional field here, so a `DeficitMeasurement` that type-checks already
/// carries the mandatory contract fields; `provenance` non-emptiness and bit
/// finiteness are checked at build time.
#[derive(Debug, Clone, PartialEq)]
pub struct DeficitMeasurement {
    /// Stable deficit identifier.
    pub deficit_id: String,
    /// Sufficiency axis the deficit was measured on.
    pub axis: String,
    /// Suggested remediation action (e.g. `ProposeLens`).
    pub suggested_action: String,
    /// Candidate template family the action would draw from.
    pub template_family: String,
    /// Slot the candidate would occupy.
    pub slot: String,
    /// Measured information, in bits.
    pub measured_bits: f64,
    /// Required information, in bits.
    pub required_bits: f64,
    /// Non-empty provenance chain for the measurement.
    pub provenance: Vec<String>,
    /// Optional scope object carried through to the proposal.
    pub scope: Option<Value>,
    /// Optional field descriptor carried through to the candidate.
    pub field: Option<Value>,
}

impl DeficitMeasurement {
    fn to_value(&self) -> Result<Value> {
        if self.deficit_id.is_empty()
            || self.axis.is_empty()
            || self.suggested_action.is_empty()
            || self.template_family.is_empty()
            || self.slot.is_empty()
        {
            return Err(AssayError::new(
                ASTRO_ASSAY_DEFICIT_INVALID,
                format!(
                    "deficit {:?} has an empty required string field",
                    self.deficit_id
                ),
                "populate deficit_id, axis, suggested_action, template_family, and slot",
            ));
        }
        if !self.measured_bits.is_finite() || !self.required_bits.is_finite() {
            return Err(AssayError::new(
                ASTRO_ASSAY_DEFICIT_INVALID,
                format!(
                    "deficit {:?} carries a non-finite bit measurement",
                    self.deficit_id
                ),
                "supply finite measured_bits and required_bits from the measurement stage",
            ));
        }
        if self.provenance.is_empty() || self.provenance.iter().any(String::is_empty) {
            return Err(AssayError::new(
                ASTRO_ASSAY_DEFICIT_INVALID,
                format!(
                    "deficit {:?} requires non-empty string provenance",
                    self.deficit_id
                ),
                "attach at least one non-empty provenance entry to every measured deficit",
            ));
        }
        let mut object = json!({
            "deficit_id": self.deficit_id,
            "axis": self.axis,
            "suggested_action": self.suggested_action,
            "template_family": self.template_family,
            "slot": self.slot,
            "measured_bits": self.measured_bits,
            "required_bits": self.required_bits,
            "freshness": "fresh",
            "trust": "verified",
            "provenance": self.provenance,
        });
        if let Some(scope) = &self.scope {
            object["scope"] = scope.clone();
        }
        if let Some(field) = &self.field {
            object["field"] = field.clone();
        }
        Ok(object)
    }
}

/// Builds the `astrolabe.optimizer_deficits.v1` document from measured deficits.
///
/// The document carries `status: "measured"` and `freshness`/`trust` labels the
/// server requires. An empty measurement set is legal and yields an empty
/// `deficits` array — a project with no measured deficit is a valid, fully
/// labeled state, not an error.
pub fn optimizer_deficits_document(measurements: &[DeficitMeasurement]) -> Result<Value> {
    let mut deficits = Vec::with_capacity(measurements.len());
    for measurement in measurements {
        deficits.push(measurement.to_value()?);
    }
    Ok(json!({
        "schema": OPTIMIZER_DEFICITS_SCHEMA,
        "status": "measured",
        "freshness": "fresh",
        "trust": "verified",
        "deficits": deficits,
    }))
}
