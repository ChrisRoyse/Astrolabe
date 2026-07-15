use super::*;

use astrolabe_assay::DeficitMeasurement;

/// Persists an `astrolabe.optimizer_deficits.v1` document produced from measured
/// deficits, then verifies the write by reading the config row back (#115).
///
/// Before this producer existed, nothing wrote `optimizer_deficits_json`, so
/// `optimizer_propose_json_at` always refused with
/// `ASTRO_OPTIMIZER_PROPOSE_DEFICITS_MISSING`. The assay pipeline is the
/// producer of that row: it frames the measured deficits (bits supplied by the
/// KSG MI measurement stage, #32) into the document the optimizer proposal path
/// consumes, writes it to the shared config store, and proves the write by an
/// independent read-back — a writer return value is never treated as evidence of
/// persisted state (standing invariant 5).
///
/// The returned value is the exact document that is now durable at
/// `config:<project>.optimizer_deficits_json`.
// The measurement-stage caller that supplies real `DeficitMeasurement`s is the
// KSG MI estimator (#32); until that lands this producer is exercised only by
// its own FSV tests, so its non-test caller is pending, not missing.
#[allow(dead_code)]
pub(crate) fn persist_measured_deficits_at(
    cache_dir: &Path,
    project: &str,
    measurements: &[DeficitMeasurement],
) -> Result<Value, DynError> {
    let document = astrolabe_assay::optimizer_deficits_document(measurements)?;
    let key = metadata_key(project, "optimizer_deficits_json");
    let serialized = document.to_string();
    write_config_value(cache_dir, &key, &serialized)?;

    // FSV: read the row back through a fresh config connection and confirm the
    // persisted bytes parse to the document that was written.
    match read_config_value(cache_dir, &key)? {
        None => Err(format!(
            "ASTRO_ASSAY_DEFICITS_WRITE_LOST: optimizer_deficits_json at config:{key} was not \
             readable back immediately after write. Remediation: check the config store \
             filesystem and retry deficit persistence before running mode=\"propose\"."
        )
        .into()),
        Some(raw) => {
            let readback: Value = serde_json::from_str(&raw).map_err(|error| -> DynError {
                format!(
                    "ASTRO_ASSAY_DEFICITS_READBACK_CORRUPT: optimizer_deficits_json at \
                     config:{key} did not parse after write: {error}. Remediation: delete the \
                     corrupt row and re-run deficit persistence."
                )
                .into()
            })?;
            if readback != document {
                return Err(format!(
                    "ASTRO_ASSAY_DEFICITS_READBACK_MISMATCH: optimizer_deficits_json at \
                     config:{key} read back a different value than was written. Remediation: \
                     quarantine the config store and re-run deficit persistence."
                )
                .into());
            }
            Ok(document)
        }
    }
}
