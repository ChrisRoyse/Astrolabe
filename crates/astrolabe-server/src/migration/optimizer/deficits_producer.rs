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

#[cfg(test)]
mod tests {
    use super::*;

    fn producer_temp_dir(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "astrolabe-deficits-producer-{}-{tag}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sample_measurement() -> DeficitMeasurement {
        DeficitMeasurement {
            deficit_id: "deficit:producer:1".to_string(),
            axis: "coverage".to_string(),
            suggested_action: "ProposeLens".to_string(),
            template_family: "hashed_set".to_string(),
            slot: "lock_atomic_usage".to_string(),
            measured_bits: 0.61,
            required_bits: 1.0,
            provenance: vec!["assay:strata:coverage:12".to_string()],
            scope: Some(json!("payments")),
            field: Some(json!("lock_calls")),
        }
    }

    #[test]
    fn producer_persists_deficits_that_the_reader_accepts() {
        let dir = producer_temp_dir("accepts");
        let document = persist_measured_deficits_at(&dir, "demo", &[sample_measurement()]).unwrap();

        // Independent readback of the persisted config row.
        let key = metadata_key("demo", "optimizer_deficits_json");
        let raw = read_config_value(&dir, &key).unwrap().expect("row present");
        let stored: Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(stored, document);

        // The reader-side validation the propose path applies accepts the row.
        let validated = optimizer_deficits_config_value(stored, &key).expect("reader accepts");
        assert_eq!(
            validated["deficits"][0]["measured_bits"].as_f64(),
            Some(0.61)
        );

        // End-to-end: the propose path now generates a proposal instead of
        // refusing DEFICITS_MISSING, proving the producer output is consumable.
        let queue = optimizer_propose_json_at(&dir, "demo", None).unwrap();
        assert_eq!(queue["status"], json!("generated"));
        assert_eq!(queue["proposal_count"], json!(1));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn producer_rejects_invalid_measurement_fail_closed() {
        let dir = producer_temp_dir("rejects");
        let mut bad = sample_measurement();
        bad.provenance.clear();
        let err = persist_measured_deficits_at(&dir, "demo", &[bad]).unwrap_err();
        assert!(err.to_string().contains("ASTRO_ASSAY_DEFICIT_INVALID"));
        // Nothing was persisted for the rejected measurement.
        let key = metadata_key("demo", "optimizer_deficits_json");
        assert!(read_config_value(&dir, &key).unwrap().is_none());
        std::fs::remove_dir_all(&dir).ok();
    }
}
