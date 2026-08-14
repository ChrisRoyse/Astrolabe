use super::*;

/// Public index-admission argument for one generation-wide observation instant.
pub(crate) const GENERATION_OBSERVED_AT_MS_ARG: &str = "generation_observed_at_ms";
/// Private parent-to-worker transport. Callers may never supply this field.
pub(crate) const GENERATION_OBSERVED_AT_MS_PRIVATE_ARG: &str =
    "_astrolabe_generation_observed_at_ms";
/// Frozen meaning of the persisted observation value.
pub(crate) const GENERATION_CLOCK_CONTRACT: &str = "astrolabe.generation-clock.utc-seconds.v1";

// Largest Unix millisecond value representable by the CBM Project row's
// four-digit UTC year format: 9999-12-31T23:59:59Z.
const GENERATION_CLOCK_MAX_MS: u64 = 253_402_300_799_000;

#[derive(Debug, Clone, Copy)]
pub(crate) struct GenerationClockRequest {
    explicit_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GenerationClock {
    observed_at_ms: u64,
}

impl GenerationClockRequest {
    /// Parse and validate an optional caller-supplied time without sampling the
    /// wall clock. This runs before any project transition or store mutation.
    pub(crate) fn parse(args: &Map<String, Value>) -> Result<Self, ToolFault> {
        let Some(value) = args.get(GENERATION_OBSERVED_AT_MS_ARG) else {
            return Ok(Self { explicit_ms: None });
        };
        let Some(observed_at_ms) = value.as_u64() else {
            let (code, message, expected) = if value.as_i64().is_some_and(|raw| raw < 0) {
                (
                    "ASTRO_GENERATION_CLOCK_RANGE_INVALID",
                    "generation_observed_at_ms cannot be negative",
                    "an unsigned Unix-millisecond integer in the supported UTC range",
                )
            } else {
                (
                    "ASTRO_GENERATION_CLOCK_TYPE_INVALID",
                    "generation_observed_at_ms must be an unsigned integer",
                    "an unsigned Unix-millisecond integer",
                )
            };
            return Err(ToolFault::new(
                code,
                message,
                "pass a nonzero Unix-millisecond integer exactly divisible by 1000, or omit the field to observe the real admission boundary",
            )
            .with_argument(GENERATION_OBSERVED_AT_MS_ARG, expected, value));
        };
        validate_generation_observed_at_ms(observed_at_ms)?;
        Ok(Self {
            explicit_ms: Some(observed_at_ms),
        })
    }

    /// Resolve the request exactly once for a generation that will actually run.
    pub(crate) fn resolve(self) -> Result<GenerationClock, ToolFault> {
        let observed_at_ms = match self.explicit_ms {
            Some(value) => value,
            None => {
                let millis = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|error| {
                        ToolFault::new(
                            "ASTRO_GENERATION_CLOCK_UNAVAILABLE",
                            format!("the system wall clock is before the Unix epoch: {error}"),
                            "repair the host wall clock, then retry the unchanged request",
                        )
                    })?
                    .as_millis();
                let millis = u64::try_from(millis).map_err(|_| {
                    ToolFault::new(
                        "ASTRO_GENERATION_CLOCK_RANGE_INVALID",
                        "the system wall clock exceeds the supported Unix-millisecond range",
                        "repair the host wall clock, then retry the unchanged request",
                    )
                })?;
                // CBM persists UTC seconds. Resolve a real boundary observation
                // into that exact shared representation instead of rounding two
                // independent samples on opposite sides of a second boundary.
                millis - (millis % 1000)
            }
        };
        validate_generation_observed_at_ms(observed_at_ms)?;
        Ok(GenerationClock { observed_at_ms })
    }
}

/// Canonical public schema for [`GENERATION_OBSERVED_AT_MS_ARG`].
pub(crate) fn generation_clock_property_schema() -> Value {
    json!({
        "type": "integer",
        "minimum": 1,
        "maximum": GENERATION_CLOCK_MAX_MS,
        "multipleOf": 1000,
        "description": "Optional reproducible generation observation in Unix milliseconds. Must be nonzero and exactly representable by the Project row's UTC-seconds field. Omit to observe the real pipeline-admission boundary once."
    })
}

impl GenerationClock {
    pub(crate) fn from_persisted(observed_at_ms: u64) -> Result<Self, ToolFault> {
        validate_generation_observed_at_ms(observed_at_ms)?;
        Ok(Self { observed_at_ms })
    }

    pub(crate) const fn observed_at_ms(self) -> u64 {
        self.observed_at_ms
    }

    pub(crate) const fn observed_at_seconds(self) -> u64 {
        self.observed_at_ms / 1000
    }

    pub(crate) fn provenance(self) -> Value {
        json!({
            "schema": GENERATION_CLOCK_CONTRACT,
            "observed_at_ms": self.observed_at_ms,
            "resolution": "utc_seconds_exact",
            "trust": "verified",
            "provenance": "index_repository admission boundary",
        })
    }

    /// Add the already-resolved clock to one worker request. It is transported
    /// as a private field so it cannot become a caller action/cache identity.
    pub(crate) fn bind_worker_arg(self, args_json: &str) -> Result<String, DynError> {
        let mut value: Value = serde_json::from_str(args_json)?;
        let object = value.as_object_mut().ok_or_else(|| -> DynError {
            "ASTRO_INDEX_WORKER_ARGS_OBJECT_REQUIRED: index arguments must remain a JSON object"
                .into()
        })?;
        if object.contains_key(GENERATION_OBSERVED_AT_MS_PRIVATE_ARG) {
            return Err(format!(
                "ASTRO_INDEX_WORKER_PRIVATE_ARG_COLLISION: caller supplied reserved argument {:?}; remediation: remove that private transport field",
                GENERATION_OBSERVED_AT_MS_PRIVATE_ARG
            )
            .into());
        }
        object.insert(
            GENERATION_OBSERVED_AT_MS_PRIVATE_ARG.to_string(),
            Value::from(self.observed_at_ms),
        );
        Ok(serde_json::to_string(&value)?)
    }
}

fn validate_generation_observed_at_ms(observed_at_ms: u64) -> Result<(), ToolFault> {
    if observed_at_ms == 0 {
        return Err(ToolFault::new(
            "ASTRO_GENERATION_CLOCK_ZERO",
            "generation_observed_at_ms must be nonzero",
            "pass a nonzero Unix-millisecond integer exactly divisible by 1000",
        )
        .with_detail(GENERATION_OBSERVED_AT_MS_ARG, observed_at_ms));
    }
    if observed_at_ms > GENERATION_CLOCK_MAX_MS {
        return Err(ToolFault::new(
            "ASTRO_GENERATION_CLOCK_RANGE_INVALID",
            format!("generation_observed_at_ms {observed_at_ms} exceeds the UTC Project-row range"),
            format!(
                "pass a value no greater than {GENERATION_CLOCK_MAX_MS} (9999-12-31T23:59:59Z)"
            ),
        )
        .with_detail(GENERATION_OBSERVED_AT_MS_ARG, observed_at_ms)
        .with_detail("maximum", GENERATION_CLOCK_MAX_MS));
    }
    if !observed_at_ms.is_multiple_of(1000) {
        return Err(ToolFault::new(
            "ASTRO_GENERATION_CLOCK_SECOND_INEXACT",
            format!(
                "generation_observed_at_ms {observed_at_ms} cannot be represented exactly by CBM's UTC-seconds Project field"
            ),
            "pass a Unix-millisecond value exactly divisible by 1000; Astrolabe never rounds an explicit observation",
        )
        .with_detail(GENERATION_OBSERVED_AT_MS_ARG, observed_at_ms)
        .with_detail("required_multiple", 1000_u64));
    }
    Ok(())
}
