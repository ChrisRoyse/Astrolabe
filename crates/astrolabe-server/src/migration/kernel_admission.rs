use super::*;

/// Public `index_repository` / `get_kernel mode="build"` argument carrying the
/// real external query corpus and every graph-routed admission control.
pub(crate) const KERNEL_ADMISSION_ARG: &str = "kernel_admission";
pub(crate) const KERNEL_ADMISSION_ACTION_SCHEMA: &str = "astrolabe.kernel-admission-action.v1";

const KERNEL_ADMISSION_FIELDS: [&str; 2] = ["queries", "params"];
const KERNEL_QUERY_FIELDS: [&str; 3] = ["stable_id", "source", "content"];
const KERNEL_PARAM_FIELDS: [&str; 8] = [
    "top_k",
    "expected_vector_dimension",
    "entry_point_count",
    "ef_search",
    "max_route_distance_computations_per_query",
    "max_exact_distance_computations",
    "min_recall_permille",
    "max_kernel_member_fraction_permille",
];

/// Closed, validated input for one complete kernel admission generation.
#[derive(Clone, Debug)]
pub(crate) struct KernelAdmissionRequest {
    pub(crate) queries: Vec<astrolabe_weave::KernelRecallQueryInput>,
    pub(crate) params: astrolabe_kernel::GraphRoutedRecallParams,
}

/// Canonical action identity for an explicit request. The raw query text is
/// represented by one framed roster hash rather than copied into project
/// metadata; the immutable query-corpus row remains the authoritative bytes.
pub(crate) fn explicit_kernel_admission_action_identity(
    request: &KernelAdmissionRequest,
) -> Result<Value, DynError> {
    let encoder = astrolabe_weave::kernel_recall_query_encoder_identity(
        astrolabe_panel::CURRENT_SEMANTIC_PANEL_VERSION,
    )
    .map_err(|error| -> DynError {
        format!(
            "ASTRO_KERNEL_ADMISSION_ENCODER_IDENTITY_FAILED: code={} message={:?} remediation={:?}",
            error.code(),
            error.message(),
            error.remediation()
        )
        .into()
    })?;
    kernel_admission_action_identity(
        request.queries.iter().map(|query| {
            (
                query.stable_id.as_str(),
                query.source.as_str(),
                query.content.as_str(),
            )
        }),
        &request.params,
        &encoder,
    )
}

/// Reconstructs the same action identity from an independently decoded current
/// corpus. Encoder validation is mandatory before its bytes can authorize an
/// unchanged shadow generation.
pub(crate) fn persisted_kernel_admission_action_identity(
    corpus: &astrolabe_weave::KernelRecallQueryCorpus,
) -> Result<Value, DynError> {
    astrolabe_weave::validate_kernel_recall_query_corpus_encoder(corpus).map_err(
        |error| -> DynError {
            format!(
                "ASTRO_KERNEL_ADMISSION_CORPUS_INVALID: code={} message={:?} remediation={:?}",
                error.code(),
                error.message(),
                error.remediation()
            )
            .into()
        },
    )?;
    kernel_admission_action_identity(
        corpus.queries.iter().map(|query| {
            (
                query.stable_id.as_str(),
                query.source.as_str(),
                query.content.as_str(),
            )
        }),
        &corpus.params,
        &corpus.encoder,
    )
}

fn kernel_admission_action_identity<'a>(
    queries: impl IntoIterator<Item = (&'a str, &'a str, &'a str)>,
    params: &astrolabe_kernel::GraphRoutedRecallParams,
    encoder: &astrolabe_weave::KernelRecallQueryEncoderIdentity,
) -> Result<Value, DynError> {
    let mut rows = queries
        .into_iter()
        .map(|(stable_id, source, content)| {
            (
                astrolabe_kernel::graph_routed_query_cx_id(stable_id, source, content.as_bytes()),
                stable_id,
                source,
                content,
            )
        })
        .collect::<Vec<_>>();
    rows.sort_by_key(|row| row.0);
    if rows.is_empty() || rows.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(
            "ASTRO_KERNEL_ADMISSION_QUERY_ROSTER_INVALID: canonical external-query roster is empty or has a duplicate derived query identity; remediation: supply distinct real query rows"
                .into(),
        );
    }
    let mut hasher = Sha256::new();
    hasher.update(b"astrolabe.kernel-admission-query-roster.v1\0");
    hash_kernel_admission_frame(&mut hasher, &u64::try_from(rows.len())?.to_be_bytes())?;
    for (query_id, stable_id, source, content) in &rows {
        hash_kernel_admission_frame(&mut hasher, query_id.as_bytes())?;
        hash_kernel_admission_frame(&mut hasher, stable_id.as_bytes())?;
        hash_kernel_admission_frame(&mut hasher, source.as_bytes())?;
        hash_kernel_admission_frame(&mut hasher, content.as_bytes())?;
    }
    Ok(json!({
        "schema": KERNEL_ADMISSION_ACTION_SCHEMA,
        "query_count": rows.len(),
        "query_roster_sha256": hex_lower(&hasher.finalize()),
        "params": params,
        "encoder": encoder,
    }))
}

fn hash_kernel_admission_frame(hasher: &mut Sha256, bytes: &[u8]) -> Result<(), DynError> {
    hasher.update(u64::try_from(bytes.len())?.to_be_bytes());
    hasher.update(bytes);
    Ok(())
}

/// Returns the exact public JSON Schema used by the MCP tools/list overlays.
pub(crate) fn kernel_admission_property_schema() -> Value {
    json!({
        "type": "object",
        "description": "Required for the first shadow kernel generation and every explicit get_kernel build. Supplies independently authored real operator/query-log text plus every graph-routed recall and work control. No graph node is synthesized as a query and no threshold has a default.",
        "properties": {
            "queries": {
                "type": "array",
                "minItems": 1,
                "description": "Nonempty persisted real-query roster. stable_id, source, and exact content jointly derive a domain-separated query identity that must be disjoint from the graph corpus.",
                "items": {
                    "type": "object",
                    "properties": {
                        "stable_id": { "type": "string", "minLength": 1 },
                        "source": { "type": "string", "minLength": 1 },
                        "content": { "type": "string", "minLength": 1 }
                    },
                    "required": ["stable_id", "source", "content"],
                    "additionalProperties": false
                }
            },
            "params": {
                "type": "object",
                "description": "All routing, exact-oracle, recall, and compactness controls are explicit and persisted into the generation identity.",
                "properties": {
                    "top_k": { "type": "integer", "minimum": 1 },
                    "expected_vector_dimension": { "type": "integer", "minimum": 1 },
                    "entry_point_count": { "type": "integer", "minimum": 1 },
                    "ef_search": { "type": "integer", "minimum": 1 },
                    "max_route_distance_computations_per_query": { "type": "integer", "minimum": 1 },
                    "max_exact_distance_computations": { "type": "integer", "minimum": 1 },
                    "min_recall_permille": { "type": "integer", "minimum": 1, "maximum": 1000 },
                    "max_kernel_member_fraction_permille": { "type": "integer", "minimum": 1, "maximum": 999 }
                },
                "required": [
                    "top_k",
                    "expected_vector_dimension",
                    "entry_point_count",
                    "ef_search",
                    "max_route_distance_computations_per_query",
                    "max_exact_distance_computations",
                    "min_recall_permille",
                    "max_kernel_member_fraction_permille"
                ],
                "additionalProperties": false
            }
        },
        "required": ["queries", "params"],
        "additionalProperties": false
    })
}

/// Parses the optional public admission object without applying any defaults.
pub(crate) fn parse_kernel_admission_request(
    args: &Map<String, Value>,
) -> Result<Option<KernelAdmissionRequest>, ToolFault> {
    let Some(value) = args.get(KERNEL_ADMISSION_ARG) else {
        return Ok(None);
    };
    let object = value.as_object().ok_or_else(|| {
        admission_fault(
            KERNEL_ADMISSION_ARG,
            "object with exactly queries and params",
            value,
            "kernel_admission must be a closed object",
        )
    })?;
    require_exact_fields(
        object,
        &KERNEL_ADMISSION_FIELDS,
        KERNEL_ADMISSION_ARG,
        value,
    )?;

    let query_value = object.get("queries").ok_or_else(|| {
        admission_fault(
            "kernel_admission.queries",
            "nonempty array",
            &Value::Null,
            "kernel_admission omitted queries",
        )
    })?;
    let query_rows = query_value
        .as_array()
        .filter(|rows| !rows.is_empty())
        .ok_or_else(|| {
            admission_fault(
                "kernel_admission.queries",
                "nonempty array of closed real-query records",
                query_value,
                "kernel_admission queries must be nonempty",
            )
        })?;
    let mut queries = Vec::with_capacity(query_rows.len());
    let mut stable_ids = BTreeSet::new();
    let mut contents = BTreeSet::new();
    for (index, row) in query_rows.iter().enumerate() {
        let path = format!("kernel_admission.queries[{index}]");
        let query = row.as_object().ok_or_else(|| {
            admission_fault(
                &path,
                "object with exactly stable_id, source, and content",
                row,
                "real-query row must be a closed object",
            )
        })?;
        require_exact_fields(query, &KERNEL_QUERY_FIELDS, &path, row)?;
        let stable_id = required_nonempty_string(query, "stable_id", &path, row)?;
        let source = required_nonempty_string(query, "source", &path, row)?;
        let content = required_nonempty_string(query, "content", &path, row)?;
        if !stable_ids.insert(stable_id.to_string()) {
            return Err(admission_fault(
                &format!("{path}.stable_id"),
                "unique nonempty stable_id",
                query.get("stable_id").unwrap_or(&Value::Null),
                "real-query stable_id is duplicated",
            ));
        }
        let content_sha256 = hex_lower(&Sha256::digest(content.as_bytes()));
        if !contents.insert(content_sha256.clone()) {
            return Err(admission_fault(
                &format!("{path}.content"),
                "content bytes unique across the admission corpus",
                query.get("content").unwrap_or(&Value::Null),
                format!("real-query content identity {content_sha256} is duplicated"),
            ));
        }
        queries.push(astrolabe_weave::KernelRecallQueryInput {
            stable_id: stable_id.to_string(),
            source: source.to_string(),
            content: content.to_string(),
        });
    }

    let params_value = object.get("params").ok_or_else(|| {
        admission_fault(
            "kernel_admission.params",
            "closed object containing every admission control",
            &Value::Null,
            "kernel_admission omitted params",
        )
    })?;
    let params = params_value.as_object().ok_or_else(|| {
        admission_fault(
            "kernel_admission.params",
            "closed object containing every admission control",
            params_value,
            "kernel_admission params must be an object",
        )
    })?;
    require_exact_fields(
        params,
        &KERNEL_PARAM_FIELDS,
        "kernel_admission.params",
        params_value,
    )?;
    let parsed = astrolabe_kernel::GraphRoutedRecallParams {
        top_k: required_positive_usize(params, "top_k")?,
        expected_vector_dimension: required_positive_usize(params, "expected_vector_dimension")?,
        entry_point_count: required_positive_usize(params, "entry_point_count")?,
        ef_search: required_positive_usize(params, "ef_search")?,
        max_route_distance_computations_per_query: required_positive_usize(
            params,
            "max_route_distance_computations_per_query",
        )?,
        max_exact_distance_computations: required_positive_usize(
            params,
            "max_exact_distance_computations",
        )?,
        min_recall_permille: required_bounded_u64(params, "min_recall_permille", 1, 1000)?,
        max_kernel_member_fraction_permille: required_bounded_u64(
            params,
            "max_kernel_member_fraction_permille",
            1,
            999,
        )?,
    };
    Ok(Some(KernelAdmissionRequest {
        queries,
        params: parsed,
    }))
}

fn require_exact_fields(
    object: &Map<String, Value>,
    expected: &[&str],
    path: &str,
    observed: &Value,
) -> Result<(), ToolFault> {
    let observed_fields = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected_fields = expected.iter().copied().collect::<BTreeSet<_>>();
    if observed_fields != expected_fields {
        return Err(admission_fault(
            path,
            format!("exact fields {expected_fields:?}"),
            observed,
            format!("observed fields {observed_fields:?}"),
        ));
    }
    Ok(())
}

fn required_nonempty_string<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    parent: &str,
    observed: &Value,
) -> Result<&'a str, ToolFault> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
        .ok_or_else(|| {
            admission_fault(
                &format!("{parent}.{field}"),
                "nonempty string",
                observed,
                format!("{field} is missing, not a string, or blank"),
            )
        })
}

fn required_positive_usize(object: &Map<String, Value>, field: &str) -> Result<usize, ToolFault> {
    let value = object.get(field).unwrap_or(&Value::Null);
    let parsed = value
        .as_u64()
        .and_then(|raw| usize::try_from(raw).ok())
        .filter(|raw| *raw > 0)
        .ok_or_else(|| {
            admission_fault(
                &format!("kernel_admission.params.{field}"),
                "positive integer representable as native usize",
                value,
                format!("{field} is missing, zero, negative, fractional, or too large"),
            )
        })?;
    Ok(parsed)
}

fn required_bounded_u64(
    object: &Map<String, Value>,
    field: &str,
    min: u64,
    max: u64,
) -> Result<u64, ToolFault> {
    let value = object.get(field).unwrap_or(&Value::Null);
    value
        .as_u64()
        .filter(|raw| (min..=max).contains(raw))
        .ok_or_else(|| {
            admission_fault(
                &format!("kernel_admission.params.{field}"),
                format!("integer in {min}..={max}"),
                value,
                format!("{field} is outside its closed admitted range"),
            )
        })
}

fn admission_fault(
    path: &str,
    expected: impl Into<String>,
    observed: &Value,
    message: impl Into<String>,
) -> ToolFault {
    ToolFault::new(
        "ASTRO_KERNEL_ADMISSION_ARGUMENT_INVALID",
        message,
        "pass the exact closed kernel_admission object advertised by tools/list; every real query and every work/admission control is mandatory",
    )
    .with_argument(path, expected, observed)
}
