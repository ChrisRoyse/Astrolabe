use super::*;

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct SearchScaleSettings {
    pub(crate) index_backend: SearchIndexBackend,
    pub(crate) funnel_activation_records: u64,
    pub(crate) estimated_index_rss_bytes: u64,
    pub(crate) master_budget_bytes: u64,
    pub(crate) source: String,
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub(crate) struct SearchScaleOverride {
    pub(crate) index_backend: Option<SearchIndexBackend>,
    pub(crate) funnel_activation_records: Option<u64>,
    pub(crate) estimated_index_rss_bytes: Option<u64>,
    pub(crate) master_budget_bytes: Option<u64>,
}

pub(crate) fn parse_search_scale_override(
    args: &Map<String, Value>,
) -> Result<Option<SearchScaleOverride>, String> {
    let Some(value) = args.get("calyx_search") else {
        return Ok(None);
    };
    let obj = value
        .as_object()
        .ok_or_else(|| "calyx_search must be a JSON object".to_string())?;
    for key in obj.keys() {
        if !matches!(
            key.as_str(),
            "index_backend"
                | "funnel_activation_records"
                | "estimated_index_rss_bytes"
                | "master_budget_bytes"
        ) {
            return Err(format!("unknown calyx_search field {key:?}"));
        }
    }

    let index_backend = match obj.get("index_backend") {
        Some(value) => {
            let raw = value
                .as_str()
                .ok_or_else(|| "calyx_search.index_backend must be a string".to_string())?;
            Some(raw.parse::<SearchIndexBackend>().map_err(|message| {
                format!(
                    "invalid calyx_search.index_backend {raw:?}: {message}; expected in_memory_hnsw, diskann, or spann"
                )
            })?)
        }
        None => None,
    };

    Ok(Some(SearchScaleOverride {
        index_backend,
        funnel_activation_records: optional_u64_field(obj, "funnel_activation_records")?,
        estimated_index_rss_bytes: optional_u64_field(obj, "estimated_index_rss_bytes")?,
        master_budget_bytes: optional_u64_field(obj, "master_budget_bytes")?,
    }))
}

pub(crate) fn optional_u64_field(
    obj: &Map<String, Value>,
    key: &str,
) -> Result<Option<u64>, String> {
    match obj.get(key) {
        Some(value) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("calyx_search.{key} must be an unsigned integer")),
        None => Ok(None),
    }
}

pub(crate) fn search_scale_settings_for_import(
    project: &str,
    request: Option<SearchScaleOverride>,
) -> Result<SearchScaleSettings, DynError> {
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    let mut settings = match read_search_scale_settings_from_config(&cache_dir, project)? {
        Some(settings) => settings,
        None => default_search_scale_settings("runtime_default")?,
    };
    if let Some(request) = request {
        apply_search_scale_override(&mut settings, request);
        settings.source = "request".to_string();
    }
    Ok(settings)
}

pub(crate) fn default_search_scale_settings(source: &str) -> Result<SearchScaleSettings, DynError> {
    Ok(SearchScaleSettings {
        index_backend: SearchIndexBackend::InMemoryHnsw,
        funnel_activation_records: DEFAULT_FUNNEL_ACTIVATION_RECORDS,
        estimated_index_rss_bytes: 0,
        master_budget_bytes: u64::try_from(astrolabe_bridge::cbm_memory_budget_bytes())?,
        source: source.to_string(),
    })
}

pub(crate) fn apply_search_scale_override(
    settings: &mut SearchScaleSettings,
    request: SearchScaleOverride,
) {
    if let Some(index_backend) = request.index_backend {
        settings.index_backend = index_backend;
    }
    if let Some(funnel_activation_records) = request.funnel_activation_records {
        settings.funnel_activation_records = funnel_activation_records;
    }
    if let Some(estimated_index_rss_bytes) = request.estimated_index_rss_bytes {
        settings.estimated_index_rss_bytes = estimated_index_rss_bytes;
    }
    if let Some(master_budget_bytes) = request.master_budget_bytes {
        settings.master_budget_bytes = master_budget_bytes;
    }
}

pub(crate) fn search_scale_summary(
    settings: &SearchScaleSettings,
    total_records: u64,
) -> Result<Value, DynError> {
    let mut config = SearchScaleConfig::with_registry_defaults(
        total_records,
        settings.estimated_index_rss_bytes,
        settings.master_budget_bytes,
    );
    config.index_backend = settings.index_backend;
    config.funnel_activation_records = settings.funnel_activation_records;
    let plan = plan_search_scale(&config)?;
    Ok(search_scale_plan_json(&plan, &settings.source))
}

pub(crate) fn search_scale_plan_json(plan: &SearchScalePlan, settings_source: &str) -> Value {
    json!({
        "schema": plan.schema,
        "status": "planned",
        "knob_registry_version": plan.knob_registry_version,
        "settings_source": settings_source,
        "total_records": plan.total_records,
        "funnel_activation_records": plan.funnel_activation_records,
        "funnel_mode": plan.funnel_mode.as_str(),
        "activation_label": plan.activation_label,
        "index_backend": plan.index_backend.as_str(),
        "index_backend_label": plan.index_backend_label,
        "estimated_index_rss_bytes": plan.estimated_index_rss_bytes,
        "master_budget_bytes": plan.master_budget_bytes,
        "freshness": plan.freshness,
        "trust": plan.trust,
    })
}

pub(crate) fn read_search_scale_settings_from_config(
    cache_dir: &Path,
    project: &str,
) -> Result<Option<SearchScaleSettings>, DynError> {
    let Some(raw) = read_config_value(cache_dir, &metadata_key(project, "search_scale_json"))?
    else {
        return Ok(None);
    };
    let value = serde_json::from_str::<Value>(&raw)?;
    let index_backend = value
        .get("index_backend")
        .and_then(Value::as_str)
        .ok_or("stored search_scale_json missing index_backend")?
        .parse::<SearchIndexBackend>()
        .map_err(|message| message.to_string())?;
    let funnel_activation_records =
        required_u64_metadata(&value, "funnel_activation_records", "search_scale_json")?;
    let estimated_index_rss_bytes =
        required_u64_metadata(&value, "estimated_index_rss_bytes", "search_scale_json")?;
    let master_budget_bytes =
        required_u64_metadata(&value, "master_budget_bytes", "search_scale_json")?;
    Ok(Some(SearchScaleSettings {
        index_backend,
        funnel_activation_records,
        estimated_index_rss_bytes,
        master_budget_bytes,
        source: "config_readback".to_string(),
    }))
}

pub(crate) fn required_u64_metadata(
    value: &Value,
    key: &str,
    subject: &str,
) -> Result<u64, DynError> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("stored {subject} missing {key}").into())
}

pub(crate) fn read_search_scale_metadata(
    cache_dir: &Path,
    project: &str,
) -> Result<Value, DynError> {
    let Some(raw) = read_config_value(cache_dir, &metadata_key(project, "search_scale_json"))?
    else {
        return Ok(search_scale_unavailable_json(
            "search scale metadata missing; rerun index_repository with calyx shadow",
        ));
    };
    match serde_json::from_str::<Value>(&raw) {
        Ok(value) => Ok(value),
        Err(error) => Ok(search_scale_unavailable_json(&format!(
            "stored search_scale_json invalid: {error}"
        ))),
    }
}

pub(crate) fn search_scale_unavailable_json(reason: &str) -> Value {
    json!({
        "schema": SEARCH_SCALE_SCHEMA,
        "status": "unavailable",
        "knob_registry_version": SEARCH_SCALE_KNOB_REGISTRY_VERSION,
        "freshness": "not_evaluated",
        "trust": "provisional",
        "reason": reason,
        "remediation": "rerun index_repository with calyx shadow after search scale planning is available",
    })
}
