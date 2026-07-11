use super::*;

#[derive(Debug, Clone)]
pub(crate) struct OwnedPromptSource {
    pub(crate) source_id: String,
    pub(crate) source_kind: PromptSourceKind,
    pub(crate) text: String,
}

pub(crate) fn security_screen_from_row_sink_rows(rows: &CbmPipelineRows) -> Value {
    let subject = security_screen_subject(&rows.project);
    let mut skips = Vec::new();
    let sources = prompt_sources_from_row_sink_rows(rows, &mut skips);
    let report = screen_prompt_injection_inputs(sources.iter().map(|source| PromptScreenInput {
        source_id: &source.source_id,
        source_kind: source.source_kind,
        text: &source.text,
    }));
    security_screen_summary(
        &subject,
        prompt_injection_screen_summary(&report.findings, report.screened_sources, skips),
    )
}

pub(crate) fn security_screen_unavailable(subject: String, reason: &str) -> Value {
    security_screen_summary(
        &subject,
        prompt_injection_screen_summary(
            &[],
            0,
            vec![skipped_screen_json(
                PROMPT_INJECTION_FINDING_KIND,
                &subject,
                reason,
                "retry with row-sink metadata available, or inspect the CBM SQLite node properties directly",
            )],
        ),
    )
}

pub(crate) fn security_screen_summary(subject: &str, prompt_injection: Value) -> Value {
    json!({
        "schema": SECURITY_SCREEN_SCHEMA,
        "subject": subject,
        "trust": "provisional",
        "freshness": "fresh",
        "prompt_injection": prompt_injection,
        "dependency_ood": dependency_ood_screen_json(subject),
    })
}

pub(crate) fn prompt_sources_from_row_sink_rows(
    rows: &CbmPipelineRows,
    skips: &mut Vec<Value>,
) -> Vec<OwnedPromptSource> {
    let mut sources = Vec::new();
    for node in &rows.nodes {
        let source_prefix = node_prompt_source_prefix(node);
        let properties = match serde_json::from_str::<Value>(&node.properties_json) {
            Ok(value) => value,
            Err(error) => {
                skips.push(skipped_screen_json(
                    PROMPT_INJECTION_FINDING_KIND,
                    &format!("{source_prefix}#properties_json"),
                    &format!("properties_json_unparseable: {error}"),
                    "repair the CBM node properties JSON and rerun the shadow import",
                ));
                continue;
            }
        };

        push_prompt_string_field(
            &mut sources,
            &source_prefix,
            &properties,
            "docstring",
            PromptSourceKind::Docstring,
        );
        push_prompt_string_field(
            &mut sources,
            &source_prefix,
            &properties,
            "comment",
            PromptSourceKind::Comment,
        );
        push_prompt_string_array_field(
            &mut sources,
            &source_prefix,
            &properties,
            "comments",
            PromptSourceKind::Comment,
        );
        if node.label.eq_ignore_ascii_case("section") {
            push_owned_prompt_source(
                &mut sources,
                format!("{source_prefix}#name"),
                PromptSourceKind::Section,
                &node.name,
            );
            for field in ["content", "text", "body"] {
                push_prompt_string_field(
                    &mut sources,
                    &source_prefix,
                    &properties,
                    field,
                    PromptSourceKind::Section,
                );
            }
        }
    }
    sources
}

pub(crate) fn push_prompt_string_field(
    sources: &mut Vec<OwnedPromptSource>,
    source_prefix: &str,
    properties: &Value,
    field: &str,
    source_kind: PromptSourceKind,
) {
    if let Some(text) = properties.get(field).and_then(Value::as_str) {
        push_owned_prompt_source(
            sources,
            format!("{source_prefix}#{field}"),
            source_kind,
            text,
        );
    }
}

pub(crate) fn push_prompt_string_array_field(
    sources: &mut Vec<OwnedPromptSource>,
    source_prefix: &str,
    properties: &Value,
    field: &str,
    source_kind: PromptSourceKind,
) {
    let Some(items) = properties.get(field).and_then(Value::as_array) else {
        return;
    };
    for (index, item) in items.iter().enumerate() {
        if let Some(text) = item.as_str() {
            push_owned_prompt_source(
                sources,
                format!("{source_prefix}#{field}[{index}]"),
                source_kind,
                text,
            );
        }
    }
}

pub(crate) fn push_owned_prompt_source(
    sources: &mut Vec<OwnedPromptSource>,
    source_id: String,
    source_kind: PromptSourceKind,
    text: &str,
) {
    if text.trim().is_empty() {
        return;
    }
    sources.push(OwnedPromptSource {
        source_id,
        source_kind,
        text: text.to_string(),
    });
}

pub(crate) fn node_prompt_source_prefix(node: &astrolabe_bridge::CbmPipelineNodeRow) -> String {
    format!("node:{}:{}:{}", node.project, node.id, node.qualified_name)
}

pub(crate) fn prompt_injection_screen_summary(
    findings: &[PromptInjectionFinding],
    screened_sources: usize,
    skips: Vec<Value>,
) -> Value {
    let status = if screened_sources == 0 && !skips.is_empty() {
        "skipped"
    } else if skips.is_empty() {
        "screened"
    } else {
        "partial"
    };
    json!({
        "screen": PROMPT_INJECTION_FINDING_KIND,
        "status": status,
        "pattern_registry_version": PROMPT_INJECTION_PATTERN_REGISTRY_VERSION,
        "screened_sources": screened_sources,
        "finding_count": findings.len(),
        "skipped_count": skips.len(),
        "trust": "provisional",
        "freshness": if status == "skipped" { "not_evaluated" } else { "fresh" },
        "findings": findings.iter().map(prompt_injection_finding_json).collect::<Vec<_>>(),
        "grounding_notes": findings
            .iter()
            .map(prompt_injection_grounding_note_json)
            .collect::<Vec<_>>(),
        "skips": skips,
    })
}

pub(crate) fn prompt_injection_finding_json(finding: &PromptInjectionFinding) -> Value {
    json!({
        "kind": finding.kind,
        "pattern_registry_version": finding.pattern_registry_version,
        "pattern_id": finding.pattern_id,
        "family": prompt_injection_family_str(finding.family),
        "severity": security_finding_severity_str(finding.severity),
        "source_id": finding.source_id,
        "source_kind": finding.source_kind.as_str(),
        "matched_signature": finding.matched_signature,
        "trust": finding.trust,
        "freshness": finding.freshness,
        "remediation": finding.remediation,
    })
}

pub(crate) fn prompt_injection_grounding_note_json(finding: &PromptInjectionFinding) -> Value {
    // Single source of truth: the grounding-note text is owned by the guard
    // contract crate. We only serialize the note it builds — never re-derive
    // the message string here (that copy previously drifted from guard).
    let note = SecurityGroundingNote::from_prompt_injection_finding(finding);
    json!({
        "kind": note.kind,
        "source_id": note.source_id,
        "source_kind": note.source_kind.as_str(),
        "trust": note.trust,
        "freshness": note.freshness,
        "message": note.message,
    })
}

pub(crate) fn dependency_ood_screen_json(subject: &str) -> Value {
    let skipped = dependency_ood_screen_unavailable(subject);
    json!({
        "screen": skipped.screen,
        "subject": skipped.subject,
        "status": skipped.status,
        "skipped_count": skipped.skipped_count,
        "trust": skipped.trust,
        "freshness": skipped.freshness,
        "reason": skipped.reason,
        "remediation": skipped.remediation,
    })
}

pub(crate) fn skipped_screen_json(
    screen: &str,
    subject: &str,
    reason: &str,
    remediation: &str,
) -> Value {
    json!({
        "screen": screen,
        "subject": subject,
        "status": "skipped",
        "skipped_count": 1,
        "trust": "provisional",
        "freshness": "not_evaluated",
        "reason": reason,
        "remediation": remediation,
    })
}

pub(crate) fn read_security_screen_metadata(
    cache_dir: &Path,
    project: &str,
) -> Result<Value, DynError> {
    let subject = security_screen_subject(project);
    let Some(raw) = read_config_value(cache_dir, &metadata_key(project, "security_screen_json"))?
    else {
        return Ok(security_screen_unavailable(
            subject,
            "security screen metadata missing; rerun index_repository with calyx shadow",
        ));
    };
    match serde_json::from_str::<Value>(&raw) {
        Ok(value) => Ok(value),
        Err(error) => Ok(security_screen_unavailable(
            subject,
            &format!("stored security_screen_json invalid: {error}"),
        )),
    }
}

pub(crate) fn security_screen_subject(project: &str) -> String {
    format!("project:{project}")
}

pub(crate) fn prompt_injection_family_str(family: PromptInjectionFamily) -> &'static str {
    family.as_str()
}

pub(crate) fn security_finding_severity_str(severity: SecurityFindingSeverity) -> &'static str {
    severity.as_str()
}
