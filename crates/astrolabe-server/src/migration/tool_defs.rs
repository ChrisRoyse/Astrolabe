use super::*;

pub(crate) fn astrolabe_tool_definitions() -> [Value; 7] {
    [
        get_provenance_tool_definition(),
        detect_anomalies_tool_definition(),
        optimizer_status_tool_definition(),
        get_readiness_tool_definition(),
        impute_fields_tool_definition(),
        anchor_outcome_tool_definition(),
        team_artifact_tool_definition(),
    ]
}

pub(crate) fn anchor_outcome_tool_definition() -> Value {
    json!({
        "name": "anchor_outcome",
        "title": "Anchor Outcome",
        "description": "Ground real-world outcome anchors for a shadow-indexed project. The test_run kind parses a JUnit/cargo/pytest/go/vitest report and writes one grounded TestPass anchor per resolved subject, paired with a Grounding ledger entry. Source must be 'ci:<provider>:<run_id>' (certain, confidence 1.0) or 'local:<context>' (provisional).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {
                    "type": "string",
                    "description": "CBM project name for a project indexed with calyx=\"shadow\"."
                },
                "kind": {
                    "type": "string",
                    "enum": ["test_run"],
                    "description": "Outcome kind. Only test_run is wired with a built-in payload."
                },
                "source": {
                    "type": "string",
                    "description": "Enforced-prefix outcome source: 'ci:<provider>:<run_id>' for CI-resolved runs or 'local:<context>' for uncommitted local runs."
                },
                "format": {
                    "type": "string",
                    "enum": ["junit_xml", "cargo_test_json", "pytest_verbose", "go_test_json", "vitest_json"],
                    "description": "Test-report format for the report payload."
                },
                "report": {
                    "type": "string",
                    "description": "Full test-report text in the declared format. Partial or malformed reports refuse fail-closed."
                },
                "report_text": {
                    "type": "string",
                    "description": "Alias for report."
                },
                "confidence": {
                    "type": "number",
                    "description": "Optional confidence. Omit for the source default (ci: exactly 1.0, local: 0.8). A ci: source may only carry exactly 1.0; a local: source must be finite in the open interval (0, 1)."
                },
                "observed_at": {
                    "type": "integer",
                    "description": "Server-observed epoch (seconds or ms) at which the outcome was observed. Defaults to the server wall clock; pass an explicit value for reproducible CI anchoring. 0 refuses."
                }
            },
            "required": ["project", "source", "format"],
            "additionalProperties": false
        },
        "outputSchema": {
            "type": "object",
            "properties": {
                "content": {
                    "type": "array",
                    "items": {"type": "object"}
                },
                "structuredContent": {"type": "object"},
                "isError": {"type": "boolean"}
            },
            "required": ["content", "isError"],
            "additionalProperties": true
        }
    })
}

pub(crate) fn get_provenance_tool_definition() -> Value {
    json!({
        "name": "get_provenance",
        "title": "Get Provenance",
        "description": "Return labeled Astrolabe provenance for a shadow-indexed project. Modes are lineage, answer_trace, verify_chain, and reproduce.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {
                    "type": "string",
                    "description": "CBM project name for a project indexed with calyx=\"shadow\"."
                },
                "mode": {
                    "type": "string",
                    "enum": ["lineage", "answer_trace", "verify_chain", "reproduce"]
                },
                "subject_id": {
                    "type": "string",
                    "description": "Symbol id or answer id required by lineage, answer_trace, and reproduce."
                },
                "subject": {
                    "type": "string",
                    "description": "Alias for subject_id."
                }
            },
            "required": ["project", "mode"],
            "additionalProperties": false
        },
        "outputSchema": {
            "type": "object",
            "properties": {
                "content": {
                    "type": "array",
                    "items": {"type": "object"}
                },
                "structuredContent": {"type": "object"},
                "isError": {"type": "boolean"}
            },
            "required": ["content", "isError"],
            "additionalProperties": true
        }
    })
}

pub(crate) fn detect_anomalies_tool_definition() -> Value {
    json!({
        "name": "detect_anomalies",
        "title": "Detect Anomalies",
        "description": "Return calibrated Astrolabe anomaly findings for a shadow-indexed project, optionally filtered by kind.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {
                    "type": "string",
                    "description": "CBM project name for a project indexed with calyx=\"shadow\"."
                },
                "kind": {
                    "type": "string",
                    "enum": ["doc_drift", "name_truth", "drift", "ood_commit", "prompt_injection"]
                }
            },
            "required": ["project"],
            "additionalProperties": false
        },
        "outputSchema": {
            "type": "object",
            "properties": {
                "content": {
                    "type": "array",
                    "items": {"type": "object"}
                },
                "structuredContent": {"type": "object"},
                "isError": {"type": "boolean"}
            },
            "required": ["content", "isError"],
            "additionalProperties": true
        }
    })
}

pub(crate) fn optimizer_status_tool_definition() -> Value {
    json!({
        "name": "optimizer_status",
        "title": "Optimizer Status",
        "description": "Return labeled Astrolabe optimizer readiness for a shadow-indexed project, durably acknowledge pending reactive trigger events for a subscription, or generate pending proposals from measured deficits.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {
                    "type": "string",
                    "description": "CBM project name for a project indexed with calyx=\"shadow\"."
                },
                "mode": {
                    "type": "string",
                    "enum": ["status", "ack_triggers", "propose"],
                    "description": "Use status for readback, ack_triggers to append a durable acknowledgement for one subscription, or propose to turn measured deficits into a persisted proposal queue."
                },
                "subscription_id": {
                    "type": "string",
                    "description": "Required when mode is ack_triggers; use a subscription_id returned by optimizer_status.reactive_triggers.subscriptions."
                }
            },
            "required": ["project"],
            "additionalProperties": false
        },
        "outputSchema": {
            "type": "object",
            "properties": {
                "content": {
                    "type": "array",
                    "items": {"type": "object"}
                },
                "structuredContent": {"type": "object"},
                "isError": {"type": "boolean"}
            },
            "required": ["content", "isError"],
            "additionalProperties": true
        }
    })
}

pub(crate) fn get_readiness_tool_definition() -> Value {
    json!({
        "name": "get_readiness",
        "title": "Get Readiness",
        "description": "Return Astrolabe's six-tier readiness predicate for a shadow-indexed project/scope. Tiers fail closed unless their measured source state is present.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {
                    "type": "string",
                    "description": "CBM project name for a project indexed with calyx=\"shadow\"."
                },
                "scope": {
                    "type": "string",
                    "description": "Optional scope id to evaluate. If omitted, project-level readiness is reported."
                },
                "axis": {
                    "type": "string",
                    "description": "Optional readiness axis label; currently used only for labeled remediation."
                }
            },
            "required": ["project"],
            "additionalProperties": false
        },
        "outputSchema": {
            "type": "object",
            "properties": {
                "content": {
                    "type": "array",
                    "items": {"type": "object"}
                },
                "structuredContent": {"type": "object"},
                "isError": {"type": "boolean"}
            },
            "required": ["content", "isError"],
            "additionalProperties": true
        }
    })
}

pub(crate) fn impute_fields_tool_definition() -> Value {
    json!({
        "name": "impute_fields",
        "title": "Impute Fields",
        "description": "Return persisted Astrolabe imputation proposals for a target field. Proposals are always inferred/provisional and are never written as trusted data.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {
                    "type": "string",
                    "description": "CBM project name for a project indexed with calyx=\"shadow\"."
                },
                "target": {
                    "type": "string",
                    "description": "Stable target id whose missing field should be proposed."
                },
                "field": {
                    "type": "string",
                    "enum": ["doc", "types", "callees", "tests"],
                    "description": "Missing field to impute."
                },
                "write_as_trusted": {
                    "type": "boolean",
                    "description": "If true, the tool refuses; imputed values cannot be merged as trusted data."
                }
            },
            "required": ["project", "target", "field"],
            "additionalProperties": false
        },
        "outputSchema": {
            "type": "object",
            "properties": {
                "content": {
                    "type": "array",
                    "items": {"type": "object"}
                },
                "structuredContent": {"type": "object"},
                "isError": {"type": "boolean"}
            },
            "required": ["content", "isError"],
            "additionalProperties": true
        }
    })
}

pub(crate) fn team_artifact_tool_definition() -> Value {
    json!({
        "name": "team_artifact",
        "title": "Team Artifact",
        "description": "Export or import the chain-verified Astrolabe team artifact. Use repo_path to target <repo>/.codebase-memory, or pass artifact_dir explicitly.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "mode": {
                    "type": "string",
                    "enum": ["export", "import"],
                    "description": "export writes graph.db.zst, vault.export.zst, and artifact.json; import verifies before adopting graph bytes."
                },
                "project": {
                    "type": "string",
                    "description": "CBM project name. Required for export; import uses it to default adopted_graph_path to the local CBM cache DB."
                },
                "repo_path": {
                    "type": "string",
                    "description": "Repository path whose .codebase-memory directory contains or receives the team artifact."
                },
                "artifact_dir": {
                    "type": "string",
                    "description": "Explicit artifact directory. Overrides repo_path/.codebase-memory."
                },
                "output_dir": {
                    "type": "string",
                    "description": "Alias for artifact_dir in export mode."
                },
                "input_dir": {
                    "type": "string",
                    "description": "Alias for artifact_dir in import mode."
                },
                "adopted_graph_path": {
                    "type": "string",
                    "description": "Import destination for verified graph bytes. Defaults to the local CBM cache DB for project."
                },
                "cache_db_path": {
                    "type": "string",
                    "description": "Alias for adopted_graph_path when importing into a CBM cache DB."
                },
                "signing_key_hex": {
                    "type": "string",
                    "description": "Optional 32-byte hex Ed25519 signing seed for export."
                },
                "expected_signer_pubkey_hex": {
                    "type": "string",
                    "description": "Optional 32-byte hex signer public key required during import."
                }
            },
            "required": ["mode"],
            "additionalProperties": false
        },
        "outputSchema": {
            "type": "object",
            "properties": {
                "content": {
                    "type": "array",
                    "items": {"type": "object"}
                },
                "structuredContent": {"type": "object"},
                "isError": {"type": "boolean"}
            },
            "required": ["content", "isError"],
            "additionalProperties": true
        }
    })
}
