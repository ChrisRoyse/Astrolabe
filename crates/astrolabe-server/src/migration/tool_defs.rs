use super::*;

pub(crate) fn astrolabe_tool_definitions() -> [Value; 9] {
    [
        get_provenance_tool_definition(),
        detect_anomalies_tool_definition(),
        optimizer_status_tool_definition(),
        get_readiness_tool_definition(),
        impute_fields_tool_definition(),
        anchor_outcome_tool_definition(),
        coverage_ingest_tool_definition(),
        team_artifact_tool_definition(),
        guard_calibrate_tool_definition(),
    ]
}

pub(crate) fn coverage_ingest_tool_definition() -> Value {
    json!({
        "name": "coverage_ingest",
        "title": "Coverage Ingest",
        "description": "Ground outcome anchors for a shadow-indexed project from a direct coverage report plus a suite run. Assembles propagation inputs from the live CBM graph (symbol line ranges + TESTS/TESTS_FILE edges), maps executed lines to the containing symbols line-exact (resolved, confidence 1.0), and — bounded to the changed-files impact set — propagates passing tests one hop along TESTS edges to covered symbols (proxy, confidence 0.6). Coverage supersedes propagation for any symbol it covers. Reports anchored / excluded_by_fanout / unmatched counts. Malformed reports, a non-resolved coverage_source, or an empty graph refuse fail-closed with no partial anchor.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {
                    "type": "string",
                    "description": "CBM project name for a project indexed with calyx=\"shadow\"."
                },
                "coverage_format": {
                    "type": "string",
                    "enum": ["lcov", "coverage_py_json", "cobertura_xml"],
                    "description": "Direct-coverage report format."
                },
                "coverage_report": {
                    "type": "string",
                    "description": "Full coverage report text in the declared format. Partial or malformed reports refuse fail-closed."
                },
                "test_format": {
                    "type": "string",
                    "enum": ["junit_xml", "cargo_test_json", "pytest_verbose", "go_test_json", "vitest_json"],
                    "description": "Suite-run report format, used to determine which tests passed for propagation."
                },
                "test_report": {
                    "type": "string",
                    "description": "Full suite-run report text in the declared test_format."
                },
                "coverage_source": {
                    "type": "string",
                    "description": "Resolved catalog source for coverage anchors: ci:/trace:/review:/git:revert: (Trusted, confidence 1.0). A proxy source refuses fail-closed."
                },
                "run_id": {
                    "type": "string",
                    "description": "Opaque run identifier; propagation anchors are sourced propagation:<run_id>."
                },
                "impact_files": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Changed files' impact set (repo-relative). Propagation anchors are confined to symbols in these files. Empty (default) means no diff: only direct coverage grounds."
                },
                "observed_at": {
                    "type": "integer",
                    "description": "Server-observed epoch (seconds or ms). Defaults to the server wall clock; pass an explicit value for reproducible anchoring. 0 refuses."
                }
            },
            "required": ["project", "coverage_format", "coverage_report", "test_format", "test_report", "coverage_source", "run_id"],
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

pub(crate) fn guard_calibrate_tool_definition() -> Value {
    json!({
        "name": "guard_calibrate",
        "title": "Guard Calibrate",
        "description": "Build/refresh a per-domain guard profile by split (inductive) conformal calibration. Each fixed guard slot's per-slot tau is set on a calibration half of its measured bad-cosine population (binomial-bounded), the achieved FAR is measured on a held-out validation half and checked against a finite-sample ceiling, and the FRR is measured on the good population. The calibration is ledgered (kind=Guard, subject=Guard(profile_hash)) and the astrolabe.optimizer_guard_health.v1 profile is persisted. Fails closed on a missing slot, a thin (<2) or single-source population, or a slot whose held-out FAR breaches its bound.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {
                    "type": "string",
                    "description": "CBM project name for a project indexed with calyx=\"shadow\"."
                },
                "domain": {
                    "type": "object",
                    "description": "Calibration domain = language x scope-class.",
                    "properties": {
                        "language": {
                            "type": "string",
                            "enum": ["rust", "python", "javascript", "typescript", "go", "java", "c", "cpp", "csharp", "ruby"]
                        },
                        "scope_class": {
                            "type": "string",
                            "description": "Non-empty scope class such as core, frontend, or test."
                        }
                    },
                    "required": ["language", "scope_class"],
                    "additionalProperties": false
                },
                "alpha": {
                    "type": "number",
                    "description": "Binomial confidence level for the per-slot tau bound (default 0.05)."
                },
                "slots": {
                    "type": "array",
                    "description": "One object per fixed guard slot with measured good_scores and bad_scores cosine arrays.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "slot": {
                                "type": "string",
                                "enum": ["code_semantic", "struct_trigrams", "api_callees", "name_semantic", "complexity_profile", "error_surface", "public_api_signature"]
                            },
                            "good_scores": {"type": "array", "items": {"type": "number"}},
                            "bad_scores": {"type": "array", "items": {"type": "number"}}
                        },
                        "required": ["slot", "good_scores", "bad_scores"],
                        "additionalProperties": false
                    }
                }
            },
            "required": ["project", "domain", "slots"],
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

pub(crate) fn anchor_outcome_tool_definition() -> Value {
    json!({
        "name": "anchor_outcome",
        "title": "Anchor Outcome",
        "description": "Ground real-world outcome anchors for a shadow-indexed project. The test_run kind parses a JUnit/cargo/pytest/go/vitest report and writes one grounded TestPass anchor per resolved subject, paired with a Grounding ledger entry. Catalog sources are ci:/trace:/review:/git:revert: (Trusted, confidence 1.0) and git:fix:/agent:/survival: (Provisional, confidence in (0,1)).",
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
                    "description": "Catalog source: ci:/trace:/review:/git:revert: for resolved evidence, or git:fix:/agent:/survival: for proxy evidence. ci: and agent: require owner plus observation components."
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
                    "description": "Optional confidence. Resolved sources require exactly 1.0; proxy sources require a finite value in (0,1) and default to 0.8."
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
