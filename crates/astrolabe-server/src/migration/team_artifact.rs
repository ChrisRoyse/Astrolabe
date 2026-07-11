use super::*;
pub(crate) const CBM_TEAM_ARTIFACT_DIR: &str = ".codebase-memory";
pub(crate) const ASTRO_TEAM_ARTIFACT_ERROR: &str = "ASTRO_TEAM_ARTIFACT_ERROR";
pub(crate) const ASTRO_TEAM_ARTIFACT_NOT_READY: &str = "ASTRO_TEAM_ARTIFACT_NOT_READY";

pub(crate) fn handle_team_artifact(args_json: &str) -> Result<String, DynError> {
    let args = serde_json::from_str::<Value>(args_json)?;
    let Some(args_obj) = args.as_object() else {
        return tool_error_result("team_artifact arguments must be a JSON object");
    };
    let Some(mode) = string_arg(args_obj, "mode") else {
        return tool_error_result("team_artifact requires mode: export or import");
    };
    match mode {
        "export" => handle_team_artifact_export(args_obj),
        "import" => handle_team_artifact_import(args_obj),
        other => tool_error_result(format!(
            "ASTRO_TEAM_ARTIFACT_MODE_UNSUPPORTED: team_artifact mode {other:?} is not available; remediation: use mode=\"export\" or mode=\"import\""
        )),
    }
}

pub(crate) fn handle_team_artifact_export(args: &Map<String, Value>) -> Result<String, DynError> {
    let Some(project) = team_project_from_args(args)? else {
        return tool_error_result("team_artifact export requires project");
    };
    if read_dial(&project)? != MigrationDial::Shadow {
        return tool_error_result(
            "team_artifact export requires calyx shadow indexing; run index_repository with calyx=\"shadow\"",
        );
    }
    let refresh_status = match ensure_shadow_import_current(&project) {
        Ok(ShadowRefreshStatus::Busy) => {
            return tool_error_result(
                "ASTRO_TEAM_ARTIFACT_BUSY: shadow import is owned by another process; remediation: retry export after index_status reports shadow_import.status=current",
            );
        }
        Ok(status) => status,
        Err(error) => {
            return tool_error_result(format!(
                "ASTRO_TEAM_ARTIFACT_NOT_READY: shadow import recovery failed: {error}; remediation: rerun index_repository with calyx=\"shadow\" before exporting"
            ));
        }
    };
    let artifact_dir = match team_artifact_dir_from_args(args, "export") {
        Ok(path) => path,
        Err(message) => return tool_error_result(message),
    };
    let signing_key =
        match optional_hex32_arg(args, "signing_key_hex", ASTRO_TEAM_ARTIFACT_SIGNATURE) {
            Ok(value) => value,
            Err(message) => return tool_error_result(message),
        };
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    match team_artifact_export_json_at(
        &cache_dir,
        &project,
        &artifact_dir,
        signing_key,
        refresh_status,
    ) {
        Ok(value) => tool_json_result(value),
        Err(error) => team_artifact_error_result("export", &project, &artifact_dir, None, error),
    }
}

pub(crate) fn handle_team_artifact_import(args: &Map<String, Value>) -> Result<String, DynError> {
    let project = team_project_from_args(args)?;
    let artifact_dir = match team_artifact_dir_from_args(args, "import") {
        Ok(path) => path,
        Err(message) => return tool_error_result(message),
    };
    let adopted_graph_path = match team_adopted_graph_path_from_args(args, project.as_deref()) {
        Ok(path) => path,
        Err(message) => return tool_error_result(message),
    };
    let expected_signer = match optional_hex32_arg(
        args,
        "expected_signer_pubkey_hex",
        ASTRO_TEAM_ARTIFACT_SIGNATURE_SIGNER,
    ) {
        Ok(value) => value,
        Err(message) => return tool_error_result(message),
    };
    team_artifact_import_result(
        &artifact_dir,
        &adopted_graph_path,
        expected_signer,
        project.as_deref(),
    )
}

pub(crate) fn team_artifact_export_json_at(
    cache_dir: &Path,
    project: &str,
    artifact_dir: &Path,
    signing_key: Option<[u8; 32]>,
    refresh_status: ShadowRefreshStatus,
) -> Result<Value, DynError> {
    let configured_vault_dir = read_config_value(cache_dir, &metadata_key(project, "vault_dir"))?
        .map(PathBuf::from)
        .unwrap_or_else(|| vault_dir(cache_dir, project));
    let lowered_path = read_config_value(cache_dir, &metadata_key(project, "lowered_sqlite_path"))?
        .map(PathBuf::from)
        .unwrap_or_else(|| lowered_sqlite_path(cache_dir, project));
    if !lowered_path.exists() {
        return Err(format!(
            "{ASTRO_TEAM_ARTIFACT_NOT_READY}: lowered SQLite sidecar is missing at {}; remediation: rerun index_status or index_repository with calyx=\"shadow\"",
            lowered_path.display()
        )
        .into());
    }
    let verify = astrolabe_ingest::verify_chain_vault_path(&configured_vault_dir)?;
    if !verify.is_intact() {
        return Err(format!(
            "{ASTRO_TEAM_ARTIFACT_LEDGER_TAIL}: shadow vault verify_chain status is {}; remediation: repair or reindex before exporting",
            verify.status
        )
        .into());
    }
    let vault_id = read_config_value(cache_dir, &metadata_key(project, "vault_id"))?
        .unwrap_or_else(|| SHADOW_VAULT_ID.to_string());
    let vault_salt = read_config_value(cache_dir, &metadata_key(project, "vault_salt"))?
        .unwrap_or_else(|| vault_salt(project));
    let vault = AsterVault::new_durable(
        &configured_vault_dir,
        VaultId::from_str(&vault_id)?,
        vault_salt.as_bytes().to_vec(),
        VaultOptions::default(),
    )?;
    let options = match signing_key {
        Some(key) => TeamArtifactExportOptions::with_signing_key(key),
        None => TeamArtifactExportOptions::unsigned(),
    };
    let report = export_team_artifact(&vault, &lowered_path, artifact_dir, &options)?;
    team_artifact_export_report_json(
        project,
        artifact_dir,
        &configured_vault_dir,
        &lowered_path,
        &verify,
        refresh_status,
        &report,
    )
}

pub(crate) fn team_artifact_import_result(
    artifact_dir: &Path,
    adopted_graph_path: &Path,
    expected_signer: Option<[u8; 32]>,
    project: Option<&str>,
) -> Result<String, DynError> {
    let options = match expected_signer {
        Some(pubkey) => TeamArtifactImportOptions::with_expected_signer(pubkey),
        None => TeamArtifactImportOptions::new(),
    };
    match import_team_artifact(artifact_dir, adopted_graph_path, &options) {
        Ok(report) => tool_json_result(team_artifact_import_report_json(
            project,
            artifact_dir,
            &report,
        )?),
        Err(error) => team_artifact_error_result(
            "import",
            project.unwrap_or("unknown"),
            artifact_dir,
            Some(adopted_graph_path),
            error,
        ),
    }
}

pub(crate) fn team_artifact_export_report_json(
    project: &str,
    artifact_dir: &Path,
    vault_dir: &Path,
    lowered_sqlite_path: &Path,
    verify: &astrolabe_ingest::VerifyChainReport,
    refresh_status: ShadowRefreshStatus,
    report: &TeamArtifactExportReport,
) -> Result<Value, DynError> {
    let mut value = json!({
        "schema": TEAM_ARTIFACT_SCHEMA,
        "mode": "export",
        "status": "exported",
        "project": project,
        "freshness": "fresh",
        "trust": "verified",
        "artifact_dir": artifact_dir,
        "manifest_path": report.manifest_path,
        "graph_db_zst_path": report.graph_db_zst_path,
        "vault_export_zst_path": report.vault_export_zst_path,
        "manifest": serde_json::to_value(&report.manifest)?,
        "signature_status": if report.manifest.signature.is_some() { "signed" } else { "unsigned" },
        "source_state": {
            "shadow_refresh": shadow_refresh_status_str(refresh_status),
            "vault_dir": vault_dir,
            "lowered_sqlite_path": lowered_sqlite_path,
            "verify_chain": verify.status,
            "ledger_rows": verify.ledger_rows,
            "checked_range_start": verify.checked_range_start,
            "checked_range_end": verify.checked_range_end,
        },
        "files": {
            "graph_db_zst": {
                "name": GRAPH_DB_ZST_NAME,
                "path": report.graph_db_zst_path,
                "sha256": report.manifest.graph_db_zst_sha256,
            },
            "vault_export_zst": {
                "name": VAULT_EXPORT_ZST_NAME,
                "path": report.vault_export_zst_path,
                "sha256": report.manifest.vault_export_zst_sha256,
            },
            "manifest": {
                "path": report.manifest_path,
            },
        },
    });
    refresh_value_artifact_hash(&mut value);
    Ok(value)
}

pub(crate) fn team_artifact_import_report_json(
    project: Option<&str>,
    artifact_dir: &Path,
    report: &TeamArtifactImportReport,
) -> Result<Value, DynError> {
    let mut value = json!({
        "schema": TEAM_ARTIFACT_SCHEMA,
        "mode": "import",
        "status": "imported",
        "project": project,
        "freshness": "fresh",
        "trust": if report.mode == "chain_verified_vault_export" { "verified" } else { "provisional" },
        "artifact_dir": artifact_dir,
        "import": {
            "mode": report.mode,
            "adopted_graph_path": report.adopted_graph_path,
            "graph_db_sha256": report.graph_db_sha256,
            "ledger_rows": report.ledger_rows,
            "merkle_root": report.merkle_root,
            "signature_status": report.signature_status,
            "fallback": report.fallback,
        },
        "serving": {
            "legacy_sqlite_adopted": true,
            "vault_restored": false,
            "trust": if report.mode == "chain_verified_vault_export" { "verified" } else { "provisional" },
            "remediation": if report.mode == "chain_verified_vault_export" {
                Value::String("legacy tools can serve the adopted graph; rerun index_repository with calyx=\"shadow\" on this machine before trusting local vault-backed surfaces".to_string())
            } else {
                Value::String("legacy graph.db.zst was adopted without vault proof; run a local reindex before treating Astrolabe vault-backed surfaces as verified".to_string())
            },
        },
    });
    refresh_value_artifact_hash(&mut value);
    Ok(value)
}

pub(crate) fn team_artifact_error_result<E>(
    mode: &str,
    project: &str,
    artifact_dir: &Path,
    adopted_graph_path: Option<&Path>,
    error: E,
) -> Result<String, DynError>
where
    E: std::fmt::Display,
{
    let message = error.to_string();
    let code = team_artifact_error_code(&message);
    let mut value = json!({
        "schema": TEAM_ARTIFACT_SCHEMA,
        "mode": mode,
        "status": "refused",
        "project": project,
        "artifact_dir": artifact_dir,
        "code": code,
        "message": message,
        "remediation": "run index_repository with this repo_path to rebuild the local CBM graph; run it with calyx=\"shadow\" before trusting vault-backed surfaces",
        "freshness": "fresh",
        "trust": "verified",
        "fallback": {
            "local_reindex": "not_run",
            "remediation": "run index_repository with this repo_path to rebuild the local CBM graph; run it with calyx=\"shadow\" before trusting vault-backed surfaces",
        },
    });
    if let Some(path) = adopted_graph_path
        && let Some(object) = value.as_object_mut()
    {
        object.insert("adopted_graph_path".to_string(), json!(path));
    }
    refresh_value_artifact_hash(&mut value);
    tool_json_error_result(value)
}

pub(crate) fn team_project_from_args(
    args: &Map<String, Value>,
) -> Result<Option<String>, DynError> {
    if let Some(project) = status_project_from_args(args)? {
        return Ok(Some(project));
    }
    Ok(string_arg(args, "repo_path")
        .map(astrolabe_bridge::cbm_project_name_from_path)
        .transpose()?)
}

pub(crate) fn team_artifact_dir_from_args(
    args: &Map<String, Value>,
    mode: &str,
) -> Result<PathBuf, String> {
    if let Some(path) = string_arg(args, "artifact_dir")
        .or_else(|| string_arg(args, "output_dir"))
        .or_else(|| string_arg(args, "input_dir"))
    {
        return Ok(PathBuf::from(path));
    }
    if let Some(repo_path) = string_arg(args, "repo_path") {
        return Ok(PathBuf::from(repo_path).join(CBM_TEAM_ARTIFACT_DIR));
    }
    Err(format!(
        "team_artifact {mode} requires artifact_dir or repo_path"
    ))
}

pub(crate) fn team_adopted_graph_path_from_args(
    args: &Map<String, Value>,
    project: Option<&str>,
) -> Result<PathBuf, String> {
    if let Some(path) =
        string_arg(args, "adopted_graph_path").or_else(|| string_arg(args, "cache_db_path"))
    {
        return Ok(PathBuf::from(path));
    }
    let Some(project) = project else {
        return Err(
            "team_artifact import requires adopted_graph_path, or project/repo_path to derive the local CBM cache DB".to_string(),
        );
    };
    let cache_dir = astrolabe_bridge::cbm_cache_dir()
        .map_err(|error| format!("resolve CBM cache dir: {error}"))?;
    Ok(sqlite_path(&cache_dir, project))
}

pub(crate) fn optional_hex32_arg(
    args: &Map<String, Value>,
    key: &str,
    code: &str,
) -> Result<Option<[u8; 32]>, String> {
    let Some(raw) = string_arg(args, key) else {
        return Ok(None);
    };
    decode_hex_32_arg(raw, key, code).map(Some)
}

pub(crate) fn decode_hex_32_arg(raw: &str, key: &str, code: &str) -> Result<[u8; 32], String> {
    if raw.len() != 64 {
        return Err(format!("{code}: {key} must be exactly 64 hex characters"));
    }
    let mut out = [0_u8; 32];
    for (index, chunk) in raw.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble_arg(chunk[0], key, code)?;
        let low = hex_nibble_arg(chunk[1], key, code)?;
        out[index] = (high << 4) | low;
    }
    Ok(out)
}

pub(crate) fn hex_nibble_arg(byte: u8, key: &str, code: &str) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!("{code}: {key} contains non-hex bytes")),
    }
}

pub(crate) fn team_artifact_error_code(message: &str) -> &str {
    for code in [
        ASTRO_TEAM_ARTIFACT_NOT_READY,
        ASTRO_TEAM_ARTIFACT_MISSING_GRAPH,
        ASTRO_TEAM_ARTIFACT_GRAPH_BYTES,
        ASTRO_TEAM_ARTIFACT_VAULT_BYTES,
        ASTRO_TEAM_ARTIFACT_LEDGER_TAIL,
        ASTRO_TEAM_ARTIFACT_MERKLE_ROOT,
        ASTRO_TEAM_ARTIFACT_SIGNATURE,
        ASTRO_TEAM_ARTIFACT_SIGNATURE_SIGNER,
    ] {
        if message.starts_with(code) {
            return code;
        }
    }
    ASTRO_TEAM_ARTIFACT_ERROR
}
