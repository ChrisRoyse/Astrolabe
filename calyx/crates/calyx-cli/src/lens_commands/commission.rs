use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use calyx_core::{Input, Lens, Modality, QuantPolicy, SlotShape};
use calyx_registry::{
    DEFAULT_TEI_ENDPOINT, FrozenLensContract, LensForgeManifest, LensForgeShape,
    LensForgeSourceTensorDtypeProfile, NormPolicy, OnnxInt8Attestation, OnnxInt8Toolchain,
    TeiHttpLens, attest_onnx_int8, profile_safetensors_sources, resolve_safetensors_weight_set,
};
use serde::Serialize;
use serde_json::json;

mod artifact;
mod batch_preflight;
mod candle;
mod fastembed;
mod fastembed_special;
mod log;
mod onnx_colbert;
mod options;
mod tei;

use artifact::{
    Artifact, FileReport, add_optional, artifact, artifact_set_sha256, file_report, find_preferred,
    manifest_files, read_hidden_size, require_named, require_named_fallback,
};
use log::{ConversionLog, run_command, run_command_capture, write_json_file};
use options::{CommissionFlags, CommissionRuntime};

use super::catalog::admission::LocalExecutionAttestationReport;
use super::catalog::{AddReport, add_attested_manifest_to_catalog};
use super::support::validate_vector_contract;
use crate::error::{CliError, CliResult};
use crate::output::print_json;

const DEFAULT_TEI_DIM: u32 = 768;
const MANIFEST_NAME: &str = "lensforge.manifest.json";
const CONVERSION_LOG_NAME: &str = "conversion-log.jsonl";

#[derive(Serialize)]
struct CommissionReport {
    hf: String,
    runtime: String,
    dtype: String,
    execution_device: Option<String>,
    device_policy: Option<String>,
    output_dir: PathBuf,
    manifest: PathBuf,
    conversion_log: PathBuf,
    max_batch: Option<usize>,
    batch_policy: calyx_registry::LensForgeBatchPolicy,
    source_tensor_dtype_profile: Option<LensForgeSourceTensorDtypeProfile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    onnx_int8_attestation: Option<OnnxInt8Attestation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    local_execution_attestation: Option<LocalExecutionAttestationReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gemm_accumulation_dtype: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output_dtype: Option<&'static str>,
    files: Vec<FileReport>,
    registered: AddReport,
}

struct CommissionOutput {
    artifacts: Vec<Artifact>,
    dim_override: Option<u32>,
    source_hf_id: Option<String>,
    source_tensor_dtype_profile: Option<LensForgeSourceTensorDtypeProfile>,
    expected_local_contract: Option<FrozenLensContract>,
    onnx_int8_attestation: Option<OnnxInt8Attestation>,
}

impl CommissionOutput {
    fn new(artifacts: Vec<Artifact>) -> Self {
        Self {
            artifacts,
            dim_override: None,
            source_hf_id: None,
            source_tensor_dtype_profile: None,
            expected_local_contract: None,
            onnx_int8_attestation: None,
        }
    }

    fn with_dim(artifacts: Vec<Artifact>, dim: u32) -> Self {
        Self {
            artifacts,
            dim_override: Some(dim),
            source_hf_id: None,
            source_tensor_dtype_profile: None,
            expected_local_contract: None,
            onnx_int8_attestation: None,
        }
    }

    fn with_source_hf_id(artifacts: Vec<Artifact>, source_hf_id: String) -> Self {
        Self {
            artifacts,
            dim_override: None,
            source_hf_id: Some(source_hf_id),
            source_tensor_dtype_profile: None,
            expected_local_contract: None,
            onnx_int8_attestation: None,
        }
    }

    fn with_dim_and_contract(
        artifacts: Vec<Artifact>,
        dim: u32,
        expected_local_contract: FrozenLensContract,
    ) -> Self {
        Self {
            artifacts,
            dim_override: Some(dim),
            source_hf_id: None,
            source_tensor_dtype_profile: None,
            expected_local_contract: Some(expected_local_contract),
            onnx_int8_attestation: None,
        }
    }

    fn with_source_tensor_dtype_profile(
        mut self,
        profile: LensForgeSourceTensorDtypeProfile,
    ) -> Self {
        self.source_tensor_dtype_profile = Some(profile);
        self
    }

    fn with_onnx_int8(commissioned: CommissionedOnnxInt8) -> Self {
        Self {
            artifacts: commissioned.artifacts,
            dim_override: None,
            source_hf_id: None,
            source_tensor_dtype_profile: None,
            expected_local_contract: None,
            onnx_int8_attestation: Some(commissioned.attestation),
        }
    }
}

struct CommissionedOnnxInt8 {
    artifacts: Vec<Artifact>,
    attestation: OnnxInt8Attestation,
}

pub(crate) fn commission(args: &[String]) -> CliResult {
    let flags = CommissionFlags::parse(args)?;
    let out = flags.output_dir()?;
    reject_nonempty_output(&out)?;
    fs::create_dir_all(&out)?;
    let mut log = ConversionLog::create(out.join(CONVERSION_LOG_NAME))?;
    log.event(json!({
        "event": "commission_start",
        "hf": flags.hf,
        "runtime": flags.runtime.manifest_runtime(),
        "dtype": flags.manifest_dtype(),
        "execution_device": flags.execution_device(),
        "device_policy": flags.device_policy_detail(),
        "output_dir": out,
    }))?;
    let mut output = match flags.runtime {
        CommissionRuntime::Tei => {
            let commissioned = commission_tei(&flags, &out, &mut log)?;
            CommissionOutput::with_source_hf_id(commissioned.artifacts, commissioned.source_hf_id)
        }
        CommissionRuntime::Candle => {
            CommissionOutput::new(candle::commission(&flags, &out, &mut log)?)
        }
        CommissionRuntime::OnnxInt8 => {
            CommissionOutput::with_onnx_int8(commission_onnx_int8(&flags, &out, &mut log)?)
        }
        CommissionRuntime::OnnxFp32 => {
            CommissionOutput::new(commission_onnx_fp32(&flags, &out, &mut log)?)
        }
        CommissionRuntime::FastembedOnnx => {
            let commissioned = fastembed::commission(&flags, &out, &mut log)?;
            CommissionOutput::with_dim_and_contract(
                commissioned.artifacts,
                commissioned.dim,
                commissioned.source_contract.ok_or_else(|| {
                    CliError::runtime("FastEmbed commission lost its immutable source contract")
                })?,
            )
        }
        CommissionRuntime::OnnxColbert => {
            let commissioned = onnx_colbert::commission(&flags, &out, &mut log)?;
            CommissionOutput::with_dim(commissioned.artifacts, commissioned.dim)
        }
        CommissionRuntime::FastembedSparse
        | CommissionRuntime::FastembedBgem3Dense
        | CommissionRuntime::FastembedBgem3Sparse
        | CommissionRuntime::FastembedBgem3Colbert
        | CommissionRuntime::FastembedReranker
        | CommissionRuntime::FastembedQwen3 => {
            let commissioned = fastembed_special::commission(&flags, &out, &mut log)?;
            CommissionOutput::with_dim_and_contract(
                commissioned.artifacts,
                commissioned.dim,
                commissioned.source_contract.ok_or_else(|| {
                    CliError::runtime("FastEmbed commission lost its immutable source contract")
                })?,
            )
        }
    };
    if matches!(
        flags.runtime,
        CommissionRuntime::Candle | CommissionRuntime::FastembedQwen3
    ) {
        let artifact_paths = output
            .artifacts
            .iter()
            .map(|artifact| artifact.path.clone())
            .collect::<Vec<_>>();
        let sources =
            resolve_safetensors_weight_set(flags.runtime.manifest_runtime(), &artifact_paths)?;
        let profile = profile_safetensors_sources(&sources)?;
        log.event(json!({
            "event": "source_tensor_dtype_profile_verified",
            "profile": profile,
        }))?;
        output = output.with_source_tensor_dtype_profile(profile);
    }
    let manifest_path = write_manifest(
        &flags,
        &out,
        &output.artifacts,
        output.dim_override,
        output.source_hf_id.as_deref(),
        output.source_tensor_dtype_profile.as_ref(),
        output.onnx_int8_attestation.as_ref(),
        &mut log,
    )?;
    let (max_batch, batch_policy, local_execution_attestation, catalog_admission) =
        match batch_preflight::apply(
            &flags,
            &manifest_path,
            output.source_tensor_dtype_profile.as_ref(),
            output.expected_local_contract.as_ref(),
            &mut log,
        ) {
            Ok(resolved) => resolved,
            Err(error) => {
                // Fail closed: a manifest that never passed mandatory persisted
                // execution attestation and the optional batch probe must not
                // linger where a manual `lens add` could register it.
                let removed = fs::remove_file(&manifest_path);
                log.event(json!({
                    "event": "commission_verification_failed_manifest_removed",
                    "manifest": manifest_path,
                    "removed": removed.is_ok(),
                    "code": error.code(),
                    "message": error.message(),
                    "remediation": error.remediation(),
                }))?;
                return Err(error);
            }
        };
    let local_numeric_dtype = matches!(
        flags.runtime,
        CommissionRuntime::Candle | CommissionRuntime::FastembedQwen3
    )
    .then_some("f32");
    let registered = add_attested_manifest_to_catalog(flags.home.as_deref(), catalog_admission)?;
    log.event(json!({
        "event": "registered",
        "catalog": registered.catalog,
        "lens_id": registered.lens_id,
    }))?;
    print_json(&CommissionReport {
        runtime: flags.runtime.manifest_runtime().to_string(),
        dtype: flags.manifest_dtype().to_string(),
        execution_device: flags.execution_device(),
        device_policy: flags.device_policy_detail(),
        hf: flags.hf,
        output_dir: out,
        manifest: manifest_path,
        conversion_log: log.path,
        max_batch,
        batch_policy,
        source_tensor_dtype_profile: output.source_tensor_dtype_profile,
        onnx_int8_attestation: output.onnx_int8_attestation,
        local_execution_attestation,
        gemm_accumulation_dtype: local_numeric_dtype,
        output_dtype: local_numeric_dtype,
        files: output.artifacts.iter().map(file_report).collect(),
        registered,
    })
}

fn commission_tei(
    flags: &CommissionFlags,
    out: &Path,
    log: &mut ConversionLog,
) -> CliResult<tei::CommissionedTei> {
    let endpoint = flags
        .endpoint
        .as_deref()
        .unwrap_or(DEFAULT_TEI_ENDPOINT)
        .to_string();
    let dim = flags.dim.unwrap_or(DEFAULT_TEI_DIM);
    let lens = TeiHttpLens::new(flags.lens_name(), &endpoint, Modality::Text, dim);
    let probe = Input::new(Modality::Text, b"Calyx TEI commission probe".to_vec());
    let vector = lens.measure(&probe)?;
    validate_vector_contract(&vector, SlotShape::Dense(dim), NormPolicy::unit())?;
    let commissioned = tei::write_descriptor(&flags.hf, endpoint, dim, out)?;
    log.event(json!({
        "event": "tei_probe_verified",
        "descriptor": commissioned.descriptor_path,
        "source_hf_id": commissioned.source_hf_id,
        "requested_hf_id": commissioned.requested_hf_id,
        "dim": dim,
    }))?;
    Ok(commissioned)
}

fn commission_onnx_int8(
    flags: &CommissionFlags,
    out: &Path,
    log: &mut ConversionLog,
) -> CliResult<CommissionedOnnxInt8> {
    let converter = resolve_program("optimum-cli")?;
    let python = resolve_program("python")?;
    require_same_python_environment(&converter, &python)?;
    let converter_program = path_text(&converter)?;
    let python_program = path_text(&python)?;
    let export_dir = export_onnx(flags, out, log, converter_program)?;
    let quant_dir = out.join("onnx-int8");
    fs::create_dir_all(&quant_dir)?;
    let target_flag = format!("--{}", flags.quant_target);
    run_command(
        log,
        converter_program,
        &[
            "onnxruntime",
            "quantize",
            "--onnx_model",
            &export_dir.display().to_string(),
            "-o",
            &quant_dir.display().to_string(),
            &target_flag,
        ],
    )?;
    let source_model = require_named(&export_dir, "model.onnx")?;
    let model = require_named(&quant_dir, "model_quantized.onnx")?;
    let toolchain = onnx_int8_toolchain(
        flags,
        &converter,
        converter_program,
        &python,
        python_program,
        log,
    )?;
    let attestation = match attest_onnx_int8(out, &source_model, &model, toolchain) {
        Ok(attestation) => attestation,
        Err(error) => {
            let event = json!({
                "event": "onnx_int8_attestation_failed",
                "code": error.code,
                "message": &error.message,
                "remediation": error.remediation,
                "source_graph": &source_model,
                "quantized_graph": &model,
            });
            if let Err(log_error) = log.event(event) {
                return Err(CliError::runtime(format!(
                    "ONNX INT8 attestation failed with {}: {}; additionally failed to persist the structured failure to {}: {}",
                    error.code,
                    error.message,
                    log.path.display(),
                    log_error
                )));
            }
            return Err(CliError::from(error));
        }
    };
    let tokenizer = require_named_fallback(&quant_dir, &export_dir, "tokenizer.json")?;
    let config = require_named_fallback(&quant_dir, &export_dir, "config.json")?;
    let dim = flags.dim.unwrap_or(read_hidden_size(&config)?);
    log.event(json!({
        "event": "onnx_int8_semantics_attested",
        "dim": dim,
        "attestation": &attestation,
    }))?;
    let mut artifacts = vec![
        artifact("model", model)?,
        artifact("tokenizer", tokenizer)?,
        artifact("config", config)?,
    ];
    for (index, external) in attestation.output.external_data.iter().enumerate() {
        artifacts.push(artifact(
            &format!("model_external_data:{index}"),
            out.join(&external.path),
        )?);
    }
    add_optional(
        &mut artifacts,
        "tokenizer_config",
        export_dir.join("tokenizer_config.json"),
    )?;
    add_optional(
        &mut artifacts,
        "special_tokens_map",
        export_dir.join("special_tokens_map.json"),
    )?;
    Ok(CommissionedOnnxInt8 {
        artifacts,
        attestation,
    })
}

fn commission_onnx_fp32(
    flags: &CommissionFlags,
    out: &Path,
    log: &mut ConversionLog,
) -> CliResult<Vec<Artifact>> {
    let export_dir = export_onnx(flags, out, log, "optimum-cli")?;
    let model = find_preferred(&export_dir, &["model.onnx"], "onnx")?;
    // Large models export weights to an external-data sidecar (`model.onnx_data`)
    // that the .onnx graph references at load. It must be in the manifest so its
    // bytes are hashed/verified AND counted toward the lens VRAM cost — otherwise
    // a multi-GB model is admitted as a few-MB graph and over-commits the GPU.
    let model_data = model.with_extension("onnx_data");
    let tokenizer = require_named(&export_dir, "tokenizer.json")?;
    let config = require_named(&export_dir, "config.json")?;
    let dim = flags.dim.unwrap_or(read_hidden_size(&config)?);
    log.event(json!({"event": "onnx_fp32_artifacts_ready", "dim": dim}))?;
    let mut artifacts = vec![
        artifact("model", model)?,
        artifact("tokenizer", tokenizer)?,
        artifact("config", config)?,
    ];
    add_optional(&mut artifacts, "model_data", model_data)?;
    add_optional(
        &mut artifacts,
        "tokenizer_config",
        export_dir.join("tokenizer_config.json"),
    )?;
    add_optional(
        &mut artifacts,
        "special_tokens_map",
        export_dir.join("special_tokens_map.json"),
    )?;
    Ok(artifacts)
}

fn export_onnx(
    flags: &CommissionFlags,
    out: &Path,
    log: &mut ConversionLog,
    converter_program: &str,
) -> CliResult<PathBuf> {
    let export_dir = out.join("onnx-export");
    fs::create_dir_all(&export_dir)?;
    run_command(
        log,
        converter_program,
        &[
            "export",
            "onnx",
            "--model",
            &flags.hf,
            "--task",
            "feature-extraction",
            "--library-name",
            "transformers",
            &export_dir.display().to_string(),
        ],
    )?;
    Ok(export_dir)
}

fn onnx_int8_toolchain(
    flags: &CommissionFlags,
    converter: &Path,
    converter_program: &str,
    python: &Path,
    python_program: &str,
    log: &mut ConversionLog,
) -> CliResult<OnnxInt8Toolchain> {
    let version_script = "import importlib.metadata as m,json,platform; print(json.dumps({'python':platform.python_version(),'optimum':m.version('optimum'),'optimum_onnx':m.version('optimum-onnx'),'onnx':m.version('onnx'),'onnxruntime':m.version('onnxruntime')},sort_keys=True))";
    let raw_versions = run_command_capture(log, python_program, &["-c", version_script])?;
    let versions: serde_json::Value = serde_json::from_str(&raw_versions).map_err(|error| {
        CliError::from(calyx_core::CalyxError {
            code: "CALYX_ONNX_INT8_TOOLCHAIN_UNATTESTED",
            message: format!(
                "parse pinned Python ONNX toolchain version output failed: {error}; output={raw_versions:?}"
            ),
            remediation: "activate one Python environment containing optimum, optimum-onnx, onnx, and onnxruntime, then recommission; never infer missing tool versions",
        })
    })?;
    let version = |name: &str| -> CliResult<String> {
        versions
            .get(name)
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(str::to_string)
            .ok_or_else(|| {
                CliError::from(calyx_core::CalyxError {
                    code: "CALYX_ONNX_INT8_TOOLCHAIN_UNATTESTED",
                    message: format!(
                        "pinned Python ONNX toolchain version output has no nonblank {name}: {raw_versions:?}"
                    ),
                    remediation: "activate one Python environment containing optimum, optimum-onnx, onnx, and onnxruntime, then recommission; never infer missing tool versions",
                })
            })
    };
    let converter_identity = artifact("converter_executable", converter.to_path_buf())?;
    let python_identity = artifact("python_executable", python.to_path_buf())?;
    let mut frozen_options = BTreeMap::new();
    frozen_options.insert(
        "command".to_string(),
        "optimum-cli onnxruntime quantize".to_string(),
    );
    frozen_options.insert("export_task".to_string(), "feature-extraction".to_string());
    frozen_options.insert("export_library".to_string(), "transformers".to_string());
    frozen_options.insert(
        "quantizer_output".to_string(),
        "onnx-int8/model_quantized.onnx".to_string(),
    );
    frozen_options.insert(
        "source_graph".to_string(),
        "onnx-export/model.onnx".to_string(),
    );
    frozen_options.insert("converter_path".to_string(), converter_program.to_string());
    frozen_options.insert("python_path".to_string(), python_program.to_string());
    Ok(OnnxInt8Toolchain {
        converter: "optimum-cli".to_string(),
        converter_version: version("optimum")?,
        optimum_onnx_version: version("optimum_onnx")?,
        converter_executable_sha256: converter_identity.sha256,
        python_version: version("python")?,
        python_executable_sha256: python_identity.sha256,
        onnx_version: version("onnx")?,
        onnxruntime_version: version("onnxruntime")?,
        quant_target: flags.quant_target.clone(),
        frozen_options,
    })
}

fn resolve_program(program: &str) -> CliResult<PathBuf> {
    let requested = Path::new(program);
    let mut candidates = Vec::new();
    if requested.components().count() > 1 {
        candidates.push(requested.to_path_buf());
    } else {
        let path = env::var_os("PATH").ok_or_else(|| {
            CliError::from(calyx_core::CalyxError::lens_unreachable(
                "PATH is unavailable while resolving ONNX commissioning tools",
            ))
        })?;
        let extensions = env::var_os("PATHEXT")
            .map(|value| {
                value
                    .to_string_lossy()
                    .split(';')
                    .filter(|extension| !extension.trim().is_empty())
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| vec![".EXE".to_string(), ".CMD".to_string(), ".BAT".to_string()]);
        for directory in env::split_paths(&path) {
            candidates.push(directory.join(program));
            if requested.extension().is_none() {
                for extension in &extensions {
                    candidates.push(directory.join(format!("{program}{extension}")));
                }
            }
        }
    }
    for candidate in candidates {
        let Ok(metadata) = fs::symlink_metadata(&candidate) else {
            continue;
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            continue;
        }
        return fs::canonicalize(&candidate).map_err(CliError::from);
    }
    Err(CliError::from(calyx_core::CalyxError::lens_unreachable(
        format!(
            "required ONNX commissioning program {program} was not found as a regular file on PATH"
        ),
    )))
}

fn require_same_python_environment(converter: &Path, python: &Path) -> CliResult {
    let converter_parent = converter.parent().ok_or_else(|| {
        CliError::runtime(format!(
            "resolved converter {} has no parent directory",
            converter.display()
        ))
    })?;
    let python_parent = python.parent().ok_or_else(|| {
        CliError::runtime(format!(
            "resolved Python {} has no parent directory",
            python.display()
        ))
    })?;
    let converter_parent_folded = converter_parent
        .to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase();
    let python_parent_folded = python_parent
        .to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase();
    let python_scripts_folded = python_parent
        .join("Scripts")
        .to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase();
    if converter_parent_folded != python_parent_folded
        && converter_parent_folded != python_scripts_folded
    {
        return Err(CliError::from(calyx_core::CalyxError {
            code: "CALYX_ONNX_INT8_TOOLCHAIN_ENVIRONMENT_MISMATCH",
            message: format!(
                "optimum-cli {} and python {} resolve to different environments",
                converter.display(),
                python.display()
            ),
            remediation: "activate exactly one Python environment whose python and optimum-cli executables share the same environment, then recommission",
        }));
    }
    Ok(())
}

fn path_text(path: &Path) -> CliResult<&str> {
    path.to_str().ok_or_else(|| {
        CliError::from(calyx_core::CalyxError::lens_unreachable(format!(
            "ONNX commissioning executable path {} is not valid UTF-8",
            path.display()
        )))
    })
}

fn write_manifest(
    flags: &CommissionFlags,
    out: &Path,
    artifacts: &[Artifact],
    dim_override: Option<u32>,
    source_hf_id: Option<&str>,
    source_tensor_dtype_profile: Option<&LensForgeSourceTensorDtypeProfile>,
    onnx_int8_attestation: Option<&OnnxInt8Attestation>,
    log: &mut ConversionLog,
) -> CliResult<PathBuf> {
    let model = artifacts
        .iter()
        .find(|item| item.role == "model")
        .ok_or_else(|| CliError::usage("commission produced no model artifact"))?;
    let dim = dim_override.or(flags.dim).unwrap_or({
        if matches!(flags.runtime, CommissionRuntime::Tei) {
            DEFAULT_TEI_DIM
        } else {
            0
        }
    });
    let inferred_dim = if dim == 0 {
        read_hidden_size(
            &artifacts
                .iter()
                .find(|item| item.role == "config")
                .map(|item| item.path.clone())
                .ok_or_else(|| CliError::usage("commission requires --dim or config.json"))?,
        )?
    } else {
        dim
    };
    let shape = manifest_shape(flags.runtime, inferred_dim);
    // Storage identity is decided by shape at commissioning time: dense shapes
    // take the TurboQuant default; sparse/multi shapes persist exact canonical
    // rows (QuantPolicy::None). A dense-only codec is refused before any
    // catalog mutation rather than advertised and failed at compression time.
    let quant_default = match shape {
        SlotShape::Dense(_) => QuantPolicy::turboquant_default(),
        SlotShape::Sparse(_) | SlotShape::Multi { .. } => QuantPolicy::None,
    };
    calyx_registry::validate_quant_policy_for_shape(&flags.lens_name(), shape, quant_default)
        .map_err(CliError::Calyx)?;
    let manifest = LensForgeManifest {
        name: flags.lens_name(),
        modality: Modality::Text,
        runtime: flags.runtime.manifest_runtime().to_string(),
        dim: inferred_dim,
        shape: Some(LensForgeShape::from_slot_shape(shape)),
        dtype: flags.manifest_dtype().to_string(),
        source_tensor_dtype_profile: source_tensor_dtype_profile.cloned(),
        onnx_int8_attestation: onnx_int8_attestation.cloned(),
        execution_device: flags.execution_device(),
        weights_sha256: model.sha256.clone(),
        artifact_set_sha256: Some(artifact_set_sha256(artifacts)?),
        files: manifest_files(out, artifacts)?,
        pooling: manifest_pooling(flags),
        norm: flags.manifest_norm(),
        source_hf_id: source_hf_id.unwrap_or(&flags.hf).to_string(),
        endpoint: flags.endpoint_for_manifest(),
        license: flags.license.clone(),
        non_commercial: flags.non_commercial,
        quant_default,
        truncate_dim: None,
        recall_delta: calyx_registry::spec::default_recall_delta(),
        max_batch: flags.max_batch,
        // Resolved by the #1157 batch preflight after this initial write.
        batch_policy: None,
    };
    let path = out.join(MANIFEST_NAME);
    write_json_file(&path, &manifest)?;
    log.event(json!({"event": "manifest_written", "path": path}))?;
    Ok(path)
}

fn reject_nonempty_output(out: &Path) -> CliResult {
    if !out.exists() {
        return Ok(());
    }
    if !out.is_dir() {
        return Err(CliError::usage(format!(
            "commission output {} exists and is not a directory",
            out.display()
        )));
    }
    let Some(existing) = fs::read_dir(out)?.next().transpose()? else {
        return Ok(());
    };
    Err(CliError::usage(format!(
        "refusing to commission into non-empty output {}; first existing entry is {}; choose a new empty --out directory so frozen or failed artifact bytes and logs cannot be overwritten",
        out.display(),
        existing.path().display()
    )))
}

fn manifest_shape(runtime: CommissionRuntime, dim: u32) -> SlotShape {
    match runtime {
        CommissionRuntime::FastembedSparse | CommissionRuntime::FastembedBgem3Sparse => {
            SlotShape::Sparse(dim)
        }
        CommissionRuntime::OnnxColbert | CommissionRuntime::FastembedBgem3Colbert => {
            SlotShape::Multi { token_dim: dim }
        }
        _ => SlotShape::Dense(dim),
    }
}

fn manifest_pooling(flags: &CommissionFlags) -> String {
    if matches!(flags.runtime, CommissionRuntime::FastembedQwen3) {
        return "last-token".to_string();
    }
    if matches!(
        flags.runtime,
        CommissionRuntime::OnnxColbert | CommissionRuntime::FastembedBgem3Colbert
    ) {
        "late-interaction".to_string()
    } else {
        flags.pooling.clone()
    }
}
