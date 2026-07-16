use std::env;
use std::path::PathBuf;

use calyx_registry::{
    CandleDeviceMode, CandleDevicePolicy, CandlePoolingPolicy, DEFAULT_CANDLE_MODEL,
    configured_device_policy, device_policy_for_mode,
};

use crate::error::{CliError, CliResult};
use crate::lens_commands::flags::value;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum CommissionRuntime {
    OnnxInt8,
    OnnxFp32,
    OnnxColbert,
    FastembedOnnx,
    FastembedSparse,
    FastembedBgem3Dense,
    FastembedBgem3Sparse,
    FastembedBgem3Colbert,
    FastembedReranker,
    FastembedQwen3,
    Candle,
    Tei,
}

impl CommissionRuntime {
    pub(super) fn parse(raw: &str) -> CliResult<Self> {
        match raw {
            "onnx-int8" => Ok(Self::OnnxInt8),
            "onnx-fp32" | "onnx" => Ok(Self::OnnxFp32),
            "onnx-colbert" | "colbert-onnx" | "answerai-colbert" => Ok(Self::OnnxColbert),
            "fastembed-onnx" | "onnx-fastembed" => Ok(Self::FastembedOnnx),
            "fastembed-sparse" => Ok(Self::FastembedSparse),
            "fastembed-bgem3-dense" | "fastembed-bge-m3-dense" => Ok(Self::FastembedBgem3Dense),
            "fastembed-bgem3-sparse" | "fastembed-bge-m3-sparse" => Ok(Self::FastembedBgem3Sparse),
            "fastembed-bgem3-colbert" | "fastembed-bge-m3-colbert" => {
                Ok(Self::FastembedBgem3Colbert)
            }
            "fastembed-reranker" => Ok(Self::FastembedReranker),
            "fastembed-qwen3" | "qwen3" => Ok(Self::FastembedQwen3),
            "candle" | "candle-local" => Ok(Self::Candle),
            "candle-fp16" => Err(CliError::usage(
                "--runtime candle-fp16 is read-only legacy syntax; use --runtime candle --dtype f16 with a new empty output directory",
            )),
            "tei" | "tei-http" | "tei_http" => Ok(Self::Tei),
            other => Err(CliError::usage(format!(
                "unsupported --runtime {other}; expected onnx-int8, onnx-fp32, onnx-colbert, fastembed-onnx, fastembed-sparse, fastembed-bgem3-*, fastembed-reranker, fastembed-qwen3, candle, or tei"
            ))),
        }
    }

    pub(super) const fn manifest_runtime(self) -> &'static str {
        match self {
            Self::OnnxInt8 => "onnx-int8",
            Self::OnnxFp32 => "onnx",
            Self::OnnxColbert => "onnx-colbert",
            Self::FastembedOnnx => "onnx-fastembed",
            Self::FastembedSparse => "fastembed-sparse",
            Self::FastembedBgem3Dense => "fastembed-bgem3-dense",
            Self::FastembedBgem3Sparse => "fastembed-bgem3-sparse",
            Self::FastembedBgem3Colbert => "fastembed-bgem3-colbert",
            Self::FastembedReranker => "fastembed-reranker",
            Self::FastembedQwen3 => "fastembed-qwen3",
            Self::Candle => "candle",
            Self::Tei => "tei",
        }
    }

    pub(super) const fn fixed_dtype(self) -> Option<&'static str> {
        match self {
            Self::OnnxInt8 => Some("int8"),
            Self::OnnxFp32 => Some("f32"),
            Self::OnnxColbert => Some("f16"),
            Self::FastembedOnnx
            | Self::FastembedSparse
            | Self::FastembedBgem3Dense
            | Self::FastembedBgem3Sparse
            | Self::FastembedBgem3Colbert
            | Self::FastembedReranker
            | Self::Tei => Some("f32"),
            Self::FastembedQwen3 | Self::Candle => None,
        }
    }

    pub(super) const fn default_norm(self) -> &'static str {
        match self {
            Self::OnnxColbert
            | Self::FastembedSparse
            | Self::FastembedBgem3Sparse
            | Self::FastembedBgem3Colbert
            | Self::FastembedReranker => "finite",
            _ => "unit",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CommissionPrecision {
    F16,
    BF16,
    F32,
}

impl CommissionPrecision {
    fn parse(raw: &str) -> CliResult<Self> {
        match raw {
            "f16" => Ok(Self::F16),
            "bf16" => Ok(Self::BF16),
            "f32" => Ok(Self::F32),
            other => Err(CliError::usage(format!(
                "unsupported local model --dtype {other}; expected f16, bf16, or f32"
            ))),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::F16 => "f16",
            Self::BF16 => "bf16",
            Self::F32 => "f32",
        }
    }
}

pub(super) struct CommissionFlags {
    pub(super) hf: String,
    pub(super) runtime: CommissionRuntime,
    manifest_dtype: &'static str,
    device_policy: Option<CandleDevicePolicy>,
    pub(super) home: Option<PathBuf>,
    pub(super) out: Option<PathBuf>,
    pub(super) name: Option<String>,
    pub(super) endpoint: Option<String>,
    pub(super) dim: Option<u32>,
    pub(super) license: Option<String>,
    pub(super) non_commercial: bool,
    pub(super) pooling: String,
    pub(super) norm: String,
    norm_explicit: bool,
    pub(super) quant_target: String,
    pub(super) max_batch: Option<usize>,
    pub(super) allow_batch_1: Option<String>,
    pub(super) skip_batch_preflight: Option<String>,
    pub(super) preflight_cap: Option<usize>,
}

impl CommissionFlags {
    pub(super) fn parse(args: &[String]) -> CliResult<Self> {
        let mut hf = None;
        let mut runtime = None;
        let mut model_precision = None;
        let mut device_mode = None;
        let mut home = None;
        let mut out = None;
        let mut name = None;
        let mut endpoint = None;
        let mut dim = None;
        let mut license = None;
        let mut non_commercial = false;
        let mut pooling = "mean".to_string();
        let mut pooling_explicit = false;
        let mut norm = "unit".to_string();
        let mut norm_explicit = false;
        let mut quant_target = "avx2".to_string();
        let mut max_batch = None;
        let mut allow_batch_1 = None;
        let mut skip_batch_preflight = None;
        let mut preflight_cap = None;
        let mut idx = 0;
        while idx < args.len() {
            match args[idx].as_str() {
                "--hf" => {
                    idx += 1;
                    hf = Some(value(args, idx, "--hf")?.to_string());
                }
                "--runtime" => {
                    idx += 1;
                    let raw = value(args, idx, "--runtime")?;
                    runtime = Some(CommissionRuntime::parse(raw)?);
                }
                "--dtype" => {
                    idx += 1;
                    model_precision =
                        Some(CommissionPrecision::parse(value(args, idx, "--dtype")?)?);
                }
                "--device" => {
                    idx += 1;
                    device_mode = Some(CandleDeviceMode::parse(value(args, idx, "--device")?)?);
                }
                "--home" => {
                    idx += 1;
                    home = Some(value(args, idx, "--home")?.into());
                }
                "--out" => {
                    idx += 1;
                    out = Some(value(args, idx, "--out")?.into());
                }
                "--name" => {
                    idx += 1;
                    name = Some(value(args, idx, "--name")?.to_string());
                }
                "--endpoint" => {
                    idx += 1;
                    endpoint = Some(value(args, idx, "--endpoint")?.to_string());
                }
                "--dim" => {
                    idx += 1;
                    let raw = value(args, idx, "--dim")?;
                    dim = Some(raw.parse().map_err(|err| {
                        CliError::usage(format!("parse --dim value {raw}: {err}"))
                    })?);
                }
                "--license" => {
                    idx += 1;
                    license = Some(value(args, idx, "--license")?.to_string());
                }
                "--non-commercial" => non_commercial = true,
                "--pooling" => {
                    idx += 1;
                    pooling = value(args, idx, "--pooling")?.to_string();
                    pooling_explicit = true;
                }
                "--norm" => {
                    idx += 1;
                    norm = value(args, idx, "--norm")?.to_string();
                    norm_explicit = true;
                }
                "--quant-target" => {
                    idx += 1;
                    quant_target = value(args, idx, "--quant-target")?.to_string();
                }
                "--max-batch" => {
                    idx += 1;
                    max_batch = Some(parse_positive_usize(
                        value(args, idx, "--max-batch")?,
                        "--max-batch",
                    )?);
                }
                "--allow-batch-1" => {
                    idx += 1;
                    allow_batch_1 = Some(require_reason(
                        value(args, idx, "--allow-batch-1")?,
                        "--allow-batch-1",
                    )?);
                }
                "--skip-batch-preflight" => {
                    idx += 1;
                    skip_batch_preflight = Some(require_reason(
                        value(args, idx, "--skip-batch-preflight")?,
                        "--skip-batch-preflight",
                    )?);
                }
                "--preflight-cap" => {
                    idx += 1;
                    preflight_cap = Some(parse_positive_usize(
                        value(args, idx, "--preflight-cap")?,
                        "--preflight-cap",
                    )?);
                }
                other => {
                    return Err(CliError::usage(format!(
                        "unexpected lens commission flag {other}"
                    )));
                }
            }
            idx += 1;
        }
        let hf = require_nonempty(hf, "--hf")?;
        let runtime = runtime.ok_or_else(|| CliError::usage("--runtime is required"))?;
        if runtime == CommissionRuntime::Candle {
            CandlePoolingPolicy::parse(&pooling)?;
            if model_precision.is_none() {
                return Err(CliError::usage(
                    "candle requires an explicit calibrated --dtype <f16|bf16|f32>",
                ));
            }
            if hf != DEFAULT_CANDLE_MODEL && !pooling_explicit {
                return Err(CliError::usage(format!(
                    "Candle model {hf} has no measured pooling policy; arbitrary models require explicit --pooling <mean|cls>"
                )));
            }
        }
        if runtime == CommissionRuntime::FastembedQwen3 {
            if model_precision.is_none() {
                return Err(CliError::usage(
                    "fastembed-qwen3 requires an explicit calibrated --dtype <f16|bf16|f32>",
                ));
            }
            if pooling_explicit && pooling != "last-token" {
                return Err(CliError::usage(
                    "fastembed-qwen3 has a frozen last-token pooling contract; omit --pooling or pass --pooling last-token",
                ));
            }
        }
        if model_precision.is_some()
            && !matches!(
                runtime,
                CommissionRuntime::Candle | CommissionRuntime::FastembedQwen3
            )
        {
            return Err(CliError::usage(
                "--dtype is supported only with --runtime candle or fastembed-qwen3",
            ));
        }
        if device_mode.is_some()
            && !matches!(
                runtime,
                CommissionRuntime::Candle | CommissionRuntime::FastembedQwen3
            )
        {
            return Err(CliError::usage(
                "--device is supported only with --runtime candle or fastembed-qwen3",
            ));
        }
        let local_model = matches!(
            runtime,
            CommissionRuntime::Candle | CommissionRuntime::FastembedQwen3
        );
        let device_policy = if local_model {
            Some(match device_mode {
                Some(mode) => device_policy_for_mode(mode)?,
                None => configured_device_policy()?,
            })
        } else {
            None
        };
        let manifest_dtype = if let Some(policy) = device_policy {
            let precision = model_precision.ok_or_else(|| {
                CliError::usage(format!(
                    "{} requires an explicit calibrated --dtype <f16|bf16|f32>",
                    runtime.manifest_runtime()
                ))
            })?;
            if !policy.is_gpu() && precision != CommissionPrecision::F32 {
                return Err(CliError::usage(format!(
                    "{} placement requires --dtype f32; half-precision CPU execution would violate the frozen lens contract",
                    policy.detail()
                )));
            }
            precision.as_str()
        } else {
            runtime.fixed_dtype().ok_or_else(|| {
                CliError::runtime("commission runtime produced no resolved dtype contract")
            })?
        };
        validate_quant_target(&quant_target)?;
        Ok(Self {
            hf,
            runtime,
            manifest_dtype,
            device_policy,
            home,
            out,
            name,
            endpoint,
            dim,
            license,
            non_commercial,
            pooling,
            norm,
            norm_explicit,
            quant_target,
            max_batch,
            allow_batch_1,
            skip_batch_preflight,
            preflight_cap,
        })
    }

    pub(super) fn output_dir(&self) -> CliResult<PathBuf> {
        if let Some(out) = &self.out {
            return Ok(out.clone());
        }
        let home = match &self.home {
            Some(path) => path.clone(),
            None => env::var_os("CALYX_HOME")
                .map(PathBuf::from)
                .ok_or_else(|| CliError::usage("CALYX_HOME is required or pass --home <dir>"))?,
        };
        Ok(home.join("lenses").join("commissioned").join(format!(
            "{}-{}",
            sanitize_path_token(&self.hf),
            self.identity_runtime_token()
        )))
    }

    pub(super) fn lens_name(&self) -> String {
        match (&self.name, self.runtime) {
            (Some(name), CommissionRuntime::Candle | CommissionRuntime::FastembedQwen3) => {
                let suffix = format!("-{}", self.local_identity_suffix());
                if name.ends_with(suffix.as_str()) {
                    name.clone()
                } else {
                    format!("{name}{suffix}")
                }
            }
            (Some(name), _) => name.clone(),
            (None, _) => format!(
                "{}-{}",
                sanitize_path_token(&self.hf),
                self.identity_runtime_token()
            ),
        }
    }

    pub(super) fn manifest_dtype(&self) -> &'static str {
        self.manifest_dtype
    }

    pub(super) fn execution_device(&self) -> Option<String> {
        self.device_policy.map(CandleDevicePolicy::frozen_token)
    }

    pub(super) fn device_policy_detail(&self) -> Option<String> {
        self.device_policy.map(CandleDevicePolicy::detail)
    }

    pub(super) fn local_device_policy(&self) -> CliResult<CandleDevicePolicy> {
        self.device_policy.ok_or_else(|| {
            CliError::runtime("local model commission is missing its resolved device policy")
        })
    }

    pub(super) fn runs_on_local_gpu(&self) -> bool {
        match self.runtime {
            CommissionRuntime::Tei => false,
            CommissionRuntime::Candle | CommissionRuntime::FastembedQwen3 => {
                self.device_policy.is_some_and(CandleDevicePolicy::is_gpu)
            }
            _ => true,
        }
    }

    pub(super) fn endpoint_for_manifest(&self) -> Option<String> {
        if matches!(self.runtime, CommissionRuntime::Tei) {
            Some(
                self.endpoint
                    .clone()
                    .unwrap_or_else(|| calyx_registry::DEFAULT_TEI_ENDPOINT.to_string()),
            )
        } else {
            None
        }
    }

    pub(super) fn manifest_norm(&self) -> String {
        if self.norm_explicit {
            self.norm.clone()
        } else {
            self.runtime.default_norm().to_string()
        }
    }

    fn identity_runtime_token(&self) -> String {
        if matches!(
            self.runtime,
            CommissionRuntime::Candle | CommissionRuntime::FastembedQwen3
        ) {
            return format!(
                "{}-{}",
                self.runtime.manifest_runtime(),
                self.local_identity_suffix()
            );
        }
        self.runtime.manifest_runtime().to_string()
    }

    fn local_identity_suffix(&self) -> String {
        let device = self
            .execution_device()
            .unwrap_or_else(|| "unresolved".to_string())
            .replace(':', "");
        format!("{device}-{}", self.manifest_dtype())
    }
}

fn require_nonempty(value: Option<String>, flag: &str) -> CliResult<String> {
    let value = value.ok_or_else(|| CliError::usage(format!("{flag} is required")))?;
    if value.trim().is_empty() {
        return Err(CliError::usage(format!("{flag} must not be empty")));
    }
    Ok(value)
}

fn validate_quant_target(raw: &str) -> CliResult {
    match raw {
        "arm64" | "avx2" | "avx512" | "avx512_vnni" | "tensorrt" => Ok(()),
        other => Err(CliError::usage(format!(
            "--quant-target {other} is unsupported"
        ))),
    }
}

fn require_reason(raw: &str, flag: &str) -> CliResult<String> {
    let reason = raw.trim();
    if reason.is_empty() {
        return Err(CliError::usage(format!(
            "{flag} requires a non-empty justification recorded in the manifest"
        )));
    }
    Ok(reason.to_string())
}

fn parse_positive_usize(raw: &str, flag: &str) -> CliResult<usize> {
    let value = raw
        .parse::<usize>()
        .map_err(|err| CliError::usage(format!("{flag} must be an integer: {err}")))?;
    if value == 0 {
        return Err(CliError::usage(format!("{flag} must be > 0")));
    }
    Ok(value)
}

fn sanitize_path_token(raw: &str) -> String {
    raw.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}
