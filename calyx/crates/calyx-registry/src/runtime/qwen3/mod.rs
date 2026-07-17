use std::path::PathBuf;
use std::sync::Mutex;

use calyx_core::{
    CalyxError, Input, Lens, LensId, Modality, Result, RuntimeExecutionAttestation, SlotShape,
    SlotVector,
};
use fastembed::Qwen3TextEmbedding;

use crate::commission::{LensForgeSourceTensorDtypeProfile, profile_safetensors_sources};
use crate::frozen::{FrozenLensContract, NormPolicy};
use crate::identity::{ContractFacts, contract_from_facts, qwen3_execution_corpus_hash};
use crate::runtime::candle::{
    CandleDevicePolicy, CandlePrecision, configure_f32_gemm_accumulation, frozen_device_policy,
    verify_f32_gemm_accumulation,
};
use crate::runtime::common::LocalModelExecutionAttestation;
use crate::runtime::common::{
    hash_files, synchronize_candle_gpu_after_host_materialization, text_from_input,
};
use crate::spec::{LensRuntime, LensSpec, default_recall_delta};

mod files;
mod load;

pub use files::Qwen3ModelFiles;
use load::{dense_batch, qwen3_model_id, read_config, read_model, read_tokenizer};

pub const DEFAULT_QWEN3_MODEL: &str = "Qwen/Qwen3-Embedding-0.6B";
pub const DEFAULT_QWEN3_MAX_TOKENS: usize = 32_768;

const OPTIONAL_QWEN3_FILES: &[&str] = &[
    "tokenizer_config.json",
    "special_tokens_map.json",
    "generation_config.json",
    "merges.txt",
    "vocab.json",
    "modules.json",
    "config_sentence_transformers.json",
    "1_Pooling/config.json",
];

#[derive(Clone, Debug, PartialEq)]
pub struct Qwen3FileSpec {
    pub name: String,
    pub model_id: String,
    pub files: Qwen3ModelFiles,
    pub max_tokens: usize,
    pub device_policy: CandleDevicePolicy,
    pub precision: CandlePrecision,
    pub expected_shape: Option<SlotShape>,
    pub expected_weights_sha256: Option<[u8; 32]>,
}

pub struct FastembedQwen3Lens {
    id: LensId,
    dim: u32,
    contract: FrozenLensContract,
    files: Qwen3ModelFiles,
    device_policy: CandleDevicePolicy,
    precision: CandlePrecision,
    source_tensor_dtype_profile: LensForgeSourceTensorDtypeProfile,
    execution_attestation: LocalModelExecutionAttestation,
    max_tokens: usize,
    model: Mutex<Qwen3TextEmbedding>,
}

impl FastembedQwen3Lens {
    pub fn from_model_id_with_policy(
        name: impl Into<String>,
        model_id: &str,
        cache_dir: PathBuf,
        device_policy: CandleDevicePolicy,
        precision: CandlePrecision,
    ) -> Result<Self> {
        let model_id = qwen3_model_id(model_id)?;
        let files = files::fetch_files(&cache_dir, &model_id)?;
        Self::from_files(Qwen3FileSpec {
            name: name.into(),
            model_id,
            files,
            max_tokens: DEFAULT_QWEN3_MAX_TOKENS,
            device_policy,
            precision,
            expected_shape: None,
            expected_weights_sha256: None,
        })
    }

    pub fn from_files(spec: Qwen3FileSpec) -> Result<Self> {
        let mut spec = spec;
        spec.model_id = qwen3_model_id(&spec.model_id)?;
        spec.files =
            Qwen3ModelFiles::from_paths(spec.model_id.clone(), spec.files.artifact_paths())?;
        if !spec.device_policy.is_gpu() && spec.precision != CandlePrecision::F32 {
            return Err(config_invalid(format!(
                "fastembed-qwen3 CPU placement {} requires f32, but the frozen lens declares {}; commission/select a distinct f32 lens for CPU execution",
                spec.device_policy.detail(),
                spec.precision.as_str()
            )));
        }
        if spec.max_tokens == 0 {
            return Err(config_invalid("fastembed-qwen3 max_tokens must be > 0"));
        }
        for path in spec.files.artifact_paths() {
            ensure_file("artifact", &path)?;
        }
        let weights_sha256 = hash_files(&spec.files.artifact_paths())?;
        if let Some(expected) = spec.expected_weights_sha256
            && weights_sha256 != expected
        {
            return Err(CalyxError::lens_frozen_violation(format!(
                "fastembed-qwen3 artifact hash drift for {}",
                spec.model_id
            )));
        }
        let source_tensor_dtype_profile = profile_safetensors_sources(&spec.files.weights)?;
        let config = read_config(&spec.files.config)?;
        let dim = u32::try_from(config.hidden_size).map_err(|_| {
            CalyxError::lens_dim_mismatch(format!(
                "Qwen3 hidden size {} exceeds u32",
                config.hidden_size
            ))
        })?;
        if let Some(expected) = spec.expected_shape
            && expected != SlotShape::Dense(dim)
        {
            return Err(CalyxError::lens_dim_mismatch(format!(
                "Qwen3 output shape Dense({dim}) != declared {expected:?}"
            )));
        }
        let tokenizer = read_tokenizer(&spec.files.tokenizer, spec.max_tokens)?;
        let (model, execution_attestation) = read_model(
            &spec.files.weights,
            config,
            tokenizer,
            spec.device_policy,
            spec.precision,
            &source_tensor_dtype_profile,
        )?;
        let execution_device = spec.device_policy.frozen_token();
        let corpus_hash = qwen3_corpus_hash(
            &spec.model_id,
            &execution_device,
            spec.precision,
            spec.max_tokens,
            &source_tensor_dtype_profile,
        );
        let contract = contract_from_facts(ContractFacts {
            name: spec.name,
            weights_sha256,
            corpus_hash,
            shape: SlotShape::Dense(dim),
            modality: Modality::Text,
            norm: NormPolicy::unit(),
        });
        Ok(Self {
            id: contract.lens_id(),
            dim,
            contract,
            files: spec.files,
            device_policy: spec.device_policy,
            precision: spec.precision,
            source_tensor_dtype_profile,
            execution_attestation,
            max_tokens: spec.max_tokens,
            model: Mutex::new(model),
        })
    }

    pub fn from_lens_spec(spec: &LensSpec) -> Result<Self> {
        let LensRuntime::FastembedQwen3 {
            model_id,
            files,
            device,
            dtype,
        } = &spec.runtime
        else {
            return Err(config_invalid("LensSpec runtime is not fastembed-qwen3"));
        };
        let model_id = qwen3_model_id(model_id)?;
        Self::from_files(Qwen3FileSpec {
            name: spec.name.clone(),
            model_id: model_id.clone(),
            files: Qwen3ModelFiles::from_paths(model_id, files.clone())?,
            max_tokens: DEFAULT_QWEN3_MAX_TOKENS,
            device_policy: frozen_device_policy(device)?,
            precision: CandlePrecision::parse(dtype)?,
            expected_shape: Some(spec.output),
            expected_weights_sha256: Some(spec.weights_sha256),
        })
    }

    pub fn contract(&self) -> &FrozenLensContract {
        &self.contract
    }

    pub fn files(&self) -> &Qwen3ModelFiles {
        &self.files
    }

    pub const fn device_policy(&self) -> CandleDevicePolicy {
        self.device_policy
    }

    pub const fn precision(&self) -> CandlePrecision {
        self.precision
    }

    pub const fn max_tokens(&self) -> usize {
        self.max_tokens
    }

    /// Canonical dtype/count profile recomputed from the loaded safetensors weight set.
    pub fn source_tensor_dtype_profile(&self) -> &LensForgeSourceTensorDtypeProfile {
        &self.source_tensor_dtype_profile
    }

    /// Frozen dtype requested from the Qwen safetensors loader.
    pub fn loader_target_dtype(&self) -> &'static str {
        self.execution_attestation.loader_target_dtype
    }

    /// Dtype observed from a real full-forward primary hidden activation.
    pub fn observed_primary_activation_dtype(&self) -> &'static str {
        self.execution_attestation.observed_primary_activation_dtype
    }

    /// Frozen device on which the full-forward attestation tensor was observed.
    pub fn observed_execution_device(&self) -> &str {
        &self.execution_attestation.observed_device
    }

    /// Method used to obtain the dtype and device observation.
    pub fn dtype_attestation_evidence(&self) -> &'static str {
        self.execution_attestation.evidence_kind
    }

    pub const fn runtime_name(&self) -> &'static str {
        "fastembed-qwen3"
    }

    pub fn lens_spec(&self) -> LensSpec {
        LensSpec {
            name: self.contract.name().to_string(),
            runtime: LensRuntime::FastembedQwen3 {
                model_id: self.files.model_id.clone(),
                files: self.files.artifact_paths(),
                device: self.device_policy.frozen_token(),
                dtype: self.precision.as_str().to_string(),
            },
            output: self.contract.shape(),
            modality: self.contract.modality(),
            weights_sha256: self.contract.weights_sha256(),
            corpus_hash: self.contract.corpus_hash(),
            norm_policy: self.contract.norm_policy(),
            max_batch: None,
            axis: None,
            asymmetry: calyx_core::Asymmetry::None,
            quant_default: calyx_core::QuantPolicy::turboquant_default(),
            truncate_dim: None,
            recall_delta: default_recall_delta(),
            retrieval_only: false,
            excluded_from_dedup: false,
        }
    }
}

impl Lens for FastembedQwen3Lens {
    fn id(&self) -> LensId {
        self.id
    }

    fn shape(&self) -> SlotShape {
        SlotShape::Dense(self.dim)
    }

    fn modality(&self) -> Modality {
        Modality::Text
    }

    fn measure(&self, input: &Input) -> Result<SlotVector> {
        let mut batch = self.measure_batch(std::slice::from_ref(input))?;
        batch.pop().ok_or_else(|| {
            CalyxError::lens_dim_mismatch(format!("lens {} returned no Qwen3 vector", self.id))
        })
    }

    fn measure_batch(&self, inputs: &[Input]) -> Result<Vec<SlotVector>> {
        if inputs.is_empty() {
            return Ok(Vec::new());
        }
        let result = (|| {
            configure_f32_gemm_accumulation(self.device_policy, self.precision)?;
            let texts = inputs
                .iter()
                .map(|input| text_from_input(self, input).map(str::to_string))
                .collect::<Result<Vec<_>>>()?;
            let model = self
                .model
                .lock()
                .map_err(|_| CalyxError::lens_unreachable("Qwen3 model mutex was poisoned"))?;
            let rows = model.embed(&texts).map_err(qwen3_error)?;
            if self.device_policy.is_gpu() {
                synchronize_candle_gpu_after_host_materialization(
                    "fastembed-qwen3",
                    model.device(),
                )?;
            }
            let vectors = dense_batch(self.dim, rows, inputs.len())?;
            for vector in &vectors {
                self.contract.verify_vector(self.id, vector)?;
            }
            Ok(vectors)
        })();
        let accumulation = verify_f32_gemm_accumulation(self.device_policy, self.precision);
        if let Err(error) = accumulation {
            return Err(qwen3_attested_runtime_context(
                error,
                "gemm_accumulation_verify",
                self.device_policy,
                &self.source_tensor_dtype_profile,
                &self.execution_attestation,
            ));
        }
        result.map_err(|error| {
            qwen3_attested_runtime_context(
                error,
                "inference",
                self.device_policy,
                &self.source_tensor_dtype_profile,
                &self.execution_attestation,
            )
        })
    }

    fn execution_attestation(&self) -> Result<Option<RuntimeExecutionAttestation>> {
        Ok(Some(
            self.execution_attestation
                .runtime_attestation("fastembed-qwen3"),
        ))
    }
}

fn ensure_file(label: &str, path: &std::path::Path) -> Result<()> {
    if path.is_file() {
        return Ok(());
    }
    Err(config_invalid(format!(
        "fastembed-qwen3 {label} file {} is missing",
        path.display()
    )))
}

pub(crate) fn qwen3_error(err: candle_core::Error) -> CalyxError {
    let message = format!("Qwen3 runtime failed: {err}");
    let lower = message.to_ascii_lowercase();
    if lower.contains("out of memory") || lower.contains("memoryallocation") {
        return CalyxError {
            code: "CALYX_VRAM_OOM",
            message,
            remediation: "free VRAM, reduce batch size, or evict lower-priority GPU lenses",
        };
    }
    CalyxError::lens_unreachable(message)
}

pub(crate) fn qwen3_runtime_context(
    error: CalyxError,
    stage: &str,
    device_policy: CandleDevicePolicy,
    precision: CandlePrecision,
    source_tensor_dtype_profile: &LensForgeSourceTensorDtypeProfile,
) -> CalyxError {
    CalyxError {
        code: error.code,
        message: format!(
            "qwen3 stage={stage} device_policy={} source_tensor_dtype_profile={} loader_target_dtype={} observed_primary_activation_dtype=unattested observed_execution_device=unattested dtype_attestation_evidence=unattested gemm_accumulation_dtype=f32 output_dtype=f32: {}",
            device_policy.detail(),
            source_tensor_dtype_profile.summary(),
            precision.as_str(),
            error.message
        ),
        remediation: error.remediation,
    }
}

fn qwen3_attested_runtime_context(
    error: CalyxError,
    stage: &str,
    device_policy: CandleDevicePolicy,
    source_tensor_dtype_profile: &LensForgeSourceTensorDtypeProfile,
    attestation: &LocalModelExecutionAttestation,
) -> CalyxError {
    CalyxError {
        code: error.code,
        message: format!(
            "qwen3 stage={stage} device_policy={} source_tensor_dtype_profile={} loader_target_dtype={} observed_primary_activation_dtype={} observed_execution_device={} dtype_attestation_evidence={} gemm_accumulation_dtype=f32 output_dtype=f32: {}",
            device_policy.detail(),
            source_tensor_dtype_profile.summary(),
            attestation.loader_target_dtype,
            attestation.observed_primary_activation_dtype,
            attestation.observed_device,
            attestation.evidence_kind,
            error.message
        ),
        remediation: error.remediation,
    }
}

pub(crate) fn qwen3_corpus_hash(
    model_id: &str,
    execution_device: &str,
    precision: CandlePrecision,
    max_tokens: usize,
    source_tensor_dtype_profile: &LensForgeSourceTensorDtypeProfile,
) -> [u8; 32] {
    qwen3_execution_corpus_hash(
        model_id,
        execution_device,
        precision.as_str(),
        max_tokens,
        &source_tensor_dtype_profile.fingerprint_sha256,
    )
}

pub(crate) fn config_invalid(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: "CALYX_LENS_CONFIG_INVALID",
        message: message.into(),
        remediation: "fix Qwen3 model/tokenizer/config or register a supported lens spec",
    }
}
