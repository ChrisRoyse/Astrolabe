use calyx_core::{CalyxError, Lens, Modality, Placement};
use calyx_registry::{
    AlgorithmicLens, CandleDevicePolicy, CandleLens, FastembedBgem3Lens, FastembedBgem3Output,
    FastembedQwen3Lens, FastembedRerankerLens, FastembedSparseLens, LensRuntime, LensSpec,
    MultimodalAdapterLens, OnnxColbertLens, OnnxLens, StaticLookupLens, TeiHttpLens,
    runtime::tei_http::DEFAULT_TEI_MAX_BATCH,
};

use super::super::support::dim;
use super::model::{GEMM_ACCUMULATION_DTYPE, NOT_APPLICABLE_DTYPE, OUTPUT_DTYPE, UNKNOWN_DTYPE};

pub(super) struct RuntimeLens {
    pub(super) lens: Box<dyn Lens>,
    pub(super) detail: String,
    pub(super) provider: String,
    pub(super) declared_model_dtype: String,
    pub(super) executed_model_dtype: String,
    pub(super) gemm_accumulation_dtype: String,
    pub(super) output_dtype: String,
    pub(super) placement: Placement,
    pub(super) native_batching: bool,
    pub(super) max_batch: Option<usize>,
    pub(super) proof: String,
    pub(super) gpu_process_required: bool,
}

pub(super) fn runtime_lens(spec: &LensSpec) -> Result<RuntimeLens, CalyxError> {
    match &spec.runtime {
        LensRuntime::Onnx { .. } => {
            let lens = OnnxLens::from_lens_spec(spec)?;
            let provider = lens.provider_policy().to_string();
            let detail = format!("{};{}", lens.runtime_name(), provider);
            Ok(RuntimeLens {
                lens: Box::new(lens),
                detail,
                provider: provider.clone(),
                // LensRuntime does not preserve ONNX graph dtype yet; tracked by #485.
                declared_model_dtype: UNKNOWN_DTYPE.to_string(),
                executed_model_dtype: UNKNOWN_DTYPE.to_string(),
                gemm_accumulation_dtype: UNKNOWN_DTYPE.to_string(),
                output_dtype: OUTPUT_DTYPE.to_string(),
                placement: Placement::Gpu,
                native_batching: true,
                max_batch: spec.max_batch,
                proof: format!("ort_cuda_provider_registered:{provider}"),
                gpu_process_required: true,
            })
        }
        LensRuntime::OnnxColbert { .. } => {
            let lens = OnnxColbertLens::from_lens_spec(spec)?;
            let provider = lens.provider_policy().to_string();
            let detail = format!("onnx_colbert;{provider}");
            Ok(RuntimeLens {
                lens: Box::new(lens),
                detail,
                provider: provider.clone(),
                declared_model_dtype: UNKNOWN_DTYPE.to_string(),
                executed_model_dtype: UNKNOWN_DTYPE.to_string(),
                gemm_accumulation_dtype: UNKNOWN_DTYPE.to_string(),
                output_dtype: OUTPUT_DTYPE.to_string(),
                placement: Placement::Gpu,
                native_batching: true,
                max_batch: spec.max_batch,
                proof: format!("ort_cuda_provider_registered:{provider}"),
                gpu_process_required: true,
            })
        }
        LensRuntime::FastembedSparse { .. } => {
            let lens = FastembedSparseLens::from_lens_spec(spec)?;
            let provider = lens.provider_policy().to_string();
            Ok(RuntimeLens {
                lens: Box::new(lens),
                detail: format!("fastembed_sparse;{provider}"),
                provider: provider.clone(),
                declared_model_dtype: UNKNOWN_DTYPE.to_string(),
                executed_model_dtype: UNKNOWN_DTYPE.to_string(),
                gemm_accumulation_dtype: UNKNOWN_DTYPE.to_string(),
                output_dtype: OUTPUT_DTYPE.to_string(),
                placement: Placement::Gpu,
                native_batching: true,
                max_batch: spec.max_batch,
                proof: format!("ort_cuda_provider_registered:{provider}"),
                gpu_process_required: true,
            })
        }
        LensRuntime::FastembedBgem3 { .. } => {
            let lens = FastembedBgem3Lens::from_lens_spec(spec)?;
            let provider = lens.provider_policy().to_string();
            let detail = format!("{};{provider}", lens.runtime_name());
            Ok(RuntimeLens {
                lens: Box::new(lens),
                detail,
                provider: provider.clone(),
                declared_model_dtype: UNKNOWN_DTYPE.to_string(),
                executed_model_dtype: UNKNOWN_DTYPE.to_string(),
                gemm_accumulation_dtype: UNKNOWN_DTYPE.to_string(),
                output_dtype: OUTPUT_DTYPE.to_string(),
                placement: Placement::Gpu,
                native_batching: true,
                max_batch: spec.max_batch,
                proof: format!("ort_cuda_provider_registered:{provider}"),
                gpu_process_required: true,
            })
        }
        LensRuntime::FastembedReranker { .. } => {
            let lens = FastembedRerankerLens::from_lens_spec(spec)?;
            let provider = lens.provider_policy().to_string();
            Ok(RuntimeLens {
                lens: Box::new(lens),
                detail: format!("fastembed_reranker;{provider}"),
                provider: provider.clone(),
                declared_model_dtype: UNKNOWN_DTYPE.to_string(),
                executed_model_dtype: UNKNOWN_DTYPE.to_string(),
                gemm_accumulation_dtype: UNKNOWN_DTYPE.to_string(),
                output_dtype: OUTPUT_DTYPE.to_string(),
                placement: Placement::Gpu,
                native_batching: false,
                max_batch: Some(1),
                proof: format!("ort_cuda_provider_registered:{provider}"),
                gpu_process_required: true,
            })
        }
        LensRuntime::FastembedQwen3 { dtype, .. } => {
            let lens = FastembedQwen3Lens::from_lens_spec(spec)?;
            let device_policy = lens.device_policy();
            let provider = device_policy.detail();
            let executed_model_dtype = lens.precision().as_str().to_string();
            let detail = format!(
                "fastembed_qwen3;provider={provider};declared_model_dtype={dtype};\
                 executed_model_dtype={executed_model_dtype};\
                 gemm_accumulation_dtype={GEMM_ACCUMULATION_DTYPE};output_dtype={OUTPUT_DTYPE};\
                 max_tokens={}",
                lens.max_tokens()
            );
            Ok(RuntimeLens {
                lens: Box::new(lens),
                detail,
                provider: provider.clone(),
                declared_model_dtype: dtype.clone(),
                executed_model_dtype,
                gemm_accumulation_dtype: GEMM_ACCUMULATION_DTYPE.to_string(),
                output_dtype: OUTPUT_DTYPE.to_string(),
                placement: device_policy.placement(),
                native_batching: true,
                max_batch: spec.max_batch,
                proof: candle_device_proof(device_policy),
                gpu_process_required: device_policy.is_gpu(),
            })
        }
        LensRuntime::CandleLocal { dtype, .. } => {
            let lens = CandleLens::from_lens_spec(spec)?;
            let device_policy = lens.device_policy();
            let provider = device_policy.detail();
            let executed_model_dtype = lens.precision().as_str().to_string();
            let detail = format!(
                "candle_local;provider={provider};declared_model_dtype={dtype};\
                 executed_model_dtype={executed_model_dtype};\
                 gemm_accumulation_dtype={GEMM_ACCUMULATION_DTYPE};output_dtype={OUTPUT_DTYPE}"
            );
            Ok(RuntimeLens {
                lens: Box::new(lens),
                detail,
                provider: provider.clone(),
                declared_model_dtype: dtype.clone(),
                executed_model_dtype,
                gemm_accumulation_dtype: GEMM_ACCUMULATION_DTYPE.to_string(),
                output_dtype: OUTPUT_DTYPE.to_string(),
                placement: device_policy.placement(),
                native_batching: false,
                max_batch: Some(1),
                proof: candle_device_proof(device_policy),
                gpu_process_required: device_policy.is_gpu(),
            })
        }
        LensRuntime::TeiHttp { endpoint } => {
            let lens = TeiHttpLens::new(&spec.name, endpoint, spec.modality, dim(spec.output));
            Ok(RuntimeLens {
                lens: Box::new(lens),
                detail: endpoint.clone(),
                provider: "resident_tei_gpu_service".to_string(),
                declared_model_dtype: UNKNOWN_DTYPE.to_string(),
                executed_model_dtype: UNKNOWN_DTYPE.to_string(),
                gemm_accumulation_dtype: UNKNOWN_DTYPE.to_string(),
                output_dtype: OUTPUT_DTYPE.to_string(),
                placement: Placement::Gpu,
                native_batching: true,
                max_batch: spec.max_batch.or(Some(DEFAULT_TEI_MAX_BATCH)),
                proof: format!("tei_endpoint_vector_contract:{endpoint}"),
                gpu_process_required: false,
            })
        }
        LensRuntime::StaticLookup { .. } => {
            let lens = StaticLookupLens::from_lens_spec(spec)?;
            let declared_model_dtype = lens.dtype().as_str().to_string();
            Ok(RuntimeLens {
                lens: Box::new(lens),
                detail: "static_lookup_mmap;cpu_explicit".to_string(),
                provider: "cpu_explicit".to_string(),
                declared_model_dtype,
                executed_model_dtype: NOT_APPLICABLE_DTYPE.to_string(),
                gemm_accumulation_dtype: NOT_APPLICABLE_DTYPE.to_string(),
                output_dtype: OUTPUT_DTYPE.to_string(),
                placement: Placement::Cpu,
                native_batching: false,
                max_batch: Some(1),
                proof: "cpu_runtime_not_gpu_claim".to_string(),
                gpu_process_required: false,
            })
        }
        LensRuntime::Algorithmic { kind } => {
            let lens = algorithmic_lens(spec, kind)?;
            Ok(RuntimeLens {
                lens: Box::new(lens),
                detail: format!("algorithmic:{kind};cpu_explicit"),
                provider: "cpu_explicit".to_string(),
                declared_model_dtype: NOT_APPLICABLE_DTYPE.to_string(),
                executed_model_dtype: NOT_APPLICABLE_DTYPE.to_string(),
                gemm_accumulation_dtype: NOT_APPLICABLE_DTYPE.to_string(),
                output_dtype: OUTPUT_DTYPE.to_string(),
                placement: Placement::Cpu,
                native_batching: false,
                max_batch: Some(1),
                proof: "cpu_runtime_not_gpu_claim".to_string(),
                gpu_process_required: false,
            })
        }
        LensRuntime::MultimodalAdapter { .. } => {
            let lens = MultimodalAdapterLens::from_lens_spec(spec)?;
            let provider = lens.provider_detail().to_string();
            let placement = if lens.provider().is_gpu() {
                Placement::Gpu
            } else {
                Placement::Cpu
            };
            let proof = if lens.provider().is_gpu() {
                format!("multimodal_onnx_provider_configured:{provider}")
            } else {
                "cpu_runtime_not_gpu_claim".to_string()
            };
            Ok(RuntimeLens {
                lens: Box::new(lens),
                detail: format!("multimodal_adapter;{provider}"),
                provider,
                declared_model_dtype: UNKNOWN_DTYPE.to_string(),
                executed_model_dtype: UNKNOWN_DTYPE.to_string(),
                gemm_accumulation_dtype: UNKNOWN_DTYPE.to_string(),
                output_dtype: OUTPUT_DTYPE.to_string(),
                placement,
                native_batching: true,
                max_batch: spec.max_batch,
                proof,
                gpu_process_required: false,
            })
        }
        LensRuntime::ExternalCmd { .. } => Err(CalyxError::lens_unreachable(
            "external-cmd lenses are not accepted for PH68 scale-audit",
        )),
    }
}

fn candle_device_proof(policy: CandleDevicePolicy) -> String {
    format!(
        "candle_device_initialized:{};placement={:?}",
        policy.detail(),
        policy.placement()
    )
}

pub(super) fn association_family(spec: &LensSpec) -> &'static str {
    if is_temporal_sidecar(spec) {
        return "temporal_sidecar";
    }
    match &spec.runtime {
        LensRuntime::Algorithmic { kind }
            if kind.contains("gdelt")
                || kind.contains("cameo")
                || kind.contains("actor")
                || kind.contains("geo")
                || kind.contains("event")
                || kind.contains("source")
                || kind.contains("tone") =>
        {
            "entity_cameo_graph"
        }
        LensRuntime::Algorithmic { kind } if kind.contains("token") || kind.contains("multi") => {
            "late_interaction_token"
        }
        LensRuntime::Algorithmic { kind } if kind.contains("sparse") => "lexical_sparse",
        LensRuntime::Algorithmic { kind } if kind.contains("byte") => "byte_char",
        LensRuntime::Algorithmic { .. } => "algorithmic",
        LensRuntime::StaticLookup { .. } => "static_lookup_semantic",
        LensRuntime::MultimodalAdapter { .. } => "multimodal_adapter",
        LensRuntime::FastembedSparse { .. } => "lexical_sparse",
        LensRuntime::FastembedBgem3 {
            output: FastembedBgem3Output::Sparse,
            ..
        } => "lexical_sparse",
        LensRuntime::FastembedBgem3 {
            output: FastembedBgem3Output::Colbert,
            ..
        } => "late_interaction_token",
        LensRuntime::FastembedBgem3 {
            output: FastembedBgem3Output::Dense,
            ..
        } => "dense_semantic",
        LensRuntime::FastembedReranker { .. } => "retrieval_reranker",
        LensRuntime::FastembedQwen3 { .. } => "dense_semantic",
        LensRuntime::OnnxColbert { .. } => "late_interaction_token",
        LensRuntime::Onnx { .. }
        | LensRuntime::CandleLocal { .. }
        | LensRuntime::TeiHttp { .. } => "dense_semantic",
        LensRuntime::ExternalCmd { .. } => "external",
    }
}

pub(super) fn is_temporal_sidecar(spec: &LensSpec) -> bool {
    let name = spec.name.to_ascii_lowercase();
    let axis = spec
        .axis
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    name.contains("temporal") || axis.contains("temporal") || axis.contains("as-of")
}

pub(super) fn is_content_modality(modality: Modality) -> bool {
    matches!(
        modality,
        Modality::Text | Modality::Code | Modality::Image | Modality::Audio | Modality::Video
    )
}

fn algorithmic_lens(spec: &LensSpec, kind: &str) -> Result<AlgorithmicLens, CalyxError> {
    match kind {
        "byte" | "byte-features" => Ok(AlgorithmicLens::byte_features(&spec.name, spec.modality)),
        "scalar" => Ok(AlgorithmicLens::scalar(&spec.name, spec.modality)),
        "ast-style" => Ok(AlgorithmicLens::ast_style(&spec.name, spec.modality)),
        "gdelt-cameo" | "gdelt_cameo" => {
            Ok(AlgorithmicLens::gdelt_cameo(&spec.name, spec.modality))
        }
        "gdelt-actor-geo" | "gdelt_actor_geo" => Ok(AlgorithmicLens::gdelt_actor_geo(
            &spec.name,
            spec.modality,
            dim(spec.output),
        )),
        "gdelt-source-domain" | "gdelt_source_domain" => Ok(AlgorithmicLens::gdelt_source_domain(
            &spec.name,
            spec.modality,
            dim(spec.output),
        )),
        "gdelt-event-geo" | "gdelt_event_geo" => Ok(AlgorithmicLens::gdelt_event_geo(
            &spec.name,
            spec.modality,
            dim(spec.output),
        )),
        "gdelt-actor-pair" | "gdelt_actor_pair" => Ok(AlgorithmicLens::gdelt_actor_pair(
            &spec.name,
            spec.modality,
            dim(spec.output),
        )),
        "gdelt-event-actor" | "gdelt_event_actor" => Ok(AlgorithmicLens::gdelt_event_actor(
            &spec.name,
            spec.modality,
            dim(spec.output),
        )),
        "gdelt-tone-signal" | "gdelt_tone_signal" => Ok(AlgorithmicLens::gdelt_tone_signal(
            &spec.name,
            spec.modality,
            dim(spec.output),
        )),
        "gdelt-source-event" | "gdelt_source_event" => Ok(AlgorithmicLens::gdelt_source_event(
            &spec.name,
            spec.modality,
            dim(spec.output),
        )),
        "sparse" | "sparse-keywords" => Ok(AlgorithmicLens::sparse_keywords(
            &spec.name,
            spec.modality,
            dim(spec.output),
        )),
        "token-hash" | "token_hash" | "multi-hash" | "multi_hash" => Ok(
            AlgorithmicLens::token_hash(&spec.name, spec.modality, dim(spec.output)),
        ),
        other => Err(CalyxError::lens_unreachable(format!(
            "scale-audit does not support algorithmic kind {other}"
        ))),
    }
}
