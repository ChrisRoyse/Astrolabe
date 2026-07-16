use calyx_core::{Modality, SlotShape};

use crate::frozen::{FrozenLensContract, LensDType, NormPolicy, sha256_digest};

pub const CANDLE_BERT_EXECUTION_REVISION: &str = "calyx-candle-bert-v6,candle-core=0.10.2,candle-nn=0.10.2,candle-transformers=0.10.2,finite-native-mask,conditional-selection,source-dtype-profile-v1,full-forward-dtype-attestation";
pub(crate) const CANDLE_DEFAULT_MAX_TOKENS: usize = 512;
pub(crate) const QWEN3_DEFAULT_MAX_TOKENS: usize = 32_768;

pub(crate) struct ContractFacts {
    pub(crate) name: String,
    pub(crate) weights_sha256: [u8; 32],
    pub(crate) corpus_hash: [u8; 32],
    pub(crate) shape: SlotShape,
    pub(crate) modality: Modality,
    pub(crate) norm: NormPolicy,
}

pub(crate) fn contract_from_facts(facts: ContractFacts) -> FrozenLensContract {
    FrozenLensContract::new(
        facts.name,
        facts.weights_sha256,
        facts.corpus_hash,
        facts.shape,
        facts.modality,
        LensDType::F32,
        facts.norm,
    )
}

pub(crate) fn candle_execution_corpus_hash(
    model_id: &str,
    max_tokens: usize,
    execution_device: &str,
    precision: &str,
    pooling: &str,
    norm_policy: NormPolicy,
    source_tensor_profile_fingerprint: &str,
) -> [u8; 32] {
    let max_tokens = max_tokens.to_string();
    let norm = format!("{norm_policy:?}");
    sha256_digest(&[
        CANDLE_BERT_EXECUTION_REVISION.as_bytes(),
        model_id.as_bytes(),
        max_tokens.as_bytes(),
        execution_device.as_bytes(),
        precision.as_bytes(),
        pooling.as_bytes(),
        norm.as_bytes(),
        source_tensor_profile_fingerprint.as_bytes(),
        b"exact-config,no-rewrite,single-execution-precision,no-replay,f32-gemm-accumulation,f32-output,source-dtype-profile-v1",
    ])
}

pub(crate) fn qwen3_execution_corpus_hash(
    model_id: &str,
    execution_device: &str,
    precision: &str,
    max_tokens: usize,
    source_tensor_profile_fingerprint: &str,
) -> [u8; 32] {
    let max_tokens = max_tokens.to_string();
    sha256_digest(&[
        b"fastembed-qwen3-text-v4",
        model_id.as_bytes(),
        execution_device.as_bytes(),
        precision.as_bytes(),
        max_tokens.as_bytes(),
        source_tensor_profile_fingerprint.as_bytes(),
        b"exact-config,no-rewrite,left-padding,last-token,l2,f32-gemm-accumulation,f32-output,source-dtype-profile-v1,full-forward-dtype-attestation",
    ])
}

pub(crate) fn onnx_custom_corpus_hash(
    model_id: &str,
    shape: SlotShape,
    pooling: &str,
    norm: NormPolicy,
) -> [u8; 32] {
    if matches!(shape, SlotShape::Sparse(_)) {
        return sha256_digest(&[
            b"onnx-custom-splade-v1",
            model_id.as_bytes(),
            b"sparse-positive-f32",
        ]);
    }
    sha256_digest(&[
        b"onnx-custom-v1",
        model_id.as_bytes(),
        pooling.as_bytes(),
        format!("{norm:?}").as_bytes(),
    ])
}

pub(crate) fn onnx_colbert_corpus_hash(model_id: &str) -> [u8; 32] {
    sha256_digest(&[
        b"onnx-colbert-token-v1",
        model_id.as_bytes(),
        b"onnx/model_fp16.onnx",
        b"attention-mask-unpooled-finite",
    ])
}

pub(crate) fn fastembed_sparse_corpus_hash(model_code: &str) -> [u8; 32] {
    sha256_digest(&[b"fastembed-sparse-v1", model_code.as_bytes()])
}

pub(crate) fn fastembed_bgem3_corpus_hash(model_code: &str, output_token: &[u8]) -> [u8; 32] {
    sha256_digest(&[b"fastembed-bgem3-v1", model_code.as_bytes(), output_token])
}

pub(crate) fn fastembed_reranker_corpus_hash(model_code: &str) -> [u8; 32] {
    sha256_digest(&[b"fastembed-reranker-v1", model_code.as_bytes()])
}

pub(crate) fn static_lookup_corpus_hash(dim: u32, dtype: &str) -> [u8; 32] {
    sha256_digest(&[
        b"static-lookup-model2vec-v1",
        dim.to_string().as_bytes(),
        dtype.as_bytes(),
    ])
}

pub(crate) fn multimodal_adapter_corpus_hash(name: &str, axis: &str, model_id: &str) -> [u8; 32] {
    sha256_digest(&[
        b"multimodal-onnx-adapter-v2",
        name.as_bytes(),
        axis.as_bytes(),
        model_id.as_bytes(),
    ])
}

pub(crate) fn external_command_weights_hash(cmd: &str, args: &[String]) -> [u8; 32] {
    let args = args.join("\0");
    sha256_digest(&[cmd.as_bytes(), args.as_bytes()])
}

pub(crate) fn external_command_corpus_hash() -> [u8; 32] {
    sha256_digest(&[b"external-cmd-runtime-v1"])
}
