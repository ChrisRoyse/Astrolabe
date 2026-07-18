use std::collections::BTreeSet;

use calyx_core::{CalyxError, Modality, Result, SlotShape};

use crate::frozen::{
    FrozenLensContract, LengthDelimitedSha256, LensDType, NormPolicy, sha256_digest,
};

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

pub(crate) fn fastembed_sparse_corpus_hash(model_code: &str, execution: &str) -> [u8; 32] {
    sha256_digest(&[
        b"fastembed-sparse-v2",
        model_code.as_bytes(),
        execution.as_bytes(),
    ])
}

pub(crate) fn fastembed_dense_corpus_hash(model_code: &str, execution: &str) -> [u8; 32] {
    sha256_digest(&[
        b"fastembed-dense-v2",
        model_code.as_bytes(),
        execution.as_bytes(),
    ])
}

#[cfg(feature = "ml-runtime")]
pub(crate) fn legacy_fastembed_dense_corpus_hash(model_code: &str) -> [u8; 32] {
    sha256_digest(&[b"fastembed-dense-v1", model_code.as_bytes()])
}

pub(crate) fn fastembed_bgem3_corpus_hash(
    model_code: &str,
    output_token: &[u8],
    execution: &str,
) -> [u8; 32] {
    sha256_digest(&[
        b"fastembed-bgem3-v2",
        model_code.as_bytes(),
        output_token,
        execution.as_bytes(),
    ])
}

pub(crate) fn fastembed_reranker_corpus_hash(model_code: &str, execution: &str) -> [u8; 32] {
    sha256_digest(&[
        b"fastembed-reranker-v2",
        model_code.as_bytes(),
        execution.as_bytes(),
    ])
}

#[derive(Clone, Debug)]
pub(crate) struct FastembedNamedArtifactDigest {
    pub(crate) role: String,
    pub(crate) logical_name: String,
    pub(crate) sha256: [u8; 32],
}

/// Hashes FastEmbed artifacts by canonical logical role/name and exact content
/// digest. Sorting makes the identity independent of manifest or filesystem
/// enumeration order without losing the name-to-bytes binding.
pub(crate) fn fastembed_named_weights_sha256(
    execution: &str,
    mut artifacts: Vec<FastembedNamedArtifactDigest>,
) -> Result<[u8; 32]> {
    if execution.is_empty() {
        return Err(fastembed_identity_invalid(
            "FastEmbed execution identity token is empty",
        ));
    }
    if artifacts.is_empty() {
        return Err(fastembed_identity_invalid(
            "FastEmbed artifact identity set is empty",
        ));
    }
    artifacts.sort_by(|left, right| {
        (&left.role, &left.logical_name).cmp(&(&right.role, &right.logical_name))
    });
    let mut names = BTreeSet::new();
    let mut hash = LengthDelimitedSha256::new();
    hash.update_part(b"calyx-fastembed-named-artifacts-v1");
    hash.update_part(execution.as_bytes());
    let artifact_count = u64::try_from(artifacts.len())
        .map_err(|_| fastembed_identity_invalid("FastEmbed artifact identity count exceeds u64"))?;
    hash.update_part(&artifact_count.to_be_bytes());
    for artifact in artifacts {
        if artifact.role.is_empty() || artifact.logical_name.is_empty() {
            return Err(fastembed_identity_invalid(
                "FastEmbed artifact role and logical name must be non-empty",
            ));
        }
        if !names.insert((artifact.role.clone(), artifact.logical_name.clone())) {
            return Err(fastembed_identity_invalid(format!(
                "duplicate FastEmbed artifact identity {}/{}",
                artifact.role, artifact.logical_name
            )));
        }
        hash.update_part(artifact.role.as_bytes());
        hash.update_part(artifact.logical_name.as_bytes());
        hash.update_part(&artifact.sha256);
    }
    Ok(hash.finalize())
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

fn fastembed_identity_invalid(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: "CALYX_ONNX_FASTEMBED_ARTIFACT_INVALID",
        message: message.into(),
        remediation: "recommission from a canonical FastEmbed artifact set whose unique logical names bind to the declared exact bytes",
    }
}
