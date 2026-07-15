use std::collections::BTreeMap;

use calyx_core::{CalyxError, Input, Lens, Result};
use ort::session::Session;
use ort::value::Tensor;
use serde_json::Value;
use tokenizers::Tokenizer;

use crate::runtime::common::{DEFAULT_MAX_TOKENS, text_from_input};

use super::config_invalid;

pub(in crate::runtime::onnx) struct TokenBatch {
    /// Rows the session runs over, including padding replicas (#1143). The
    /// first `indices.len()` rows are real inputs; padding rows replicate the
    /// first real row and their outputs are dropped by the consumers.
    pub(in crate::runtime::onnx) batch: usize,
    pub(in crate::runtime::onnx) seq: usize,
    pub(in crate::runtime::onnx) ids: Vec<i64>,
    pub(in crate::runtime::onnx) mask: Vec<i64>,
    pub(in crate::runtime::onnx) indices: Vec<usize>,
}

struct EncodedInput {
    index: usize,
    seq: usize,
    ids: Vec<i64>,
    mask: Vec<i64>,
}

pub(in crate::runtime::onnx) fn max_tokens_from_config(value: &Value) -> Result<usize> {
    let max_tokens = value
        .get("max_position_embeddings")
        .or_else(|| value.get("max_sequence_length"))
        .or_else(|| value.get("model_max_length"))
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_MAX_TOKENS)
        .min(DEFAULT_MAX_TOKENS);
    if max_tokens == 0 {
        return Err(config_invalid("custom ONNX max token count must be > 0"));
    }
    Ok(max_tokens)
}

pub(in crate::runtime::onnx) fn token_batches(
    tokenizer: &Tokenizer,
    lens: &dyn Lens,
    inputs: &[Input],
    max_tokens: usize,
    max_batch: Option<usize>,
    pad_batches: bool,
) -> Result<Vec<TokenBatch>> {
    if max_batch == Some(0) {
        return Err(config_invalid("custom ONNX max_batch must be > 0"));
    }
    let max_batch = max_batch.unwrap_or(usize::MAX).max(1);
    let mut groups: BTreeMap<usize, Vec<EncodedInput>> = BTreeMap::new();
    for (index, input) in inputs.iter().enumerate() {
        let encoded = encode_input(tokenizer, lens, input, index, max_tokens)?;
        groups.entry(encoded.seq).or_default().push(encoded);
    }
    build_batches_from_groups(groups, max_batch, pad_batches)
}

pub(in crate::runtime::onnx) fn stream_token_batches(
    tokenizer: &Tokenizer,
    lens: &dyn Lens,
    inputs: &[Input],
    max_tokens: usize,
    max_batch: Option<usize>,
    pad_batches: bool,
    mut emit: impl FnMut(TokenBatch) -> Result<()>,
) -> Result<()> {
    if max_batch == Some(0) {
        return Err(config_invalid("custom ONNX max_batch must be > 0"));
    }
    let max_batch = max_batch.unwrap_or(usize::MAX).max(1);
    let mut groups: BTreeMap<usize, Vec<EncodedInput>> = BTreeMap::new();
    for (index, input) in inputs.iter().enumerate() {
        let encoded = encode_input(tokenizer, lens, input, index, max_tokens)?;
        let group = groups.entry(encoded.seq).or_default();
        group.push(encoded);
        if group.len() == max_batch {
            let batch = build_batch(group, max_batch)?;
            group.clear();
            emit(batch)?;
        }
    }
    let groups = groups
        .into_iter()
        .filter(|(_, group)| !group.is_empty())
        .collect::<BTreeMap<_, _>>();
    for batch in build_batches_from_groups(groups, max_batch, pad_batches)? {
        emit(batch)?;
    }
    Ok(())
}

fn encode_input(
    tokenizer: &Tokenizer,
    lens: &dyn Lens,
    input: &Input,
    index: usize,
    max_tokens: usize,
) -> Result<EncodedInput> {
    let text = text_from_input(lens, input)?;
    let encoded = tokenizer
        .encode(text, true)
        .map_err(|err| config_invalid(format!("tokenizer encode failed: {err}")))?;
    let (ids, mask) = token_inputs(&encoded, max_tokens);
    let seq = stable_seq_len(ids.len(), max_tokens)?;
    Ok(EncodedInput {
        index,
        seq,
        ids,
        mask,
    })
}

fn build_batches_from_groups(
    groups: BTreeMap<usize, Vec<EncodedInput>>,
    max_batch: usize,
    pad_batches: bool,
) -> Result<Vec<TokenBatch>> {
    let mut batches = Vec::new();
    for group in groups.into_values() {
        for chunk in group.chunks(max_batch) {
            let padded = if pad_batches {
                padded_batch_len(chunk.len(), max_batch)?
            } else {
                chunk.len()
            };
            batches.push(build_batch(chunk, padded)?);
        }
    }
    Ok(batches)
}

/// Stable batch bucket for GPU sessions (#1143): the next power of two,
/// capped at `max_batch`. Ragged batch sizes otherwise multiply the distinct
/// (batch, seq) shapes the ORT CUDA BFC arena retains allocations for, which
/// grows device memory monotonically on long streams.
fn padded_batch_len(len: usize, max_batch: usize) -> Result<usize> {
    if len == 0 || len > max_batch {
        return Err(CalyxError::lens_dim_mismatch(format!(
            "custom ONNX batch bucket: chunk of {len} rows violates max_batch {max_batch}"
        )));
    }
    Ok(len
        .checked_next_power_of_two()
        .unwrap_or(max_batch)
        .min(max_batch))
}

fn stable_seq_len(len: usize, max_tokens: usize) -> Result<usize> {
    let max_tokens = max_tokens.max(1);
    let len = len.clamp(1, max_tokens);
    let bucket = len.next_power_of_two().min(max_tokens);
    if bucket < len {
        return Err(CalyxError::lens_dim_mismatch(
            "custom ONNX stable sequence bucket is shorter than tokenized input",
        ));
    }
    Ok(bucket)
}

fn build_batch(encoded: &[EncodedInput], padded_batch: usize) -> Result<TokenBatch> {
    if padded_batch < encoded.len() {
        return Err(CalyxError::lens_dim_mismatch(format!(
            "custom ONNX batch bucket {padded_batch} is smaller than the {} real rows",
            encoded.len()
        )));
    }
    let seq = encoded
        .first()
        .map(|input| input.seq)
        .ok_or_else(|| CalyxError::lens_dim_mismatch("custom ONNX token batch is empty"))?;
    let mut flat_ids = Vec::with_capacity(padded_batch * seq);
    let mut flat_mask = Vec::with_capacity(padded_batch * seq);
    let mut indices = Vec::with_capacity(encoded.len());
    for item in encoded {
        if item.seq != seq {
            return Err(CalyxError::lens_dim_mismatch(
                "custom ONNX token batch mixed sequence buckets",
            ));
        }
        indices.push(item.index);
        for index in 0..seq {
            flat_ids.push(item.ids.get(index).copied().unwrap_or(0));
            flat_mask.push(item.mask.get(index).copied().unwrap_or(0));
        }
    }
    // Padding replicates the first real row: real token content keeps every
    // pooling policy valid (an all-zero mask row would fail mean pooling and
    // can emit NaN inside models that pool internally). Outputs of padding
    // rows are dropped by the consumers via `indices`.
    let row_len = seq;
    for _ in encoded.len()..padded_batch {
        flat_ids.extend_from_within(..row_len);
        flat_mask.extend_from_within(..row_len);
    }
    Ok(TokenBatch {
        batch: padded_batch,
        seq,
        ids: flat_ids,
        mask: flat_mask,
        indices,
    })
}

fn token_inputs(encoding: &tokenizers::Encoding, max_tokens: usize) -> (Vec<i64>, Vec<i64>) {
    let mut ids = encoding
        .get_ids()
        .iter()
        .take(max_tokens)
        .map(|id| i64::from(*id))
        .collect::<Vec<_>>();
    let mut mask = encoding
        .get_attention_mask()
        .iter()
        .take(max_tokens)
        .map(|value| i64::from(*value))
        .collect::<Vec<_>>();
    if ids.is_empty() {
        ids.push(0);
        mask.push(0);
    }
    if mask.len() != ids.len() {
        mask.resize(ids.len(), 1);
    }
    (ids, mask)
}

pub(in crate::runtime::onnx) fn session_inputs(
    session: &Session,
    batch: &TokenBatch,
) -> Result<Vec<(String, Tensor<i64>)>> {
    let shape = vec![batch.batch as i64, batch.seq as i64];
    let mut values = Vec::with_capacity(session.inputs().len());
    for input in session.inputs() {
        let name = input.name();
        let tensor = if name.contains("token_type_ids") || name.contains("segment") {
            Tensor::from_array((shape.clone(), vec![0_i64; batch.ids.len()]))
        } else if name.contains("input_ids") || name.contains("token") {
            Tensor::from_array((shape.clone(), batch.ids.clone()))
        } else if name.contains("attention_mask") || name.contains("mask") {
            Tensor::from_array((shape.clone(), batch.mask.clone()))
        } else if name.contains("position_ids") || name.contains("position") {
            Tensor::from_array((shape.clone(), position_ids(batch)))
        } else {
            return Err(config_invalid(format!(
                "unsupported custom ONNX input {}",
                input.name()
            )));
        }
        .map_err(|err| config_invalid(format!("build ONNX tensor {} failed: {err}", name)))?;
        values.push((name.to_string(), tensor));
    }
    Ok(values)
}

fn position_ids(batch: &TokenBatch) -> Vec<i64> {
    let mut out = Vec::with_capacity(batch.batch * batch.seq);
    for _ in 0..batch.batch {
        out.extend(0..batch.seq as i64);
    }
    out
}
