use candle_core::{DType, Device, Result, Shape, Tensor};
use candle_nn::{Embedding, LayerNorm, Module, VarBuilder, embedding, layer_norm};
use candle_transformers::models::bert::{BertEncoder, Config};

/// Changes whenever Calyx's owned BERT execution semantics change.
pub use crate::identity::CANDLE_BERT_EXECUTION_REVISION;

pub(super) struct CalyxBertModel {
    embeddings: CalyxBertEmbeddings,
    encoder: BertEncoder,
    pub(super) device: Device,
}

impl CalyxBertModel {
    pub(super) fn load(vb: VarBuilder, config: &Config) -> Result<Self> {
        let (embeddings, encoder) = match (
            CalyxBertEmbeddings::load(vb.pp("embeddings"), config),
            BertEncoder::load(vb.pp("encoder"), config),
        ) {
            (Ok(embeddings), Ok(encoder)) => (embeddings, encoder),
            (Err(error), _) | (_, Err(error)) => {
                let Some(model_type) = &config.model_type else {
                    return Err(error);
                };
                match (
                    CalyxBertEmbeddings::load(vb.pp(format!("{model_type}.embeddings")), config),
                    BertEncoder::load(vb.pp(format!("{model_type}.encoder")), config),
                ) {
                    (Ok(embeddings), Ok(encoder)) => (embeddings, encoder),
                    _ => return Err(error),
                }
            }
        };
        Ok(Self {
            embeddings,
            encoder,
            device: vb.device().clone(),
        })
    }

    pub(super) fn forward(
        &self,
        input_ids: &Tensor,
        token_type_ids: &Tensor,
        attention_mask: Option<&Tensor>,
    ) -> Result<Tensor> {
        let embedding_output = self.embeddings.forward(input_ids, token_type_ids)?;
        let attention_mask = match attention_mask {
            Some(attention_mask) => attention_mask.clone(),
            None => input_ids.ones_like()?,
        };
        let attention_mask =
            finite_additive_attention_mask(&attention_mask, embedding_output.dtype())?;
        self.encoder.forward(&embedding_output, &attention_mask)
    }

    pub(super) fn full_forward_dtype_probe(&self) -> Result<Tensor> {
        let input_ids = Tensor::zeros((1, 1), DType::U32, &self.device)?;
        let token_type_ids = Tensor::zeros((1, 1), DType::U32, &self.device)?;
        let attention_mask = Tensor::ones((1, 1), DType::U32, &self.device)?;
        self.forward(&input_ids, &token_type_ids, Some(&attention_mask))
    }
}

struct CalyxBertEmbeddings {
    word_embeddings: Embedding,
    position_embeddings: Embedding,
    token_type_embeddings: Embedding,
    layer_norm: LayerNorm,
}

impl CalyxBertEmbeddings {
    fn load(vb: VarBuilder, config: &Config) -> Result<Self> {
        Ok(Self {
            word_embeddings: embedding(
                config.vocab_size,
                config.hidden_size,
                vb.pp("word_embeddings"),
            )?,
            position_embeddings: embedding(
                config.max_position_embeddings,
                config.hidden_size,
                vb.pp("position_embeddings"),
            )?,
            token_type_embeddings: embedding(
                config.type_vocab_size,
                config.hidden_size,
                vb.pp("token_type_embeddings"),
            )?,
            layer_norm: layer_norm(
                config.hidden_size,
                config.layer_norm_eps,
                vb.pp("LayerNorm"),
            )?,
        })
    }

    fn forward(&self, input_ids: &Tensor, token_type_ids: &Tensor) -> Result<Tensor> {
        let (_batch_size, sequence_length) = input_ids.dims2()?;
        let input_embeddings = self.word_embeddings.forward(input_ids)?;
        let token_type_embeddings = self.token_type_embeddings.forward(token_type_ids)?;
        let embeddings = (&input_embeddings + token_type_embeddings)?;
        let position_ids = (0..sequence_length as u32).collect::<Vec<_>>();
        let position_ids = Tensor::new(position_ids.as_slice(), input_ids.device())?;
        let embeddings =
            embeddings.broadcast_add(&self.position_embeddings.forward(&position_ids)?)?;
        self.layer_norm.forward(&embeddings)
    }
}

fn finite_additive_attention_mask(attention_mask: &Tensor, dtype: DType) -> Result<Tensor> {
    let attention_mask = match attention_mask.rank() {
        3 => attention_mask.unsqueeze(1)?,
        2 => attention_mask.unsqueeze(1)?.unsqueeze(1)?,
        rank => candle_core::bail!(
            "Calyx BERT attention mask rank {rank} is unsupported; expected rank 2 or 3"
        ),
    };
    let masked_positions = attention_mask.eq(0_u32)?;
    let shape = attention_mask.shape().clone();
    let zero = Tensor::zeros(shape.clone(), dtype, attention_mask.device())?;
    let floor = finite_floor(dtype, shape, attention_mask.device())?;
    masked_positions.where_cond(&floor, &zero)
}

fn finite_floor(dtype: DType, shape: Shape, device: &Device) -> Result<Tensor> {
    match dtype {
        DType::F16 => Tensor::full(half::f16::MIN, shape, device),
        DType::BF16 => Tensor::full(half::bf16::MIN, shape, device),
        DType::F32 => Tensor::full(f32::MIN, shape, device),
        other => candle_core::bail!(
            "Calyx BERT execution contract {CANDLE_BERT_EXECUTION_REVISION} does not support dtype {other:?}"
        ),
    }
}
