//! [FastEmbed](https://github.com/Anush008/fastembed-rs) - Fast, light, accurate library built for retrieval embedding generation.
//!
//! The library provides the TextEmbedding struct to interface with text embedding models.
//!
//! Every ONNX-backed constructor requires an explicit [`SessionPolicy`] and exactly one
//! matching execution provider. Default initialization options intentionally leave the policy
//! unspecified, so session construction fails before ONNX Runtime can choose an implicit CPU
//! fallback.
//!
#![cfg_attr(
    feature = "hf-hub",
    doc = r#"
 ### Instantiating [TextEmbedding](crate::TextEmbedding)
 ```
 use fastembed::{EmbeddingModel, SessionPolicy, TextEmbedding, TextInitOptions};
 use ort::ep::CPU;

# fn model_demo() -> anyhow::Result<()> {
 // Model defaults are available, but execution placement must be explicit.
 let model = TextEmbedding::try_new(
     TextInitOptions::default()
         .with_execution_providers(vec![CPU::default().build().error_on_failure()])
         .with_session_policy(SessionPolicy::explicit_cpu()),
 )?;

 // List all supported models
 dbg!(TextEmbedding::list_supported_models());

 // With custom model options and the same explicit placement contract.
 let model = TextEmbedding::try_new(
     TextInitOptions::new(EmbeddingModel::AllMiniLML6V2)
         .with_show_download_progress(true)
         .with_execution_providers(vec![CPU::default().build().error_on_failure()])
         .with_session_policy(SessionPolicy::explicit_cpu()),
 )?;
 # Ok(())
 # }
 ```
"#
)]
//! Find more info about the available options in the [InitOptions](crate::InitOptions) documentation.
//!
#![cfg_attr(
    feature = "hf-hub",
    doc = r#"
 ### Embeddings generation
```
# use fastembed::{SessionPolicy, TextEmbedding, TextInitOptions};
# use ort::ep::CPU;
# fn embedding_demo() -> anyhow::Result<()> {
# let mut model = TextEmbedding::try_new(
#     TextInitOptions::default()
#         .with_execution_providers(vec![CPU::default().build().error_on_failure()])
#         .with_session_policy(SessionPolicy::explicit_cpu()),
# )?;
 let documents = vec![
    "passage: Hello, World!",
    "query: Hello, World!",
    "passage: This is an example passage.",
    // You can leave out the prefix but it's recommended
    "fastembed-rs is licensed under MIT"
    ];

 // Generate embeddings with the default batch size, 256
 let embeddings = model.embed(documents, None)?;

 println!("Embeddings length: {}", embeddings.len()); // -> Embeddings length: 4
 # Ok(())
 # }
 ```
"#
)]

mod common;

mod bgem3_embedding;
#[cfg(feature = "image-models")]
mod image_embedding;
mod init;
mod models;
pub mod output;
mod pooling;
mod reranking;
mod sparse_text_embedding;
mod text_embedding;

pub use ort::execution_providers::ExecutionProviderDispatch;

pub use crate::common::{get_cache_dir, Embedding, Error, SparseEmbedding, TokenizerFiles};
pub use crate::models::{
    model_info::ModelInfo, model_info::RerankerModelInfo, quantization::QuantizationMode,
};
pub use crate::output::{EmbeddingOutput, OutputKey, OutputPrecedence, SingleBatchOutput};
pub use crate::pooling::Pooling;

// For all Embedding
pub use crate::init::{InitOptions as BaseInitOptions, InitOptionsWithLength, SessionPolicy};
pub use crate::models::ModelTrait;

// For Text Embedding
pub use crate::models::text_embedding::EmbeddingModel;
#[deprecated(note = "use `TextInitOptions` instead")]
pub use crate::text_embedding::TextInitOptions as InitOptions;
pub use crate::text_embedding::{
    InitOptionsUserDefined, TextEmbedding, TextInitOptions, UserDefinedEmbeddingModel,
};

// For Sparse Text Embedding
pub use crate::models::sparse::SparseModel;
pub use crate::sparse_text_embedding::{
    SparseInitOptions, SparseTextEmbedding, UserDefinedSparseModel,
};

// For BGEM3 Joint Embedding
pub use crate::bgem3_embedding::{
    Bgem3Embedding, Bgem3EmbeddingOutput, Bgem3InitOptions, UserDefinedBgem3Model,
};
pub use crate::models::bgem3::Bgem3Model;

// For Image Embedding
#[cfg(feature = "image-models")]
pub use crate::image_embedding::{
    ImageEmbedding, ImageInitOptions, ImageInitOptionsUserDefined, UserDefinedImageEmbeddingModel,
};
pub use crate::models::image_embedding::ImageEmbeddingModel;

// For Reranking
pub use crate::models::reranking::RerankerModel;
pub use crate::reranking::{
    OnnxSource, RerankInitOptions, RerankInitOptionsUserDefined, RerankResult, TextRerank,
    UserDefinedRerankingModel,
};

// For Qwen3 (candle backend)
#[cfg(feature = "qwen3")]
pub use crate::models::qwen3::{
    Config as Qwen3Config, Qwen3Model, Qwen3TextEmbedding, Qwen3VLEmbedding,
};

// For Nomic Embed Text v2 MoE (candle backend)
#[cfg(feature = "nomic-v2-moe")]
pub use crate::models::nomic_v2_moe::{NomicConfig, NomicV2MoeTextEmbedding};
