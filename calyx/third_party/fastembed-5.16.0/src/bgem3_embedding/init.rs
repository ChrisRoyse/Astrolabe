use ort::session::Session;
use tokenizers::Tokenizer;

use crate::{
    init::{HasMaxLength, InitOptionsWithLength},
    models::bgem3::Bgem3Model,
    ExternalInitializerFile, SparseEmbedding, TokenizerFiles,
};

use super::DEFAULT_MAX_LENGTH;

impl HasMaxLength for Bgem3Model {
    const MAX_LENGTH: usize = DEFAULT_MAX_LENGTH;
}

pub type Bgem3InitOptions = InitOptionsWithLength<Bgem3Model>;

#[derive(Debug, Clone)]
pub struct Bgem3EmbeddingOutput {
    pub dense: Vec<Vec<f32>>,
    pub sparse: Vec<SparseEmbedding>,
    pub colbert: Vec<Vec<Vec<f32>>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserDefinedBgem3Model {
    pub onnx_file: Vec<u8>,
    pub external_initializers: Vec<ExternalInitializerFile>,
    pub tokenizer_files: TokenizerFiles,
    pub model: Bgem3Model,
}

impl UserDefinedBgem3Model {
    pub fn new(onnx_file: Vec<u8>, tokenizer_files: TokenizerFiles) -> Self {
        Self {
            onnx_file,
            external_initializers: Vec::new(),
            tokenizer_files,
            model: Bgem3Model::default(),
        }
    }

    pub fn with_model(mut self, model: Bgem3Model) -> Self {
        self.model = model;
        self
    }

    pub fn with_external_initializer(
        mut self,
        file_name: impl Into<String>,
        buffer: Vec<u8>,
    ) -> Self {
        self.external_initializers
            .push(ExternalInitializerFile::new(file_name, buffer));
        self
    }
}

pub struct Bgem3Embedding {
    pub tokenizer: Tokenizer,
    pub(crate) session: Session,
    pub(crate) need_token_type_ids: bool,
    pub model: Bgem3Model,
}
