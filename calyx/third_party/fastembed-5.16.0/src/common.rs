use anyhow::{Result, anyhow};
#[cfg(feature = "hf-hub")]
use hf_hub::api::sync::{ApiBuilder, ApiRepo};
#[cfg(feature = "hf-hub")]
use std::path::PathBuf;
use tokenizers::{AddedToken, PaddingParams, PaddingStrategy, Tokenizer, TruncationParams};

const DEFAULT_CACHE_DIR: &str = ".fastembed_cache";

pub fn get_cache_dir() -> String {
    std::env::var("FASTEMBED_CACHE_DIR").unwrap_or(DEFAULT_CACHE_DIR.into())
}

#[derive(Debug, Clone, PartialEq)]
pub struct SparseEmbedding {
    pub indices: Vec<usize>,
    pub values: Vec<f32>,
}

/// Type alias for the embedding vector
pub type Embedding = Vec<f32>;

/// Type alias for the error type
pub type Error = anyhow::Error;

// Tokenizer files for "bring your own" models
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenizerFiles {
    pub tokenizer_file: Vec<u8>,
    pub config_file: Vec<u8>,
    pub special_tokens_map_file: Vec<u8>,
    pub tokenizer_config_file: Vec<u8>,
}

/// One external-data file referenced by the exact in-memory ONNX graph.
///
/// `file_name` must be the canonical relative POSIX path stored in the graph's
/// `TensorProto.external_data.location` entry. The buffer is retained by ONNX
/// Runtime for the committed session's lifetime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalInitializerFile {
    pub file_name: String,
    pub buffer: Vec<u8>,
}

impl ExternalInitializerFile {
    pub fn new(file_name: impl Into<String>, buffer: Vec<u8>) -> Self {
        Self {
            file_name: file_name.into(),
            buffer,
        }
    }
}

/// The procedure for loading tokenizer files from the hugging face hub is separated
/// from the main load_tokenizer function (which is expecting bytes, from any source).
#[cfg(feature = "hf-hub")]
pub fn load_tokenizer_hf_hub(model_repo: ApiRepo, max_length: usize) -> Result<Tokenizer> {
    let tokenizer_files: TokenizerFiles = TokenizerFiles {
        tokenizer_file: std::fs::read(model_repo.get("tokenizer.json")?)?,
        config_file: std::fs::read(&model_repo.get("config.json")?)?,
        special_tokens_map_file: std::fs::read(&model_repo.get("special_tokens_map.json")?)?,

        tokenizer_config_file: std::fs::read(&model_repo.get("tokenizer_config.json")?)?,
    };

    load_tokenizer(tokenizer_files, max_length)
}

/// Function can be called directly from the try_new_from_user_defined function (providing file bytes)
///
/// Or indirectly from the try_new function via load_tokenizer_hf_hub (converting HF files to bytes)
pub fn load_tokenizer(tokenizer_files: TokenizerFiles, max_length: usize) -> Result<Tokenizer> {
    // Deserialize each tokenizer file
    let config: serde_json::Value = serde_json::from_slice(&tokenizer_files.config_file)
        .map_err(|error| tokenizer_error("JSON_INVALID", "config.json", error))?;
    let special_tokens_map: serde_json::Value =
        serde_json::from_slice(&tokenizer_files.special_tokens_map_file)
            .map_err(|error| tokenizer_error("JSON_INVALID", "special_tokens_map.json", error))?;
    let tokenizer_config: serde_json::Value =
        serde_json::from_slice(&tokenizer_files.tokenizer_config_file)
            .map_err(|error| tokenizer_error("JSON_INVALID", "tokenizer_config.json", error))?;
    let mut tokenizer: tokenizers::Tokenizer =
        tokenizers::Tokenizer::from_bytes(tokenizer_files.tokenizer_file)
            .map_err(|error| tokenizer_error("TOKENIZER_INVALID", "tokenizer.json", error))?;

    let config = config.as_object().ok_or_else(|| {
        tokenizer_error(
            "ROOT_OBJECT_REQUIRED",
            "config.json",
            "top-level value is not an object",
        )
    })?;
    let tokenizer_config = tokenizer_config.as_object().ok_or_else(|| {
        tokenizer_error(
            "ROOT_OBJECT_REQUIRED",
            "tokenizer_config.json",
            "top-level value is not an object",
        )
    })?;
    let special_tokens_map = special_tokens_map.as_object().ok_or_else(|| {
        tokenizer_error(
            "ROOT_OBJECT_REQUIRED",
            "special_tokens_map.json",
            "top-level value is not an object",
        )
    })?;

    // Some upstream BGE metadata declares an intentionally huge numeric cap.
    let model_max_length = tokenizer_config
        .get("model_max_length")
        .ok_or_else(|| {
            tokenizer_error(
                "MODEL_MAX_LENGTH_MISSING",
                "tokenizer_config.json",
                "model_max_length is required",
            )
        })?
        .as_f64()
        .filter(|length| length.is_finite() && *length >= 1.0 && length.fract() == 0.0)
        .ok_or_else(|| {
            tokenizer_error(
                "MODEL_MAX_LENGTH_INVALID",
                "tokenizer_config.json",
                "model_max_length must be a finite integer greater than or equal to one",
            )
        })?;
    if max_length == 0 {
        return Err(tokenizer_error(
            "REQUESTED_MAX_LENGTH_INVALID",
            "constructor options",
            "max_length must be greater than zero",
        ));
    }
    let model_max_length = if model_max_length >= usize::MAX as f64 {
        usize::MAX
    } else {
        model_max_length.floor() as usize
    };
    let max_length = max_length.min(model_max_length);
    let raw_pad_id = config
        .get("pad_token_id")
        .ok_or_else(|| {
            tokenizer_error(
                "PAD_TOKEN_ID_MISSING",
                "config.json",
                "pad_token_id is required",
            )
        })?
        .as_u64()
        .ok_or_else(|| {
            tokenizer_error(
                "PAD_TOKEN_ID_INVALID",
                "config.json",
                "pad_token_id must be an unsigned integer",
            )
        })?;
    let pad_id = u32::try_from(raw_pad_id).map_err(|_| {
        tokenizer_error(
            "PAD_TOKEN_ID_OUT_OF_RANGE",
            "config.json",
            format!("pad_token_id {raw_pad_id} exceeds u32"),
        )
    })?;
    let pad_token = tokenizer_config
        .get("pad_token")
        .and_then(serde_json::Value::as_str)
        .filter(|token| !token.is_empty())
        .ok_or_else(|| {
            tokenizer_error(
                "PAD_TOKEN_INVALID",
                "tokenizer_config.json",
                "pad_token must be a non-empty string",
            )
        })?
        .into();

    let mut tokenizer = tokenizer
        .with_padding(Some(PaddingParams {
            // TODO: the user should be able to choose the padding strategy
            strategy: PaddingStrategy::BatchLongest,
            pad_token,
            pad_id,
            ..Default::default()
        }))
        .with_truncation(Some(TruncationParams {
            max_length,
            ..Default::default()
        }))
        .map_err(|error| {
            tokenizer_error(
                "TRUNCATION_CONFIGURATION_INVALID",
                "tokenizer metadata",
                error,
            )
        })?
        .clone();
    for (name, value) in special_tokens_map {
        let token = if let Some(content) = value.as_str() {
            if content.is_empty() {
                return Err(tokenizer_error(
                    "SPECIAL_TOKEN_INVALID",
                    "special_tokens_map.json",
                    format!("special token {name} is empty"),
                ));
            }
            AddedToken {
                content: content.into(),
                special: true,
                ..Default::default()
            }
        } else if let Some(value) = value.as_object() {
            let content = required_special_token_string(value, name, "content")?;
            AddedToken {
                content,
                special: true,
                single_word: required_special_token_bool(value, name, "single_word")?,
                lstrip: required_special_token_bool(value, name, "lstrip")?,
                rstrip: required_special_token_bool(value, name, "rstrip")?,
                normalized: required_special_token_bool(value, name, "normalized")?,
            }
        } else {
            return Err(tokenizer_error(
                "SPECIAL_TOKEN_INVALID",
                "special_tokens_map.json",
                format!("special token {name} must be a string or object"),
            ));
        };
        tokenizer.add_special_tokens(&[token]);
    }
    Ok(tokenizer.into())
}

fn required_special_token_string(
    value: &serde_json::Map<String, serde_json::Value>,
    token: &str,
    field: &str,
) -> Result<String> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            tokenizer_error(
                "SPECIAL_TOKEN_FIELD_INVALID",
                "special_tokens_map.json",
                format!("special token {token} requires non-empty string field {field}"),
            )
        })
}

fn required_special_token_bool(
    value: &serde_json::Map<String, serde_json::Value>,
    token: &str,
    field: &str,
) -> Result<bool> {
    value
        .get(field)
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| {
            tokenizer_error(
                "SPECIAL_TOKEN_FIELD_INVALID",
                "special_tokens_map.json",
                format!("special token {token} requires boolean field {field}"),
            )
        })
}

fn tokenizer_error(
    code: &'static str,
    source: impl std::fmt::Display,
    detail: impl std::fmt::Display,
) -> anyhow::Error {
    anyhow!(
        "FASTEMBED_TOKENIZER_METADATA_INVALID code={code} source={source} detail={detail} remediation=repair the exact frozen tokenizer metadata bytes before constructing an ONNX session"
    )
}

pub fn normalize(v: &[f32]) -> Vec<f32> {
    let norm = (v.iter().map(|val| val * val).sum::<f32>()).sqrt();
    let epsilon = 1e-12;

    // We add the super-small epsilon to avoid dividing by zero
    v.iter().map(|&val| val / (norm + epsilon)).collect()
}

/// Pulls a model repo from HuggingFace..
/// HF_HOME decides the location of the cache folder
/// HF_ENDPOINT modifies the URL for the HuggingFace location.
#[cfg(feature = "hf-hub")]
pub fn pull_from_hf(
    model_name: String,
    default_cache_dir: PathBuf,
    show_download_progress: bool,
) -> anyhow::Result<ApiRepo> {
    use std::env;

    let cache_dir = env::var("HF_HOME")
        .map(PathBuf::from)
        .unwrap_or(default_cache_dir);

    let endpoint = env::var("HF_ENDPOINT").unwrap_or_else(|_| "https://huggingface.co".to_string());

    let api = ApiBuilder::new()
        .with_cache_dir(cache_dir)
        .with_endpoint(endpoint)
        .with_progress(show_download_progress)
        .build()?;

    let repo = api.model(model_name);
    Ok(repo)
}
