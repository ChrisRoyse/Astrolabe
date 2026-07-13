//! Lens runtime implementations.

pub mod adapters;
pub mod algorithmic;
#[cfg(feature = "ml-runtime")]
pub mod candle;
pub(crate) mod common;
pub mod external_cmd;
#[cfg(feature = "ml-runtime")]
pub mod onnx;
#[cfg(feature = "ml-runtime")]
pub mod qwen3;
#[cfg(feature = "ml-runtime")]
pub mod static_lookup;
pub mod tei_http;
