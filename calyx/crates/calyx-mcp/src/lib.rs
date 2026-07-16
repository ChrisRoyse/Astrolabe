//! MCP interface for agent-facing Calyx operations.
//!
//! The wire stack is split across modules: [`jsonrpc`] decodes inbound requests,
//! [`protocol`] frames responses and MCP descriptors, [`schema`] builds tool
//! input schemas, and [`server`] holds the tool registry and dispatch.
//!
//! # Ingest Input Retention
//!
//! `calyx.ingest` text input follows the Aster input-store contract from issue
//! #446: retained text bytes are written as content-addressed `cxinput:v1:`
//! Blob-CF rows in the same atomic batch as the Base row, and the MCP write path
//! reads those rows back before reporting success. Redacted text is labeled on
//! both `Constellation.input_ref.redacted` and `CxFlags.redacted_input`.
//!
//! `calyx.ingest_media` intentionally keeps a separate retained-artifact path.
//! Raw image/audio/video bytes and generated derived text live behind
//! `calyx-vault://...` artifact pointers, while the durable
//! `DerivedMediaArtifactRecord` links source media, target derived text, hashes,
//! runtime, and model metadata. Media-derived text constellations therefore use
//! artifact pointers plus artifact-record lineage rather than `cxinput:v1:`
//! rows; changing that would be a media artifact migration, not text-retention
//! plumbing.

pub mod jsonrpc;
pub mod protocol;
pub mod schema;
pub mod server;
pub mod tools;

pub use jsonrpc::{
    CALYX_MCP_JSONRPC_INVALID, JsonRpcId, JsonRpcRequest, JsonRpcWire, decode_jsonrpc_request,
    decode_jsonrpc_wire,
};
pub use protocol::{
    ContentBlock, JSONRPC_CALYX_ERROR, JSONRPC_INTERNAL_ERROR, JSONRPC_INVALID_PARAMS,
    JSONRPC_METHOD_NOT_FOUND, JsonRpcError, JsonRpcResponse, ToolCallResult, ToolDef,
};
pub use server::{
    CALYX_MCP_TOOL_DUPLICATE, MCP_PROTOCOL_VERSION, McpServer, SERVER_NAME, Tool, ToolError,
    ToolResult,
};
