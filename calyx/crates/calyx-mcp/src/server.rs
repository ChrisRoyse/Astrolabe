//! MCP server: tool registry plus dispatch for the three mandatory methods
//! (`initialize`, `tools/list`, `tools/call`).
//!
//! Dispatch never panics out: a tool that panics is caught and converted to a
//! `-32603` internal error so the stdio loop survives. A tool that returns a
//! [`CalyxError`] is mapped to a `-32000` error preserving its `CALYX_*` code.

use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};

use calyx_core::{AuthN, CalyxError, no_anonymous_write};
use serde_json::{Value, json};

use crate::jsonrpc::JsonRpcRequest;
use crate::protocol::{JsonRpcError, JsonRpcResponse, ToolCallResult, ToolDef};

/// MCP protocol revision this scaffold speaks (echoed in `initialize`).
pub const MCP_PROTOCOL_VERSION: &str = "2024-11-05";
/// Server name reported in `initialize.serverInfo`.
pub const SERVER_NAME: &str = "calyx-mcp";

/// Local code for a duplicate tool registration (a setup-time programming error;
/// kept MCP-local rather than widening the closed `calyx-core` catalog).
pub const CALYX_MCP_TOOL_DUPLICATE: &str = "CALYX_MCP_TOOL_DUPLICATE";

/// Failure class returned by a tool call.
#[derive(Debug)]
pub enum ToolError {
    /// Structurally wrong arguments: maps to JSON-RPC `-32602`.
    InvalidParams(String),
    /// Calyx domain failure: maps to JSON-RPC `-32000` with `CALYX_*` data.
    Calyx(CalyxError),
}

impl ToolError {
    /// Builds an invalid-params error.
    pub fn invalid_params(message: impl Into<String>) -> Self {
        Self::InvalidParams(message.into())
    }
}

impl From<CalyxError> for ToolError {
    fn from(error: CalyxError) -> Self {
        Self::Calyx(error)
    }
}

/// Tool call result type.
pub type ToolResult<T> = std::result::Result<T, ToolError>;

/// A registerable MCP tool. Implementors are `Send + Sync` so a server can be
/// shared across threads; `call` must be side-effect-honest and fail closed.
pub trait Tool: Send + Sync {
    /// The descriptor advertised by `tools/list`.
    fn def(&self) -> ToolDef;
    /// Whether this tool can mutate durable Calyx state and therefore requires
    /// a caller identity before dispatch.
    fn requires_authn(&self) -> bool;
    /// Executes the tool against decoded `arguments`, returning a JSON payload.
    fn call(&self, params: Value) -> ToolResult<Value>;
}

/// The dispatch surface: an ordered registry of tools keyed by name.
#[derive(Default)]
pub struct McpServer {
    tools: BTreeMap<String, Box<dyn Tool>>,
}

impl McpServer {
    /// Creates an empty server (no tools registered).
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers `tool`, failing closed on a duplicate name so two tools can
    /// never silently shadow one another.
    pub fn register(&mut self, tool: Box<dyn Tool>) -> Result<(), CalyxError> {
        let name = tool.def().name;
        if self.tools.contains_key(&name) {
            return Err(CalyxError {
                code: CALYX_MCP_TOOL_DUPLICATE,
                message: format!("tool already registered: {name}"),
                remediation: "register each MCP tool under a unique name",
            });
        }
        self.tools.insert(name, tool);
        Ok(())
    }

    /// Number of registered tools.
    pub fn tool_count(&self) -> usize {
        self.tools.len()
    }

    /// Routes a decoded request to its handler, always returning a response.
    pub fn dispatch(&self, request: JsonRpcRequest) -> JsonRpcResponse {
        self.dispatch_with_authn(request, None)
    }

    /// Routes a decoded request with an optional authenticated caller identity.
    ///
    /// Mutating tools are rejected before their `call` body runs when `authn` is
    /// absent. Read-only tools continue to work anonymously.
    pub fn dispatch_with_authn(
        &self,
        request: JsonRpcRequest,
        authn: Option<&AuthN>,
    ) -> JsonRpcResponse {
        match request.method.as_str() {
            "initialize" => self.handle_initialize(request),
            "tools/list" => self.handle_tools_list(request),
            "tools/call" => self.handle_tools_call(request, authn),
            other => JsonRpcResponse::error(request.id, JsonRpcError::method_not_found(other)),
        }
    }

    fn handle_initialize(&self, request: JsonRpcRequest) -> JsonRpcResponse {
        let result = json!({
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": { "tools": {} },
            "serverInfo": {
                "name": SERVER_NAME,
                "version": env!("CARGO_PKG_VERSION"),
            },
        });
        JsonRpcResponse::success(request.id, result)
    }

    fn handle_tools_list(&self, request: JsonRpcRequest) -> JsonRpcResponse {
        let defs: Vec<ToolDef> = self.tools.values().map(|tool| tool.def()).collect();
        JsonRpcResponse::success(request.id, json!({ "tools": defs }))
    }

    fn handle_tools_call(&self, request: JsonRpcRequest, authn: Option<&AuthN>) -> JsonRpcResponse {
        let id = request.id.clone();
        let params = request.params.unwrap_or(Value::Null);

        let name = match params.get("name").and_then(Value::as_str) {
            Some(name) if !name.is_empty() => name.to_string(),
            _ => {
                return JsonRpcResponse::error(
                    id,
                    JsonRpcError::invalid_params("tools/call requires a non-empty string `name`"),
                );
            }
        };
        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));

        let Some(tool) = self.tools.get(&name) else {
            return JsonRpcResponse::error(id, JsonRpcError::method_not_found(&name));
        };
        if tool.requires_authn()
            && let Err(error) = no_anonymous_write(authn)
        {
            return JsonRpcResponse::error(id, JsonRpcError::from_calyx(&error));
        }

        // A tool is third-party logic: isolate panics so one bad call cannot take
        // down the stdio loop. AssertUnwindSafe is sound here — on panic we only
        // construct a fresh error and touch no tool-owned state afterwards.
        let outcome = catch_unwind(AssertUnwindSafe(|| tool.call(arguments)));
        match outcome {
            Ok(Ok(value)) => match serde_json::to_string(&value) {
                Ok(payload) => JsonRpcResponse::success(id, json!(ToolCallResult::text(payload))),
                Err(error) => JsonRpcResponse::error(
                    id,
                    JsonRpcError::internal(format!("serialize tool result: {error}")),
                ),
            },
            Ok(Err(ToolError::InvalidParams(message))) => {
                JsonRpcResponse::error(id, JsonRpcError::invalid_params(message))
            }
            Ok(Err(ToolError::Calyx(calyx))) => {
                JsonRpcResponse::error(id, JsonRpcError::from_calyx(&calyx))
            }
            Err(_panic) => {
                JsonRpcResponse::error(id, JsonRpcError::internal("internal server error"))
            }
        }
    }
}

