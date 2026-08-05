//! The one type for a fault the caller can act on (#989).
//!
//! # Why this type exists
//!
//! Before #989 the MCP surface had no type for "a fault the caller can correct".
//! A handler either flattened `{code, message, remediation}` into one human string
//! and returned it as the sole `content[0].text` of an error result, or returned a
//! bare `DynError` that escaped the handler entirely. Neither is machine-readable:
//!
//! * the flattened string turned three contract fields into punctuation, so a
//!   caller had to regex an English sentence to learn what to fix;
//! * an escaped `DynError` was relabelled at the boundary as
//!   `ASTRO_MCP_HANDLER_INTERNAL` with a remediation about persisted stores and
//!   locks — telling an agent to investigate state that a caller typo never
//!   touched, and implying a server defect that a retry might clear (#910).
//!
//! [`ToolFault`] keeps the three contract fields as *fields* all the way to the
//! wire, and carries typed details (which argument, what type was expected, what
//! arrived) alongside them. Because it implements [`std::error::Error`], the same
//! value works whether a handler returns it as `Ok(fault.into_result()?)` or lets
//! it escape as `Err(fault.into())` — both boundaries recognise it and emit the
//! identical envelope.
//!
//! # Wire contract
//!
//! Per the MCP specification (2026-07-28, *Tools → Error Handling*), an input
//! validation failure is a **tool execution error**, not a JSON-RPC protocol
//! error: it is reported inside a successful result with `isError: true` so the
//! model can read it and self-correct. Protocol errors are reserved for unknown
//! tools and malformed requests, which a model cannot fix. The same section's
//! *Structured Content* rule says a tool returning structured content should also
//! mirror the serialized JSON into a text block, which [`ToolFault::into_result`]
//! does.
//!
//! The envelope is versioned by [`TOOL_FAULT_SCHEMA`] so a caller can detect the
//! shape without guessing, and is deliberately its own schema rather than a
//! tool's `outputSchema`: an error result must never be validated against the
//! success schema (SEP-2145; the cross-validation bug that motivates it is live
//! in several MCP clients).
//!
//! # Anti-recurrence
//!
//! [`ToolFault::new`] cannot be called without a code, a message, and a
//! remediation, so a fault built through this type is structurally incapable of
//! losing them.
//!
//! The legacy `helpers::tool_error_result(String)` — which took those three
//! fields already flattened into one sentence — is what made the unstructured
//! shape the easy one to reach, and it is being retired: its remaining callers
//! migrate under #990, after which it is deleted and the compiler, not a
//! convention, is what prevents the shape from returning. It survives this commit
//! only because a concurrent session holds several of those call sites open in
//! this same worktree, so removing it now would silently destroy in-flight work.
//! That is a sequencing constraint, not a design choice.

use std::error::Error;
use std::fmt;

use astrolabe_bridge::BridgeError;

use super::*;

/// Version tag on every caller-facing fault envelope.
///
/// Present as the `schema` field so a caller can recognise the shape without
/// inferring it from which keys happen to be set.
pub(crate) const TOOL_FAULT_SCHEMA: &str = "astrolabe.tool_fault/v1";

/// A refusal the caller can act on, carried with its contract fields intact.
///
/// Construct with [`ToolFault::new`], attach typed details with
/// [`ToolFault::with_detail`] or [`ToolFault::with_argument`], and emit with
/// [`ToolFault::into_result`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ToolFault {
    code: String,
    message: String,
    remediation: String,
    /// Extra machine-readable context (`argument`, `expected_type`, …) merged
    /// into the envelope beside the three contract fields.
    details: Map<String, Value>,
}

impl ToolFault {
    /// A fault with the three mandatory contract fields.
    ///
    /// `code` is the stable identifier a caller branches on, `message` states
    /// what was refused, and `remediation` states what to change. All three are
    /// required because a fault missing any one of them is not actionable.
    pub(crate) fn new(
        code: impl Into<String>,
        message: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            remediation: remediation.into(),
            details: Map::new(),
        }
    }

    /// Attach one machine-readable detail field to the envelope.
    ///
    /// Keys that would shadow a contract field (`schema`, `status`, `code`,
    /// `message`, `remediation`) are rejected at construction time by
    /// [`ToolFault::envelope`], which writes the contract fields last.
    pub(crate) fn with_detail(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }

    /// Attach the standard argument-fault triple: which argument, what type it
    /// had to be, and what actually arrived.
    ///
    /// This is the shape an agent needs to repair a call without re-reading the
    /// tool schema.
    pub(crate) fn with_argument(
        self,
        argument: impl Into<String>,
        expected_type: impl Into<String>,
        actual: &Value,
    ) -> Self {
        self.with_detail("argument", Value::String(argument.into()))
            .with_detail("expected_type", Value::String(expected_type.into()))
            .with_detail("actual_type", Value::String(json_type_name(actual).into()))
    }

    /// The stable code a caller branches on.
    pub(crate) fn code(&self) -> &str {
        &self.code
    }

    /// The canonical envelope: schema and status, the three contract fields, and
    /// every attached detail.
    ///
    /// Contract fields are written after the details so a stray detail key can
    /// never displace them.
    pub(crate) fn envelope(&self) -> Value {
        let mut envelope = self.details.clone();
        envelope.insert("schema".into(), Value::String(TOOL_FAULT_SCHEMA.into()));
        envelope.insert("status".into(), Value::String("error".into()));
        envelope.insert("code".into(), Value::String(self.code.clone()));
        envelope.insert("message".into(), Value::String(self.message.clone()));
        envelope.insert(
            "remediation".into(),
            Value::String(self.remediation.clone()),
        );
        Value::Object(envelope)
    }

    /// Render as an MCP tool execution error: `isError: true`, the envelope in
    /// `structuredContent`, and the serialized envelope mirrored into the text
    /// block for clients that do not read structured content.
    pub(crate) fn into_result(self) -> Result<String, DynError> {
        tool_json_error_result(self.envelope())
    }

    /// Recover a fault from an error that escaped a handler as `Err`.
    ///
    /// Walks the source chain, so a fault wrapped by an intermediate error is
    /// still classified as caller-correctable rather than collapsing into
    /// `ASTRO_MCP_HANDLER_INTERNAL`. Also recognises a [`BridgeError`], whose
    /// envelope already carries the same three contract fields.
    pub(crate) fn from_error(error: &(dyn Error + Send + Sync + 'static)) -> Option<Self> {
        let mut current: Option<&(dyn Error + 'static)> = Some(error);
        while let Some(candidate) = current {
            if let Some(fault) = candidate.downcast_ref::<ToolFault>() {
                return Some(fault.clone());
            }
            if let Some(bridge) = candidate.downcast_ref::<BridgeError>() {
                let envelope = bridge.envelope();
                let mut fault = Self::new(
                    envelope.code.clone(),
                    envelope.message.clone(),
                    envelope.remediation.clone(),
                );
                if let Some(stderr) = envelope.stderr.as_ref() {
                    fault = fault.with_detail("stderr", Value::String(stderr.clone()));
                }
                return Some(fault);
            }
            current = candidate.source();
        }
        None
    }
}

impl fmt::Display for ToolFault {
    /// The legacy single-line rendering, kept byte-identical to what the
    /// flattened constructor produced so human-facing stderr and log lines read
    /// exactly as before. The structured envelope, not this string, is the
    /// machine contract.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}: {}; remediation: {}",
            self.code, self.message, self.remediation
        )
    }
}

impl Error for ToolFault {}

/// Emit a caller-correctable refusal as an MCP tool execution error.
///
/// The only way to produce an error tool result. Takes the fault whole so the
/// code, message, and remediation cannot be lost to string formatting.
pub(crate) fn tool_fault_result(fault: ToolFault) -> Result<String, DynError> {
    fault.into_result()
}

/// The canonical envelope for an error that escaped a handler as `Err`, or
/// `None` when the error carries no structured envelope and is therefore a
/// genuine internal fault.
///
/// The single classification point shared by the JSON-RPC boundary and the CLI
/// boundary, so both agree on what counts as caller-correctable.
pub(crate) fn tool_fault_from_error(error: &(dyn Error + Send + Sync + 'static)) -> Option<Value> {
    ToolFault::from_error(error).map(|fault| fault.envelope())
}

/// Render an escaped error as an MCP tool execution error when it is
/// caller-correctable, or `None` when it is a genuine internal fault that must
/// keep propagating.
pub(crate) fn tool_fault_result_from_error(
    error: &(dyn Error + Send + Sync + 'static),
) -> Option<Result<String, DynError>> {
    ToolFault::from_error(error).map(ToolFault::into_result)
}

/// Build a fault for an argument whose JSON type is wrong.
///
/// The overwhelmingly common caller error, given its own constructor so every
/// tool reports it with the same fields.
pub(crate) fn argument_type_fault(
    code: &str,
    tool: &str,
    argument: &str,
    expected_type: &str,
    actual: &Value,
) -> ToolFault {
    ToolFault::new(
        code,
        format!(
            "{tool} argument '{argument}' must be {expected_type}; received {}",
            json_type_name(actual)
        ),
        format!(
            "correct the JSON type of '{argument}' to match the inputSchema returned by tools/list, then retry"
        ),
    )
    .with_argument(argument, expected_type, actual)
}
