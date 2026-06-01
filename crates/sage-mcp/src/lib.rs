#![deny(unsafe_code)]
#![deny(clippy::all)]
#![deny(unreachable_pub)]
#![warn(missing_docs)]

//! sage-mcp — MCP server bridging Astrid capsule tools to Claude.
//!
//! Claude (running as a `claude -p` subprocess supervised by the
//! `sage` capsule) is restricted to MCP-only tools via
//! `--allowedTools 'mcp__sage__*'`. This capsule owns the MCP-facing
//! contract: it discovers the tools other capsules export via the
//! `tool.v1.request.describe` fan-out, shapes them into MCP tool
//! descriptors, caches them, and serves the assembled list on
//! `sage.v1.tools.list`.
//!
//! Three handler paths:
//!
//! * `sage.v1.tools.describe` -> [`SageMcp::describe_tools`]:
//!   on-demand fan-out + cache replace + republish.
//! * `tool.v1.response.describe.*` -> [`SageMcp::collect_tool_descriptors`]:
//!   event-driven cache merge.
//! * `sage.v1.tool.call.<call_id>` -> [`SageMcp::handle_tool_call`]:
//!   live execute bridge — strips the `mcp__sage__` prefix, fans out
//!   to `tool.v1.execute.<bare_name>`, drains
//!   `tool.v1.execute.<bare_name>.result`, reshapes into the
//!   `sage.v1.tool.result.<call_id>` envelope that
//!   `sage::tooling::result::handle_tool_result` consumes. The bridge
//!   owns the response invariant: every accepted call publishes
//!   exactly one result, success or failure, so sage's
//!   `pending_tool_calls` slot retires cleanly without waiting on the
//!   60 s deadline sweeper.

mod cache;
mod discovery;
mod execute;

use astrid_sdk::prelude::*;

/// sage-mcp bridge.
#[derive(Default)]
pub struct SageMcp;

#[capsule]
impl SageMcp {
    /// `sage.v1.tools.describe` — assemble (or replay) the MCP tool
    /// list and publish it on `sage.v1.tools.list`.
    ///
    /// The payload is intentionally ignored; the request is a bare
    /// "give me the current surface" signal. We accept a JSON value to
    /// stay forward-compatible with future request fields (e.g. a
    /// `force_refresh` flag) without changing the wire shape.
    #[astrid::interceptor("describe_tools")]
    pub fn describe_tools(&self, _payload: serde_json::Value) -> Result<(), SysError> {
        discovery::describe_tools();
        Ok(())
    }

    /// `tool.v1.response.describe.*` — event-driven cache update.
    ///
    /// Every tool-providing capsule broadcasts its descriptor set on
    /// load and on relevant config changes. We merge each broadcast
    /// into the cache via CAS so the next `describe_tools` call (and
    /// the agent runner's tool-list view) reflects the live surface
    /// without a full re-discovery.
    #[astrid::interceptor("collect_tool_descriptors")]
    pub fn collect_tool_descriptors(
        &self,
        payload: serde_json::Value,
    ) -> Result<(), SysError> {
        discovery::collect_tool_descriptors(payload);
        Ok(())
    }

    /// `sage.v1.tool.call.<call_id>` — live execute bridge.
    ///
    /// Strips the `mcp__sage__` MCP prefix off the inbound `tool_name`,
    /// publishes `tool.v1.execute.<bare>` with the SDK-canonical
    /// `ToolExecuteRequest` shape, drains
    /// `tool.v1.execute.<bare>.result` for the matching `call_id`, and
    /// publishes `sage.v1.tool.result.<call_id>` with the result
    /// reshaped into the `{ call_id, content, isError }` envelope
    /// `sage::tooling::result::handle_tool_result` expects. Every
    /// failure path (unknown prefix, invalid name, subscribe / publish
    /// error, 50 s drain timeout) writes back an `isError:true`
    /// envelope so the sage-side `pending_tool_calls` slot retires
    /// cleanly. See `execute` for the wire-shape and timeout details.
    #[astrid::interceptor("handle_tool_call")]
    pub fn handle_tool_call(&self, payload: serde_json::Value) -> Result<(), SysError> {
        execute::handle_tool_call(payload)
    }
}
