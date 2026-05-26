#![deny(unsafe_code)]
#![deny(clippy::all)]
#![deny(unreachable_pub)]
#![warn(missing_docs)]

//! sage-mcp — MCP server bridging Astrid capsule tools to Claude.
//!
//! Claude (running as a `claude -p` subprocess supervised by the
//! `sage` capsule) is restricted to MCP-only tools via
//! `--allowedTools 'mcp__sage__*'`. When Claude wants to call a
//! tool, the call surfaces as a `sage.v1.tool.call.<call-id>` event
//! on the bus. `sage-mcp` picks it up, validates the principal's
//! capability scope, dispatches via the `tool.v1` bus protocol to
//! the capsule that owns the tool, and returns the result on
//! `sage.v1.tool.result.<call-id>`.
//!
//! On the other side, when Claude requests a tools-list (MCP
//! initialize / list_tools), `sage-mcp` queries `tool.v1` describe
//! and shapes the responses into MCP tool descriptors so Claude
//! sees a normal MCP server surface.

use astrid_sdk::prelude::*;

/// sage-mcp bridge.
#[derive(Default)]
pub struct SageMcp;

#[capsule]
impl SageMcp {
    // Scaffolding only — tool-call dispatch and descriptor
    // collection land in the first real implementation pass.
}
