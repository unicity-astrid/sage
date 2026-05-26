#![deny(unsafe_code)]
#![deny(clippy::all)]
#![deny(unreachable_pub)]
#![warn(missing_docs)]

//! Sage — Claude headless agent runner on Astrid OS.
//!
//! Supervises one `claude -p --input-format stream-json --output-format
//! stream-json` subprocess per principal. Streams the user's turns in,
//! parses Claude's stream-json events out, dispatches tool-call events
//! to the bus where `sage-mcp` picks them up, feeds tool-call results
//! back in. The subprocess is long-lived so Anthropic-side prompt
//! caching stays warm turn-to-turn.
//!
//! Bills against the user's Anthropic Agent SDK credit (per Anthropic's
//! June 15, 2026 billing model). For per-turn API completion mode that
//! bypasses the SDK credit, see the sibling crate `sage-completion`.

use astrid_sdk::prelude::*;

/// Sage agent runner.
#[derive(Default)]
pub struct Sage;

#[capsule]
impl Sage {
    // Scaffolding only. Handlers land with sage-mcp; subprocess
    // supervision lands once the agent-provider contract is locked.
}
