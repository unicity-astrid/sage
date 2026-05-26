#![deny(unsafe_code)]
#![deny(clippy::all)]
#![deny(unreachable_pub)]
#![warn(missing_docs)]

//! sage-completion — Anthropic API LLM provider for Astrid OS.
//!
//! Subscribes to `llm.v1.request.generate.sage` IPC events, calls the
//! Anthropic Messages API via the HTTP airlock, parses the SSE
//! streaming response, and publishes standardized
//! `llm.v1.stream.sage` events back to the event bus.
//!
//! This is the per-turn completion path. It bills against Anthropic
//! API usage credits, separate from the Agent SDK credit consumed by
//! `claude -p` (see the sibling crate `sage`). When `capsule-router`
//! picks "Claude" as the model for a turn but doesn't want to spin up
//! a full Claude Code agent loop, the request lands here.

use astrid_sdk::prelude::*;

/// sage-completion provider.
#[derive(Default)]
pub struct SageCompletion;

#[capsule]
impl SageCompletion {
    // Scaffolding only — actual request/response handlers land
    // once we wire up the Anthropic Messages API client.
}
