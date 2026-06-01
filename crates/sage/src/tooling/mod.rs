//! S7 tool plumbing: result write-back, 60 s deadline enforcement,
//! approval-verdict routing, audit-meta sidecar.
//!
//! All three behaviours share the same write path: encode a stream-json
//! frame, call [`process::Process::write_stdin`] once.
//!
//! Correlation: sage mints a fresh UUIDv4 `call_id` per dispatch — that
//! is sage's internal handle for the round-trip and the topic-tail key
//! external responders echo on `sage.v1.tool.result.<call_id>`. It is
//! NOT what claude expects to see back. The supervisor stashes the
//! actual upstream id alongside the pending entry in
//! `pending_tool_calls` as a [`crate::state::Correlation`]: either
//! claude's `sdk_control_request.request_id` (MCP control path) or the
//! assistant's `tool_use_id` (tool_use path). Write-back here reads
//! that correlation and emits the matching wire shape —
//! `control_response` with the `mcp_response` wrapper for the former,
//! `user/tool_result` envelope for the latter. Mixing them up strands
//! claude waiting on a reply it can never match, tripping the 60 s SDK
//! timeout.
//!
//! ## Module map
//!
//! * [`encode`] — pure, host-call-free encoders + helpers. The only
//!   funnel for tool-result wire shape; covered by the regression test
//!   pinning the `request_id` / `tool_use_id` echo invariant.
//! * [`result`] — `handle_tool_result` + `enforce_deadlines`. Both
//!   route through the encoders above and follow the
//!   "phase-1-under-lock, phase-2-after" discipline.
//! * [`approval`] — `register_pending_approval{,_from_request}` +
//!   `route_approvals`. Uses a sentinel marker in `partial_tool_inputs`
//!   keyed `approval:<correlation_id>` to thread the verdict back.
//! * [`meta`] — `record_tool_call_meta` + [`MAX_TOOL_CALL_META`]. The
//!   sidecar `call_id -> ToolCallMeta` index used by `enforce_deadlines`.

use astrid_sdk::prelude::*;

mod approval;
mod encode;
mod meta;
mod result;

pub(crate) use approval::{register_pending_approval_from_request, route_approvals};
pub(crate) use meta::record_tool_call_meta;
pub(crate) use result::{enforce_deadlines, handle_tool_result};

// Re-exported through `tooling::MAX_TOOL_CALL_META` so existing doclinks
// in `lib.rs` keep resolving without callers reaching into the
// submodule path. The constant itself is read only inside `meta`.
#[allow(unused_imports)]
pub(crate) use meta::MAX_TOOL_CALL_META;

/// Publish a `sage.v1.event.<session_id>.error` envelope. Shared
/// between the result and approval slices because both fall back to it
/// when a stdin write fails — the session is then doomed and the
/// supervisor will tear it down on the next read_logs() tick.
pub(super) fn publish_session_error(session_id: &str, reason: &str, detail: &str) {
    let _ = ipc::publish_json(
        &format!("sage.v1.event.{session_id}.error"),
        &serde_json::json!({
            "reason": reason,
            "detail": detail,
        }),
    );
}
