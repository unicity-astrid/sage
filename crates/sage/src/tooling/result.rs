//! Tool-result write-back path and 60 s deadline enforcement.
//!
//! Both entry points share an invariant: NO host calls are issued
//! while holding the `Sessions` lock. Phase 1 (under lock) prepares
//! the encoded frame, evicts the pending entry, and clones the
//! `PersistentProcess` handle. Phase 2 (lock released) does every
//! `write_stdin` and bus publish. Holding the sessions mutex across a
//! host call would serialise the whole supervisor loop and risks
//! deadlock if the host call re-enters the bus drain.

use astrid_sdk::prelude::*;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Mutex;

use crate::state::Sessions;
use crate::{TOOL_CALL_DEADLINE, ToolCallMeta};

use super::encode::{encode_tool_result_frame, is_expired};
use super::publish_session_error;

/// Wire-shape of a `sage.v1.tool.result.<call_id>` payload from
/// `sage-mcp`. `content` is forwarded into the `mcp_response.content`
/// array verbatim — the bridge already validated it against the tool
/// schema before publishing.
///
/// Wire shape intentionally does NOT carry the Claude-side correlation
/// (e.g. `tool_use_id` or `sdk_control_request.request_id`) — that
/// mapping is sage-internal (stored alongside the entry in
/// [`crate::state::RuntimeSession::pending_tool_calls`]) and is
/// reconstituted at write-back time when sage encodes the
/// `control_response` frame for claude's stdin. External responders on
/// `sage.v1.tool.call.<call_id>` therefore never need to understand
/// Claude's protocol semantics; they echo `call_id` only. This keeps
/// the bus contract LLM-agnostic and prevents leaking provider-specific
/// id schemes onto the cross-capsule wire.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ToolResultEvent {
    pub call_id: String,
    /// Free-form content blocks (typically `[{type:"text",text:...}]`).
    /// Stored as JSON to keep the codec/bridge contract loose.
    pub content: serde_json::Value,
    #[serde(default, rename = "isError")]
    pub is_error: bool,
}

/// Handle a `sage.v1.tool.result.<call_id>` envelope.
///
/// Scans every live session for one whose `pending_tool_calls` carries
/// the matching `call_id`; first match wins (UUIDv4 is globally unique
/// in practice). On match: encode the result frame against the stored
/// `Correlation` — MCP control-request results go back as
/// `control_response.mcp_response` echoing claude's original
/// `request_id`, plain assistant `tool_use` results go back as a fresh
/// `user`-role turn carrying a `tool_result` block keyed by
/// `tool_use_id`. Single `write_stdin` call, then evict the pending-
/// call entry. On a stdin write error or `too-large`, publish
/// `sage.v1.event.<sid>.error{reason:"stdin_write_failed"}` so the
/// supervisor can tear the session down on the next tick.
pub(crate) fn handle_tool_result(
    sessions: &Sessions,
    tool_call_meta: &Mutex<HashMap<String, ToolCallMeta>>,
    payload: serde_json::Value,
) -> Result<(), SysError> {
    let event: ToolResultEvent = serde_json::from_value(payload)
        .map_err(|e| SysError::ApiError(format!("tool_result: bad payload: {e}")))?;

    // INVARIANT: NO host calls under the Sessions lock. Phase 1: find
    // the session, pop the pending entry, encode the line, clone the
    // `PersistentProcess` handle out. Phase 2 (below): issue the host write.
    let prepared = sessions.with(|map| -> Option<PreparedWrite> {
        for (sid, session) in map.iter_mut() {
            if let Some(pending) = session.pending_tool_calls.remove(&event.call_id) {
                // Encode against the stored correlation, NOT the
                // `call_id` — claude has never seen sage's call_id and
                // will silently 60-s-timeout if we echo that instead of
                // its own `request_id` / `tool_use_id`.
                let line = encode_tool_result_frame(
                    &pending.correlation,
                    &event.content,
                    event.is_error,
                );
                return Some(PreparedWrite {
                    session_id: sid.clone(),
                    process: session.process.clone(),
                    line,
                });
            }
        }
        None
    })?;

    let outcome = match prepared {
        None => WriteOutcome::NoMatch,
        Some(p) => match p.process.write_stdin(p.line.as_bytes()) {
            Ok(_) => WriteOutcome::Written,
            Err(e) => WriteOutcome::Failed {
                session_id: p.session_id,
                reason: format!("{e:?}"),
            },
        },
    };

    // Successful match OR a write failure both retire the sidecar meta
    // entry (the call is no longer in flight). NoMatch leaves it alone
    // so a late audit event from a slow-publish race still lands.
    if !matches!(outcome, WriteOutcome::NoMatch)
        && let Ok(mut meta) = tool_call_meta.lock()
    {
        meta.remove(&event.call_id);
    }

    match outcome {
        WriteOutcome::Written => Ok(()),
        WriteOutcome::NoMatch => {
            // Late result for a call that already deadline-expired (or
            // came from a tool S6 didn't register) — drop on the floor.
            log::warn(format!(
                "sage: tool_result for unknown call_id {}; dropping",
                event.call_id
            ));
            Ok(())
        }
        WriteOutcome::Failed { session_id, reason } => {
            publish_session_error(&session_id, "stdin_write_failed", &reason);
            // Session is doomed — caller can't recover from a stdin
            // failure, but we don't tear down here because the run
            // loop's `stop_session` path is the canonical eviction
            // route. Next iteration will see `read_logs().running=false`
            // and finish the cleanup.
            Ok(())
        }
    }
}

/// Sweep every session's `pending_tool_calls` and synthesize an
/// `isError:true` write-back for any call older than
/// [`TOOL_CALL_DEADLINE`]. Publishes
/// `sage.v1.event.<sid>.tool_timeout{call_id, tool_name}` for each.
///
/// `tool_call_meta` is the sidecar index populated by
/// `record_tool_call_meta` from the supervisor's
/// `sage.v1.audit.tool_call` publishes. Its keys (`call_id`, UUIDv4)
/// match the keys the supervisor pushes into `pending_tool_calls`, so
/// the lookup actually hits — unlike `partial_tool_inputs`, which is
/// keyed by Anthropic's `tool_use_id` and was the source of the
/// "always unknown" verifier finding.
pub(crate) fn enforce_deadlines(
    sessions: &Sessions,
    tool_call_meta: &Mutex<HashMap<String, ToolCallMeta>>,
) -> Result<(), SysError> {
    // Unit MUST match supervisor::now_ms (crates/sage/src/supervisor.rs):
    // `pending_tool_calls` stores monotonic-millis at dispatch time, so we
    // compare in milliseconds here. Mixing ns/ms made every dispatched
    // tool call appear ~1_000_000x past the deadline on the first sweep.
    let now_ms = u64::try_from(time::monotonic().as_millis()).unwrap_or(u64::MAX);
    let deadline_ms = u64::try_from(TOOL_CALL_DEADLINE.as_millis()).unwrap_or(u64::MAX);

    // INVARIANT: NO host calls under the Sessions lock — write_stdin is
    // a host call that can block. Phase 1 (under lock): identify every
    // expired call, evict its pending entry, encode the timeout frame,
    // and clone the `PersistentProcess` handle. Phase 2 (lock released):
    // issue all stdin writes and the meta-lookup + ipc::publish back-
    // channel.
    let pending = sessions.with(|map| -> Vec<TimeoutPrepared> {
        let mut out = Vec::new();
        for (sid, session) in map.iter_mut() {
            // Collect expired ids first; can't mutate while iterating.
            let expired: Vec<String> = session
                .pending_tool_calls
                .iter()
                .filter_map(|(call_id, pending)| {
                    if is_expired(now_ms, pending.started_ms, deadline_ms) {
                        Some(call_id.clone())
                    } else {
                        None
                    }
                })
                .collect();

            for call_id in &expired {
                let Some(pending) = session.pending_tool_calls.remove(call_id) else {
                    continue;
                };
                let content = serde_json::Value::String(format!(
                    "sage: tool call deadline exceeded ({}s)",
                    TOOL_CALL_DEADLINE.as_secs()
                ));
                // Use the captured correlation here too — a timeout
                // frame echoing sage's `call_id` would be just as
                // unmatchable to claude as a successful result with the
                // wrong id.
                let line = encode_tool_result_frame(&pending.correlation, &content, true);
                out.push(TimeoutPrepared {
                    session_id: sid.clone(),
                    call_id: call_id.clone(),
                    process: session.process.clone(),
                    line,
                });
            }
        }
        out
    })?;

    // Phase 2: write outside the lock.
    let timeouts: Vec<TimeoutWrite> = pending
        .into_iter()
        .map(|p| {
            let write_err = p.process.write_stdin(p.line.as_bytes()).err();
            TimeoutWrite {
                session_id: p.session_id,
                call_id: p.call_id,
                write_err: write_err.map(|e| format!("{e:?}")),
            }
        })
        .collect();

    // Resolve tool names + clean up the sidecar after the session lock
    // is released. Lock order: sessions -> tool_call_meta. Single
    // critical section here, no overlap with the sessions lock above.
    let resolved_names = {
        let mut meta = tool_call_meta
            .lock()
            .map_err(|_| SysError::ApiError("sage tool_call_meta lock poisoned".into()))?;
        timeouts
            .iter()
            .map(|t| {
                meta.remove(&t.call_id)
                    .map(|m| m.tool_name)
                    .unwrap_or_else(|| "unknown".to_string())
            })
            .collect::<Vec<_>>()
    };

    for (t, tool_name) in timeouts.into_iter().zip(resolved_names) {
        if let Some(reason) = t.write_err {
            publish_session_error(&t.session_id, "stdin_write_failed", &reason);
        } else {
            let _ = ipc::publish_json(
                &format!("sage.v1.event.{}.tool_timeout", t.session_id),
                &serde_json::json!({
                    "call_id": t.call_id,
                    "tool_name": tool_name,
                }),
            );
        }
    }
    Ok(())
}

// ---- internal hand-off types ------------------------------------------

enum WriteOutcome {
    Written,
    NoMatch,
    Failed { session_id: String, reason: String },
}

/// Hand-off package collected under `Sessions::with` and consumed
/// outside the lock by [`handle_tool_result`]. Carries the cloned
/// `PersistentProcess` handle so the host `write_stdin` can run with the
/// sessions mutex released.
struct PreparedWrite {
    session_id: String,
    process: process::PersistentProcess,
    line: String,
}

/// Per-expired-call hand-off collected by [`enforce_deadlines`] under
/// the lock and consumed outside it.
struct TimeoutPrepared {
    session_id: String,
    call_id: String,
    process: process::PersistentProcess,
    line: String,
}

struct TimeoutWrite {
    session_id: String,
    call_id: String,
    write_err: Option<String>,
}
