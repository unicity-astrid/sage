//! Approval (`permission_request`) lifecycle: register on request,
//! route on response.
//!
//! Pairs with the `approval.v1.request` / `approval.v1.response.<id>`
//! bus topics. The supervisor publishes the request when claude emits a
//! `permission_request` control frame; some external decider replies on
//! the matching response topic; this module records the in-flight set
//! and routes the verdict back into claude's stdin as a
//! `control_response` frame.

use astrid_sdk::prelude::*;
use serde::Deserialize;

use crate::state::Sessions;
use crate::topic_tail;

use super::encode::{approval_marker_key, encode_approval_verdict};
use super::publish_session_error;

/// Wire-shape of an `approval.v1.response.<correlation_id>` payload.
/// Mirrors the `behavior:"allow"|"deny"` form Claude expects in a
/// `control_response`'s `response` object.
///
/// Accepts the `updated_input` field as either snake_case (capsule-bus
/// convention) or `updatedInput` (MCP wire convention) so any producer
/// publishing the verdict can use the natural form for its surface.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ApprovalResponse {
    #[serde(default)]
    pub correlation_id: String,
    /// `"allow"` or `"deny"`.
    pub behavior: String,
    /// Optional rewritten arguments to substitute into the tool call.
    #[serde(default, alias = "updatedInput")]
    pub updated_input: Option<serde_json::Value>,
    /// Optional human-readable rationale.
    #[serde(default)]
    pub message: Option<String>,
}

/// Wire-shape of an `approval.v1.request` payload (supervisor publishes
/// this on the fixed `approval.v1.request` topic when claude emits a
/// `permission_request` control frame). Only fields needed for the
/// register path are deserialized.
#[derive(Debug, Clone, Deserialize)]
struct ApprovalRequest {
    session_id: String,
    /// Claude's `sdk_control_request.request_id`. The matching
    /// `approval.v1.response` is expected to echo this value (either on
    /// the topic tail or in the `correlation_id` body field).
    request_id: String,
}

/// Drain a batch of `approval.v1.request` envelopes published by the
/// supervisor on the fixed `approval.v1.request` topic. For each one
/// register a `approval:<request_id>` sentinel in the matching
/// session's `partial_tool_inputs` so the corresponding
/// `approval.v1.response.<request_id>` can be routed back to claude's
/// stdin by [`route_approvals`].
///
/// Wiring rationale: the supervisor lives in a sibling slice we can't
/// modify here, but it already publishes a self-describing payload
/// (carries `session_id` + `request_id`). Self-subscribing keeps the
/// approval lifecycle end-to-end functional without crossing the slice
/// boundary.
pub(crate) fn register_pending_approval_from_request(
    sessions: &Sessions,
    messages: Vec<ipc::Message>,
) -> Result<(), SysError> {
    if messages.is_empty() {
        return Ok(());
    }
    for msg in messages {
        let req: ApprovalRequest = match serde_json::from_str(&msg.payload) {
            Ok(r) => r,
            Err(e) => {
                log::warn(format!("sage: approval.v1.request parse failed: {e}"));
                continue;
            }
        };
        if req.session_id.is_empty() || req.request_id.is_empty() {
            log::warn("sage: approval.v1.request missing session_id/request_id");
            continue;
        }
        if let Err(e) = register_pending_approval(sessions, &req.session_id, &req.request_id) {
            log::warn(format!(
                "sage: register approval ({}/{}) failed: {e:?}",
                req.session_id, req.request_id
            ));
        }
    }
    Ok(())
}

/// Route a batch of `approval.v1.response.*` envelopes back into the
/// matching session's stdin as `control_response` verdicts.
///
/// Match strategy: the topic's trailing segment is the `correlation_id`
/// S6 set when publishing the original `approval.v1.request`; the
/// payload also carries it, so we accept either source (topic wins to
/// keep the path tight). Sessions store their outstanding approval
/// correlation ids in `partial_tool_inputs` keyed under
/// `approval:<correlation_id>` — same map, distinct namespace, no
/// extra state struct needed.
///
/// Verdict encoding: `{behavior:"allow", updatedInput?, message?}` or
/// `{behavior:"deny", message?}`. Always wrapped as the inner
/// `response` of a `control_response` frame; the codec's existing
/// `ControlResponseToolResult` variant carries the wrong shape (it's
/// for tool results, not permission decisions), so we encode the
/// verdict envelope manually here.
pub(crate) fn route_approvals(
    sessions: &Sessions,
    messages: Vec<ipc::Message>,
) -> Result<(), SysError> {
    if messages.is_empty() {
        return Ok(());
    }

    // Pre-parse before grabbing the lock.
    let mut parsed: Vec<(String, ApprovalResponse)> = Vec::with_capacity(messages.len());
    for msg in messages {
        let Some(corr_id) = topic_tail(&msg.topic).map(str::to_string) else {
            log::warn(format!("sage: approval response missing tail: {}", msg.topic));
            continue;
        };
        match serde_json::from_str::<ApprovalResponse>(&msg.payload) {
            Ok(mut r) => {
                if r.correlation_id.is_empty() {
                    r.correlation_id = corr_id.clone();
                }
                parsed.push((corr_id, r));
            }
            Err(e) => {
                log::warn(format!("sage: approval payload parse failed: {e}"));
            }
        }
    }

    // INVARIANT: NO host calls under the Sessions lock. Phase 1 (under
    // lock): match correlation ids to sessions, evict the marker,
    // encode the verdict frame, and clone the `PersistentProcess` handle.
    // Phase 2 (lock released): issue every `write_stdin` and any
    // failure publish.
    let mut pending = sessions.with(|map| -> Vec<ApprovalPrepared> {
        let mut out = Vec::new();
        for (corr_id, resp) in parsed {
            let approval_marker = approval_marker_key(&corr_id);
            let mut matched = false;
            for (sid, session) in map.iter_mut() {
                if session.partial_tool_inputs.remove(&approval_marker).is_some() {
                    matched = true;
                    let frame = encode_approval_verdict(&resp);
                    out.push(ApprovalPrepared {
                        session_id: sid.clone(),
                        correlation_id: corr_id.clone(),
                        process: Some(session.process.clone()),
                        line: frame,
                    });
                    break;
                }
            }
            if !matched {
                // Defer the log out of the closure too — log::warn is
                // a host call (publishes to the log bus).
                out.push(ApprovalPrepared::unmatched(corr_id));
            }
        }
        out
    })?;

    for p in pending.drain(..) {
        match p.process_opt() {
            None => {
                log::warn(format!(
                    "sage: approval verdict for unknown correlation_id {}; dropping",
                    p.correlation_id
                ));
            }
            Some((proc, line)) => {
                if let Err(e) = proc.write_stdin(line.as_bytes()) {
                    publish_session_error(
                        &p.session_id,
                        "stdin_write_failed",
                        &format!("{e:?}"),
                    );
                }
            }
        }
    }
    Ok(())
}

/// Register an outstanding approval request against a session. Stores
/// a sentinel in `partial_tool_inputs` keyed
/// `approval:<correlation_id>` so [`route_approvals`] can match the
/// response back without growing a fresh map. Wired from
/// [`register_pending_approval_from_request`] in the run-loop drain of
/// `approval.v1.request`.
pub(crate) fn register_pending_approval(
    sessions: &Sessions,
    session_id: &str,
    correlation_id: &str,
) -> Result<(), SysError> {
    let marker = approval_marker_key(correlation_id);
    sessions.with(|map| {
        if let Some(session) = map.get_mut(session_id) {
            session.partial_tool_inputs.insert(
                marker,
                crate::state::PartialTool {
                    name: "<approval>".to_string(),
                    input_json: String::new(),
                },
            );
        }
    })
}

/// Per-correlation-id hand-off collected by [`route_approvals`].
/// `process` is `None` when no session matched the correlation id, in
/// which case the caller logs and drops outside the sessions lock.
struct ApprovalPrepared {
    session_id: String,
    correlation_id: String,
    process: Option<process::PersistentProcess>,
    line: String,
}

impl ApprovalPrepared {
    fn unmatched(correlation_id: String) -> Self {
        Self {
            session_id: String::new(),
            correlation_id,
            process: None,
            line: String::new(),
        }
    }

    fn process_opt(&self) -> Option<(&process::PersistentProcess, &str)> {
        self.process.as_ref().map(|p| (p, self.line.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_response_accepts_camel_case_updated_input() {
        // MCP wire emits `updatedInput`; the serde alias makes it
        // parse to the snake_case field without losing the value.
        let raw = r#"{
            "correlation_id": "corr_x",
            "behavior": "allow",
            "updatedInput": {"path":"/y"}
        }"#;
        let parsed: ApprovalResponse = serde_json::from_str(raw).unwrap();
        assert_eq!(parsed.behavior, "allow");
        assert_eq!(
            parsed.updated_input.unwrap(),
            serde_json::json!({"path":"/y"})
        );
    }

    #[test]
    fn approval_response_accepts_snake_case_updated_input() {
        let raw = r#"{
            "correlation_id": "corr_y",
            "behavior": "allow",
            "updated_input": {"path":"/z"}
        }"#;
        let parsed: ApprovalResponse = serde_json::from_str(raw).unwrap();
        assert_eq!(
            parsed.updated_input.unwrap(),
            serde_json::json!({"path":"/z"})
        );
    }
}
