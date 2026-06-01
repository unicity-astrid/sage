//! Cooperative supervisor for live `claude -p` subprocesses.
//!
//! The supervisor is the body of `#[astrid::run]`. Every ~50 ms it:
//!
//! 1. Drains stdout from every active session, feeding bytes into the
//!    session's [`codec::LineDecoder`].
//! 2. Dispatches every decoded envelope to the matching
//!    `sage.v1.event.<sid>.*` IPC topic.
//! 3. Detects process crash / buffer overflow / capsule reload and
//!    publishes synthetic `exited` events so consumers don't hang.
//!
//! Tool dispatch: on a complete `ToolUseStart` (inline `input`) or a
//! `ToolUseStop` (after partial accumulation) the supervisor mints a
//! fresh `call_id` (UUIDv4), persists it as a pending entry, and
//! publishes `sage.v1.tool.call.<call_id>`. `sage-mcp` picks that up,
//! runs the tool through the bus, and replies on
//! `sage.v1.tool.result.<call_id>`, which `lib.rs::handle_tool_result`
//! turns back into a stream-json frame on the claude stdin.

use crate::codec::{AssistantBlock, CodecError, Decoded};
use crate::state::{
    Correlation, PartialTool, PendingCall, RuntimeSession, SessionRecord, Sessions, delete_record,
    list_all_records,
};
use astrid_sdk::prelude::*;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

/// Supervisor tick cadence. Conservative enough to keep idle-capsule
/// CPU near zero, fast enough that interactive token streams from the
/// model feel live.
pub(crate) const TICK_INTERVAL: Duration = Duration::from_millis(50);

/// Run one supervisor tick across every active session. Returns
/// `Ok(())` even if individual sessions hit errors — errors are
/// surfaced as IPC events, never bubbled up to abort the tick.
pub(crate) fn tick(sessions: &Sessions) -> Result<(), SysError> {
    // First-tick recovery: any persisted records whose Process handle
    // is gone are publish-then-deleted as `capsule_reload` exits.
    if sessions.take_reload_recovered_flag()? {
        reload_recover(sessions)?;
    }

    // Collect session ids without holding the lock across the per-
    // session work (some of which publishes IPC, which can in turn
    // poll our subscriptions).
    let session_ids: Vec<String> = sessions.with(|map| map.keys().cloned().collect())?;

    for sid in session_ids {
        drive_session(sessions, &sid)?;
    }

    Ok(())
}

/// Pull new stdout from one session and dispatch its events.
///
/// INVARIANT: NO host calls under the Sessions lock. Mirrors the
/// Phase-1/Phase-2 pattern in [`crate::tooling::result::handle_tool_result`]:
///
/// 1. Phase 1a (under lock): clone the `Arc<Process>` handle and
///    snapshot the principal_id.
/// 2. Phase 2 (lock released): call `process.read_logs()` — a host
///    call that may block and could re-enter the bus drain.
/// 3. Phase 1b (re-lock): feed the bytes into the codec, decode any
///    completed lines, and run `collect_events` so the mutations to
///    `partial_tool_inputs` / `pending_tool_calls` stay coherent.
///
/// Holding the sessions mutex across the host call would serialise the
/// whole supervisor loop and risks deadlock; cloning the `Arc<Process>`
/// is cheap and `read_logs` only needs `&Process`.
fn drive_session(sessions: &Sessions, session_id: &str) -> Result<(), SysError> {
    // Phase 1a: clone what we need out from under the lock.
    let prep = sessions.with(|map| -> Option<DrivePrep> {
        let session = map.get(session_id)?;
        Some(DrivePrep {
            process: Arc::clone(&session.process),
            principal_id: session.record.principal_id.clone(),
        })
    })?;

    let Some(prep) = prep else { return Ok(()) };

    // Phase 2: host call with NO sessions lock held.
    let logs = match prep.process.read_logs() {
        Ok(l) => l,
        Err(e) => {
            log::warn(format!("sage: read_logs failed for {session_id}: {e}"));
            return Ok(());
        }
    };

    // Phase 1b: re-take the lock to feed the codec and update in-flight
    // tool-call bookkeeping. The session may have been evicted in
    // between the two lock acquisitions (e.g. shutdown on another
    // path); treat that as Skip.
    let outcome = sessions.with(|map| -> Option<DriveOutcome> {
        let session = map.get_mut(session_id)?;

        let mut events: Vec<PendingEvent> = Vec::new();
        let mut buffer_overflow = false;
        if !logs.stdout.is_empty() {
            let decoded = session.codec.feed(logs.stdout.as_bytes()).collect::<Vec<_>>();
            for item in decoded {
                match item {
                    Ok(d) => {
                        collect_events(session, &prep.principal_id, session_id, d, &mut events)
                    }
                    Err(CodecError::LineTooLong) => {
                        buffer_overflow = true;
                    }
                    Err(CodecError::Malformed(msg)) => {
                        log::warn(format!("sage: malformed stream-json on {session_id}: {msg}"));
                    }
                }
            }
        }

        if buffer_overflow {
            return Some(DriveOutcome::BufferOverflow);
        }

        let exited = if logs.running { None } else { Some(logs.exit) };

        Some(DriveOutcome::Drained { events, exited })
    })?;

    match outcome {
        None => Ok(()),
        Some(DriveOutcome::BufferOverflow) => {
            publish_exit(session_id, "buffer_overflow", None, None);
            evict(sessions, session_id)?;
            Ok(())
        }
        Some(DriveOutcome::Drained { events, exited }) => {
            for ev in events {
                ev.publish();
            }
            if let Some(exit_info) = exited {
                let (code, sig) = match exit_info {
                    Some(info) => (info.exit_code, info.signal),
                    None => (None, None),
                };
                publish_exit(session_id, "exited", code, sig);
                evict(sessions, session_id)?;
            }
            Ok(())
        }
    }
}

enum DriveOutcome {
    Drained {
        events: Vec<PendingEvent>,
        exited: Option<Option<process::ExitInfo>>,
    },
    BufferOverflow,
}

/// Hand-off package collected under `Sessions::with` and consumed
/// outside the lock by [`drive_session`]. Carries the cloned
/// `Arc<Process>` handle so the host `read_logs` runs with the sessions
/// mutex released — mirrors the pattern in [`crate::tooling::result`].
struct DrivePrep {
    process: Arc<process::Process>,
    principal_id: String,
}

/// IPC events queued while the session lock is held; published after
/// we release the lock so subscribers' handlers can re-enter freely.
struct PendingEvent {
    topic: String,
    payload: Value,
}

impl PendingEvent {
    fn publish(self) {
        if let Err(e) = ipc::publish_json(&self.topic, &self.payload) {
            log::warn(format!("publish {} failed: {e}", self.topic));
        }
    }
}

/// Translate one [`Decoded`] envelope into the corresponding
/// `sage.v1.event.<sid>.*` payloads, updating in-flight tool-call
/// bookkeeping along the way.
fn collect_events(
    session: &mut RuntimeSession,
    principal_id: &str,
    session_id: &str,
    decoded: Decoded,
    out: &mut Vec<PendingEvent>,
) {
    match decoded {
        Decoded::SystemInit { model, .. } => {
            out.push(PendingEvent {
                topic: format!("sage.v1.event.{session_id}.init"),
                payload: serde_json::json!({ "model": model }),
            });
        }
        Decoded::Assistant { content_blocks } => {
            for block in content_blocks {
                match block {
                    AssistantBlock::Text { text } => {
                        out.push(PendingEvent {
                            topic: format!("sage.v1.event.{session_id}.text"),
                            payload: serde_json::json!({ "delta": text }),
                        });
                    }
                    AssistantBlock::ToolUseStart {
                        id,
                        name,
                        input_partial,
                    } => {
                        if let Some(json_str) = input_partial {
                            // Inline-input variant: dispatch immediately.
                            let arguments = serde_json::from_str::<Value>(&json_str)
                                .unwrap_or(Value::Null);
                            dispatch_tool_call(
                                session,
                                principal_id,
                                session_id,
                                &id,
                                &name,
                                arguments,
                                out,
                            );
                        } else {
                            // Streamed: stash the buffer so deltas can
                            // append.
                            session.partial_tool_inputs.insert(
                                id,
                                PartialTool {
                                    name,
                                    input_json: String::new(),
                                },
                            );
                        }
                    }
                }
            }
        }
        Decoded::ToolUseDelta { id, partial_json } => {
            if let Some(pt) = session.partial_tool_inputs.get_mut(&id) {
                pt.input_json.push_str(&partial_json);
            } else {
                // Delta with no prior start — accept defensively.
                session.partial_tool_inputs.insert(
                    id,
                    PartialTool {
                        name: String::new(),
                        input_json: partial_json,
                    },
                );
            }
        }
        Decoded::ToolUseStop { id } => {
            if let Some(pt) = session.partial_tool_inputs.remove(&id) {
                let arguments = if pt.input_json.is_empty() {
                    Value::Object(Default::default())
                } else {
                    serde_json::from_str::<Value>(&pt.input_json).unwrap_or(Value::Null)
                };
                dispatch_tool_call(
                    session,
                    principal_id,
                    session_id,
                    &id,
                    &pt.name,
                    arguments,
                    out,
                );
            }
        }
        Decoded::ControlRequest {
            request_id,
            subtype,
            payload,
        } => match subtype.as_str() {
            "mcp_message" => {
                // Extract the tools/call from the wrapped JSON-RPC.
                let params = payload
                    .get("message")
                    .and_then(|m| m.get("params"))
                    .cloned()
                    .unwrap_or(Value::Null);
                let name = params
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);
                let call_id = Uuid::new_v4().to_string();
                session.pending_tool_calls.insert(
                    call_id.clone(),
                    PendingCall {
                        started_ms: now_ms(),
                        // Captured here at dispatch time so
                        // `handle_tool_result` can echo claude's
                        // original `request_id` back — NOT sage's
                        // internal `call_id`, which claude never saw.
                        correlation: Correlation::McpControl {
                            claude_request_id: request_id.clone(),
                        },
                    },
                );
                out.push(PendingEvent {
                    topic: format!("sage.v1.tool.call.{call_id}"),
                    payload: serde_json::json!({
                        // `call_id` is also mirrored into the payload so
                        // sage-mcp can recover it from the body alone —
                        // interceptor dispatch only delivers the action
                        // name and payload bytes, not the source topic,
                        // so the topic-suffix call_id is invisible to the
                        // handler unless echoed here.
                        "call_id": call_id,
                        "session_id": session_id,
                        "principal_id": principal_id,
                        "tool_name": name,
                        "arguments": arguments,
                        // tag for handle_tool_result so it writes back
                        // a control_response (with mcp_response wrapper)
                        // on the matching slot.
                        "via_mcp_control": true,
                        "claude_request_id": request_id,
                    }),
                });
                out.push(PendingEvent {
                    topic: "sage.v1.audit.tool_call".to_string(),
                    payload: serde_json::json!({
                        "principal_id": principal_id,
                        "session_id": session_id,
                        "call_id": call_id,
                        "tool_name": name,
                    }),
                });
            }
            "permission_request" => {
                out.push(PendingEvent {
                    topic: "approval.v1.request".to_string(),
                    payload: serde_json::json!({
                        "session_id": session_id,
                        "principal_id": principal_id,
                        "request_id": request_id,
                        "payload": payload,
                    }),
                });
            }
            other => {
                log::warn(format!(
                    "sage: unknown sdk_control_request subtype '{other}' on {session_id}"
                ));
            }
        },
        Decoded::Result {
            subtype,
            is_error,
            usage,
            total_cost_usd,
            permission_denials,
        } => {
            out.push(PendingEvent {
                topic: format!("sage.v1.event.{session_id}.done"),
                payload: serde_json::json!({
                    "subtype": subtype,
                    "is_error": is_error,
                    "usage": usage,
                    "total_cost_usd": total_cost_usd,
                    "permission_denials": permission_denials,
                }),
            });
        }
        Decoded::StreamEvent { event } => {
            // Token-level events; consumer opts in.
            out.push(PendingEvent {
                topic: format!("sage.v1.event.{session_id}.partial"),
                payload: serde_json::json!({ "event": event }),
            });
        }
        Decoded::UserToolResultEcho { .. } | Decoded::Ping => {
            // No-op: echoes are observability-only, ping is keepalive.
        }
        Decoded::Unknown(value) => {
            log::warn(format!(
                "sage: unknown stream-json envelope on {session_id}: {}",
                value
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or("<no type>")
            ));
        }
    }
}

fn dispatch_tool_call(
    session: &mut RuntimeSession,
    principal_id: &str,
    session_id: &str,
    tool_use_id: &str,
    name: &str,
    arguments: Value,
    out: &mut Vec<PendingEvent>,
) {
    let call_id = Uuid::new_v4().to_string();
    session.pending_tool_calls.insert(
        call_id.clone(),
        PendingCall {
            started_ms: now_ms(),
            // The `tool_use_id` from the assistant's tool_use block is
            // what the response envelope must carry; claude matches the
            // result back via that id, not sage's `call_id`.
            correlation: Correlation::ToolUse {
                tool_use_id: tool_use_id.to_string(),
            },
        },
    );
    out.push(PendingEvent {
        topic: format!("sage.v1.tool.call.{call_id}"),
        payload: serde_json::json!({
            // Mirror `call_id` into the body so sage-mcp's interceptor
            // can recover it (the dispatcher only delivers payload bytes
            // and the action name, not the source topic).
            "call_id": call_id,
            "session_id": session_id,
            "principal_id": principal_id,
            "tool_name": name,
            "arguments": arguments,
            "tool_use_id": tool_use_id,
        }),
    });
    out.push(PendingEvent {
        topic: "sage.v1.audit.tool_call".to_string(),
        payload: serde_json::json!({
            "principal_id": principal_id,
            "session_id": session_id,
            "call_id": call_id,
            "tool_name": name,
        }),
    });
}

fn publish_exit(session_id: &str, reason: &str, exit_code: Option<i32>, signal: Option<i32>) {
    let _ = ipc::publish_json(
        &format!("sage.v1.event.{session_id}.exited"),
        &serde_json::json!({
            "reason": reason,
            "exit_code": exit_code,
            "signal": signal,
        }),
    );
}

/// Drop a runtime session AND its persisted record.
fn evict(sessions: &Sessions, session_id: &str) -> Result<(), SysError> {
    sessions.with(|map| {
        map.remove(session_id);
    })?;
    let _ = delete_record(session_id);
    Ok(())
}

/// First-tick recovery: anything in KV but not in the runtime map is
/// an orphan from the previous capsule incarnation.
fn reload_recover(sessions: &Sessions) -> Result<(), SysError> {
    let live_ids: HashMap<String, ()> =
        sessions.with(|map| map.keys().cloned().map(|k| (k, ())).collect())?;
    let records: Vec<SessionRecord> = match list_all_records() {
        Ok(r) => r,
        Err(e) => {
            log::warn(format!("sage: reload-recovery list failed: {e}"));
            return Ok(());
        }
    };
    for rec in records {
        if live_ids.contains_key(&rec.session_id) {
            continue;
        }
        // Defense in depth: refuse to format!() an unvalidated id into
        // an IPC topic, even when it came from our own KV store. A
        // stale record from before validation was deployed (or a future
        // bug that writes a tainted id) shouldn't be able to publish on
        // an attacker-chosen topic. Drop the orphan record either way.
        if crate::validate_id("session_id", &rec.session_id).is_err() {
            log::warn("sage: reload-recovery dropping record with invalid session_id");
            let _ = delete_record(&rec.session_id);
            continue;
        }
        publish_exit(&rec.session_id, "capsule_reload", None, None);
        let _ = delete_record(&rec.session_id);
    }
    Ok(())
}

fn now_ms() -> u64 {
    u64::try_from(astrid_sdk::time::monotonic().as_millis()).unwrap_or(0)
}
