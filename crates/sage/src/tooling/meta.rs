//! Sidecar `call_id -> ToolCallMeta` index — keeps the (session_id,
//! tool_name) pair audit-published on `sage.v1.audit.tool_call` so
//! `enforce_deadlines` can surface a real `tool_name` in its timeout
//! events. Hard-capped via [`MAX_TOOL_CALL_META`] so a stuck supervisor
//! can't OOM the capsule.

use astrid_sdk::prelude::*;
use std::collections::HashMap;
use std::sync::Mutex;

use crate::ToolCallMeta;

/// Soft cap on the `tool_call_meta` sidecar index. The supervisor only
/// inserts on dispatch and tooling.rs removes on result/timeout, so the
/// map is normally bounded by [`crate::state::MAX_SESSIONS_PER_PRINCIPAL`]
/// × per-session in-flight calls. This is a defensive ceiling in case a
/// future upstream bug ever drops a result event — we'd rather drop
/// observability than balloon memory.
pub(crate) const MAX_TOOL_CALL_META: usize = 4096;

/// Drain a batch of `sage.v1.audit.tool_call` envelopes into the sidecar
/// `call_id -> ToolCallMeta` index. Idempotent (last writer wins per
/// `call_id`); LIFO-evicts the oldest excess once
/// [`MAX_TOOL_CALL_META`] is reached so the map can't grow unbounded
/// even if the supervisor leaks an audit on every dispatch.
pub(crate) fn record_tool_call_meta(
    tool_call_meta: &Mutex<HashMap<String, ToolCallMeta>>,
    messages: Vec<ipc::Message>,
) -> Result<(), SysError> {
    if messages.is_empty() {
        return Ok(());
    }
    let mut meta = tool_call_meta
        .lock()
        .map_err(|_| SysError::ApiError("sage tool_call_meta lock poisoned".into()))?;
    for msg in messages {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&msg.payload) else {
            continue;
        };
        let Some(call_id) = value.get("call_id").and_then(|v| v.as_str()) else {
            continue;
        };
        let tool_name = value
            .get("tool_name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let session_id = value
            .get("session_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if meta.len() >= MAX_TOOL_CALL_META
            && let Some(victim) = meta.keys().next().cloned()
        {
            meta.remove(&victim);
        }
        meta.insert(
            call_id.to_string(),
            ToolCallMeta {
                session_id,
                tool_name,
            },
        );
    }
    Ok(())
}
