//! Tool execute bridge — `sage.v1.tool.call.<call_id>` -> `tool.v1.execute.<name>` fan-out
//! and `tool.v1.execute.<name>.result` -> `sage.v1.tool.result.<call_id>` reshape.
//!
//! Wire contract:
//!
//! * **Inbound** (`sage.v1.tool.call.<call_id>`, published by `sage::supervisor`):
//!   `{ call_id, session_id, principal_id, tool_name, arguments, ... }`. The
//!   topic-suffix `call_id` is also mirrored into the body because the
//!   interceptor dispatcher only delivers the action name + payload bytes
//!   — the source topic is not visible to the handler.
//! * **Outbound request** (`tool.v1.execute.<tool_name>`): the SDK-canonical
//!   `ToolExecuteRequest` shape `{ type:"tool_execute_request", call_id,
//!   tool_name, arguments }`, mirroring what the router capsule emits.
//!   The handler-side macro deserializes via `__AstridToolExecPayload`
//!   which only requires `{ call_id, tool_name, arguments }`, so the
//!   tagged form is accepted unchanged.
//! * **Outbound result** (`sage.v1.tool.result.<call_id>`): the
//!   sage-internal envelope `{ call_id, content, isError }` consumed by
//!   `sage::tooling::result::handle_tool_result`. `content` is forwarded
//!   verbatim as a `[{ "type":"text", "text":<string> }]` array so the
//!   existing encoder paths don't need to learn a new shape.
//!
//! MCP-side names are prefixed `mcp__sage__<original>` (see
//! [`crate::discovery::MCP_TOOL_PREFIX`]). Claude calls tools by the
//! prefixed name; the bridge strips the prefix before routing to the
//! `tool.v1.execute.<original>` topic. Anything that doesn't carry the
//! prefix is rejected as an unknown tool — sage only owns the
//! `mcp__sage__*` namespace.
//!
//! INVARIANT: every accepted `sage.v1.tool.call.<call_id>` MUST publish
//! exactly one `sage.v1.tool.result.<call_id>` envelope, success or
//! failure. The sage-side `pending_tool_calls` map otherwise leaks
//! entries until the 60 s deadline sweeper fires — at which point claude
//! has already 60-s-timed-out the request and any later reply would land
//! on an absent slot and warn-drop.

use astrid_sdk::prelude::*;
use serde::Deserialize;
use serde_json::{Value, json};

/// MCP tool-name prefix sage exposes to Claude.
///
/// Mirrors [`crate::discovery::MCP_TOOL_PREFIX`] verbatim — the two
/// constants are kept independent so the discovery and execute paths
/// can be reviewed in isolation. A drift between them would surface
/// instantly as "every tool call deadline-exceeds".
const MCP_TOOL_PREFIX: &str = "mcp__sage__";

/// Per-call drain window for the `tool.v1.execute.<name>.result` reply.
/// Bounded well under sage's 60 s `TOOL_CALL_DEADLINE` so the bridge
/// times out first and synthesises a clean `isError:true` result rather
/// than letting the supervisor's deadline-sweeper write back a generic
/// "deadline exceeded" string. 50 s leaves comfortable headroom for the
/// stdin write + bus hop on top of a worst-case tool runtime.
const EXECUTE_TIMEOUT_MS: u64 = 50_000;

/// Slice length for the result-drain loop. A single `recv(timeout)`
/// would only pick up the first batch on the subscription; the loop
/// keeps polling in shorter slices until either the matching result
/// arrives or the timeout budget closes.
const EXECUTE_SLICE_MS: u64 = 250;

/// Tool-name charset cap. Same shape as the discovery validator
/// ([`crate::discovery`]) — names must be non-empty, ASCII
/// alphanumeric plus `_`, `.`, `-`. Rejects path separators, unicode
/// bidi overrides, control chars, and the like before they can reach
/// the routed topic. The hostile input here is the inbound
/// `sage.v1.tool.call.*` payload — a sibling capsule could publish a
/// crafted `tool_name` that, if appended verbatim, would forge or
/// shadow a `tool.v1.execute.*` topic.
const MAX_TOOL_NAME_LEN: usize = 128;

/// Inbound payload shape published by `sage::supervisor` on
/// `sage.v1.tool.call.<call_id>`. Only the fields the bridge actually
/// uses are deserialized; everything else (`session_id`,
/// `principal_id`, `tool_use_id`, `via_mcp_control`,
/// `claude_request_id`, ...) is allowed-by-default through serde's
/// "ignore unknown" behaviour. We don't need them here — the call_id
/// is sufficient for response routing back to sage, and sage's
/// `handle_tool_result` reconstitutes the Claude-side correlation from
/// its own `pending_tool_calls` map.
#[derive(Debug, Clone, Deserialize)]
struct InboundCall {
    call_id: String,
    tool_name: String,
    #[serde(default)]
    arguments: Value,
}

/// Handle a `sage.v1.tool.call.<call_id>` dispatch.
///
/// On every accepted call this publishes exactly one
/// `sage.v1.tool.result.<call_id>` envelope. Failure paths
/// (malformed payload, unknown tool, oversize / disallowed-charset
/// name, subscription failure, publish failure, timeout) all
/// short-circuit through [`publish_error`] so the supervisor's
/// `pending_tool_calls` slot is retired by `handle_tool_result`
/// rather than dangling until the 60 s deadline.
///
/// Returning `Ok(())` even on logical failures is intentional — the
/// interceptor return value is consumed by the host as "did the action
/// dispatch cleanly"; the result envelope is what carries the
/// tool-call outcome back to sage.
pub(crate) fn handle_tool_call(payload: Value) -> Result<(), SysError> {
    // Decode the inbound envelope. A serde failure here means the
    // payload didn't even carry a `call_id` — we have no slot to write
    // an error back into, so log and drop. Sage's supervisor will hit
    // the 60 s deadline and synthesise its own timeout.
    let inbound: InboundCall = match serde_json::from_value(payload) {
        Ok(v) => v,
        Err(e) => {
            log::warn(format!(
                "sage-mcp: handle_tool_call: malformed payload (no call_id recoverable): {e}"
            ));
            return Ok(());
        }
    };

    // Strip the `mcp__sage__` prefix. Anything else is not a tool sage
    // routes; emit an error result so the call slot retires cleanly.
    let Some(bare) = inbound.tool_name.strip_prefix(MCP_TOOL_PREFIX) else {
        publish_error(
            &inbound.call_id,
            format!(
                "sage-mcp: tool '{}' is not in the mcp__sage__ namespace",
                inbound.tool_name
            ),
        );
        return Ok(());
    };

    // Validate the bare tool name BEFORE constructing the routed topic.
    // A hostile / buggy publisher could otherwise smuggle topic
    // segments through this. The discovery path applies the same rule
    // to the names it accepts into the MCP tool list, so any name that
    // legitimately reached claude already passed this gate; this is
    // belt-and-suspenders for the call-side.
    if !is_valid_tool_name(bare) {
        publish_error(
            &inbound.call_id,
            format!("sage-mcp: invalid tool name '{bare}'"),
        );
        return Ok(());
    }

    let route_topic = format!("tool.v1.execute.{bare}");
    let result_topic = format!("tool.v1.execute.{bare}.result");

    // Subscribe BEFORE publishing — the responder might publish the
    // reply before we'd otherwise have a chance to subscribe. RAII
    // Drop on `sub` releases the kernel-side resource on every return
    // path, including the timeout branch and the early-error paths
    // below.
    let sub = match ipc::subscribe(&result_topic) {
        Ok(s) => s,
        Err(e) => {
            publish_error(
                &inbound.call_id,
                format!("sage-mcp: failed to subscribe to {result_topic}: {e}"),
            );
            return Ok(());
        }
    };

    // Forward the call. The wire shape matches what the router capsule
    // emits and what every SDK-generated tool handler deserializes via
    // `__AstridToolExecPayload`. `type` is the IpcPayload tag —
    // serde's tagged-enum representation requires it; the handler-side
    // struct-deserialize ignores it.
    let forward = json!({
        "type": "tool_execute_request",
        "call_id": inbound.call_id,
        "tool_name": bare,
        "arguments": inbound.arguments,
    });
    if let Err(e) = ipc::publish_json(&route_topic, &forward) {
        publish_error(
            &inbound.call_id,
            format!("sage-mcp: failed to publish {route_topic}: {e}"),
        );
        return Ok(());
    }

    // Drain results until we see the one matching this `call_id` or
    // the bounded window closes. The subscription is a wildcard-free
    // exact topic so we only see results for THIS tool, but other
    // concurrent callers may collide on the same tool — we filter by
    // call_id to be safe.
    let mut remaining = EXECUTE_TIMEOUT_MS;
    while remaining > 0 {
        let step = remaining.min(EXECUTE_SLICE_MS);
        let poll = match sub.recv(step) {
            Ok(p) => p,
            Err(_) => break,
        };

        for msg in poll.messages {
            // Parse the result envelope. Malformed entries are skipped
            // — a sibling caller's bad publish on the shared topic
            // shouldn't trip our deadline.
            let Ok(value) = serde_json::from_str::<Value>(&msg.payload) else {
                continue;
            };

            // The router and the SDK macro both emit
            // `{ type, call_id, result: { call_id, content, is_error } }`.
            // Match against the OUTER call_id; the inner one is
            // redundant.
            let envelope_call_id = value.get("call_id").and_then(Value::as_str);
            if envelope_call_id != Some(inbound.call_id.as_str()) {
                continue;
            }

            let result_obj = value.get("result");
            let content = result_obj
                .and_then(|r| r.get("content"))
                .cloned()
                .unwrap_or(Value::String(String::new()));
            let is_error = result_obj
                .and_then(|r| r.get("is_error"))
                .and_then(Value::as_bool)
                .unwrap_or(false);

            publish_result(&inbound.call_id, content, is_error);
            return Ok(());
        }

        remaining = remaining.saturating_sub(step);
    }

    // Timeout: synthesise an error result so the call retires cleanly.
    // sage's deadline sweeper would eventually do this on its own
    // schedule, but we do it from here so the bridge owns the
    // request -> response invariant end-to-end and there is exactly
    // one place that decides when to write back. Without this,
    // pending_tool_calls leaks the slot up to ~60 s past claude's
    // own perception of the deadline.
    publish_error(
        &inbound.call_id,
        format!(
            "sage-mcp: tool '{bare}' did not respond within {}s",
            EXECUTE_TIMEOUT_MS / 1_000
        ),
    );
    Ok(())
}

/// Publish a success/passthrough result on `sage.v1.tool.result.<call_id>`.
///
/// Content is wrapped in the MCP-style `[{type:"text", text:<...>}]`
/// array sage's `handle_tool_result` already understands. If the
/// underlying tool returned structured JSON (object / array) we still
/// wrap it as a text block whose body is the serialized JSON; sage's
/// downstream encoder treats `content` opaquely, and claude's MCP side
/// expects an array of blocks anyway.
fn publish_result(call_id: &str, content: Value, is_error: bool) {
    let text = match &content {
        Value::String(s) => s.clone(),
        // Bool / Number / Null / Object / Array — serialize to JSON
        // text so the wire payload stays UTF-8 string-shaped.
        _ => serde_json::to_string(&content)
            .unwrap_or_else(|_| String::from("<unserializable tool result>")),
    };

    let envelope = json!({
        "call_id": call_id,
        "content": [
            { "type": "text", "text": text }
        ],
        "isError": is_error,
    });

    let topic = format!("sage.v1.tool.result.{call_id}");
    if let Err(e) = ipc::publish_json(&topic, &envelope) {
        log::warn(format!("sage-mcp: failed to publish {topic}: {e}"));
    }
}

/// Convenience wrapper: build and publish an `isError:true` result on
/// `sage.v1.tool.result.<call_id>` with `text` as the body.
fn publish_error(call_id: &str, text: String) {
    log::warn(format!("sage-mcp: tool call {call_id} failed: {text}"));
    publish_result(call_id, Value::String(text), true);
}

/// Tool-name charset gate. Same rule as the discovery validator —
/// non-empty, length-capped, ASCII alphanumeric plus `_ . -`. See
/// [`crate::discovery::is_valid_name`] for the source of the rule.
fn is_valid_tool_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_TOOL_NAME_LEN
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_name_charset_rejects_path_traversal() {
        assert!(is_valid_tool_name("read_file"));
        assert!(is_valid_tool_name("fs.read"));
        assert!(is_valid_tool_name("a-b-c"));
        assert!(!is_valid_tool_name(""));
        assert!(!is_valid_tool_name("foo/bar"));
        assert!(!is_valid_tool_name("foo bar"));
        assert!(!is_valid_tool_name("foo\nbar"));
        assert!(!is_valid_tool_name("foo*"));
    }

    #[test]
    fn tool_name_length_capped() {
        let ok = "a".repeat(MAX_TOOL_NAME_LEN);
        let too_long = "a".repeat(MAX_TOOL_NAME_LEN + 1);
        assert!(is_valid_tool_name(&ok));
        assert!(!is_valid_tool_name(&too_long));
    }

    #[test]
    fn inbound_call_decodes_minimum_shape() {
        let v = json!({
            "call_id": "abc",
            "tool_name": "mcp__sage__do",
            "arguments": { "x": 1 }
        });
        let parsed: InboundCall = serde_json::from_value(v).unwrap();
        assert_eq!(parsed.call_id, "abc");
        assert_eq!(parsed.tool_name, "mcp__sage__do");
        assert_eq!(parsed.arguments, json!({ "x": 1 }));
    }

    #[test]
    fn inbound_call_tolerates_extra_fields() {
        let v = json!({
            "call_id": "abc",
            "tool_name": "mcp__sage__do",
            "arguments": null,
            "session_id": "sid",
            "principal_id": "p",
            "tool_use_id": "tu",
            "via_mcp_control": true,
            "claude_request_id": "rid",
        });
        let parsed: InboundCall = serde_json::from_value(v).unwrap();
        assert_eq!(parsed.call_id, "abc");
    }

    #[test]
    fn inbound_call_arguments_defaults_to_null_when_missing() {
        let v = json!({
            "call_id": "abc",
            "tool_name": "mcp__sage__do",
        });
        let parsed: InboundCall = serde_json::from_value(v).unwrap();
        assert_eq!(parsed.arguments, Value::Null);
    }
}
