//! Broker front door — the sanitized `astrid.v1.*` MCP surface.
//!
//! This is sage-mcp's SECOND front door, sitting over the SAME
//! discovery ([`crate::discovery`]) and execute ([`crate::execute`])
//! internals as the agent-runner path. Where the agent path serves the
//! `mcp__sage__*` namespace Claude consumes via `--allowed-tools`, the
//! broker serves a generic, third-party MCP client through a
//! shim/proxy.
//!
//! ## Topics
//!
//! * **inbound** `astrid.v1.request.mcp.tools.list`  -> [`handle_mcp_list`]
//! * **inbound** `astrid.v1.request.mcp.tool.call`   -> [`handle_mcp_call`]
//! * **outbound** `astrid.v1.response.<req_id>`        (both handlers)
//!
//! ## Wire contract
//!
//! The proxy/shim delivers the PAYLOAD only — the source topic is not
//! visible to the handler, and the proxy that bridges the external MCP
//! client subscribes to `astrid.v1.response.*` and forwards the body
//! verbatim. So:
//!
//! * `req_id` is mirrored into the request body and echoed into the
//!   reply body (the proxy correlates on the body, not the topic);
//! * the egress topic `astrid.v1.response.<req_id>` MUST be a single
//!   segment after the prefix. The kernel's `topic_matches` is
//!   strict-arity (a 4-segment `astrid.v1.response.*` subscription
//!   never matches a 5-segment topic), so a `req_id` carrying a `.`
//!   would be silently dropped. We reject any `req_id` that is not a
//!   single clean segment before publishing.
//!
//! ## Trust boundary
//!
//! The shim NEVER sees `tool.v1.*` — it only ever touches the
//! sanitized `astrid.v1.*` surface. All `tool.v1.*` fan-out lives
//! behind [`crate::execute::dispatch_with_approval`], which charset-gates
//! the tool name before it can reach a routed topic. The list reply
//! carries RAW MCP descriptors (no `mcp__sage__` prefix) because the
//! broker is a standard MCP server, not the agent runner.
//!
//! ## Confused-deputy gate (state-mutating calls)
//!
//! [`handle_mcp_call`] is state-mutating and externally reachable, so it
//! additionally requires the inbound message's kernel-set `source_id`
//! (the originating capsule UUID, via [`astrid_sdk::runtime::caller`]) to
//! be in the operator-pinned trusted-ingress allow-set
//! (`trusted_ingress_ids` `[env]` key). This stops a non-ingress capsule
//! from puppeting sage-mcp into executing tools on a principal's behalf.
//! [`handle_mcp_list`] is read-only (it returns the public tool surface
//! the proxy already publishes) and is NOT gated as strictly. See
//! [`crate::execute::is_trusted_ingress`] for why the trust marker
//! (`verified()`) cannot substitute for the `source_id` identity check.

use astrid_sdk::prelude::*;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{discovery, execute};

/// Egress topic prefix. The reply lands on `<prefix><req_id>`; with a
/// single-segment `req_id` that is exactly 4 segments, which the
/// proxy's `astrid.v1.response.*` subscription matches.
const RESPONSE_PREFIX: &str = "astrid.v1.response.";

/// `req_id` length cap. A correlation id is a UUID-ish token; anything
/// longer is rejected before it can be stamped into an egress topic.
const MAX_REQ_ID_LEN: usize = 128;

/// Inbound `astrid.v1.request.mcp.tools.list` payload.
///
/// `req_id` is the proxy's correlation token, mirrored into the body
/// because the handler cannot see the source topic. Any other fields
/// are ignored (forward-compat with future pagination cursors etc.).
#[derive(Debug, Deserialize)]
struct ListRequest {
    req_id: String,
}

/// Inbound `astrid.v1.request.mcp.tool.call` payload.
///
/// Standard MCP `tools/call` shape (`name` + `arguments`) plus the
/// proxy `req_id`. `name` is a RAW MCP tool name — the broker does not
/// use the `mcp__sage__` prefix.
#[derive(Debug, Deserialize)]
struct CallRequest {
    req_id: String,
    name: String,
    #[serde(default)]
    arguments: Value,
}

/// Handle `astrid.v1.request.mcp.tools.list`.
///
/// Runs the shared describe-collect snapshot, converts to MCP
/// descriptors, and replies on `astrid.v1.response.<req_id>` with
/// `{ kind:"tools.list", req_id, tools:[...] }`. Exactly one reply per
/// accepted request.
pub(crate) fn handle_mcp_list(payload: Value) -> Result<(), SysError> {
    let req: ListRequest = match serde_json::from_value(payload) {
        Ok(v) => v,
        Err(e) => {
            // No recoverable req_id — there is no channel to reply on,
            // so the proxy will time out its own request. Log and drop.
            log::warn(format!(
                "sage-mcp: broker tools.list: malformed payload (no req_id): {e}"
            ));
            return Ok(());
        }
    };

    let Some(reply_topic) = reply_topic(&req.req_id) else {
        log::warn(format!(
            "sage-mcp: broker tools.list: rejecting unroutable req_id '{}'",
            req.req_id
        ));
        return Ok(());
    };

    let snapshot = discovery::collect_snapshot();
    let tools = discovery::to_mcp_descriptors(&snapshot);

    let reply = json!({
        "kind": "tools.list",
        "req_id": req.req_id,
        "tools": tools,
    });
    publish_reply(&reply_topic, &reply);
    Ok(())
}

/// Handle `astrid.v1.request.mcp.tool.call`.
///
/// Runs the shared execute-dispatch and replies on
/// `astrid.v1.response.<req_id>` with
/// `{ kind:"tool.call", req_id, content:[...], isError:bool }`. Every
/// failure path (unknown/invalid name, subscribe/publish error, drain
/// timeout) reshapes into an `isError:true` reply so the proxy never
/// hangs. Exactly one reply per accepted request.
pub(crate) fn handle_mcp_call(payload: Value) -> Result<(), SysError> {
    let req: CallRequest = match serde_json::from_value(payload) {
        Ok(v) => v,
        Err(e) => {
            log::warn(format!(
                "sage-mcp: broker tool.call: malformed payload (no req_id): {e}"
            ));
            return Ok(());
        }
    };

    let Some(reply_topic) = reply_topic(&req.req_id) else {
        log::warn(format!(
            "sage-mcp: broker tool.call: rejecting unroutable req_id '{}'",
            req.req_id
        ));
        return Ok(());
    };

    // Confused-deputy gate. `astrid.v1.request.mcp.tool.call` is
    // state-mutating and externally reachable through the cli proxy, so
    // before we dispatch we require the message's kernel-set
    // `source_id` (the originating capsule UUID, NOT a guest-settable
    // body field) to be in the operator-pinned trusted-ingress
    // allow-set. A capsule the operator has NOT designated as an ingress
    // bridge must not be able to puppet sage-mcp into executing tools on
    // a principal's behalf. Failure paths reply `isError:true` (never
    // dispatch) so the proxy still gets exactly one reply and never
    // hangs. See [`execute::is_trusted_ingress`] for why `verified()` is
    // insufficient on this path.
    let source_id = match runtime::caller() {
        Ok(ctx) => ctx.source_id,
        Err(e) => {
            // No caller context — cannot attribute the ingress. Fail
            // closed rather than dispatch an unattributed mutation.
            log::warn(format!(
                "sage-mcp: broker tool.call: no caller context, rejecting req_id '{}': {e}",
                req.req_id
            ));
            let reply = json!({
                "kind": "tool.call",
                "req_id": req.req_id,
                "content": mcp_content(Value::String(
                    "sage-mcp: caller context unavailable; tool call rejected".into(),
                )),
                "isError": true,
            });
            publish_reply(&reply_topic, &reply);
            return Ok(());
        }
    };
    if !execute::is_trusted_ingress(&source_id) {
        log::warn(format!(
            "sage-mcp: broker tool.call: rejecting untrusted ingress source_id '{source_id}' \
             for req_id '{}'",
            req.req_id
        ));
        let reply = json!({
            "kind": "tool.call",
            "req_id": req.req_id,
            "content": mcp_content(Value::String(
                "sage-mcp: ingress not in trusted allow-set; tool call rejected".into(),
            )),
            "isError": true,
        });
        publish_reply(&reply_topic, &reply);
        return Ok(());
    }

    // Argument-level policy gate — the binding PDP. Evaluated in-process
    // at THIS chokepoint (the one capsule-space point holding parsed
    // `(name, arguments)` before fan-out), so a supervised Claude cannot
    // route around it the way it could strip a settings-tier PreToolUse
    // hook. DENY → reply `isError` + never dispatch. The gate only ever
    // NARROWS: no matching rule, no policy configured, or a policy-load
    // failure all return `Allow`, leaving the host's execution-time
    // capability enforcement as the live boundary — degrade-to-PEP, never
    // "anything goes". The reason surfaced back is the operator's static
    // rule id, never a reflected argument. See [`crate::policy`].
    if let crate::policy::Decision::Deny { reason } =
        crate::policy::evaluate(&crate::policy::load_rules(), &req.name, &req.arguments)
    {
        log::info(format!(
            "sage-mcp: policy denied tool '{}' (req_id '{}'): {reason}",
            req.name, req.req_id
        ));
        let _ = ipc::publish_json(
            "sage.v1.audit.policy_deny",
            &serde_json::json!({ "tool": req.name, "rule": reason }),
        );
        let reply = json!({
            "kind": "tool.call",
            "req_id": req.req_id,
            "content": mcp_content(Value::String(format!(
                "sage-mcp: tool call denied by policy (rule: {reason})"
            ))),
            "isError": true,
        });
        publish_reply(&reply_topic, &reply);
        return Ok(());
    }

    // The execute core wants a `call_id` for result correlation on the
    // shared `tool.v1.execute.<bare>.result` topic. The broker's
    // `req_id` doubles as that correlation token — it is already
    // single-segment / charset-clean (validated by `reply_topic`), and
    // it never leaves the `astrid.v1.*` surface beyond the inner
    // `tool.v1.execute` request body.
    //
    // `dispatch_with_approval` additionally watches `astrid.v1.approval`
    // for the drain window: if the routed tool blocks on a capability
    // approval, we surface an `approval-required` flag in this reply so the
    // shim can elicit the choice from Claude (the broker can't call the
    // host `astrid:elicit` syscall — it is install/upgrade-gated — so it
    // relays the bus envelope instead). The shim then drives
    // `astrid.v1.request.mcp.approval.respond` -> [`approval::handle_mcp_approval`],
    // which maps the choice onto `astrid.v1.approval.response.<id>` to
    // unblock the tool. See [`crate::approval`].
    let reply = match execute::dispatch_with_approval(&req.name, &req.req_id, &req.arguments) {
        execute::DispatchOutcome::Result(content, is_error) => json!({
            "kind": "tool.call",
            "req_id": req.req_id,
            "content": mcp_content(content),
            "isError": is_error,
        }),
        execute::DispatchOutcome::ApprovalRequired(required) => json!({
            "kind": "tool.call",
            "req_id": req.req_id,
            // No tool result yet — the tool is parked on the approval. The
            // shim MUST elicit the choice and respond on
            // `astrid.v1.request.mcp.approval.respond` (echoing back the
            // `tool_name` + `call_id` the flag carries) before a result can
            // be produced. `content` is empty and `isError` false: this is
            // a pending state, not a failure. The terminal result is
            // delivered by `approval::handle_mcp_approval` once the decision
            // lands — see [`crate::approval`]. `req.req_id` doubles as the
            // dispatch `call_id` (it is the result-correlation token).
            "content": mcp_content(Value::String(String::new())),
            "isError": false,
            "approval_required": required.to_reply_flag(&req.name, &req.req_id),
        }),
        execute::DispatchOutcome::Failed(message) => json!({
            "kind": "tool.call",
            "req_id": req.req_id,
            "content": mcp_content(Value::String(message)),
            "isError": true,
        }),
    };
    publish_reply(&reply_topic, &reply);
    Ok(())
}

/// Build the single-segment egress topic for `req_id`, or `None` if the
/// id cannot form a clean single segment.
///
/// Rejects empty, oversized, and any id carrying a `.` (which would
/// turn the 4-segment response topic into a 5-segment one the proxy's
/// `astrid.v1.response.*` subscription can't match) or whitespace /
/// control / wildcard bytes (which would forge or shadow topics). Same
/// charset family the tool-name gate uses, so the surface is uniform.
///
/// `pub(crate)` so the approval bridge ([`crate::approval`]) reuses the
/// exact same egress-topic gate when acking the shim — one definition,
/// no drift.
pub(crate) fn reply_topic(req_id: &str) -> Option<String> {
    if req_id.is_empty() || req_id.len() > MAX_REQ_ID_LEN {
        return None;
    }
    let clean = req_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'));
    if !clean {
        return None;
    }
    Some(format!("{RESPONSE_PREFIX}{req_id}"))
}

/// Wrap a tool result into the MCP `content` block array sage already
/// emits elsewhere: `[{ "type":"text", "text":<string> }]`. Structured
/// (non-string) results are serialized to JSON text so the wire stays
/// UTF-8 string-shaped and the proxy needs no schema knowledge.
///
/// `pub(crate)` so the approval bridge ([`crate::approval`]) shapes the
/// resumed/denied terminal `tool.call` reply with the exact same content
/// encoding the non-parked path uses — no drift between the two reply legs.
pub(crate) fn mcp_content(content: Value) -> Value {
    let text = match &content {
        Value::String(s) => s.clone(),
        _ => serde_json::to_string(&content)
            .unwrap_or_else(|_| String::from("<unserializable tool result>")),
    };
    json!([{ "type": "text", "text": text }])
}

/// Publish the broker reply, logging (not erroring) on host failure —
/// the proxy times out on its side if delivery fails.
fn publish_reply(topic: &str, reply: &Value) {
    if let Err(e) = ipc::publish_json(topic, reply) {
        log::warn(format!("sage-mcp: broker failed to publish {topic}: {e}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reply_topic_accepts_uuid_simple() {
        let id = "0191f3a2b4c74d8e9f01234567890abc";
        assert_eq!(
            reply_topic(id).as_deref(),
            Some("astrid.v1.response.0191f3a2b4c74d8e9f01234567890abc")
        );
    }

    #[test]
    fn reply_topic_rejects_dotted_req_id() {
        // A `.` would make the egress topic 5 segments — the proxy's
        // 4-segment `astrid.v1.response.*` subscription would never
        // match it, so the reply would be silently dropped.
        assert!(reply_topic("a.b").is_none());
    }

    #[test]
    fn reply_topic_rejects_topic_smuggling() {
        assert!(reply_topic("").is_none());
        assert!(reply_topic("a b").is_none());
        assert!(reply_topic("a*b").is_none());
        assert!(reply_topic("a\nb").is_none());
        assert!(reply_topic("a/b").is_none());
        let too_long = "a".repeat(MAX_REQ_ID_LEN + 1);
        assert!(reply_topic(&too_long).is_none());
    }

    #[test]
    fn reply_topic_accepts_hyphenated_uuid() {
        let id = "0191f3a2-b4c7-4d8e-9f01-234567890abc";
        assert!(reply_topic(id).is_some());
    }

    #[test]
    fn mcp_content_wraps_string_verbatim() {
        let blocks = mcp_content(Value::String("hello".into()));
        assert_eq!(blocks, json!([{ "type": "text", "text": "hello" }]));
    }

    #[test]
    fn mcp_content_serializes_structured_result() {
        let blocks = mcp_content(json!({ "ok": true }));
        assert_eq!(blocks, json!([{ "type": "text", "text": "{\"ok\":true}" }]));
    }

    #[test]
    fn list_request_requires_req_id() {
        assert!(serde_json::from_value::<ListRequest>(json!({})).is_err());
        let ok: ListRequest = serde_json::from_value(json!({ "req_id": "x" })).unwrap();
        assert_eq!(ok.req_id, "x");
    }

    #[test]
    fn call_request_defaults_arguments() {
        let req: CallRequest =
            serde_json::from_value(json!({ "req_id": "x", "name": "fs.read" })).unwrap();
        assert_eq!(req.req_id, "x");
        assert_eq!(req.name, "fs.read");
        assert_eq!(req.arguments, Value::Null);
    }
}
