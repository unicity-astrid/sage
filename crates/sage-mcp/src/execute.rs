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

use crate::approval::{self, ApprovalRequired};

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

/// Manifest `[env]` key holding the comma-separated allow-set of
/// trusted ingress capsule UUIDs for state-mutating broker calls.
///
/// The operator pins which ingress capsule(s) — today the cli proxy;
/// tomorrow a Telegram / Discord bridge — are permitted to drive
/// `astrid.v1.request.mcp.tool.call`. Read back at call time via
/// [`astrid_sdk::env::var_opt`]. See [`is_trusted_ingress`].
const TRUSTED_INGRESS_ENV_KEY: &str = "trusted_ingress_ids";

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

    // Reuse the shared dispatch/drain core. On any failure path it
    // returns an `Err(message)` which we reshape into the sage-side
    // `isError:true` envelope so the supervisor slot retires cleanly.
    match dispatch_tool(bare, &inbound.call_id, &inbound.arguments) {
        Ok((content, is_error)) => publish_result(&inbound.call_id, content, is_error),
        Err(message) => publish_error(&inbound.call_id, message),
    }
    Ok(())
}

/// Shared execute core: subscribe-before-publish on
/// `tool.v1.execute.<bare>`, drain `tool.v1.execute.<bare>.result` for
/// the matching `call_id`, and return `(content, is_error)`.
///
/// This is the single dispatch path behind BOTH front doors —
/// `sage.v1.tool.call.*` (agent runner) and the
/// `astrid.v1.request.mcp.tool.call` broker — so the wire shape, the
/// charset/topic-segment hardening, the 50 s bounded drain, and the
/// `call_id` filtering live in exactly one place. Callers own response
/// delivery: the agent path reshapes into the sage envelope, the broker
/// path into the MCP `tool.call` reply.
///
/// `bare` MUST already be charset-validated by the caller —
/// constructing the routed topic from an unchecked name would let a
/// hostile publisher forge `tool.v1.execute.*` segments.
///
/// Returns `Err(message)` on every failure (subscribe, publish, drain
/// timeout); the caller renders that as its surface's error shape.
pub(crate) fn dispatch_tool(
    bare: &str,
    call_id: &str,
    arguments: &Value,
) -> Result<(Value, bool), String> {
    let route_topic = format!("tool.v1.execute.{bare}");
    let result_topic = format!("tool.v1.execute.{bare}.result");

    // Subscribe BEFORE publishing — the responder might publish the
    // reply before we'd otherwise have a chance to subscribe. RAII
    // Drop on `sub` releases the kernel-side resource on every return
    // path, including the timeout branch and the early-error paths
    // below.
    let sub = ipc::subscribe(&result_topic)
        .map_err(|e| format!("sage-mcp: failed to subscribe to {result_topic}: {e}"))?;

    // Forward the call. The wire shape matches what the router capsule
    // emits and what every SDK-generated tool handler deserializes via
    // `__AstridToolExecPayload`. `type` is the IpcPayload tag —
    // serde's tagged-enum representation requires it; the handler-side
    // struct-deserialize ignores it.
    let forward = json!({
        "type": "tool_execute_request",
        "call_id": call_id,
        "tool_name": bare,
        "arguments": arguments,
    });
    ipc::publish_json(&route_topic, &forward)
        .map_err(|e| format!("sage-mcp: failed to publish {route_topic}: {e}"))?;

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
            // The router and the SDK macro both emit
            // `{ type, call_id, result: { call_id, content, is_error } }`.
            // `match_result` parses and filters on the OUTER call_id;
            // malformed entries / sibling-caller publishes on the shared
            // topic return `None` and are skipped without tripping our
            // deadline.
            if let Some((content, is_error)) = match_result(&msg.payload, call_id) {
                return Ok((content, is_error));
            }
        }

        remaining = remaining.saturating_sub(step);
    }

    // Timeout: synthesise an error so the call retires cleanly. For the
    // agent path, sage's deadline sweeper would eventually do this on
    // its own schedule, but we do it from here so the bridge owns the
    // request -> response invariant end-to-end and there is exactly one
    // place that decides when to write back. Without this,
    // pending_tool_calls leaks the slot up to ~60 s past claude's own
    // perception of the deadline.
    Err(format!(
        "sage-mcp: tool '{bare}' did not respond within {}s",
        EXECUTE_TIMEOUT_MS / 1_000
    ))
}

/// Outcome of a broker tool dispatch that watches for a mid-call approval.
///
/// The capability-gated tool's host-side `request_approval` syscall
/// publishes an `astrid.v1.approval` envelope and BLOCKS its WASM thread
/// until a decision lands. When [`dispatch_with_approval`] observes that
/// envelope it short-circuits with [`DispatchOutcome::ApprovalRequired`]
/// so the broker can surface the elicit flag in its reply rather than
/// burning the whole drain window on a tool that cannot make progress
/// until a human (via the shim → Claude) decides.
pub(crate) enum DispatchOutcome {
    /// The tool produced a result within the window: `(content, is_error)`.
    Result(Value, bool),
    /// The tool requested capability approval mid-call; the broker must
    /// relay this to the shim and, on the returned choice, publish the
    /// matching `astrid.v1.approval.response.<request_id>` decision.
    ApprovalRequired(ApprovalRequired),
    /// Dispatch failed before producing either (subscribe / publish error,
    /// drain timeout with no approval observed).
    Failed(String),
}

/// Broker dispatch that additionally watches `astrid.v1.approval` for the
/// duration of the result drain.
///
/// Identical wire shape to [`dispatch_tool`] for the request/result hops,
/// but it also subscribes (before publishing the execute request) to the
/// fixed `astrid.v1.approval` topic. If the routed tool blocks on a
/// capability approval, that envelope arrives on this subscription and the
/// dispatch returns [`DispatchOutcome::ApprovalRequired`] so the broker can
/// drive the elicitation/approval bridge ([`crate::approval`]). Otherwise
/// it behaves exactly like [`dispatch_tool`] — first matching result wins,
/// timeout → `Failed`.
///
/// `tool_name` MUST already be charset-validated by the caller (the broker
/// validates via [`is_valid_tool_name`] before calling).
pub(crate) fn dispatch_with_approval(
    tool_name: &str,
    call_id: &str,
    arguments: &Value,
) -> DispatchOutcome {
    if !is_valid_tool_name(tool_name) {
        return DispatchOutcome::Failed(format!("sage-mcp: invalid tool name '{tool_name}'"));
    }

    let route_topic = format!("tool.v1.execute.{tool_name}");
    let result_topic = format!("tool.v1.execute.{tool_name}.result");

    // Subscribe to BOTH the per-tool result topic and the fixed approval
    // topic BEFORE publishing the execute request, so neither a fast
    // result nor a fast approval can race ahead of our subscription. RAII
    // Drop on both handles releases the kernel-side resources on every
    // return path.
    let result_sub = match ipc::subscribe(&result_topic) {
        Ok(s) => s,
        Err(e) => {
            return DispatchOutcome::Failed(format!(
                "sage-mcp: failed to subscribe to {result_topic}: {e}"
            ));
        }
    };
    let approval_sub = match ipc::subscribe(approval::APPROVAL_REQUEST_TOPIC) {
        Ok(s) => s,
        Err(e) => {
            return DispatchOutcome::Failed(format!(
                "sage-mcp: failed to subscribe to {}: {e}",
                approval::APPROVAL_REQUEST_TOPIC
            ));
        }
    };

    let forward = json!({
        "type": "tool_execute_request",
        "call_id": call_id,
        "tool_name": tool_name,
        "arguments": arguments,
    });
    if let Err(e) = ipc::publish_json(&route_topic, &forward) {
        return DispatchOutcome::Failed(format!("sage-mcp: failed to publish {route_topic}: {e}"));
    }

    // Drain both subscriptions in lockstep slices until a matching result
    // arrives, an approval surfaces, or the window closes. Each `recv` is
    // bounded by the slice; we poll the approval sub non-blocking between
    // result slices so an approval published while we're parked on the
    // result `recv` is still seen within one slice.
    let mut remaining = EXECUTE_TIMEOUT_MS;
    while remaining > 0 {
        let step = remaining.min(EXECUTE_SLICE_MS);

        // Check the approval topic first (non-blocking) — an approval means
        // the tool can make no further progress until a decision, so we
        // must not keep blocking on the result topic.
        if let Some(req) = poll_approval(&approval_sub) {
            return DispatchOutcome::ApprovalRequired(req);
        }

        match result_sub.recv(step) {
            Ok(poll) => {
                for msg in poll.messages {
                    if let Some((content, is_error)) = match_result(&msg.payload, call_id) {
                        return DispatchOutcome::Result(content, is_error);
                    }
                }
            }
            Err(_) => {
                // Result `recv` timed out for this slice; loop will re-check
                // the approval sub and continue until the budget closes.
            }
        }

        // One more approval check after the result slice — covers an
        // approval that landed during the blocking `recv` above.
        if let Some(req) = poll_approval(&approval_sub) {
            return DispatchOutcome::ApprovalRequired(req);
        }

        remaining = remaining.saturating_sub(step);
    }

    DispatchOutcome::Failed(format!(
        "sage-mcp: tool '{tool_name}' did not respond within {}s",
        EXECUTE_TIMEOUT_MS / 1_000
    ))
}

/// Non-blocking poll of the approval subscription. Returns the first
/// well-formed [`ApprovalRequired`] envelope seen, or `None`.
///
/// `astrid.v1.approval` is a single global broadcast topic carrying no
/// `call_id` / `tool_name`. Correctness here rests on the engine serialising
/// guest calls per capsule instance behind the store mutex: this dispatch
/// holds that lock for its whole drain, so no other sage-mcp `handle_mcp_call`
/// can be watching the topic concurrently. The only approval we can observe
/// during our window is the one OUR OWN routed tool raised — see the
/// "Concurrency / correlation" note in [`crate::approval`]. The decision is
/// independently routed by `request_id` to the host's per-request topic, so
/// the surfaced approval is always unblocked by exactly the tool that raised
/// it.
///
/// Skips any payload on the shared topic that is not an `approval_required`
/// envelope (other `IpcPayload` variants could in principle share the topic)
/// and any that fails to deserialize.
fn poll_approval(sub: &ipc::Subscription) -> Option<ApprovalRequired> {
    let poll = sub.poll().ok()?;
    for msg in poll.messages {
        let Ok(value) = serde_json::from_str::<Value>(&msg.payload) else {
            continue;
        };
        if !approval::is_approval_required(&value) {
            continue;
        }
        if let Ok(req) = serde_json::from_value::<ApprovalRequired>(value) {
            return Some(req);
        }
    }
    None
}

/// Match a `tool.v1.execute.<name>.result` payload against `call_id`,
/// returning `(content, is_error)` when it is the result for this call.
///
/// Mirrors the inline parse in [`dispatch_tool`]'s drain loop so both the
/// approval-aware and plain paths agree on the result envelope shape.
///
/// `pub(crate)` so the approval bridge ([`crate::approval`]) reuses the exact
/// same parser when it drains the resumed/denied result after a decision —
/// one definition, no wire-shape drift between the two result legs.
pub(crate) fn match_result(payload: &str, call_id: &str) -> Option<(Value, bool)> {
    let value = serde_json::from_str::<Value>(payload).ok()?;
    if value.get("call_id").and_then(Value::as_str) != Some(call_id) {
        return None;
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
    Some((content, is_error))
}

/// Confused-deputy guard for state-mutating broker calls.
///
/// `source_id` is the kernel-set UUID of the capsule that originated the
/// inbound IPC message ([`astrid_sdk::runtime::caller`] →
/// `CallerContext::source_id`). It is NOT guest-settable — the kernel
/// stamps it from the publishing capsule's invocation context, so a
/// malicious guest cannot forge it the way it could forge a body field.
/// We require it to be a member of the operator-pinned allow-set read
/// from the `trusted_ingress_ids` manifest `[env]` key (comma-separated
/// UUIDs; the cli proxy today, extensible to future Telegram / Discord
/// bridges). Whitespace around entries is trimmed; empty entries are
/// ignored. An unset / empty allow-set fails CLOSED — no ingress is
/// trusted until the operator names one.
///
/// ## Why `principal.verified()` is insufficient here
///
/// The broker surface (`astrid.v1.request.mcp.tool.call`) is reached
/// through the cli proxy, which forwards client traffic with a plain
/// [`astrid_sdk::ipc::publish`] (see `capsule-cli`'s ingress path) — NOT
/// `publish_as`. The host therefore attributes the principal as
/// `Verified(<proxy's own invocation principal>)`: the host NEVER emits
/// `Claimed` on this path (that variant only appears behind `publish_as`,
/// which the proxy does not use for tool calls), and the proxy stamps
/// the default verified attribution. So `verified()` returning `Some`
/// proves only "*some* capsule published this in a verified invocation
/// context" — it does NOT identify *which* capsule, and every sibling
/// capsule on the bus would equally satisfy it. The confused-deputy
/// question is "did a TRUSTED ingress forward this?", which only
/// `source_id` (the originating capsule's identity) answers. We keep the
/// kernel-resolved principal for downstream capability checks but gate
/// admission on `source_id`, not trust marker.
pub(crate) fn is_trusted_ingress(source_id: &str) -> bool {
    let Ok(Some(raw)) = env::var_opt(TRUSTED_INGRESS_ENV_KEY) else {
        // Unset or host error: fail closed — no ingress is trusted.
        return false;
    };
    ingress_allowed(&raw, source_id)
}

/// Pure allow-set membership check, split out so the comma-list parsing
/// is unit-testable without the host `env::var_opt` call.
///
/// Splits on `,`, trims each entry, drops empties, and tests exact
/// membership. An allow-set that is empty (or only whitespace / commas)
/// admits nothing — the fail-closed property is preserved here as well
/// as in [`is_trusted_ingress`]'s unset branch.
fn ingress_allowed(raw: &str, source_id: &str) -> bool {
    // An empty source_id (e.g. an empty caller context) must never match
    // an empty / blank allow-set entry — blank entries are filtered, and
    // we additionally refuse to treat an empty source_id as a real
    // identity.
    if source_id.is_empty() {
        return false;
    }
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .any(|allowed| allowed == source_id)
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
///
/// `pub(crate)` so the approval bridge ([`crate::approval`]) applies the
/// exact same gate to the `tool_name` the shim echoes back before it builds
/// the `tool.v1.execute.<name>.result` topic to drain — one definition, no
/// drift between the dispatch and resume legs.
pub(crate) fn is_valid_tool_name(name: &str) -> bool {
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
    fn ingress_allowed_matches_single_uuid() {
        let proxy = "0191f3a2-b4c7-4d8e-9f01-234567890abc";
        assert!(ingress_allowed(proxy, proxy));
    }

    #[test]
    fn ingress_allowed_matches_within_list_and_trims() {
        let raw = " aaaa , 0191f3a2-b4c7-4d8e-9f01-234567890abc ,bbbb ";
        assert!(ingress_allowed(raw, "0191f3a2-b4c7-4d8e-9f01-234567890abc"));
        assert!(ingress_allowed(raw, "aaaa"));
        assert!(ingress_allowed(raw, "bbbb"));
    }

    #[test]
    fn ingress_allowed_rejects_non_member() {
        let raw = "aaaa,bbbb";
        assert!(!ingress_allowed(raw, "cccc"));
    }

    #[test]
    fn ingress_allowed_empty_set_admits_nothing() {
        assert!(!ingress_allowed("", "aaaa"));
        assert!(!ingress_allowed("   ", "aaaa"));
        assert!(!ingress_allowed(",, ,", "aaaa"));
    }

    #[test]
    fn ingress_allowed_empty_source_never_matches() {
        // A blank caller source_id must not slip through, even against a
        // (filtered-away) blank entry.
        assert!(!ingress_allowed("", ""));
        assert!(!ingress_allowed("aaaa,,bbbb", ""));
    }

    #[test]
    fn ingress_allowed_requires_exact_match() {
        let raw = "0191f3a2-b4c7-4d8e-9f01-234567890abc";
        // No prefix / substring matches.
        assert!(!ingress_allowed(raw, "0191f3a2"));
        assert!(!ingress_allowed(
            raw,
            "0191f3a2-b4c7-4d8e-9f01-234567890abcd"
        ));
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
