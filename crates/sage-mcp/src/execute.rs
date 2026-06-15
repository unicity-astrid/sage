//! Tool execute core — `tool.v1.execute.<name>` fan-out and
//! `tool.v1.execute.<name>.result` drain, behind the `astrid.v1.*` broker.
//!
//! Wire contract:
//!
//! * **Outbound request** (`tool.v1.execute.<tool_name>`): the SDK-canonical
//!   `ToolExecuteRequest` shape `{ type:"tool_execute_request", call_id,
//!   tool_name, arguments }`, mirroring what the router capsule emits.
//!   The handler-side macro deserializes via `__AstridToolExecPayload`
//!   which only requires `{ call_id, tool_name, arguments }`, so the
//!   tagged form is accepted unchanged.
//! * **Inbound result** (`tool.v1.execute.<tool_name>.result`): parsed by
//!   [`match_result`], filtered on `call_id`, and returned to the broker
//!   caller as `(content, is_error)` for reshaping into the MCP
//!   `tool.call` reply.
//!
//! The bare tool name is supplied by the broker, which strips the
//! `mcp__sage__` MCP prefix and charset-validates before constructing the
//! routed topic — see [`crate::broker`]. The single execution door is the
//! broker; there is no `sage.v1.tool.call.*` agent-runner leg (it was
//! retired — the registered `astrid mcp serve` MCP server is where the
//! supervised `claude -p` executes tools, so an inline sage dispatch would
//! double-execute).

use astrid_sdk::prelude::*;
use serde_json::{Value, json};

use crate::approval::{self, ApprovalRequired};

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
/// `astrid.v1.request.mcp.tool.call` payload — a crafted `tool_name`
/// that, if appended verbatim, would forge or shadow a
/// `tool.v1.execute.*` topic.
const MAX_TOOL_NAME_LEN: usize = 128;

/// KV key prefix recording an ingress `source_id` the user has consented
/// to trust for state-mutating broker calls. See [`is_ingress_trusted`].
const INGRESS_TRUST_KEY_PREFIX: &str = "mcp.ingress.trust.";

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

/// Broker dispatch: subscribe-before-publish on `tool.v1.execute.<name>`,
/// drain `tool.v1.execute.<name>.result` for the matching `call_id`, and
/// additionally watch `astrid.v1.approval` for the duration of the drain.
///
/// The sole execute path behind the `astrid.v1.request.mcp.tool.call`
/// broker — the wire-shape, the charset/topic-segment hardening, the 50 s
/// bounded drain, and the `call_id` filtering live here. It subscribes
/// (before publishing the execute request) to the fixed `astrid.v1.approval`
/// topic too. If the routed tool blocks on a capability approval, that
/// envelope arrives on this subscription and the dispatch returns
/// [`DispatchOutcome::ApprovalRequired`] so the broker can drive the
/// elicitation/approval bridge ([`crate::approval`]). Otherwise the first
/// matching result wins; a closed window → `Failed`.
///
/// `tool_name` MUST already be charset-validated by the caller (the broker
/// validates via [`is_valid_tool_name`] before calling) — constructing the
/// routed topic from an unchecked name would let a hostile publisher forge
/// `tool.v1.execute.*` segments.
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
/// Used by [`dispatch_with_approval`]'s drain loop. `pub(crate)` so the
/// approval bridge ([`crate::approval`]) reuses the exact same parser when
/// it drains the resumed/denied result after a decision — one definition,
/// no wire-shape drift between the two result legs.
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

/// KV key recording consent to trust an ingress `source_id`. Split out so
/// the prefix is applied in exactly one place and both the read
/// ([`is_ingress_trusted`]) and the write
/// ([`crate::approval::handle_mcp_ingress_respond`]) agree on the key shape.
///
/// Returns `None` for an empty `source_id` — an unattributed caller must
/// never resolve to a routable trust key (which, with an empty suffix,
/// would collapse to the bare prefix and risk a spurious match / write).
pub(crate) fn ingress_trust_key(source_id: &str) -> Option<String> {
    if source_id.is_empty() {
        return None;
    }
    Some(format!("{INGRESS_TRUST_KEY_PREFIX}{source_id}"))
}

/// Confused-deputy guard for state-mutating broker calls.
///
/// `source_id` is the kernel-set UUID of the capsule that originated the
/// inbound IPC message ([`astrid_sdk::runtime::caller`] →
/// `CallerContext::source_id`). It is NOT guest-settable — the kernel
/// stamps it from the publishing capsule's invocation context, so a
/// malicious guest cannot forge it the way it could forge a body field.
/// An ingress is trusted iff the per-(principal, source_id) KV key
/// `mcp.ingress.trust.<source_id>` exists — written ONLY by
/// [`crate::approval::handle_mcp_ingress_respond`] after the user
/// interactively consents via the shim's elicit prompt. There is no
/// operator-maintained allow-list and nothing a capsule computes; trust is
/// recorded purely from a human accept, keyed on the kernel-stamped
/// originating identity.
///
/// KV is scoped per-principal (and per-capsule) by the kernel, so this is
/// naturally per-(principal, source_id) — consent granted under one
/// principal does not leak to another. Fails CLOSED: an empty source_id, a
/// missing key, or a host read error all return `false`.
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
pub(crate) fn is_ingress_trusted(source_id: &str) -> bool {
    let Some(key) = ingress_trust_key(source_id) else {
        return false;
    };
    // Present key (any value) → trusted; missing → not; host error → fail
    // closed.
    matches!(kv::get_bytes_opt(&key), Ok(Some(_)))
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
    fn ingress_trust_key_applies_prefix() {
        let id = "0191f3a2-b4c7-4d8e-9f01-234567890abc";
        assert_eq!(
            ingress_trust_key(id).as_deref(),
            Some("mcp.ingress.trust.0191f3a2-b4c7-4d8e-9f01-234567890abc")
        );
    }

    #[test]
    fn ingress_trust_key_rejects_empty_source() {
        // An unattributed (empty) source_id must never resolve to a routable
        // trust key — otherwise the read would collapse to the bare prefix
        // and a write under an empty caller would grant blanket trust.
        assert_eq!(ingress_trust_key(""), None);
    }

    #[test]
    fn is_ingress_trusted_empty_source_fails_closed() {
        // No host KV call is reached for an empty source_id — it short-circuits
        // to `false` via `ingress_trust_key` returning `None`. (The non-empty
        // path needs a live host and is exercised by integration, not here.)
        assert!(!is_ingress_trusted(""));
    }
}
