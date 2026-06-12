#![deny(unsafe_code)]
#![deny(clippy::all)]
#![deny(unreachable_pub)]
#![warn(missing_docs)]

//! sage-mcp — MCP server bridging Astrid capsule tools to Claude.
//!
//! Claude (running as a `claude -p` subprocess supervised by the
//! `sage` capsule) is restricted to MCP-only tools via
//! `--allowedTools 'mcp__sage__*'`. This capsule owns the MCP-facing
//! contract: it discovers the tools other capsules export via the
//! `tool.v1.request.describe` fan-out, shapes them into MCP tool
//! descriptors, caches them, and serves the assembled list on
//! `sage.v1.tools.list`.
//!
//! Tool DISCOVERY is shared; tool EXECUTION flows through ONE door.
//!
//! ### Discovery (cache-feeding, used by the broker)
//!
//! * `sage.v1.tools.describe` -> [`SageMcp::describe_tools`]:
//!   on-demand fan-out + cache replace + republish.
//! * `tool.v1.response.describe.*` -> [`SageMcp::collect_tool_descriptors`]:
//!   event-driven cache merge.
//!
//! ### Broker surface (`astrid.v1.*`) — the live execution door
//!
//! The front door for an MCP client behind a shim/proxy. `astrid mcp
//! serve` (the rmcp stdio shim, unicity-astrid/astrid#880) is that
//! client: the supervised `claude -p` subprocess registers it via
//! `--mcp-config` and calls `mcp__sage__*` tools against it DIRECTLY over
//! MCP. The shim only ever touches the sanitized `astrid.v1.*` surface
//! and NEVER sees `tool.v1.*`.
//!
//! There is no longer a `sage.v1.tool.call.*` agent-runner execution leg:
//! the sage supervisor used to dispatch tool calls inline on that topic,
//! but that double-executed every tool once the registered MCP server was
//! in play (claude executes against the broker AND sage would re-execute
//! on the bus). The inline leg was retired; the broker is the sole
//! execution path.
//!
//! * `astrid.v1.request.mcp.tools.list` -> [`SageMcp::handle_mcp_list`]:
//!   describe-collect snapshot, RAW MCP descriptors, reply on
//!   `astrid.v1.response.<req_id>` with
//!   `{ kind:"tools.list", req_id, tools:[...] }`.
//! * `astrid.v1.request.mcp.tool.call` -> [`SageMcp::handle_mcp_call`]:
//!   execute-dispatch, reply on `astrid.v1.response.<req_id>` with
//!   `{ kind:"tool.call", req_id, content:[...], isError:bool }`. When the
//!   routed tool blocks on a capability approval, the reply instead carries
//!   an `approval_required` flag (see below).
//! * `astrid.v1.request.mcp.approval.respond` ->
//!   [`SageMcp::handle_mcp_approval`]: the shim's elicited approval choice,
//!   mapped onto `astrid.v1.approval.response.<id>` to unblock the tool.
//!
//! ### Elicitation/approval bridge (`astrid.v1.approval.*`)
//!
//! Capability-gated tools call the host `request_approval` syscall, which
//! publishes `astrid.v1.approval` and BLOCKS the tool until a decision
//! lands. The broker cannot call the host `astrid:elicit` syscall (it is
//! install/upgrade-gated), so it relays the bus envelopes: `handle_mcp_call`
//! watches `astrid.v1.approval` during dispatch and surfaces an
//! `approval_required` flag (carrying the `tool_name` + `call_id`) in its
//! reply; the shim elicits the choice from Claude and forwards it on
//! `astrid.v1.request.mcp.approval.respond`; `handle_mcp_approval` maps the
//! choice onto `astrid.v1.approval.response.<id>` to resume (or deny) the
//! tool, then DRAINS the resumed/denied result and delivers it to the shim
//! as a terminal `tool.call` reply — the original dispatch could not keep a
//! result subscription alive across the synchronous interceptor return, so
//! ownership of result delivery moves to the approval handler. The engine
//! serialises guest calls per capsule instance, so at most one sage-mcp
//! dispatch watches the global approval topic at a time and the observed
//! approval is always its own tool's — see the concurrency note in
//! [`approval`]. Only constrained approval verbs are relayed — never a
//! secret.
//!
//! The `req_id` is mirrored into the reply body because the proxy
//! delivers the payload only (no source topic). The egress topic is
//! single-segment-per-id by construction — see [`broker`].

mod approval;
mod broker;
mod cache;
mod discovery;
mod execute;
mod hook_gate;
mod policy;

use astrid_sdk::prelude::*;

/// sage-mcp bridge.
#[derive(Default)]
pub struct SageMcp;

#[capsule]
impl SageMcp {
    /// `sage.v1.tools.describe` — assemble (or replay) the MCP tool
    /// list and publish it on `sage.v1.tools.list`.
    ///
    /// The payload is intentionally ignored; the request is a bare
    /// "give me the current surface" signal. We accept a JSON value to
    /// stay forward-compatible with future request fields (e.g. a
    /// `force_refresh` flag) without changing the wire shape.
    #[astrid::interceptor("describe_tools")]
    pub fn describe_tools(&self, _payload: serde_json::Value) -> Result<(), SysError> {
        discovery::describe_tools();
        Ok(())
    }

    /// `tool.v1.response.describe.*` — event-driven cache update.
    ///
    /// Every tool-providing capsule broadcasts its descriptor set on
    /// load and on relevant config changes. We merge each broadcast
    /// into the cache via CAS so the next `describe_tools` call (and
    /// the agent runner's tool-list view) reflects the live surface
    /// without a full re-discovery.
    #[astrid::interceptor("collect_tool_descriptors")]
    pub fn collect_tool_descriptors(&self, payload: serde_json::Value) -> Result<(), SysError> {
        discovery::collect_tool_descriptors(payload);
        Ok(())
    }

    /// `astrid.v1.request.mcp.tools.list` — broker front door.
    ///
    /// Runs the same describe-collect snapshot as [`Self::describe_tools`],
    /// converts it to RAW MCP tool descriptors (no `mcp__sage__`
    /// prefix), and replies on `astrid.v1.response.<req_id>` with
    /// `{ kind:"tools.list", req_id, tools:[...] }`. The `req_id` is read
    /// from the body — the proxy delivers payload only. See [`broker`].
    #[astrid::interceptor("handle_mcp_list")]
    pub fn handle_mcp_list(&self, payload: serde_json::Value) -> Result<(), SysError> {
        broker::handle_mcp_list(payload)
    }

    /// `astrid.v1.request.mcp.tool.call` — broker front door.
    ///
    /// Runs the shared execute-dispatch core ([`execute::dispatch_with_approval`])
    /// — charset/topic-segment hardening, 50 s bounded drain, `call_id`
    /// filtering — and replies on `astrid.v1.response.<req_id>` with
    /// `{ kind:"tool.call", req_id, content:[...], isError:bool }`. Every
    /// failure path reshapes into `isError:true` so the proxy never
    /// hangs.
    ///
    /// State-mutating, so it is confused-deputy gated: the inbound
    /// message's kernel-set `source_id` must be in the operator-pinned
    /// `trusted_ingress_ids` allow-set before any dispatch. See
    /// [`broker`].
    #[astrid::interceptor("handle_mcp_call")]
    pub fn handle_mcp_call(&self, payload: serde_json::Value) -> Result<(), SysError> {
        broker::handle_mcp_call(payload)
    }

    /// `astrid.v1.request.mcp.approval.respond` — broker approval bridge.
    ///
    /// The shim elicited an approval choice from Claude (in response to an
    /// `approval_required` flag a prior [`Self::handle_mcp_call`] reply
    /// carried) and forwards it here as
    /// `{ req_id, request_id, decision, tool_name, call_id }`. Maps the
    /// choice onto `astrid.v1.approval.response.<request_id>` to unblock the
    /// host `request_approval` the gated tool is parked on, then drains the
    /// resumed (approve) or `isError` (deny) tool result and delivers it to
    /// the shim on `astrid.v1.response.<req_id>` as a terminal `tool.call`
    /// reply — completing the round-trip the original dispatch could not (its
    /// result subscription died when the interceptor returned).
    ///
    /// State-mutating (it can grant a capability), so it is confused-deputy
    /// gated on the kernel-set `source_id` exactly like
    /// [`Self::handle_mcp_call`]. Unknown / untrusted / malformed inputs
    /// publish a `deny` so the parked tool retires cleanly (and, when
    /// routable, deliver the resulting `isError` reply to the shim). Only
    /// constrained approval verbs are relayed — never a secret. See
    /// [`approval`].
    #[astrid::interceptor("handle_mcp_approval")]
    pub fn handle_mcp_approval(&self, payload: serde_json::Value) -> Result<(), SysError> {
        approval::handle_mcp_approval(payload)
    }

    /// `hook.v1.event.before_tool_call` — native-tool verdict responder.
    ///
    /// sage-mcp participates in the hook-bridge `ToolCallBefore` merge: it
    /// evaluates the native tool named in the fan-out payload against the
    /// invoking principal's policy and replies `{ skip }` on the
    /// correlation-keyed reply topic. `skip:true` blocks the call (deny-wins
    /// merge). This is the SECOND plane of the same PDP the broker enforces
    /// in-process for `mcp__sage__*` tools — one operator rule set, two
    /// transports. A fan-out with no `correlation_id` is observe-only and
    /// gets no reply. See [`hook_gate`].
    #[astrid::interceptor("handle_before_tool_call")]
    pub fn handle_before_tool_call(&self, payload: serde_json::Value) -> Result<(), SysError> {
        hook_gate::handle_before_tool_call(payload)
    }
}
