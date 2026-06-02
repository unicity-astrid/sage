//! Tool descriptor discovery and the `sage.v1.tools.list` publish path.
//!
//! Two entry points feed the cache:
//!
//! * [`describe_tools`] — on-demand fan-out (subscribe-before-publish
//!   ordering, mirrors the registry capsule). Replaces the cached
//!   snapshot wholesale so descriptors from departed capsules don't
//!   linger. Cache-hit short-circuits the fan-out when the snapshot is
//!   fresher than [`super::cache::CACHE_TTL_MS`].
//! * [`collect_tool_descriptors`] — event-driven; merges every
//!   broadcast `tool.v1.response.describe.*` into the cache via CAS.
//!
//! Both publish `sage.v1.tools.list` with MCP-shaped descriptors whose
//! names are prefixed `mcp__sage__<original>` so the agent runner can
//! pass them straight to Claude via `--allowed-tools mcp__sage__*`.

use astrid_sdk::prelude::*;

use crate::cache::{self, McpToolDescriptor};

/// Fan-out topic — every tool-providing capsule subscribes to this and
/// replies on its own `tool.v1.response.describe.<source_id>`.
const DESCRIBE_REQUEST_TOPIC: &str = "tool.v1.request.describe";
/// Wildcard pattern for the per-source response topics.
const DESCRIBE_RESPONSE_PATTERN: &str = "tool.v1.response.describe.*";
/// Topic on which the agent runner consumes the assembled MCP tool list.
const TOOLS_LIST_TOPIC: &str = "sage.v1.tools.list";

/// MCP tool name prefix sage exposes to Claude. The `--allowed-tools
/// mcp__sage__*` flag on the agent subprocess matches against this.
const MCP_TOOL_PREFIX: &str = "mcp__sage__";

/// Total drain window for the describe fan-out (matches the registry
/// capsule's settle window).
const DISCOVERY_TIMEOUT_MS: u64 = 500;
/// Slice size for the drain loop. A single `recv(timeout)` would only
/// pick up the first batch; the loop keeps polling in shorter slices
/// until the budget closes.
const DISCOVERY_SLICE_MS: u64 = 100;

/// Per-tool name length cap. MCP+claude accept long names but a
/// hostile capsule could publish kilobyte names — reject anything
/// past this before it reaches the cache.
const MAX_TOOL_NAME_LEN: usize = 128;
/// Per-tool description cap.
const MAX_DESCRIPTION_LEN: usize = 4_096;
/// Per-tool serialized `inputSchema` cap (JSON bytes). Bigger than a
/// realistic tool schema needs but small enough to bound the cache
/// regardless of provider behaviour.
const MAX_INPUT_SCHEMA_BYTES: usize = 16_384;
/// Per-tool serialized `capabilities` cap.
const MAX_CAPABILITIES_BYTES: usize = 2_048;
/// Hard cap on tools accepted from a single `describe` response /
/// broadcast. Caches further cap the merged state via
/// `cache::MAX_CACHED_TOOLS`.
const MAX_TOOLS_PER_RESPONSE: usize = 256;

/// Handle `sage.v1.tools.describe`.
///
/// Cache-fresh path: republish the cached list and return. Cache-miss /
/// stale path: subscribe-before-publish fan-out, dedupe by name
/// (last-write-wins), replace the cache, publish the new list.
pub(crate) fn describe_tools() {
    let snapshot = collect_snapshot();
    publish_tools_list(&snapshot);
}

/// Assemble the current tool-descriptor snapshot, running the
/// describe-collect fan-out only when the cache is stale.
///
/// Shared by the agent-facing `describe_tools` publish path and the
/// broker-facing `astrid.v1.request.mcp.tools.list` handler so the two
/// front doors run the exact same discovery + cache logic — no
/// duplicated fan-out, dedupe, or TTL handling.
pub(crate) fn collect_snapshot() -> Vec<McpToolDescriptor> {
    let cached = cache::load();
    let now = wall_ms();
    if cached.is_fresh(now) {
        return cached.as_vec();
    }

    let descriptors = discover();
    cache::replace(descriptors).as_vec()
}

/// Convert internal descriptors to the standard MCP `tools/list`
/// descriptor shape (`name`, `description`, `inputSchema`, plus optional
/// `title`/`capabilities`) for the broker reply body.
///
/// Unlike [`publish_tools_list`], names are emitted RAW — the broker is
/// a generic MCP front door, not Claude's `mcp__sage__*` namespace, so
/// it must not stamp the agent-runner prefix onto the descriptors a
/// third-party MCP client consumes.
pub(crate) fn to_mcp_descriptors(descriptors: &[McpToolDescriptor]) -> Vec<serde_json::Value> {
    descriptors.iter().map(mcp_descriptor).collect()
}

/// Shape one internal descriptor into an MCP tool-descriptor object.
/// `prefix` is prepended to the name (empty for the broker surface,
/// `mcp__sage__` for the agent-runner surface).
fn mcp_descriptor_with_prefix(d: &McpToolDescriptor, prefix: &str) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    obj.insert(
        "name".to_string(),
        serde_json::Value::String(format!("{prefix}{}", d.name)),
    );
    if let Some(title) = &d.title {
        obj.insert(
            "title".to_string(),
            serde_json::Value::String(title.clone()),
        );
    }
    obj.insert(
        "description".to_string(),
        serde_json::Value::String(d.description.clone()),
    );
    obj.insert("inputSchema".to_string(), d.input_schema.clone());
    if let Some(caps) = &d.capabilities {
        obj.insert("capabilities".to_string(), caps.clone());
    }
    serde_json::Value::Object(obj)
}

/// Broker-surface MCP descriptor: raw (unprefixed) name.
fn mcp_descriptor(d: &McpToolDescriptor) -> serde_json::Value {
    mcp_descriptor_with_prefix(d, "")
}

/// Handle an inbound `tool.v1.response.describe.*` broadcast.
///
/// The kernel routes every matching message to this action. We
/// extract descriptors, merge them into the cache via CAS, and
/// re-publish the assembled list so downstream consumers see fresh
/// additions immediately.
pub(crate) fn collect_tool_descriptors(payload: serde_json::Value) {
    let descriptors = parse_describe_response(&payload);
    if descriptors.is_empty() {
        return;
    }

    let merged = cache::upsert(descriptors).as_vec();
    publish_tools_list(&merged);
}

/// Subscribe-before-publish fan-out. Mirrors the registry capsule
/// pattern: open the subscription, fire the empty `{}` request, drain
/// up to `DISCOVERY_TIMEOUT_MS` in `DISCOVERY_SLICE_MS` slices.
fn discover() -> Vec<McpToolDescriptor> {
    let sub = match ipc::subscribe(DESCRIBE_RESPONSE_PATTERN) {
        Ok(s) => s,
        Err(e) => {
            log::warn(format!(
                "sage-mcp: failed to subscribe to {DESCRIBE_RESPONSE_PATTERN}: {e}"
            ));
            return Vec::new();
        }
    };

    if let Err(e) = ipc::publish(DESCRIBE_REQUEST_TOPIC, "{}") {
        log::warn(format!(
            "sage-mcp: failed to publish {DESCRIBE_REQUEST_TOPIC}: {e}"
        ));
        return Vec::new();
    }

    let mut acc: Vec<McpToolDescriptor> = Vec::new();
    let mut remaining = DISCOVERY_TIMEOUT_MS;
    loop {
        let step = remaining.min(DISCOVERY_SLICE_MS);
        match sub.recv(step) {
            Ok(result) => {
                for msg in &result.messages {
                    let Ok(value) = serde_json::from_str::<serde_json::Value>(&msg.payload) else {
                        continue;
                    };
                    acc.extend(parse_describe_response(&value));
                }
            }
            Err(_) => break,
        }
        remaining = remaining.saturating_sub(step);
        if remaining == 0 {
            break;
        }
    }

    // Dedupe by name, last-write-wins. We iterate in reverse so the
    // final retain preserves the last occurrence.
    acc.reverse();
    let mut seen = std::collections::HashSet::new();
    acc.retain(|d| seen.insert(d.name.clone()));
    acc.reverse();
    acc
}

/// Extract descriptors from a `tool.v1.response.describe.*` payload.
///
/// Honours both the direct envelope (`{ "tools": [...] }`, emitted by
/// the SDK `tool_describe` macro arm) and the wrapped Custom envelope
/// (`{ "data": { "tools": [...] } }`). Each entry is deserialized
/// independently — malformed entries are skipped without aborting the
/// whole response. Untrusted-input gates:
///
/// * names that are empty or don't match the `^[A-Za-z0-9_.-]+$`
///   charset are dropped (prevents path-style names, unicode bidi
///   overrides, control chars from reaching the wire);
/// * descriptors with oversized name / description / schema /
///   capabilities are dropped — a hostile broadcaster cannot DoS the
///   cache by inflating individual entries;
/// * the per-response array is hard-capped at
///   [`MAX_TOOLS_PER_RESPONSE`].
fn parse_describe_response(value: &serde_json::Value) -> Vec<McpToolDescriptor> {
    let tools = value
        .get("tools")
        .or_else(|| value.get("data").and_then(|d| d.get("tools")))
        .and_then(|t| t.as_array());

    let Some(tools) = tools else {
        return Vec::new();
    };

    let take = tools.len().min(MAX_TOOLS_PER_RESPONSE);
    let mut out = Vec::with_capacity(take);
    for raw in tools.iter().take(take) {
        let Ok(desc) = serde_json::from_value::<McpToolDescriptor>(remap_input_schema(raw.clone()))
        else {
            continue;
        };
        if !is_valid_descriptor(&desc) {
            continue;
        }
        out.push(desc);
    }
    out
}

/// Allowed tool-name charset. Matches `^[A-Za-z0-9_.-]+$` — same shape
/// MCP uses for tool identifiers. Anything else (path separators,
/// whitespace, unicode bidi, control chars) is rejected.
fn is_valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_TOOL_NAME_LEN
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

/// Full descriptor validation: charset on the name, byte-size caps on
/// description / schema / capabilities. Discard anything that violates;
/// the broadcaster has no claim on cache state.
fn is_valid_descriptor(desc: &McpToolDescriptor) -> bool {
    if !is_valid_name(&desc.name) {
        return false;
    }
    if desc.description.len() > MAX_DESCRIPTION_LEN {
        return false;
    }
    if let Some(t) = &desc.title
        && t.len() > MAX_DESCRIPTION_LEN
    {
        return false;
    }
    if json_byte_len(&desc.input_schema) > MAX_INPUT_SCHEMA_BYTES {
        return false;
    }
    if let Some(caps) = &desc.capabilities
        && json_byte_len(caps) > MAX_CAPABILITIES_BYTES
    {
        return false;
    }
    true
}

/// Serialized-byte length of a JSON value. Used for hostile-payload
/// size checks. `serde_json::to_vec` on an in-memory `Value` should
/// not fail in practice; treat a serializer error as "oversized" so
/// the guard remains fail-closed.
fn json_byte_len(value: &serde_json::Value) -> usize {
    serde_json::to_vec(value).map_or(usize::MAX, |v| v.len())
}

/// SDK-generated tool schemas use the field name `input_schema` while
/// MCP uses `inputSchema`. Accept both at parse time by renaming on
/// the fly so downstream code can rely on the MCP shape.
fn remap_input_schema(mut value: serde_json::Value) -> serde_json::Value {
    if let Some(obj) = value.as_object_mut()
        && !obj.contains_key("inputSchema")
        && let Some(schema) = obj.remove("input_schema")
    {
        obj.insert("inputSchema".to_string(), schema);
    }
    value
}

/// Publish the assembled MCP tool list. Names are prefixed
/// `mcp__sage__<original>` so the agent runner can pass them through
/// `--allowed-tools mcp__sage__*`. The cache stores raw names; the
/// prefix is purely a wire concern for the agent-facing topic.
fn publish_tools_list(descriptors: &[McpToolDescriptor]) {
    let mcp_shaped: Vec<serde_json::Value> = descriptors
        .iter()
        .map(|d| mcp_descriptor_with_prefix(d, MCP_TOOL_PREFIX))
        .collect();

    if let Err(e) = ipc::publish_json(TOOLS_LIST_TOPIC, &mcp_shaped) {
        log::warn(format!(
            "sage-mcp: failed to publish {TOOLS_LIST_TOPIC}: {e}"
        ));
    }
}

/// Wall-clock millis used for cache TTL bookkeeping.
fn wall_ms() -> u64 {
    time::now()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}
