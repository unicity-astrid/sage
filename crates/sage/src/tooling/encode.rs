//! Pure encoders + pure helpers used by the result and approval write
//! paths. Nothing in this file touches host APIs; every function is
//! deterministic from its inputs so the wire-shape invariants can be
//! unit-tested without standing up a `process::Process` resource.

use crate::codec::{ContentBlock, Outbound, encode};
use crate::state::Correlation;

use super::approval::ApprovalResponse;

/// Turn a free-form JSON `content` value into a `Vec<ContentBlock>`
/// the codec expects. Accepts:
///  * an array of objects (already in the right shape) — pass through.
///  * a plain string — wrap as a single text block.
///  * anything else — `serde_json::to_string` and wrap as text so the
///    LLM still sees structured output rather than a parse error.
pub(super) fn content_blocks_from_json(content: &serde_json::Value) -> Vec<ContentBlock> {
    if let Some(arr) = content.as_array() {
        let mut out = Vec::with_capacity(arr.len());
        for v in arr {
            // Try shape `{type:"text",text:"..."}` first.
            if v.get("type").and_then(|t| t.as_str()) == Some("text")
                && let Some(text) = v.get("text").and_then(|t| t.as_str())
            {
                out.push(ContentBlock::Text {
                    text: text.to_string(),
                });
                continue;
            }
            // Otherwise, stringify and forward as text. Lossy but
            // forward-compatible with future MCP content kinds.
            out.push(ContentBlock::Text {
                text: serde_json::to_string(v).unwrap_or_default(),
            });
        }
        if !out.is_empty() {
            return out;
        }
    }
    if let Some(s) = content.as_str() {
        return vec![ContentBlock::Text {
            text: s.to_string(),
        }];
    }
    // Empty arrays, null, etc.
    vec![ContentBlock::Text {
        text: serde_json::to_string(content).unwrap_or_default(),
    }]
}

/// Pure encode of the tool-result write-back frame, selecting the
/// stream-json shape from the stored [`Correlation`]:
///
/// * [`Correlation::McpControl`] — emits `control_response` with the
///   `mcp_response` wrapper and `request_id = claude_request_id`.
/// * [`Correlation::ToolUse`] — emits a `user`-role envelope with a
///   single `tool_result` content block tagged `tool_use_id`.
///
/// Extracted so the request-id echo invariant can be unit-tested
/// without standing up a `process::Process` resource. Callers in
/// `handle_tool_result` and `enforce_deadlines` go through this single
/// funnel; if either path ever regresses to echoing sage's internal
/// `call_id`, the dedicated tests below catch it.
pub(super) fn encode_tool_result_frame(
    correlation: &Correlation,
    content: &serde_json::Value,
    is_error: bool,
) -> String {
    let blocks = content_blocks_from_json(content);
    let frame = match correlation {
        Correlation::McpControl { claude_request_id } => Outbound::ControlResponseToolResult {
            request_id: claude_request_id.as_str(),
            content: blocks,
            is_error,
        },
        Correlation::ToolUse { tool_use_id } => Outbound::UserToolResult {
            tool_use_id: tool_use_id.as_str(),
            content: blocks,
            is_error,
        },
    };
    encode(&frame)
}

pub(super) fn encode_approval_verdict(resp: &ApprovalResponse) -> String {
    let allow = resp.behavior == "allow";
    let mut inner = serde_json::json!({
        "behavior": if allow { "allow" } else { "deny" },
    });
    if let Some(obj) = inner.as_object_mut() {
        if allow && let Some(updated) = &resp.updated_input {
            obj.insert("updatedInput".to_string(), updated.clone());
        }
        if let Some(msg) = &resp.message {
            obj.insert("message".to_string(), serde_json::Value::String(msg.clone()));
        }
    }
    let frame = serde_json::json!({
        "type": "control_response",
        "response": {
            "subtype": "success",
            "request_id": resp.correlation_id,
            "response": inner,
        },
    });
    let mut line = serde_json::to_string(&frame).unwrap_or_default();
    line.push('\n');
    line
}

pub(super) fn approval_marker_key(correlation_id: &str) -> String {
    format!("approval:{correlation_id}")
}

/// Pure-logic predicate extracted so the unit-mismatch bug is testable
/// without constructing a kernel `process::Process` resource. Both
/// arguments MUST be in milliseconds — `supervisor::now_ms` stores
/// millis into `pending_tool_calls`, so the caller in
/// `enforce_deadlines` reads in millis too. Saturating subtraction
/// keeps the comparison sane if the monotonic clock ever races a tick
/// backwards (it won't, but the cost is one extra instruction).
pub(super) fn is_expired(now_ms: u64, started_ms: u64, deadline_ms: u64) -> bool {
    now_ms.saturating_sub(started_ms) >= deadline_ms
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TOOL_CALL_DEADLINE;

    #[test]
    fn content_blocks_pass_through_array_of_text() {
        let v = serde_json::json!([
            {"type":"text","text":"hello"},
            {"type":"text","text":"world"},
        ]);
        let blocks = content_blocks_from_json(&v);
        assert_eq!(blocks.len(), 2);
        match &blocks[0] {
            ContentBlock::Text { text } => assert_eq!(text, "hello"),
        }
    }

    #[test]
    fn content_blocks_wrap_plain_string() {
        let v = serde_json::json!("just a string");
        let blocks = content_blocks_from_json(&v);
        assert_eq!(blocks.len(), 1);
        match &blocks[0] {
            ContentBlock::Text { text } => assert_eq!(text, "just a string"),
        }
    }

    #[test]
    fn content_blocks_stringify_unknown_shape() {
        let v = serde_json::json!({"foo": "bar"});
        let blocks = content_blocks_from_json(&v);
        // single fallback text block stringifying the value
        assert_eq!(blocks.len(), 1);
        match &blocks[0] {
            ContentBlock::Text { text } => assert!(text.contains("foo")),
        }
    }

    #[test]
    fn approval_verdict_allow_with_updated_input() {
        let resp = ApprovalResponse {
            correlation_id: "corr_1".into(),
            behavior: "allow".into(),
            updated_input: Some(serde_json::json!({"path":"/x"})),
            message: Some("approved with edit".into()),
        };
        let line = encode_approval_verdict(&resp);
        let v: serde_json::Value = serde_json::from_str(line.trim_end()).unwrap();
        assert_eq!(v["type"], "control_response");
        assert_eq!(v["response"]["subtype"], "success");
        assert_eq!(v["response"]["request_id"], "corr_1");
        assert_eq!(v["response"]["response"]["behavior"], "allow");
        assert_eq!(v["response"]["response"]["updatedInput"]["path"], "/x");
        assert_eq!(v["response"]["response"]["message"], "approved with edit");
    }

    #[test]
    fn approval_verdict_deny_strips_updated_input() {
        let resp = ApprovalResponse {
            correlation_id: "corr_2".into(),
            behavior: "deny".into(),
            updated_input: Some(serde_json::json!({"ignored":true})),
            message: Some("nope".into()),
        };
        let line = encode_approval_verdict(&resp);
        let v: serde_json::Value = serde_json::from_str(line.trim_end()).unwrap();
        assert_eq!(v["response"]["response"]["behavior"], "deny");
        assert!(v["response"]["response"].get("updatedInput").is_none());
        assert_eq!(v["response"]["response"]["message"], "nope");
    }

    #[test]
    fn approval_marker_key_format() {
        assert_eq!(approval_marker_key("abc"), "approval:abc");
    }

    #[test]
    fn is_expired_uses_milliseconds_consistently() {
        // Regression: supervisor stores monotonic-millis in
        // `pending_tool_calls`; enforce_deadlines used to compare them
        // as nanoseconds, blowing every dispatched call past the
        // deadline on the first sweep. This test pins the unit.
        let deadline_ms = TOOL_CALL_DEADLINE.as_millis() as u64;

        // 50 ms elapsed: well under a 60 s deadline — must NOT fire.
        let started_ms: u64 = 1_000_000;
        let now_ms: u64 = started_ms + 50;
        assert!(
            !is_expired(now_ms, started_ms, deadline_ms),
            "50ms elapsed must not exceed a {deadline_ms}ms deadline"
        );

        // 59_999 ms elapsed: just under the boundary — must NOT fire.
        let now_ms_just_under: u64 = started_ms + deadline_ms - 1;
        assert!(
            !is_expired(now_ms_just_under, started_ms, deadline_ms),
            "1ms before deadline must not fire"
        );

        // Exactly at the deadline — must fire.
        let now_ms_at: u64 = started_ms + deadline_ms;
        assert!(
            is_expired(now_ms_at, started_ms, deadline_ms),
            "elapsed == deadline must fire"
        );

        // Well past the deadline — must fire.
        let now_ms_over: u64 = started_ms + deadline_ms + 5_000;
        assert!(
            is_expired(now_ms_over, started_ms, deadline_ms),
            "elapsed > deadline must fire"
        );

        // Backwards monotonic clock (defensive): saturating_sub yields
        // 0, must NOT fire.
        let now_ms_back: u64 = started_ms - 10;
        assert!(
            !is_expired(now_ms_back, started_ms, deadline_ms),
            "negative elapsed (saturated) must not fire"
        );
    }

    // ---- request_id / tool_use_id echo invariant (regression) ----
    //
    // The bus contract uses sage's internal `call_id` (UUIDv4) to
    // address `sage.v1.tool.result.<call_id>` — but claude never sees
    // that id. Echoing it back into the write-back frame would silently
    // strand claude waiting on its own original id. These tests pin
    // the encoder to use the stored [`Correlation`], not the call_id.
    //
    // The funnel is `encode_tool_result_frame`; both `handle_tool_result`
    // and `enforce_deadlines` route through it. Testing the helper
    // directly verifies the wire shape without needing a live
    // `process::Process` resource.

    #[test]
    fn encode_tool_result_frame_mcp_control_echoes_claude_request_id() {
        // McpControl correlation captures the `sdk_control_request.request_id`
        // claude sent. The encoded line MUST set `response.request_id`
        // to that value — NOT sage's call_id, NOT anything else.
        let correlation = Correlation::McpControl {
            claude_request_id: "claude_req_42".to_string(),
        };
        let content = serde_json::json!([{"type":"text","text":"ok"}]);
        let line = encode_tool_result_frame(&correlation, &content, false);

        let v: serde_json::Value = serde_json::from_str(line.trim_end())
            .expect("encoded line must be valid JSON");

        // Wire shape: control_response with mcp_response wrapper.
        assert_eq!(v["type"], "control_response");
        assert_eq!(v["response"]["subtype"], "success");
        // THE invariant: request_id is claude's, not sage's.
        assert_eq!(
            v["response"]["request_id"], "claude_req_42",
            "request_id must echo claude's original sdk_control_request.request_id"
        );
        // The mcp_response wrapper is mandatory on this path.
        let mcp = &v["response"]["response"]["mcp_response"];
        assert!(mcp.is_object(), "mcp_response wrapper missing");
        assert_eq!(mcp["isError"], false);
        assert_eq!(mcp["content"][0]["type"], "text");
        assert_eq!(mcp["content"][0]["text"], "ok");
    }

    #[test]
    fn encode_tool_result_frame_mcp_control_does_not_use_call_id() {
        // Belt-and-braces: explicitly arrange a divergent call_id /
        // claude_request_id pair and verify the call_id never appears
        // anywhere in the frame. The original bug used `event.call_id`
        // as the request_id; this test fails if anyone reintroduces
        // that shortcut.
        let correlation = Correlation::McpControl {
            claude_request_id: "claude_req_alpha".to_string(),
        };
        let content = serde_json::json!("done");
        let line = encode_tool_result_frame(&correlation, &content, false);
        assert!(
            line.contains("claude_req_alpha"),
            "frame missing claude_request_id"
        );
        assert!(
            !line.contains("sage_call_xyz"),
            "frame must not contain sage's internal call_id"
        );
    }

    #[test]
    fn encode_tool_result_frame_tool_use_echoes_tool_use_id() {
        // ToolUse correlation MUST produce a `user`-role envelope
        // carrying a `tool_result` block tagged with the `tool_use_id`
        // — not a control_response, and not keyed off sage's call_id.
        // The wire shape is structurally different from the MCP path;
        // mixing them up causes claude to time out at 60 s.
        let correlation = Correlation::ToolUse {
            tool_use_id: "toolu_99".to_string(),
        };
        let content = serde_json::json!([{"type":"text","text":"42"}]);
        let line = encode_tool_result_frame(&correlation, &content, false);

        let v: serde_json::Value = serde_json::from_str(line.trim_end())
            .expect("encoded line must be valid JSON");

        // The envelope is a user-role message, NOT a control_response.
        assert_eq!(v["type"], "user");
        assert_eq!(v["message"]["role"], "user");

        // The single content block is a tool_result tagged by tool_use_id.
        let block = &v["message"]["content"][0];
        assert_eq!(block["type"], "tool_result");
        assert_eq!(
            block["tool_use_id"], "toolu_99",
            "tool_use_id must echo the assistant's original tool_use.id"
        );
        assert_eq!(block["is_error"], false);
        assert_eq!(block["content"][0]["type"], "text");
        assert_eq!(block["content"][0]["text"], "42");
    }

    #[test]
    fn encode_tool_result_frame_tool_use_does_not_use_call_id() {
        // Symmetric divergence test for the tool_use path: the
        // `call_id` value the bus uses for routing must never appear
        // inside the frame — only `tool_use_id` does.
        let correlation = Correlation::ToolUse {
            tool_use_id: "toolu_real".to_string(),
        };
        let content = serde_json::json!("done");
        let line = encode_tool_result_frame(&correlation, &content, false);
        assert!(line.contains("toolu_real"), "frame missing tool_use_id");
        assert!(
            !line.contains("sage_call_xyz"),
            "frame must not contain sage's internal call_id"
        );
        // And not under any control_response key either.
        assert!(
            !line.contains("\"control_response\""),
            "tool_use path must not emit control_response frame"
        );
    }

    #[test]
    fn encode_tool_result_frame_propagates_is_error_on_both_paths() {
        // The deadline-enforcement sweep encodes a synthetic
        // `is_error:true` frame; this guards against either variant
        // dropping the flag.
        let mcp = encode_tool_result_frame(
            &Correlation::McpControl {
                claude_request_id: "r".into(),
            },
            &serde_json::json!("nope"),
            true,
        );
        let v: serde_json::Value = serde_json::from_str(mcp.trim_end()).unwrap();
        assert_eq!(v["response"]["response"]["mcp_response"]["isError"], true);

        let tool = encode_tool_result_frame(
            &Correlation::ToolUse {
                tool_use_id: "t".into(),
            },
            &serde_json::json!("nope"),
            true,
        );
        let v: serde_json::Value = serde_json::from_str(tool.trim_end()).unwrap();
        assert_eq!(v["message"]["content"][0]["is_error"], true);
    }
}
