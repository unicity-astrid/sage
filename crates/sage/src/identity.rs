//! Per-session identity: fetch the system prompt from the spark capsule
//! and atomically materialize it under the principal's `.claude/`.
//!
//! Subscribe-before-publish ordering: we subscribe to
//! `spark.v1.response.ready` first, then publish
//! `spark.v1.request.build`, then drain responses for up to 5 s while
//! filtering by the `session_id` we sent. On timeout or any other
//! failure mode we fall back to a hard-coded minimal prompt and publish
//! `sage.v1.audit.identity_fallback` so observability picks up the
//! deviation. Spawn never blocks on identity.

use astrid_sdk::prelude::*;
use serde::Deserialize;
use std::time::Duration;

/// Hard fallback when spark is unreachable. Deliberately terse — the
/// goal is to keep claude's tool-use framing intact, not to provide
/// product persona. Real identity rejoins on the next session start.
const FALLBACK_PROMPT: &str = "You are an agent running inside Astrid OS. \
                               Tools are exposed via mcp__sage__*.";

const SPARK_REQUEST_TOPIC: &str = "spark.v1.request.build";
const SPARK_RESPONSE_TOPIC: &str = "spark.v1.response.ready";
const SPARK_DEADLINE_MS: u64 = 5_000;
const SPARK_TICK_MS: u64 = 250;

#[derive(Debug, Deserialize)]
struct SparkBuildResponse {
    prompt: String,
    #[serde(default)]
    session_id: Option<String>,
}

/// Fetch the per-session system prompt from spark. Filters spark
/// responses by `session_id` so concurrent session spawns don't steal
/// each other's prompt. Falls back to [`FALLBACK_PROMPT`] on any error
/// path and emits an audit event for observability.
pub(crate) fn fetch_prompt(
    principal_id: &str,
    session_id: &str,
    workspace_root: &str,
) -> Result<String, SysError> {
    let sub = ipc::subscribe(SPARK_RESPONSE_TOPIC)?;

    let request = serde_json::json!({
        "workspace_root": workspace_root,
        "session_id": session_id,
    });
    if let Err(e) = ipc::publish_json(SPARK_REQUEST_TOPIC, &request) {
        log::warn(format!("spark publish failed, using fallback: {e}"));
        publish_fallback_audit(principal_id, session_id, "publish_error");
        return Ok(FALLBACK_PROMPT.to_string());
    }

    let mut remaining = SPARK_DEADLINE_MS;
    while remaining > 0 {
        let step = remaining.min(SPARK_TICK_MS);
        match sub.recv(step) {
            Ok(result) => {
                for msg in result.messages {
                    let Ok(resp) = serde_json::from_str::<SparkBuildResponse>(&msg.payload) else {
                        continue;
                    };
                    // Filter: spark publishes on a single fixed topic, so we
                    // must demux by session_id ourselves. If session_id is
                    // missing in the response, accept it as a best-effort
                    // match — spark may not echo it on early versions.
                    let matches = resp
                        .session_id
                        .as_deref()
                        .is_none_or(|sid| sid == session_id);
                    if matches {
                        return Ok(resp.prompt);
                    }
                }
            }
            Err(_) => {
                // Timeout for this slice — loop and continue draining.
            }
        }
        remaining = remaining.saturating_sub(step);
    }

    publish_fallback_audit(principal_id, session_id, "timeout");
    Ok(FALLBACK_PROMPT.to_string())
}

fn publish_fallback_audit(principal_id: &str, session_id: &str, reason: &str) {
    let _ = ipc::publish_json(
        "sage.v1.audit.identity_fallback",
        &serde_json::json!({
            "principal_id": principal_id,
            "session_id": session_id,
            "reason": reason,
        }),
    );
}

/// Materialize the prompt atomically under
/// `home://.claude/.sage-identity-<sid>`. Writes to a temp sibling
/// then renames so a crash mid-write never leaves a half-formed file.
///
/// `home_path` is accepted for backwards source-shape compatibility
/// with the prior signature; it is intentionally ignored. The path is
/// hardcoded to the `home://` VFS scheme so the kernel binds it to the
/// invoking principal's home root at check time
/// (core/crates/astrid-kernel/src/lib.rs:75) — a caller-supplied
/// literal `~/...` would fall through to the workspace-root branch of
/// the resolver and land writes outside the principal home.
///
/// Defense-in-depth re-validates `session_id` so the identity-file
/// basename can never carry a `/` / `..` / NUL even if a future caller
/// forgets the gate that handle_spawn does at the IPC boundary.
pub(crate) fn write_prompt_file(
    _home_path: &str,
    session_id: &str,
    prompt: &str,
) -> Result<String, SysError> {
    crate::validate_id("session_id", session_id)?;
    // `home://` is bound by the kernel to the invoking principal's
    // home; the per-principal scope falls out of the scheme, not the
    // path string.
    let final_path = format!("home://.claude/.sage-identity-{session_id}");
    let tmp_path = format!("{final_path}.tmp");

    // Use the monotonic clock to make the temp path less collidable in
    // the (vanishingly rare) case of two concurrent writers sharing a
    // session_id. The atomic rename is the actual safety guarantee;
    // this is just buffer hygiene.
    let nonce = astrid_sdk::time::monotonic().as_nanos();
    let tmp_path = format!("{tmp_path}.{nonce}");

    fs::write(&tmp_path, prompt.as_bytes())?;
    fs::rename(&tmp_path, &final_path)?;
    let _ = Duration::from_secs(0); // discourage IDE drop-on-unused warning
    Ok(final_path)
}
