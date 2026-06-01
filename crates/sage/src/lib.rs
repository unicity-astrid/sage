#![deny(unsafe_code)]
#![deny(clippy::all)]
#![deny(unreachable_pub)]
#![warn(missing_docs)]

//! Sage — Claude headless agent runner on Astrid OS.
//!
//! Supervises one `claude -p --input-format stream-json --output-format
//! stream-json` subprocess per principal session. Streams the user's
//! turns in, parses Claude's stream-json events out, dispatches tool-
//! call events to the bus where `sage-mcp` picks them up, feeds tool-
//! call results back in. The subprocess is long-lived so Anthropic-
//! side prompt caching stays warm turn-to-turn.
//!
//! Bills against the user's Anthropic Agent SDK credit (per Anthropic's
//! June 15, 2026 billing model). For per-turn API completion mode that
//! bypasses the SDK credit, see the sibling crate `sage-completion`.
//!
//! # S6 wiring
//!
//! S6 lands the three core lifecycle paths:
//!
//! * `handle_spawn` — provision a `claude -p` subprocess, fetch identity
//!   from spark with fallback, write the system-prompt file, spawn with
//!   the hardened argv set, persist the [`state::SessionRecord`].
//! * `handle_send` — encode a user-turn stream-json envelope and write
//!   it to the session's stdin in one call.
//! * `#[astrid::run]` — supervisor tick at [`TICK_PERIOD`] cadence
//!   driving [`supervisor::tick`]: drain stdout, decode stream-json,
//!   publish `sage.v1.event.<sid>.*` for text / init / tool_use /
//!   result, detect crash / buffer-overflow / capsule-reload, emit
//!   `sage.v1.tool.call.<call_id>` for each tool dispatch.
//!
//! `handle_tool_result` write-back, 60 s deadline enforcement, and
//! approval routing live in [`tooling`] (shipped in S7's slice).

use astrid_sdk::prelude::*;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use uuid::Uuid;

// `codec` exposes wire scaffolding for stream-json frames. The
// `Outbound::ControlResponseError` variant is reserved for the
// protocol-failure write-back path; the active code uses
// `ControlResponseToolResult` with `is_error: true` for tool-side
// failures and reserves `ControlResponseError` for SDK-protocol-level
// errors handled by the supervisor in a follow-up slice.
#[allow(dead_code)]
mod codec;
mod identity;
mod shutdown;
mod spawn;
mod state;
mod supervisor;
mod tooling;

use codec::{Outbound, encode};
use state::{
    MAX_SESSIONS_PER_PRINCIPAL, RuntimeSession, SessionRecord, Sessions, save_record,
};

/// 60 s per-tool-call deadline. Matches the sage-mcp dispatch timeout
/// so `claude -p` never sits on a tool call that's been abandoned on
/// the bus. Re-exported here so [`tooling::enforce_deadlines`] can
/// reference it without a circular module dependency.
pub(crate) const TOOL_CALL_DEADLINE: Duration = Duration::from_secs(60);

/// Graceful-shutdown grace before falling back to SIGKILL.
/// [`shutdown::stop_session`] reads this.
pub(crate) const GRACEFUL_SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

/// KV prefix for the "respawn this principal's sessions on next tick"
/// marker dropped by identity-refresh teardown. Scanned in the
/// supervisor loop by [`shutdown::respawn_pending`].
pub(crate) const PENDING_RESTART_PREFIX: &str = "sage.pending_restart";

/// Maximum accepted length for `principal_id` or `session_id` read off
/// the IPC bus. Mirrors `sage-install::layout::sanitize_principal_id`.
const MAX_ID_LEN: usize = 128;

/// Validate an untrusted id (principal_id or session_id) from an IPC
/// payload before it flows into path construction, KV keys, or topic
/// formatting.
///
/// Rejects:
///   * empty / pure-`.` / pure-`..` reserved segments,
///   * anything longer than [`MAX_ID_LEN`],
///   * any character outside `[A-Za-z0-9._-]` (catches `/`, `\`, NUL,
///     quotes, whitespace, and topic delimiters all in one rule).
///
/// Mirrors the alphabet enforced by
/// `sage-install::layout::sanitize_principal_id` so a value that
/// successfully provisions a principal home is also a valid spawn
/// input. `field` is the logical name (used only in error text).
pub(crate) fn validate_id(field: &str, id: &str) -> Result<(), SysError> {
    if id.is_empty() {
        return Err(SysError::ApiError(format!("{field} must not be empty")));
    }
    if id == "." || id == ".." {
        return Err(SysError::ApiError(format!(
            "{field} '{id}' is a reserved path segment"
        )));
    }
    if id.len() > MAX_ID_LEN {
        return Err(SysError::ApiError(format!(
            "{field} exceeds {MAX_ID_LEN} characters"
        )));
    }
    for c in id.chars() {
        let ok = c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-';
        if !ok {
            return Err(SysError::ApiError(format!(
                "{field} contains disallowed character '{c}' (allowed: [A-Za-z0-9._-])"
            )));
        }
    }
    Ok(())
}

/// Sage agent runner — capsule singleton.
///
/// Holds the live [`Sessions`] registry directly. The `#[capsule]`
/// macro stores a single `OnceLock<Sage>` and gives every handler the
/// same `&self` for the duration of one capsule incarnation. That
/// satisfies the requirement to share `Process` resource handles
/// across IPC dispatches (KV-backed state would not — `Process` is a
/// component-model `resource` and is not serializable). Durable
/// metadata still rides in KV per-session via [`state::SessionRecord`];
/// the runtime map is rebuilt on reload by the supervisor's first-tick
/// recovery sweep.
///
/// `tool_call_meta` is a sidecar index keyed by the supervisor-minted
/// `call_id` (UUIDv4). The supervisor publishes
/// `sage.v1.audit.tool_call{call_id,tool_name,session_id}` on every
/// dispatch; the run-loop drains that subscription into this map so
/// [`tooling::enforce_deadlines`] can surface the real `tool_name` in
/// `sage.v1.event.<sid>.tool_timeout` instead of `"unknown"`. Entries
/// are removed on tool-result write-back or on deadline expiry; the
/// map is hard-capped at [`tooling::MAX_TOOL_CALL_META`] entries to bound
/// memory under upstream-bug pathological cases.
#[derive(Default)]
pub struct Sage {
    pub(crate) sessions: Sessions,
    pub(crate) tool_call_meta: Mutex<HashMap<String, ToolCallMeta>>,
}

/// Sidecar metadata per outstanding tool call. Mirrors the supervisor's
/// `sage.v1.audit.tool_call` payload (the subset we need).
#[derive(Debug, Clone)]
pub(crate) struct ToolCallMeta {
    /// Session that dispatched the call. Captured for future scope-
    /// limited cleanup paths (e.g. evicting outstanding tool calls
    /// when a session exits). Currently only `tool_name` is consumed
    /// by `tooling::enforce_deadlines`; the field is preserved so the
    /// audit-ingest contract doesn't lose information.
    #[allow(dead_code)]
    pub session_id: String,
    /// Tool name lifted from the supervisor's audit publish.
    pub tool_name: String,
}

/// `sage.v1.request.spawn` payload.
#[derive(Debug, Deserialize)]
pub struct SpawnRequest {
    /// Astrid principal this session belongs to.
    pub principal_id: String,
    /// Optional caller-provided session id — generated UUIDv4 if absent.
    #[serde(default)]
    pub session_id: Option<String>,
    /// Optional first turn to write after spawn completes.
    #[serde(default)]
    pub initial_message: Option<String>,
}

/// `sage.v1.request.send.<sid>` payload — `session_id` is duplicated
/// in-body so dispatch handlers don't have to parse the topic suffix
/// themselves.
#[derive(Debug, Deserialize)]
pub struct SendRequest {
    /// Target session id.
    pub session_id: String,
    /// Plain-text user turn body.
    pub text: String,
}

#[capsule]
impl Sage {
    /// Spawn a new `claude -p` subprocess for a principal session.
    #[astrid::interceptor("handle_spawn")]
    pub fn handle_spawn(&self, req: SpawnRequest) -> Result<(), SysError> {
        // Untrusted input gate. principal_id flows into KV keys and
        // topic strings (the fs path is `home://...`, kernel-scoped per
        // invocation — principal_id no longer reaches the path);
        // session_id flows into the identity file basename and per-
        // session topics. Reject anything outside `[A-Za-z0-9._-]`
        // before the value escapes into formatted strings.
        validate_id("principal_id", &req.principal_id)?;
        if let Some(sid) = &req.session_id {
            validate_id("session_id", sid)?;
        }

        // Per-principal session cap.
        let in_use = self.sessions.count_for_principal(&req.principal_id)?;
        if in_use >= MAX_SESSIONS_PER_PRINCIPAL {
            let _ = ipc::publish_json(
                "sage.v1.event.session_rejected",
                &serde_json::json!({
                    "principal_id": req.principal_id,
                    "reason": "principal_limit",
                    "active": in_use,
                    "limit": MAX_SESSIONS_PER_PRINCIPAL,
                }),
            );
            return Ok(());
        }

        let session_id = req.session_id.unwrap_or_else(|| Uuid::new_v4().to_string());
        let principal_id = req.principal_id;

        // Block until sage-install confirms the principal's `.claude/`
        // is provisioned. sage-install is the source of truth: it
        // performs its own idempotency check (returns `already_installed:
        // true` on a fast-reply cache-hit) and publishes
        // `success: false` with an `error` field on hard failure. On a
        // hard failure we surface the error to the spawn-error topic and
        // abort the spawn — proceeding would just spawn `claude -p`
        // against an unprovisioned principal home.
        //
        // On success sage-install returns the host-resolved absolute
        // home path (it canonicalises `home://` before publishing the
        // InstallComplete envelope). Threading that path through the
        // spawn keeps a single canonicalize host call per principal-
        // install and guarantees the claude subprocess sees a real
        // filesystem path in `HOME` / cwd rather than the `home://`
        // VFS scheme string — which would silently break per-principal
        // isolation if the subprocess fell back to ambient `$HOME`.
        let resolved_home = match ensure_install(&principal_id) {
            EnsureInstall::Ok(home) => home,
            EnsureInstall::Failed(reason) => {
                publish_spawn_error(
                    &session_id,
                    &principal_id,
                    &format!("install_failed: {reason}"),
                );
                return Ok(());
            }
        };

        // Read API key from the capsule's runtime config. The kernel
        // elicited `api_key` from `[env]` (type = "secret") at install
        // time and persists it via the SecretStore; here it surfaces as
        // a plain `env::var` read — the host injects the cleartext into
        // the wasm guest's config, never logged.
        let api_key = env::var("api_key").unwrap_or_default();
        if api_key.is_empty() {
            publish_spawn_error(&session_id, &principal_id, "api_key_missing");
            return Ok(());
        }

        // Fetch identity prompt from spark with a 5 s budget. Falls
        // back to a hard-coded minimal prompt + audit on timeout.
        //
        // `home_path` is the absolute filesystem path returned by
        // sage-install — NOT the `home://` VFS scheme. Identity-file
        // writes still go through the VFS scheme (see
        // `identity::write_prompt_file`), but the path threaded into
        // the subprocess `HOME` / cwd must be a real OS path the host
        // spawn primitive can interpret.
        let home_path = resolved_home;
        let prompt = identity::fetch_prompt(&principal_id, &session_id, &home_path)
            .unwrap_or_else(|e| {
                log::warn(format!("sage: identity fetch errored: {e}, using fallback"));
                "You are an agent running inside Astrid OS. Tools are exposed via mcp__sage__*."
                    .into()
            });
        let identity_path = match identity::write_prompt_file(&home_path, &session_id, &prompt) {
            Ok(p) => p,
            Err(e) => {
                publish_spawn_error(
                    &session_id,
                    &principal_id,
                    &format!("identity_write_failed: {e}"),
                );
                return Ok(());
            }
        };

        let started_at_ms = astrid_sdk::time::now()
            .ok()
            .and_then(|t| {
                t.duration_since(std::time::UNIX_EPOCH)
                    .ok()
                    .map(|d| d.as_millis())
            })
            .and_then(|m| u64::try_from(m).ok())
            .unwrap_or(0);

        let spawned = match spawn::spawn_claude(&spawn::SpawnInputs {
            principal_id: &principal_id,
            session_id: &session_id,
            home_path: &home_path,
            identity_path: &identity_path,
            api_key: &api_key,
        }) {
            Ok(s) => s,
            Err(e) => {
                publish_spawn_error(&session_id, &principal_id, &format!("spawn_failed: {e}"));
                return Ok(());
            }
        };

        let record = SessionRecord {
            principal_id: principal_id.clone(),
            session_id: session_id.clone(),
            identity_path,
            started_at_ms,
            os_pid: spawned.os_pid,
        };
        save_record(&record)?;

        self.sessions.with(|map| {
            map.insert(
                session_id.clone(),
                RuntimeSession {
                    record: record.clone(),
                    process: Arc::new(spawned.process),
                    codec: codec::LineDecoder::new(),
                    pending_tool_calls: Default::default(),
                    partial_tool_inputs: Default::default(),
                },
            );
        })?;

        let _ = ipc::publish_json(
            "sage.v1.audit.spawn",
            &serde_json::json!({
                "principal_id": principal_id,
                "session_id": session_id,
                "pid": spawned.os_pid,
                "flags_hash": spawned.flags_hash,
            }),
        );
        let _ = ipc::publish_json(
            &format!("sage.v1.event.{session_id}.spawned"),
            &serde_json::json!({
                "principal_id": principal_id,
                "session_id": session_id,
                "pid": spawned.os_pid,
            }),
        );

        // Optional first turn.
        if let Some(text) = req.initial_message
            && !text.is_empty()
        {
            send_user_turn(&self.sessions, &session_id, &text)?;
        }

        Ok(())
    }

    /// Send a user turn into an existing session's stdin.
    #[astrid::interceptor("handle_send")]
    pub fn handle_send(&self, req: SendRequest) -> Result<(), SysError> {
        // Validate before the id reaches any format!/IPC topic.
        validate_id("session_id", &req.session_id)?;
        send_user_turn(&self.sessions, &req.session_id, &req.text)
    }

    /// Tool-result write-back. Topic `sage.v1.tool.result.<call_id>`.
    /// Delegates to [`tooling::handle_tool_result`] which encodes a
    /// stream-json `control_response` (with the mandatory `mcp_response`
    /// wrapper) and pushes it to the matching session's stdin. After a
    /// successful match, drops the matching `tool_call_meta` sidecar
    /// entry so the index doesn't grow unbounded.
    #[astrid::interceptor("handle_tool_result")]
    pub fn handle_tool_result(&self, payload: serde_json::Value) -> Result<(), SysError> {
        tooling::handle_tool_result(&self.sessions, &self.tool_call_meta, payload)
    }

    /// Supervisor run loop. Each tick (~50 ms):
    /// 1. Drains every active session's stdout via [`supervisor::tick`].
    /// 2. Drains `sage.v1.request.stop.*` and gracefully terminates
    ///    matching sessions ([`shutdown::stop_session`]).
    /// 3. Drains `tool.v1.execute.save_identity.result` for identity-
    ///    refresh teardown ([`shutdown::handle_identity_refresh`]).
    /// 4. Drains `sage.v1.audit.tool_call` into the sidecar
    ///    `tool_call_meta` index so [`tooling::enforce_deadlines`] can
    ///    surface real tool names on timeout events.
    /// 5. Drains `approval.v1.request` and registers each as a pending
    ///    approval against the matching session
    ///    ([`tooling::register_pending_approval_from_request`]).
    /// 6. Drains `approval.v1.response.*` and forwards verdicts.
    /// 7. Sweeps `pending_tool_calls` for 60 s deadlines.
    /// 8. Sweeps the `sage.pending_restart.*` KV markers and respawns
    ///    each torn-down session with a fresh identity prompt
    ///    ([`shutdown::respawn_pending`]).
    #[astrid::run]
    fn run(&self) -> Result<(), SysError> {
        let stop_sub = ipc::subscribe("sage.v1.request.stop.*")?;
        let identity_sub = ipc::subscribe("tool.v1.execute.save_identity.result")?;
        let approval_response_sub = ipc::subscribe("approval.v1.response.*")?;
        // S6's supervisor publishes the request on a fixed topic with
        // the request_id in the payload; we self-subscribe so the
        // approval-routing path is end-to-end functional without
        // touching supervisor.rs.
        let approval_request_sub = ipc::subscribe("approval.v1.request")?;
        // Sidecar feed: supervisor's audit publish carries call_id +
        // tool_name + session_id. Drained into self.tool_call_meta.
        let tool_audit_sub = ipc::subscribe("sage.v1.audit.tool_call")?;
        let _ = runtime::signal_ready();
        log::info("sage: supervisor loop starting");

        loop {
            if let Err(e) = supervisor::tick(&self.sessions) {
                log::warn(format!("sage: supervisor tick errored: {e}"));
            }

            if let Ok(poll) = stop_sub.poll() {
                for msg in poll.messages {
                    let sid = topic_tail(&msg.topic)
                        .map(str::to_string)
                        .unwrap_or_default();
                    if sid.is_empty() {
                        continue;
                    }
                    // The topic tail is attacker-controlled (anyone with
                    // ipc::publish to `sage.v1.request.stop.*` can pick
                    // it). Validate before it reaches log lines or
                    // downstream `format!()`s.
                    if validate_id("session_id", &sid).is_err() {
                        log::warn("sage: stop request with invalid session_id; dropping");
                        continue;
                    }
                    if let Err(e) = shutdown::stop_session(&self.sessions, &sid, "requested") {
                        log::warn(format!("sage: stop({sid}) failed: {e:?}"));
                    }
                }
            }

            if let Ok(poll) = identity_sub.poll() {
                for msg in poll.messages {
                    if let Err(e) = shutdown::handle_identity_refresh(&self.sessions, &msg) {
                        log::warn(format!("sage: identity-refresh failed: {e:?}"));
                    }
                }
            }

            // Audit-tool-call sidecar update. Must happen BEFORE
            // enforce_deadlines so the first sweep already has names
            // for any call_id that just landed.
            if let Ok(poll) = tool_audit_sub.poll()
                && let Err(e) = tooling::record_tool_call_meta(&self.tool_call_meta, poll.messages)
            {
                log::warn(format!("sage: tool_call audit ingest failed: {e:?}"));
            }

            // Approval request register — wires the sentinel into the
            // session's partial_tool_inputs so the matching
            // approval.v1.response can be routed back to stdin.
            if let Ok(poll) = approval_request_sub.poll()
                && let Err(e) = tooling::register_pending_approval_from_request(
                    &self.sessions,
                    poll.messages,
                )
            {
                log::warn(format!("sage: approval register failed: {e:?}"));
            }

            if let Ok(poll) = approval_response_sub.poll()
                && let Err(e) = tooling::route_approvals(&self.sessions, poll.messages)
            {
                log::warn(format!("sage: approval routing failed: {e:?}"));
            }

            if let Err(e) =
                tooling::enforce_deadlines(&self.sessions, &self.tool_call_meta)
            {
                log::warn(format!("sage: deadline sweep failed: {e:?}"));
            }

            if let Err(e) = shutdown::respawn_pending(&self.sessions) {
                log::warn(format!("sage: respawn sweep failed: {e:?}"));
            }

            if astrid_sdk::time::sleep(supervisor::TICK_INTERVAL).is_err() {
                // Sleep returning Err implies host shutdown / unload.
                break;
            }
        }
        Ok(())
    }
}

/// Write a `user`-role stream-json envelope to a session's stdin.
///
/// INVARIANT: `process.write_stdin` is a host call that may block on
/// kernel-side back-pressure and could re-enter the bus drain. Holding
/// the `Sessions` mutex across it would serialise the entire supervisor
/// loop and risks deadlock. The pattern here — encode + clone the
/// `Arc<Process>` handle under the lock, drop the guard, then write —
/// is the canonical lock-discipline shape mirrored by every callsite
/// in [`tooling`].
fn send_user_turn(sessions: &Sessions, session_id: &str, text: &str) -> Result<(), SysError> {
    let line = encode(&Outbound::UserTurn { text });
    if line.len() > 1024 * 1024 {
        let _ = ipc::publish_json(
            &format!("sage.v1.event.{session_id}.error"),
            &serde_json::json!({ "reason": "stdin_quota" }),
        );
        return Ok(());
    }

    // Phase 1: clone the Process handle out from under the lock.
    let process = sessions.with(|map| map.get(session_id).map(|s| s.process.clone()))?;
    let Some(process) = process else {
        log::warn(format!("send to unknown session {session_id}"));
        return Ok(());
    };

    // Phase 2: host call outside the lock.
    match process.write_stdin(line.as_bytes()) {
        Ok(_) => Ok(()),
        Err(e) => {
            let msg = format!("{e}");
            if msg.contains("TooLarge") {
                let _ = ipc::publish_json(
                    &format!("sage.v1.event.{session_id}.error"),
                    &serde_json::json!({ "reason": "stdin_quota" }),
                );
            } else {
                log::warn(format!("write_stdin send_user_turn failed: {msg}"));
            }
            Ok(())
        }
    }
}

/// Result of [`ensure_install`].
///
/// We deliberately do NOT model "timeout" or "internal SDK error" as a
/// distinct variant — both end up surfaced through `Failed` so the spawn
/// path uniformly aborts and the operator sees one stream of spawn-
/// error events instead of chasing two divergent topics.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum EnsureInstall {
    /// sage-install confirmed the principal is provisioned. Either a
    /// fresh `success: true` event arrived, or the cache-hit fast-reply
    /// (`already_installed: true`) landed. The string is the
    /// host-resolved absolute home path lifted from the
    /// `sage.v1.install.complete` envelope — sage-install canonicalises
    /// `home://` before publishing so this is a real filesystem path
    /// the subprocess `HOME` / cwd can interpret. Falls back to the
    /// `home://` VFS scheme string if sage-install omitted the field
    /// (older capsule version); the spawn path will still function but
    /// the subprocess may not see a valid `$HOME`.
    Ok(String),
    /// Either sage-install published `success: false` (carrying its
    /// `error` field), or the 30 s deadline elapsed with no response,
    /// or an SDK call blew up. Carries an operator-readable reason
    /// string forwarded to `sage.v1.event.<sid>.error`.
    Failed(String),
}

/// Classification of one `sage.v1.install.complete` envelope when
/// matched against a target `principal_id`. Pure function — extracted
/// from [`ensure_install`] so the success / failure / skip branching
/// is unit-testable on the host without standing up the IPC bus.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum InstallEnvelope {
    /// Envelope matched our principal and reported `success: true`.
    /// The string is the resolved home path from the envelope's
    /// `home_path` field — empty if the field was missing or blank
    /// (older sage-install incarnations); the caller treats empty as
    /// "fall back to `home://` VFS scheme".
    Success(String),
    /// Envelope matched our principal and reported `success: false`.
    /// The string is the install error reason, lifted verbatim from the
    /// `error` field if present, otherwise `"unknown"`.
    Failure(String),
    /// Envelope was for a different principal, was unparseable, or had
    /// no `principal_id` field. The caller should keep waiting.
    Skip,
}

/// Pure classifier for a single `sage.v1.install.complete` payload
/// against `principal_id`.
///
/// Returns [`InstallEnvelope::Skip`] for any payload that does not
/// match `principal_id` (including malformed JSON), [`Success`] for a
/// matching `success: true`, and [`Failure(reason)`] for a matching
/// `success: false` (using the `error` field, or `"unknown"` if the
/// envelope omitted it). Treated as failure rather than success-by-
/// default so a malformed sage-install envelope cannot silently
/// progress the spawn.
///
/// [`Success`]: InstallEnvelope::Success
/// [`Failure(reason)`]: InstallEnvelope::Failure
pub(crate) fn classify_install_complete(payload: &str, principal_id: &str) -> InstallEnvelope {
    let Ok(value) = serde_json::from_str::<Value>(payload) else {
        return InstallEnvelope::Skip;
    };
    if value
        .get("principal_id")
        .and_then(Value::as_str)
        .is_none_or(|p| p != principal_id)
    {
        return InstallEnvelope::Skip;
    }
    if value.get("success").and_then(Value::as_bool) == Some(true) {
        let home_path = value
            .get("home_path")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        return InstallEnvelope::Success(home_path);
    }
    let reason = value
        .get("error")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or("unknown")
        .to_string();
    InstallEnvelope::Failure(reason)
}

/// Drive sage-install for `principal_id` and block until it terminates.
///
/// Source-of-truth contract:
///
/// * sage-install owns idempotency. It writes the install-complete
///   marker into its OWN per-capsule KV namespace; the kernel scopes
///   KV by `{principal}:capsule:{capsule_id}` so sage cannot read it
///   from here. The previous implementation tried to and silently
///   missed every time, forcing a full publish/subscribe round-trip on
///   every spawn — including for already-provisioned principals. That
///   short-circuit is now sage-install's job: it returns
///   `already_installed: true` on a cache-hit, which is fast because
///   the publish/subscribe traffic is loopback within the bus.
///
/// * sage-install signals success with `success: true`, hard failure
///   with `success: false` + an `error` field. A hard failure here
///   must abort the spawn — proceeding to fork `claude -p` against an
///   unprovisioned `.claude/` directory would just produce a noisier
///   downstream failure.
///
/// * A 30 s deadline with no matching reply is treated as a hard
///   failure too. The host may have unloaded sage-install, or the
///   capsule registry may be missing it — in either case the spawn
///   has no useful work to do.
fn ensure_install(principal_id: &str) -> EnsureInstall {
    let sub = match ipc::subscribe("sage.v1.install.complete") {
        Ok(s) => s,
        Err(e) => return EnsureInstall::Failed(format!("subscribe_failed: {e}")),
    };
    if let Err(e) = ipc::publish_json(
        "sage.v1.install.run",
        &serde_json::json!({ "principal_id": principal_id }),
    ) {
        return EnsureInstall::Failed(format!("publish_failed: {e}"));
    }

    let deadline = Duration::from_secs(30);
    let mut remaining_ms = u64::try_from(deadline.as_millis()).unwrap_or(30_000);
    while remaining_ms > 0 {
        let step = remaining_ms.min(2_000);
        if let Ok(result) = sub.recv(step) {
            for msg in result.messages {
                // Multiple principals may be installing concurrently on
                // the bus — `classify_install_complete` filters to our
                // own principal_id and folds the success/failure shape
                // into a single decision. Failure includes the `error`
                // string verbatim so the operator sees the real reason.
                match classify_install_complete(&msg.payload, principal_id) {
                    InstallEnvelope::Success(home_path) => {
                        // sage-install ought to publish a resolved
                        // absolute path here. If it didn't (older
                        // capsule version with an empty `home_path`
                        // field), fall back to the VFS scheme so the
                        // spawn still has *something* to thread into
                        // HOME/cwd. Note: the subprocess will then see
                        // `home://` and likely fall back to ambient
                        // $HOME, breaking per-principal isolation —
                        // this is the silent-failure mode the resolved
                        // path closes; the fallback exists only so a
                        // version skew doesn't hard-block spawns.
                        let resolved = if home_path.is_empty() {
                            "home://".to_string()
                        } else {
                            home_path
                        };
                        return EnsureInstall::Ok(resolved);
                    }
                    InstallEnvelope::Failure(reason) => return EnsureInstall::Failed(reason),
                    InstallEnvelope::Skip => {}
                }
            }
        }
        remaining_ms = remaining_ms.saturating_sub(step);
    }

    EnsureInstall::Failed(format!(
        "install_timeout: no sage.v1.install.complete for principal {principal_id} within 30s"
    ))
}

fn publish_spawn_error(session_id: &str, principal_id: &str, reason: &str) {
    let _ = ipc::publish_json(
        &format!("sage.v1.event.{session_id}.error"),
        &serde_json::json!({
            "principal_id": principal_id,
            "session_id": session_id,
            "reason": reason,
        }),
    );
}

/// Pull the trailing segment out of an IPC topic (the bit after the
/// last `.`). Used by [`tooling::route_approvals`] to recover the
/// `correlation_id` from a wildcard-subscription envelope.
pub(crate) fn topic_tail(topic: &str) -> Option<&str> {
    topic.rsplit('.').next().filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Regression: a sage.v1.install.complete payload with success:false
    // must surface as Failure(error) so handle_spawn aborts with the
    // real reason instead of progressing to api_key_missing.
    #[test]
    fn install_complete_failure_carries_error_reason() {
        let payload = r#"{
            "principal_id": "p1",
            "success": false,
            "home_path": "",
            "error": "permission_denied: /.claude/settings.local.json"
        }"#;
        assert_eq!(
            classify_install_complete(payload, "p1"),
            InstallEnvelope::Failure("permission_denied: /.claude/settings.local.json".into()),
        );
    }

    #[test]
    fn install_complete_failure_without_error_falls_back_to_unknown() {
        let payload = r#"{"principal_id":"p1","success":false,"home_path":""}"#;
        assert_eq!(
            classify_install_complete(payload, "p1"),
            InstallEnvelope::Failure("unknown".into()),
        );
    }

    #[test]
    fn install_complete_empty_error_falls_back_to_unknown() {
        let payload = r#"{"principal_id":"p1","success":false,"home_path":"","error":""}"#;
        assert_eq!(
            classify_install_complete(payload, "p1"),
            InstallEnvelope::Failure("unknown".into()),
        );
    }

    #[test]
    fn install_complete_success_path() {
        let payload =
            r#"{"principal_id":"p1","success":true,"home_path":"/home/me/.astrid/principals/p1"}"#;
        assert_eq!(
            classify_install_complete(payload, "p1"),
            InstallEnvelope::Success("/home/me/.astrid/principals/p1".into()),
        );
    }

    #[test]
    fn install_complete_cache_hit_already_installed_is_success() {
        // sage-install fast-reply: success:true with already_installed:true.
        let payload = r#"{
            "principal_id": "p1",
            "success": true,
            "home_path": "/home/me/.astrid/principals/p1",
            "already_installed": true
        }"#;
        assert_eq!(
            classify_install_complete(payload, "p1"),
            InstallEnvelope::Success("/home/me/.astrid/principals/p1".into()),
        );
    }

    #[test]
    fn install_complete_success_without_home_path_returns_empty_string() {
        // Older sage-install incarnations may omit `home_path` from the
        // success envelope; surface as empty string so the caller can
        // detect and fall back to the VFS scheme without misclassifying
        // it as a failure.
        let payload = r#"{"principal_id":"p1","success":true}"#;
        assert_eq!(
            classify_install_complete(payload, "p1"),
            InstallEnvelope::Success(String::new()),
        );
    }

    #[test]
    fn install_complete_other_principal_is_skip() {
        let payload =
            r#"{"principal_id":"p2","success":false,"home_path":"","error":"boom"}"#;
        // Even a failure for a *different* principal must Skip, not
        // Failure — otherwise concurrent installs would abort each
        // other's spawn paths.
        assert_eq!(
            classify_install_complete(payload, "p1"),
            InstallEnvelope::Skip,
        );
    }

    #[test]
    fn install_complete_missing_principal_id_is_skip() {
        let payload = r#"{"success":true,"home_path":"/x"}"#;
        assert_eq!(
            classify_install_complete(payload, "p1"),
            InstallEnvelope::Skip,
        );
    }

    #[test]
    fn install_complete_malformed_json_is_skip() {
        assert_eq!(
            classify_install_complete("not json", "p1"),
            InstallEnvelope::Skip,
        );
    }

    #[test]
    fn install_complete_missing_success_field_treats_as_failure() {
        // Defence in depth: an envelope missing both `success` and
        // `error` is treated as a failure (with "unknown") rather than
        // silently succeeded — preserves the original bug's invariant
        // that a non-success payload cannot proceed to spawn.
        let payload = r#"{"principal_id":"p1","home_path":"/x"}"#;
        assert_eq!(
            classify_install_complete(payload, "p1"),
            InstallEnvelope::Failure("unknown".into()),
        );
    }
}
