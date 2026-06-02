//! Building the `claude -p` subprocess.
//!
//! Centralises the hardened argv + env we feed [`process::Command`].
//! Every flag here matters: dropping `--strict-mcp-config` smuggles in
//! `.mcp.json` from the redirected HOME; dropping `--tools ""` lets the
//! built-in Bash/Read/Write/Edit tools loose against the host
//! filesystem; etc. See the agent_mode_subprocess_lifecycle design
//! decision in the slice for the rationale on each flag.

use astrid_sdk::prelude::*;
use sha2::{Digest, Sha256};

const CLAUDE_BIN: &str = "claude";

/// Inputs for [`spawn_claude`].
pub(crate) struct SpawnInputs<'a> {
    /// Principal that owns this session. Threaded into the child env as
    /// `ASTRID_PRINCIPAL_ID` so the `astrid-emit` hook helper can stamp
    /// it on outgoing `sage.v1.unverified_hook.*` events. Sage's run
    /// loop re-verifies the claim against the per-(principal, session)
    /// hook token before republishing on the canonical `hook.v1.event.*`
    /// topic; the env value itself is untrusted (the child process may
    /// have leaked or rewritten it).
    pub principal_id: &'a str,
    pub session_id: &'a str,
    pub home_path: &'a str,
    pub identity_path: &'a str,
    /// Anthropic API key — when `Some`, threaded into the child env as
    /// `ANTHROPIC_API_KEY`. When `None`, the env var is OMITTED entirely
    /// so Claude falls back to its keychain OAuth credential path
    /// (subscription / `claude /login` mode). Note: argv is identical in
    /// both auth modes, so [`argv_hash`] is stable across modes for the
    /// same `session_id` — only the spawn env differs. That preserves
    /// the audit-stability invariant: a downstream consumer correlating
    /// by `flags_hash` will see the same fingerprint regardless of how
    /// the subprocess authenticated.
    pub api_key: Option<&'a str>,
    /// Per-(principal, session) random token, minted by sage at spawn
    /// time and persisted in KV under
    /// `sage.hook_token.<principal>.<session>`. Threaded into the child
    /// env as `ASTRID_HOOK_TOKEN`; `astrid-emit` echoes it back in the
    /// hook envelope so sage can distinguish authentic hook fires from
    /// forged `sage.v1.unverified_hook.*` publishes. Always present
    /// (no Option) — every spawn gets a token. Must NEVER appear in
    /// argv: it would land in process listings / audit logs and the
    /// `flags_hash` audit-stability invariant
    /// ([`argv_hash_unchanged_across_auth_modes`]) requires argv stay
    /// independent of per-spawn secrets.
    pub hook_token: &'a str,
}

/// Outcome of a successful spawn — the live process plus the audit
/// fingerprint of the argv we used so the spawn event can record it.
pub(crate) struct Spawned {
    pub process: process::Process,
    pub os_pid: u32,
    /// Deterministic SHA-256 digest of the full argv, formatted as
    /// `"sha256:<hex>"`. Computed by [`argv_hash`] with a NUL byte
    /// separator between arguments so distinct argv lists (e.g.
    /// `["a", "bc"]` vs `["ab", "c"]`) cannot collide. Reproducible
    /// across capsule reloads and across the fleet — audit consumers
    /// can use it as a stable fingerprint to cross-reference spawns.
    pub flags_hash: String,
}

/// Build the hardened argv for `claude -p`.
fn argv(session_id: &str, identity_path: &str) -> Vec<String> {
    vec![
        "-p".to_string(),
        "--input-format".to_string(),
        "stream-json".to_string(),
        "--output-format".to_string(),
        "stream-json".to_string(),
        "--verbose".to_string(),
        // No `.mcp.json` from disk — sage parses tool_use directly out
        // of the stream, the .mcp.json on disk is a documented stub.
        "--strict-mcp-config".to_string(),
        // Disable every built-in tool. Tool surface is exclusively
        // mcp__sage__* (which sage parses inline; claude only sees the
        // tool names through --append-system-prompt for now).
        "--tools".to_string(),
        String::new(),
        "--allowed-tools".to_string(),
        "mcp__sage__*".to_string(),
        // Permission prompts route through an MCP tool — sage-mcp
        // handles them on the bus.
        "--permission-prompt-tool".to_string(),
        "mcp__sage__approve".to_string(),
        // -p only: skip writing claude's own session JSONL. Source of
        // truth for the conversation is the bus + sage's KV records.
        "--no-session-persistence".to_string(),
        "--append-system-prompt-file".to_string(),
        identity_path.to_string(),
        "--session-id".to_string(),
        session_id.to_string(),
    ]
}

/// Construct + spawn the `claude -p` background process. Returns a live
/// [`process::Process`] plus the audit fingerprint.
///
/// Defense-in-depth re-validates `principal_id` and `session_id` so the
/// hardened argv + spawn env can never carry an unsanitised id, even if
/// a future caller path forgets the gate at the IPC boundary. The
/// session_id flows into `--session-id` (claude treats it as opaque,
/// but pathological values would still pollute the spawn log line);
/// principal_id is captured in the spawn audit event.
pub(crate) fn spawn_claude(inputs: &SpawnInputs<'_>) -> Result<Spawned, SysError> {
    crate::validate_id("principal_id", inputs.principal_id)?;
    crate::validate_id("session_id", inputs.session_id)?;

    let args = argv(inputs.session_id, inputs.identity_path);

    // Build the command. ANTHROPIC_API_KEY is conditional on auth_mode:
    // when the caller supplies `Some(key)` (api_key mode) we thread it
    // through, when `None` (subscription mode) we OMIT the call entirely
    // so Claude falls back to the keychain OAuth credential written by
    // `claude /login`. The argv itself is identical in both modes — see
    // [`SpawnInputs::api_key`] for the audit-stability rationale.
    let mut cmd = process::Command::new(CLAUDE_BIN)
        .args(args.iter().cloned())
        .env("HOME", inputs.home_path)
        // Belt-and-braces: also disable session persistence via env.
        // Some claude versions honour the flag; older builds may only
        // honour the env. Either path is fine.
        .env("CLAUDE_CODE_SKIP_PROMPT_HISTORY", "1")
        // Hook-bridge envelope: the `astrid-emit` helper (shipping in
        // core via astrid#814) reads these three vars and stamps them
        // onto every `sage.v1.unverified_hook.*` publish. Sage's run
        // loop verifies the token against KV before republishing on
        // the canonical `hook.v1.event.*` topic — env values are
        // untrusted on the way in, but the KV lookup acts as the CA.
        .env("ASTRID_PRINCIPAL_ID", inputs.principal_id)
        .env("ASTRID_SESSION_ID", inputs.session_id)
        .env("ASTRID_HOOK_TOKEN", inputs.hook_token)
        .cwd(inputs.home_path);
    if let Some(key) = inputs.api_key {
        cmd = cmd.env("ANTHROPIC_API_KEY", key);
    }

    let proc = cmd.spawn_background()?;
    let os_pid = proc.os_pid().unwrap_or(0);

    let flags_hash = argv_hash(&args);

    Ok(Spawned {
        process: proc,
        os_pid,
        flags_hash,
    })
}

/// Compute a deterministic SHA-256 fingerprint over an argv list.
///
/// Each argument is fed in followed by a `0x00` separator byte; that
/// way `["a", "bc"]` and `["ab", "c"]` hash to different values even
/// though their concatenations are identical. The output is formatted
/// as `"sha256:<lowercase-hex>"` so audit consumers can tell the
/// algorithm at a glance.
fn argv_hash(args: &[String]) -> String {
    let mut hasher = Sha256::new();
    for a in args {
        hasher.update(a.as_bytes());
        hasher.update([0x00]);
    }
    format!("sha256:{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// argv_hash must be deterministic: the same argv produces the
    /// same digest across calls (and, by extension, across process
    /// invocations and capsule reloads). This is the property the
    /// previous DefaultHasher implementation violated because the
    /// SipHash seed is randomised per process.
    #[test]
    fn argv_hash_is_deterministic() {
        let args = vec![
            "-p".to_string(),
            "--session-id".to_string(),
            "abc123".to_string(),
        ];
        let a = argv_hash(&args);
        let b = argv_hash(&args);
        assert_eq!(a, b);
        assert!(a.starts_with("sha256:"));
        // SHA-256 hex is 64 chars; plus the "sha256:" prefix = 71.
        assert_eq!(a.len(), "sha256:".len() + 64);
    }

    /// The 0x00 separator must make `["a", "bc"]` distinct from
    /// `["ab", "c"]`. Without it the two would collide.
    #[test]
    fn argv_hash_distinguishes_boundaries() {
        let lhs = argv_hash(&["a".to_string(), "bc".to_string()]);
        let rhs = argv_hash(&["ab".to_string(), "c".to_string()]);
        assert_ne!(lhs, rhs);
    }

    /// Known-answer test: pin the digest for the empty argv so a
    /// regression that silently changes the framing (e.g. drops the
    /// separator, switches algorithm) is caught.
    ///
    /// `Sha256::new().finalize()` for the empty input is the
    /// well-known constant
    /// `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
    #[test]
    fn argv_hash_empty_is_known_value() {
        let h = argv_hash(&[]);
        assert_eq!(
            h,
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
    }

    /// Audit-stability invariant: argv is constructed from `session_id`
    /// and `identity_path` only — the auth mode flows through env, not
    /// argv. So [`argv_hash`] must produce the same fingerprint for a
    /// given `session_id` regardless of whether the caller is in
    /// api_key mode (`Some(key)`) or subscription mode (`None`). A
    /// downstream audit consumer correlating spawns by `flags_hash`
    /// will not be able to distinguish auth modes from this digest
    /// alone — that's by design; `auth_mode` is published alongside
    /// `flags_hash` on `sage.v1.audit.spawn`.
    #[test]
    fn argv_hash_unchanged_across_auth_modes() {
        let sid = "sid-stable";
        let path = "home://.claude/.sage-identity-sid-stable";
        let args = argv(sid, path);
        let hash_api_key = argv_hash(&args);
        let hash_subscription = argv_hash(&args);
        assert_eq!(hash_api_key, hash_subscription);

        // Belt-and-braces: also confirm that the argv builder itself is
        // not silently branching on something out-of-band — calling it
        // twice with the same inputs must produce byte-identical output.
        let args_again = argv(sid, path);
        assert_eq!(args, args_again);
    }
}
