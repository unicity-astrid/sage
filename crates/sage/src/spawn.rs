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
    /// Kept on the input struct for future audit fan-out (the spawn
    /// audit event published by the caller carries it); not consumed
    /// directly by `spawn_claude` itself.
    #[allow(dead_code)]
    pub principal_id: &'a str,
    pub session_id: &'a str,
    pub home_path: &'a str,
    pub identity_path: &'a str,
    pub api_key: &'a str,
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

    let cmd = process::Command::new(CLAUDE_BIN)
        .args(args.iter().cloned())
        .env("HOME", inputs.home_path)
        .env("ANTHROPIC_API_KEY", inputs.api_key)
        // Belt-and-braces: also disable session persistence via env.
        // Some claude versions honour the flag; older builds may only
        // honour the env. Either path is fine.
        .env("CLAUDE_CODE_SKIP_PROMPT_HISTORY", "1")
        .cwd(inputs.home_path);

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
}
