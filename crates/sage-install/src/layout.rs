//! Per-principal `.claude/` directory layout — paths, sanitization, and
//! KV key derivation.
//!
//! Paths use the `home://` VFS scheme. The kernel resolves it at check
//! time against the invoking principal's home root
//! (`~/.astrid/home/<principal>/`, see core/crates/astrid-kernel/src/lib.rs:75),
//! so per-principal isolation is enforced by the host rather than
//! encoded in the path string. principal_id is still validated as
//! untrusted IPC input — it is used for the KV install-complete key
//! and surfaced in status events — but it never participates in path
//! construction.

use astrid_sdk::prelude::*;

/// Per-principal home root. The kernel binds `home://` to the
/// invoking principal's home directory at check time, so every fs call
/// from this capsule against `home://...` lands inside that principal's
/// scope.
pub(crate) fn principal_home() -> String {
    "home://".to_string()
}

/// `.claude/` config dir under the principal home.
pub(crate) fn claude_dir() -> String {
    "home://.claude".to_string()
}

/// `.claude/projects/` — required by `claude` even when session
/// persistence is disabled.
pub(crate) fn projects_dir() -> String {
    "home://.claude/projects".to_string()
}

/// Path to `.claude/settings.local.json` — the hardened settings file.
pub(crate) fn settings_path() -> String {
    "home://.claude/settings.local.json".to_string()
}

/// Path to `.claude/.mcp.json` — the MCP server stub (sage parses
/// tool_use directly from stream-json; this entry exists so
/// `--allowed-tools mcp__sage__*` resolves).
pub(crate) fn mcp_path() -> String {
    "home://.claude/.mcp.json".to_string()
}

/// KV key marking a completed install for `principal_id`.
///
/// Namespaced under `sage.` so the prefix can't collide with another
/// capsule's "install.complete.*" markers — every capsule sharing the KV
/// surface keeps its own top-level bucket.
pub(crate) fn install_complete_key(sanitized_id: &str) -> String {
    format!("sage.install.complete.{sanitized_id}")
}

/// Validate and normalise a principal id read off the IPC bus.
///
/// Rejects `..`, `/`, `\`, NUL, and any character outside
/// `[A-Za-z0-9._-]`. The accepted alphabet matches every other
/// per-principal VFS resolver in the Astrid stack; this is the only
/// untrusted-input gate in the install path.
pub(crate) fn sanitize_principal_id(id: &str) -> Result<String, SysError> {
    if id.is_empty() {
        return Err(SysError::ApiError("principal_id must not be empty".into()));
    }
    if id == "." || id == ".." {
        return Err(SysError::ApiError(format!(
            "principal_id '{id}' is a reserved path segment"
        )));
    }
    if id.len() > 128 {
        return Err(SysError::ApiError(
            "principal_id exceeds 128 characters".into(),
        ));
    }
    for c in id.chars() {
        let ok = c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-';
        if !ok {
            return Err(SysError::ApiError(format!(
                "principal_id contains disallowed character '{c}' (allowed: [A-Za-z0-9._-])"
            )));
        }
    }
    Ok(id.to_string())
}

/// Hardened `.claude/settings.local.json` body.
///
/// Pins `permissions.allow` to `mcp__sage__*` only, denies every
/// built-in tool, disables hook execution and skill shell substitution,
/// and pins `apiKeyHelper` to `/bin/false` so claude cannot fall back
/// to ambient credentials (the per-principal key lives in KV).
pub(crate) fn settings_json() -> serde_json::Value {
    serde_json::json!({
        "permissions": {
            "allow": ["mcp__sage__*"],
            "deny": [
                "Bash",
                "Read",
                "Write",
                "Edit",
                "WebFetch",
                "WebSearch",
                "Glob",
                "Grep",
                "Task",
                "NotebookEdit"
            ]
        },
        "disableSkillShellExecution": true,
        "disableAllHooks": true,
        "apiKeyHelper": "/bin/false",
        "cleanupPeriodDays": 30
    })
}

/// `.claude/.mcp.json` stub — documented placeholder. The real
/// per-principal MCP surface is delivered via sage parsing tool_use
/// blocks out of claude's stream-json and bridging them onto the
/// Astrid IPC bus (see `sage-mcp`). The stub keeps `claude`'s
/// `--allowed-tools mcp__sage__*` flag resolving without spawning a
/// stdio server.
pub(crate) fn mcp_json() -> serde_json::Value {
    serde_json::json!({
        "mcpServers": {
            "sage": {
                "command": "/bin/false",
                "args": [],
                "env": {}
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // sanitize_principal_id
    // ------------------------------------------------------------------

    #[test]
    fn sanitize_accepts_typical_id() {
        assert_eq!(
            sanitize_principal_id("alice").unwrap(),
            "alice".to_string()
        );
    }

    #[test]
    fn sanitize_accepts_full_allowed_alphabet() {
        // Every ASCII alnum + the three punctuation characters in the spec
        let id = "AZaz09._-";
        assert_eq!(sanitize_principal_id(id).unwrap(), id.to_string());
    }

    #[test]
    fn sanitize_accepts_pubkey_shaped_id() {
        // 64-char hex — common shape for ed25519 principal ids.
        let id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(sanitize_principal_id(id).unwrap(), id.to_string());
    }

    #[test]
    fn sanitize_rejects_empty_string() {
        let err = sanitize_principal_id("").unwrap_err();
        assert!(matches!(err, SysError::ApiError(_)));
    }

    #[test]
    fn sanitize_rejects_dot() {
        let err = sanitize_principal_id(".").unwrap_err();
        assert!(matches!(err, SysError::ApiError(ref m) if m.contains("reserved path segment")));
    }

    #[test]
    fn sanitize_rejects_dotdot() {
        let err = sanitize_principal_id("..").unwrap_err();
        assert!(matches!(err, SysError::ApiError(ref m) if m.contains("reserved path segment")));
    }

    #[test]
    fn sanitize_rejects_forward_slash() {
        // Path traversal attempt — would escape the principal home.
        let err = sanitize_principal_id("alice/bob").unwrap_err();
        assert!(matches!(err, SysError::ApiError(ref m) if m.contains("disallowed character '/'")));
    }

    #[test]
    fn sanitize_rejects_backslash() {
        let err = sanitize_principal_id("alice\\bob").unwrap_err();
        assert!(matches!(err, SysError::ApiError(ref m) if m.contains("disallowed character")));
    }

    #[test]
    fn sanitize_rejects_nul_byte() {
        // Filesystem syscalls truncate at NUL; never let one through.
        let err = sanitize_principal_id("alice\0bob").unwrap_err();
        assert!(matches!(err, SysError::ApiError(ref m) if m.contains("disallowed character")));
    }

    #[test]
    fn sanitize_rejects_path_traversal_sequence() {
        let err = sanitize_principal_id("../../etc/passwd").unwrap_err();
        // Trips on the '/' before it reaches the literal `..` check.
        assert!(matches!(err, SysError::ApiError(_)));
    }

    #[test]
    fn sanitize_rejects_space() {
        let err = sanitize_principal_id("alice bob").unwrap_err();
        assert!(matches!(err, SysError::ApiError(_)));
    }

    #[test]
    fn sanitize_rejects_unicode() {
        // Non-ASCII letters are outside the allowlist.
        let err = sanitize_principal_id("álice").unwrap_err();
        assert!(matches!(err, SysError::ApiError(_)));
    }

    #[test]
    fn sanitize_rejects_oversized_id() {
        let id: String = "a".repeat(129);
        let err = sanitize_principal_id(&id).unwrap_err();
        assert!(matches!(err, SysError::ApiError(ref m) if m.contains("128")));
    }

    #[test]
    fn sanitize_accepts_id_at_128_limit() {
        let id: String = "a".repeat(128);
        assert_eq!(sanitize_principal_id(&id).unwrap(), id);
    }

    // ------------------------------------------------------------------
    // settings_json — integration test for the hardened body shape.
    //
    // This is the security-critical surface: every change must keep the
    // deny list and helper pinning intact, otherwise `claude` could
    // escape the mcp__sage__* sandbox.
    // ------------------------------------------------------------------

    /// Every built-in tool that must be denied. Source-of-truth list,
    /// asserted against the generated JSON so a regression on either
    /// side is caught.
    const REQUIRED_DENIES: &[&str] = &[
        "Bash",
        "Read",
        "Write",
        "Edit",
        "WebFetch",
        "WebSearch",
        "Glob",
        "Grep",
        "Task",
        "NotebookEdit",
    ];

    #[test]
    fn settings_allow_list_is_mcp_sage_only() {
        let v = settings_json();
        let allow = v
            .pointer("/permissions/allow")
            .and_then(|x| x.as_array())
            .expect("permissions.allow must be a JSON array");
        assert_eq!(allow.len(), 1, "only one allow entry permitted");
        assert_eq!(allow[0], serde_json::json!("mcp__sage__*"));
    }

    #[test]
    fn settings_deny_list_contains_every_builtin_tool() {
        let v = settings_json();
        let deny = v
            .pointer("/permissions/deny")
            .and_then(|x| x.as_array())
            .expect("permissions.deny must be a JSON array");
        for required in REQUIRED_DENIES {
            assert!(
                deny.iter().any(|d| d == required),
                "deny list missing built-in tool '{required}' — claude could call it directly"
            );
        }
        // Catch regressions in the *other* direction: stray entries.
        assert_eq!(
            deny.len(),
            REQUIRED_DENIES.len(),
            "deny list must contain exactly the required built-in tools"
        );
    }

    #[test]
    fn settings_pins_api_key_helper_to_bin_false() {
        let v = settings_json();
        assert_eq!(
            v.pointer("/apiKeyHelper").and_then(|x| x.as_str()),
            Some("/bin/false"),
            "apiKeyHelper must be /bin/false so claude cannot fall back to ambient creds"
        );
    }

    #[test]
    fn settings_disables_hooks_and_skill_shell_execution() {
        let v = settings_json();
        assert_eq!(
            v.pointer("/disableAllHooks").and_then(|x| x.as_bool()),
            Some(true),
            "hook execution must be disabled"
        );
        assert_eq!(
            v.pointer("/disableSkillShellExecution")
                .and_then(|x| x.as_bool()),
            Some(true),
            "skill shell execution must be disabled"
        );
    }

    // ------------------------------------------------------------------
    // mcp_json — verify the stub shape.
    // ------------------------------------------------------------------

    #[test]
    fn mcp_stub_points_at_bin_false() {
        let v = mcp_json();
        assert_eq!(
            v.pointer("/mcpServers/sage/command")
                .and_then(|x| x.as_str()),
            Some("/bin/false"),
            "stub MCP server command must be /bin/false"
        );
    }

    // ------------------------------------------------------------------
    // KV key namespacing — guard against accidental collisions with
    // other capsules sharing the kv surface.
    // ------------------------------------------------------------------

    #[test]
    fn install_complete_key_is_sage_namespaced() {
        assert_eq!(
            install_complete_key("alice"),
            "sage.install.complete.alice"
        );
    }

    // ------------------------------------------------------------------
    // Path layout — sanity that every emitted path lives under the
    // declared fs scope.
    //
    // Paths must all use the `home://` VFS scheme so the kernel binds
    // them to the invoking principal at check time. A literal `~/...`
    // path falls through to the workspace-root branch of the resolver
    // and writes land in the wrong place (silent data loss).
    // ------------------------------------------------------------------

    #[test]
    fn all_paths_live_under_home_scheme() {
        assert!(principal_home().starts_with("home://"));
        assert!(claude_dir().starts_with("home://"));
        assert!(projects_dir().starts_with("home://"));
        assert!(settings_path().starts_with("home://"));
        assert!(mcp_path().starts_with("home://"));
    }

    #[test]
    fn no_path_carries_literal_tilde() {
        // Defence-in-depth regression — silent fall-through to workspace
        // root if any of these slip back into the legacy `~/...` form.
        for p in [
            principal_home(),
            claude_dir(),
            projects_dir(),
            settings_path(),
            mcp_path(),
        ] {
            assert!(
                !p.starts_with('~'),
                "path '{p}' must use the home:// scheme, not a literal tilde"
            );
        }
    }
}
