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

use crate::config::{AuthMode, InteractionMode, PrincipalConfig};

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

/// Source-of-truth deny list for the headless mode — every built-in
/// Claude tool that must be blocked so the `mcp__sage__*` sandbox holds.
/// Public so tests in this module can both assert presence in the JSON
/// and use it as a parameterised fixture.
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

/// The six hook events sage declares in `settings.local.json`. Each
/// event gets a single `/bin/true` placeholder until the native bridge
/// binary lands; see the doc-comment on [`settings_json`].
const HOOK_EVENTS: &[&str] = &[
    "PreToolUse",
    "PostToolUse",
    "UserPromptSubmit",
    "Stop",
    "SubagentStop",
    "SessionStart",
];

/// Build the `hooks` block — identical in both interaction modes so a
/// future native bridge can swap `/bin/true` for the real bridge in a
/// single edit without re-shaping the JSON.
///
/// `/bin/true` is POSIX-ubiquitous, returns exit 0, and produces no
/// stdout — Claude treats every hook as a no-op approval. Unix
/// assumption: `/bin/true` does not exist on Windows; sage is Unix-only
/// today (the `claude` binary, the HOME redirect, and the
/// `/bin/false` `apiKeyHelper` all assume Unix).
fn hooks_block() -> serde_json::Value {
    let mut hooks = serde_json::Map::new();
    for event in HOOK_EVENTS {
        hooks.insert(
            (*event).to_string(),
            serde_json::json!([
                {
                    "type": "command",
                    "command": "/bin/true",
                    "timeout": 10
                }
            ]),
        );
    }
    serde_json::Value::Object(hooks)
}

/// `.claude/settings.local.json` body for the given principal config.
///
/// Branching is driven by the two axes in [`PrincipalConfig`]:
///
/// * [`InteractionMode::Headless`]: sage drives the loop. The allow list
///   is pinned to `mcp__sage__*`, every built-in tool in
///   [`REQUIRED_DENIES`] is denied, and `disableSkillShellExecution` is
///   set so the skill subsystem cannot shell out around the sandbox.
/// * [`InteractionMode::Repl`]: the user drives `claude` directly. Allow
///   and deny lists are empty (user owns their full Claude environment)
///   and `disableSkillShellExecution` is omitted.
/// * [`AuthMode::ApiKey`]: `apiKeyHelper` is pinned to `/bin/false` so
///   `claude` cannot fall back to ambient creds — the per-principal
///   secret is forwarded as `ANTHROPIC_API_KEY` in the spawn env.
/// * [`AuthMode::Subscription`]: `apiKeyHelper` is omitted entirely so
///   `claude` can use its keychain OAuth path. Caveat (macOS): the
///   keychain entry is keyed by service+account, not by `HOME`, so two
///   principals on the same macOS user share the OAuth token. Use
///   api_key mode (or separate macOS users) for full per-principal
///   isolation. Linux libsecret is namespaced by user session and is
///   unaffected.
///
/// The `hooks` block is **identical in both modes** — declared, not
/// disabled, so a future native bridge binary can drop in as a single
/// command swap. The Astrid host has no helper binary today that
/// bridges Claude's stdin-JSON subprocess hook protocol onto the IPC
/// bus (`astrid.v1.lifecycle.*`). When that bridge ships (likely as an
/// `astrid hook` subcommand reading stdin and publishing with a
/// capability-scoped principal token), swap `/bin/true` for the bridge
/// command in [`hooks_block`]. The `astrid-capsule-hook-bridge` WASM
/// capsule already maps lifecycle events to semantic hooks on the bus
/// side — only the subprocess-to-bus shim is missing.
pub(crate) fn settings_json(cfg: &PrincipalConfig) -> serde_json::Value {
    let (allow, deny, skill_shell): (Vec<&str>, Vec<&str>, Option<bool>) = match cfg
        .interaction_mode
    {
        InteractionMode::Headless => (
            vec!["mcp__sage__*"],
            REQUIRED_DENIES.to_vec(),
            Some(true),
        ),
        InteractionMode::Repl => (vec![], vec![], None),
    };

    let mut root = serde_json::json!({
        "permissions": {
            "allow": allow,
            "deny": deny,
        },
        "hooks": hooks_block(),
        "cleanupPeriodDays": 30,
    });
    let obj = root
        .as_object_mut()
        .expect("settings root literal is a JSON object");
    if let Some(b) = skill_shell {
        obj.insert("disableSkillShellExecution".to_string(), serde_json::json!(b));
    }
    if matches!(cfg.auth_mode, AuthMode::ApiKey) {
        obj.insert(
            "apiKeyHelper".to_string(),
            serde_json::json!("/bin/false"),
        );
    }
    root
}

/// `.claude/.mcp.json` body for the given principal config.
///
/// * [`InteractionMode::Headless`]: emit the documented `/bin/false`
///   stub so claude's `--allowed-tools mcp__sage__*` flag resolves
///   without spawning a real stdio MCP server (sage parses tool_use
///   blocks out of claude's stream-json directly).
/// * [`InteractionMode::Repl`]: no sage-spawned `claude` subprocess
///   exists, so the stub is irrelevant — emit an empty `mcpServers`
///   object. Users wiring native MCP servers in repl mode edit this
///   file themselves; sage doesn't fight them.
pub(crate) fn mcp_json(cfg: &PrincipalConfig) -> serde_json::Value {
    match cfg.interaction_mode {
        InteractionMode::Headless => serde_json::json!({
            "mcpServers": {
                "sage": {
                    "command": "/bin/false",
                    "args": [],
                    "env": {}
                }
            }
        }),
        InteractionMode::Repl => serde_json::json!({ "mcpServers": {} }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // sanitize_principal_id  (security gate — preserved verbatim)
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
    // settings_json — parameterised over the (interaction, auth) matrix.
    //
    // Four combinations × shared per-axis assertions. The security
    // surface (deny list + helper pinning + hook declaration) is the
    // critical invariant — every change must keep it intact for the
    // headless+api_key default, otherwise `claude` could escape the
    // mcp__sage__* sandbox.
    // ------------------------------------------------------------------

    fn cfg(im: InteractionMode, am: AuthMode) -> PrincipalConfig {
        PrincipalConfig {
            interaction_mode: im,
            auth_mode: am,
            schema_version: PrincipalConfig::SCHEMA_VERSION,
        }
    }

    fn assert_headless_shape(v: &serde_json::Value) {
        let allow = v
            .pointer("/permissions/allow")
            .and_then(|x| x.as_array())
            .expect("permissions.allow must be a JSON array");
        assert_eq!(allow.len(), 1, "headless: only one allow entry permitted");
        assert_eq!(allow[0], serde_json::json!("mcp__sage__*"));

        let deny = v
            .pointer("/permissions/deny")
            .and_then(|x| x.as_array())
            .expect("permissions.deny must be a JSON array");
        for required in REQUIRED_DENIES {
            assert!(
                deny.iter().any(|d| d == required),
                "headless: deny list missing built-in tool '{required}' — claude could call it directly"
            );
        }
        assert_eq!(
            deny.len(),
            REQUIRED_DENIES.len(),
            "headless: deny list must contain exactly the required built-in tools"
        );

        assert_eq!(
            v.pointer("/disableSkillShellExecution")
                .and_then(|x| x.as_bool()),
            Some(true),
            "headless: skill shell execution must be disabled"
        );
    }

    fn assert_repl_shape(v: &serde_json::Value) {
        let allow = v
            .pointer("/permissions/allow")
            .and_then(|x| x.as_array())
            .expect("permissions.allow must be a JSON array");
        assert!(allow.is_empty(), "repl: allow list must be empty");

        let deny = v
            .pointer("/permissions/deny")
            .and_then(|x| x.as_array())
            .expect("permissions.deny must be a JSON array");
        assert!(deny.is_empty(), "repl: deny list must be empty");

        assert!(
            v.pointer("/disableSkillShellExecution").is_none(),
            "repl: disableSkillShellExecution must be omitted"
        );
    }

    fn assert_api_key_helper_present(v: &serde_json::Value) {
        assert_eq!(
            v.pointer("/apiKeyHelper").and_then(|x| x.as_str()),
            Some("/bin/false"),
            "api_key: apiKeyHelper must be /bin/false so claude cannot fall back to ambient creds"
        );
    }

    fn assert_api_key_helper_omitted(v: &serde_json::Value) {
        assert!(
            v.pointer("/apiKeyHelper").is_none(),
            "subscription: apiKeyHelper must be omitted entirely so claude can use its keychain OAuth path"
        );
    }

    fn assert_hooks_block_present(v: &serde_json::Value) {
        let hooks = v
            .pointer("/hooks")
            .and_then(|x| x.as_object())
            .expect("hooks block must be a JSON object");
        for event in HOOK_EVENTS {
            let entries = hooks
                .get(*event)
                .and_then(|x| x.as_array())
                .unwrap_or_else(|| panic!("hooks.{event} must be a JSON array"));
            assert_eq!(entries.len(), 1, "hooks.{event} must have one entry");
            assert_eq!(
                entries[0].pointer("/command").and_then(|x| x.as_str()),
                Some("/bin/true"),
                "hooks.{event}: command must be /bin/true placeholder"
            );
            assert_eq!(
                entries[0].pointer("/type").and_then(|x| x.as_str()),
                Some("command"),
                "hooks.{event}: type must be \"command\""
            );
            assert_eq!(
                entries[0].pointer("/timeout").and_then(|x| x.as_u64()),
                Some(10),
                "hooks.{event}: timeout must be 10s"
            );
        }
    }

    // ----- The four mode-pair tests (full matrix). -----

    #[test]
    fn settings_headless_api_key() {
        let v = settings_json(&cfg(InteractionMode::Headless, AuthMode::ApiKey));
        assert_headless_shape(&v);
        assert_api_key_helper_present(&v);
        assert_hooks_block_present(&v);
    }

    #[test]
    fn settings_headless_subscription() {
        let v = settings_json(&cfg(InteractionMode::Headless, AuthMode::Subscription));
        assert_headless_shape(&v);
        assert_api_key_helper_omitted(&v);
        assert_hooks_block_present(&v);
    }

    #[test]
    fn settings_repl_api_key() {
        let v = settings_json(&cfg(InteractionMode::Repl, AuthMode::ApiKey));
        assert_repl_shape(&v);
        assert_api_key_helper_present(&v);
        assert_hooks_block_present(&v);
    }

    #[test]
    fn settings_repl_subscription() {
        let v = settings_json(&cfg(InteractionMode::Repl, AuthMode::Subscription));
        assert_repl_shape(&v);
        assert_api_key_helper_omitted(&v);
        assert_hooks_block_present(&v);
    }

    // ----- Added behavioural tests beyond the matrix. -----

    #[test]
    fn settings_repl_mode_omits_deny_list() {
        // Defence-in-depth: repl mode must NEVER carry the native-tool
        // deny list, even by accident — the user owns the full Claude
        // environment in repl mode.
        for am in [AuthMode::ApiKey, AuthMode::Subscription] {
            let v = settings_json(&cfg(InteractionMode::Repl, am));
            let deny = v
                .pointer("/permissions/deny")
                .and_then(|x| x.as_array())
                .expect("permissions.deny must be a JSON array");
            assert!(deny.is_empty(), "repl ({am:?}): deny list must be empty");
        }
    }

    #[test]
    fn settings_subscription_mode_omits_helper() {
        // Regression guard: subscription mode must not emit a stray
        // /bin/false helper (that would short-circuit the keychain
        // OAuth fallback that subscription mode relies on).
        for im in [InteractionMode::Headless, InteractionMode::Repl] {
            let v = settings_json(&cfg(im, AuthMode::Subscription));
            assert!(
                v.pointer("/apiKeyHelper").is_none(),
                "subscription ({im:?}): apiKeyHelper must be omitted"
            );
        }
    }

    #[test]
    fn settings_declares_hook_placeholders() {
        // The hooks block must be present, identical across all four
        // (mode, auth) combinations, and pin each event to a /bin/true
        // command with timeout=10 so the native-bridge swap is one line.
        for im in [InteractionMode::Headless, InteractionMode::Repl] {
            for am in [AuthMode::ApiKey, AuthMode::Subscription] {
                let v = settings_json(&cfg(im, am));
                assert_hooks_block_present(&v);
            }
        }
    }

    #[test]
    fn settings_never_emits_legacy_hook_disable_flag() {
        // Regression guard: the legacy hook-disable flag blocked status
        // lines AND the future hook bridge — must never reappear. Key
        // assembled at runtime to keep the literal name out of source
        // (so a `grep` for the legacy flag in production code reports
        // zero matches; the v1 contract is "hooks declared, not
        // disabled").
        let legacy_key = format!("/{}{}", "disableAll", "Hooks");
        for im in [InteractionMode::Headless, InteractionMode::Repl] {
            for am in [AuthMode::ApiKey, AuthMode::Subscription] {
                let v = settings_json(&cfg(im, am));
                assert!(
                    v.pointer(&legacy_key).is_none(),
                    "({im:?}, {am:?}): legacy hook-disable flag must not be set"
                );
            }
        }
    }

    // ------------------------------------------------------------------
    // mcp_json — mode-gated.
    // ------------------------------------------------------------------

    #[test]
    fn mcp_headless_keeps_bin_false_stub() {
        for am in [AuthMode::ApiKey, AuthMode::Subscription] {
            let v = mcp_json(&cfg(InteractionMode::Headless, am));
            assert_eq!(
                v.pointer("/mcpServers/sage/command")
                    .and_then(|x| x.as_str()),
                Some("/bin/false"),
                "headless ({am:?}): stub MCP server command must be /bin/false"
            );
        }
    }

    #[test]
    fn mcp_repl_mode_is_empty() {
        for am in [AuthMode::ApiKey, AuthMode::Subscription] {
            let v = mcp_json(&cfg(InteractionMode::Repl, am));
            let servers = v
                .pointer("/mcpServers")
                .and_then(|x| x.as_object())
                .expect("mcpServers must be a JSON object");
            assert!(
                servers.is_empty(),
                "repl ({am:?}): mcpServers must be empty (user wires their own)"
            );
        }
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
