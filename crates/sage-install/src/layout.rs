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

/// Path to `.claude/.mcp.json` — registers the `sage` MCP server
/// (`astrid mcp serve --principal <id>`) that claude calls `mcp__sage__*`
/// tools against. See [`mcp_json`] for the body.
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

/// Source-of-truth deny list for the headless NATIVE-TOOLS model — the
/// ESCAPE / orchestration surface that stays blocked even though Claude's
/// own dev tools (Bash / Read / Write / Edit / Glob / Grep / Web*) are now
/// ALLOWED and sandboxed. Denied: a second shell (`PowerShell`), sub-agent
/// spawn / teaming, scheduling + control-flow transitions, Astrid's OWN
/// task surface, off-host exfiltration channels, raw MCP resource /
/// tool-loading surfaces, and the indirect-execution skill surface — each
/// a governance axis that does not belong to a single supervised session.
///
/// Defence-in-depth caveat: this list lives in `settings.local.json`,
/// Claude's WEAKEST, fully session-overridable settings tier — a capable
/// session can edit any of these denies away. The BINDING tool gate is
/// the spawn argv (`--permission-mode dontAsk` — anything not in
/// `permissions.allow` is auto-denied — plus `--disallowedTools <this
/// list>`, see `sage::spawn::argv` / `sage::spawn::DENIED_TOOLS`), which
/// sits above every on-disk file tier in Claude's precedence order; and
/// the Astrid HOST sandbox bounds whatever does run. This file copy is a
/// redundant second layer, not the primary enforcement boundary.
///
/// SYNC (load-bearing): every name here MUST also appear in
/// `sage::spawn::DENIED_TOOLS` (sage/src/spawn.rs), the copy hoisted into
/// the binding `--disallowedTools` CLI tier. The two crates have no
/// dependency edge, so the list is mirrored, not shared. A name present
/// HERE but absent THERE is denied only in the overridable tier — a
/// session edits it out of `settings.local.json` and calls it, so the
/// deny is not actually binding. Both sides anchor on the same element
/// count (`assert_headless_shape` here, `denied_tools_count_anchors_…`
/// there) so a one-sided edit trips a test. Any change to one list must
/// mirror to the other.
///
/// Coverage strategy: entries fall into two groups.
/// * Current surface — every tool in Claude's published tools reference
///   that can act, spawn, schedule, message, read MCP resources, or load
///   other tools. Inert read-only conveniences with no escape value
///   (e.g. `AskUserQuestion`) are intentionally NOT listed; the argv gate
///   is the real boundary and a deny here would only add churn.
/// * Legacy aliases — older tool names (`Task`, `MultiEdit`, `BashOutput`,
///   `KillShell`, `SlashCommand`) Claude has since renamed or folded into
///   other tools. Denying a name Claude no longer ships is a harmless
///   no-op, and keeps the gate intact for principals pinned to an older
///   `claude` build during the version-pin window.
///
/// Public-in-module so tests can both assert presence in the JSON and use
/// it as a parameterised fixture.
const REQUIRED_DENIES: &[&str] = &[
    // A second shell on its own tool name — the native shell is `Bash`
    // (now allowed, sandboxed); the redundant shell surface stays closed.
    "PowerShell",
    // Sub-agent spawn / teaming — a spawned agent runs its OWN tool calls
    // and is a separate principal-scoping question. `Task` is the legacy
    // `Agent` alias.
    "Agent",
    "Task",
    "Workflow",
    "SendMessage",
    "TeamCreate",
    "TeamDelete",
    // Scheduling / control flow — queue a future prompt, reschedule a loop,
    // or drive plan-mode / worktree transitions outside sage's run loop.
    "CronCreate",
    "CronDelete",
    "CronList",
    "ScheduleWakeup",
    "EnterPlanMode",
    "ExitPlanMode",
    "EnterWorktree",
    "ExitWorktree",
    // Astrid's OWN task surface — these are ASTRID's tools, not Claude's;
    // the supervised session must not drive Astrid's control plane.
    "TaskCreate",
    "TaskGet",
    "TaskList",
    "TaskStop",
    "TaskUpdate",
    "TaskOutput",
    // External / exfiltration surfaces — off-host channels sage does not
    // mediate.
    "PushNotification",
    "RemoteTrigger",
    "ShareOnboardingGuide",
    // MCP resource + tool-loading surfaces: reading raw MCP resources or
    // loading deferred tools reaches a tool around the gated surface.
    "ListMcpResourcesTool",
    "ReadMcpResourceTool",
    "ToolSearch",
    "WaitForMcpServers",
    // Indirect-execution surface — a skill / slash command can fan out to
    // other tools; deferred until the indirect path is governed.
    // `SlashCommand` is the legacy `Skill` alias.
    "Skill",
    "SlashCommand",
];

/// Native dev-tool surface auto-approved under the headless native-tools
/// model. With `--permission-mode dontAsk` (binding via argv) only tools
/// matched here — or read-only sandboxed Bash — run without a prompt;
/// everything else, including the [`REQUIRED_DENIES`] escape surface, is
/// auto-denied. `mcp__sage__*` keeps the registered sage MCP server
/// reachable for Astrid-specific operations. Bounds on what these tools can
/// DO come from the sandbox (Astrid host + Claude inner), not this list.
const NATIVE_ALLOW: &[&str] = &[
    "Bash",
    "Read",
    "Write",
    "Edit",
    "MultiEdit",
    "NotebookEdit",
    "Glob",
    "Grep",
    "WebFetch",
    "WebSearch",
    "LSP",
    "Monitor",
    "BashOutput",
    "KillShell",
    "TodoWrite",
    "mcp__sage__*",
];

/// The Claude hook events sage declares in `settings.local.json`. Each
/// event is wired through the `astrid-emit` native helper, which
/// publishes the Claude-side hook payload on the sage-namespaced
/// `sage.v1.hook.*` topic so sage's run-loop validator can
/// authenticate the spawn-token and republish on the canonical
/// `hook.v1.event.*` (or sage-namespaced `sage.v1.notification`) topic.
/// See [`HOOK_TOPIC_MAP`] for the per-event topic.
///
/// The set spans Claude's session lifecycle (start/end), the prompt and
/// tool-call turns, the subagent lifecycle (start/stop), and the
/// compaction window (pre/post). Every canonical target already exists
/// in the hook-bridge event vocabulary, so this set widens with no
/// cross-capsule contract change. Events Claude reports as semantically
/// distinct are kept distinct: `Stop` is a per-turn "assistant message
/// sent" signal, NOT session end — `SessionEnd` is the real session
/// terminator (see [`HOOK_TOPIC_MAP`]).
const HOOK_EVENTS: &[&str] = &[
    "SessionStart",
    "SessionEnd",
    "UserPromptSubmit",
    "PreToolUse",
    "PostToolUse",
    "Stop",
    "SubagentStart",
    "SubagentStop",
    "PreCompact",
    "PostCompact",
    "Notification",
];

/// Per-event mapping from Claude's hook name to the sage-namespaced
/// `sage.v1.hook.*` topic that `astrid-emit` publishes on.
///
/// Sage's run-loop validator subscribes to `sage.v1.hook.*`,
/// authenticates the per-(principal, session) spawn token carried in
/// the envelope, and republishes on the canonical `hook.v1.event.<name>`
/// topic (or `sage.v1.notification` for the one event without a
/// canonical equivalent today).
///
/// Semantic care: Claude's `Stop` fires at the end of every response
/// turn (the assistant message was sent), so it maps to `message_sent`,
/// NOT `session_end`. `SessionEnd` — which fires once when the session
/// actually terminates — is what carries `session_end`. Conflating the
/// two would make any session-lifecycle subscriber fire on every turn.
///
/// SYNC: keep aligned with sage::hooks::HOOK_TOPIC_MAP (sage/src/hooks.rs).
/// sage-install cannot import from the sage crate (separate workspace
/// crate, no dependency edge), so the table is mirrored here. Any edit
/// to one side must mirror to the other. Order must match HOOK_EVENTS.
const HOOK_TOPIC_MAP: &[(&str, &str)] = &[
    ("SessionStart", "sage.v1.hook.session_start"),
    ("SessionEnd", "sage.v1.hook.session_end"),
    ("UserPromptSubmit", "sage.v1.hook.message_received"),
    ("PreToolUse", "sage.v1.hook.before_tool_call"),
    ("PostToolUse", "sage.v1.hook.after_tool_call"),
    ("Stop", "sage.v1.hook.message_sent"),
    ("SubagentStart", "sage.v1.hook.subagent_start"),
    ("SubagentStop", "sage.v1.hook.subagent_stop"),
    ("PreCompact", "sage.v1.hook.on_compaction_started"),
    ("PostCompact", "sage.v1.hook.on_compaction_completed"),
    ("Notification", "sage.v1.hook.notification"),
];

/// Lookup the `astrid-emit` topic for a Claude hook event.
fn hook_topic(event: &str) -> &'static str {
    HOOK_TOPIC_MAP
        .iter()
        .find_map(|(k, v)| if *k == event { Some(*v) } else { None })
        .expect("HOOK_EVENTS and HOOK_TOPIC_MAP must stay in sync")
}

/// Build the `hooks` block — identical in both interaction modes.
///
/// Each event invokes the `astrid-emit` native helper with the
/// sage-namespaced `sage.v1.hook.*` topic. `astrid-emit`
/// reads Claude's stdin hook payload, packages it into the envelope
/// shape sage's validator expects (hook, payload, correlation_id,
/// principal_id, session_id, token), and publishes on the bus.
///
/// Forward-compatible: `astrid-emit` ships separately in the core
/// distribution (filed at astrid#814). Until that binary lands the
/// `command` strings are inert — claude exec-spawns the helper, the
/// shell reports "not found", and Claude treats the hook as a no-op.
/// No change to this file is needed once the helper lands.
///
/// Unix assumption: this assumes a Unix `PATH` lookup for `astrid-emit`;
/// sage is Unix-only today (the `claude` binary, the HOME redirect, and
/// the `/bin/false` `apiKeyHelper` all assume Unix).
fn hooks_block() -> serde_json::Value {
    let mut hooks = serde_json::Map::new();
    for event in HOOK_EVENTS {
        let topic = hook_topic(event);
        hooks.insert(
            (*event).to_string(),
            serde_json::json!([
                {
                    "type": "command",
                    "command": format!("astrid-emit {topic}"),
                    "timeout": 10
                }
            ]),
        );
    }
    serde_json::Value::Object(hooks)
}

/// `.claude/settings.local.json` body for the given principal config.
///
/// ENFORCEABILITY: this authors `settings.local.json`, which is Claude's
/// **Local** settings tier — the WEAKEST, fully session-overridable tier
/// in Claude's precedence order (Managed > CLI args > Local > Project >
/// User). A capable session can edit any value here — the deny list, the
/// permission modes, `apiKeyHelper` — and Claude will honour the edit.
/// So nothing in this file is binding on its own.
///
/// The BINDING tool/permission gate is the spawn argv, which sits above
/// every on-disk file tier (only Managed, a fixed SYSTEM-path tier sage
/// cannot author, outranks it). See `sage::spawn::argv`: `--permission-mode
/// dontAsk` auto-denies any tool not allow-listed (fail-secure, no prompt),
/// `--sandbox` bounds Claude's native tools (under the Astrid host
/// sandbox), `--disallowedTools <REQUIRED_DENIES>` binds the escape-surface
/// deny, `--strict-mcp-config` + `--mcp-config` register the `astrid mcp
/// serve` MCP server for Astrid-specific ops, and `--no-session-persistence`
/// suppresses Claude's own JSONL. Those flags cannot be overridden from
/// within the session.
///
/// This file therefore serves two non-binding purposes:
/// * a redundant, defence-in-depth deny layer ([`REQUIRED_DENIES`]) that
///   only narrows the surface the argv already pins — useful while a
///   value still holds, never relied on as the boundary; and
/// * a carrier for two strings Claude reads only from a settings tier and
///   not from argv: the `apiKeyHelper` command path and the `hooks` block.
///   Both name external commands Claude execs; their integrity rests on
///   the commands themselves (and, for hooks, the per-spawn token sage's
///   validator checks), not on this file being tamper-proof.
///
/// Branching is driven by the two axes in [`PrincipalConfig`]:
///
/// * [`InteractionMode::Headless`]: sage drives the loop. The allow list
///   is [`NATIVE_ALLOW`] (Claude's dev tools + the sage MCP surface), the
///   escape surface in [`REQUIRED_DENIES`] is denied, `permissions.defaultMode`
///   is `dontAsk` (auto-deny the rest, no prompt), the `sandbox` block bounds
///   Claude's native tools, and `disableSkillShellExecution` blocks the skill
///   shell path.
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
/// disabled. Each event invokes `astrid-emit <topic>` (the native
/// helper shipping separately in core per astrid#814) so claude's
/// stdin-JSON subprocess hook protocol is bridged onto the
/// `sage.v1.hook.*` IPC topic. Sage's run-loop validator
/// then authenticates the per-(principal, session) spawn token and
/// republishes on canonical `hook.v1.event.*` (or
/// `sage.v1.notification` for the one event without a canonical
/// equivalent today). The `astrid-capsule-hook-bridge` WASM capsule
/// already maps lifecycle events to semantic hooks on the bus side.
pub(crate) fn settings_json(cfg: &PrincipalConfig) -> serde_json::Value {
    let (allow, deny, headless): (Vec<&str>, Vec<&str>, bool) = match cfg.interaction_mode {
        InteractionMode::Headless => (NATIVE_ALLOW.to_vec(), REQUIRED_DENIES.to_vec(), true),
        InteractionMode::Repl => (vec![], vec![], false),
    };

    let mut permissions = serde_json::json!({
        "allow": allow,
        "deny": deny,
    });
    if headless {
        // Fail-secure headless posture: a tool not in `allow` (and not a
        // read-only sandboxed Bash command) is auto-DENIED, never prompted
        // — a prompt would hang the terminal-less `-p` session. Mirrors the
        // binding `--permission-mode dontAsk` argv flag.
        permissions["defaultMode"] = serde_json::json!("dontAsk");
    }

    let mut root = serde_json::json!({
        "permissions": permissions,
        "hooks": hooks_block(),
        "cleanupPeriodDays": 30,
    });
    let obj = root
        .as_object_mut()
        .expect("settings root literal is a JSON object");

    if headless {
        // Claude's own Bash/file sandbox — a best-effort INNER layer under
        // the Astrid host sandbox. Writes are bounded to the working dir
        // (cwd = the principal HOME); `allowUnsandboxedCommands:false` stops
        // a command opting out. Network egress + sensitive-read denials
        // belong in the (un-overridable) managed tier; this overridable copy
        // only ever narrows, and if Claude's sandbox cannot initialise
        // nested inside the host sandbox the host sandbox still binds.
        obj.insert(
            "sandbox".to_string(),
            serde_json::json!({
                "enabled": true,
                "allowUnsandboxedCommands": false,
                "filesystem": { "allowWrite": ["./", "$TMPDIR"] }
            }),
        );
        // The skill subsystem can fan out to shell; `Skill` is denied, but
        // block its shell path defensively too.
        obj.insert(
            "disableSkillShellExecution".to_string(),
            serde_json::json!(true),
        );
    }
    if matches!(cfg.auth_mode, AuthMode::ApiKey) {
        obj.insert("apiKeyHelper".to_string(), serde_json::json!("/bin/false"));
    }
    root
}

/// `.claude/.mcp.json` body for the given principal config.
///
/// * [`InteractionMode::Headless`]: register the `sage` MCP server as
///   `astrid mcp serve --principal <principal_id>` — the stdio MCP server
///   that fronts the sage-mcp broker (unicity-astrid/astrid#880). claude
///   loads exactly this file via `--strict-mcp-config --mcp-config
///   .claude/.mcp.json` (see `sage::spawn`), does the native MCP
///   handshake, and discovers the `mcp__sage__*` tools from `tools/list`.
///   `principal_id` is the sanitised invoking principal, baked in so the
///   spawned server stamps the right identity on its broker requests:
///   `astrid mcp serve` does NOT infer it — absent `--principal` it falls
///   back to the active/default principal, which would mis-scope tools.
/// * [`InteractionMode::Repl`]: no sage-spawned `claude` subprocess
///   exists, so emit an empty `mcpServers` object. Users wiring native
///   MCP servers in repl mode edit this file themselves; sage doesn't
///   fight them.
pub(crate) fn mcp_json(cfg: &PrincipalConfig, principal_id: &str) -> serde_json::Value {
    match cfg.interaction_mode {
        InteractionMode::Headless => serde_json::json!({
            "mcpServers": {
                "sage": {
                    "command": "astrid",
                    "args": ["mcp", "serve", "--principal", principal_id],
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
            ..PrincipalConfig::default()
        }
    }

    fn assert_headless_shape(v: &serde_json::Value) {
        // Native-tools allow surface: the dev tools + the sage MCP server,
        // exactly NATIVE_ALLOW.
        let allow = v
            .pointer("/permissions/allow")
            .and_then(|x| x.as_array())
            .expect("permissions.allow must be a JSON array");
        for required in NATIVE_ALLOW {
            assert!(
                allow.iter().any(|a| a == required),
                "headless: allow list missing native tool '{required}'"
            );
        }
        assert_eq!(
            allow.len(),
            NATIVE_ALLOW.len(),
            "headless: allow list must be exactly NATIVE_ALLOW"
        );

        // The escape surface stays denied, exactly REQUIRED_DENIES — and a
        // native dev tool must never appear on BOTH lists.
        let deny = v
            .pointer("/permissions/deny")
            .and_then(|x| x.as_array())
            .expect("permissions.deny must be a JSON array");
        for required in REQUIRED_DENIES {
            assert!(
                deny.iter().any(|d| d == required),
                "headless: deny list missing escape tool '{required}'"
            );
        }
        assert_eq!(
            deny.len(),
            REQUIRED_DENIES.len(),
            "headless: deny list must contain exactly the escape surface"
        );
        for allowed in NATIVE_ALLOW {
            assert!(
                !deny.iter().any(|d| d == allowed),
                "headless: native tool '{allowed}' must not also be denied"
            );
        }

        // Fail-secure permission mode + Claude's inner sandbox, both pinned.
        assert_eq!(
            v.pointer("/permissions/defaultMode").and_then(|x| x.as_str()),
            Some("dontAsk"),
            "headless: permission defaultMode must be dontAsk (fail-secure)"
        );
        assert_eq!(
            v.pointer("/sandbox/enabled").and_then(|x| x.as_bool()),
            Some(true),
            "headless: Claude's sandbox must be enabled"
        );
        assert_eq!(
            v.pointer("/sandbox/allowUnsandboxedCommands")
                .and_then(|x| x.as_bool()),
            Some(false),
            "headless: a command must not be able to opt out of the sandbox"
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
        // Repl is the user's own environment — sage imposes no native-tools
        // posture: no dontAsk mode, no sandbox object.
        assert!(
            v.pointer("/permissions/defaultMode").is_none(),
            "repl: permission defaultMode must be omitted"
        );
        assert!(
            v.pointer("/sandbox").is_none(),
            "repl: sandbox object must be omitted"
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
            let command = entries[0]
                .pointer("/command")
                .and_then(|x| x.as_str())
                .unwrap_or_else(|| panic!("hooks.{event}: command must be a string"));
            assert!(
                command.starts_with("astrid-emit "),
                "hooks.{event}: command must start with 'astrid-emit ' (got {command:?})"
            );
            let expected_topic = hook_topic(event);
            assert!(
                command.ends_with(expected_topic),
                "hooks.{event}: command must end with topic {expected_topic:?} (got {command:?})"
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
        // (mode, auth) combinations, and wire each event through
        // `astrid-emit <topic>` with timeout=10 so sage's run-loop
        // validator receives the per-event hook envelope.
        for im in [InteractionMode::Headless, InteractionMode::Repl] {
            for am in [AuthMode::ApiKey, AuthMode::Subscription] {
                let v = settings_json(&cfg(im, am));
                assert_hooks_block_present(&v);
            }
        }
    }

    #[test]
    fn settings_never_emits_bin_true_placeholder() {
        // Regression guard: the pre-#814 no-op placeholder must never
        // reappear once the astrid-emit shim is wired in. Literal
        // assembled at runtime so a source-tree grep for the legacy
        // command reports zero matches; the v1 contract is "hooks emit
        // through astrid-emit, not the legacy placeholder".
        let legacy_command = format!("/bin/{}", "true");
        for im in [InteractionMode::Headless, InteractionMode::Repl] {
            for am in [AuthMode::ApiKey, AuthMode::Subscription] {
                let v = settings_json(&cfg(im, am));
                let hooks = v
                    .pointer("/hooks")
                    .and_then(|x| x.as_object())
                    .expect("hooks block must be a JSON object");
                for event in HOOK_EVENTS {
                    let entries = hooks
                        .get(*event)
                        .and_then(|x| x.as_array())
                        .unwrap_or_else(|| panic!("hooks.{event} must be a JSON array"));
                    for entry in entries {
                        let command = entry
                            .pointer("/command")
                            .and_then(|x| x.as_str())
                            .unwrap_or_else(|| {
                                panic!("hooks.{event}: command must be a string")
                            });
                        assert_ne!(
                            command, legacy_command,
                            "({im:?}, {am:?}) hooks.{event}: \
                             /bin/true placeholder must not be emitted"
                        );
                        assert!(
                            !command.contains(&legacy_command),
                            "({im:?}, {am:?}) hooks.{event}: \
                             command must not contain legacy /bin/true (got {command:?})"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn hook_events_and_topic_map_stay_in_sync() {
        // Defence-in-depth: the two source-of-truth tables for the
        // hook authoring contract must enumerate the same Claude
        // events, in the same order. A drift here would leave one
        // table referencing an event the other doesn't, silently
        // breaking the per-event topic lookup.
        assert_eq!(
            HOOK_EVENTS.len(),
            HOOK_TOPIC_MAP.len(),
            "HOOK_EVENTS and HOOK_TOPIC_MAP must enumerate the same events"
        );
        for (event, (k, _)) in HOOK_EVENTS.iter().zip(HOOK_TOPIC_MAP.iter()) {
            assert_eq!(event, k, "HOOK_EVENTS and HOOK_TOPIC_MAP must agree on order");
        }
        for (_, topic) in HOOK_TOPIC_MAP {
            assert!(
                topic.starts_with("sage.v1.hook."),
                "topic {topic:?} must live under sage.v1.hook.*"
            );
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
    fn mcp_headless_registers_sage_server() {
        for am in [AuthMode::ApiKey, AuthMode::Subscription] {
            let v = mcp_json(&cfg(InteractionMode::Headless, am), "alice");
            assert_eq!(
                v.pointer("/mcpServers/sage/command")
                    .and_then(|x| x.as_str()),
                Some("astrid"),
                "headless ({am:?}): the sage MCP server command must be `astrid`"
            );
            let args: Vec<&str> = v
                .pointer("/mcpServers/sage/args")
                .and_then(|x| x.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
                .unwrap_or_default();
            assert_eq!(
                args,
                vec!["mcp", "serve", "--principal", "alice"],
                "headless ({am:?}): sage server must be `astrid mcp serve --principal <id>` with the baked principal"
            );
        }
    }

    #[test]
    fn mcp_repl_mode_is_empty() {
        for am in [AuthMode::ApiKey, AuthMode::Subscription] {
            let v = mcp_json(&cfg(InteractionMode::Repl, am), "alice");
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
    // Cross-crate deny-list mirror — full-membership drift guard.
    // ------------------------------------------------------------------

    #[test]
    fn required_denies_equal_canonical_binding_mirror() {
        // Drift guard for the mirror with `sage::spawn::DENIED_TOOLS`
        // (sage/src/spawn.rs). No dependency edge exists between the two
        // crates (each is a `cdylib`-only workspace member, so neither can
        // import the other's const as a library), so the lists cannot be
        // `assert_eq!`d directly. Instead this pins `REQUIRED_DENIES`
        // against a FULL, independently-written canonical set — the same
        // canonical surface the spawn-side test
        // (`denied_tools_equal_canonical_required_denies`) pins
        // `DENIED_TOOLS` to. The pairing is load-bearing: `REQUIRED_DENIES`
        // rides only the overridable Local tier (`settings.local.json`), so
        // a name present here but dropped from `DENIED_TOOLS` is denied
        // only in the defeasible tier and never reaches the binding
        // `--disallowedTools` CLI tier. Anchoring BOTH lists to the same
        // canonical set means a one-sided add/drop/substitute fails the
        // build on at least one side, forcing the mirror back into
        // alignment. Stronger than a count anchor: a same-size substitution
        // (swap one tool for another) is caught here.
        //
        // SYNC: this canonical set MUST match the `CANONICAL` set in
        // sage::spawn::tests::denied_tools_equal_canonical_required_denies
        // (sage/src/spawn.rs) exactly.
        const CANONICAL: &[&str] = &[
            "PowerShell",
            "Agent",
            "Task",
            "Workflow",
            "SendMessage",
            "TeamCreate",
            "TeamDelete",
            "CronCreate",
            "CronDelete",
            "CronList",
            "ScheduleWakeup",
            "EnterPlanMode",
            "ExitPlanMode",
            "EnterWorktree",
            "ExitWorktree",
            "TaskCreate",
            "TaskGet",
            "TaskList",
            "TaskStop",
            "TaskUpdate",
            "TaskOutput",
            "PushNotification",
            "RemoteTrigger",
            "ShareOnboardingGuide",
            "ListMcpResourcesTool",
            "ReadMcpResourceTool",
            "ToolSearch",
            "WaitForMcpServers",
            "Skill",
            "SlashCommand",
        ];

        // Compare as sets so a pure reordering of either list (no semantic
        // effect — deny order is irrelevant) does not spuriously fail,
        // while any membership difference (add, drop, substitute) does.
        let actual: std::collections::BTreeSet<&str> =
            REQUIRED_DENIES.iter().copied().collect();
        let canonical: std::collections::BTreeSet<&str> =
            CANONICAL.iter().copied().collect();

        let missing: Vec<&str> = canonical.difference(&actual).copied().collect();
        let unexpected: Vec<&str> = actual.difference(&canonical).copied().collect();
        assert!(
            missing.is_empty() && unexpected.is_empty(),
            "REQUIRED_DENIES drifted from the canonical binding mirror.\n  \
             missing from REQUIRED_DENIES: {missing:?}\n  \
             unexpected in REQUIRED_DENIES: {unexpected:?}\n  \
             re-sync REQUIRED_DENIES with sage::spawn::DENIED_TOOLS.",
        );

        // Belt-and-braces: no duplicate collapsed the set below the list
        // length, which would mask a drift behind an equal-set comparison.
        assert_eq!(
            actual.len(),
            REQUIRED_DENIES.len(),
            "REQUIRED_DENIES contains a duplicate entry",
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
