//! Building the `claude -p` subprocess.
//!
//! Centralises the hardened argv + env we feed [`process::Command`].
//! Every flag here matters: dropping `--strict-mcp-config` smuggles in
//! `.mcp.json` from the redirected HOME; dropping `--tools ""` lets the
//! built-in Bash/Read/Write/Edit tools loose against the host
//! filesystem; etc.
//!
//! Enforcement lives in the argv on purpose. Claude's tier precedence is
//! `Managed > CLI args > Local (settings.local.json) > Project > User`.
//! CLI args are the only session-un-overridable tier reachable from
//! capsule-space — sage owns the full argv and execs `claude` directly,
//! so anything expressed as a flag here sits above every on-disk file
//! tier and a running session cannot edit it away. Two flags carry that
//! weight: `--disallowedTools` hoists the deny list out of the Local
//! tier (`settings.local.json`, fully session-overridable) into the
//! binding CLI tier, and `--setting-sources local` narrows on-disk tier
//! loading to just sage's own authored file so a stray `user`/`project`
//! settings file cannot dilute the posture. Managed and CLI flags always
//! load regardless of `--setting-sources`, so the narrowing only shrinks
//! the overridable surface; it never weakens the managed tier.

use astrid_sdk::prelude::*;
use sha2::{Digest, Sha256};

const CLAUDE_BIN: &str = "claude";

/// Built-in Claude tools denied at the CLI-args tier.
///
/// Claude's tier precedence is `Managed > CLI args > Local
/// (settings.local.json) > Project (settings.json) > User
/// (~/.claude/settings.json)`. CLI args are the only
/// session-un-overridable tier reachable from capsule-space: sage owns
/// the full argv and execs `claude` directly, so a deny passed here as
/// `--disallowedTools` sits above every on-disk file tier and a session
/// cannot edit it away mid-run. The same list also rides in
/// `settings.local.json` (sage-install's `REQUIRED_DENIES`) as
/// defense-in-depth, but that file is the *Local* tier — Claude's
/// weakest, fully session-overridable scope — so the file copy alone is
/// not binding. Hoisting it into argv is the genuine enforceable upgrade.
///
/// A bare tool name (no scope qualifier) removes the tool from the
/// model's context entirely. The rule is exhaustive by design: any
/// built-in that can act (file/shell/web/task), surface other tools, or
/// drive control flow outside the `mcp__sage__*` surface is denied so a
/// session cannot reach around the sandbox via a tool the list forgot.
///
/// SYNC: this list MUST be identical (same set) to
/// `sage_install::layout::REQUIRED_DENIES` (sage-install/src/layout.rs).
/// The two crates have no dependency edge (each sage crate is a
/// `cdylib`-only workspace member, so one cannot import the other's const
/// as a library without adding `rlib` to the producer's crate-type — a
/// build-profile change out of scope), so the list is mirrored here by
/// hand — same arrangement as the `HOOK_TOPIC_MAP` mirror. The mirror is
/// load-bearing, not cosmetic: `REQUIRED_DENIES` rides only the fully
/// session-overridable Local tier (`settings.local.json`), so a tool
/// denied there but ABSENT here is not actually blocked — a capable
/// session edits it out of the Local file and calls it. Only the names
/// that appear in THIS list reach the binding `--disallowedTools` CLI
/// tier. Any edit to either list must mirror to the other; the
/// [`denied_tools_equal_canonical_required_denies`] test pins this copy
/// against an independently-written canonical set (full membership, not
/// just count) so a name added to or dropped from either side fails the
/// build, and the per-name presence on the Local-tier copy is asserted in
/// sage-install's `assert_headless_shape`.
const DENIED_TOOLS: &[&str] = &[
    // File / shell / web — the core action surface. `PowerShell` is a
    // Bash-equivalent shell on its own tool name; `LSP` drives a language
    // server that can read/edit; `Monitor` runs a command in the
    // background under Bash-equivalent semantics — none are covered by
    // denying `Bash` alone.
    "Bash",
    "PowerShell",
    "Read",
    "Write",
    "Edit",
    "MultiEdit",
    "NotebookEdit",
    "WebFetch",
    "WebSearch",
    "Glob",
    "Grep",
    "LSP",
    "Monitor",
    // Background-shell control: `Bash` is denied, but these address
    // shells by id and must not remain reachable on their own.
    "BashOutput",
    "KillShell",
    // Agent / sub-agent spawning and orchestration — the highest-value
    // escape: a spawned agent or workflow runs its own tool calls and
    // could reach a capability this session is denied. `Agent` is the
    // current name; `Task` is the legacy alias for the same surface.
    "Agent",
    "Task",
    "Workflow",
    "SendMessage",
    "TeamCreate",
    "TeamDelete",
    // Scheduling / control flow — anything that can queue a future
    // prompt, reschedule a loop, or drive plan-mode / worktree
    // transitions outside sage's run loop.
    "CronCreate",
    "CronDelete",
    "CronList",
    "ScheduleWakeup",
    "EnterPlanMode",
    "ExitPlanMode",
    "EnterWorktree",
    "ExitWorktree",
    // Task-list surface — created/queried/stopped tasks are control flow
    // that bypasses sage's loop; deny the whole family.
    "TaskCreate",
    "TaskGet",
    "TaskList",
    "TaskStop",
    "TaskUpdate",
    "TaskOutput",
    "TodoWrite",
    // External / exfiltration surfaces — push notifications, remote
    // routine triggers on claude.ai, and the onboarding-guide upload all
    // reach off-host channels sage does not mediate.
    "PushNotification",
    "RemoteTrigger",
    "ShareOnboardingGuide",
    // MCP resource + tool-loading surfaces: reading raw MCP resources or
    // loading deferred tools is a way back to a capability the curated
    // `mcp__sage__*` allow list does not expose. `ListMcpResourcesTool`
    // and `ReadMcpResourceTool` carry the `Tool` suffix in the current
    // reference.
    "ListMcpResourcesTool",
    "ReadMcpResourceTool",
    "ToolSearch",
    "WaitForMcpServers",
    // Indirect-execution surfaces: a slash command or a skill can run
    // shell / arbitrary tools. `SlashCommand` is the legacy alias for the
    // skill surface; deny both.
    "Skill",
    "SlashCommand",
];

/// Inputs for [`spawn_claude`].
pub(crate) struct SpawnInputs<'a> {
    /// Principal that owns this session. Threaded into the child env as
    /// `ASTRID_PRINCIPAL_ID` so the `astrid-emit` hook helper can stamp
    /// it on outgoing `sage.v1.hook.*` events. Sage's run
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
    /// forged `sage.v1.hook.*` publishes. Always present
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
        // Constrain which on-disk setting tiers load to `local` only —
        // the scope of the `settings.local.json` sage-install authors
        // (`local` = `.claude/settings.local.json`, which under the HOME
        // redirect resolves to sage's authored file). This excludes the
        // `user` (`~/.claude/settings.json`) and `project`
        // (`.claude/settings.json`) tiers so a stray file in either —
        // dropped into the redirected HOME or the project dir — cannot
        // dilute sage's posture by injecting allow rules or flipping a
        // permission mode. Managed (system/MDM) and CLI flags always
        // load regardless of this list, so this only NARROWS the
        // overridable file surface; it cannot weaken the managed tier.
        // sage's hooks block has no CLI-flag form, so `local` must stay
        // in the list for the `astrid-emit` hook wiring to load.
        "--setting-sources".to_string(),
        "local".to_string(),
        // Disable every built-in tool. Tool surface is exclusively
        // mcp__sage__* (which sage parses inline; claude only sees the
        // tool names through --append-system-prompt for now).
        "--tools".to_string(),
        String::new(),
        "--allowed-tools".to_string(),
        "mcp__sage__*".to_string(),
        // Hoist the deny list into the CLI-args tier. The same names
        // also ride in `settings.local.json` (the Local tier, fully
        // session-overridable) as defense-in-depth, but a CLI deny sits
        // above every on-disk file tier in Claude's precedence
        // (`Managed > CLI args > Local > Project > User`) — a session
        // cannot edit a process-argv flag, so this is the binding,
        // session-un-overridable copy. Bare tool names remove each tool
        // from the model's context entirely. See [`DENIED_TOOLS`].
        "--disallowedTools".to_string(),
        DENIED_TOOLS.join(" "),
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
        // onto every `sage.v1.hook.*` publish. Sage's run
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
    ///
    /// The enforcement flags added to the argv (`--disallowedTools`,
    /// `--setting-sources`) are likewise built from neither the auth
    /// mode nor any per-spawn secret, so adding them does not perturb
    /// this invariant: the digest stays stable across auth modes, only
    /// its value changed (a deliberate fingerprint update — see
    /// [`argv_carries_tier_narrowing_enforcement`]).
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

    /// The argv must carry the two session-un-overridable enforcement
    /// levers reachable from capsule-space: `--disallowedTools` (the deny
    /// list hoisted into the binding CLI tier) and `--setting-sources
    /// local` (on-disk tier narrowing). Both ride above every on-disk
    /// file tier in Claude's precedence, so a running session cannot edit
    /// them away. Dropping either silently regresses enforcement back to
    /// the fully session-overridable `settings.local.json` posture, so
    /// pin their presence.
    #[test]
    fn argv_carries_tier_narrowing_enforcement() {
        let args = argv("sid", "home://.claude/.sage-identity-sid");

        // `--setting-sources local`: the value must be exactly `local`
        // (the scope of sage's authored settings.local.json). `user` or
        // `project` would either drop sage's own hook wiring or readmit a
        // stray settings file — both regressions.
        let ss = args
            .iter()
            .position(|a| a == "--setting-sources")
            .expect("argv must pass --setting-sources to narrow on-disk tiers");
        assert_eq!(
            args.get(ss + 1).map(String::as_str),
            Some("local"),
            "--setting-sources must be `local` — the scope of sage's settings.local.json",
        );

        // `--disallowedTools`: the deny list rides the CLI tier. The
        // value is the space-joined DENIED_TOOLS list, so a session
        // cannot override it from any on-disk file.
        let dt = args
            .iter()
            .position(|a| a == "--disallowedTools")
            .expect("argv must pass --disallowedTools to bind the deny list");
        let joined = args
            .get(dt + 1)
            .expect("--disallowedTools must carry a value");
        assert_eq!(joined, &DENIED_TOOLS.join(" "));
        // Spot-check the load-bearing escape tools are individually
        // present in the rendered BINDING value. These are the names a
        // capable session would reach for to break out of the
        // `mcp__sage__*` sandbox — `Agent`/`Workflow` (sub-agent spawn,
        // the highest-value escape), `PowerShell`/`Monitor` (Bash-
        // equivalent shells the plain `Bash` deny does not cover),
        // `ListMcpResourcesTool`/`ReadMcpResourceTool` (raw MCP resource
        // reads around the curated allow list) — alongside the original
        // action surface. A deny that lands only in the overridable
        // `settings.local.json` (REQUIRED_DENIES) but not here is NOT
        // binding, so pin each one in argv.
        for tool in [
            "Bash",
            "PowerShell",
            "Read",
            "Write",
            "Edit",
            "WebFetch",
            "Task",
            "Agent",
            "Workflow",
            "Monitor",
            "ListMcpResourcesTool",
            "ReadMcpResourceTool",
        ] {
            assert!(
                joined.split(' ').any(|t| t == tool),
                "deny list must include {tool}",
            );
        }
    }

    /// `DENIED_TOOLS` mirrors `sage_install::layout::REQUIRED_DENIES`
    /// across a crate boundary with no dependency edge. Guard the local
    /// copy's shape so an accidental trim is caught here: every entry is
    /// a bare tool name (no scope qualifier — a bare name removes the
    /// tool from context, a scoped rule like `Bash(rm *)` would only
    /// deny matching calls and leave the tool reachable), and there are
    /// no duplicates. The exhaustiveness contract itself is asserted in
    /// sage-install's tests against the settings.local.json deny array.
    #[test]
    fn denied_tools_are_bare_unscoped_names() {
        let mut seen = std::collections::HashSet::new();
        for t in DENIED_TOOLS {
            assert!(
                !t.contains('(') && !t.contains(' ') && !t.is_empty(),
                "{t} must be a bare unscoped tool name",
            );
            assert!(seen.insert(*t), "{t} is duplicated in DENIED_TOOLS");
        }
    }

    /// Drift guard for the cross-crate mirror with
    /// `sage_install::layout::REQUIRED_DENIES`.
    ///
    /// No dependency edge exists between the two crates (each is a
    /// `cdylib`-only workspace member, so neither can import the other's
    /// const as a library), so the lists cannot be `assert_eq!`d
    /// directly. Instead this test pins `DENIED_TOOLS` against a FULL,
    /// independently-written canonical set — the exhaustive headless deny
    /// surface. This is deliberately stronger than a count anchor: a count
    /// check passes whenever the two lists merely have the same length,
    /// so swapping one tool for another (same count, different members)
    /// would slip through. Comparing the whole set catches additions,
    /// removals, AND substitutions.
    ///
    /// The matching guard on the other side of the mirror lives in
    /// sage-install's `assert_headless_shape`, which asserts every
    /// `REQUIRED_DENIES` member appears in the authored `settings.local.json`
    /// deny array and that the array length equals `REQUIRED_DENIES.len()`.
    /// Together the two guards anchor both copies to the same canonical
    /// surface: a name added to or dropped from either list, without the
    /// mirror edit, fails the build on at least one side.
    ///
    /// SYNC: when you add/remove a denied tool, update this canonical set
    /// AND `REQUIRED_DENIES` (sage-install/src/layout.rs) in lockstep.
    #[test]
    fn denied_tools_equal_canonical_required_denies() {
        // The canonical headless deny surface — every built-in Claude tool
        // that must be blocked so `mcp__sage__*` is the SOLE reachable
        // surface. Independently written (not derived from DENIED_TOOLS) so
        // it is a genuine cross-check, not a tautology. MUST match
        // `sage_install::layout::REQUIRED_DENIES` exactly.
        const CANONICAL: &[&str] = &[
            "Bash",
            "PowerShell",
            "Read",
            "Write",
            "Edit",
            "NotebookEdit",
            "WebFetch",
            "WebSearch",
            "Glob",
            "Grep",
            "LSP",
            "Monitor",
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
            "TodoWrite",
            "PushNotification",
            "RemoteTrigger",
            "ShareOnboardingGuide",
            "ListMcpResourcesTool",
            "ReadMcpResourceTool",
            "ToolSearch",
            "WaitForMcpServers",
            "Skill",
            "SlashCommand",
            "MultiEdit",
            "BashOutput",
            "KillShell",
        ];

        // Compare as sets so a pure reordering of either list (which has no
        // semantic effect — `--disallowedTools` is order-insensitive) does
        // not spuriously fail, while any membership difference (add, drop,
        // or substitute) does.
        let actual: std::collections::BTreeSet<&str> = DENIED_TOOLS.iter().copied().collect();
        let canonical: std::collections::BTreeSet<&str> = CANONICAL.iter().copied().collect();

        // Surface the exact drift on failure so the fix is obvious.
        let missing: Vec<&str> = canonical.difference(&actual).copied().collect();
        let unexpected: Vec<&str> = actual.difference(&canonical).copied().collect();
        assert!(
            missing.is_empty() && unexpected.is_empty(),
            "DENIED_TOOLS drifted from the canonical REQUIRED_DENIES mirror.\n  \
             missing from DENIED_TOOLS (denied only in the overridable Local tier, \
             NOT in the binding CLI tier): {missing:?}\n  \
             unexpected in DENIED_TOOLS (not in canonical set): {unexpected:?}\n  \
             re-sync DENIED_TOOLS with sage_install::layout::REQUIRED_DENIES.",
        );

        // Belt-and-braces: no duplicate collapsed the set below the list
        // length, which would mask a drift behind an equal-set comparison.
        assert_eq!(
            actual.len(),
            DENIED_TOOLS.len(),
            "DENIED_TOOLS contains a duplicate entry",
        );
    }
}
