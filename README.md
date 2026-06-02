# sage

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![MSRV: 1.94](https://img.shields.io/badge/MSRV-1.94-blue)](https://www.rust-lang.org)

**The Anthropic Claude integration for [Astrid OS](https://github.com/unicity-astrid/astrid).** Powered by Claude.

Sage is the runtime bridge that lets Astrid host Claude as a first-class agent — capability-gated, audit-trailed, identity-decoupled from the model. The user-facing agent has its own identity (configured via `capsule-identity` / `spark`); Claude is the engine underneath.

## What's in this repo

This is a multi-capsule bundle. Four wasm components ship together as a single Astrid distro:

| Crate | Role |
|-------|------|
| `sage` | Supervises `claude -p` headless subprocesses (one per session, ≤4 per principal). Streams stdin/stdout, parses Claude's stream-json, dispatches tool-call events to the bus, feeds results back. |
| `sage-completion` | Direct Anthropic Messages API LLM provider. Implements `astrid:llm@1.0.0`. For per-turn completions when Astrid is driving the agent loop. |
| `sage-mcp` | MCP tool bridge. Picks up `sage.v1.tool.call.*` events from `sage`, validates args + capabilities, dispatches via `tool.v1.*` capsule IPC, publishes results back. |
| `sage-install` | Provisioner. `astrid sage install` walks the user through per-principal `HOME`-isolated Claude setup. |

## Two billing paths

- **Agent mode** (`sage` crate): `claude -p` runs Claude's own agent loop. Burns the Anthropic Agent SDK credit on Pro/Max subscriptions ($20 / $100 / $200/mo respectively as of June 15, 2026).
- **Completion mode** (`sage-completion` crate): direct Anthropic API per-turn. Burns API usage credits, separate from the Agent SDK credit. Used when Astrid drives the loop and wants per-turn model routing.

`capsule-router` picks per-turn — Sonnet/Haiku via completion mode for routine work, Opus via either mode only when reasoning depth warrants it.

## Interaction modes

Sage exposes two orthogonal per-principal axes. The first picks **who drives `claude`**:

- **headless** (default) — Astrid spawns `claude -p` from the `sage` capsule and owns the agent loop. Tool surface is locked to `mcp__sage__*` (sage parses `tool_use` blocks out of stream-json and routes them via the bus). All native Claude Code tools (`Bash`, `Read`, `Write`, `Edit`, `WebFetch`, …) are denied. This is the recommended mode for unattended / multi-user / production deployments — every tool dispatch is auditable and capability-gated through Astrid.
- **repl** — the operator runs `claude` directly inside the principal folder (`~/.astrid/home/<principal>/`). Sage refuses to spawn (publishes `sage.v1.event.session_rejected{reason:"interaction_mode_is_repl"}` on `sage.v1.request.spawn`). The deny list is empty so the user has full access to the native Claude Code tool set; sage's MCP surface is not wired (the in-process `mcp__sage__*` bridge requires sage to own the subprocess). Hooks are still declared in `settings.local.json` so a future native hook bridge can audit/police the session without re-shipping the file (see [Known deficiency #6](#known-deficiencies)).

### Headless usage

```bash
astrid capsule install sage          # operator picks interaction_mode=headless, auth_mode=api_key
astrid sage install <principal>      # provisions ~/.astrid/home/<principal>/.claude/
astrid sage spawn <principal>        # sage publishes sage.v1.request.spawn; supervisor returns a session id
astrid sage send <session-id> "hi"   # writes a user turn into the running claude -p stdin
```

### REPL usage

```bash
astrid capsule install sage          # operator picks interaction_mode=repl
astrid sage install <principal>      # provisions ~/.astrid/home/<principal>/.claude/ (hooks declared, deny list empty)
cd ~/.astrid/home/<principal>        # then drive claude directly:
HOME="$PWD" claude
```

### Switching modes at runtime

Publish a `sage.v1.request.settings.set` IPC envelope. Sage owns `kv://sage.principal.config` (the canonical source of truth) and re-emits `sage.v1.install.relink` so `sage-install` rewrites the on-disk `.claude/settings.local.json` + `.mcp.json` with the new shape. On a successful relink, sage publishes `sage.v1.settings.changed` for downstream subscribers (dashboards, audit sinks). Audit trail is `sage.v1.audit.settings_changed{previous_config, new_config}`. Topic shapes are in the [topic contract](#v1-ipc-topic-contract) below.

```jsonc
// publish on sage.v1.request.settings.set
{ "principal_id": "alice", "interaction_mode": "repl" }                 // headless -> repl
{ "principal_id": "alice", "auth_mode": "subscription" }                // api_key -> subscription
{ "principal_id": "alice", "interaction_mode": "headless", "auth_mode": "api_key" }  // full reset
```

Absent fields are preserved (partial-patch semantics). The merged record is validated before persistence; an out-of-range `schema_version` is rejected.

## Authentication modes

The second axis picks **how `claude` authenticates against Anthropic**:

- **api_key** (default) — sage reads the per-principal `api_key` secret (kernel-elicited at install time from `Capsule.toml [env]`, stored in the host SecretStore, surfaced as the capsule's runtime config) and exports it as `ANTHROPIC_API_KEY` in the `claude` child env on every spawn. `apiKeyHelper` is pinned to `/bin/false` in `settings.local.json` so Claude cannot fall back to ambient credentials. Each principal carries an independent key — full cryptographic isolation.
- **subscription** — sage never sets `ANTHROPIC_API_KEY` and omits the `apiKeyHelper` pin so Claude can fall back to its keychain OAuth credential path. The operator runs `claude /login` **manually inside the principal folder** (sage explicitly never invokes `/login`). This unlocks the Anthropic Pro / Max subscription billing path that the Agent SDK is gated on.

The operator selects both axes at `astrid capsule install sage` time. The `api_key` secret is offered unconditionally (the kernel walks every `[env]` key — there is no `when=` semantics today); subscription-mode operators **leave the secret prompt blank**, and empty values are not persisted.

### macOS Keychain caveat

`claude /login` on macOS writes OAuth tokens to a keychain entry keyed by **service+account**, NOT by `HOME`. Two principal folders on the same macOS user account share that credential — **subscription mode does NOT cryptographically isolate principals on macOS**. For full per-principal isolation on macOS, either:

- use `api_key` mode (each principal gets its own `SecretStore`-encrypted key), or
- run principals under separate macOS user accounts.

Linux is unaffected — libsecret is namespaced by user session. Sage explicitly **never invokes `claude /login`** in either mode; subscription users run it manually inside the principal folder out-of-band.

## Writing a capsule that extends Claude

Any capsule that subscribes to `tool.v1.request.describe` and `tool.v1.execute.<name>` becomes a `mcp__sage__<name>` tool from Claude's perspective when headless mode is active. The `#[capsule]` + `#[astrid::tool]` macros generate the IPC plumbing, so authors write idiomatic Rust handlers:

```toml
# capsules/<your-capsule>/Capsule.toml
[package]
name = "my-cool-capsule"
version = "0.1.0"
astrid-version = ">=0.7.0"

[[component]]
id = "my-cool"
file = "my_cool_capsule.wasm"
type = "executable"

[capabilities]
fs_read = ["cwd://"]   # whatever your tool actually needs

[publish]
"tool.v1.response.describe.*" = {}
"tool.v1.execute.*.result"    = {}

[subscribe]
"tool.v1.request.describe" = { handler = "tool_describe" }
"tool.v1.execute.greet"    = { handler = "tool_execute_greet" }
```

```rust
// capsules/<your-capsule>/src/lib.rs
use astrid_sdk::prelude::*;
use astrid_sdk::schemars;
use serde::Deserialize;

#[derive(Default)]
pub struct MyCool;

#[derive(Debug, Default, Deserialize, schemars::JsonSchema)]
pub struct GreetArgs {
    /// Who to greet.
    pub name: String,
}

#[capsule]
impl MyCool {
    /// Greet a person by name. Returns the greeting string.
    #[astrid::tool("greet")]
    pub fn greet(&self, args: GreetArgs) -> Result<String, SysError> {
        Ok(format!("Hello, {}!", args.name))
    }
}
```

Install the capsule, run `astrid sage spawn <principal>`, and Claude sees `mcp__sage__greet` in its tool list. End-to-end flow: sage-mcp fans out `tool.v1.request.describe`, collates responses into `sage.v1.tools.list`, and bridges Claude's `tool_use` blocks onto `tool.v1.execute.<name>` (with a 50 s deadline). The tool descriptor's doc-comment becomes the description Claude sees; `inputSchema` is derived from `GreetArgs` via `schemars`.

## v1 IPC topic contract

All topics follow the `<domain>.<v1>.<kind>.<verb>[.<discriminator>]` convention. Trailing `*` is a single-segment wildcard (correlation id or session id).

Two flavours of subscribe exist in the bundle:
- **Manifest-declared** — listed in the crate's `Capsule.toml` `[subscribe]` block, dispatched by the host to a named handler function.
- **Runtime-subscribed** — opened from the supervisor `#[astrid::run]` loop via `ipc::subscribe(...)` and drained per tick. These are documented inline with each table and flagged "(runtime)".

The same distinction applies to publishes: anything not covered by the `[publish]` block's wildcard pattern is flagged "(runtime)" in the table. See [Known deficiency #5](#known-deficiencies) for the open manifest-reconciliation work.

### `sage` (agent runner)

| Direction | Topic | Payload |
|---|---|---|
| Subscribe | `sage.v1.request.spawn` | `{principal_id: String, session_id?: String, initial_message?: String}` |
| Subscribe | `sage.v1.request.send.<sid>` | `{session_id: String, text: String}` (single user turn, ≤1 MiB) |
| Subscribe | `sage.v1.request.settings.set` | `{principal_id, interaction_mode?, auth_mode?}` (partial-patch; absent fields preserved) |
| Subscribe | `sage.v1.tool.result.<call_id>` | `{content: String, isError: bool}` (write-back from sage-mcp) |
| Subscribe (runtime) | `sage.v1.request.stop.<sid>` | `{}` — graceful termination request |
| Subscribe (runtime) | `tool.v1.execute.save_identity.result` | `{success: bool, principal_id?: String}` — identity refresh trigger |
| Subscribe (runtime) | `approval.v1.response.<call_id>` | `{allowed: bool, reason?: String}` — capability-approval verdict |
| Subscribe (runtime) | `sage.v1.install.complete` | `{principal_id, success: bool, ...}` (awaited from `ensure_install`) |
| Publish | `sage.v1.event.<sid>.spawned` | `{principal_id, session_id, pid}` |
| Publish | `sage.v1.event.<sid>.init` | `{session_id, model, cwd, tools: [String]}` |
| Publish | `sage.v1.event.<sid>.text` | `{delta: String}` |
| Publish | `sage.v1.event.<sid>.done` | `{usage: Usage, is_error: bool, permission_denials: [String]}` |
| Publish | `sage.v1.event.<sid>.exited` | `{exit_code?: i32, signal?: i32, reason?: String, stdout_tail?: String, stderr_tail?: String}` |
| Publish | `sage.v1.event.<sid>.respawned` | `{principal_id, reason: "identity_refresh", flags_hash}` |
| Publish | `sage.v1.event.<sid>.error` | `{reason: String}` (e.g. `stdin_quota`, `api_key_missing`) |
| Publish | `sage.v1.event.session_rejected` | `{reason: "principal_limit" \| "interaction_mode_is_repl" \| ...}` |
| Publish | `sage.v1.tool.call.<call_id>` | `{session_id, principal_id, tool_name, arguments: JSON}` |
| Publish | `sage.v1.install.relink` | `{principal_id, config: PrincipalConfig}` (sage publishes on settings.set; sage-install rewrites the on-disk JSON) |
| Publish | `sage.v1.settings.changed` | `{principal_id, config: PrincipalConfig, schema_version}` (emitted after sage-install confirms the rewrite) |
| Publish (runtime) | `sage.v1.audit.spawn` | `{principal_id, session_id, pid, flags_hash, auth_mode, interaction_mode}` |
| Publish (runtime) | `sage.v1.audit.tool_call` | `{principal_id, session_id, call_id, tool_name, allowed: bool, decision_source}` |
| Publish (runtime) | `sage.v1.audit.identity_fallback` | `{principal_id, session_id, reason: String}` |
| Publish (runtime) | `sage.v1.audit.install_choices` | `{interaction_mode, auth_mode}` (emitted from `#[astrid::install]`) |
| Publish (runtime) | `sage.v1.audit.settings_changed` | `{principal_id, previous_config, new_config}` |
| Publish (runtime) | `sage.v1.install.run` | `{principal_id, config?: PrincipalConfig}` (awakens `sage-install` from `ensure_install`) |

### `sage-mcp` (tool bridge)

| Direction | Topic | Payload |
|---|---|---|
| Subscribe | `sage.v1.tool.call.<call_id>` | mirror of sage publish |
| Subscribe | `sage.v1.tools.describe` | `{}` (trigger describe-collect) |
| Subscribe | `tool.v1.response.describe.*` | `{tools: [ToolDescriptor]}` (fan-in cache) |
| Publish | `sage.v1.tool.result.<call_id>` | `{content: String, isError: bool}` |
| Publish | `sage.v1.tools.list` | `{tools: [McpToolDescriptor]}` |
| Publish | `tool.v1.request.describe` | `{}` (broadcast describe-collect) |
| Publish | `tool.v1.execute.<name>` (single) and `tool.v1.execute.<ns>.<name>` (dotted) | `{type: "tool_execute_request", call_id, tool_name, arguments}` |

### `sage-completion` (LLM provider)

| Direction | Topic | Payload |
|---|---|---|
| Subscribe | `llm.v1.request.describe` | `{}` |
| Subscribe | `llm.v1.request.generate.sage` | `IpcPayload::LlmRequest { request_id, model, messages, tools, system, ... }` |
| Publish | `llm.v1.response.describe` | `{providers: [ProviderEntry]}` |
| Publish | `llm.v1.response.describe.*` | `{providers: [ProviderEntry]}` (correlation-routed) |
| Publish | `llm.v1.stream.sage` | `IpcPayload::LlmStreamEvent { request_id, event: StreamEvent }` |

`StreamEvent` variants emitted: `TextDelta`, `ToolCallStart{id,name}`, `ToolCallDelta{id,args_delta}` (opaque partial JSON, never per-chunk parsed), `ToolCallEnd{id}`, `Usage{input_tokens,output_tokens}` (cumulative, once at end), `Done`, `Error(msg)`.

### `sage-install` (provisioner)

| Direction | Topic | Payload |
|---|---|---|
| Subscribe | `sage.v1.install.run` | `{principal_id, force?: bool, config?: PrincipalConfig}` |
| Subscribe | `sage.v1.install.relink` | `{principal_id, config?: PrincipalConfig}` |
| Publish | `sage.v1.install.status` | `{principal_id, step: String}` |
| Publish | `sage.v1.install.complete` | `{principal_id, success: bool, error?: String}` |
| Publish | `sage.v1.audit.settings_changed` | `{principal_id, previous_config, new_config}` (emitted after every relink-confirmed rewrite) |

Also publishes one-shot `spark.v1.request.build` and reads `spark.v1.response.ready` for identity injection per session (per-session-id `.sage-identity-<sid>` file written atomically to the principal's `.claude/`).

## Known deficiencies

1. **`.mcp.json` is a stub, not a real MCP server.** Claude expects to fork-exec the MCP server as a native subprocess; shipping such a binary requires host-side kernel work (an `astrid-mcp-shim` native binary) that is out of scope for the capsules-only Sage workspace. v1 ships with `.claude/.mcp.json` containing `{"mcpServers":{"sage":{"command":"/bin/false","args":[],"env":{}}}}` — the documented stub. Claude's tool surface still works because (a) `--allowed-tools mcp__sage__*` gates the surface, (b) `sage` parses `tool_use` content blocks directly out of `claude -p`'s `--output-format stream-json` and routes them via the bus, (c) `--append-system-prompt-file` enumerates available tools so Claude knows what to call. When the kernel ships a native `astrid-mcp-shim` binary, `sage-install` will rewrite `.mcp.json` to point at it (additive change, no IPC contract churn). **Flagged gap** — tracked outside this workspace.
2. **No native MCP tools/list response.** Because of (1), Claude never sees a real MCP `tools/list` — the `--append-system-prompt-file` enumeration is the surrogate. Tool descriptions surface through that channel rather than the protocol-level `tools/list` call.
3. **Authentication is per-principal and dual-mode; macOS subscription mode is not isolated.** Sage supports two auth modes, configured per-principal at `astrid capsule install sage` time via `Capsule.toml [env]`:
   - **api_key** — the kernel elicits the `api_key` secret, persists it in the host `SecretStore`, and injects it as the capsule's runtime config. Sage reads it back via `astrid_sdk::env::var("api_key")` at spawn time and exports it as `ANTHROPIC_API_KEY` in the `claude` child env. `apiKeyHelper` is pinned to `/bin/false` in `settings.local.json` so Claude cannot fall back to ambient credentials. Each principal carries an independent key — full cryptographic isolation.
   - **subscription** — sage never sets `ANTHROPIC_API_KEY` and omits the `apiKeyHelper` pin. The operator runs `claude /login` manually inside the principal folder. **On macOS**, `claude /login` writes OAuth tokens to a keychain entry keyed by service+account, NOT by HOME — two principal folders on the same macOS user account share that credential, so subscription mode does NOT cryptographically isolate principals on macOS. Use api_key mode (or separate macOS users) for full isolation. Linux libsecret is namespaced by user session and is unaffected. Sage explicitly never invokes `claude /login` — operators run it manually.

   See the [Authentication modes](#authentication-modes) section above for the full walkthrough and the macOS caveat.
4. **Pre-#752 register-only describe.** `sage-completion` publishes to both `llm.v1.response.describe` (unsuffixed; legacy registry drain) and `llm.v1.response.describe.*` (correlation-routed; post-#752). Drop the unsuffixed publish once every consumer is on post-#752.
5. **Manifest publish/subscribe surfaces narrower than runtime.** `sage/Capsule.toml` declares `sage.v1.event.*` and `sage.v1.tool.call.*` publishes plus the four handler-bound subscribes (`sage.v1.request.spawn`, `sage.v1.request.send.*`, `sage.v1.request.settings.set`, `sage.v1.tool.result.*`). At runtime the supervisor additionally opens `ipc::subscribe` for `sage.v1.request.stop.*`, `tool.v1.execute.save_identity.result`, `approval.v1.response.*`, and `sage.v1.install.complete`, and publishes to `sage.v1.audit.*` and `sage.v1.install.run`. Once host enforcement of manifest `[publish]/[subscribe]` against runtime calls lands, these need to either be declared in `Capsule.toml` or converted to handler-bound subscribes. Until then the topic-contract table above is the source of truth — the `(runtime)` markers flag every gap.
6. **Native `astrid-emit` binary does not exist yet.** `sage-install` authors `settings.local.json` with `astrid-emit --topic sage.v1.hook.<name>` commands for every Claude hook event, and sage's run-loop validator is fully wired and ready to consume them (see the [Hook Event Validation](#hook-event-validation) section above). The shim binary itself ships separately — tracked at [`unicity-astrid/astrid#814`](https://github.com/unicity-astrid/astrid/issues/814). Until it lands, Claude exec's a non-existent command on every hook fire and the event never reaches the bus; this degrades sage's observability but does not break the spawn flow (Claude treats the missing command as a non-blocking error per its protocol). When `astrid-emit` lands, hook events start flowing with **zero further sage changes required** — the sage-side contract is forward-compatible by design. Sage is also **Unix-only** today (the `claude` binary, the HOME redirect, the `/bin/false` `apiKeyHelper`, and the eventual `astrid-emit` invocation all assume Unix). **Flagged gap** — binary tracked outside this workspace; capability-token hardening tracked in [`rfcs#30`](https://github.com/unicity-astrid/rfcs/pull/30).
7. **Sage-side audit topics are not yet mirrored to a shared cross-capsule audit topic.** Sage publishes `sage.v1.audit.*` (spawn, tool_call, identity_fallback, install_choices, settings_changed, respawn_abandoned). The kernel-side `astrid.v1.audit.entry` is admin-action-shaped (method / required_capability / target_principal) and is not the right home for capsule-emitted attribution events. Establishing a shared cross-capsule audit namespace (`audit.v1.event` or equivalent) is RFC-class work, deferred. The TODO is present at every audit publish site in `sage` and `sage-install` source.

## Hook Event Validation

Claude Code hooks are configured in `settings.local.json` with a `command` string that Claude fork-execs with the hook payload piped over stdin. Sage uses a **sage-as-validator** model to bring those subprocess invocations onto the audited IPC bus without granting the hook subprocess a kernel principal of its own.

### The validation chain

1. **Native emit (`astrid-emit`)** — a host-side binary (shipping separately in core via [astrid#814](https://github.com/unicity-astrid/astrid/issues/814)) is configured as the hook `command` by `sage-install`. On invocation, `astrid-emit` reads the hook stdin payload, base64-encodes it, and publishes on `sage.v1.hook.<name>` with an envelope carrying `hook`, `payload`, `correlation_id: null`, plus three transport fields lifted from its env: `principal_id` (from `ASTRID_PRINCIPAL_ID`), `session_id` (from `ASTRID_SESSION_ID`), and `token` (from `ASTRID_HOOK_TOKEN`).
2. **Per-session token mint** — when sage spawns `claude -p` in `handle_spawn`, it generates a 256-bit random token via the host CSPRNG (`runtime::random_bytes`), persists it to `kv://sage.hook_token.<principal>.<session>`, and sets all three env vars (`ASTRID_PRINCIPAL_ID`, `ASTRID_SESSION_ID`, `ASTRID_HOOK_TOKEN`) on the `claude` child process. The token is unique per `(principal, session)`.
3. **Run-loop validation** — sage subscribes to `sage.v1.hook.*` in its `#[astrid::run]` supervisor. For each event, sage looks up `kv://sage.hook_token.<principal>.<session>` using the **claimed** `(principal, session)` from the envelope and compares the stored token against the envelope's `token` field. The kernel's per-principal KV scoping bounds the lookup to sage's own namespace, so cross-principal lookups cannot return another principal's token even when the claim is forged.
4. **Republish (sage as CA)** — on a token match, sage strips the transport fields (`principal_id`, `session_id`, `token`) and republishes the canonical hook-event-request shape (`hook`, `payload`, `correlation_id: null`) on `hook.v1.event.<name>`. Topic mapping: `PreToolUse` → `before_tool_call`, `PostToolUse` → `after_tool_call`, `UserPromptSubmit` → `message_received`, `Stop` → `session_end`, `SubagentStop` → `subagent_stop`. The Claude-side `Notification` hook has no canonical Astrid equivalent and is republished on the sage-namespaced topic `sage.v1.notification`. The republish carries sage's own capsule attribution — downstream subscribers trust sage's vouching ("sage as a CA"); the `principal_id` rides inside the payload, not in the kernel-attributed envelope metadata.
5. **Mismatch handling** — on token mismatch, sage drops the event and publishes `sage.v1.audit.hook_spoof_attempt` with the claimed fields so the spoof attempt is observable. Sage does **not** treat the envelope's `principal_id` as authentic until the token matches; the claim is purely an index into the KV namespace until validated.
6. **Session cleanup** — on graceful stop, supervisor-driven eviction, or capsule-reload orphan sweep, sage deletes `kv://sage.hook_token.<principal>.<session>` so a leaked token cannot be replayed after the session ends.

### Residual gap: Linux `/proc/<pid>/environ` env-stealability

`ASTRID_HOOK_TOKEN` is exported into the `claude` subprocess environment. On **Linux**, any process running under the same uid can read `/proc/<claude_pid>/environ` and extract the token, then mint forged hook events that will pass sage's validation. macOS hides `environ` from non-root callers (`ps -E` requires elevation), but Linux does not provide that protection by default.

Threat model: a co-tenant attacker process running under the same uid as `claude` (e.g. another shell session, a compromised binary) can steal the per-session token and impersonate the hook source for the lifetime of that session.

Current mitigations: short-lived sessions, fresh token mint on every spawn (including identity-refresh respawn), per-session token rotation, and KV scrub on session end. Full mitigation requires kernel-issued capability tokens scoped per-hook, replacing the env-shared shared secret entirely — see [RFC#30](https://github.com/unicity-astrid/rfcs/pull/30) for the capability-token forward direction.

### What sage does NOT trust

- The `principal_id` field in the incoming envelope is a **claim** — not an authentication — until the token lookup matches. It is an index, not an authentication claim.
- The `session_id` field is likewise a claim — it only resolves into a real (principal, session) once the token matches.
- The kernel-attributed sender of the `sage.v1.hook.*` event (whatever capsule or native binary published it) is not trusted to be `astrid-emit`. Any publisher with the topic capability could attempt the chain; the token-match step is the sole gate.
- Sage's republish on `hook.v1.event.<name>` is the canonical attribution downstream subscribers consume — subscribers should not subscribe to `sage.v1.hook.*` directly.

The `astrid-emit` binary does not exist yet (tracked at [astrid#814](https://github.com/unicity-astrid/astrid/issues/814)). Sage authors the `settings.local.json` command strings referencing it today, so the chain is forward-compatible: hook events will start flowing the moment the host binary lands, with no further sage changes required.

## Claude binary version pin

Sage parses `claude -p --output-format stream-json` output by line-delimited JSON dispatch. The stream-json grammar (notably `system.init`, `assistant.message.content[].type ∈ {text, tool_use}`, `result.subtype`, `sdk_control_request`, the mandatory `control_response.response.mcp_response` wrapper) is **not part of the documented public API** of the Claude Code CLI. It is observed empirically, corroborated by third-party SDKs.

Therefore: **the bundled or expected `claude` binary version is pinned per Sage release.** Every Claude Code release MUST be re-verified for stream-json grammar drift before bumping Sage's expected version. `sage-install` records the version it provisioned against in KV (`sage.claude_version.<principal_id>`); on mismatch at spawn time, sage publishes a typed audit event before proceeding so drift is visible.

Currently expected: `claude-code` ≥ 2.1.x.

## Status

Pre-alpha. The four crate skeletons + Capsule.toml contracts are landed; the `sage` supervisor (`#[astrid::run]`), spawn, send, tool-result write-back, identity refresh, and graceful stop paths are wired in `crates/sage/src/`. `sage-mcp` ships discovery + describe AND the execute bridge: `handle_tool_call` strips the `mcp__sage__` prefix, gates the bare name through a charset whitelist, subscribes to `tool.v1.execute.<bare>.result` BEFORE publishing the request on `tool.v1.execute.<bare>`, drains for 50 s in `EXECUTE_SLICE_MS` steps filtering by `call_id`, and synthesises an `isError:true` envelope on every failure path (unknown prefix, invalid name, subscribe/publish error, timeout) so sage's `pending_tool_calls` slot retires cleanly. Capability enforcement and bridge-side audit publishes remain follow-up work — the bridge itself is shipped. `sage-completion` and `sage-install` are wired end-to-end against the surfaces above. The `.mcp.json` native-shim caveat from Known Deficiency #1 below still applies — Claude does not actually fork-exec a sage MCP server, the tool surface is observed via stream-json parsing. S8 polish covers workspace lock cleanup, this README, the topic contract surface, and the adversarial review against the published behaviour invariants.

## Trademark

This project is an unofficial integration with Claude and Claude Code. It is not affiliated with, endorsed by, or sponsored by Anthropic, PBC. "Claude" and "Anthropic" are trademarks of Anthropic, PBC.

## License

Dual-licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
