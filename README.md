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
| Publish | `sage.v1.event.session_rejected` | `{reason: "principal_limit" \| ...}` |
| Publish | `sage.v1.tool.call.<call_id>` | `{session_id, principal_id, tool_name, arguments: JSON}` |
| Publish (runtime) | `sage.v1.audit.spawn` | `{principal_id, session_id, pid, flags_hash: String}` |
| Publish (runtime) | `sage.v1.audit.tool_call` | `{principal_id, session_id, call_id, tool_name, allowed: bool, decision_source}` |
| Publish (runtime) | `sage.v1.audit.identity_fallback` | `{principal_id, session_id, reason: String}` |
| Publish (runtime) | `sage.v1.install.run` | `{principal_id}` (awakens `sage-install` from `ensure_install`) |

### `sage-mcp` (tool bridge)

| Direction | Topic | Payload |
|---|---|---|
| Subscribe | `sage.v1.tool.call.<call_id>` | mirror of sage publish |
| Subscribe | `sage.v1.tools.describe` | `{}` (trigger describe-collect) |
| Subscribe | `tool.v1.response.describe.*` | `{tools: [ToolDescriptor]}` (fan-in cache) |
| Publish | `sage.v1.tool.result.<call_id>` | `{content: String, isError: bool}` |
| Publish | `sage.v1.tools.list` | `{tools: [McpToolDescriptor]}` |
| Publish | `tool.v1.request.describe` | `{}` (broadcast describe-collect) |
| Publish | `tool.v1.request.execute` | `{tool_name, arguments, correlation_id}` |

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
| Subscribe | `sage.v1.install.run` | `{principal_id, force?: bool}` |
| Subscribe | `sage.v1.install.relink` | `{principal_id}` |
| Publish | `sage.v1.install.status` | `{principal_id, step: String}` |
| Publish | `sage.v1.install.complete` | `{principal_id, success: bool, error?: String}` |

Also publishes one-shot `spark.v1.request.build` and reads `spark.v1.response.ready` for identity injection per session (per-session-id `.sage-identity-<sid>` file written atomically to the principal's `.claude/`).

## Known deficiencies

1. **`.mcp.json` is a stub, not a real MCP server.** Claude expects to fork-exec the MCP server as a native subprocess; shipping such a binary requires host-side kernel work (an `astrid-mcp-shim` native binary) that is out of scope for the capsules-only Sage workspace. v1 ships with `.claude/.mcp.json` containing `{"mcpServers":{"sage":{"command":"/bin/false","args":[],"env":{}}}}` — the documented stub. Claude's tool surface still works because (a) `--allowed-tools mcp__sage__*` gates the surface, (b) `sage` parses `tool_use` content blocks directly out of `claude -p`'s `--output-format stream-json` and routes them via the bus, (c) `--append-system-prompt-file` enumerates available tools so Claude knows what to call. When the kernel ships a native `astrid-mcp-shim` binary, `sage-install` will rewrite `.mcp.json` to point at it (additive change, no IPC contract churn). **Flagged gap** — tracked outside this workspace.
2. **No native MCP tools/list response.** Because of (1), Claude never sees a real MCP `tools/list` — the `--append-system-prompt-file` enumeration is the surrogate. Tool descriptions surface through that channel rather than the protocol-level `tools/list` call.
3. **macOS Keychain is HOME-blind.** `claude /login` writes OAuth tokens to the macOS Keychain keyed by service+account, not by HOME. Setting `HOME=~/.astrid/principals/<id>/` does **not** isolate auth across principals on macOS. `sage-install` works around this by storing the per-principal `ANTHROPIC_API_KEY` in KV (collected via `elicit::secret` at install time, encrypted at rest by the host) and exporting it as env at spawn. Sage explicitly does **not** invoke `claude /login` on macOS.
4. **Pre-#752 register-only describe.** `sage-completion` publishes to both `llm.v1.response.describe` (unsuffixed; legacy registry drain) and `llm.v1.response.describe.*` (correlation-routed; post-#752). Drop the unsuffixed publish once every consumer is on post-#752.
5. **Manifest publish/subscribe surfaces narrower than runtime.** `sage/Capsule.toml` declares `sage.v1.event.*` and `sage.v1.tool.call.*` publishes plus the three handler-bound subscribes (`sage.v1.request.spawn`, `sage.v1.request.send.*`, `sage.v1.tool.result.*`). At runtime the supervisor additionally opens `ipc::subscribe` for `sage.v1.request.stop.*`, `tool.v1.execute.save_identity.result`, `approval.v1.response.*`, and `sage.v1.install.complete`, and publishes to `sage.v1.audit.*` and `sage.v1.install.run`. Once host enforcement of manifest `[publish]/[subscribe]` against runtime calls lands, these need to either be declared in `Capsule.toml` or converted to handler-bound subscribes. Until then the topic-contract table above is the source of truth — the `(runtime)` markers flag every gap.

## Claude binary version pin

Sage parses `claude -p --output-format stream-json` output by line-delimited JSON dispatch. The stream-json grammar (notably `system.init`, `assistant.message.content[].type ∈ {text, tool_use}`, `result.subtype`, `sdk_control_request`, the mandatory `control_response.response.mcp_response` wrapper) is **not part of the documented public API** of the Claude Code CLI. It is observed empirically, corroborated by third-party SDKs.

Therefore: **the bundled or expected `claude` binary version is pinned per Sage release.** Every Claude Code release MUST be re-verified for stream-json grammar drift before bumping Sage's expected version. `sage-install` records the version it provisioned against in KV (`sage.claude_version.<principal_id>`); on mismatch at spawn time, sage publishes a typed audit event before proceeding so drift is visible.

Currently expected: `claude-code` ≥ 2.1.x.

## Status

Pre-alpha. The four crate skeletons + Capsule.toml contracts are landed; the `sage` supervisor (`#[astrid::run]`), spawn, send, tool-result write-back, identity refresh, and graceful stop paths are wired in `crates/sage/src/`. `sage-mcp` ships discovery + describe; the execute bridge (validation, capability check, `tool.v1.request.execute` fan-out, 60 s result drain, audit) lands in the follow-up slice — `handle_tool_call` is a documented logging-only stub today. `sage-completion` and `sage-install` are wired end-to-end against the surfaces above. S8 polish covers workspace lock cleanup, this README, the topic contract surface, and the adversarial review against the published behaviour invariants.

## Trademark

This project is an unofficial integration with Claude and Claude Code. It is not affiliated with, endorsed by, or sponsored by Anthropic, PBC. "Claude" and "Anthropic" are trademarks of Anthropic, PBC.

## License

Dual-licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
