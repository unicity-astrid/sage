# Astrid — Claude Code plugin

Turn a vanilla `claude` REPL into a **governed Astrid agent**. Installing this
plugin registers the Astrid MCP server (`astrid mcp serve`) so Claude Code
discovers and calls the live Astrid capsule tool surface (filesystem, http,
shell, system, skills, …), scoped to an Astrid principal — with the daemon
brought up automatically and torn down when you're done.

The integration lives entirely in **Claude Code's** plugin system. Astrid stays
agent-agnostic — it's just an MCP server on the bus; this plugin is the
Claude-specific adapter. A Codex/Gemini adapter would be its own plugin against
the same `astrid mcp serve` surface.

## What it bundles

- **MCP server** (`.mcp.json` → `bin/astrid-up`) — ensures a daemon is running,
  then becomes `astrid mcp serve --principal <you>`. The daemon is booted in
  **ephemeral** mode: it self-cleans ~30s after the last client disconnects, so
  it lives exactly as long as the editor. An already-running daemon (persistent
  or shared with another session) is reused untouched.
- **SessionStart doctor** (`hooks/hooks.json` → `bin/astrid-doctor`) — at
  session start, injects who you are (principal), what governs you, and the
  daemon/broker readiness state into context, with the exact fix for any gap.
- **Astrid HUD status line** (`bin/astrid-statusline`) — overlays your principal
  and daemon state onto Claude Code's bottom bar (see *HUD* below).
- **`/astrid:*` commands** — `/astrid:whoami`, `/astrid:status`,
  `/astrid:capsules`, `/astrid:doctor`, `/astrid:hud`. Read-only operator
  views, backed by the `astrid` CLI.
- **Astrid identity output-style** — *Astrid agent*: frames Claude as a
  capability-scoped, audited agent acting for a principal (coding instructions
  preserved). Enable via `/output-style`.
- **`userConfig.principal`** — the Astrid principal this session acts as. Leave
  blank to use the active CLI principal (`astrid mcp serve` resolves it).

## Prerequisites

- The `astrid` CLI installed and on `PATH` (or at `~/.astrid/bin/astrid`),
  **built from a revision that has `astrid mcp serve`**. The plugin can't
  bootstrap the runtime itself — it wires Claude Code to an Astrid that already
  exists. (`astrid-daemon` must sit next to `astrid`, or on `PATH`, for the
  ephemeral boot.)
- The **sage-mcp broker** capsule loaded in the daemon (it answers
  `astrid.v1.request.mcp.*`). Without it, the server connects but lists no
  tools. `/astrid:doctor` tells you if it's missing.

## Install (the wow path)

**Dev / today — load it raw, no install:**

```sh
claude --plugin-dir /path/to/capsules/sage/astrid-plugin
```

Set the principal once when prompted (or leave blank for the active principal).
The daemon starts on first launch; `mcp__astrid__*` tools appear.

**Distributed — your own marketplace (no Anthropic gatekeeping):**

```sh
# the marketplace manifest lives at the bundle root (capsules/sage)
claude plugin marketplace add unicity-astrid/astrid     # or a local path
claude plugin install astrid@astrid
```

`--scope user` makes every `claude` session in every project an Astrid agent.

## HUD (status line)

A plugin can't register the *main* status line — Claude Code only lets a plugin
default `agent`/`subagentStatusLine`. Wire it once yourself, or run
`/astrid:hud` to get the exact snippet (resolved to this plugin's path) and have
Claude offer to add it:

```jsonc
// ~/.claude/settings.json
"statusLine": {
  "type": "command",
  "command": "<plugin-root>/bin/astrid-statusline",
  "padding": 0
}
```

Renders: `⬡ astrid:<principal> ●  │ <model> │ <dir> ⎇ <branch> │ <context-bar> │ <cost>`
— the dot is green when the daemon is up.

## Caveat: tool *calls* need a trusted ingress (one-time)

`tools/list` is ungated — Claude Code will **see** the Astrid tools immediately.
`tools/call` is confused-deputy gated by the sage-mcp broker: it only dispatches
for a `source_id` listed in the broker's `trusted_ingress_ids`. Until that's
set to the CLI uplink's id, calls are denied (fail-closed). Set it once when
installing/configuring the sage-mcp capsule. (Single-tenant: you're admin, so
the principal stamp is a self-stamp — fine on your own machine.)
`/astrid:doctor` flags this if your calls come back denied.

## Not yet: native-action governance on the bus

Today the plugin governs everything that flows **through** Astrid (every
`mcp__astrid__*` call passes the broker policy gate + capability checks + audit)
and observes session start. It does **not** yet push Claude's *native* tool use
(Bash/Read/Write/Edit) onto the Astrid bus — `astrid-emit` requires a sage spawn
token that an interactive session doesn't have, and the CLI has no token-free
publish path. Surfacing native actions for capsule-side governance needs a small
core addition (a principal-authenticated emit path); it's the next milestone for
the hook plane, not something the plugin can close on its own.
