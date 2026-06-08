# Astrid — Claude Code plugin

Turn a vanilla `claude` REPL into an **Astrid agent**. Installing this plugin
registers the Astrid MCP server (`astrid mcp serve`) so Claude Code discovers
and calls the live Astrid capsule tool surface (filesystem, http, shell,
system, skills, …), scoped to an Astrid principal — with the daemon brought up
automatically.

The integration lives entirely in **Claude Code's** plugin system. Astrid stays
agent-agnostic — it's just an MCP server on the bus; this plugin is the
Claude-specific adapter. A Codex/Gemini adapter would be its own plugin against
the same `astrid mcp serve` surface.

## What it bundles (v1)

- **MCP server** (`.mcp.json`) → `bin/astrid-up`, a wrapper that ensures the
  daemon is running and then becomes `astrid mcp serve --principal <you>`.
- **`userConfig.principal`** → the Astrid principal this session acts as.

Roadmap (v2): the hook plane (`hooks/hooks.json` → `astrid-emit`, wiring the
session lifecycle onto the bus), `/astrid-*` slash commands, operator agents,
and an Astrid output-style identity.

## Prerequisites

- The `astrid` CLI installed and on `PATH` (or at `~/.astrid/bin/astrid`),
  **built from a revision that has `astrid mcp serve`**.
- The **sage-mcp broker** capsule installed in the daemon (it answers
  `astrid.v1.request.mcp.*`). Without it, the server connects but lists no
  tools.

## Install (the wow path)

**Dev / today — load it raw, no install:**

```sh
claude --plugin-dir /path/to/capsules/sage/astrid-plugin
```

Set the principal once when prompted (or leave blank for the active principal).
The daemon starts on first launch; `mcp__astrid__*` tools appear.

**Distributed — your own marketplace (no Anthropic gatekeeping):**

```sh
# point at a repo/dir that contains .claude-plugin/marketplace.json
claude plugin marketplace add unicity-astrid/astrid     # or a local path
claude plugin install astrid@astrid
```

`--scope user` makes every `claude` session in every project an Astrid agent.

## Caveat: tool *calls* need a trusted ingress (one-time)

`tools/list` is ungated — Claude Code will **see** the Astrid tools immediately.
`tools/call` is confused-deputy gated by the sage-mcp broker: it only dispatches
for a `source_id` listed in the broker's `trusted_ingress_ids`. Until that's
set to the CLI uplink's id, calls are denied (fail-closed). Set it once when
installing/configuring the sage-mcp capsule. (Single-tenant: you're admin, so
the principal stamp is a self-stamp — fine on your own machine.)
