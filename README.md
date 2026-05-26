# sage

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![MSRV: 1.94](https://img.shields.io/badge/MSRV-1.94-blue)](https://www.rust-lang.org)

**The Anthropic Claude integration for [Astrid OS](https://github.com/unicity-astrid/astrid).** Powered by Claude.

Sage is the runtime bridge that lets Astrid host Claude as a first-class agent — capability-gated, audit-trailed, identity-decoupled from the model. The user-facing agent has its own identity (configured via `capsule-identity`); Claude is the engine underneath.

## What's in this repo

This is a multi-capsule bundle. Four wasm components ship together as a single Astrid distro:

| Crate | Role |
|-------|------|
| `sage` | Supervises `claude -p` headless subprocesses (one per principal). Streams stdin/stdout, dispatches tool calls to the bus, feeds results back. |
| `sage-completion` | Direct Anthropic API LLM provider. Implements `astrid:llm` (`rfc:llm-provider.v1`). For per-turn completions when Astrid is driving the agent loop. |
| `sage-mcp` | MCP server projecting Astrid capsule tools as MCP for Claude. The single boundary Claude can act through. |
| `sage-install` | Provisioner. `astrid sage install` walks the user through per-principal `HOME=`-isolated Claude setup and OAuth. |

## Two billing paths

- **Agent mode** (`sage` crate): `claude -p` runs Claude's own agent loop. Burns the Anthropic Agent SDK credit on Pro/Max subscriptions ($20 / $100 / $200/mo respectively as of June 15, 2026).
- **Completion mode** (`sage-completion` crate): direct Anthropic API per-turn. Burns API usage credits, separate from the Agent SDK credit. Used when Astrid drives the loop and wants per-turn model routing.

`capsule-router` picks per-turn — Sonnet/Haiku via completion mode for routine work, Opus via either mode only when reasoning depth warrants it.

## Status

Pre-alpha. Scaffolding only. See [project memory] for the locked-in architecture and the implementation roadmap.

## Trademark

This project is an unofficial integration with Claude and Claude Code. It is not affiliated with, endorsed by, or sponsored by Anthropic, PBC. "Claude" and "Anthropic" are trademarks of Anthropic, PBC.

## License

Dual-licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
