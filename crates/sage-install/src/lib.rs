#![deny(unsafe_code)]
#![deny(clippy::all)]
#![deny(unreachable_pub)]
#![warn(missing_docs)]

//! sage-install — per-principal Claude home provisioner.
//!
//! Triggered by `astrid sage install` (which publishes
//! `sage.v1.install.run`). For a given principal, this capsule:
//!
//! 1. Creates `~/.astrid/principals/<principal>/.claude/` if it
//!    doesn't exist.
//! 2. Writes a `.claude/settings.local.json` pointing at `sage-mcp`
//!    via `mcpServers`, installing hooks (PostToolUse → audit,
//!    UserPromptSubmit → classification, PreCompact → snapshot),
//!    and restricting tools to `mcp__sage__*`.
//! 3. Spawns an interactive `HOME=<principal-home> claude /login`
//!    subprocess so the user can authenticate with their Anthropic
//!    account against the isolated config dir. Auth lands in the
//!    per-principal `.claude.json` (Linux) — see the macOS Keychain
//!    caveat documented in the sage README.
//!
//! Idempotent — re-running on an already-linked principal updates
//! settings/hooks without disturbing existing auth.

use astrid_sdk::prelude::*;

/// sage-install provisioner.
#[derive(Default)]
pub struct SageInstall;

#[capsule]
impl SageInstall {
    // Scaffolding only — install/relink handlers land in the
    // first real implementation pass.
}
