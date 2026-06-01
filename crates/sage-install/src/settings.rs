//! Concrete writers for `.claude/settings.local.json` and
//! `.claude/.mcp.json`. Both go through [`crate::atomic::write_atomic`]
//! so a crashed install never leaves a half-written config file.

use astrid_sdk::prelude::*;

use crate::{atomic, config::PrincipalConfig, layout};

/// Write the `.claude/settings.local.json` for the invoking principal,
/// shaped by `cfg` (interaction × auth axes — see
/// [`layout::settings_json`]). Assumes `.claude/` already exists (the
/// install handler creates it before calling here). The path resolves
/// through `home://`, which the kernel scopes to the per-invocation
/// principal — no principal_id appears in the path.
pub(crate) fn write_settings(cfg: &PrincipalConfig) -> Result<(), SysError> {
    let path = layout::settings_path();
    let body = serde_json::to_vec_pretty(&layout::settings_json(cfg))?;
    atomic::write_atomic(&path, &body)
}

/// Write the `.claude/.mcp.json` for the invoking principal, shaped by
/// `cfg`. In headless mode the body is the documented `/bin/false`
/// stub (keeps `claude`'s `--allowed-tools mcp__sage__*` resolving
/// while real tool dispatch happens via sage parsing claude's
/// stream-json tool_use blocks). In repl mode the body is an empty
/// `mcpServers` object (the user wires native servers themselves).
pub(crate) fn write_mcp(cfg: &PrincipalConfig) -> Result<(), SysError> {
    let path = layout::mcp_path();
    let body = serde_json::to_vec_pretty(&layout::mcp_json(cfg))?;
    atomic::write_atomic(&path, &body)
}
