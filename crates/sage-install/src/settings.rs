//! Concrete writers for `.claude/settings.local.json` and
//! `.claude/.mcp.json`. Both go through [`crate::atomic::write_atomic`]
//! so a crashed install never leaves a half-written config file.

use astrid_sdk::prelude::*;

use crate::{atomic, layout};

/// Write the hardened `.claude/settings.local.json` for the invoking
/// principal. Assumes `.claude/` already exists (the install handler
/// creates it before calling here). The path resolves through
/// `home://`, which the kernel scopes to the per-invocation
/// principal — no principal_id appears in the path.
pub(crate) fn write_settings() -> Result<(), SysError> {
    let path = layout::settings_path();
    let body = serde_json::to_vec_pretty(&layout::settings_json())?;
    atomic::write_atomic(&path, &body)
}

/// Write the documented `.claude/.mcp.json` stub for the invoking
/// principal. The stub keeps `claude`'s `--allowed-tools mcp__sage__*`
/// flag resolving while real tool dispatch happens via sage parsing
/// claude's stream-json tool_use blocks.
pub(crate) fn write_mcp() -> Result<(), SysError> {
    let path = layout::mcp_path();
    let body = serde_json::to_vec_pretty(&layout::mcp_json())?;
    atomic::write_atomic(&path, &body)
}
