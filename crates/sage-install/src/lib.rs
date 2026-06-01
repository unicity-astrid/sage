#![deny(unsafe_code)]
#![deny(clippy::all)]
#![deny(unreachable_pub)]
#![warn(missing_docs)]

//! sage-install — per-principal Claude home provisioner.
//!
//! Triggered by `astrid sage install` (which publishes
//! `sage.v1.install.run`). For a given principal, this capsule:
//!
//! 1. Sanitises `principal_id` (rejects path-traversal, NULs, and any
//!    character outside `[A-Za-z0-9._-]`). The sanitised id is used for
//!    the KV install-complete key and surfaces in status events; it
//!    does NOT appear in fs paths because the kernel scopes the
//!    `home://` VFS scheme per-invocation-principal at check time
//!    (core/crates/astrid-kernel/src/lib.rs:75).
//! 2. Resolves home = `home://` (bound by the kernel to
//!    `~/.astrid/home/<principal>/`).
//! 3. Checks the KV idempotency marker `sage.install.complete.<id>` —
//!    short-circuits to a cached `sage.v1.install.complete` event
//!    unless `force=true`.
//! 4. Creates `.claude/` and `.claude/projects/`.
//! 5. Atomically writes `.claude/settings.local.json` (hardened
//!    permissions: only `mcp__sage__*` allowed, every built-in tool
//!    denied, hooks + skill shell substitution disabled,
//!    `apiKeyHelper=/bin/false` so Claude cannot fall back to ambient
//!    creds).
//! 6. Atomically writes `.claude/.mcp.json` (documented `/bin/false`
//!    stub — sage parses `tool_use` blocks from claude's stream-json
//!    instead of running a stdio MCP server).
//! 7. Records `sage.install.complete.<id>` in KV and publishes
//!    `sage.v1.install.complete{success:true, home_path}`.
//!
//! `handle_relink` re-writes the two config files only; it never
//! prompts, never rotates secrets, and never touches the completion
//! marker.
//!
//! NEVER runs `claude /login` — macOS Keychain entries are scoped by
//! service/account, not by `HOME`, so a per-principal `HOME` redirect
//! would still share OAuth across principals. The Anthropic key is
//! elicited at install time via the sibling `sage` crate's `[env]`
//! block (stored in the host SecretStore) and forwarded into the
//! `claude -p` subprocess as `ANTHROPIC_API_KEY` at spawn time —
//! `sage` reads it back with `astrid_sdk::env::var("api_key")`.
//!
//! # Onboarding credential lifecycle (READ BEFORE EDITING)
//!
//! Initial-setup credentials (the Anthropic API key, model id, any
//! other per-principal config) come from the **sibling `sage` crate's
//! `[env]` block in its `Capsule.toml`** — NOT from `elicit::*` in
//! this capsule. The kernel elicits each declared `[env]` value at
//! capsule install time, persists it in its SecretStore, and injects
//! it as the capsule's runtime config; `sage` reads it back via
//! `astrid_sdk::env::var("api_key")` at spawn time. See
//! `capsules/astrid-capsule-openai/Capsule.toml` for the canonical
//! `[env]` schema (`type = "secret" | "string" | "integer"`,
//! `request`, optional `default` / `placeholder`).
//!
//! The runtime `astrid_sdk::elicit::*` module is for one-shot dynamic
//! prompts, NOT initial onboarding. The host gates `astrid:elicit@1.0.0`
//! to `#[astrid::install]` / `#[astrid::upgrade]` lifecycle phases —
//! calling it from an IPC interceptor returns `not-in-lifecycle` and
//! the install fails loudly. Do not re-introduce an `elicit::secret`
//! call from a subscribed-IPC handler in this crate; declare the
//! credential under `[env]` in the consuming capsule's manifest
//! instead.

mod atomic;
mod layout;
mod settings;

use astrid_sdk::prelude::*;
use serde::{Deserialize, Serialize};

use crate::layout::{
    claude_dir, install_complete_key, principal_home, projects_dir, sanitize_principal_id,
};

/// Install-time IPC payload (`sage.v1.install.run`).
#[derive(Debug, Clone, Deserialize)]
pub struct InstallRequest {
    /// Untrusted: sanitised before any filesystem access.
    pub principal_id: String,
    /// Re-run the install even when the KV completion marker is set.
    #[serde(default)]
    pub force: bool,
}

/// Relink-time IPC payload (`sage.v1.install.relink`).
#[derive(Debug, Clone, Deserialize)]
pub struct RelinkRequest {
    /// Untrusted: sanitised before any filesystem access.
    pub principal_id: String,
}

/// Progress message published on `sage.v1.install.status`.
#[derive(Debug, Clone, Serialize)]
struct InstallStatus {
    principal_id: String,
    step: &'static str,
    message: String,
}

/// Terminal event published on `sage.v1.install.complete`.
#[derive(Debug, Clone, Serialize)]
struct InstallComplete {
    principal_id: String,
    success: bool,
    home_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    already_installed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// KV value at `install.complete.<id>` — proof of a successful install.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct InstallMarker {
    installed_at: u64,
    version: String,
    home_path: String,
}

const STATUS_TOPIC: &str = "sage.v1.install.status";
const COMPLETE_TOPIC: &str = "sage.v1.install.complete";
const CAPSULE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// sage-install provisioner.
#[derive(Default)]
pub struct SageInstall;

#[capsule]
impl SageInstall {
    /// Subscriber for `sage.v1.install.run`.
    ///
    /// Runs the full per-principal install: sanitize -> idempotency
    /// gate -> create dirs -> write settings -> write mcp stub ->
    /// record completion -> publish event. (API-key onboarding lives
    /// in the sibling `sage` crate's `[env]` block, not here.)
    #[astrid::interceptor("handle_install")]
    pub fn handle_install(&self, req: InstallRequest) -> Result<(), SysError> {
        let raw_id = req.principal_id.clone();
        match run_install(&req) {
            Ok(home) => {
                publish_complete(&InstallComplete {
                    principal_id: req.principal_id,
                    success: true,
                    home_path: home,
                    already_installed: None,
                    error: None,
                });
            }
            Err(e) => {
                // Untyped error string — the WIT host error already
                // carries the variant name. Capsule callers can string-match
                // for now; a typed envelope ships with the install RFC.
                let msg = e.to_string();
                log::error(format!("sage-install failed for {raw_id}: {msg}"));
                publish_complete(&InstallComplete {
                    principal_id: req.principal_id,
                    success: false,
                    home_path: String::new(),
                    already_installed: None,
                    error: Some(msg),
                });
            }
        }
        Ok(())
    }

    /// Subscriber for `sage.v1.install.relink`.
    ///
    /// Re-writes `.claude/settings.local.json` and `.claude/.mcp.json`
    /// for an already-installed principal. Never elicits, never rotates
    /// the API key, never touches the completion marker.
    #[astrid::interceptor("handle_relink")]
    pub fn handle_relink(&self, req: RelinkRequest) -> Result<(), SysError> {
        let raw_id = req.principal_id.clone();
        match run_relink(&req) {
            Ok(home) => {
                publish_complete(&InstallComplete {
                    principal_id: req.principal_id,
                    success: true,
                    home_path: home,
                    already_installed: None,
                    error: None,
                });
            }
            Err(e) => {
                let msg = e.to_string();
                log::error(format!("sage-install relink failed for {raw_id}: {msg}"));
                publish_complete(&InstallComplete {
                    principal_id: req.principal_id,
                    success: false,
                    home_path: String::new(),
                    already_installed: None,
                    error: Some(msg),
                });
            }
        }
        Ok(())
    }
}

/// Full install pipeline. On `Err`, the caller publishes the failure
/// event and we deliberately do NOT write the KV completion marker —
/// the next run retries cleanly.
fn run_install(req: &InstallRequest) -> Result<String, SysError> {
    let sanitized = sanitize_principal_id(&req.principal_id)?;
    let home = principal_home();

    publish_status(&sanitized, "begin", "starting install");

    // Idempotency check — short-circuit unless force=true.
    if !req.force
        && let Some(marker) = kv::get_json_opt::<InstallMarker>(&install_complete_key(&sanitized))?
    {
        publish_status(&sanitized, "already_installed", "skipping install");
        publish_complete(&InstallComplete {
            principal_id: req.principal_id.clone(),
            success: true,
            home_path: marker.home_path.clone(),
            already_installed: Some(true),
            error: None,
        });
        return Ok(marker.home_path);
    }

    // Provision dirs first so the temp-cleanup pass below can read them.
    // create_dir_all is idempotent so this is safe even when the
    // directory survived from a previous failed run.
    provision_dirs(&sanitized)?;

    // Best-effort scrub of stale temp siblings left by a previous crash
    // between fs::write and fs::rename. Without this, partial-write
    // siblings persist until the *next* failed install — the criterion
    // "cleaned on next run" requires that they also disappear on the
    // next *successful* run.
    atomic::cleanup_temp(&layout::settings_path());
    atomic::cleanup_temp(&layout::mcp_path());

    // Run the remaining steps. On error, scrub temp siblings of the two
    // known files and propagate; the outer handler publishes the failure
    // envelope without writing the completion marker.
    //
    // API-key onboarding is NOT done here — see the crate-level doc.
    // The kernel elicits `api_key` from the sibling `sage` crate's
    // `[env]` block at install time; `sage` reads it back via
    // `env::var("api_key")` at spawn time.
    if let Err(e) = write_configs(&sanitized) {
        atomic::cleanup_temp(&layout::settings_path());
        atomic::cleanup_temp(&layout::mcp_path());
        return Err(e);
    }

    // Resolve `home://` to an absolute path so external subscribers
    // (e.g. the spawn path forwarding the resolved root as `HOME=` to
    // the claude subprocess) don't have to know about the VFS scheme.
    // Falls back to the scheme path if canonicalisation isn't
    // supported.
    let resolved_home = fs::canonicalize(&home).unwrap_or_else(|_| home.clone());

    let marker = InstallMarker {
        installed_at: epoch_secs(),
        version: CAPSULE_VERSION.to_string(),
        home_path: resolved_home.clone(),
    };
    kv::set_json(&install_complete_key(&sanitized), &marker)?;

    publish_status(&sanitized, "complete", "install finished");
    Ok(resolved_home)
}

/// Relink pipeline — re-writes only the two config files.
fn run_relink(req: &RelinkRequest) -> Result<String, SysError> {
    let sanitized = sanitize_principal_id(&req.principal_id)?;
    let home = principal_home();

    publish_status(&sanitized, "relink_begin", "rewriting configs");

    // Directory must exist for relink to make sense, but create_dir_all
    // is idempotent — call it for safety in case .claude/ was nuked.
    provision_dirs(&sanitized)?;

    // Scrub stale temp siblings from any earlier crashed write — same
    // reasoning as in run_install. Safe to run before the writes
    // because cleanup_temp only matches the `.<basename>.tmp.` prefix.
    atomic::cleanup_temp(&layout::settings_path());
    atomic::cleanup_temp(&layout::mcp_path());

    if let Err(e) = write_configs(&sanitized) {
        atomic::cleanup_temp(&layout::settings_path());
        atomic::cleanup_temp(&layout::mcp_path());
        return Err(e);
    }

    let resolved_home = fs::canonicalize(&home).unwrap_or_else(|_| home.clone());

    publish_status(&sanitized, "relink_complete", "configs rewritten");
    Ok(resolved_home)
}

fn provision_dirs(sanitized_id: &str) -> Result<(), SysError> {
    publish_status(sanitized_id, "mkdir", "creating .claude/ and projects/");
    fs::create_dir_all(&claude_dir())?;
    fs::create_dir_all(&projects_dir())?;
    Ok(())
}

fn write_configs(sanitized_id: &str) -> Result<(), SysError> {
    publish_status(sanitized_id, "write_settings", "writing settings.local.json");
    settings::write_settings()?;
    publish_status(sanitized_id, "write_mcp", "writing .mcp.json stub");
    settings::write_mcp()?;
    Ok(())
}

fn publish_status(principal_id: &str, step: &'static str, message: &str) {
    let _ = ipc::publish_json(
        STATUS_TOPIC,
        &InstallStatus {
            principal_id: principal_id.to_string(),
            step,
            message: message.to_string(),
        },
    );
}

fn publish_complete(event: &InstallComplete) {
    let _ = ipc::publish_json(COMPLETE_TOPIC, event);
}

fn epoch_secs() -> u64 {
    time::now()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
