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
//! 5. Atomically writes `.claude/settings.local.json` for the principal,
//!    shaped by the `PrincipalConfig` threaded over the IPC envelope.
//!    In `headless` interaction mode the allow list is pinned to
//!    `mcp__sage__*` and every built-in tool is denied; in `repl` mode
//!    the user owns their full Claude environment and the deny list is
//!    empty. In `api_key` auth mode `apiKeyHelper` is pinned to
//!    `/bin/false` so Claude cannot fall back to ambient creds; in
//!    `subscription` mode the helper is omitted so the keychain OAuth
//!    path is reachable. The `hooks` block is declared identically in
//!    both modes with `/bin/true` placeholders until the native bridge
//!    binary lands (see `crate::layout::settings_json` for the
//!    dual-mode contract).
//! 6. Atomically writes `.claude/.mcp.json`. In `headless` mode the
//!    body is the documented `/bin/false` stub (sage parses `tool_use`
//!    blocks directly out of claude's stream-json — the stub keeps
//!    `--allowed-tools mcp__sage__*` resolving). In `repl` mode the
//!    body is an empty `mcpServers` object — users wire native MCP
//!    servers themselves.
//! 7. Records `sage.install.complete.<id>` in KV and publishes
//!    `sage.v1.install.complete{success:true, home_path}`.
//!
//! # Runtime-rewrite contract
//!
//! `handle_relink` re-writes the two config files only; it never
//! prompts, never rotates secrets, and never touches the completion
//! marker. It IS the runtime-rewrite contract that sage drives whenever
//! `sage.v1.request.settings.set` mutates the per-principal config:
//! sage persists the merged `PrincipalConfig` in its KV namespace and
//! publishes `sage.v1.install.relink{principal_id, config}`; this
//! capsule consumes the envelope and rewrites the on-disk JSON so the
//! files on disk track the in-KV truth. A successful relink terminates
//! the cycle by republishing `sage.v1.install.complete`, which sage
//! treats as the cue to broadcast `sage.v1.settings.changed`. See the
//! README "Interaction modes" and "Authentication modes" sections for
//! the end-to-end walkthrough.
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
mod config;
mod layout;
mod settings;

use astrid_sdk::prelude::*;
use serde::{Deserialize, Serialize};

use crate::config::PrincipalConfig;
use crate::layout::{
    claude_dir, install_complete_key, principal_home, projects_dir, sanitize_principal_id,
};

/// Install-time IPC payload (`sage.v1.install.run`).
///
/// The optional `config` field is the per-principal interaction × auth
/// shape, threaded over the IPC envelope from the sibling `sage` crate
/// (which is the canonical owner of the KV-persisted config — see
/// `capsules/sage/crates/sage/src/config.rs`). When absent we fall back
/// to `PrincipalConfig::default()` = headless + api_key, which is the
/// pre-dual-mode behaviour and the back-compat path for older sage
/// envelopes.
#[derive(Debug, Clone, Deserialize)]
pub struct InstallRequest {
    /// Untrusted: sanitised before any filesystem access.
    pub principal_id: String,
    /// Re-run the install even when the KV completion marker is set.
    #[serde(default)]
    pub force: bool,
    /// Per-principal interaction × auth shape; `None` defaults to
    /// `{Headless, ApiKey}` for back-compat with older sage envelopes.
    #[serde(default)]
    pub config: Option<PrincipalConfig>,
}

/// Relink-time IPC payload (`sage.v1.install.relink`).
///
/// `config` carries the same payload as on [`InstallRequest`]; sage
/// publishes a relink envelope on every `sage.v1.settings.changed` so
/// the on-disk JSON tracks the in-KV truth.
#[derive(Debug, Clone, Deserialize)]
pub struct RelinkRequest {
    /// Untrusted: sanitised before any filesystem access.
    pub principal_id: String,
    /// Per-principal interaction × auth shape; `None` defaults to
    /// `{Headless, ApiKey}` for back-compat with older sage envelopes.
    #[serde(default)]
    pub config: Option<PrincipalConfig>,
}

/// Progress message published on `sage.v1.install.status`.
#[derive(Debug, Clone, Serialize)]
struct InstallStatus {
    principal_id: String,
    step: &'static str,
    message: String,
}

/// Terminal event published on `sage.v1.install.complete`.
///
/// The optional `config` field carries the resolved `PrincipalConfig`
/// used by the writers back to sage as an informational echo — sage's
/// `classify_install_complete` does NOT consume it (the spawn path
/// already has its own copy from KV), but downstream subscribers
/// (dashboards, audit sinks) can mirror the install-time choices
/// without re-reading sage's KV. Absent in failure envelopes (no
/// successful write happened).
#[derive(Debug, Clone, Serialize)]
struct InstallComplete {
    principal_id: String,
    success: bool,
    home_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    already_installed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    config: Option<PrincipalConfig>,
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
        // Resolve the config once at the handler boundary so success and
        // error envelopes both echo the same shape back to sage; absent
        // (older sage envelopes) defaults to `{Headless, ApiKey, v1}`
        // per the back-compat fallback in `run_install`.
        let resolved_cfg = req.config.unwrap_or_default();
        match run_install(&req) {
            Ok(home) => {
                publish_complete(&InstallComplete {
                    principal_id: req.principal_id,
                    success: true,
                    home_path: home,
                    already_installed: None,
                    error: None,
                    config: Some(resolved_cfg),
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
                    config: None,
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
        // Resolve once at the handler boundary — symmetrical with
        // `handle_install` so success envelopes can echo the shape sage
        // applied.
        let resolved_cfg = req.config.unwrap_or_default();
        match run_relink(&req) {
            Ok(home) => {
                // Audit the operator's settings rewrite on relink. Sage
                // publishes its own `sage.v1.audit.settings_changed`
                // mirror at the KV layer; this one attributes the on-disk
                // rewrite to a specific principal_id at the source-of-
                // truth layer.
                //
                // TODO(astrid-rfcs#TBD): mirror to a shared cross-capsule
                // audit topic once a convention lands; the kernel-side
                // `astrid.v1.audit.entry` is admin-action-shaped and not
                // the right home for capsule-emitted attribution.
                let _ = ipc::publish_json(
                    "sage.v1.audit.settings_changed",
                    &serde_json::json!({
                        "principal_id": raw_id,
                        "new_config": resolved_cfg,
                    }),
                );
                publish_complete(&InstallComplete {
                    principal_id: req.principal_id,
                    success: true,
                    home_path: home,
                    already_installed: None,
                    error: None,
                    config: Some(resolved_cfg),
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
                    config: None,
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
    let cfg = req.config.unwrap_or_else(|| {
        log::info("sage-install: no config on InstallRequest, defaulting to {headless, api_key}");
        PrincipalConfig::default()
    });

    publish_status(&sanitized, "begin", "starting install");

    // Idempotency check — short-circuit unless force=true.
    if !req.force
        && let Some(marker) = kv::get_json_opt::<InstallMarker>(&install_complete_key(&sanitized))?
    {
        publish_status(&sanitized, "already_installed", "skipping install");
        // Audit the install-time choices on the cache-hit path. The
        // emit is best-effort (no propagated error) — the install
        // proceeds even if the bus rejects the publish.
        //
        // TODO(astrid-rfcs#TBD): mirror to a shared cross-capsule audit
        // topic once a convention lands; the kernel-side
        // `astrid.v1.audit.entry` is admin-action-shaped and not the
        // right home for capsule-emitted attribution.
        publish_install_choices(&sanitized, &cfg, true);
        publish_complete(&InstallComplete {
            principal_id: req.principal_id.clone(),
            success: true,
            home_path: marker.home_path.clone(),
            already_installed: Some(true),
            error: None,
            config: Some(cfg),
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
    if let Err(e) = write_configs(&sanitized, &cfg) {
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

    // Audit the install-time choices on the fresh-install success path
    // (mirrors the cache-hit emit above). Best-effort: no propagated
    // error — the install is already committed to KV.
    publish_install_choices(&sanitized, &cfg, false);

    publish_status(&sanitized, "complete", "install finished");
    Ok(resolved_home)
}

/// Relink pipeline — re-writes only the two config files.
fn run_relink(req: &RelinkRequest) -> Result<String, SysError> {
    let sanitized = sanitize_principal_id(&req.principal_id)?;
    let home = principal_home();
    let cfg = req.config.unwrap_or_else(|| {
        log::info("sage-install: no config on RelinkRequest, defaulting to {headless, api_key}");
        PrincipalConfig::default()
    });

    publish_status(&sanitized, "relink_begin", "rewriting configs");

    // Directory must exist for relink to make sense, but create_dir_all
    // is idempotent — call it for safety in case .claude/ was nuked.
    provision_dirs(&sanitized)?;

    // Scrub stale temp siblings from any earlier crashed write — same
    // reasoning as in run_install. Safe to run before the writes
    // because cleanup_temp only matches the `.<basename>.tmp.` prefix.
    atomic::cleanup_temp(&layout::settings_path());
    atomic::cleanup_temp(&layout::mcp_path());

    if let Err(e) = write_configs(&sanitized, &cfg) {
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

fn write_configs(sanitized_id: &str, cfg: &PrincipalConfig) -> Result<(), SysError> {
    publish_status(sanitized_id, "write_settings", "writing settings.local.json");
    settings::write_settings(cfg)?;
    publish_status(sanitized_id, "write_mcp", "writing .mcp.json stub");
    settings::write_mcp(cfg)?;
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

/// Best-effort audit emit on the install path. Fires on both the
/// cache-hit short-circuit (`cache_hit = true`, no on-disk write
/// happened) and the fresh-install success path (`cache_hit = false`,
/// settings + mcp JSON were just rewritten). Errors are swallowed
/// intentionally — the install is the source of truth, the audit
/// record is informational.
fn publish_install_choices(principal_id: &str, cfg: &PrincipalConfig, cache_hit: bool) {
    let _ = ipc::publish_json(
        "sage.v1.audit.install_choices",
        &serde_json::json!({
            "principal_id": principal_id,
            "config": cfg,
            "cache_hit": cache_hit,
        }),
    );
}

fn epoch_secs() -> u64 {
    time::now()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthMode, InteractionMode};

    /// Back-compat round-trip: an `InstallRequest` from an older sage
    /// version that omits the `config` field must deserialize cleanly,
    /// land `req.config` as `None`, and resolve to
    /// `PrincipalConfig::default()` = `{Headless, ApiKey, v1}` when the
    /// handler falls back. This pins the contract that sage-install's
    /// writers always have a `PrincipalConfig` to branch on, even when
    /// the envelope predates the dual-mode change.
    #[test]
    fn install_request_without_config_defaults_to_headless_api_key_v1() {
        let payload = r#"{"principal_id":"alice"}"#;
        let req: InstallRequest =
            serde_json::from_str(payload).expect("payload must deserialize");
        assert_eq!(req.principal_id, "alice");
        assert!(!req.force, "force defaults to false");
        assert!(
            req.config.is_none(),
            "absent config field must surface as None, not a deserialize error"
        );

        // Mirror the fallback used by `run_install` / `handle_install`.
        let resolved = req.config.unwrap_or_default();
        assert_eq!(resolved.interaction_mode, InteractionMode::Headless);
        assert_eq!(resolved.auth_mode, AuthMode::ApiKey);
        assert_eq!(resolved.schema_version, PrincipalConfig::SCHEMA_VERSION);
    }

    /// Same round-trip on the relink envelope — `RelinkRequest` carries
    /// the optional `config` field too, and the fallback must match.
    #[test]
    fn relink_request_without_config_defaults_to_headless_api_key_v1() {
        let payload = r#"{"principal_id":"alice"}"#;
        let req: RelinkRequest =
            serde_json::from_str(payload).expect("payload must deserialize");
        assert_eq!(req.principal_id, "alice");
        assert!(req.config.is_none());

        let resolved = req.config.unwrap_or_default();
        assert_eq!(resolved.interaction_mode, InteractionMode::Headless);
        assert_eq!(resolved.auth_mode, AuthMode::ApiKey);
        assert_eq!(resolved.schema_version, PrincipalConfig::SCHEMA_VERSION);
    }

    /// Forward path: a fully-specified envelope deserializes verbatim.
    /// Pins the wire shape sage's `ensure_install` publishes today so a
    /// regression in either capsule's serde alphabet is caught.
    #[test]
    fn install_request_with_config_round_trips() {
        let payload = r#"{
            "principal_id":"alice",
            "force":true,
            "config":{
                "interaction_mode":"repl",
                "auth_mode":"subscription",
                "schema_version":1
            }
        }"#;
        let req: InstallRequest =
            serde_json::from_str(payload).expect("payload must deserialize");
        assert!(req.force);
        let cfg = req.config.expect("config must be Some");
        assert_eq!(cfg.interaction_mode, InteractionMode::Repl);
        assert_eq!(cfg.auth_mode, AuthMode::Subscription);
        assert_eq!(cfg.schema_version, 1);
    }

    /// `InstallComplete` with no echo-back config (failure envelope)
    /// must omit the field via `skip_serializing_if`. Pins the
    /// back-compat shape for older sage subscribers that don't yet
    /// expect a `config` key on the envelope.
    #[test]
    fn install_complete_failure_omits_config_field() {
        let event = InstallComplete {
            principal_id: "alice".into(),
            success: false,
            home_path: String::new(),
            already_installed: None,
            error: Some("boom".into()),
            config: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(
            !json.contains("\"config\""),
            "config must be skipped when None"
        );
    }

    /// `InstallComplete` success envelope DOES carry the `config` echo
    /// (the resolved shape — defaulted when the request omitted it).
    #[test]
    fn install_complete_success_carries_config_echo() {
        let event = InstallComplete {
            principal_id: "alice".into(),
            success: true,
            home_path: "/home/alice".into(),
            already_installed: None,
            error: None,
            config: Some(PrincipalConfig::default()),
        };
        let v: serde_json::Value = serde_json::to_value(&event).unwrap();
        assert_eq!(
            v.pointer("/config/interaction_mode").and_then(|x| x.as_str()),
            Some("headless")
        );
        assert_eq!(
            v.pointer("/config/auth_mode").and_then(|x| x.as_str()),
            Some("api_key")
        );
        assert_eq!(
            v.pointer("/config/schema_version").and_then(|x| x.as_u64()),
            Some(1)
        );
    }
}
