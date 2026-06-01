//! Per-principal sage runtime configuration.
//!
//! Two orthogonal axes, both serialised in snake_case wire form so the
//! values match the `[env]` `select` options the operator sees at install
//! time:
//!
//! * [`InteractionMode`] — `headless` (Astrid drives `claude -p`) versus
//!   `repl` (user runs `claude` directly in the principal folder).
//! * [`AuthMode`] — `api_key` (kernel-elicited secret, exported to the
//!   subprocess as `ANTHROPIC_API_KEY`) versus `subscription` (user runs
//!   `claude /login` manually; sage never sets `ANTHROPIC_API_KEY`).
//!
//! Persisted in sage's per-capsule per-principal KV namespace at the
//! single canonical key [`KV_KEY`]. The `#[astrid::install]` lifecycle
//! hook is the first writer; the `handle_settings_set` IPC interceptor
//! is the runtime writer thereafter. Both call
//! [`PrincipalConfig::validate`] before persisting — IPC input is
//! untrusted and the install env values pass through host elicitation
//! that does NOT enforce the snake_case alphabet.
//!
//! `schema_version` is set to 1 from day one so a future schema bump can
//! migrate or reject stale records without ambiguity.

use astrid_sdk::prelude::*;
use serde::{Deserialize, Serialize};

/// KV key under which the per-principal config record is stored. The
/// kernel scopes KV per capsule per principal, so the key needs no
/// principal suffix — sage's own KV namespace is already
/// principal-scoped at the host boundary.
pub(crate) const KV_KEY: &str = "sage.principal.config";

/// Current schema version. Bump only when the wire shape changes.
pub(crate) const SCHEMA_VERSION: u32 = 1;

/// How users drive `claude` in this principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InteractionMode {
    /// Sage spawns `claude -p` and owns the loop. Tools restricted to
    /// `mcp__sage__*`. Fail-secure default — the more restricted of
    /// the two interaction paths.
    #[default]
    Headless,
    /// User runs `claude` directly in the principal folder. Sage does
    /// not spawn the subprocess; tools are the native Claude Code tool
    /// set (no `mcp__sage__*` in v1 — pending the native MCP sidecar).
    Repl,
}

/// How `claude` authenticates against Anthropic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    /// Sage exports `ANTHROPIC_API_KEY` from the kernel-elicited
    /// `[env].api_key` secret on every spawn. Fail-secure default —
    /// fails closed on a missing secret rather than silently joining
    /// the user's keychain OAuth.
    #[default]
    ApiKey,
    /// User runs `claude /login` manually inside the principal folder.
    /// Sage never sets `ANTHROPIC_API_KEY`. On macOS, OAuth tokens are
    /// stored in a keychain entry keyed by service+account, NOT by
    /// `HOME` — two principal folders on the same macOS user share
    /// the credential. Document the caveat to the operator.
    Subscription,
}

/// Per-principal sage runtime configuration. Written by sage's install
/// hook on first run, by `handle_settings_set` thereafter. Read by
/// `handle_spawn` at the top of the spawn pipeline. Crate-private so
/// the canonical record never leaks across the capsule boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PrincipalConfig {
    /// Interaction mode (see [`InteractionMode`]).
    pub(crate) interaction_mode: InteractionMode,
    /// Auth mode (see [`AuthMode`]).
    pub(crate) auth_mode: AuthMode,
    /// Schema version. Always [`SCHEMA_VERSION`] for records written by
    /// this version of sage.
    pub(crate) schema_version: u32,
}

impl Default for PrincipalConfig {
    /// Fail-secure default for missing / malformed KV records:
    /// headless (the more restricted execution path) plus api_key (the
    /// auth mode that fails-closed on a missing secret rather than
    /// silently joining the user's keychain OAuth).
    fn default() -> Self {
        Self {
            interaction_mode: InteractionMode::default(),
            auth_mode: AuthMode::default(),
            schema_version: SCHEMA_VERSION,
        }
    }
}

impl PrincipalConfig {
    /// Validate the record. IPC input passes through here as a defence-
    /// in-depth gate against forged payloads (the serde enum alphabet
    /// already rejects unknown variants; this checks the numeric field
    /// since serde happily accepts any u32 there).
    pub(crate) fn validate(&self) -> Result<(), SysError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(SysError::ApiError(format!(
                "unsupported schema_version: got {}, expected {}",
                self.schema_version, SCHEMA_VERSION
            )));
        }
        Ok(())
    }
}

/// Load the current config from KV, or return [`PrincipalConfig::default`]
/// when the key is missing or the payload fails to deserialize. Fail-
/// secure on parse error so a corrupted record cannot crash the spawn
/// path — the default {Headless, ApiKey, schema_version=1} is the
/// safest fallback.
pub(crate) fn load_or_default() -> PrincipalConfig {
    match kv::get_json_opt::<PrincipalConfig>(KV_KEY) {
        Ok(Some(cfg)) => {
            if cfg.validate().is_ok() {
                cfg
            } else {
                log::warn(format!(
                    "sage: principal config schema_version {} unsupported; using default",
                    cfg.schema_version
                ));
                PrincipalConfig::default()
            }
        }
        Ok(None) => PrincipalConfig::default(),
        Err(e) => {
            log::warn(format!(
                "sage: failed to load principal config: {e:?}; using default"
            ));
            PrincipalConfig::default()
        }
    }
}

/// Persist a config record to KV under [`KV_KEY`]. Callers MUST call
/// [`PrincipalConfig::validate`] before invoking this.
pub(crate) fn save(cfg: &PrincipalConfig) -> Result<(), SysError> {
    kv::set_json(KV_KEY, cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_headless_api_key() {
        let cfg = PrincipalConfig::default();
        assert_eq!(cfg.interaction_mode, InteractionMode::Headless);
        assert_eq!(cfg.auth_mode, AuthMode::ApiKey);
        assert_eq!(cfg.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn snake_case_wire_form() {
        let cfg = PrincipalConfig {
            interaction_mode: InteractionMode::Repl,
            auth_mode: AuthMode::Subscription,
            schema_version: SCHEMA_VERSION,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        assert!(json.contains("\"interaction_mode\":\"repl\""));
        assert!(json.contains("\"auth_mode\":\"subscription\""));
    }

    #[test]
    fn round_trips_through_json() {
        let cfg = PrincipalConfig {
            interaction_mode: InteractionMode::Headless,
            auth_mode: AuthMode::Subscription,
            schema_version: SCHEMA_VERSION,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: PrincipalConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, parsed);
    }

    #[test]
    fn validate_rejects_unknown_schema_version() {
        let cfg = PrincipalConfig {
            interaction_mode: InteractionMode::Headless,
            auth_mode: AuthMode::ApiKey,
            schema_version: 99,
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_accepts_current_schema_version() {
        assert!(PrincipalConfig::default().validate().is_ok());
    }

    // Partial-update round-trip: the SettingsSetRequest shape uses
    // Option<...> for each field so absent fields preserve the current
    // value. Verified at the handler level — here we mirror the merge
    // semantic explicitly to lock the contract in. The Option<_> patch
    // values are sourced from real JSON deserialization (rather than
    // constructed as literals) so the merge expression operates on
    // opaque-to-the-compiler Options — locking the semantic without
    // tripping `clippy::unnecessary_literal_unwrap`.
    #[test]
    fn partial_update_preserves_absent_interaction_mode() {
        // Helper takes opaque Option<_> by-value so clippy can't see
        // through to a literal None/Some at the call site.
        fn merge(
            current: PrincipalConfig,
            patch_interaction: Option<InteractionMode>,
            patch_auth: Option<AuthMode>,
        ) -> PrincipalConfig {
            PrincipalConfig {
                interaction_mode: patch_interaction.unwrap_or(current.interaction_mode),
                auth_mode: patch_auth.unwrap_or(current.auth_mode),
                schema_version: SCHEMA_VERSION,
            }
        }

        let current = PrincipalConfig {
            interaction_mode: InteractionMode::Repl,
            auth_mode: AuthMode::ApiKey,
            schema_version: SCHEMA_VERSION,
        };

        // Simulate handle_settings_set with a partial IPC payload:
        // interaction_mode absent, auth_mode present. Deserialize the
        // real wire shape so the Option<_> values come from serde, not
        // from literal `Some(...)` / `None`.
        #[derive(Deserialize)]
        struct PartialPatch {
            #[serde(default)]
            interaction_mode: Option<InteractionMode>,
            #[serde(default)]
            auth_mode: Option<AuthMode>,
        }
        let payload = r#"{"auth_mode":"subscription"}"#;
        let patch: PartialPatch = serde_json::from_str(payload).unwrap();
        // Confirm the patch shape before exercising the merge — guards
        // against a future serde change silently breaking the contract.
        assert!(patch.interaction_mode.is_none());
        assert_eq!(patch.auth_mode, Some(AuthMode::Subscription));

        let merged = merge(current, patch.interaction_mode, patch.auth_mode);

        // interaction_mode preserved from current, auth_mode taken from
        // the patch.
        assert_eq!(merged.interaction_mode, InteractionMode::Repl);
        assert_eq!(merged.auth_mode, AuthMode::Subscription);
    }

    // Defence: serde must reject unknown enum variants at deserialize
    // time. This is the closed-alphabet guarantee `validate()` relies on
    // — without it, IPC input with `"interaction_mode":"hybrid"` would
    // round-trip as a valid record. Pairs with
    // `load_or_default`'s fail-secure-on-Err path: a malformed KV
    // record produces an Err here, which `load_or_default` catches and
    // degrades to default with no panic.
    #[test]
    fn deserialize_rejects_unknown_interaction_mode() {
        let bad = r#"{"interaction_mode":"hybrid","auth_mode":"api_key","schema_version":1}"#;
        let parsed: Result<PrincipalConfig, _> = serde_json::from_str(bad);
        assert!(parsed.is_err());
    }

    #[test]
    fn deserialize_rejects_unknown_auth_mode() {
        let bad =
            r#"{"interaction_mode":"headless","auth_mode":"oauth_pkce","schema_version":1}"#;
        let parsed: Result<PrincipalConfig, _> = serde_json::from_str(bad);
        assert!(parsed.is_err());
    }

    #[test]
    fn malformed_json_fails_to_deserialize() {
        // Garbage payload — the kv::get_json_opt host call would return
        // Err on this shape, which load_or_default catches and degrades
        // to default. Verify the shape itself does fail to parse so the
        // fail-secure path is actually reached.
        let parsed: Result<PrincipalConfig, _> = serde_json::from_str("not json at all");
        assert!(parsed.is_err());
        let parsed: Result<PrincipalConfig, _> = serde_json::from_str("{}");
        assert!(parsed.is_err());
    }

    // Serde shape for the IPC request payload: both fields optional.
    #[test]
    fn settings_set_request_partial_payload_round_trips() {
        // Only auth_mode set; interaction_mode absent from the JSON.
        let payload = r#"{"principal_id":"p1","auth_mode":"subscription"}"#;
        #[derive(Deserialize)]
        struct Probe {
            principal_id: String,
            #[serde(default)]
            interaction_mode: Option<InteractionMode>,
            #[serde(default)]
            auth_mode: Option<AuthMode>,
        }
        let probe: Probe = serde_json::from_str(payload).unwrap();
        assert_eq!(probe.principal_id, "p1");
        assert!(probe.interaction_mode.is_none());
        assert_eq!(probe.auth_mode, Some(AuthMode::Subscription));
    }
}
