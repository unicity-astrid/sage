//! Per-principal config — the dual-axis (interaction × auth) shape
//! threaded through every `.claude/` writer in this crate.
//!
//! # Duplicate, not shared
//!
//! The canonical [`PrincipalConfig`] lives in the sibling `sage` crate at
//! `capsules/sage/crates/sage/src/config.rs`. We mirror the same shape
//! here so `sage-install` can branch the JSON writers without taking a
//! dependency on `sage` (the install crate runs in a separate WASM
//! component with its own KV namespace — the config is threaded over the
//! IPC envelope, not read out of a shared store). Keep the serde shape
//! byte-identical with the canonical type: any drift breaks the relink
//! envelope's `config` field.
//!
//! When the canonical type changes (new mode value, new field), update
//! both copies in the same commit, bump [`PrincipalConfig::SCHEMA_VERSION`]
//! to invalidate older relink envelopes, and add the back-compat default
//! branch to [`PrincipalConfig::validate`].

use serde::{Deserialize, Serialize};

/// How the user drives Claude. Wire-form is `"headless" | "repl"`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InteractionMode {
    /// Astrid spawns `claude -p` and drives the agent loop.
    #[default]
    Headless,
    /// User runs `claude` directly in the principal folder (native REPL).
    Repl,
}

/// How Claude authenticates. Wire-form is `"api_key" | "subscription"`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    /// Host SecretStore-backed Anthropic API key (default).
    #[default]
    ApiKey,
    /// User runs `claude /login` in the principal folder; macOS Keychain
    /// path is HOME-blind and not cryptographically principal-isolated.
    Subscription,
}

/// Per-principal sage config. Mirror of the canonical
/// `sage::config::PrincipalConfig` — see module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrincipalConfig {
    /// How the user drives Claude (headless vs repl).
    #[serde(default)]
    pub interaction_mode: InteractionMode,
    /// How Claude authenticates (api_key vs subscription).
    #[serde(default)]
    pub auth_mode: AuthMode,
    /// Forward-compat tag. Bumped when the shape changes incompatibly.
    #[serde(default = "PrincipalConfig::default_schema_version")]
    pub schema_version: u32,
}

impl Default for PrincipalConfig {
    fn default() -> Self {
        Self {
            interaction_mode: InteractionMode::default(),
            auth_mode: AuthMode::default(),
            schema_version: Self::SCHEMA_VERSION,
        }
    }
}

impl PrincipalConfig {
    /// Wire-format version. Persisted so older sage payloads can be
    /// detected and migrated; bump on incompatible shape changes.
    pub const SCHEMA_VERSION: u32 = 1;

    fn default_schema_version() -> u32 {
        Self::SCHEMA_VERSION
    }

    /// Best-effort sanity check. Today the serde enum variants are
    /// closed (anything else is a deserialize error), so the only thing
    /// left to enforce is `schema_version <= SCHEMA_VERSION` — a future
    /// payload from a newer sage would fail loudly here rather than be
    /// silently truncated to the default.
    #[allow(dead_code)]
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version > Self::SCHEMA_VERSION {
            return Err(format!(
                "PrincipalConfig.schema_version {} exceeds supported {} — upgrade sage-install",
                self.schema_version,
                Self::SCHEMA_VERSION
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_headless_api_key_v1() {
        let cfg = PrincipalConfig::default();
        assert_eq!(cfg.interaction_mode, InteractionMode::Headless);
        assert_eq!(cfg.auth_mode, AuthMode::ApiKey);
        assert_eq!(cfg.schema_version, 1);
    }

    #[test]
    fn serde_wire_format_uses_snake_case() {
        let cfg = PrincipalConfig {
            interaction_mode: InteractionMode::Repl,
            auth_mode: AuthMode::Subscription,
            schema_version: 1,
        };
        let v = serde_json::to_value(cfg).unwrap();
        assert_eq!(v["interaction_mode"], "repl");
        assert_eq!(v["auth_mode"], "subscription");
        assert_eq!(v["schema_version"], 1);
    }

    #[test]
    fn deserialise_accepts_missing_fields_via_defaults() {
        let cfg: PrincipalConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(cfg, PrincipalConfig::default());
    }

    #[test]
    fn validate_rejects_future_schema_version() {
        let cfg = PrincipalConfig {
            schema_version: u32::MAX,
            ..PrincipalConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_accepts_current_schema_version() {
        assert!(PrincipalConfig::default().validate().is_ok());
    }
}
