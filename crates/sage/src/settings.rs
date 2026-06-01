//! `handle_settings_set` business logic.
//!
//! Split out of `lib.rs` to keep that file under the 1000-line CI gate.
//! The interceptor wrapper lives on the `Sage` impl in `lib.rs`; this
//! module owns the partial-patch / validate / persist / publish chain
//! and emits both the new settings-changed topic and the relink trigger.
//!
//! Contract / ordering (see the wrapper's doc-comment for the canonical
//! version):
//!
//! 1. `sage.v1.audit.settings_changed` — covered by the existing
//!    `sage.v1.audit.*` wildcard `[publish]` declaration; emitted BEFORE
//!    the relink trigger so an audit consumer sees the intent even if
//!    the relink reply never arrives.
//! 2. `sage.v1.install.relink` — triggers sage-install's `handle_relink`;
//!    the file rewrite happens in sage-install's per-capsule KV
//!    namespace (distinct from sage's), so the new config travels
//!    in-payload (see S2/S4 — `RelinkRequest` carries an optional
//!    `config` field for cross-namespace propagation).
//! 3. `sage.v1.settings.changed` — emitted synchronously after the
//!    relink trigger publish. The current slice does NOT block on the
//!    matching `sage.v1.install.complete` reply; an asynchronous
//!    wait-for-relink-complete pattern can be added if a consumer needs
//!    hard ordering. Flagged for follow-up in the S8 doc.
//!
//! TODO(astrid-rfcs#TBD): mirror to a shared cross-capsule audit topic
//! once a convention lands; kernel-side `astrid.v1.audit.entry` is
//! admin-action-shaped and not the right home.

use astrid_sdk::prelude::*;

use crate::config;
use crate::{SettingsSetRequest, validate_id};

const AUDIT_TOPIC: &str = "sage.v1.audit.settings_changed";
const RELINK_TOPIC: &str = "sage.v1.install.relink";
const CHANGED_TOPIC: &str = "sage.v1.settings.changed";

/// Apply a `SettingsSetRequest` end-to-end. Never propagates errors:
/// internal failures publish an `error` field on the audit topic and
/// return Ok (interceptor contract — publishers don't see handler
/// errors). The caller (the interceptor in `lib.rs`) just returns the
/// `Ok(())` we return here.
pub(crate) fn apply(req: SettingsSetRequest) -> Result<(), SysError> {
    // Untrusted input gate. principal_id flows into the relink payload
    // and audit publish; reject anything outside the standard alphabet
    // before the value escapes into formatted strings.
    if let Err(e) = validate_id("principal_id", &req.principal_id) {
        let _ = ipc::publish_json(
            AUDIT_TOPIC,
            &serde_json::json!({
                "principal_id": req.principal_id,
                "error": format!("invalid_principal_id: {e}"),
            }),
        );
        return Ok(());
    }

    // Load existing config (or default) and capture for audit.
    let previous = config::load_or_default();

    // Apply partial patch: absent Option fields preserve the current
    // value; present fields overwrite.
    let merged = config::PrincipalConfig {
        interaction_mode: req
            .interaction_mode
            .unwrap_or(previous.interaction_mode),
        auth_mode: req.auth_mode.unwrap_or(previous.auth_mode),
        schema_version: config::SCHEMA_VERSION,
    };

    // Defence-in-depth: validate the merged record even though the
    // serde enum alphabet has already filtered unknown variants —
    // `schema_version` is a u32 and could be forged by a future
    // upstream change.
    if let Err(e) = merged.validate() {
        let _ = ipc::publish_json(
            AUDIT_TOPIC,
            &serde_json::json!({
                "principal_id": req.principal_id,
                "previous_config": previous,
                "error": format!("validate_failed: {e}"),
            }),
        );
        return Ok(());
    }

    // Persist. KV write errors surface as audit-error + Ok.
    if let Err(e) = config::save(&merged) {
        let _ = ipc::publish_json(
            AUDIT_TOPIC,
            &serde_json::json!({
                "principal_id": req.principal_id,
                "previous_config": previous,
                "error": format!("kv_save_failed: {e:?}"),
            }),
        );
        return Ok(());
    }

    // Ordered publish chain — see module doc-comment for the rationale
    // on this exact ordering.

    // (1) sage.v1.audit.settings_changed FIRST.
    let _ = ipc::publish_json(
        AUDIT_TOPIC,
        &serde_json::json!({
            "principal_id": req.principal_id,
            "previous_config": previous,
            "new_config": merged,
        }),
    );

    // (2) sage.v1.install.relink: trigger sage-install's rewrite. The
    // merged config is threaded into the payload so sage-install (in a
    // different KV namespace) does not need to read sage's KV.
    let _ = ipc::publish_json(
        RELINK_TOPIC,
        &serde_json::json!({
            "principal_id": req.principal_id,
            "config": merged,
        }),
    );

    // (3) sage.v1.settings.changed. Synchronous w.r.t. the relink
    // trigger publish — NOT awaiting the relink-complete reply.
    // Hard-ordering consumers should drive their own
    // `sage.v1.install.complete` subscription.
    let _ = ipc::publish_json(
        CHANGED_TOPIC,
        &serde_json::json!({
            "principal_id": req.principal_id,
            "config": merged,
            "schema_version": config::SCHEMA_VERSION,
        }),
    );

    Ok(())
}
