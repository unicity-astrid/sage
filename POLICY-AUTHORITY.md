# Sage policy authority — the sage-side of governed-Claude (#901)

Tracks the sage half of #901 ("govern Claude Code via its native policy engine").
#901 lists the **core** deliverables (`astrid-gate`, `policyHelper`, the
managed-settings template, the bwrap fail-open fix); this is the **sage** half
they talk to: the per-principal policy engine, the live verdict responder, and
the signed-snapshot authority.

The policy engine is `sage-mcp` `policy::evaluate` (first-match-wins, default
Allow, linear matchers — no regex). One operator rule set, two transports.

## Status

| Piece | State |
|---|---|
| `policy::evaluate` engine | **shipped** (`sage-mcp/src/policy.rs`) |
| Plane A — `mcp__sage__*` broker chokepoint gate | **shipped** (`broker::handle_mcp_call`, un-bypassable) |
| Plane B — native-tool `before_tool_call` verdict responder | **shipped, this slice** (`sage-mcp/src/hook_gate.rs`) |
| mcp_tool gate (MVP native transport) | shipped, **stopgap** — retires when `astrid-gate` lands (`broker::pretooluse_gate_reply`) |
| Managed-settings template (rich) | partial — `managed_settings_json` is a subset; grow to #901's full lock |
| Signed-snapshot minting | **blocked** on the signing-location decision (below) |
| Snapshot serving (for `policyHelper`) | not started — depends on minting |
| Revocation channel | not started |

## Wire contract 1 — gate ↔ responder (live verdict) — DEFINED + responder shipped

The `astrid-gate` PreToolUse hook (core, #901) and the sage responder speak the
existing **hook-bridge `ToolCallBefore`** contract, so the responder is
interoperable whether the publisher is the kernel bridge or `astrid-gate`:

- **request** → `hook.v1.event.before_tool_call`, body
  `{ hook, payload: { tool_name, tool_input, … }, correlation_id }`.
- **reply** → `hook.v1.response.before_tool_call.<correlation_id>`, body
  `{ skip: bool, reason? }`. **`skip:true` blocks** (deny-wins merge — any
  participant can veto). No `correlation_id` ⇒ observe-only, no reply.
- **deadline / fail-open**: `astrid-gate` owns a ~3 s deadline and on timeout
  emits its OWN verdict (degrade to managed `ask`), never leaning on Claude's
  hook timeout (which is fail-open). The responder is best-effort: a missing
  reply = "no opinion" to the merge.

Full spec lives in `sage-mcp/src/hook_gate.rs` (module doc). `astrid-gate`
builds against this; nothing further is needed sage-side for the live path.

**Proxy dependency**: the CLI-uplink ingress allowlist must permit
`hook.v1.event.before_tool_call` (publish, from an external `astrid-gate`) and
`hook.v1.response.before_tool_call.*` (subscribe) — a capsule-cli change, same
shape as the prior `sage.v1.hook.*` allow.

## Wire contract 2 — policyHelper ↔ snapshot (offline cache) — DESIGN, blocked

`policyHelper` (core, managed-only executable) emits Claude's managed
`permissions` JSON, computed from a signed snapshot it can verify offline.

- **snapshot** = `{ principal, permissions, tiers, issued_at, expires_at }` +
  ed25519 signature over canonical bytes; `policyHelper` verifies with an
  embedded public key, checks expiry, serves last-good from a signed local
  cache when the daemon is unreachable (24 h TTL, 15 min refresh,
  degrade-to-most-restrictive on expiry).
- **fetch** = `policyHelper` requests `sage.v1.policy.snapshot.request {principal}`
  → authority replies on a correlation topic with the signed snapshot.

## Open decision (yours) — where signing lives

A WASM capsule has **no key custody** (no capsule `sign` host fn; ed25519 is
daemon-side in `astrid-crypto`). So "sage mints signed snapshots" can't be
literally in-capsule. Two options:

1. **daemon-side minter (recommended)** — sage hands the daemon the policy
   content; the daemon signs with its key and serves. Keeps key custody where
   it already is; no new signing primitive exposed to capsules.
2. **capability-gated `sign` host fn** — sage calls it. More flexible, but hands
   capsules a signing primitive (a capability surface to reason about).

This decision gates the **minting + snapshot-serving** legs only. The **live
verdict responder** (this slice) needs no signing and is done.

## Sequencing

- Live path: responder (done) + `astrid-gate` (core) + the proxy allow → working
  native-tool gate. No signing dependency.
- Offline path: signing decision → minter → snapshot serving → `policyHelper`.
- When `astrid-gate` lands: sage-install migrates the PreToolUse hook authoring
  `mcp_tool → astrid-gate`, and `broker::pretooluse_gate_reply` (the MVP) retires.
- Mode 2 immutable config rides #890 (read-only file-injection, closes #881).
