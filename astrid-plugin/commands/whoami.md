---
description: Show the Astrid principal this session acts as, plus its capabilities and quota.
allowed-tools: Bash(astrid agent current:*), Bash(astrid caps show:*), Bash(astrid quota show:*)
---

Report the Astrid identity and mandate backing this session.

Active principal:

!`astrid agent current 2>/dev/null || echo "(unavailable — is the astrid CLI installed?)"`

Capabilities held by that principal:

!`astrid caps show 2>/dev/null || echo "(unavailable — the daemon may be down)"`

Quota / budget:

!`astrid quota show 2>/dev/null || echo "(unavailable — the daemon may be down)"`

Summarize in a few lines: who this session acts as, what it is allowed to do, and any budget limits. If a section is unavailable, say so and note that `astrid start` brings the daemon up.
