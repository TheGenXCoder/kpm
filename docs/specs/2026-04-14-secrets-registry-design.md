# KPM Secrets Registry — Design Spec

**Date:** 2026-04-14
**Status:** Approved for implementation
**Scope:** First build — `kpm add`, `kpm list`, `kpm remove`, AgentKMS write endpoint

---

## Problem

Developers store secrets in dozens of places — .env files, Obsidian notes, Apple Notes, Slack messages, SSH config, random credential files. No system, no audit trail, no revocation. KPM currently handles secret *usage* (templates, env injection, encryption) but has no front door for getting secrets *into* the system.

## Solution

A secrets registry that organizes secrets by service, makes them discoverable via `kpm list`, and ensures every write is audited and policy-checked through AgentKMS.

## Design Principles

1. **Secrets are never human-readable** in commands, arguments, logs, or output
2. **Every write goes through AgentKMS** — audited, policy-checked, mTLS-authenticated
3. **`service/name` is the only required structure** — tags, description, expiry are optional
4. **ABAC policy model** — attributes on identity (cert) and policy (server config), not on secrets
5. **KPM is the client, AgentKMS is the engine** — KPM is the funnel, AgentKMS is the product

---

## Data Model

### Secret Path

`service/name` — maps to AgentKMS KV at `kv/generic/{service}/{name}`

Examples:
- `cloudflare/dns-token`
- `github/personal-pat`
- `anthropic/api-key`
- `db/postgres-prod`
- `ssh/deploy-key`

### Secret Metadata

Stored as fields alongside the secret value in the KV store:

| Field | Required | Purpose |
|-------|----------|---------|
| `_value` | Yes | The secret itself (never exposed in list/show) |
| `_description` | No | Human-readable note ("DNS edit token for catalyst9.ai zone") |
| `_tags` | No | Comma-separated tags ("ci,dns,production") |
| `_created` | Auto | ISO-8601 timestamp |
| `_updated` | Auto | ISO-8601 timestamp |
| `_expires` | No | ISO-8601 expiry (informational — policy enforces access) |
| `_type` | No | "api-token", "password", "certificate", "ssh-key", "connection-string" |

Underscore prefix prevents collision with actual secret fields for multi-field secrets.

### Multi-field Secrets

Some secrets have multiple related values (e.g., AWS needs access_key + secret_key):

```bash
kpm add aws/prod
  Access Key ID: ****
  Secret Access Key: ****
```

Stored as `kv/generic/aws/prod` with fields `access_key_id` and `secret_access_key` (plus `_metadata` fields).

---

## Commands

### kpm add

Stores a secret in AgentKMS.

```bash
# Interactive (default) — value prompted with masked input
kpm add cloudflare/dns-token
  Value: ****
  Description (optional): DNS edit token for catalyst9.ai
  Tags (optional): dns,ci

# From clipboard/pipe
pbpaste | kpm add cloudflare/dns-token

# From file (SSH keys, certs)
kpm add ssh/deploy-key --from ~/.ssh/deploy_key

# With metadata flags
kpm add cloudflare/dns-token --tags dns,ci --description "catalyst9.ai DNS" --type api-token --expires 2027-01-01
```

**Behavior:**
- Prompts for value with masked input (like ssh-keygen passphrase prompt)
- Sends `POST /credentials/generic/{service}/{name}` to AgentKMS
- Confirms: `Stored cloudflare/dns-token (tagged: dns, ci)`
- If secret already exists, prompts: `cloudflare/dns-token already exists. Overwrite? [y/N]`

### kpm list

Shows secrets by service. Never shows values.

```bash
# All secrets
kpm list

cloudflare/
  dns-token          api-token   [dns, ci]        "catalyst9.ai DNS"
  redirect-rules     api-token   [dns]

github/
  personal-pat       api-token   [dev]
  deploy-key         ssh-key     [ci, production]

anthropic/
  api-key            api-token   [dev, ci]

# Filter by service
kpm list cloudflare

# Filter by tag
kpm list --tag ci

# Filter by type
kpm list --type ssh-key
```

**Behavior:**
- Fetches secret listing from AgentKMS (needs a list endpoint or convention)
- Groups by service (first path segment)
- Shows: name, type, tags, description — never values
- Indicates expired secrets if `_expires` is past

### kpm remove

Revokes/deletes a secret.

```bash
kpm remove cloudflare/dns-token
  Remove cloudflare/dns-token? This cannot be undone. [y/N] y
  Removed cloudflare/dns-token
```

**Behavior:**
- Sends `DELETE /credentials/generic/{service}/{name}` to AgentKMS
- Requires confirmation
- Audited server-side

### kpm describe (future)

Show metadata about a secret without revealing the value.

```bash
kpm describe cloudflare/dns-token

cloudflare/dns-token
  Type:        api-token
  Tags:        dns, ci
  Description: catalyst9.ai DNS
  Created:     2026-04-14T10:30:00Z
  Updated:     2026-04-14T10:30:00Z
  Expires:     2027-01-01T00:00:00Z
  Access:      bert (unrestricted), ci-server (read-only)
```

---

## AgentKMS Changes

### New endpoint: POST /credentials/generic/{path}

Write a secret to the KV store. Mirrors the existing GET endpoint.

**Request:**
```json
{
  "secrets": {
    "_value": "the-actual-secret",
    "_description": "catalyst9.ai DNS edit token",
    "_tags": "dns,ci",
    "_type": "api-token",
    "_created": "2026-04-14T10:30:00Z"
  }
}
```

**Response:**
```json
{
  "path": "cloudflare/dns-token",
  "status": "created",
  "version": 1
}
```

**Security:**
- mTLS required
- Policy check: caller must have `write` permission for this path
- Audit event logged with operation=credential_write, path, caller — never the value
- Rate limited (configurable)

### New endpoint: DELETE /credentials/generic/{path}

Delete a secret from the KV store.

### New endpoint: GET /credentials/generic (list)

List all secret paths the caller has access to (metadata only, never values).

**Response:**
```json
{
  "secrets": [
    {
      "path": "cloudflare/dns-token",
      "type": "api-token",
      "tags": ["dns", "ci"],
      "description": "catalyst9.ai DNS",
      "created": "2026-04-14T10:30:00Z"
    }
  ]
}
```

---

## ABAC Policy Model (designed now, basic implementation first)

### Attributes available at evaluation time

| Attribute | Source | First build |
|-----------|--------|-------------|
| `caller` | mTLS cert CN | Yes |
| `team` | mTLS cert O | Yes |
| `role` | mTLS cert OU | Yes |
| `machine` | mTLS cert CN/SAN | Yes |
| `secret_path` | Path being accessed | Yes |
| `operation` | read, write, list, delete | Yes |
| `time` | Server wall clock | Next iteration |
| `network` | Source IP/CIDR | Next iteration |
| `secret_tags` | Tags on the secret | Next iteration |
| `session_age` | Time since token issued | Next iteration |

### Policy rule structure

```yaml
rules:
  - id: bert-full-access
    effect: allow
    match:
      caller: bert
    resources: ["*"]

  - id: bill-office-hours
    effect: allow
    match:
      caller: bill
      time: "0600-1800"
      machine: bills-laptop
      network: "10.2.10.0/24"
    resources: ["db/*", "app/*"]

  - id: ci-readonly
    effect: allow
    match:
      role: service
    resources: ["*"]
    operations: [read, list]

  - id: deny-all
    effect: deny
    match: {}
    resources: ["*"]
```

Evaluation: first match wins, explicit deny-all at bottom. Extends existing AgentKMS policy engine with more attributes.

### First implementation

Basic allow/deny with: caller, team, role, machine, secret_path, operation. Sufficient for dev and small team use. ABAC attributes (time, network, tags) added in next iteration.

### Future: Split knowledge / dual control (PCI-DSS)

Secrets flagged with `split: true` require N of M authorized callers to authenticate within a time window before AgentKMS releases the value. Each caller provides their mTLS cert, AgentKMS collects the quorum, then vends. KPM handles "waiting for additional authorization" response. Designed but not scoped for implementation.

---

## Integration with existing KPM features

### kpm add → kpm env/run flow

1. `kpm add anthropic/api-key` — stores in AgentKMS
2. Template references it: `ANTHROPIC_API_KEY=${kms:llm/anthropic}` (or `${kms:kv/anthropic/api-key#_value}`)
3. `kpm env --from template` — resolves from AgentKMS, encrypted by default
4. `kpm run -- myapp` — decrypts at moment of use

### Template reference mapping

The `kpm add` path `service/name` maps to AgentKMS KV at `kv/generic/{service}/{name}`. Template references:

- `${kms:kv/cloudflare/dns-token#_value}` — explicit
- `${kms:cloudflare/dns-token}` — shorthand (resolves `_value` field by default)

The shorthand makes templates cleaner. The resolver treats a bare reference (no `#field`) as `#_value`.

### kpm list → kpm tree relationship

- `kpm list` — shows secrets in the registry (what's stored)
- `kpm tree` — shows templates and what secrets they reference (what's used)

Both are views into the same system from different angles.

---

## Implementation order

1. AgentKMS: `POST /credentials/generic/{path}` write endpoint (dev server)
2. AgentKMS: `GET /credentials/generic` list endpoint (dev server)
3. AgentKMS: `DELETE /credentials/generic/{path}` delete endpoint (dev server)
4. KPM: `kpm add` with interactive, pipe, and file input
5. KPM: `kpm list` with service and tag filtering
6. KPM: `kpm remove` with confirmation
7. KPM: Update template resolver to support `${kms:service/name}` shorthand
8. Tests for all of the above
9. Update quickstart to seed secrets using `kpm add` instead of `agentkms-dev secrets set`

---

## Blog post series outline

### Part 1: "Your secrets are everywhere. Here's one place for all of them."
- The scattered secrets problem (real examples)
- Install KPM + quickstart
- `kpm add`, `kpm list` — get organized
- `kpm env` + `kpm run` — use them securely

### Part 2: "Your .env files are a liability."
- Templates replace .env files
- Ciphertext by default, JIT decrypt
- `kpm show` — safe inspection
- mock-codex demo (ciphertext → decrypted)

### Part 3: "One config across all your machines."
- Config profiles
- `kpm import --scan` (interactive migration)
- Push/pull across machines
- The CISO pitch: revoke access, configs evaporate

### Part 4: "Securing AI agent workflows."
- `kpm run --secure` for agentic workloads
- Process-scoped secrets (PID-tree, delegated sessions)
- Per-agent audit trails
- The regulated industry story
