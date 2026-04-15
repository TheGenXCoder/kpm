# KPM Secrets Registry — Design Spec (v2)

**Date:** 2026-04-14
**Revised:** 2026-04-14 (incorporated Grok review feedback)
**Status:** Approved for implementation
**Scope:** First public release — registry, scanner, separated data model, versioning

---

## Problem

Developers store secrets in dozens of places — .env files, Obsidian notes, Apple Notes, Slack messages, SSH config, random credential files. No system, no audit trail, no revocation. KPM currently handles secret *usage* (templates, env injection, encryption) but has no front door for getting secrets *into* the system.

## Solution

A secrets registry that organizes secrets by service, makes them discoverable via `kpm list`, and ensures every write is audited and policy-checked through AgentKMS. Combined with an interactive import scanner that finds secrets scattered across your filesystem and brings them into one place.

## Design Principles

1. **Secrets are never human-readable** in commands, arguments, logs, or output
2. **Every write goes through AgentKMS** — audited, policy-checked, mTLS-authenticated
3. **`service/name` is the only required structure** — tags, description, expiry are optional
4. **ABAC policy model** — attributes on identity (cert) and policy (server config), not on secrets
5. **KPM is the client, AgentKMS is the engine** — KPM is the funnel, AgentKMS is the product
6. **Metadata is separated from secret values** — list/describe never touches the secrets store
7. **Secrets are versioned** — every write creates a new version, previous versions retained for audit

---

## Data Model

### Separated Storage (Grok review: don't mix metadata with values)

Two parallel KV paths in AgentKMS:

```
kv/secrets/{service}/{name}     → the actual secret value(s)
kv/metadata/{service}/{name}    → description, tags, type, timestamps, version info
```

**Why separate:**
- List endpoint queries metadata store only — zero risk of value leakage
- Multi-field secrets stay clean (no underscore prefix conventions)
- Versioning is natural — metadata tracks version count, secrets store holds current + history
- Audit and policy evaluation don't need to load secret values
- Different access controls possible (list metadata without read access to values)

### Secret Path

`service/name` — the user-facing identifier.

Examples:
- `cloudflare/dns-token`
- `github/personal-pat`
- `anthropic/api-key`
- `db/postgres-prod`
- `ssh/deploy-key`

### Metadata Record

Stored at `kv/metadata/{service}/{name}`:

```json
{
  "service": "cloudflare",
  "name": "dns-token",
  "description": "DNS edit token for catalyst9.ai zone",
  "tags": ["dns", "ci", "production"],
  "type": "api-token",
  "created": "2026-04-14T10:30:00Z",
  "updated": "2026-04-14T15:00:00Z",
  "expires": "2027-01-01T00:00:00Z",
  "version": 3,
  "versions": [
    {"version": 1, "created": "2026-04-14T10:30:00Z", "caller": "bert"},
    {"version": 2, "created": "2026-04-14T12:00:00Z", "caller": "bert"},
    {"version": 3, "created": "2026-04-14T15:00:00Z", "caller": "bert"}
  ]
}
```

### Secret Value Record

Stored at `kv/secrets/{service}/{name}`:

```json
{
  "value": "the-actual-secret"
}
```

For multi-field secrets (e.g., AWS):

```json
{
  "access_key_id": "AKIA...",
  "secret_access_key": "wJalr..."
}
```

### Secret Versioning

Every `kpm add` to an existing path creates a new version:
- Current value stored at `kv/secrets/{service}/{name}`
- Previous version moved to `kv/secrets/{service}/{name}/v{N}`
- Metadata `versions` array updated
- Configurable retention: keep last N versions (default: 10)
- Old versions are readable via `kpm get service/name --version 2` (audited)
- `kpm history service/name` shows version timeline (metadata only, no values)

### Secret Types

Optional classification for display and validation:

| Type | Description | Detected by scanner |
|------|-------------|-------------------|
| `api-token` | API key / bearer token | Prefix patterns (sk-, ghp_, AKIA, etc.) |
| `password` | Password / passphrase | Key name patterns (password, passwd, secret) |
| `certificate` | TLS/SSL cert or key | `-----BEGIN` header |
| `ssh-key` | SSH private/public key | `-----BEGIN OPENSSH` or `ssh-rsa` |
| `connection-string` | Database connection URL | `postgres://`, `mongodb://`, etc. |
| `jwt` | JSON Web Token | `eyJ` prefix with period separators |
| `generic` | Unclassified secret | Default |

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
- Sends to AgentKMS: secret value to `POST /secrets/{path}`, metadata to `POST /metadata/{path}`
- Confirms: `Stored cloudflare/dns-token (tagged: dns, ci)`
- If secret already exists: creates new version, prompts `cloudflare/dns-token exists (v2). Update to v3? [y/N]`
- Auto-detects type from value format if `--type` not specified

### kpm list

Shows secrets by service. Never shows values.

```bash
# All secrets
kpm list

cloudflare/
  dns-token          api-token   [dns, ci]        "catalyst9.ai DNS"            v3
  redirect-rules     api-token   [dns]                                          v1

github/
  personal-pat       api-token   [dev]                                          v2
  deploy-key         ssh-key     [ci, production]  "deploy to prod servers"     v1

anthropic/
  api-key            api-token   [dev, ci]                                      v1  EXPIRES in 30d

# Filter by service
kpm list cloudflare

# Filter by tag
kpm list --tag ci

# Filter by type
kpm list --type ssh-key
```

**Behavior:**
- Queries metadata store only (GET /metadata) — never touches secrets
- Groups by service (first path segment)
- Shows: name, type, tags, description, version, expiry warnings
- Indicates expired or soon-to-expire secrets

### kpm remove

Soft-deletes a secret. Value retained for audit trail, marked as deleted in metadata.

```bash
kpm remove cloudflare/dns-token
  Remove cloudflare/dns-token (v3)? Secret will be marked deleted. [y/N] y
  Removed cloudflare/dns-token
```

**Behavior:**
- Marks metadata as `"deleted": true, "deleted_at": "...", "deleted_by": "bert"`
- Secret value retained in versioned store for audit/compliance
- `kpm list` no longer shows it (unless `--include-deleted`)
- Hard delete available via `kpm remove --purge` (requires elevated policy)

### kpm describe

Show metadata about a secret without revealing the value.

```bash
kpm describe cloudflare/dns-token

cloudflare/dns-token
  Type:        api-token
  Tags:        dns, ci
  Description: catalyst9.ai DNS
  Created:     2026-04-14T10:30:00Z
  Updated:     2026-04-14T15:00:00Z
  Expires:     2027-01-01T00:00:00Z
  Version:     3 (3 versions retained)
  Access:      bert (unrestricted), ci-server (read-only)
```

### kpm history

Show version history for a secret. Metadata only — never values.

```bash
kpm history cloudflare/dns-token

cloudflare/dns-token — 3 versions

  v3  2026-04-14T15:00:00Z  bert    (current)
  v2  2026-04-14T12:00:00Z  bert    
  v1  2026-04-14T10:30:00Z  bert    
```

### kpm import --scan

Interactive scanner that finds secrets in existing files and brings them into KPM.

```bash
kpm import --scan ~/.config

Scanning ~/.config/ ...

Found 47 files, 12 potential secrets:

  ~/.config/gh/hosts.yml
    [x] oauth_token          → github/gh-cli-token          (api-token)

  ~/.bashrc
    [x] ANTHROPIC_API_KEY    → anthropic/api-key             (api-token)
    [x] OPENAI_API_KEY       → openai/api-key                (api-token)
    [ ] EDITOR=nvim          (not a secret — skipped)

  ~/.config/myapp/config.yaml
    [x] db_password          → myapp/db-password             (password)
    [x] api_secret           → myapp/api-secret              (api-token)
    [ ] log_level: info      (not a secret — skipped)

  ~/.ssh/id_ed25519
    [x] private key          → ssh/personal                  (ssh-key)

Use arrow keys to select/deselect, Enter to confirm.

Store 6 secrets in AgentKMS? [Y/n] y

  Stored github/gh-cli-token (api-token)
  Stored anthropic/api-key (api-token)
  Stored openai/api-key (api-token)
  Stored myapp/db-password (password)
  Stored myapp/api-secret (api-token)
  Stored ssh/personal (ssh-key)

✓ 6 secrets imported to AgentKMS
✓ 4 files can be converted to templates (run: kpm import --templatize)
```

**Detection patterns (priority order):**

1. **API key prefixes:** `sk-`, `pk_`, `AKIA`, `ghp_`, `gho_`, `sg-`, `xoxb-`, `xoxp-`, `Bearer `, `token_`
2. **Connection strings:** `postgres://`, `mongodb://`, `mysql://`, `redis://`, `amqp://` containing passwords
3. **Private key headers:** `-----BEGIN OPENSSH PRIVATE KEY-----`, `-----BEGIN RSA PRIVATE KEY-----`, `-----BEGIN EC PRIVATE KEY-----`, `-----BEGIN PRIVATE KEY-----`
4. **JWTs:** `eyJ` prefix with 2+ period separators, length > 40
5. **Env var patterns:** `export VAR=value` or `VAR=value` where key name contains: password, secret, token, api_key, access_key, private_key, connection_string
6. **High-entropy strings:** Base64 blobs > 20 chars, hex strings > 32 chars in config file contexts
7. **AWS key pairs:** `AKIA[0-9A-Z]{16}` with nearby 40-char base64 string

**Safety rules:**
- Never auto-add anything — always interactive selection
- `--dry-run` flag shows what would be found without prompting
- Never transmit potential secrets until user explicitly confirms
- Never modify source files (templatization is a separate opt-in step)
- Chunk scanning for large directories (progress indicator)
- Skip binary files, .git directories, node_modules, vendor

### kpm import --templatize (follow-up to --scan)

After importing secrets, optionally convert source files to templates:

```bash
kpm import --templatize ~/.bashrc

Original:
  export ANTHROPIC_API_KEY=sk-ant-oat01-xxx...

Template:
  export ANTHROPIC_API_KEY=${kms:anthropic/api-key}

Write template to ~/.kpm/templates/bashrc.template? [Y/n] y
✓ Template saved. Add to your .bashrc:
  eval $(kpm env --from ~/.kpm/templates/bashrc.template --output shell)
```

---

## AgentKMS Changes

### Storage paths

```
kv/secrets/{service}/{name}          → current secret value
kv/secrets/{service}/{name}/v{N}     → versioned history
kv/metadata/{service}/{name}         → metadata record (JSON)
```

### New endpoint: POST /secrets/{path}

Write a secret value. Creates or updates.

**Request:**
```json
{
  "value": "the-actual-secret"
}
```

Or for multi-field:
```json
{
  "access_key_id": "AKIA...",
  "secret_access_key": "wJalr..."
}
```

**Response:**
```json
{
  "path": "cloudflare/dns-token",
  "version": 3,
  "status": "updated"
}
```

**Security:**
- mTLS required
- Policy check: caller must have `write` operation for this path
- Audit event: operation=secret_write, path, caller, version — never the value
- Versioning: previous value moved to `kv/secrets/{path}/v{N-1}`

### New endpoint: POST /metadata/{path}

Write metadata for a secret.

**Request:**
```json
{
  "description": "catalyst9.ai DNS edit token",
  "tags": ["dns", "ci"],
  "type": "api-token",
  "expires": "2027-01-01T00:00:00Z"
}
```

**Response:**
```json
{
  "path": "cloudflare/dns-token",
  "version": 3,
  "status": "updated"
}
```

### New endpoint: GET /metadata (list)

List all secret metadata the caller has access to. Never returns values.

**Response:**
```json
{
  "secrets": [
    {
      "path": "cloudflare/dns-token",
      "type": "api-token",
      "tags": ["dns", "ci"],
      "description": "catalyst9.ai DNS",
      "created": "2026-04-14T10:30:00Z",
      "updated": "2026-04-14T15:00:00Z",
      "version": 3,
      "expired": false
    }
  ]
}
```

### New endpoint: GET /metadata/{path}

Get metadata for a specific secret.

### New endpoint: DELETE /secrets/{path}

Soft-delete: marks metadata as deleted, retains versioned values.
Hard-delete (`?purge=true`): removes everything. Requires elevated policy.

### New endpoint: GET /secrets/{path}/history

List version metadata (timestamps, callers). Never returns values.

---

## ABAC Policy Model

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
| `secret_tags` | Tags on the secret (from metadata) | Next iteration |
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

### First implementation

Basic allow/deny with: caller, team, role, machine, secret_path, operation. The attributes already present in the mTLS cert identity. Full ABAC (time, network, tags) is explicitly v2 — documentation will state this clearly.

### Future: Split knowledge / dual control (PCI-DSS)

Secrets flagged with `split: true` require N of M authorized callers to authenticate within a time window before AgentKMS releases the value. Each caller provides their mTLS cert, AgentKMS collects the quorum, then vends. KPM handles "waiting for additional authorization" response. Designed but not scoped for implementation.

---

## Integration with existing KPM features

### kpm add → kpm env/run flow

1. `kpm add anthropic/api-key` — stores value at `kv/secrets/anthropic/api-key`, metadata at `kv/metadata/anthropic/api-key`
2. Template references it: `ANTHROPIC_API_KEY=${kms:anthropic/api-key}`
3. `kpm env --from template` — resolves from AgentKMS, encrypted by default
4. `kpm run -- myapp` — decrypts at moment of use

### Template reference shorthand

`${kms:service/name}` resolves the primary value (single-field: the value; multi-field: all fields).
`${kms:service/name#field}` resolves a specific field from a multi-field secret.

Resolver detects path type:
- Starts with `llm/` → hits `GET /credentials/llm/{provider}` (existing endpoint)
- Starts with `kv/` → hits `GET /credentials/generic/{path}` (existing endpoint)
- Otherwise → hits `GET /secrets/{service}/{name}` (new endpoint, returns value only)

### kpm list → kpm tree relationship

- `kpm list` — shows secrets in the registry (what's stored in AgentKMS)
- `kpm tree` — shows templates and what secrets they reference (what's configured locally)

Both are views into the same system from different angles.

---

## Implementation order

### Phase 1: Server foundation
1. AgentKMS: Separated storage paths (secrets vs metadata)
2. AgentKMS: `POST /secrets/{path}` write endpoint with versioning
3. AgentKMS: `POST /metadata/{path}` write endpoint
4. AgentKMS: `GET /metadata` list endpoint
5. AgentKMS: `GET /metadata/{path}` describe endpoint
6. AgentKMS: `DELETE /secrets/{path}` soft-delete endpoint
7. AgentKMS: `GET /secrets/{path}/history` version history endpoint

### Phase 2: Registry CLI
8. KPM: `kpm add` with interactive (masked), pipe, and file input
9. KPM: `kpm list` with service, tag, and type filtering
10. KPM: `kpm describe` metadata display
11. KPM: `kpm history` version timeline
12. KPM: `kpm remove` with confirmation + soft-delete
13. KPM: Auto-detect secret type from value format
14. KPM: Update template resolver for `${kms:service/name}` shorthand

### Phase 3: Import scanner
15. KPM: Secret detection engine (pattern matching)
16. KPM: `kpm import --scan` interactive file scanner
17. KPM: `kpm import --dry-run` preview mode
18. KPM: `kpm import --templatize` source file conversion

### Phase 4: Polish
19. Update `kpm quickstart` to use `kpm add` for seeding
20. Tests for all of the above
21. Update README, demo scripts, demo containers
22. Blog post drafts

---

## Blog post series outline

### Part 1: "I had 47 places I stored secrets. Then I built this."
- Personal story — the scattered secrets reality
- Install KPM + quickstart
- `kpm add`, `kpm list` — get organized
- `kpm import --scan` — find what you've been leaking
- `kpm env` + `kpm run` — use them securely
- CTA: try it, give feedback

### Part 2: "Your .env files are a liability."
- Templates replace .env files
- Ciphertext by default, JIT decrypt
- `kpm show` — safe inspection
- mock-codex demo (ciphertext → decrypted for the tool)
- Two-container demo (push configs, pull on new machine)

### Part 3: "One config across all your machines."
- Config profiles (stow-like, but with secrets)
- `kpm import --templatize` — convert existing configs
- Push/pull across machines
- The CISO pitch: revoke access, configs evaporate

### Part 4: "Securing AI agent workflows."
- `kpm run --secure` for agentic workloads
- Process-scoped secrets (PID-tree, delegated sessions)
- Per-agent audit trails
- ABAC policy for regulated industries
- The enterprise story
