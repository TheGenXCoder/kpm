# KPM Secrets Registry — Design Spec (v3 Final)

**Date:** 2026-04-14
**Revised:** 2026-04-14 (v3 — final, scope locked, Grok + Claude review)
**Status:** Approved for implementation

---

## Release Scope

### v0.1.0 — Registry + Versioning (this build)
- `kpm add`, `kpm list`, `kpm remove`, `kpm describe`, `kpm history`
- AgentKMS write/list/delete/history endpoints
- Separated data model (secrets vs metadata — two KV paths)
- Secret versioning with configurable retention
- Soft-delete with audit trail
- Auto-detect secret type from value format
- Template resolver shorthand `${kms:service/name}`
- Updated quickstart using `kpm add` for seeding

### v0.2.0 — Import Scanner (next release)
- `kpm import --scan` with interactive selection
- `kpm import --dry-run` preview mode
- `kpm import --templatize` with backup creation
- Secret detection engine (pattern matching)

### Future (designed, not scheduled)
- ABAC attributes beyond mTLS cert (time, network, tags) — explicitly v2
- Config profiles (stow-like layering)
- Split knowledge / dual control (PCI-DSS)
- Ephemeral configs (FUSE / virtual filesystem)

---

## Problem

Developers store secrets in dozens of places — .env files, Obsidian notes, Apple Notes, Slack messages, SSH config, random credential files. No system, no audit trail, no revocation. KPM currently handles secret *usage* (templates, env injection, encryption) but has no front door for getting secrets *into* the system.

## Solution

A secrets registry that organizes secrets by service, makes them discoverable via `kpm list`, and ensures every write is audited and policy-checked through AgentKMS.

## Design Principles

1. **Secrets are never human-readable** in commands, arguments, logs, or output
2. **Every write goes through AgentKMS** — audited, policy-checked, mTLS-authenticated
3. **`service/name` is the only required structure** — tags, description, expiry are optional
4. **Metadata is fully separated from secret values** — two distinct KV paths, list/describe never touches the secrets store
5. **Secrets are versioned** — every write creates a new version, previous versions retained for audit
6. **ABAC policy model** — attributes on identity and policy, not on secrets. v0.1.0 implements cert-based attributes only (caller, team, role, machine, path, operation). Time, network, and tag-based attributes are explicitly deferred to v2.
7. **KPM is the client, AgentKMS is the engine** — KPM is the adoption funnel, AgentKMS is the product

---

## Data Model

### Separated Storage

**Two parallel KV paths in AgentKMS. These are never co-located.**

```
kv/secrets/{service}/{name}          → current secret value(s) ONLY
kv/secrets/{service}/{name}/v{N}     → versioned history (value only)
kv/metadata/{service}/{name}         → all non-secret data (JSON)
```

**Invariant:** The list and metadata endpoints query `kv/metadata/` exclusively. They never read from, reference, or return data from `kv/secrets/`. This is enforced at the API handler level, not by convention.

**Why this separation is non-negotiable:**
- List endpoint cannot accidentally leak values — it physically cannot access them
- Multi-field secrets use natural field names (no underscore prefix hacks)
- Versioning is clean — metadata tracks the version count and history, secrets store holds the actual values
- Policy evaluation and audit logging never need to load secret values
- Future: different access controls per store (list metadata without read access to values)

### Secret Path

`service/name` — the user-facing identifier. Maps to both KV paths.

Examples:
- `cloudflare/dns-token`
- `github/personal-pat`
- `anthropic/api-key`
- `db/postgres-prod`
- `ssh/deploy-key`

### Metadata Record

Stored at `kv/metadata/{service}/{name}`. Contains everything EXCEPT the secret value.

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
  "deleted": false,
  "versions": [
    {"version": 1, "created": "2026-04-14T10:30:00Z", "caller": "bert"},
    {"version": 2, "created": "2026-04-14T12:00:00Z", "caller": "bert"},
    {"version": 3, "created": "2026-04-14T15:00:00Z", "caller": "bert"}
  ]
}
```

### Secret Value Record

Stored at `kv/secrets/{service}/{name}`. Contains ONLY the secret value(s). No metadata.

Single-field secret:
```json
{
  "value": "the-actual-secret"
}
```

Multi-field secret (e.g., AWS):
```json
{
  "access_key_id": "AKIA...",
  "secret_access_key": "wJalr..."
}
```

### Secret Versioning

Every `kpm add` to an existing path creates a new version:

1. Current value at `kv/secrets/{service}/{name}` is copied to `kv/secrets/{service}/{name}/v{N}`
2. New value written to `kv/secrets/{service}/{name}`
3. Metadata `versions` array appended, `version` counter incremented, `updated` timestamp set
4. Configurable retention: keep last N versions (default: 10). Oldest pruned on write.
5. `kpm get service/name --version 2` reads from `kv/secrets/{service}/{name}/v2` (audited)
6. `kpm history service/name` reads from `kv/metadata/{service}/{name}` — versions array only, never values

**`kpm history` never returns secret values.** There is no `--show-values` flag. If you need a historical value, use `kpm get service/name --version N` which goes through the full auth + policy + audit pipeline.

### Secret Types

Optional classification for display and auto-detection:

| Type | Description | Auto-detected from |
|------|-------------|-------------------|
| `api-token` | API key / bearer token | Prefix: `sk-`, `ghp_`, `AKIA`, `sg-`, `xoxb-`, `Bearer ` |
| `password` | Password / passphrase | Key name: password, passwd, secret |
| `certificate` | TLS/SSL cert or key | Content: `-----BEGIN CERTIFICATE-----` |
| `ssh-key` | SSH private/public key | Content: `-----BEGIN OPENSSH PRIVATE KEY-----` |
| `connection-string` | Database connection URL | Content: `postgres://`, `mongodb://` etc. |
| `jwt` | JSON Web Token | Content: `eyJ` + 2 periods + length > 40 |
| `generic` | Unclassified | Default when no pattern matches |

---

## Commands (v0.1.0)

### kpm add

Stores a secret in AgentKMS. Secret value is never visible in command arguments.

```bash
# Interactive (default) — value prompted with masked input
kpm add cloudflare/dns-token
  Value: ****
  Description (optional): DNS edit token for catalyst9.ai
  Tags (optional): dns,ci

# From clipboard/pipe — value never appears in command line
pbpaste | kpm add cloudflare/dns-token

# From file (SSH keys, certs) — reads file content as the value
kpm add ssh/deploy-key --from ~/.ssh/deploy_key

# With metadata flags
kpm add cloudflare/dns-token --tags dns,ci --description "catalyst9.ai DNS" --type api-token --expires 2027-01-01
```

**Behavior:**
- Interactive: masked input using `golang.org/x/term` (no echo, like ssh-keygen)
- Pipe: reads stdin to EOF, never echoes
- File: reads file content, never echoes
- Two API calls: `POST /secrets/{path}` (value), `POST /metadata/{path}` (metadata)
- Confirms: `Stored cloudflare/dns-token v1 (tagged: dns, ci)`
- Existing secret: `cloudflare/dns-token exists (v2). Update to v3? [y/N]`
- Auto-detects type if `--type` not specified
- Value is `[]byte` throughout, zeroed after API call completes

### kpm list

Shows secrets by service. Queries metadata store only. **Never touches `kv/secrets/`.**

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

5 secrets across 3 services

# Filter by service
kpm list cloudflare

# Filter by tag
kpm list --tag ci

# Filter by type
kpm list --type ssh-key

# Include soft-deleted
kpm list --include-deleted
```

### kpm describe

Show metadata about a secret. **Never touches `kv/secrets/`.**

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
```

### kpm history

Show version timeline. **Metadata only — never values.**

```bash
kpm history cloudflare/dns-token

cloudflare/dns-token — 3 versions

  v3  2026-04-14T15:00:00Z  bert    (current)
  v2  2026-04-14T12:00:00Z  bert
  v1  2026-04-14T10:30:00Z  bert
```

### kpm remove

Soft-delete. Value retained for audit/compliance.

```bash
kpm remove cloudflare/dns-token
  Remove cloudflare/dns-token (v3)? Secret will be marked deleted. [y/N] y
  Removed cloudflare/dns-token

# Hard delete (requires elevated policy)
kpm remove --purge cloudflare/dns-token
  PERMANENTLY delete cloudflare/dns-token and all 3 versions? This cannot be undone. [y/N] y
  Purged cloudflare/dns-token
```

**Behavior:**
- Soft-delete: sets `deleted: true`, `deleted_at`, `deleted_by` in metadata. Values retained.
- `kpm list` hides deleted secrets. `kpm list --include-deleted` shows them.
- Hard delete (`--purge`): removes metadata AND all versioned values. Requires `purge` operation in policy. Audit logged.

---

## AgentKMS Changes (v0.1.0)

### Storage paths

```
kv/secrets/{service}/{name}          → current secret value (ONLY values, no metadata)
kv/secrets/{service}/{name}/v{N}     → versioned value history (ONLY values)
kv/metadata/{service}/{name}         → metadata record as JSON (NEVER contains values)
```

### New endpoints

| Method | Path | Purpose | Reads from |
|--------|------|---------|-----------|
| `POST` | `/secrets/{path}` | Write secret value (creates version) | writes to `kv/secrets/` |
| `GET` | `/secrets/{path}` | Read secret value (existing, enhanced) | `kv/secrets/` |
| `GET` | `/secrets/{path}?version=N` | Read historical version | `kv/secrets/{path}/v{N}` |
| `DELETE` | `/secrets/{path}` | Soft-delete (or `?purge=true`) | both stores |
| `POST` | `/metadata/{path}` | Write metadata | writes to `kv/metadata/` |
| `GET` | `/metadata/{path}` | Read metadata for one secret | `kv/metadata/` |
| `GET` | `/metadata` | List all metadata (never values) | `kv/metadata/` |
| `GET` | `/secrets/{path}/history` | Version timeline (metadata only) | `kv/metadata/` |

**Security invariants:**
- All endpoints require mTLS + valid session token
- All endpoints are policy-checked (caller + operation + path)
- All endpoints produce audit events (operation, path, caller, version — never values)
- List and metadata endpoints are physically separated from the secrets store — they cannot return values even if a bug exists in the handler, because they don't have access to the secrets KV path
- Rate limited (configurable, default disabled in dev mode)

### POST /secrets/{path} — Write

**Request:**
```json
{"value": "the-actual-secret"}
```
Or multi-field:
```json
{"access_key_id": "AKIA...", "secret_access_key": "wJalr..."}
```

**Response:**
```json
{"path": "cloudflare/dns-token", "version": 3, "status": "updated"}
```

**Versioning behavior:**
1. Read current value at `kv/secrets/{path}`
2. If exists, copy to `kv/secrets/{path}/v{current_version}`
3. Write new value to `kv/secrets/{path}`
4. Prune versions beyond retention limit

### POST /metadata/{path} — Write metadata

**Request:**
```json
{
  "description": "catalyst9.ai DNS edit token",
  "tags": ["dns", "ci"],
  "type": "api-token",
  "expires": "2027-01-01T00:00:00Z"
}
```

Server auto-populates: `created`, `updated`, `version`, `versions` array, `caller`.

### GET /metadata — List

Returns all metadata records the caller has `list` access to. **Never returns values.**

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
      "expired": false,
      "deleted": false
    }
  ]
}
```

---

## ABAC Policy Model

### v0.1.0 attributes (from mTLS cert)

| Attribute | Source |
|-----------|--------|
| `caller` | mTLS cert CN (e.g. "bert", "ci-deployer") |
| `team` | mTLS cert O (e.g. "dev", "ops") |
| `role` | mTLS cert OU (e.g. "developer", "service") |
| `machine` | mTLS cert CN or SAN |
| `secret_path` | The path being accessed |
| `operation` | read, write, list, delete, purge |

### v2+ attributes (explicitly not in v0.1.0)

| Attribute | Source | Status |
|-----------|--------|--------|
| `time` | Server wall clock | Designed, not implemented |
| `network` | Source IP/CIDR | Designed, not implemented |
| `secret_tags` | Tags from metadata store | Designed, not implemented |
| `session_age` | Time since token issued | Designed, not implemented |

Documentation and README will clearly state: "v0.1.0 enforces access based on certificate identity and path. Time-based, network-based, and tag-based policy attributes are coming in v2."

### Policy rule structure

```yaml
rules:
  - id: bert-full-access
    effect: allow
    match:
      caller: bert
    resources: ["*"]
    operations: [read, write, list, delete, purge]

  - id: dev-team-readwrite
    effect: allow
    match:
      team: dev
    resources: ["*"]
    operations: [read, write, list]

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

### Future: Split knowledge / dual control (PCI-DSS)

Secrets flagged with `split: true` require N of M authorized callers to authenticate within a time window before AgentKMS releases the value. Designed but not scoped for implementation. Data model does not preclude it.

---

## Integration with existing KPM features

### kpm add → kpm env/run flow

```
kpm add anthropic/api-key          # stores in AgentKMS (two writes: secrets + metadata)
     ↓
Template: ${kms:anthropic/api-key} # references the stored secret
     ↓
kpm env --from template            # resolves from AgentKMS, encrypted by default
     ↓
kpm run -- myapp                   # decrypts at moment of use via UDS
```

### Template reference shorthand

- `${kms:service/name}` → resolves primary `value` field from `GET /secrets/{service}/{name}`
- `${kms:service/name#field}` → resolves specific field from multi-field secret
- `${kms:llm/provider}` → existing LLM endpoint (unchanged)
- `${kms:kv/path#key}` → existing generic endpoint (unchanged)

Resolver detects path type by prefix:
- `llm/` → `GET /credentials/llm/{provider}`
- `kv/` → `GET /credentials/generic/{path}`
- Everything else → `GET /secrets/{service}/{name}` (new registry endpoint)

### kpm list vs kpm tree

- `kpm list` — what's stored in AgentKMS (the registry)
- `kpm tree` — what templates exist locally and what secrets they reference

---

## v0.2.0 — Import Scanner (designed, deferred)

### kpm import --scan

Interactive scanner. Finds secrets in files, presents selection, stores confirmed secrets.

**Safety rules (non-negotiable):**
- Never auto-store anything — every secret requires explicit user confirmation
- `--dry-run` shows what would be found without any writes or transmissions
- Never transmit potential secrets to AgentKMS until user confirms
- Never modify source files — templatization is a separate, explicit command
- Create backups before any templatization (`{file}.kpm-backup`)
- Skip: binary files, `.git/`, `node_modules/`, `vendor/`, files > 1MB
- Progress indicator for large directory scans
- Detection confidence level shown (high/medium/low) so user can make informed choices

**Detection patterns (priority order):**
1. API key prefixes: `sk-`, `pk_`, `AKIA`, `ghp_`, `gho_`, `sg-`, `xoxb-`, `xoxp-`, `Bearer `, `token_`
2. Connection strings: `postgres://`, `mongodb://`, `mysql://`, `redis://`, `amqp://` with embedded credentials
3. Private key headers: `-----BEGIN OPENSSH PRIVATE KEY-----`, `-----BEGIN RSA PRIVATE KEY-----`, `-----BEGIN EC PRIVATE KEY-----`, `-----BEGIN PRIVATE KEY-----`
4. JWTs: `eyJ` prefix with 2+ period separators, length > 40
5. Env var exports where key name contains: password, secret, token, api_key, access_key, private_key
6. High-entropy strings: base64 blobs > 20 chars, hex strings > 32 chars in config contexts
7. AWS key pairs: `AKIA[0-9A-Z]{16}` with nearby 40-char base64 string

### kpm import --templatize

Converts source files to templates. **Always creates a backup first.**

```bash
kpm import --templatize ~/.bashrc

  Backup: ~/.bashrc.kpm-backup
  
  Original:  export ANTHROPIC_API_KEY=sk-ant-oat01-xxx...
  Template:  export ANTHROPIC_API_KEY=${kms:anthropic/api-key}

  Write template to ~/.kpm/templates/bashrc.template? [Y/n] y
  ✓ Template saved
  ✓ Original backed up to ~/.bashrc.kpm-backup
```

---

## Implementation Plan (v0.1.0 only)

### Phase 1: AgentKMS server endpoints (agentkms repo, feat/registry branch)

1. Storage layer: implement separated `kv/secrets/` and `kv/metadata/` paths in the backend
2. `POST /secrets/{path}` — write with versioning
3. `POST /metadata/{path}` — write metadata
4. `GET /metadata` — list all metadata (never values)
5. `GET /metadata/{path}` — describe one secret
6. `DELETE /secrets/{path}` — soft-delete + `?purge=true`
7. `GET /secrets/{path}/history` — version timeline from metadata
8. Policy: add `write`, `delete`, `purge` operations to policy engine
9. Audit: new event types for write, delete, purge operations
10. Tests for all endpoints

### Phase 2: KPM registry commands (kpm repo)

File structure:
```
internal/kpm/
  registry.go          — client methods: WriteSecret, WriteMetadata, ListMetadata, etc.
  registry_test.go
  add.go               — kpm add logic (interactive, pipe, file)
  add_test.go
  list.go              — kpm list logic (formatting, filtering)
  list_test.go
  describe.go          — kpm describe logic
  history.go           — kpm history logic
  remove.go            — kpm remove logic (soft-delete, purge)
  remove_test.go
  detect.go            — secret type auto-detection from value
  detect_test.go
```

11. `registry.go` — new client methods for the registry endpoints
12. `add.go` — interactive input (masked), pipe detection, file reading, type auto-detection
13. `list.go` — formatted output grouped by service, filtering by tag/type/service
14. `describe.go` — metadata display
15. `history.go` — version timeline display
16. `remove.go` — confirmation prompt, soft-delete, purge
17. `detect.go` — pattern-based secret type detection
18. Update `cmd/kpm/main.go` with new subcommands
19. Update template resolver for `${kms:service/name}` shorthand
20. Tests for all commands

### Phase 3: Integration + polish

21. Update `kpm quickstart` to seed secrets using `kpm add`
22. Update demo containers and demo.md
23. Update README
24. Full test pass

### Security checkpoints (gate each phase)

- [ ] Phase 1: Verify list/metadata endpoints cannot return values (unit test + integration test)
- [ ] Phase 1: Verify all writes produce audit events without values
- [ ] Phase 1: Verify soft-delete retains values, purge requires elevated policy
- [ ] Phase 2: Verify `kpm add` never echoes/logs values
- [ ] Phase 2: Verify `kpm list` output contains no values (fuzz test with known values)
- [ ] Phase 2: Verify `kpm history` output contains no values
- [ ] Phase 2: Verify `[]byte` zeroing on all secret paths in kpm

---

## Blog post series outline

### Part 1: "I had 47 places I stored secrets. Then I built this."
- Personal story — the scattered secrets reality
- Install KPM + quickstart
- `kpm add`, `kpm list`, `kpm describe` — get organized
- `kpm env` + `kpm run` — use them securely
- Versioning + history — the audit trail
- CTA: try it, give feedback, star the repo
- Teaser: "Part 2: import scanner that finds what you've been leaking"

### Part 2: "Your .env files are a liability."
- Templates replace .env files
- Ciphertext by default, JIT decrypt
- `kpm show` — safe inspection
- mock-codex demo (ciphertext → decrypted for the tool)
- Two-container demo (push configs, pull on new machine)

### Part 3: "I scanned my machine. Here's what I found."
- `kpm import --scan` (ships in v0.2.0)
- Interactive migration walkthrough
- `kpm import --templatize` — convert files with backup
- Before/after: dotfiles repo with secrets vs templates

### Part 4: "Securing AI agent workflows."
- `kpm run --secure` for agentic workloads
- Process-scoped secrets (PID-tree, delegated sessions)
- Per-agent audit trails
- ABAC policy for regulated industries
- The CISO pitch: revoke and it evaporates
