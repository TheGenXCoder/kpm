# kpm

[![CI](https://github.com/TheGenXCoder/kpm/actions/workflows/ci.yml/badge.svg)](https://github.com/TheGenXCoder/kpm/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

**Stop scattering secrets across your machine. One CLI to store, manage, and inject them — encrypted by default.**

KPM is a secrets lifecycle tool. Add secrets from the command line. Organize them by service. Inject them into your environment as ciphertext that only decrypts at the moment your app needs it. Back it with [AgentKMS](https://github.com/TheGenXCoder/agentkms) in production, or run the built-in dev server locally.

```bash
# Install
curl -sL kpm.catalyst9.ai/install | bash

# Set up a local dev environment (no server needed)
kpm quickstart

# Add a secret
kpm add cloudflare/dns-token --tags dns,ci --type api-token

# See what you have
kpm list
```

```
cloudflare/
  dns-token              api-token      [dns, ci]        v1

anthropic/
  api-key                api-token      [dev, ci]        v1

ssh/
  deploy-key             ssh-key                         v1

3 secrets across 3 services
```

---

## Why

API keys in `.env` files. Tokens in Obsidian notes. SSH keys in `~/.ssh` with no audit trail. Passwords in Slack messages to yourself. You know it's wrong but the alternative — setting up Vault, configuring policies, running a sidecar — is worse than the risk.

KPM fixes this in two commands. Your secrets go into one place, encrypted, audited, and accessible from any machine.

---

## Quick Start

```bash
# Install (uses prebuilt binary; falls back to source build if Go is installed)
curl -sL kpm.catalyst9.ai/install | bash

# Quickstart: generates PKI, starts local AgentKMS, seeds demo secrets,
# writes config + starter templates.
kpm quickstart
```

The full sequence runs in under 30 seconds on a fresh machine.

> **Verifying the install script.** `kpm.catalyst9.ai/install` is a 302 redirect to `raw.githubusercontent.com/TheGenXCoder/kpm/main/scripts/install.sh`. Review it before piping to bash if you'd like: `curl -sL kpm.catalyst9.ai/install | less`. For air-gapped or audit-sensitive environments, download a pinned release binary directly from the [Releases page](https://github.com/TheGenXCoder/kpm/releases) and verify its SHA256 against the release notes.

### Add your real secrets

```bash
# Interactive — value is masked (like ssh-keygen)
kpm add anthropic/api-key --tags dev,ci

# From clipboard
pbpaste | kpm add github/deploy-pat --tags ci             # macOS
xclip -selection clipboard -o | kpm add github/deploy-pat # Linux (X11)
wl-paste | kpm add github/deploy-pat                      # Linux (Wayland)

# From file
kpm add ssh/deploy-key --from-file ~/.ssh/deploy_key --description "production deploy"
```

KPM auto-detects the secret type from the value: `sk-` prefix becomes `api-token`, `-----BEGIN OPENSSH` becomes `ssh-key`, `postgres://` becomes `connection-string`.

### Use them

```bash
# Load into your shell (ciphertext — safe)
eval $(kpm env --from ~/.kpm/templates/shell-env.template --output shell)

# Your env has ciphertext, not plaintext
echo $ANTHROPIC_API_KEY
# ENC[kpm:s1a2b3:EncryptedBlobHere...]

# Run any tool — KPM decrypts on the fly for that process only
kpm run -- codex "fix the auth bug"
kpm run -- python train.py
kpm run -- docker-compose up
```

When the process exits, the plaintext is gone. Your shell never saw it.

---

## Secrets Registry

KPM organizes secrets by `service/name`. Every write is audited and policy-checked through AgentKMS.

### Commands

```bash
kpm add <service/name>           # Store a secret (interactive, pipe, or --from-file)
  --tags <a,b,c>                 # Comma-separated tags (e.g. ci, dev, prod)
  --type <kind>                  # Secret kind: api-token | ssh-key | connection-string
                                 # | jwt | password | generic. Auto-detected from
                                 # the value when omitted (e.g. sk- → api-token).
  --description "..."            # Free-form description (shown by kpm describe)
  --from-file <path>             # Read value from file instead of prompt/pipe
  --expires <ISO-8601>           # Set expiry timestamp (informational, not enforced)
kpm list                         # List all secrets (metadata only — never values)
kpm list --tag ci                # Filter by tag
kpm list --json                  # JSON output for scripting
kpm describe <service/name>      # Show metadata (type, tags, description, version)
kpm history <service/name>       # Version timeline (never values)
kpm get <service/name>           # Retrieve the actual value
kpm remove <service/name>        # Soft-delete (--purge for hard delete)
```

### What you see vs what's hidden

```bash
$ kpm describe cloudflare/dns-token

cloudflare/dns-token
  Type:        api-token
  Tags:        dns, ci
  Description: catalyst9.ai DNS edit token
  Created:     2026-04-15T10:30:00Z
  Version:     3
```

No value. Ever. Use `kpm get` to retrieve it — that goes through the full auth + policy + audit pipeline.

### Versioning

Every `kpm add` to an existing path creates a new version. Previous versions are retained (last 10 by default). Version history is metadata only — never exposes values.

```bash
$ kpm history cloudflare/dns-token

cloudflare/dns-token — 3 versions

  v3  2026-04-15T15:00:00Z  bert    (current)
  v2  2026-04-15T12:00:00Z  bert
  v1  2026-04-15T10:30:00Z  bert
```

---

## Encrypted Environment

KPM defaults to secure mode. Your environment variables contain ciphertext, not plaintext.

### How it works

1. `kpm env` fetches secrets from AgentKMS over mTLS
2. Encrypts each value with a session key (AES-256-GCM)
3. Starts a background decrypt listener on a Unix domain socket
4. Outputs ciphertext blobs + the socket path

```bash
eval $(kpm env --from ~/.kpm/templates/shell-env.template --output shell)
```

Now your shell has:
```
ANTHROPIC_API_KEY=ENC[kpm:s1a2b3:EncryptedBlobHere...]
KPM_SESSION=s1a2b3
KPM_DECRYPT_SOCK=/tmp/kpm-s1a2b3.sock
```

An attacker who dumps your process memory or runs `ps eww` sees ciphertext. Useless.

### JIT decrypt

When a tool needs the real value:

```bash
kpm run -- your-app
```

KPM decrypts all `ENC[kpm:...]` blobs for the child process, then destroys the plaintext when it exits.

### Inspect safely

```bash
$ kpm show

KPM Session: s1a2b3 (TTL: 58m32s remaining)

  ANTHROPIC_API_KEY         encrypted
  OPENAI_API_KEY            encrypted
  GITHUB_TOKEN              encrypted

3 secrets managed
```

No values shown. Ever.

---

## Three Security Levels

| | Plaintext (`--plaintext`) | Secure (default) | Strict (`--strict`) |
|---|---|---|---|
| Secrets in env | Plaintext | Ciphertext | Ciphertext |
| Key material on client | Secret values (brief) | Session key (TTL) | None |
| Network at use time | No | No | Yes (every decrypt) |
| Server-side revocation | No | No (until TTL) | Yes, immediate |
| Per-access audit | No | No | Yes |
| Best for | Trusted dev machine | CI/CD, general use | Production, compliance |

---

## Templates

Templates replace `.env` files. They live in git. Secrets are references, not values.

```bash
# .env.template — safe to commit
APP_NAME=my-service
DB_PASSWORD=${kms:kv/db/prod#password}
ANTHROPIC_API_KEY=${kms:anthropic/api-key}
PORT=${kms:kv/app/config#port:-8080}
```

### Template hierarchy

Three levels, project overrides user overrides enterprise:

```bash
$ kpm tree

Enterprise: /etc/catalyst9/.kpm/templates
  vpn-config.template       2 secrets [kv/vpn/corp#cert, kv/vpn/corp#key]

User: ~/.kpm/templates
  shell-env.template        3 secrets [anthropic/api-key, openai/api-key, github/token]

Project: ./.kpm/templates
  .env.template             4 secrets [kv/db/prod#password, kv/db/prod#host, ...]
```

### Reference syntax

```bash
${kms:service/name}              # Registry secret (primary value)
${kms:service/name#field}        # Multi-field secret (specific field)
${kms:llm/anthropic}             # LLM provider credential
${kms:kv/db/prod#password}       # KV store with key selector
${kms:kv/app/config#port:-8080}  # With fallback default
```

---

## Multi-Client / Multi-Project Workflow

One template tree. Many contexts. Zero `.env` shuffling.

KPM uses two mechanisms that compose to make context switching trivial:

### Profiles walk up the directory tree

Every directory can have a `.kpm/config.yaml`. KPM walks up from your cwd and merges every one it finds — child values override parent values.

```
~/clients/
├── acme/
│   └── .kpm/config.yaml           # customer: acme
│       └── us-east/
│           └── .kpm/config.yaml   # region: us-east
│               └── project-alpha/
│                   └── .kpm/config.yaml   # project: alpha, env: staging
└── globex/
    └── .kpm/config.yaml           # customer: globex
```

```bash
$ cd ~/clients/acme/us-east/project-alpha
$ kpm profile
customer: acme           ← ~/clients/acme/.kpm/config.yaml
region:   us-east        ← ~/clients/acme/us-east/.kpm/config.yaml
project:  alpha          ← ~/clients/acme/us-east/project-alpha/.kpm/config.yaml
env:      staging        ← ~/clients/acme/us-east/project-alpha/.kpm/config.yaml
```

Profiles are **plaintext metadata** — customer names, region codes, environment identifiers. Never secrets.

### One template, every context

Reference profile values in any template with `{{profile:key}}`:

```bash
# ~/.config/kpm/templates/claude.template
ANTHROPIC_API_KEY=${kms:customers/{{profile:customer}}/anthropic-key}
CLAUDE_MODEL={{profile:model:-claude-opus-4-7}}
```

In `~/clients/acme/...` this resolves to Acme's Anthropic key. In `~/clients/globex/...` it resolves to Globex's. Same command. Different secrets. No work.

### Compose templates with includes

```bash
# ~/.config/kpm/templates/db-migrations.template
${kms:include/customers/{{profile:customer}}/aws}
${kms:include/customers/{{profile:customer}}/{{profile:env}}/db}
MIGRATION_DIR=/app/migrations
```

Circular includes are detected. Include depth is bounded. Missing paths fail loudly.

### Security design

**Profiles walk up. Templates don't.**

Templates control secret access, so walking would be a privilege-escalation vector — a parent directory could silently grant secret access to every project below it. Profiles only contain identifiers that shape paths; they can't add permissions.

See [blog post Part 3](https://blog.catalyst9.ai/posts/part-3-multi-client/) for the full story.

---

## Shell Integration

Add to `~/.zshrc` or `~/.bashrc`:

```bash
eval $(kpm env --from ~/.kpm/templates/shell-env.template --output shell 2>/dev/null)
```

Your shell loads ciphertext on startup. Use `kpm run` to decrypt for any tool:

```bash
kpm run -- codex "fix the bug"
kpm run -- ssh deploy@prod
kpm run -- terraform apply
```

---

## v0.3 Capabilities

### Dynamic Secrets

AgentKMS mints scoped, short-lived credentials on demand. Your AI agent gets a 15-minute token for exactly what it needs — never your master key. Credentials expire automatically; no manual rotation. See [Part 5](https://blog.catalyst9.ai/posts/part-5-dynamic-secrets/).

### MCP Integration

AI tools (Claude, Codex, etc.) connect to AgentKMS via the [Model Context Protocol](https://modelcontextprotocol.io). The MCP server exposes credential operations as tools — agents can request secrets through a structured interface without touching your shell environment. Combine with `kpm run --secure` allow-lists (Part 4) to control exactly which secrets each tool can see.

### Forensics Chain-of-Custody

Every credential access produces a tamper-evident audit record: who, what, when, from where. When a key leaks, you know which agent used it, in which session, at which timestamp — in seconds. See [Part 6](https://blog.catalyst9.ai/posts/part-6-forensics/).

### Plugin Architecture

Extend KPM without forking. Plugins hook into the request pipeline as Go shared libraries — add custom secret backends, approval workflows, or policy engines. See [Part 7](https://blog.catalyst9.ai/posts/part-7-plugin-model/).

---

## All Commands

| Command | Description |
|---------|-------------|
| `kpm quickstart` | Set up local dev environment (PKI + server + secrets + templates) |
| `kpm add <service/name>` | Store a secret (interactive, pipe, or `--from-file`) |
| `kpm list [service]` | List secrets (metadata only). `--tag`, `--json`, `--include-deleted` |
| `kpm describe <service/name>` | Show secret metadata (never values) |
| `kpm history <service/name>` | Version timeline (never values) |
| `kpm get <service/name>` | Retrieve a secret value |
| `kpm remove <service/name>` | Soft-delete (`--purge` for hard delete) |
| `kpm env --from <template>` | Resolve template (secure by default, `--plaintext` to opt out) |
| `kpm run -- <cmd> [args]` | Run command with decrypted secrets |
| `kpm run --secure -- <cmd> [args]` | Run with per-tool allow-list (only listed env vars decrypted) |
| `kpm show [VAR]` | Inspect managed secrets in current env |
| `kpm tree` | Show template hierarchy |
| `kpm decrypt <blob>` | JIT decrypt a single blob (inside `kpm run` context) |
| `kpm init` | Write `~/.kpm/config.yaml` |

**Examples:**

```bash
kpm add cloudflare/dns-token                    # interactive (masked input)
echo "sk-xxx" | kpm add anthropic/api-key       # from pipe
kpm add ssh/key --from-file ~/.ssh/id_ed25519   # from file
kpm list --tag production                       # filter by tag
kpm list --json | jq '.[] | .service'           # scripting
eval $(kpm env --from template --output shell)  # load into shell
kpm run -- your-app                             # decrypt for one process
```

---

## Architecture

```
  kpm add / kpm env / kpm run          AI tools (Claude, Codex, etc.)
          |                                       |
          | mTLS (mutual TLS)          MCP protocol (Model Context Protocol)
          |                                       |
          +-------------------+-------------------+
                              |
                        AgentKMS Server
                         |         |
               Plugins --+         +-- Dynamic Secrets
               (extend without        (scoped, short-lived
                forking)               credentials minted per request)
                              |
                    Secret Backends
               (dev encrypted file, OpenBao, enterprise vaults)
                              |
                    AES-256-GCM session encryption
                              |
                    ENC[kpm:...] ciphertext in environment
                              |
                  Unix domain socket (local only, 0600 permissions)
                              |
                    JIT decrypt at moment of use
                              |
                    Forensics audit log (tamper-evident chain-of-custody)
```

KPM is the local client. [AgentKMS](https://github.com/TheGenXCoder/agentkms) is the server. In dev mode, `kpm quickstart` runs both. In production, AgentKMS runs on your infrastructure with OpenBao or enterprise vault backends. AI tools connect via the MCP server — they request credentials, AgentKMS mints scoped short-lived tokens, and every access is logged to the forensics chain.

---

## Security

- Secrets never human-readable in commands, arguments, logs, or output
- `[]byte` everywhere for secret values — never `string` until final write
- Aggressive manual zeroing after use (not reliant on Go GC)
- AES-256-GCM with fresh random session keys
- Unix domain socket for JIT decrypt (local only, permission-locked, dies with process)
- mTLS on every server request
- Every write audited with caller identity, operation, timestamp — never the value
- Policy-checked at the server: who can read/write/delete which paths
- Separated storage: metadata and values in different KV paths — list endpoints physically cannot return values

---

## Configuration

`~/.kpm/config.yaml`:

```yaml
server: https://agentkms.local:8443
cert: ~/.kpm/certs/client.crt
key: ~/.kpm/certs/client.key
ca: ~/.kpm/certs/ca.crt
default_template: .env.template
session_key_ttl: 3600
```

All CLI flags override config values. `~` is expanded automatically.

---

## Testing

```bash
# Automated (runs everything in a disposable Docker container)
curl -sL https://raw.githubusercontent.com/TheGenXCoder/kpm/main/tests/run-tests.sh | bash

# Manual (human-guided, 20 tests with checkboxes)
# See: tests/MANUAL_TEST_GUIDE.md
```

---

## Roadmap

Shipped in v0.3:
- Dynamic Secrets — AgentKMS mints scoped, short-lived credentials (see [Part 5](https://blog.catalyst9.ai/posts/part-5-dynamic-secrets/))
- MCP server — AI tools connect to AgentKMS via the Model Context Protocol
- Forensics chain-of-custody — full audit trail with tamper-evident log (see [Part 6](https://blog.catalyst9.ai/posts/part-6-forensics/))
- Plugin architecture — extend KPM without forking (see [Part 7](https://blog.catalyst9.ai/posts/part-7-plugin-model/))
- `kpm run --secure` allow-lists — per-tool env filtering (see [Part 4](https://blog.catalyst9.ai/posts/part-4-ai-agents/))

Coming up:
- **Import scanner** — `kpm import --scan ~/.config` finds secrets in your files, offers to secure them
- **ABAC policy** — Time-based, network-based, and tag-based access rules
- **Split knowledge** — PCI-DSS dual-control: N-of-M authorization for sensitive secrets
- **Windows support**

---

## Documentation

**Product narrative:**
- [**Part 1: I had 47 places I stored secrets**](https://blog.catalyst9.ai/posts/part-1-scattered-secrets/) — why KPM exists
- [**Part 2: Your .env files are a liability**](https://blog.catalyst9.ai/posts/part-2-env-files-liability/) — ciphertext-by-default and JIT decrypt
- [**Part 3: One template tree, twelve clients, zero friction**](https://blog.catalyst9.ai/posts/part-3-multi-client/) — profiles + includes
- [**Part 4: AI coding agents make the secrets problem worse**](https://blog.catalyst9.ai/posts/part-4-ai-agents/) — process-scoped decryption for agentic workflows
- [**Part 5: Your AI agent gets 15-minute credentials, not your master key**](https://blog.catalyst9.ai/posts/part-5-dynamic-secrets/) — dynamic secrets and scoped credential minting
- [**Part 6: When a credential leaks, you know everything in 30 seconds**](https://blog.catalyst9.ai/posts/part-6-forensics/) — forensics chain-of-custody
- [**Part 7: Go pro for plugins — how AgentKMS stays small and gets big**](https://blog.catalyst9.ai/posts/part-7-plugin-model/) — plugin architecture

**Policy:**
- [**SECURITY.md**](SECURITY.md) — threat model, defended vs not defended, disclosure policy
- [**CONTRIBUTING.md**](CONTRIBUTING.md) — how to contribute, security-sensitive areas
- [**CHANGELOG.md**](CHANGELOG.md) — release history

**Engineering design records** (in the AgentKMS repo — server-side implementation lives there):
- [**Forensics as the v0.3 product target**](https://github.com/TheGenXCoder/agentkms/blob/main/docs/design/2026-04-16-forensics-v0.3.md)
- [**Dynamic Secrets — AgentKMS as secret-issuing authority**](https://github.com/TheGenXCoder/agentkms/blob/main/docs/design/2026-04-16-dynamic-secrets.md)
- [**Deployment model & sovereignty principle**](https://github.com/TheGenXCoder/agentkms/blob/main/docs/design/2026-04-16-deployment-model.md)
- [**Design record index**](https://github.com/TheGenXCoder/agentkms/blob/main/docs/design/README.md)

---

## License

Apache 2.0. See [LICENSE](LICENSE).

Built by [@TheGenXCoder](https://github.com/TheGenXCoder). AgentKMS server at [TheGenXCoder/agentkms](https://github.com/TheGenXCoder/agentkms).
