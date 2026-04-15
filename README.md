# kpm

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
# Install (requires go 1.21+ and git; release binaries coming soon)
curl -sL kpm.catalyst9.ai/install | bash

# Quickstart: generates PKI, starts local AgentKMS, seeds demo secrets,
# writes config + starter templates. Running in under 30 seconds.
kpm quickstart
```

### Add your real secrets

```bash
# Interactive — value is masked (like ssh-keygen)
kpm add anthropic/api-key --tags dev,ci

# From clipboard
pbpaste | kpm add github/deploy-pat --tags ci

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
  kpm add / kpm env / kpm run
          |
          | mTLS (mutual TLS)
          v
    AgentKMS Server
          |
          v
    Secret Backends (dev encrypted file, OpenBao, enterprise vaults)
          |
          v
    AES-256-GCM session encryption
          |
          v
    ENC[kpm:...] ciphertext in environment
          |
          | Unix domain socket (local only, 0600 permissions)
          v
    JIT decrypt at moment of use
```

KPM is the local client. [AgentKMS](https://github.com/TheGenXCoder/agentkms) is the server. In dev mode, `kpm quickstart` runs both. In production, AgentKMS runs on your infrastructure with OpenBao or enterprise vault backends.

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

- **v0.2.0** — Import scanner: `kpm import --scan ~/.config` finds secrets in your files, offers to secure them
- **ABAC policy** — Time-based, network-based, and tag-based access rules
- **Config profiles** — Stow-like config management with secrets, layered per machine/environment
- **Release binaries** — No Go requirement for installation
- **Split knowledge** — PCI-DSS dual-control: N-of-M authorization for sensitive secrets

---

## License

Apache 2.0. See [LICENSE](LICENSE).

Built by [@TheGenXCoder](https://github.com/TheGenXCoder). AgentKMS server at [TheGenXCoder/agentkms](https://github.com/TheGenXCoder/agentkms).
