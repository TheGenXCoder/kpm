# kpm

**Secure secrets CLI. Replaces .env files with encrypted, template-based config management.**

Backed by [AgentKMS](https://github.com/TheGenXCoder/agentkms) in production. Works standalone with a built-in dev server.

---

## The Problem

Your `.env` file is plaintext. It's on disk, in git history, in process memory, and showing up in CI logs. Every tool that reads it gets the raw value — whether or not that was intentional. One misconfigured log line and your database password is in Datadog.

## The Solution

Templates live in git. Secrets stay in AgentKMS. Your environment variables hold ciphertext — not plaintext — until the exact moment a process needs them.

```bash
# .env.template — safe to commit
APP_NAME=my-service
DB_PASSWORD=${kms:kv/db/prod#password}
ANTHROPIC_API_KEY=${kms:llm/anthropic}

# Resolve the template — secrets become encrypted blobs
$ kpm env --from .env.template
DB_PASSWORD=ENC[kpm:s1a2b3c4:base64...]
ANTHROPIC_API_KEY=ENC[kpm:s1a2b3c4:base64...]
KPM_SESSION=s1a2b3c4
KPM_DECRYPT_SOCK=/tmp/kpm-s1a2b3c4.sock
✓ Resolved 2 secrets from AgentKMS
✓ Encrypted values (AES-256-GCM, session: s1a2b3c4, TTL: 300s)

# Tools get plaintext only at the moment of use
$ kpm run -- node server.js
✓ Decrypted 2 secrets from session s1a2b3c4
```

Attach it to anything:

```bash
kpm run -- codex
kpm run -- python train.py
kpm run -- docker-compose up
```

---

## Quick Start

```bash
# Install (requires git and go 1.21+; release binaries coming soon)
curl -sL https://raw.githubusercontent.com/TheGenXCoder/kpm/main/scripts/install.sh | bash

# Set up a local dev environment — no server configuration needed
kpm quickstart

# See what's managed
kpm tree

# Load secrets into your shell
eval $(kpm env --from ~/.kpm/templates/shell-env.template --plaintext --output shell)

# Inspect what's in the current environment
kpm show

# Run anything with secrets injected
kpm run -- your-app
```

`kpm quickstart` handles everything: generates PKI, starts a local AgentKMS dev server, seeds demo secrets, and writes `~/.kpm/config.yaml` and starter templates. You can be running in under 30 seconds.

---

## How It Works

KPM has three security levels. Pick the one that fits your threat model.

### Plaintext mode (`--plaintext`)

Secrets are fetched from AgentKMS over mTLS and injected as plaintext values. Better than `.env` files — nothing on disk, nothing in git — but secret values do briefly exist in the process environment.

```bash
kpm env --from .env.template --plaintext
kpm run --plaintext -- your-app
```

Best for: trusted local dev machines where simplicity matters.

### Secure mode (default)

Secrets are fetched from AgentKMS, then AES-256-GCM encrypted with a short-lived session key. Ciphertext blobs go into the environment. A background listener on a Unix domain socket decrypts them just-in-time when a process actually needs them.

```bash
# Default behavior — no flag needed
kpm env --from .env.template
kpm run -- your-app
```

The session key lives only in the background listener process. The child process sees ciphertext. A memory dump or `ps eww` shows blobs, not secrets.

Best for: CI/CD pipelines, shared developer machines, general hardening.

### Strict mode (`--strict`)

No session key is ever held locally. Every decrypt request goes over mTLS to AgentKMS, where it is individually audited. If AgentKMS is unreachable or revokes access mid-session, decryption fails immediately.

```bash
kpm run --strict -- your-app
```

Best for: production deployments, compliance requirements, high-threat environments.

---

## Template Hierarchy

Templates are organized in three levels. KPM merges them — project overrides user overrides enterprise.

```
$ kpm tree

Enterprise: /etc/catalyst9/.kpm/templates
  (no templates found)

User: /Users/you/.kpm/templates
  shell-env.template        3 secrets [llm/anthropic, llm/openai, kv/github#token]

Project: /path/to/project/.kpm/templates
  .env.template             4 secrets [kv/db/prod#host, kv/db/prod#password, kv/app/config#jwt_secret, kv/db/prod#port]
```

Template reference syntax:

```bash
# KV secret — specific key
DB_PASSWORD=${kms:kv/db/prod#password}

# LLM API key
ANTHROPIC_API_KEY=${kms:llm/anthropic}

# With fallback default
PORT=${kms:kv/app/config#port:-8080}
```

---

## Commands

| Command | Description |
|---------|-------------|
| `kpm quickstart` | Set up local dev environment (PKI, dev server, demo secrets, templates) |
| `kpm env --from <template>` | Resolve template and print env vars (secure by default) |
| `kpm env --from <template> --plaintext` | Resolve template with plaintext output |
| `kpm env --from <template> --output shell` | Shell export format for `eval $()` |
| `kpm run -- <cmd> [args]` | Resolve template and run command with injected env |
| `kpm get <ref>` | Fetch a single secret by KMS reference |
| `kpm decrypt <blob>` | JIT decrypt a ciphertext blob (must be inside `kpm run`) |
| `kpm show [VAR]` | Show managed secrets in current environment |
| `kpm tree` | Show template hierarchy and what each template manages |
| `kpm init` | Write `~/.kpm/config.yaml` |
| `kpm version` | Print version |

**Global flags:**

```
--config <path>   Config file (default: ~/.kpm/config.yaml)
--server <url>    AgentKMS server URL (overrides config)
--cert <path>     mTLS client cert
--key <path>      mTLS client key
--ca <path>       CA cert for AgentKMS
--verbose         Debug output (never prints secret values)
```

---

## Architecture

```
.env.template (committed to git)
       |
       v
   kpm env / kpm run
       |
       | mTLS
       v
  AgentKMS Server ──> secret backends (dev, OpenBao, enterprise vaults)
       |
       v
  AES-256-GCM session key
       |
       v
  ENC[kpm:...] blobs in environment
       |
       | Unix domain socket (local only, permission-locked)
       v
  JIT decrypt at moment of use
```

KPM is a local client. It never stores secrets. AgentKMS is the source of truth — it handles mTLS authentication, policy, audit logs, and short-lived credential vending.

For production deployments, see the [AgentKMS repository](https://github.com/TheGenXCoder/agentkms).

---

## Security Model

- **`[]byte` everywhere** — secrets are never held as `string` until the absolute last write
- **Aggressive zeroing** — memory is explicitly cleared after use; Go GC is not relied on
- **AES-256-GCM session encryption** — each session uses a fresh random 256-bit key
- **Unix domain socket** — JIT decrypt runs over a local-only socket with `0600` permissions; no network exposure
- **Session key isolation** — the session key lives only in the background listener process; the child process sees only ciphertext
- **mTLS for all server communication** — mutual TLS authentication on every AgentKMS request
- **No secrets in logs** — `--verbose` prints paths, timings, and flow; never values or ciphertext blobs

---

## Configuration

`~/.kpm/config.yaml` (generated by `kpm init` or `kpm quickstart`):

```yaml
server: https://agentkms.local:8443
cert: ~/.kpm/certs/client.crt
key: ~/.kpm/certs/client.key
ca: ~/.kpm/certs/ca.crt
default_template: .env.template
session_key_ttl: 300
```

All flag values override config file values.

---

## Shell Integration

Add to `~/.zshrc` or `~/.bashrc` to load secrets into your shell on startup:

```bash
eval $(kpm env --from ~/.kpm/templates/shell-env.template --plaintext --output shell 2>/dev/null)
```

---

## License

Apache 2.0. See [LICENSE](LICENSE).
