# KPM + AgentKMS Unified Design Spec

**Date:** 2026-04-11
**Status:** Approved for implementation
**Scope:** Weekend build (2026-04-12 / 2026-04-13)
**Author:** Bert Smith (TheGenXCoder)

---

## Executive Summary

Rewrite `key-pair-manager` (KPM) as a Go binary (`cmd/kpm`) inside the AgentKMS repository. KPM becomes the local developer-facing CLI for secrets injection, backed by AgentKMS as the single source of truth. Introduces three injection modes: plaintext (default), `--secure` (session key + ciphertext), and `--secure-strict` (network round-trip per decrypt). Replaces `.env` files with a safe `.env.template` pattern using KMS references.

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| KPM language | Go rewrite (`cmd/kpm` in AgentKMS repo) | Reuse mTLS, crypto, zeroization. Bash can't handle ciphertext/JIT cleanly. Blast radius ~zero (just open-sourced). |
| JIT decrypt mechanism | C: both session key + network round-trip | `--secure` (session key, 5min TTL) for 95% of use. `--secure-strict` (live `/decrypt` call) for high-threat. Low implementation cost — AgentKMS has both endpoints. |
| Template resolution | KPM-side (client) | Zero AgentKMS changes for templates. `.env.template` with `${kms:...}` references. Server-side templates are a future premium feature. |

## Core Rule

**AgentKMS is the single source of truth.** Secrets and their policies live in its pluggable backend (dev, OpenBao, enterprise vaults). AgentKMS handles mTLS auth, policy, audit, short-lived vending, and cache policy hints. KPM is the local client, caching layer, and injection engine — never a secret store.

---

## 1. Architecture Overview

```
+-------------------------------------------------------+
|                    AgentKMS Server                      |
|  (source of truth -- unchanged this weekend)           |
|                                                         |
|  /credentials/llm/{provider}  -> LLM API keys         |
|  /credentials/generic/{path}  -> arbitrary secrets     |
|  /encrypt                     -> envelope encrypt      |
|  /decrypt                     -> envelope decrypt      |
|  mTLS auth . policy . audit . short-lived vending      |
+--------------------------+------------------------------+
                           | mTLS
+--------------------------v------------------------------+
|                  cmd/kpm (new Go binary)                |
|                                                         |
|  Subcommands:                                          |
|    kpm export   --from .env.template [--secure]        |
|    kpm run      --secure [--strict] <cmd>              |
|    kpm get      <kms-ref>                              |
|    kpm decrypt  <env-var>                              |
|    kpm store    <name> (local keychain, legacy compat) |
|    kpm list                                            |
|    kpm cache    list|clear                             |
|    kpm init                                            |
|                                                         |
|  Layers:                                               |
|    Template Parser  -> resolves ${kms:...} refs        |
|    AgentKMS Client  -> reuses pkg/client, mTLS         |
|    Injection Engine -> plaintext | ciphertext modes    |
|    Cache Layer      -> go-keyring (approved items)     |
|    JIT Decrypt      -> session key or /decrypt call    |
+---------------------------------------------------------+
```

**Key principle:** AgentKMS gets zero changes this weekend (except the optional ~15-line `cache_policy` field). All new code lives in `cmd/kpm/` and `internal/kpm/`. KPM reuses existing `pkg/client`, `pkg/crypto`, `pkg/tlsutil`.

---

## 2. Template Parser

### Template file format

```bash
# .env.template -- safe to commit to git
APP_NAME=my-service
LOG_LEVEL=info

# KMS references -- resolved at export/run time
DB_PASSWORD=${kms:kv/db/prod#password}
DB_HOST=${kms:kv/db/prod#host}
OPENAI_KEY=${kms:llm/openai}
ANTHROPIC_KEY=${kms:llm/anthropic}

# Optional default if KMS unreachable + no cache
FALLBACK_PORT=${kms:kv/app/config#port:-8080}
```

### Reference syntax

`${kms:<type>/<path>[#<key>][:-<default>]}`

| Pattern | Resolves to |
|---------|------------|
| `${kms:llm/openai}` | `GET /credentials/llm/openai` -> `.api_key` |
| `${kms:kv/db/prod#password}` | `GET /credentials/generic/db/prod` -> `.secrets["password"]` |
| `${kms:kv/db/prod#host:-localhost}` | Same, falls back to `localhost` if unavailable |

### Regex

```go
var kmsRefPattern = regexp.MustCompile(`\$\{kms:([a-z]+)/(.*?)(?:#([^:}]+))?(?::-(.*?))?\}`)
// Groups: [1]=type (llm|kv), [2]=path, [3]=key (optional), [4]=default (optional)
```

### Data structures

```go
type KMSReference struct {
    Type    string // "llm" or "kv"
    Path    string // e.g. "db/prod" or "openai"
    Key     string // e.g. "password" (empty for LLM)
    Default string // fallback value (empty if none)
}

type ResolvedEntry struct {
    Key        string        // env var name (e.g. "DB_PASSWORD")
    PlainValue []byte        // only in plaintext mode; zero after use
    Ciphertext []byte        // populated in --secure modes
    IsKMSRef   bool          // false = plain passthrough value
    Ref        KMSReference  // parsed reference (if IsKMSRef)
    Source     string        // "agentkms", "cache", or "default"
}
```

### Batch optimization

Multiple references to the same KV path (e.g. `kv/db/prod#password`, `kv/db/prod#host`) resolve with a single `GET /credentials/generic/db/prod` call. The generic endpoint returns `map[string][]byte`.

### Parser behavior

1. Read `.env.template` line by line
2. Plain `KEY=value` lines pass through (`IsKMSRef=false`)
3. Lines with `${kms:...}` parsed into `KMSReference`
4. Batch all references, dedupe by type+path, make minimal API calls
5. Return `[]ResolvedEntry` for the injection engine
6. Never log resolved secret values (even in `--verbose`)

---

## 3. Injection Engine + JIT Decrypt

### Mode 1: Plaintext (default -- no flags)

```bash
kpm export --from .env.template
kpm run -- myapp --port 8080
```

**Flow:**
1. Template parser resolves all `${kms:...}` via AgentKMS (mTLS)
2. Plaintext written to stdout (`export`) or injected into child env (`run`)
3. `PlainValue` zeroed immediately after write/injection
4. Warning header: `# WARNING: contains plaintext secrets -- do not commit`

**Trade-off:** Plaintext touches env/memory. Simple, compatible with every tool. Fine for trusted dev machines.

### Mode 2: `--secure` (session key -- default hardened)

```bash
kpm export --from .env.template --secure
kpm run --secure -- myapp --port 8080
```

**Flow:**
1. KPM authenticates to AgentKMS (mTLS), requests a session key (AES-256-GCM, configurable TTL, default 5 minutes)
2. AgentKMS generates session key, stores it keyed by session ID, returns `{session_id, encrypted_session_key}` (encrypted to KPM's client cert public key)
3. KPM decrypts session key locally using its mTLS private key
4. Template parser resolves secrets as plaintext internally
5. KPM encrypts each value with session key -> ciphertext blob
6. Plaintext zeroed immediately after encryption
7. Ciphertext injected into env: `DB_PASSWORD=ENC[kpm:sid:base64blob]`
8. For `kpm run`: spawns a Unix Domain Socket decrypt listener alongside child process; injects `KPM_DECRYPT_SOCK` into child env

**JIT Decrypt via UDS:**
- App (or thin wrapper) connects to `KPM_DECRYPT_SOCK` (Unix socket, local-only)
- Sends: `{"ciphertext": "ENC[...]"}`
- Listener validates session TTL, decrypts with session key (in-memory), returns plaintext, zeros immediately
- UDS is permission-locked to user; listener validates calling process UID via `golang.org/x/sys/unix` `GetsockoptUcred`

**Why UDS:**
- No disk I/O (no temp files)
- Not network-accessible (local-only, permission-locked)
- Language-agnostic (Python, Node, Go, Ruby can all connect)
- KPM controls lifecycle: socket removed when `kpm run` exits
- Session key lives only in the KPM process, never in the child

**Thin client helpers (weekend: shell only; Python/Go libs post-weekend):**

```bash
# Shell
DB_PASS=$(kpm decrypt "$DB_PASSWORD")
```

### Mode 3: `--secure-strict` (network round-trip -- paranoid)

```bash
kpm run --secure-strict -- myapp --port 8080
```

**Differences from `--secure`:**
- No session key fetched. Ciphertext encrypted directly by AgentKMS server-side key
- UDS listener makes a live mTLS `POST /decrypt` to AgentKMS on every decrypt request
- Plaintext exists only for UDS response write duration, then zeroed
- AgentKMS unreachable -> decrypt fails (by design, no fallback)
- AgentKMS can revoke/deny mid-session (policy change, breach detection)
- Every decrypt is individually audited server-side
- No key material of any kind on client machine

### Comparison table

| | Plaintext (default) | `--secure` | `--secure-strict` |
|---|---|---|---|
| Secrets in env | Plaintext | Ciphertext blobs | Ciphertext blobs |
| Key material on client | Secret values (brief) | Session key (5min TTL) | None |
| Network at use time | No (fetched upfront) | No (local decrypt) | Yes (every decrypt) |
| Offline capable | After initial fetch | Within TTL | No |
| Server-side revocation | No | No (until TTL) | Yes, immediate |
| Per-access audit | No | No | Yes |
| Speed | Fastest | Fast | Slower |
| Best for | Trusted dev machine | CI/CD, general hardening | Hotel WiFi, prod, compliance |

### Security requirements (all modes)

- **`[]byte` everywhere** for secrets. Never `string` until the absolute last moment of writing.
- **Manual zeroing loops** after use. Do not rely on Go GC.
- **UDS cleanup:** `defer os.Remove(socketPath)` + `os/signal` handler.
- **UDS credential check:** Validate calling process UID via `unix.GetsockoptUcred`.
- **No secret logging:** `--verbose` prints flow/timing/paths, never values or ciphertext.
- **Reuse `pkg/crypto`** for all envelope encryption (existing patterns handle zeroing).

---

## 4. Cache Layer

### Purpose

Approved offline access when AgentKMS is unreachable. Never the default path; always a fallback.

### Policy model

AgentKMS controls cacheability via a `cache_policy` field on the generic credential response (~15 lines of Go, the one small server-side addition):

```json
{
  "secrets": {"password": "..."},
  "cache_policy": {
    "allow_local_cache": true,
    "max_ttl_seconds": 3600,
    "require_encryption": true
  }
}
```

Default: `allow_local_cache: false`. KPM never caches unless the server explicitly permits it.

**Weekend fallback (if zero server changes preferred):** KPM-side heuristic -- cache only paths matching `kv/ssh/*` or `kv/config/*`, or items with `:cacheable` suffix in template.

### Storage backend

```go
type CacheBackend interface {
    Store(key string, ciphertext []byte, expiresAt time.Time) error
    Fetch(key string) ([]byte, error)
    Delete(key string) error
    List() ([]CacheEntry, error)
}
```

Implementation: `github.com/zalando/go-keyring` (macOS Keychain with biometric, Linux dbus/secret-service, `pass` fallback).

Secrets stored **double-encrypted**: first by AgentKMS envelope, then by a local key derived from the mTLS client cert. Even a keychain dump yields only ciphertext.

Cache entry key format: `kpm:<path>#<key>`

### Cache commands

```bash
kpm cache list                    # cached items + TTL remaining + fetch timestamp
kpm cache clear                   # wipe all
kpm cache clear kv/db/prod        # wipe specific path
```

### Interaction with injection modes

| Mode | Cache behavior |
|---|---|
| Plaintext | AgentKMS down -> check cache -> decrypt locally -> inject. Warn: "using cached value (fetched 47m ago)" |
| `--secure` | Cache provides plaintext for local session-key encryption. Same warning. |
| `--secure-strict` | Cache never used. Fail loud. |

---

## 5. Command Surface

CLI framework: Cobra (consistent with AgentKMS CLI).

### Global flags

```
--config <path>      Config file (default: ~/.kpm/config.yaml)
--server <url>       AgentKMS server URL (overrides config)
--cert <path>        mTLS client cert
--key <path>         mTLS client key
--ca <path>          CA cert for AgentKMS
--verbose            Debug output (never prints secret values)
```

### Config file (`~/.kpm/config.yaml`)

```yaml
server: https://agentkms.local:8443
cert: ~/.kpm/certs/client.crt
key: ~/.kpm/certs/client.key
ca: ~/.kpm/certs/ca.crt
default_template: .env.template
secure_mode: false
session_key_ttl: 300
```

### Commands

#### `kpm export` -- resolve template, output env vars

```bash
kpm export --from .env.template                      # plaintext, dotenv format
kpm export --from .env.template --secure             # ciphertext, dotenv format
kpm export --from .env.template --output json        # JSON format
kpm export --from .env.template --output shell       # export KEY=value format
```

#### `kpm run` -- resolve + inject + exec child process

```bash
kpm run -- myapp --port 8080                         # plaintext
kpm run --secure -- myapp --port 8080                # session key + UDS
kpm run --secure-strict -- myapp --port 8080         # live /decrypt + UDS
kpm run --from custom.env.template --secure -- myapp # custom template
```

In `--secure` modes: spawns UDS listener, injects `KPM_DECRYPT_SOCK`, listener dies when child exits.

#### `kpm get` -- fetch a single secret

```bash
kpm get kv/db/prod#password                          # plaintext to stdout
kpm get llm/openai                                   # LLM API key
kpm get kv/db/prod#password --secure                 # ENC[...] blob
```

#### `kpm decrypt` -- JIT shell helper

```bash
DB_PASS=$(kpm decrypt "$DB_PASSWORD")                # from argument
kpm decrypt --env DB_PASSWORD                        # from env var by name
```

Uses `KPM_DECRYPT_SOCK` if available (fast). Falls back to direct AgentKMS `/decrypt` via mTLS.

#### `kpm cache` -- manage local cache

```bash
kpm cache list
kpm cache clear
kpm cache clear kv/db/prod
```

#### `kpm init` -- first-time setup

```bash
kpm init                                             # interactive
kpm init --server https://agentkms.local:8443        # non-interactive
```

Generates `~/.kpm/config.yaml`. Optionally bootstraps mTLS certs if AgentKMS enrollment is enabled.

#### `kpm store` / `kpm list` -- legacy compatibility (local-only)

```bash
kpm store my-ssh-key                                 # local keychain (no AgentKMS)
kpm list                                             # local + remote secrets
```

Preserves bash KPM workflow for users without AgentKMS.

---

## 6. Demo Outline

### Prerequisites

- AgentKMS running locally (`localhost:8443`) with dev backend
- mTLS certs generated (existing `cmd/enroll`)
- Pre-loaded secrets:
  - `kv/db/prod` -> `{"password": "s3cret-pg-pass", "host": "db.prod.internal", "port": "5432"}`
  - `kv/app/config` -> `{"jwt_secret": "hmac-key-here", "port": "8080"}`
  - `llm/openai` -> API key
  - `llm/anthropic` -> API key
  - `kv/ssh/deploy` -> `{"private_key": "-----BEGIN OPENSSH..."}`
- Tiny demo app that reads env vars and prints "connected to {DB_HOST}:{DB_PORT}"

### Demo 1: Simple mode (.env replacement)

Show `.env.template` (no secrets) -> `kpm export` (resolved) -> `kpm run` (app works). Beat: "Your .env is now just a template. Secrets live in AgentKMS. Nothing on disk, nothing in git."

### Demo 2: Hardened mode (--secure)

Same template with `--secure`. Show ciphertext in `env | grep`. Show `ps eww` dump (attacker sees blobs). App still works via JIT. Beat: "One flag. Attacker sees garbage."

### Demo 3: Paranoid mode (--secure-strict)

Run with `--secure-strict`. Kill AgentKMS mid-session -- access fails immediately. Restart -- access restored. Beat: "Zero key material on your machine. AgentKMS can cut access instantly."

### Demo 4: SSH key management

Load SSH key from AgentKMS into ssh-agent without disk. Connect to server. No key file on disk. Beat: "SSH keys don't live in ~/.ssh anymore. Laptop stolen -- keys aren't on it."

---

## 7. Video Script Structure

### Video 1: "Your .env Files Are a Liability" (3-5 min)

| Segment | Duration | Content |
|---------|----------|---------|
| Hook | 30s | "Raise your hand if you have a .env file with real API keys right now." |
| The problem | 45s | Plaintext .env, git history, ps eww dump, leak articles |
| Demo 1: Simple mode | 90s | .env.template -> kpm export -> kpm run |
| Demo 2: Hardened mode | 90s | --secure, ciphertext in env dump, app still works |
| How it works | 30s | Quick diagram, 3-mode table |
| CTA | 15s | "Both tools are open source. Star, try, tell me what breaks." |

### Video 2: "SSH Keys Don't Belong on Your Laptop" (3-5 min)

| Segment | Duration | Content |
|---------|----------|---------|
| Hook | 30s | "14 SSH keys in ~/.ssh. Every one unencrypted on disk." |
| The problem | 30s | ls ~/.ssh, no expiry/audit/revocation |
| Demo: SSH via KPM | 90s | Load from AgentKMS, connect, no file on disk |
| Hardened SSH | 60s | --secure, env dump shows ciphertext |
| Bigger picture | 30s | "kpm = universal secrets CLI backed by AgentKMS" |
| CTA | 15s | "Links below. Building this live as a solo founder." |

---

## 8. Implementation Order (Weekend)

1. **Go module setup:** `cmd/kpm/main.go` with Cobra scaffold, `internal/kpm/` package
2. **Template parser:** regex, `KMSReference`, `ResolvedEntry`, batch dedup
3. **AgentKMS client integration:** reuse `pkg/client` for mTLS, wire up LLM + generic credential fetching
4. **`kpm export` (plaintext):** end-to-end template -> resolved env output (first working demo)
5. **`kpm run` (plaintext):** exec child with injected env
6. **`kpm get`:** single-secret fetch
7. **`--secure` mode:** session key request, local encrypt, UDS listener, `kpm decrypt` helper
8. **`--secure-strict` mode:** proxy decrypt through AgentKMS
9. **Cache layer:** `go-keyring` integration, cache commands
10. **`kpm init`:** config file generation
11. **Legacy compat:** `kpm store`, `kpm list` for local-only use

**Minimum viable demo (items 1-5):** template parser + plaintext export/run. This alone is the ".env killer" video.

**Full hardened demo (items 1-8):** all three modes working. This is the "hotel WiFi" video.

---

## 9. Dependencies

| Package | Purpose |
|---------|---------|
| `github.com/spf13/cobra` | CLI framework (already in go.mod) |
| `github.com/zalando/go-keyring` | Cross-platform keychain (cache layer) |
| `golang.org/x/sys/unix` | UDS credential checking |
| `pkg/client` (internal) | AgentKMS mTLS client |
| `pkg/crypto` (internal) | Envelope encryption, zeroing |
| `pkg/tlsutil` (internal) | TLS configuration |

---

## 10. AgentKMS Changes (Optional, Minimal)

The only server-side change considered for this weekend:

**`cache_policy` field on generic credential response** (~15 lines):

```go
type CachePolicy struct {
    AllowLocalCache    bool `json:"allow_local_cache"`
    MaxTTLSeconds      int  `json:"max_ttl_seconds"`
    RequireEncryption  bool `json:"require_encryption"`
}
```

Added to `genericCredentialResponse`. Defaults to `allow_local_cache: false`. If deferred, KPM uses a client-side heuristic (cache only `kv/ssh/*` and `kv/config/*` paths).

---

## 11. Post-Weekend Roadmap

- Python/Go JIT decrypt client libraries (`pip install kpm-client`, `pkg/kpmclient`)
- Server-side templates (`GET /templates/{name}` -- premium feature)
- `kpm rotate` -- trigger credential rotation from CLI
- Windows support (go-keyring supports Windows Credential Manager)
- CI/CD integration guide (GitHub Actions, GitLab CI)
- MCP tool integration (`kpm` as an MCP tool for Claude Code)
