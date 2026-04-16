# Changelog

All notable changes to KPM are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html), with the caveat that pre-1.0 releases may include breaking changes in minor versions.

## [Unreleased]

### Added
- Blog series (Parts 1-4) describing the design and threat model
- `CONTRIBUTING.md` with security-sensitive areas list
- GitHub Actions CI: tests with race detector, coverage gate on `internal/kpm`, cross-compile matrix (linux/darwin × amd64/arm64)
- `scripts/install.sh` now prefers prebuilt release binaries, falling back to source build
- `SECURITY.md` with threat model and disclosure policy

### Changed
- Error messages now parse server JSON responses and include operation context (`write cloudflare/dns-token: denied: caller lacks secret_write permission (policy_denied)`)

## [0.1.0] — 2026-04-16

First public release.

### Secrets registry
- `kpm add service/name` — store secrets interactively (masked input), from a pipe, or from a file (`--from-file`)
- `kpm list` — organized by service; filter with `--tag`, `--type`, `--include-deleted`; JSON output with `--json`
- `kpm describe service/name` — metadata only, never values
- `kpm history service/name` — version timeline, never values
- `kpm get service/name` — retrieve a value (full auth + policy + audit pipeline)
- `kpm remove service/name` — soft-delete by default; `--purge` for hard delete
- Secret type auto-detection (api-token, ssh-key, cert, connection-string, jwt, aws-access-key, stripe-key, slack-token, github-pat, hex) with regex validation and false-positive protection
- Versioning: every write creates a new version; last 10 retained by default

### Encrypted environment
- `kpm env --from template` — resolves templates to ciphertext blobs by default (`ENC[kpm:session:blob]`)
- `--plaintext` opt-in for legacy scripts that can't use `kpm run`
- AES-256-GCM session encryption with a per-session key held only by the background listener
- `kpm run -- command` — JIT decrypt for the child process only; plaintext is destroyed when the child exits
- `kpm shell-init` — starts the decrypt listener bound to a UID-scoped Unix domain socket (`0600` permissions, `SO_PEERCRED` validation on Linux)
- `kpm show` — inspect managed secrets in the current env (shows `encrypted` status, never values)
- Session TTL (default 1 hour); listener refuses decrypts after expiry

### Template system
- Three-level hierarchy: enterprise (`/etc/catalyst9/.kpm/templates`), user (`$XDG_CONFIG_HOME/kpm/templates`), project (`./.kpm/templates`)
- Reference syntax: `${kms:service/name}`, `${kms:service/name#field}`, `${kms:kv/path#key:-default}`
- Include directive: `${kms:include/other-template}` for composition
- Circular include detection with clear error path
- `kpm tree` — show template hierarchy

### Multi-client / multi-project workflow
- `.kpm/config.yaml` profile variables walk up the directory tree (child overrides parent)
- `{{profile:key}}` substitution in templates
- Profiles are plaintext metadata only — they cannot grant secret access
- `kpm profile` / `kpm show --profile` — display merged profile with source files

### Security properties
- Separated storage invariant: list/describe/history endpoints physically cannot return values (different KV path from the secrets store)
- Adversarial fuzz test in the test suite: asserts known-plaintext markers never appear in read-path output
- Audit events written via `context.WithoutCancel` so they survive client disconnection
- Audit events never contain secret values; SHA-256 hashes used for correlation
- Dev server encrypted at rest: AES-256-GCM with key derived via HKDF-SHA256 from the server's EC private key; atomic writes; `0600` permissions
- Three modes: `--plaintext` (opt-in), default (ciphertext + local decrypt), `--strict` (every decrypt round-trips to AgentKMS with per-operation policy + audit)

### Testing
- 46 integration tests (automated in a disposable Docker container via `tests/run-tests.sh`)
- 6 explicit security checks (list/describe/history/show/JSON output never leak values; env var is always ciphertext)
- Unit coverage ≥ 79% on `internal/kpm` (adversarial tests: bit-flip, wrong-key, truncation, policy-denied, session-expired)
- Cross-compiled release binaries: linux-amd64, linux-arm64, darwin-amd64, darwin-arm64

### Requires
- AgentKMS server v0.2.0 or later (for the registry endpoints)
- Go 1.21+ only if building from source; prebuilt binaries have no runtime dependencies

### Known limitations
- Windows is not supported in 0.1.x (planned post-v0.2.0)
- Release binaries are not yet signed (reproducible builds on roadmap)
- ABAC policy is limited to mTLS cert attributes in 0.1.x; full ABAC is planned for v0.2.0

[Unreleased]: https://github.com/TheGenXCoder/kpm/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/TheGenXCoder/kpm/releases/tag/v0.1.0
