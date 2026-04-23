# Changelog

All notable changes to KPM are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html), with the caveat that pre-1.0 releases may include breaking changes in minor versions.

## [Unreleased]

## [0.3.1] — 2026-04-23

### Fixed
- `kpm scan files` no longer hangs on large trees. Added a default skip-dirs list covering VCS (`.git`, `.svn`, `.hg`), dependency caches (`node_modules`, `vendor`, `__pycache__`, `.venv`, `venv`, `.tox`), build outputs (`target`, `dist`, `build`, `out`, `.next`, `.nuxt`, `.turbo`, `.cache`), infra state (`.terraform`, `.vagrant`), IDE (`.idea`, `.vscode`), and test/coverage artifacts (`coverage`, `.nyc_output`, `.pytest_cache`). Opt out with `--no-skip-dirs`.
- `kpm scan files` no longer infinite-loops on symlink cycles. Walker tracks visited `(device, inode)` pairs and skips re-entry.

### Added
- `kpm scan files --no-skip-dirs` — disable the default skip list (rarely useful; `node_modules` etc. will be fully scanned).

## [0.3.0] — 2026-04-23

### Added
- `kpm scan` — three-mode secrets scanner with shared detection engine, always-redacted output, and non-zero exit on findings:
  - `kpm scan shell` — inspect the environment of every process owned by the current user for exposed secrets. Linux reads `/proc/<pid>/environ` directly; macOS parses `ps -E` output.
  - `kpm scan files [path...]` — recursive filesystem scanner with `.gitignore` respect (single-level), binary-skip via NUL-byte detection, `--max-depth`, `--no-recurse`, `--exclude <glob>`, `--no-gitignore`, `--include-binary`. Detects both `KEY=VALUE`/`key: value`/`"key":"value"` pairs and raw value matches.
  - `kpm scan logs [path]` — stream scanner for log files or stdin. Value-pattern only by default (log lines rarely have `KEY=` structure); `--include-names` enables structured-log detection. `--follow` for `tail -f` semantics.
- `--summary` flag on all three scan modes — collapses duplicate findings into unique `(variable, redacted preview)` rows with a count of distinct sources. Typical dev-machine output drops from ~200 rows to ~12-15.
- `--paranoid` flag — expanded detection (URL-embedded credentials, broader name patterns, Shannon-entropy heuristic on values ≥ 20 chars). Higher false-positive rate; recommended for audits, not CI gates.
- `--json` and `--quiet` output modes on all three scan modes for dashboards and CI gates respectively.
- `kpm update` — self-update command that shells out to the canonical install script at `https://kpm.catalyst9.ai/install`. Flags: `--source-only`, `--tag <version>`, `--dir <path>`, `--yes`/`-y`.
- `kpm-scan-*` help screens modeled on `aws sts --help` — sectioned `NAME`, `SYNOPSIS`, `DESCRIPTION`, `OPTIONS`, `EXIT STATUS`, `EXAMPLES`, `SEE ALSO`.

### Security
- Non-leak invariant: raw `Finding.Value` is discarded at the detection→output boundary. Regression tests guard all three modes × all three output formats (table, JSON, quiet) — raw canary values must never appear in output.
- Name-detector deny-list expanded beyond classic shell env (`SSH_AUTH_SOCK`, `GPG_TTY`, `PATH`, etc.) to include per-session identifiers: `STARSHIP_SESSION_KEY`, `TERM_SESSION_ID`, `ITERM_SESSION_ID`, `XDG_SESSION_*`, `DBUS_SESSION_BUS_ADDRESS`, `SSH_AGENT_PID`, `I3SOCK`, `SWAYSOCK`, and similar. These match `*_KEY`/`*_ID` patterns but are random session IDs, not credentials.

### Changed
- `install.sh` default `KPM_RELEASE_TAG` bumped to `v0.3.0`.

### Fixed
- Shannon-entropy heuristic in paranoid detection divides by rune count (not byte count) for correct behavior on non-ASCII values.

## [0.2.1] — 2026-04-22

### Added
- `kpm run --secure` — per-tool allow-list filter. Reads `.kpm/secure-allowlist.yaml` (project-local first, then user-global; first-wins, no merge). Only secrets matching the tool's exact env-var list are resolved into the child process environment; everything else is filtered. Tool not in allow-list → warn and run with KMS secrets filtered out. `--secure` without a template is a hard error.
- `kpm run --strict` — **real implementation** (v0.2.0 shipped the flag as a parse-only stub). Strict mode holds no session key and performs no local decryption; each UDS decrypt request round-trips to AgentKMS over mTLS. Blobs encode `KMSReference` as base64-JSON, not ciphertext. Session TTL is irrelevant in strict mode. `--strict + --plaintext` → hard error.
- `--strict` + `--secure` compose: secure filters first, strict wraps what survives.
- `//blog:part-N` cross-reference annotations on CLI flag definitions and shell-init wiring (feeds the blog-vs-code drift CI in the blog repo).

### Changed
- `install.sh` default `KPM_RELEASE_TAG` bumped to `v0.2.1`.

### Security
- Independent code review completed on `--secure` and `--strict`; both approved. Strict-mode blob format verified to contain no secret material.

## [0.2.0] — 2026-04-22

### Added
- Blog series (7 parts) describing the design and threat model — live at [blog.catalyst9.ai](https://blog.catalyst9.ai)
- Comprehensive secret type detection: GitHub tokens, Stripe keys, Slack tokens, AWS access keys, strict JWTs, MongoDB SRV / Redis TLS connection strings, DSA and encrypted PKCS#8 private keys, hex-encoded keys
- `CONTRIBUTING.md` with security-sensitive areas list
- `SECURITY.md` with threat model and disclosure policy
- GitHub Actions CI: `go vet`, race-detector tests, 75% coverage gate on `internal/kpm`, cross-compile matrix (linux/darwin × amd64/arm64)
- `scripts/install.sh` prefers prebuilt release binaries; source build as fallback
- `--source-only` flag to skip prebuilt download

### Changed
- Error messages parse server JSON responses and include operation context (`write cloudflare/dns-token: denied: caller lacks secret_write permission (policy_denied)`)
- `install.sh` default `KPM_RELEASE_TAG` bumped to `v0.2.0`
- Recommended minimum server: AgentKMS v0.3.0 (v0.2.0 still supported for registry + encrypted-env features only)

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
