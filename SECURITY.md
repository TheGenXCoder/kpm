# Security Policy

## Reporting a Vulnerability

**Do not file security vulnerabilities as public GitHub issues.**

Email security reports to: `security@catalyst9.ai`

Include:
- A description of the vulnerability
- Steps to reproduce (a minimal example, if possible)
- The version or commit hash where you observed the issue
- Your assessment of impact and affected components

You should receive an acknowledgment within 72 hours. We'll work with you on a disclosure timeline. Coordinated disclosure is appreciated.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |
| < 0.1.0 | No        |

Security fixes land on the latest minor version. Earlier versions are not backported.

## Security Model

This section describes the threats KPM defends against, the threats it does not, and the assumptions behind the design. Skim this before deploying KPM in environments that matter.

### What KPM defends against

**Secrets at rest on disk**
Secrets are never written to plaintext files managed by KPM. `.env.template` files contain only `${kms:...}` references, not values. The template hierarchy (enterprise/user/project) stores references, not secrets. The AgentKMS dev server's on-disk state is AES-256-GCM encrypted with a key derived from the server's EC private key via HKDF-SHA256.

**Secrets in source control**
Templates are safe to commit. They contain references to secrets, not the secrets themselves. Projects can commit `.kpm/config.yaml` files (profile metadata) without exposing any sensitive material.

**Secrets in process environment**
In the default "secure" mode, environment variables contain AES-256-GCM ciphertext blobs (`ENC[kpm:session-id:base64ciphertext]`). An attacker who dumps the process environment, runs `ps eww`, or inspects `/proc/$PID/environ` sees only ciphertext. The plaintext appears only in the child process invoked through `kpm run`, for the duration of that process.

**Secrets in crash dumps, observability pipelines, logs**
Because environment variables are ciphertext in the default mode, any tool that captures environment variables for diagnostics captures only ciphertext. The plaintext is ephemeral.

**Replay of old tokens**
Session keys have a configurable TTL (default: 1 hour). After expiry, the background decrypt listener refuses requests. The user must re-run `kpm env` to establish a new session.

**Accidental leakage through list/describe/history endpoints**
By design, the server's metadata endpoints (`GET /metadata`, `GET /metadata/{path}`, `GET /secrets/{path}?action=history`) query a physically separate KV path from the secrets store. They cannot return values, because they do not have access to the secret values store — not by convention, but by code structure. An adversarial fuzz test in the CI pipeline asserts that known-plaintext secrets never appear in the output of any read-path endpoint.

**Unauthorized writes, deletes, and reads**
Every operation on AgentKMS is authenticated via mTLS and authorized via the policy engine. Policy evaluates the caller's identity (from the client certificate), the operation, the target path, and configurable attributes (team, role, machine). Deny-by-default with explicit allow rules.

**Audit trail tampering**
Audit events are written through `context.WithoutCancel(ctx)` so they survive client disconnection. Audit events never contain secret values. Event validation rejects payloads containing PEM headers or long hex sequences that might be key material.

### What KPM does NOT defend against

KPM is not a magic wand. The following threats are outside its model.

**A compromised process running as the user, in the same shell session that ran `kpm shell-init`**
The decrypt socket is UID-scoped, not process-scoped. If you run malware as yourself, that malware can connect to `KPM_DECRYPT_SOCK` and request decryption. Mitigations:
- Use `--strict` mode for high-value secrets. The listener proxies to AgentKMS, which can apply per-request policy and deny in real time.
- Don't run untrusted code as your login user. This is outside KPM's scope.

**Physical access to unlocked hardware**
If an attacker has a root shell on an unlocked laptop, all bets are off. Disk encryption and screen locks are the controls here, not KPM.

**Hardware attacks (rowhammer, cold boot, speculative execution)**
KPM's crypto uses the Go standard library's `crypto/aes` and `crypto/cipher` packages with GCM mode. It does not use hardware security modules or secure enclaves (yet). Memory-resident key material is theoretically vulnerable to hardware attacks against the OS. This is accepted risk for the current threat model.

**Compromise of the AgentKMS server itself**
If an attacker roots the AgentKMS host, they can read the on-disk encrypted store (they'll still need the server's EC key to decrypt, but that's also on the host). Server hardening is the responsibility of whoever deploys AgentKMS. The dev mode is for local development only; production deployments should use OpenBao, Vault, or a cloud KMS backend with its own isolation.

**Tampered KPM binary**
If an attacker replaces your `kpm` or `agentkms-dev` binary with a malicious version, they control everything downstream. Signed releases and reproducible builds are on the roadmap but not in v0.1.0. For now, if you're installing KPM in an environment where binary integrity matters, build from source and verify the git commit hash against a known-good reference.

**Network attacks when AgentKMS is reachable via untrusted networks**
mTLS protects the connection. The threat model for server access is:
- The server's CA is the root of trust.
- Only callers with a cert signed by that CA can authenticate.
- Policy further restricts what authenticated callers can do.
- Cert revocation is supported (see AgentKMS docs).

If the CA is compromised, everything downstream is compromised. Protect the CA.

**Side channels in the client**
Timing, power, or electromagnetic side channels against the local decrypt listener are theoretically possible. Not defended against.

### Design assumptions

1. **Unix domain sockets are trustworthy for local IPC.** UDS with `0600` permissions and UID validation via `SO_PEERCRED` (on Linux) is sufficient isolation for the intended threat model.

2. **AES-256-GCM is secure.** No novel cryptography; we rely on the Go standard library's implementation, which uses constant-time operations where appropriate.

3. **The host OS enforces process isolation.** If the kernel is compromised, all bets are off — standard assumption.

4. **Go's garbage collector cannot be trusted to zero secret memory.** We use `[]byte` everywhere for secrets and explicitly zero after use. This is not perfect (Go doesn't guarantee that zeroed memory isn't still in some other location), but it's the best we can do in a GC'd language without dropping to unsafe code.

5. **The AgentKMS dev server is not for production.** It uses an in-memory policy engine and a single encrypted file for storage. Production deployments use OpenBao or other Vault backends.

## Reporting Practices We Commit To

- Acknowledge security reports within 72 hours.
- Work with reporters on coordinated disclosure timelines.
- Credit reporters in the security advisory (unless they prefer anonymity).
- Publish a CVE for any vulnerability that affects released versions.
- Fix reported vulnerabilities in a timely manner (target: high-severity within 7 days, medium within 30, low within 90).

## Cryptographic Primitives

| Primitive | Use | Library |
|-----------|-----|---------|
| AES-256-GCM | Session encryption, on-disk encryption (dev server) | `crypto/aes`, `crypto/cipher` (stdlib) |
| HKDF-SHA256 | Key derivation from EC private key (dev server) | `golang.org/x/crypto/hkdf` |
| ECDSA P-256 | Server identity, session tokens | `crypto/ecdsa` (stdlib) |
| mTLS | All server communication | `crypto/tls` (stdlib) |
| HMAC-SHA256 | Session token signing | `crypto/hmac` (stdlib) |

All primitives use the Go standard library where available. No custom cryptography. No pre-release or experimental primitives.

## Testing

KPM's test suite is intentionally adversarial where it matters:

- **Fuzz tests on read-path endpoints** — known-plaintext secrets are added to the registry, every read endpoint is exercised, and the output is grep'd for the plaintext. Any leak is a test failure.
- **Bit-flip tests on ciphertext** — every byte of a ciphertext blob can be flipped, and the test asserts GCM authentication fails. No silent corruption.
- **Truncation tests** — ciphertext shortened below the nonce size, below the tag size, and arbitrarily within the payload. All should fail to decrypt, never silently succeed.
- **Wrong-key tests** — decrypt attempts with an unrelated key, an EC key from a different curve, and a corrupted key file. All should error; none should panic.
- **Policy bypass attempts** — every endpoint is tested with a caller whose policy denies the operation, and verified to return 403 with no information leakage.

Run the security-relevant tests yourself:

```bash
# Unit tests
cd /path/to/kpm
go test ./internal/kpm/ -run "Security|Leak|Tamper|Bit|Crypto" -v

# Integration tests (includes adversarial fuzz)
curl -sL https://raw.githubusercontent.com/TheGenXCoder/kpm/main/tests/run-tests.sh | bash
```

## Disclosed Vulnerabilities

None yet. This list will be updated if/when vulnerabilities are disclosed.

---

**Last updated:** 2026-04-15 (v0.1.0 release)
