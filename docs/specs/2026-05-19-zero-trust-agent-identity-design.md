# KPM + AgentKMS — Zero-Trust Identity & Agent Containment

**Date:** 2026-05-19
**Status:** Proposed — initial draft, not yet implementation-ready
**Scope:** Multi-principal identity model (human, device, workload, agent); capability-token schema; per-task enforcement runtime that survives goal-equivalence attacks
**Author:** Bert Smith (TheGenXCoder)
**Related:** [`docs/design.md`](../design.md) (2026-04-11 unified spec), [`docs/specs/2026-04-14-secrets-registry-design.md`](2026-04-14-secrets-registry-design.md), blog Parts 4–7 (AI agents, dynamic secrets, forensics, plugins)

---

## Executive Summary

The current KPM + AgentKMS pair authenticates clients by mTLS cert subject and authorizes by path-based policy. That works for "a developer's laptop fetches a secret." It does not work for:

- One human moving between devices and expecting the same secrets to follow,
- AI agents and autonomous workloads (CI runners, cron jobs, clawbots) acting as first-class principals,
- Least-privilege containment of agents whose goal-equivalence reasoning routes around verb-level blocks (block `rm`, the agent reaches for `truncate -s 0`).

This design proposes:

1. **A flat principal model with four kinds** — human, device, workload, agent — each with its own bootstrap path, none subordinate to another.
2. **Capability tokens** issued by AgentKMS that bind an identity to a finite, declared set of effects (filesystem regions, network destinations, exec binaries, secret references) with a hard TTL and revocation.
3. **An enforcement runtime — `kpm run --task`** — that consumes a capability token and configures an OS substrate (Linux namespaces + overlayfs + seccomp + network namespace; macOS VM) where forbidden effects are *physically impossible*, not intercepted.

AgentKMS is the Authorization Server. KPM-runner is the Policy Enforcement Point. The model maps cleanly onto OAuth's AS/RS separation, applied to OS containment.

---

## Design Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Identity granularity | Flat: human, device, workload, agent — all parallel | Hierarchical models break when CI/cron/bots act without a human. Flat composes. |
| Trust transport | mTLS (device factor) + bearer token (principal claims) | Device cert proves "trusted machine"; token proves "as this principal right now." Either alone is insufficient. |
| Bootstrap for non-humans | Platform attestation: k8s ServiceAccount tokens, OIDC, enrollment-token fallback | Standard workload-identity patterns. No secrets-on-disk for the common case. |
| Containment primitive | OS substrate (overlayfs, namespaces, seccomp, netns) | Defeats goal-equivalence by making the *effect* impossible, not the verb. |
| Scope vocabulary | Effects, not syscalls: `fs.write`, `net.connect`, `exec.binary`, `secrets.read`, `tools.invoke` | Declarative scope survives translation across OS substrates. Syscall lists don't. |
| Token format | JWT-style claims with deterministic JSON canonicalization, AgentKMS signs (Ed25519) | Standard, inspectable, attenuable. Server can mint, client can present, runner can parse — no shared secret needed downstream. |
| Token attenuation | AgentKMS-mediated (no client-side attenuation in v1) | Macaroons / RFC 9449 DPoP are tempting but add cryptographic surface area. Round-trip to AgentKMS is fine for v1; revisit. |
| Revocation | Server-side denylist by `jti` with short TTL as primary defense | "Short TTL + denylist" beats CRL distribution for sub-15-minute tokens. |

---

## Core Principle

> **AgentKMS describes what may happen. The runner makes everything else impossible.**

A capability token is a contract: identity, scope, deadline. The runner reads the contract and stands up a sandbox where the agent can do exactly the listed things and nothing else — not because primitives are blocked one-by-one, but because the resources required for forbidden effects aren't present in the agent's view of the world.

---

## 1. Principal Model

Four kinds, all peer-level:

| Kind | Examples | Bootstrap | Identity material |
|---|---|---|---|
| **Human** | `human:bert` | Passphrase / WebAuthn / OIDC login + device factor | Token issued post-auth |
| **Device** | `device:bert-tp-dev` | One-time enrollment, mTLS cert thereafter (TPM-bound if available) | Long-lived cert (1y), rotatable |
| **Workload** | `workload:ci/woodpecker`, `workload:cron/db-backup`, `workload:agent/clawbot-12` | Platform attestation (k8s SA token, OIDC, enrollment) | Short-lived token per session |
| **Agent session** | `agent:claude/sess-abc123` | Derived from any session token via `/v1/tokens/attenuate` | Short-lived child token |

### Identity URI scheme

Every principal has a SPIFFE-style URI used as the canonical identifier in tokens, policy, and audit:

```
spiffe://<trust-domain>/tenant/<tenant>/<kind>/<id>[/device/<device>]
```

Examples:

```
spiffe://catalyst9.local/tenant/catalyst9/human/bert/device/bert-tp-dev
spiffe://catalyst9.local/tenant/catalyst9/device/bert-tp-dev
spiffe://catalyst9.local/tenant/catalyst9/workload/ci/woodpecker
spiffe://catalyst9.local/tenant/catalyst9/agent/claude/sess-abc123
```

Trust domain = operator boundary (one per AgentKMS deployment). Tenant = organizational unit within an operator. The trust domain is asserted by AgentKMS's signing key; the tenant is asserted by policy.

### Parent chains

Tokens carry an optional `parent` claim. Audit walks the chain:

- A human-launched Claude session has parent `human:bert`.
- An autonomous clawbot pod has no parent — it is itself a workload principal.
- A nested agent (Claude spawns Codex) has parent `agent:claude/sess-abc123`.

The audit record records the full chain. Policy can reference parent claims (`parent.kind == "human"`).

---

## 2. Token-Exchange Flows

All flows produce a **session token** — the principal-bearing JWT presented on every subsequent AgentKMS call alongside the device mTLS cert.

### 2.1 Human (kpm on a laptop)

```
1. User runs: kpm login
2. kpm presents device mTLS cert to AgentKMS /v1/auth/start
3. AgentKMS picks the configured human-auth method for the tenant
     (passphrase | WebAuthn | OIDC) and returns a challenge
4. kpm runs the challenge interactively (prompt / browser / hw token)
5. kpm presents the challenge response to /v1/auth/finish
6. AgentKMS verifies and issues a session token:
     sub: spiffe://catalyst9.local/tenant/catalyst9/human/bert
     dev: spiffe://catalyst9.local/tenant/catalyst9/device/bert-tp-dev
     exp: now + 1h
```

Same human on a different enrolled device → same `sub`, different `dev`. Same secrets, distinguishable audit.

### 2.2 Kubernetes workload (in-cluster CI/cron/bot pod)

```
1. Pod's projected ServiceAccount token is mounted at
     /var/run/secrets/kubernetes.io/serviceaccount/token
2. Workload POSTs the SA token to AgentKMS /v1/auth/k8s
3. AgentKMS verifies via the cluster's TokenReview API
4. AgentKMS maps (namespace, serviceaccount) -> workload principal via tenant config
5. AgentKMS issues a session token:
     sub: spiffe://catalyst9.local/tenant/catalyst9/workload/openclaw/clawbot
     exp: now + 15m
```

No human, no device cert needed (the cluster network position + SA token are the trust factors). Token TTL is shorter because the SA token rotates frequently and re-attestation is cheap.

### 2.3 External CI / cloud workload (GitHub Actions, etc.)

```
1. Job runs with GITHUB_TOKEN_OIDC populated by Actions
2. Job POSTs the OIDC token to AgentKMS /v1/auth/oidc
3. AgentKMS fetches issuer JWKs (cached), verifies signature + claims
4. Tenant config maps (issuer, audience, repository, ref) -> principal
5. AgentKMS issues a session token (TTL = job duration cap, e.g. 1h)
```

Same flow for GitLab CI, Vault, Auth0, Google, Okta — anywhere with a trustworthy OIDC issuer.

### 2.4 Enrollment-token fallback (bare-metal, edge)

For hosts that can't do k8s SA or OIDC: one-time enrollment token issued by an operator, redeemed once for a device cert + machine token. Subsequent auth is the device-factor flow with no human factor.

### 2.5 Agent derivation (attenuation)

```
1. kpm-runner is about to fork an agent for a specific task
2. It POSTs to /v1/tokens/attenuate with:
     - Its current session token (parent)
     - The requested scope (subset of parent's scope)
     - The requested TTL (<= parent's remaining TTL, capped at 15m default)
     - A task description (free-form, audit-only)
3. AgentKMS validates that requested scope is a subset of parent scope,
   applies tenant policy (e.g. "Claude agents may never request secrets/aws/*"),
   and mints a child token with:
     sub: spiffe://.../agent/claude/sess-abc123
     parent: <parent jti>
     scope: <attenuated>
     task_id: <generated>
     exp: now + min(requested, 15m)
4. Runner consumes the child token, sets up the sandbox, execs the agent
```

---

## 3. Capability Token Schema

```json
{
  "iss": "spiffe://catalyst9.local/agentkms",
  "sub": "spiffe://catalyst9.local/tenant/catalyst9/agent/claude/sess-abc123",
  "tenant": "catalyst9",
  "dev":  "spiffe://catalyst9.local/tenant/catalyst9/device/bert-tp-dev",
  "parent": "01HX2P3Q4R5...",
  "jti":  "01J8Y9Z0K1...",
  "task_id": "task-2026-05-19-001",
  "iat":  1747695600,
  "exp":  1747696500,
  "nbf":  1747695600,
  "scope": {
    "fs": {
      "read":   ["./src/**", "./docs/**"],
      "write":  ["./output/**", "/tmp/task-2026-05-19-001/**"],
      "delete": []
    },
    "net": {
      "connect": [
        "api.anthropic.com:443",
        "raw.githubusercontent.com:443"
      ],
      "dns": ["1.1.1.1:53"]
    },
    "exec": {
      "binaries": ["python3.12", "node22", "git"],
      "env_keep": ["PATH", "HOME", "LANG"]
    },
    "secrets": {
      "read": [
        "anthropic/api-key",
        "github/deploy-pat"
      ]
    },
    "tools": {
      "invoke": ["fs.list", "fs.read", "git.diff"]
    }
  },
  "limits": {
    "cpu_ms":   60000,
    "wallclock_ms": 900000,
    "mem_mb":   2048,
    "egress_bytes": 100000000
  }
}
```

### Field semantics

| Field | Meaning |
|---|---|
| `iss` | Issuer (AgentKMS for the trust domain). Signed with AgentKMS's tenant signing key. |
| `sub` | The principal — what the action is *as*. SPIFFE URI. |
| `dev` | The device factor — optional, present when the principal is operating from a specific device. |
| `parent` | The `jti` of the issuing session token. Audit chain root. |
| `jti` | Unique token ID. Used for revocation. |
| `task_id` | Free-form, runner-supplied. Lets you correlate audit rows for one logical job. |
| `scope.fs` | Filesystem access. Globs relative to the runner's CWD or absolute paths. **`delete: []` is explicit, not the default**, because deletion has too many goal-equivalent paths to elide. |
| `scope.net` | Egress allow-list. Host:port, no wildcards in v1. |
| `scope.exec` | Allowed binaries (PATH-resolved, then frozen) and which env vars to pass through. |
| `scope.secrets` | Which registry secrets the agent may decrypt. AgentKMS's existing read-policy applies on top. |
| `scope.tools` | Which kpm-runner-mediated tools (filesystem peek, git operations, etc.) the agent may invoke. |
| `limits` | Hard resource caps. Runner enforces via cgroups. Exceeding any → SIGKILL + audit. |

### Why `delete` is explicit

`fs.write: ["./output/**"]` permits modifying files under `./output/`. It does **not** permit deletion. To allow `unlink` inside `./output/`, the token must say `fs.delete: ["./output/**"]` separately. This forces the policy author to think about a class of operations that's often where damage happens.

The runner enforces this by mounting writable paths with an overlay that captures unlinks into the upper layer's whiteouts — and then refusing to merge them down. The agent observes successful "deletion" within its session view, but the underlying file is never touched. (Optional mode: hard-fail unlink syscalls instead, surfacing the violation immediately. Default is "isolate within session.")

---

## 4. Enforcement Runtime: `kpm run --task`

The runner is a new subcommand that takes a capability token and an inner command. It exec's the inner command in a sandbox whose shape is dictated entirely by the token's scope.

### 4.1 Lifecycle

```
                         +----------------------+
                         |  kpm run --task FILE  |
                         |    --cmd <argv>...    |
                         +----------+-----------+
                                    |
                                    | (1) load token from FILE
                                    |     verify AgentKMS signature
                                    |     check tenant trust-anchor
                                    |     check exp > now + margin
                                    v
                         +----------------------+
                         |  Plan: derive needed |
                         |  namespaces, mounts, |
                         |  netns rules, ...    |
                         +----------+-----------+
                                    |
                                    | (2) bootstrap sandbox
                                    v
                       +------------------------+
                       | unshare(mount, net,    |
                       | user, pid, ipc, uts);  |
                       | pivot_root to chroot;  |
                       | overlay mounts;        |
                       | netns + egress proxy;  |
                       | cgroup limits;         |
                       | seccomp filter;        |
                       | drop caps;             |
                       +-----------+------------+
                                   |
                                   | (3) exec inner command
                                   v
                       +------------------------+
                       | inner command runs in  |
                       | the sandbox; uses kpm  |
                       | mediation socket for   |
                       | secrets + tool calls   |
                       +-----------+------------+
                                   |
                                   | (4) on inner exit OR token expiry
                                   v
                       +------------------------+
                       | SIGKILL sandbox tree;  |
                       | revoke jti at AgentKMS;|
                       | flush audit chain;     |
                       | tear down mounts/netns |
                       +------------------------+
```

### 4.2 Linux substrate

Primary platform.

| Concern | Mechanism |
|---|---|
| Filesystem | Mount namespace + overlayfs. Lower layer = read-only host bind for every `fs.read` glob root. Upper layer = tmpfs scoped to `fs.write` globs. Paths not in any glob simply don't exist in the sandbox's view. |
| Unlinks/truncates outside writable upper | Cannot happen: the targets aren't on a writable layer. |
| Network | Network namespace with a single veth to a userspace egress proxy (runner-owned). Proxy enforces `net.connect` allow-list at SOCKS5 / SNI inspection level. |
| Executables | `exec.binaries` resolved against host PATH at sandbox build time; their paths are bind-mounted in. Nothing else is on PATH inside. |
| Syscalls | seccomp-bpf filter denying obviously dangerous syscalls (`ptrace`, `setuid`, `mount`, `pivot_root`, `keyctl`, etc.). Defense in depth; substrate is primary. |
| Resource limits | cgroup v2 controllers for CPU, memory, IO, PIDs. |
| Identity | User namespace mapping the agent to an unprivileged uid inside; outside is the runner uid. |
| Secrets | Inner command never sees plaintext env. A Unix-domain socket (mediation socket) is bound inside the sandbox; agent makes "decrypt this blob" RPCs. Runner verifies each request against `scope.secrets` and AgentKMS's policy before passing through. |
| Tool calls | Same mediation socket exposes `scope.tools` operations. Filesystem peek, git commands, etc., are runner-mediated so they're audited and bounded. |

Implementation reference: `bubblewrap`-style wrapper, ~600 lines of Go using `golang.org/x/sys/unix`. No new daemons.

### 4.3 macOS substrate

Secondary platform; less-strong guarantees.

| Concern | Mechanism |
|---|---|
| Containment primary | A virtual machine (Lima, Colima, Apple Virtualization Framework). The agent runs inside the VM; the host is the boundary. |
| File sharing | virtiofs bind for `fs.read` globs (read-only), separate writable mount for `fs.write` globs. |
| Network | VM network with host-side firewall on the bridge enforcing `net.connect`. |
| Secrets / tool calls | Mediation socket forwarded into the VM (virtio-serial). |
| Cost | One-time VM image build, multi-second startup. Optimize with persistent warm VMs per tenant. |

For lighter-weight cases (read-only tools, no network), `sandbox-exec` can be used directly without a VM, but Apple has deprecated the SBPL DSL and its long-term availability is uncertain.

### 4.4 Token consumption

The runner does **no policy decisions**. It reads the token's claims and translates them mechanically into substrate config. If the token says "no network," the runner unshares network namespace and routes the inner command to an empty netns. If the token says "fs.write: ['./output/**']," the runner mounts `./output` as the only writable region. Etc.

This separation is load-bearing: it means the runner does not need to be the policy expert. AgentKMS reasons about *who can do what*; the runner reasons about *what does what map to in this kernel*.

### 4.5 Failure modes

| Failure | Behavior |
|---|---|
| Token expires mid-task | SIGTERM inner command at `exp - grace`, SIGKILL at `exp`. Runner exits with `124`. Audit row recorded. |
| Token revoked by AgentKMS during execution | Runner subscribes to a revocation stream (long-poll or SSE) per `jti`; on revocation, immediate SIGKILL. |
| Inner command attempts forbidden effect | Substrate makes it impossible: write to non-writable path → EROFS; connect to non-allowed host → ECONNREFUSED at proxy; banned syscall → EPERM from seccomp. None of these escape the sandbox. |
| Inner command attempts privilege escalation | User namespace + dropped capabilities + seccomp ban on `setuid`/`mount`/etc. Defense in depth: the substrate boundary is enforced by the kernel, not the runner. |
| Mediation socket DoS by inner command | Per-second rate limits; over the limit → 429-equivalent on the socket; sustained abuse → SIGKILL + audit. |
| Resource limit exceeded | cgroup OOM-kill or CPU starvation; audit row with which limit tripped. |

### 4.6 What this design does *not* prevent

Stated explicitly so users don't assume more than is offered:

- **Timing side channels.** A malicious agent can encode information by varying its execution time, observable from the audit timestamps. Not defended.
- **Covert channels through approved secrets.** If the agent is allowed to write to `./output/` and connect to `api.anthropic.com:443`, it can encode arbitrary data in either. The defense is "approve narrower scope," not the runtime.
- **Bugs in upstream tools.** `node22` is in `exec.binaries`. If `node22` has an RCE that pivots the kernel, you're in kernel land — the runner is below that layer. Keep your toolchain patched.
- **Kernel vulnerabilities.** Namespaces have had escapes. Defense: keep odev's kernel current; for the highest-value tasks, use the macOS substrate's VM mode (also available on Linux via firecracker if needed).

---

## 5. Audit Records

Every operation produces one or more rows. Schema:

```json
{
  "ts":            "2026-05-19T22:14:30.123456Z",
  "event":         "secret.read",
  "principal":     "spiffe://catalyst9.local/tenant/catalyst9/agent/claude/sess-abc123",
  "parent_chain": [
    "spiffe://catalyst9.local/tenant/catalyst9/human/bert",
    "spiffe://catalyst9.local/tenant/catalyst9/device/bert-tp-dev"
  ],
  "tenant":        "catalyst9",
  "task_id":       "task-2026-05-19-001",
  "jti":           "01J8Y9Z0K1...",
  "target":        "anthropic/api-key",
  "decision":      "allow",
  "policy_id":     "tenant-catalyst9-agent-secrets",
  "session_id":    "sess-abc123",
  "client_addr":   "127.0.0.1:58234",
  "trace_id":      "...",
  "tamper_seal":   "<hash-chain link, see blog Part 6>"
}
```

Sample chains:

| Scenario | `principal` | `parent_chain` |
|---|---|---|
| Human reads secret directly | `human/bert` | `[device/bert-tp-dev]` |
| Human-launched Claude reads secret | `agent/claude/sess-abc123` | `[human/bert, device/bert-tp-dev]` |
| Clawbot reads secret autonomously | `workload/openclaw/clawbot-12` | `[]` |
| CI job reads secret | `workload/ci/woodpecker-build-9942` | `[]` |
| Claude spawns Codex which reads secret | `agent/codex/sess-def456` | `[agent/claude/sess-abc123, human/bert, device/bert-tp-dev]` |

The forensic value is in the chain, not the leaf. Compromise of `anthropic/api-key` → query the chain for every read of that key, group by principal, surface anomalies.

---

## 6. Migration Path

| Phase | What changes | Today's status | Affects |
|---|---|---|---|
| **Phase 0** | mTLS device certs, `stub-allow-all` policy | ✓ deployed | None — current state |
| **Phase 1** | AgentKMS gains token issuer + verifier. Add `/v1/auth/finish` for human passphrase auth. kpm gains `kpm login`. Policy still permissive. | A-04 already on roadmap | kpm CLI, AgentKMS server, no infra |
| **Phase 2** | Workload attestation endpoints: `/v1/auth/k8s`, `/v1/auth/oidc`. Tenant config schema for trusted issuers. | New | AgentKMS server, tenant config |
| **Phase 3** | `kpm run --task` Linux substrate. Mediation socket for secrets and tools. | New | kpm runner only |
| **Phase 4** | Policy DSL with claim-aware matchers. Replace `stub-allow-all`. Add `/v1/tokens/attenuate`. | New | AgentKMS server, policy authors |
| **Phase 5** | macOS substrate (VM-based). | New, secondary platform | kpm runner |
| **Phase 6** | TPM-backed device keys, hardware-token human auth (FIDO2). | New | kpm, AgentKMS |

Phases 1–4 are the minimum viable zero-trust agent set. Phase 0 (today) is forward-compatible: the device cert minted in Task #1 of the May 2026 setup work has the right subject scheme to participate in every later phase unchanged.

---

## 7. Open Questions

1. **Scope-declaration UX.** Capability tokens are powerful but only if the policy author can describe scope correctly. Three candidate paths:
   - **(a) Per-task templates**: developer pre-declares `tasks/refactor-auth.scope.yaml` and references it: `kpm run --task=tasks/refactor-auth.scope.yaml -- claude ...`.
   - **(b) Interactive grants**: agent requests a scope extension mid-task; AgentKMS prompts the human or applies a tenant rule.
   - **(c) LLM-inferred scope**: a meta-LLM call decides scope from the agent's stated intent before minting. Adds latency and a new failure mode (the meta-LLM is wrong).

2. **CA-per-tenant vs single shared CA.** Today there's one `agentkms-ca`. A multi-tenant deployment may want a CA per tenant for strong cryptographic isolation, with AgentKMS holding intermediate signing keys. Trade-off: ops cost vs blast radius on key compromise.

3. **Goal-equivalence at network layer.** Mature: HTTP egress to `api.anthropic.com` allows arbitrary data exfil via prompt parameters. Mitigation is narrower scope ("agent can only call these RPC paths on this host") via L7 proxying. Research-grade.

4. **Hardware-bound device keys.** TPM (Linux), Secure Enclave (macOS), or YubiKey PIV would prevent device-cert exfiltration. Requires PKCS#11 support in kpm — not present today.

5. **Federation across trust domains.** When a human at one tenant invokes a workload at another, the audit chain crosses trust boundaries. SPIFFE has a federation pattern (trust-domain bundles); AgentKMS would need to import them.

6. **Quota / rate limits per principal.** Beyond per-task limits in `scope.limits`, principals may need long-running budgets (Bert's Claude sessions can't exceed N requests/day). Probably AgentKMS-side accounting, not runner.

7. **Revocation propagation latency.** Default: short TTL + denylist. For sub-second propagation (incident response), need push-based revocation. Adds AgentKMS infra (pub/sub, runner long-poll).

---

## 8. Out of Scope (for this design)

- Specific cryptographic primitives beyond "Ed25519 for token signing, AES-256-GCM for any envelope encryption" — that's the existing AgentKMS choice.
- The blog-Part-6 forensics hash chain — already designed, this doc just adopts it as the audit storage layer.
- Server-side template resolution — covered by `2026-04-14-secrets-registry-design.md` and unchanged.
- The kpm template syntax (`${kms:...}`, `{{profile:...}}`) — unchanged.
- Plugin-based secret backends — unchanged from blog Part 7.

---

## 9. Implementation Sketch (not commitments)

Rough complexity to scope conversations, not to plan a release:

| Component | Where | Size estimate |
|---|---|---|
| Token issuer (Ed25519 sign, JWT serialize) | AgentKMS Go server | ~400 LOC + tests |
| Token verifier middleware | AgentKMS | ~200 LOC |
| `kpm login` interactive flow | kpm CLI | ~300 LOC |
| `/v1/auth/k8s` (TokenReview) | AgentKMS | ~150 LOC |
| `/v1/auth/oidc` (JWKS fetch + verify) | AgentKMS | ~250 LOC |
| Policy DSL with claim matchers | AgentKMS | ~600 LOC + DSL spec |
| `/v1/tokens/attenuate` | AgentKMS | ~200 LOC |
| Token revocation denylist | AgentKMS | ~150 LOC |
| `kpm run --task` Linux substrate | kpm runner (new package) | ~800 LOC + integration tests |
| Egress proxy | kpm runner | ~250 LOC |
| Mediation socket protocol + server | kpm runner | ~400 LOC |
| Mediation socket client (drop-in for secret-reading tools) | kpm-sdk for inner-agent | ~150 LOC |
| macOS VM substrate | kpm runner | ~600 LOC + Lima/Apple-VF bootstrap |

Order of value delivery: token issuer → human auth → workload attestation (k8s first, OIDC second) → attenuation → `kpm run --task` Linux. macOS substrate, hardware-bound keys, and federation are second-wave.

---

## 10. Decision Log

(To be filled in as the design is reviewed.)

| Date | Decision | Driver |
|---|---|---|
| 2026-05-19 | Initial draft | Identity gap surfaced during odev kpm bootstrap (see Task #1) |
