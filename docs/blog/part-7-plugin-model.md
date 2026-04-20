# Go pro for plugins — how AgentKMS stays small and gets big

## The core idea in one sentence

**AgentKMS is one binary. Everything provider-specific, audit-specific, or compliance-specific is a plugin — an independent process it talks to over gRPC.**

The core handles the hard parts: policy evaluation, the credential vending pipeline, mTLS, and the audit bus. Everything else — GitHub Actions secrets, AWS STS, anomaly detection, SOC 2 evidence — is a plugin. Official ones ship bundled. The ecosystem builds the rest.

Here's why that matters, what the plugin API looks like, and what we're committed to keeping free forever.

## Why plugins, not a monolith

Every secret provider has its own API, its own auth dance, its own quirks.

AWS STS needs a role ARN and a session name and will give you fifteen-minute credentials. GitHub's fine-grained PATs have their own permission model and their own scoping rules. A corporate internal service probably speaks OAuth2 with a custom claims schema. HashiCorp Cloud has its own notion of "secret paths." Stripe ephemeral keys work completely differently from any of the above.

If you bake all of that into one binary, you get three problems:

1. **Blast radius coupling.** A bug in the GitHub adapter blocks a release for everyone, including people who don't use GitHub.
2. **Bloated attack surface.** Every provider's auth library ships with every deployment, whether or not you use it.
3. **Slow iteration.** Adding a new provider means waiting for a core release.

The plugin model breaks all three. Each provider adapter is an independent binary. It starts when AgentKMS needs it and talks to the core over gRPC on a Unix domain socket. One crashes? The core keeps running. One needs an update? Ship it independently. Your security team wants to audit the AWS adapter in isolation? It's a bounded, single-purpose binary with a clear interface.

This is the same pattern as Terraform providers, Vault secret backends, and Packer builders. It works at that scale. It works here.

## The plugin API

A plugin can implement up to four interfaces. Most plugins implement one or two.

```
┌─────────────────────────────────────────────────────────┐
│                       AgentKMS Core                      │
│                                                          │
│  Policy Engine ──► Audit Bus ──► Credential Store        │
│        │                               ▲                 │
│        │       Vending Pipeline        │                 │
│        ▼                               │                 │
│  ScopeValidator ──► ScopeNarrow ──► ScopeAnalyzer        │
│        │                               │                 │
│        ▼                               ▼                 │
│  ScopeSerializer ──────────────► CredentialVender        │
│                                        │                 │
└────────────────────────────────────────┼─────────────────┘
                                         │
                              ┌──────────▼──────────┐
                              │   Upstream Provider  │
                              │  (GitHub, AWS, etc.) │
                              └─────────────────────┘
```

**`ScopeValidator`** — "Is this scope request structurally valid for my provider?"

The agent asked for `github:repo-write:org/my-repo`. The GitHub plugin checks: is `repo-write` a real permission? Does `org/my-repo` match a valid repo pattern? Is the combination allowed? If not, the request fails here — before it ever reaches the upstream API.

**`ScopeAnalyzer`** — "Is this scope risky? Warn but don't block."

The agent asked for `aws:s3:*`. That's valid. The AWS plugin can also flag it: "This scope covers all S3 buckets in the account. Did you mean `aws:s3:my-specific-bucket`?" The analyzer emits an audit event and a warning. Policy decides whether to block or warn. The plugin just provides the signal.

**`ScopeSerializer`** — "Convert this normalized scope to my provider's native format."

AgentKMS uses a normalized scope format internally. The serializer translates it into whatever the upstream API actually wants — an AWS IAM policy document, a GitHub token permission set, a Vault policy HCL blob.

**`CredentialVender`** — "Call the upstream API and mint the credential."

This is the one that actually makes the network call. It receives the serialized scope, calls the provider, and returns a short-lived credential with its TTL and any provider metadata the audit trail should capture.

The core orchestrates: validate → narrow → analyze → serialize → vend → audit. The plugin owns only the provider-specific steps. The core never changes for a new provider. The plugin handles all the provider weirdness.

## What ships in the box

The launch release bundles a set of plugins that covers the demo end-to-end:

**Credential vendors:**
- `dynsecrets-github` — GitHub fine-grained PATs, scoped by repo and permission set
- `dynsecrets-aws` — AWS STS AssumeRole, scoped by IAM policy, 15-minute TTL

**Audit sinks:**
- `audit-file` — append-line JSON audit log, always-on default
- `audit-stdout` — human-readable audit stream, useful in dev

**Analysis:**
- `anomaly-basic` — rule-based anomaly detection: impossible travel, off-hours access, permission escalation attempts
- `forensics-cli` — the `akms forensics` commands from Part 6: timeline, actor, diff

**Ingestion:**
- `ingest-github-actions` — ingest GitHub Actions audit logs to correlate CI secret access with pipeline runs

You can disable any of these. You can replace any of these. If you build a better file audit sink, you can swap it in with a one-line config change.

These plugins are OSS, MIT-licensed, and bundled. They are not the ceiling.

## The Catalyst9 Enterprise Pack

For teams that need more than the bundled set, Catalyst9 builds and maintains the Enterprise Pack — a collection of separately installable plugins.

```bash
# Install what you need
akms plugin install c9-retention-unlimited
akms plugin install c9-anomaly-ml
akms plugin install c9-dashboard
akms plugin install c9-siem-splunk
akms plugin install c9-compliance-soc2
```

Each plugin handles its own license. The core has zero license awareness. You install it, it works, or it doesn't. There's no phone-home from the core binary.

**What's in the Enterprise Pack:**

- **`c9-retention-unlimited`** — Unlimited audit log retention with pluggable storage backends (Postgres, S3, ClickHouse). The bundled `audit-file` sink retains 90 days. This removes the ceiling.

- **`c9-anomaly-ml`** — ML-based anomaly scoring that learns your team's patterns over time. The bundled rule engine catches obvious violations. This catches the subtle drift.

- **`c9-dashboard`** — Live web UI. Real-time credential vend events, anomaly score heatmap, actor drill-down, time-range slicing. The bundled tools are CLI-first. This is for the ops team on the other monitor.

- **`c9-compliance-soc2`** / **`c9-compliance-gdpr`** — One-click evidence exports. Map audit events to control requirements. Generate reports your auditor can actually read. This doesn't change what gets audited — it adds a reporting layer over what was always there.

- **`c9-siem-splunk`** / **`c9-siem-datadog`** / **`c9-siem-elasticsearch`** — Route audit events to your existing SIEM in its native format. The bundled `audit-file` and `audit-stdout` are sufficient for standalone deployments. Teams with existing security infrastructure need this.

- **`c9-hsm`** — Hardware Security Module backend. Root key material in a FIPS 140-2 Level 3 HSM instead of software keystore. For deployments where the software root key is a non-starter.

- **`c9-sso`** — SAML2 and OIDC integration. Map identity provider groups to AgentKMS policy principals. For teams that want every secrets access tied to their IdP identity.

The Enterprise Pack is additive. Everything in the bundled set continues to work exactly as it did. You're adding capability, not replacing it.

## Community plugins

The plugin API is public. It's versioned. We're committing to API stability across minor versions.

Anyone can write a provider adapter. A few obvious ones we expect to see:

- `dynsecrets-stripe` — ephemeral Stripe restricted keys for payment API testing
- `dynsecrets-hashicorp-cloud` — HCP Vault Secrets as a credential backend
- `dynsecrets-doppler` — pull from Doppler's provider model into AgentKMS scoping
- `dynsecrets-internal` — adapter template for custom internal credential services

Plugins are signed. Catalyst9 signs official and Enterprise Pack plugins with the `c9-official` key. Third-party plugins can be self-signed — you install them by explicitly trusting the signing key:

```bash
akms plugin install --trust-key stripe-labs/dynsecrets-stripe
```

Unsigned plugins work with a warning. We're not blocking the ecosystem while it builds.

```bash
# Search the plugin registry (when it exists)
akms plugin search "stripe"
akms plugin search "audit"
akms plugin search "siem"
```

The registry is on the roadmap, not live yet. For now, plugins are installed by URL or local path. The tooling to discover and share them will grow as the ecosystem does.

## The OSS commitment

This section matters. Read it carefully.

The following will **never** be moved behind a plugin paywall:

- **Core credential vending.** The full validate → narrow → analyze → serialize → vend → audit pipeline. This is the product. It's MIT-licensed and it stays that way.
- **Full audit emission.** Every credential vend event is emitted. Every denial. Every anomaly signal. No sampling, no truncation in the core.
- **mTLS.** The authentication model is not a paid feature.
- **Policy engine.** Full deny-by-default policy evaluation. Not capped at N rules, not limited to N principals.
- **MCP server.** The model-context-protocol interface for AI agents. Free forever.
- **Unlimited users.** No seat licensing in the core.
- **The bundled plugins.** `dynsecrets-github`, `dynsecrets-aws`, `audit-file`, `anomaly-basic`, `forensics-cli` — bundled, MIT, no ceiling.

The Enterprise Pack plugins are paid because they take ongoing engineering to maintain and because they serve the specific needs of teams with compliance requirements and existing security infrastructure. They're additive. They're opt-in. They don't carve out core functionality to force an upgrade.

`--no-upgrade-hints` is a real flag. It works. The tool doesn't nag you. A brief footer on some outputs mentions the Enterprise Pack exists. `--no-upgrade-hints` removes it. The tool works without it.

One more thing: if a third-party builds a better retention plugin than our `c9-retention-unlimited`, and teams prefer that one, that's the ecosystem working correctly. We'd rather the problem be solved than be the only solver.

## Close the series

Seven posts. We started with 47 scattered secrets across `.env` files, Slack DMs, and a TextEdit window called `creds-rotate-TODO.txt`. We end with a forensics-grade, plugin-extensible credential-issuing authority for AI agents.

The problem hasn't changed. Developers put secrets where they shouldn't. They've done this since the first `.env` file got committed to a public repo in 2009, and they'll do it again tomorrow morning.

What changed is the blast radius. AI coding agents don't just read your environment — they spawn subprocesses, execute shell commands, and do it all again in a loop, at the speed of inference, with a context window full of your codebase. A compromised agent session doesn't expose one secret. It exposes everything the agent could read.

The answer we've been building toward:

- **Encrypt by default.** Ciphertext in your shell. Plaintext only for the process that earns it.
- **Scope by policy.** Short-lived, minimal-permission credentials minted at request time, not stored credentials granted at deploy time.
- **Expire by design.** Nothing lasts. The blast radius of a leaked credential is bounded by its TTL.
- **Audit everything.** Every vend, every denial, every anomaly. The forensics tools to reconstruct what happened.
- **Make it extensible.** A plugin model that lets the ecosystem grow without waiting on us.

That's the architecture. It's not a weekend hack. It's a considered answer to a problem that got quietly worse while we were busy writing feature code.

---

**The repo:** [github.com/TheGenXCoder/kpm](https://github.com/TheGenXCoder/kpm)

**Deploy it in five minutes:** [docs/getting-started.md](https://github.com/TheGenXCoder/kpm/blob/main/docs/getting-started.md)

**Contribute:** [CONTRIBUTING.md](https://github.com/TheGenXCoder/kpm/blob/main/CONTRIBUTING.md) — the list of security-sensitive modules where extra-careful review applies is in there.

**The series:**
- [Part 1: I had 47 places I stored secrets](part-1-scattered-secrets.md)
- [Part 2: Why your .env files are a liability](part-2-env-files-liability.md)
- [Part 3: Multi-client profiles without the shuffle](part-3-multi-client.md)
- [Part 4: AI coding agents make the secrets problem worse](part-4-ai-agents.md)
- [Part 5: Dynamic secrets and the TTL that saves you](part-5-dynamic-secrets.md)
- [Part 6: Forensics — what actually happened in that agent session](part-6-forensics.md)
- Part 7: The plugin model (this post)
