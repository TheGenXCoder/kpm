# I had 47 places I stored secrets. Then I built this.

## The inventory

A few weeks ago I went hunting for an api key I needed. I grep'd my home directory for strings that looked like API tokens. Here's where I found my own secrets:

- Four `.env` files across three projects, two with production DB passwords
- Three encrypted Obsidian notes with API tokens from 2023
- Two Apple Notes with "temporary" credentials from vendor integrations
- My dotfiles repo — with the keys scrubbed, but the git history remembered
- Fourteen files under `~/.config/` with OAuth tokens, signing keys, or cloud credentials
- A TextEdit window I'd left open for three weeks titled `creds-rotate-TODO.txt`
- Eleven Slack DMs to myself, each with a key I'd pasted to "remember it"
- Six SSH private keys in `~/.ssh`, three of them without passphrases
- Two `docker login` sessions I'd forgotten about

47 places. No system. No audit. No expiry. If my laptop got stolen, an attacker would need about forty-five minutes with `grep -r` to walk out with everything.

I'm a security-conscious developer with thirty years in the industry. This is still what my machine looks like. I'd bet a reasonable amount it's what yours looks like too.

## Why existing tools don't fix this

The standard answer is "use a secrets manager." Fine. Which one?

**HashiCorp Vault** is the serious answer. It's also a whole operational commitment — a server to run, policies to write in HCL, sidecars for your apps, an unseal ceremony. For a team of thirty it's worth it. For me, solo, it's a full-time job I don't want.

**1Password CLI / Doppler / AWS Secrets Manager** solve part of the problem. They're great for teams that already live in that ecosystem. They're not great when you want to own your infrastructure, work offline, or not hand every secret to a third-party SaaS.

**SOPS** encrypts files-on-disk brilliantly. It doesn't solve "I can't remember where I put the Cloudflare token."

**Keychain / libsecret / gopass** are local-only. They work for one machine. My dev laptop, my server, my laptop-in-a-drawer that I boot once a month — none of them share state.

None of these tools meet the real need: **find everywhere my secrets are, put them in one place, and give me a frictionless way to use them from any machine without ever writing them to disk again.**

## What I built

[KPM](https://github.com/TheGenXCoder/kpm) is a secrets CLI that does three things:

1. **Organizes what you have** into a registry: `service/name`, tagged, versioned, audited
2. **Loads them into your shell as ciphertext** — your `$ANTHROPIC_API_KEY` is a `ENC[kpm:...]` blob, not plaintext
3. **Decrypts on demand** for the tool that needs the value — and only for that tool, only for as long as it runs

It's backed by [AgentKMS](https://github.com/TheGenXCoder/agentkms), an mTLS-authenticated server I built to be small enough to run alongside my apps without running my life.

## The 30-second walkthrough

```bash
# Install
curl -sL kpm.catalyst9.ai/install | bash

# Set up a local dev environment (no external server needed)
kpm quickstart
```

Two commands, under a minute. You now have a local AgentKMS instance with mTLS-signed certs and an empty registry.

Add your first secret:

```bash
$ kpm add anthropic/api-key --tags dev,ci
Value: ••••••••••••••••
Stored anthropic/api-key v1 (tagged: dev, ci) [api-token]
```

The prompt is masked — no echo, like `ssh-keygen`. The type (`api-token`) was auto-detected from the `sk-` prefix.

See what you've organized:

```bash
$ kpm list

anthropic/
  api-key                 api-token    [dev, ci]                    v1

cloudflare/
  dns-token               api-token    [dns, ci]    "DNS edit token" v1

github/
  deploy-pat              api-token    [ci]                         v1

ssh/
  deploy-key              ssh-key                   "prod deploy"   v1

4 secrets across 4 services
```

**Metadata only. No values.** Run `kpm describe cloudflare/dns-token` or `kpm history cloudflare/dns-token` — same thing. The list endpoint on the server is physically unable to return values (separated storage: metadata and secrets live in different KV paths).

## The shell integration

Add this line to your `.bashrc` or `.zshrc`:

```bash
eval "$(kpm shell-init)"
```

Open a new terminal. Check your environment:

```bash
$ echo $ANTHROPIC_API_KEY
ENC[kpm:s1a2b3c4:SGVsbG8gd29ybGQgdGhpcyBpc24ndCBwbGFp...]
```

**That's not your API key.** That's an AES-256-GCM ciphertext blob, tagged with a session ID. If someone `ps eww`'s your shell, dumps your process memory, or greps your environment, they get this.

When you need the actual value:

```bash
$ kpm run -- claude "fix the auth bug"
```

KPM scans your environment for `ENC[kpm:...]` blobs, decrypts them via a Unix domain socket bound to your UID, passes plaintext to the child process, and destroys the plaintext when the child exits.

Your shell still has ciphertext:

```bash
$ echo $ANTHROPIC_API_KEY
ENC[kpm:s1a2b3c4:SGVsbG8gd29ybGQ...]
```

The child process got the real key for the duration of its work. Your shell never did.

## Multi-client work

This is the part I'm most proud of because it addresses something no other tool does well.

I work on multiple client projects. Each needs different secrets — CompanyX's Anthropic key, CompanyY's AWS credentials, my personal GitHub token. I used to switch `~/.env` files by hand. Now:

```bash
$ tree ~/clients -L 3
~/clients
├── acme
│   ├── .kpm/config.yaml       # profile: { customer: acme }
│   ├── us-east
│   │   ├── .kpm/config.yaml   # profile: { region: us-east }
│   │   ├── project-alpha
│   │   │   └── .kpm/config.yaml  # profile: { project: alpha, env: staging }
│   │   └── project-beta
│   └── us-west
└── globex
```

One template, adapts to every permutation:

```bash
# ~/.config/kpm/templates/claude.template
ANTHROPIC_API_KEY=${kms:customers/{{profile:customer}}/anthropic-key}
CLAUDE_MODEL={{profile:model:-claude-opus-4-6}}
```

In `acme/us-east/project-alpha/`:

```bash
$ kpm show --profile
KPM Session: s1a2b3c4 (TTL: 58m12s remaining)

  ANTHROPIC_API_KEY         encrypted

1 secrets managed

Profile:
  customer: acme           ← ~/clients/acme/.kpm/config.yaml
  region: us-east          ← ~/clients/acme/us-east/.kpm/config.yaml
  project: alpha           ← ~/clients/acme/us-east/project-alpha/.kpm/config.yaml
  env: staging             ← ~/clients/acme/us-east/project-alpha/.kpm/config.yaml
```

Profile configs walk up the directory tree and merge. Child overrides parent. Templates don't walk (that'd be a security risk), but profiles do (they're plaintext metadata).

`kpm run -- claude` picks up `acme`'s Anthropic key. `cd ../project-beta` and the same command uses a different key. Zero friction. Zero `.env` file shuffle.

## Security model

Short version:

- **mTLS everywhere.** Every server call is mutual-TLS authenticated. No bearer tokens for server identity.
- **Policy-checked server-side.** Every read, write, and delete goes through policy evaluation. Deny-by-default.
- **Audited.** Every operation logs the caller, the path, and the outcome. Never the value.
- **Ciphertext in your env.** The default mode of `kpm env` produces `ENC[kpm:...]` blobs. Plaintext is an explicit opt-in.
- **`[]byte` everywhere.** Secrets are byte slices, not strings, so they can be zeroed. We zero them aggressively and don't trust Go's garbage collector for key material.
- **Separated storage.** The metadata endpoint physically cannot return values — it queries a different KV path than the secrets store.
- **Adversarial tests.** The test suite fuzzes the list/describe/history endpoints with known-plaintext secrets and asserts zero occurrences in the output.

Code coverage: 80%+ across all security-critical packages, with enforced minimums (85% on auth, policy, and audit). Adversarial fuzz tests run in CI.

## What it's not

KPM isn't trying to replace Vault in a mature enterprise with a dedicated platform team and existing HCL policies. If you already have that, KPM complements it. For everyone else — solo developers, small teams, consultants juggling clients — this is the tool that actually fits.

KPM isn't a SaaS. I won't hold your secrets. AgentKMS runs wherever you run it — your laptop, your server, a K3s cluster in your closet.

KPM isn't "done," but the foundation is solid. **v0.3** ships:

- **Dynamic Secrets** — AgentKMS mints scoped, short-lived credentials for AWS STS, GitHub App, and more
- **Plugin architecture** — extend with Go, Python, Rust, or any language that speaks gRPC (`hashicorp/go-plugin`)
- **MCP server** — Claude Code, Cursor, and other AI tools connect directly via the Model Context Protocol
- **Forensics chain-of-custody** — when a credential leaks, one command shows who issued it, who used it, scope, and whether it was already expired
- **`kpm run --secure`** — per-tool allow-lists so your AI agent only gets the secrets it needs
- **Prebuilt binaries** — `curl | bash` just works on macOS and Linux, no Go required

On the roadmap:
- Import scanner — `kpm import --scan ~/.config` finds secrets in your files
- Windows support (named pipes for the JIT decrypt path)
- ABAC policy — time-based, network-based access rules
- Split knowledge — PCI-DSS dual-control for sensitive secrets

## Try it

```bash
curl -sL kpm.catalyst9.ai/install | bash
kpm quickstart
kpm add test/demo
kpm list
```

Star the repo if you want to see where this goes: [github.com/TheGenXCoder/kpm](https://github.com/TheGenXCoder/kpm).

The feedback window is open — file issues, break things, tell me what's wrong.

---

**This is Part 1 of a 7-part series.** Part 2: why your `.env` files are a liability even if they never leave your machine, and what ciphertext-by-default actually buys you.
