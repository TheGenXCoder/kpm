# One template tree, twelve clients, zero friction

## The annoying problem

I work with multiple clients. Some weeks four, sometimes a dozen. Each has their own:

- Cloud account (AWS, GCP, or Azure — sometimes all three)
- Database credentials (a staging and a production, almost always)
- AI provider credentials (the pattern of "each client pays for their own Claude access" is becoming standard)
- VPN or tunnel credentials
- Region/environment conventions that don't overlap

Switching between clients used to be a fifteen-minute ritual: set `AWS_PROFILE`, `cp ~/creds/clientname/.env .`, edit `~/.ssh/config`, unset half-remembered env vars from the last client, remember the new client's naming conventions. Every single context switch.

The wrong answer is "make them all the same." They're not the same, and standardizing across clients is someone else's job. The right answer is: **describe what's different once, then forget about it.**

That's what KPM's profile system does.

## The data model

Every directory can have a `.kpm/config.yaml` file with a `profile:` section. Profile configs are **plaintext metadata** (not secrets) — customer names, region codes, project identifiers. When you `cd` into a directory, KPM walks up the tree and merges all the `.kpm/config.yaml` files it finds, with child values overriding parent values for the same key.

Here's how I've structured it:

```
~/clients/
├── acme/
│   └── .kpm/config.yaml           # customer: acme
│       ├── us-east/
│       │   └── .kpm/config.yaml   # region: us-east
│       │       ├── project-alpha/
│       │       │   └── .kpm/config.yaml   # project: alpha, env: staging
│       │       └── project-beta/
│       │           └── .kpm/config.yaml   # project: beta, env: production
│       └── us-west/
│           └── .kpm/config.yaml   # region: us-west
└── globex/
    └── .kpm/config.yaml           # customer: globex
```

When I `cd ~/clients/acme/us-east/project-alpha`:

```bash
$ kpm profile
customer: acme           ← ~/clients/acme/.kpm/config.yaml
region:   us-east        ← ~/clients/acme/us-east/.kpm/config.yaml
project:  alpha          ← ~/clients/acme/us-east/project-alpha/.kpm/config.yaml
env:      staging        ← ~/clients/acme/us-east/project-alpha/.kpm/config.yaml
```

No repetition. Each level declares only what's new at that level.

## Why profiles walk but templates don't

This is where I spent the most time thinking. There's an obvious question: "If profile configs walk up, why don't templates walk up?"

Profile configs and templates solve different problems and have different security properties.

**Templates control secret access.** A template declares which secrets a process gets. If templates walked up the directory tree, an attacker who could create a `.kpm/templates/claude.template` in a parent directory could grant secret access to every project below it. You'd open a new terminal, `cd` into a project, run `kpm run -- claude`, and discover that a parent directory had silently added your AWS root key to the environment. That's a privilege-escalation vector.

**Profile configs are plaintext metadata.** They contain strings like `customer: acme` and `region: us-east`. These aren't secrets. They're identifiers. They can't escalate privilege. At worst, an attacker who can write to a parent `.kpm/config.yaml` could mess with your tab completion or make some tool think it's in the wrong region. Not a security concern.

So the rule is:
- **Templates: explicit only.** Project level (`./.kpm/templates/`) or user level (`$XDG_CONFIG_HOME/kpm/templates/`). No walking.
- **Profiles: walk up, merge.** Same pattern as `.gitconfig`, `.editorconfig`, `.npmrc`. Safe because profiles are plaintext.

## One template, every client

Here's the template that does the heavy lifting for AI coding work:

```bash
# $XDG_CONFIG_HOME/kpm/templates/claude.template
ANTHROPIC_API_KEY=${kms:customers/{{profile:customer}}/anthropic-key}
CLAUDE_MODEL={{profile:model:-claude-opus-4-6}}
CLAUDE_MAX_TOKENS={{profile:max_tokens:-8192}}
```

The `{{profile:customer}}` part gets replaced at runtime with whatever `customer` is in the merged profile. The `${kms:...}` part then resolves to the actual secret path in AgentKMS.

In `~/clients/acme/us-east/project-alpha/`:

```bash
$ kpm run -- claude "review this PR"

# Profile resolves customer=acme, so:
# Template resolves ${kms:customers/acme/anthropic-key}
# Which fetches the secret stored at customers/acme/anthropic-key
# Which is Acme's Anthropic key, not mine
```

In `~/clients/globex/`:

```bash
$ kpm run -- claude "review this PR"

# customer=globex this time
# ${kms:customers/globex/anthropic-key} resolves to Globex's key
```

Same command. Different secrets. Zero work.

## Includes for composition

The second piece is template composition. A database template might need both database credentials and AWS credentials. Instead of duplicating, use `${kms:include/path}`:

```bash
# ~/.config/kpm/templates/db-migrations.template
${kms:include/customers/{{profile:customer}}/aws}
${kms:include/customers/{{profile:customer}}/{{profile:env}}/db}
MIGRATION_DIR=/app/migrations
```

That pulls in two other templates, resolving profile variables at each level:

```bash
# Resolves to:
# - customers/acme/aws.template (AWS creds for Acme)
# - customers/acme/staging/db.template (Acme's staging DB creds)
# - Plus the local MIGRATION_DIR setting
```

One template declares the composition. Profile variables determine which actual templates get included. If I move from staging to production, I change `env: staging` to `env: production` in the project-level config, and every command I run now points at the production secrets. No search-and-replace. No forgotten `.env` file that still has staging values.

Circular includes are detected and error clearly. Include depth is bounded. Missing include paths fail loudly with the list of directories checked.

## The onboarding problem

Here's the real-world scenario that sold me on this design.

Last month I added a new client. Here's what I did:

1. Created `~/clients/newclient/` with a `.kpm/config.yaml` containing `customer: newclient`.
2. Ran `kpm add customers/newclient/anthropic-key` and pasted their Claude key.
3. Ran `kpm add customers/newclient/aws` with their AWS access key.
4. Done.

All my existing templates — for `claude`, `terraform`, `aws-cli`, `psql`, whatever — work in the new client's directories automatically. I didn't create new templates. I didn't edit existing templates. I added two secrets to the registry and created one metadata file.

When I cycle off that client in three months, I run `kpm remove customers/newclient/anthropic-key` and `kpm remove customers/newclient/aws`. Their access is gone. The directory structure is still there for historical context, but the secrets aren't — so `kpm run -- claude` in their directory will fail with a clear error. No orphaned keys sitting in an old `.env` file that I might accidentally source later.

## The whole multi-client demo

In one terminal:

```bash
$ cd ~/clients/acme/us-east/project-alpha
$ kpm show --profile
KPM Session: s1a2b3c4 (TTL: 58m12s remaining)

  ANTHROPIC_API_KEY         encrypted
  AWS_ACCESS_KEY_ID         encrypted
  AWS_SECRET_ACCESS_KEY     encrypted
  DB_PASSWORD               encrypted

4 secrets managed

Profile:
  customer: acme           ← ~/clients/acme/.kpm/config.yaml
  region:   us-east        ← ~/clients/acme/us-east/.kpm/config.yaml
  project:  alpha          ← ~/clients/acme/us-east/project-alpha/.kpm/config.yaml
  env:      staging        ← ~/clients/acme/us-east/project-alpha/.kpm/config.yaml

$ kpm run -- claude "summarize this week's commits"
# → Uses Acme's Claude key
```

In another terminal:

```bash
$ cd ~/clients/globex
$ kpm show --profile
KPM Session: s9x8y7z6 (TTL: 58m01s remaining)

  ANTHROPIC_API_KEY         encrypted
  AWS_ACCESS_KEY_ID         encrypted
  AWS_SECRET_ACCESS_KEY     encrypted

3 secrets managed

Profile:
  customer: globex         ← ~/clients/globex/.kpm/config.yaml

$ kpm run -- claude "draft the release notes"
# → Uses Globex's Claude key
```

Same command, same shell setup, entirely different secrets for each context. I just `cd` and work. The tool figures out which client I'm working on and gets the right credentials.

## Why this matters beyond consulting

I talk about this in terms of clients because that's my use case. But the same pattern applies to:

- **Multi-environment deployments** — dev, staging, production with different secret stores
- **Monorepos with multiple services** — each service has its own database, its own API keys
- **Personal + work** — your personal GitHub token vs your work GitHub token, switched by `cd`
- **Security zones** — "green" projects (internal only) vs "red" projects (customer data) with different policy requirements

Anywhere you have a hierarchy of contexts, with some things common and some things different, profile merging + include directives turn it from a matrix of duplicated config into a tree of inheritance.

## A note on security

Profiles and templates form a split trust model:

- **Templates are authoritative about what secrets a process receives.** They're explicit and tightly scoped. An attacker can't add templates to parent directories to inject secrets.
- **Profiles are suggestions about context.** They tell the template which path to construct. An attacker could write a bogus `.kpm/config.yaml` somewhere, but the worst they can do is redirect your template to a non-existent secret path — which errors loudly.

The actual access decision happens at the server. AgentKMS checks: does this caller (identified by mTLS cert) have permission to read this secret path? That check happens regardless of what the profile or template says. Profile variables are just string substitution; they don't grant permissions.

So you can have `customers/acme/anthropic-key` and `customers/globex/anthropic-key` in the registry, each with its own policy. If you accidentally end up in a `globex` profile context while trying to read Acme's secret, the server denies you. The worst a misconfigured profile can do is deny-by-policy — not leak secrets.

## Try it

```bash
# Install
curl -sL kpm.catalyst9.ai/install | bash
kpm quickstart

# Set up two fake "clients"
mkdir -p /tmp/kpm-demo/acme /tmp/kpm-demo/globex
echo "profile:\n  customer: acme" > /tmp/kpm-demo/acme/.kpm/config.yaml
echo "profile:\n  customer: globex" > /tmp/kpm-demo/globex/.kpm/config.yaml

# Check each
cd /tmp/kpm-demo/acme && kpm profile
cd /tmp/kpm-demo/globex && kpm profile
```

Then build a template that uses `{{profile:customer}}` and watch it adapt.

Repo: [github.com/TheGenXCoder/kpm](https://github.com/TheGenXCoder/kpm)

---

**Part 4:** how this whole model changes when you're running AI agents that spawn sub-agents. The "one secret to the whole process tree" problem, and why we built `kpm run --secure` specifically for agentic workflows.
