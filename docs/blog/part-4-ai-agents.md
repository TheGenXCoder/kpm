# AI coding agents make the secrets problem worse. Here's the fix.

## What changed when Claude started running commands

A year ago, "using an AI coding tool" meant pasting code into a chat window. The AI suggested a diff, you applied it, you ran it. The AI never touched your system. Your secrets were between you and the machine.

That model is gone. Claude Code runs shell commands. Cursor's composer runs tools. Aider edits files and commits. Codex CLI spawns builds and tests. The AI is no longer a text prediction service you consult — it's a process on your laptop, with your privileges, executing commands that touch your environment.

The first time a developer realizes this, they check their shell environment and notice something uncomfortable: the AI process inherited every secret they'd ever `export`ed. `ANTHROPIC_API_KEY`, `AWS_ACCESS_KEY_ID`, `DATABASE_URL`, `GITHUB_TOKEN` — all of it. And the AI process is spawning child processes (your build, your tests, your `docker run`) that inherit those same secrets.

The usual advice — "don't put secrets in env vars" — doesn't work here. The whole AI-tool ecosystem runs on env vars. `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GOOGLE_API_KEY`, whatever provider your tool uses. You can't not have them in the environment. The tools require it.

So the real question is: **how do you give the AI the one secret it needs without giving it every secret you have?**

## The process tree problem

Here's a mental model that helps. When you run `claude "fix the failing test"`, the process tree looks something like:

```
zsh (your shell, holds all your env vars)
└── claude (AI agent, reads ANTHROPIC_API_KEY)
    ├── go test (spawned by AI to run the test)
    ├── docker ps (spawned by AI to check state)
    ├── gh pr view (spawned by AI to check context)
    └── vim (spawned by AI to edit a file)
```

Every child process — `go test`, `docker ps`, `gh pr view`, `vim` — inherits the full env from `claude`, which inherited the full env from `zsh`. If any one of those tools has a plugin that exfiltrates env vars (a compromised VS Code extension, a malicious npm postinstall, a supply-chain-compromised helper binary), your AWS keys are gone. And the AI doesn't *need* those AWS keys — it only needs `ANTHROPIC_API_KEY` to talk to Anthropic's API.

The unix model treats the process tree as a single trust domain. That's fine when you wrote every binary. It's not fine when a "smart" process is deciding what other binaries to run.

## The obvious-but-wrong answer: shell wrappers

The first instinct is to wrap the AI tool: `ANTHROPIC_API_KEY=$(some-vault-cmd) claude "..."`. This kinda works, but it has three failures:

1. **The plaintext leaks into process args.** `ps -ef` shows the whole command line. The key is visible to any other process on the machine for the duration of your AI session.

2. **The plaintext is in the AI process's environment.** It then propagates to every child process the AI spawns. Every tool the AI uses inherits your provider key.

3. **It only handles one secret.** Real AI sessions need multiple secrets: the LLM key, maybe AWS for infrastructure queries, maybe a GitHub token for PR operations. You end up with a shell of `A=$(...) B=$(...) C=$(...) tool` which is awful ergonomics and still has problems 1 and 2.

You can do better.

## KPM's model: encrypted env + per-process decrypt

Recap from earlier posts. KPM puts **ciphertext** in your env, not plaintext:

```
$ env | grep ANTHROPIC
ANTHROPIC_API_KEY=ENC[kpm:s1a2b3c4:base64ciphertext...]
```

A process that dumps the env sees ciphertext. Useless without the session key, which lives in a separate listener process.

When you run an AI tool, you use `kpm run`:

```bash
$ kpm run -- claude "fix the failing test"
```

`kpm run` decrypts the ciphertext **for the child process only**:

```
zsh (env has ciphertext, useless to anyone who dumps it)
└── kpm run (decrypts in-memory, builds child env)
    └── claude (gets real ANTHROPIC_API_KEY)
        ├── go test (inherits env from claude — same plaintext)
        ├── docker ps (inherits env from claude — same plaintext)
        └── ...
```

That's already a big improvement over plaintext env vars in `zsh`. But notice: `go test`, `docker ps`, and the rest of the child processes **still inherit the real plaintext**. The AI's children are a fresh attack surface.

For most people that's acceptable. The tools the AI spawns are running on your machine anyway, as you; they would have been able to read your env even without the AI. The AI just concentrates the risk into a short window.

But for some secrets, you want more. That's where `--secure` comes in.

## `kpm run --secure`: process-scoped filtering

The `--secure` flag changes the behavior. Instead of decrypting everything the child process inherits, KPM reads a per-tool allow-list:

```yaml
# ~/.config/kpm/secure-allowlist.yaml
claude:
  - ANTHROPIC_API_KEY
  - CLAUDE_MODEL
cursor:
  - OPENAI_API_KEY
  - ANTHROPIC_API_KEY
codex:
  - OPENAI_API_KEY
gh:
  - GITHUB_TOKEN
terraform:
  - AWS_ACCESS_KEY_ID
  - AWS_SECRET_ACCESS_KEY
  - AWS_SESSION_TOKEN
```

Now:

```bash
$ kpm run --secure -- claude "fix the failing test"
```

The `claude` process sees only `ANTHROPIC_API_KEY` and `CLAUDE_MODEL` as plaintext. **Every other secret remains ciphertext** in its environment.

```
zsh (env has ciphertext)
└── kpm run --secure (reads allow-list for "claude")
    └── claude
        env includes:
          ANTHROPIC_API_KEY=sk-real-value         # allowed, plaintext
          CLAUDE_MODEL=claude-opus-4-6            # allowed, plaintext
          AWS_ACCESS_KEY_ID=ENC[kpm:...]          # still ciphertext
          DATABASE_URL=ENC[kpm:...]               # still ciphertext
          GITHUB_TOKEN=ENC[kpm:...]               # still ciphertext
```

When the AI spawns a child that actually needs one of those other secrets (say, `terraform plan`), you can either:

1. Let the child run in ciphertext mode and fail with a clear "ciphertext detected" error, then rerun with `kpm run -- terraform plan` explicitly.
2. Add an allow-list entry for `terraform` and let the whole chain work.

The default is option 1. Explicit is better than implicit. If the AI wants to run your Terraform against production, you should know about it.

## Running an AI agent under `--strict`

There's a harder mode still. `kpm run --strict` doesn't hold any session key on the client. Every decrypt request round-trips to AgentKMS over mTLS, is audited, and can be denied in real time by policy.

For an AI agent, this means:

```bash
$ kpm run --strict -- claude "review my code"
```

- Every time the agent tries to decrypt `ANTHROPIC_API_KEY`, a network request goes to AgentKMS.
- AgentKMS evaluates policy: is this the right user? At the right time of day? From the right network? For this specific secret?
- The request is logged with caller identity, timestamp, and outcome.
- If the answer is no, the agent gets `permission denied` and the operation fails.

The policy layer is where teams who run AI agents at scale will live. "Claude can use `claude-pilot-team/claude-key` but not `prod-infra/aws-root`." "Cursor can read database credentials for staging but not production." Those rules live in AgentKMS policy, not in your shell config.

## The audit question

Every AI session that touches secrets generates an audit trail. For `kpm run` (default), the audit is at the server: "user X decrypted the `ANTHROPIC_API_KEY` session at 14:32:01 from machine Y." For `kpm run --strict`, the audit is per-operation: "user X decrypted `kv/aws/prod#access-key` at 14:32:47."

When a developer asks "what did the AI do on my machine?", you have three places to look:

1. **Shell history** — what commands did you ask it to run? (This is your record.)
2. **KPM decrypt log** — what secrets did it access? (This is the server's record.)
3. **AgentKMS audit events** — what was denied and why? (This catches attempts.)

If the AI was compromised (prompt injection, supply chain, misconfigured tool), the decrypt log tells you which secrets were exposed. You rotate those and nothing else. Without this layering, your only option when an AI session goes wrong is to rotate everything. With it, you rotate surgically.

## The "what about `eval`?" problem

AI tools love `eval`-style loops. The classic pattern: the AI writes a script, runs it, observes the output, writes another script, repeats. When that script contains a shell command that needs a secret, the AI wants the secret as a plaintext env var.

The KPM answer is: **the script should call the tool, not inline the secret.**

Don't have the AI write:
```bash
curl -H "Authorization: Bearer $ANTHROPIC_API_KEY" https://api.anthropic.com/...
```

Have it write:
```bash
kpm run -- curl -H "Authorization: Bearer $ANTHROPIC_API_KEY" https://api.anthropic.com/...
```

Or better, wrap the tool so the AI never sees the secret:
```bash
# ~/bin/claude-api
#!/usr/bin/env bash
kpm run -- curl "$@"
```

The AI writes `claude-api https://api.anthropic.com/...` and KPM decrypts for the duration of that one curl. No plaintext in the AI's conversation history, no plaintext in the AI's generated scripts, no plaintext sitting in `.bash_history`.

This is a small change in how you wrap tools. It's a big change in the AI's ability to exfiltrate.

## The quickstart for AI workflows

If you already use KPM, add the AI tools you use to your templates:

```bash
# ~/.config/kpm/templates/ai.template
ANTHROPIC_API_KEY=${kms:llm/anthropic}
OPENAI_API_KEY=${kms:llm/openai}
GOOGLE_API_KEY=${kms:llm/google}
GITHUB_TOKEN=${kms:github/pat}
```

Then add to your `~/.zshrc`:

```bash
eval $(kpm env --from ~/.config/kpm/templates/ai.template --output shell)
```

Your shell always has the encrypted versions. When you run an AI:

```bash
kpm run -- claude "help me debug this"
kpm run -- cursor
kpm run -- aider --model gpt-4
```

For high-value secrets (production infra, payment APIs), use `--secure` with a per-tool allow-list. For the highest-value secrets, use `--strict` and let AgentKMS policy decide per-operation.

## Why this matters now

The shape of the development workflow is changing fast. Three years ago, the question "what can read my environment?" had a small answer: my shell, my editor, and whatever I explicitly ran. Today, my editor is running an LLM that's spawning subprocesses that are spawning more subprocesses, and each one inherits what came before. The blast radius of `export SECRET=...` has grown quietly and enormously.

The mitigation isn't to stop using AI tools. They're too useful. The mitigation is to re-architect how secrets reach processes so that scope actually means something. Ciphertext in the shell environment. JIT decrypt at the moment of use. Per-tool allow-lists for sensitive secrets. Server-side policy for the most sensitive ones. Audit trails for everything.

This is why KPM exists. The old model (env vars are secrets) was showing its age five years ago. AI coding tools have made the failure mode concrete and unavoidable: a process that reads your whole environment and spawns processes that inherit it is no longer an edge case. It's the default developer workflow.

You can keep using environment variables. You just can't let the values in them be real.

## Try it

```bash
curl -sL kpm.catalyst9.ai/install | bash
kpm quickstart
eval $(kpm shell-init)

# Add your provider keys
kpm add llm/anthropic
kpm add llm/openai

# Run your AI tools through kpm
kpm run -- claude "hello"
kpm run --secure -- cursor
```

Repo: [github.com/TheGenXCoder/kpm](https://github.com/TheGenXCoder/kpm)

---

That's the four-part series. If you want to go deeper, the threat model is in [SECURITY.md](https://github.com/TheGenXCoder/kpm/blob/main/SECURITY.md) and the contributing guide (with the list of security-sensitive areas where extra-careful review applies) is in [CONTRIBUTING.md](https://github.com/TheGenXCoder/kpm/blob/main/CONTRIBUTING.md).
