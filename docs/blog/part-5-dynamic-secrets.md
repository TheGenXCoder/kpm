# Your AI agent gets 15-minute credentials, not your master key

## The problem with credentials that last forever

Your Anthropic API key doesn't expire. Your AWS access key doesn't expire. Your GitHub PAT doesn't expire — not unless you set it to, and most people don't, because then you have to remember to rotate it.

Long-lived credentials made sense when "using a credential" meant a human opening a terminal, doing a thing, and closing it. The credential was idle 23 hours a day. The risk window was narrow.

That logic breaks when an AI agent is running your credentials.

An AI coding session today isn't one command. It's thirty. The agent reads your code, searches your dependencies, runs tests, checks PR status, maybe makes an API call to verify something. Each one of those is a subprocess that inherits your full credential set. The session might run for an hour, with your real AWS `ACCESS_KEY_ID` sitting in a live environment the whole time.

"Rotating credentials quarterly" doesn't help when the agent can leak them in the first five minutes — into conversation history, into a log file it wrote, into a test fixture it committed, into a `.env.generated` file it thought was transient. The key was real and the agent had it for the full session.

The fix isn't better hygiene. The fix is credentials that are **constitutionally incapable of being useful after the session ends** — because they were minted for this session and expire when it does.

## Dynamic secrets: mint, use, expire

AgentKMS holds one privileged admin credential per provider. That's the thing worth protecting. It never leaves AgentKMS. The agent never sees it.

Instead, when an agent needs access to a resource, AgentKMS mints a **scoped, time-boxed credential** for that specific request:

1. The agent sends a credential request to AgentKMS over MCP.
2. AgentKMS evaluates policy: who is asking, for what, on behalf of which session.
3. AgentKMS calls the upstream provider API and mints a short-lived token scoped to exactly what the policy allows.
4. The agent receives the ephemeral token. It works immediately.
5. The TTL expires. The token is dead — whether the agent leaked it or not.

No rotation ceremony. No cleanup. No "did the agent clear its context window?" concern. The credential self-destructs.

The canonical example is AWS STS. Your admin key lives in AgentKMS. When an agent needs S3 access:

```bash
# What the agent requests
kpm get-credential aws/s3-read-only --ttl 15m

# What AgentKMS returns
AWS_ACCESS_KEY_ID=ASIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_SESSION_TOKEN=AQoDYXdzEJr//////////wEa...
# Expires: 2026-04-16T14:47:23Z (15 minutes from now)
```

The agent gets a real, working AWS session token. It's scoped to one IAM role and one S3 bucket. It's valid for fifteen minutes. Your admin key never left AgentKMS. The agent never had it. When the fifteen minutes are up, the STS token is dead — regardless of where it ended up.

This is the AWS STS model applied uniformly across every provider that supports it. The agent always gets the temporary credential, never the root key.

## GitHub App tokens: the vibe-coding story

GitHub App installation tokens are the best illustration of how this works in practice, because they're already designed for exactly this use case.

A GitHub App is a first-party integration with your GitHub org. It gets permissions you define (read code, write PRs, manage secrets — you pick), scoped to repos you specify. When something needs to act on GitHub on your behalf, it requests an **installation token** from the App. That token inherits the App's scope. It expires in one hour. Hard limit, no extensions.

Here's what that looks like in an AI coding session:

```
Developer: "Fix the failing CI and open a PR"
Claude Code → AgentKMS: I need GitHub access for acmecorp/frontend
AgentKMS: policy check → Claude Code + this user can push to acmecorp/frontend
AgentKMS → GitHub API: mint installation token for acmecorp/frontend, contents:write
AgentKMS → Claude Code: {token: "ghs_abc123...", expires_in: 3600}
Claude Code: creates branch, commits fix, opens PR
(1 hour later) ghs_abc123 is dead
```

The token can only push to `acmecorp/frontend`. Not `acmecorp/infra`. Not `acmecorp/payroll-service`. Not any other repo in the org. The App's permissions are a hard ceiling.

What happens if the token leaks?

```bash
# Agent wrote a debug file with the token in it
$ cat /tmp/debug-claude-session-20260416.log
...
github_token=ghs_abc123efg456hij789klm
...
```

That token expires in an hour. If it leaks into conversation history, it's dead before most monitoring systems would even surface the alert. If it gets committed to a public repo — something GitHub's secret scanning would catch and alert on immediately — it's dead before anyone could use it. You get a notification, you acknowledge it, and you move on. No breach. No incident. No 3 AM rotation.

Compare that to leaking a personal access token with `repo` scope and no expiry. That's an incident.

```bash
# AgentKMS config for GitHub App credentials
kpm policy set github/app-token \
  --consumer claude-code \
  --scope "repo:acmecorp/frontend" \
  --permissions "contents:write,pull_requests:write" \
  --ttl 1h \
  --max-per-session 3
```

The `--max-per-session 3` limit is optional but useful: an agent that mints more than three GitHub tokens in one session is doing something worth reviewing.

## Per-user attribution as a side effect

When every credential is minted on demand, every credential carries a minting identity. That turns out to be useful for reasons unrelated to security.

The Anthropic Admin API lets you create per-user API keys — workspace keys that belong to a specific person in your org. When AgentKMS mints an Anthropic key for a user, it mints their key, not the shared key:

```
Frank starts a Claude Code session
→ AgentKMS mints an Anthropic key with Frank's workspace identity
→ Frank's session uses that key
→ Tokens consumed appear in the Anthropic Console under Frank's entry

Bert starts a Claude Code session
→ AgentKMS mints an Anthropic key with Bert's workspace identity
→ Bert's session uses that key
→ Tokens consumed appear under Bert's entry
```

No manual tracking. No "who left the expensive model running?" archaeology. Your CFO opens the Anthropic Console and sees two rows:

```
Frank Yamamoto   3,847,221 tokens   $2,401.51
Bert Smith       4,967,003 tokens   $3,104.38
```

Bert should probably stop asking the model to write novels.

The same attribution applies to every provider AgentKMS manages. GitHub App tokens minted for Frank carry Frank's identity in the audit log. AWS STS sessions for the CI agent carry the CI agent's identity. When something goes wrong, you don't look at shared credentials and wonder who did what. You look at the minted-for field and you know.

Offboarding is also clean. When Frank leaves:

```bash
kpm identity revoke frank@acmecorp.com --cascade

# What this does:
# 1. Marks the identity as revoked in AgentKMS
# 2. Calls GitHub API to revoke any live tokens minted for Frank
# 3. Calls AWS STS to invalidate any live sessions minted for Frank
# 4. Marks Anthropic workspace key inactive
# 5. Any future mint requests carrying Frank's identity are denied
```

One command. Zero residual access. No "did we get all the PATs?" review. There are no PATs. There are only minted tokens, and minted tokens carry minting identity, and revocation cascades to all of them.

## The MCP interface

None of the above requires wrapper scripts or `eval $(...)` or custom shell functions. AI tools that support MCP (Model Context Protocol) talk to AgentKMS directly:

```json
// Claude Code / Cursor / Codex: ~/.config/mcp/servers.json
{
  "mcpServers": {
    "agentkms": {
      "command": "kpm",
      "args": ["mcp", "serve"],
      "env": {
        "KPM_SERVER": "https://kms.acmecorp.internal"
      }
    }
  }
}
```

That's the full config. The agent discovers the `agentkms` MCP server and gets access to its tools:

- `get_credential(provider, scope, ttl)` — mint and return a short-lived token
- `list_credentials()` — what's live in this session
- `revoke_credential(id)` — kill it early if the task is done
- `audit_log(session_id)` — what did this session access?

When Claude Code needs a GitHub token, it calls `get_credential`. It gets a token. It uses it. It doesn't know or care that the token was minted from a GitHub App installation key that lives in an HSM. It just got a credential that works, scoped to what it needs, for long enough to finish the work.

No shell magic. No wrapper scripts. One MCP config entry that any MCP-compatible tool can use.

Claude Code, Cursor, Codex, and any other editor or agent that speaks MCP uses the same interface. The policy lives in AgentKMS, not in per-tool shell aliases.

## Try it

```bash
# Install KPM
curl -sL kpm.catalyst9.ai/install | bash

# Initialize with dynamic secrets support
kpm init --with-dynamic-secrets

# Configure a GitHub App (you'll need to create the App in GitHub first)
kpm provider add github-app \
  --app-id 12345 \
  --private-key ./path/to/key.pem \
  --installation-id 67890

# Configure AWS STS
kpm provider add aws-sts \
  --role-arn arn:aws:iam::123456789012:role/agent-scoped-role \
  --session-duration 900

# Set policy for Claude Code
kpm policy set \
  --consumer claude-code \
  --provider github-app \
  --scope "repo:your-org/your-repo" \
  --permissions "contents:write,pull_requests:write"

# Add the MCP server to your editor config
kpm mcp install --editor claude-code

# Test it
kpm credential mint github-app --ttl 5m
```

Repo: [github.com/TheGenXCoder/kpm](https://github.com/TheGenXCoder/kpm)

---

**Part 6:** What happens when a credential leaks despite all of this? That's where forensics comes in — audit logs, session replay, and the "blast radius" calculation that tells you exactly what you need to rotate and nothing else.
