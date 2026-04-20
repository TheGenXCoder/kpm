# When a credential leaks, you know everything in 30 seconds

## The incident that used to take a week

GitHub emails you at 2am: "We found a token matching one of your personal access tokens in a public repository."

Old world. You wake up, stare at the notification, and feel the specific dread of not knowing which token it is, who created it, what it could do, whether someone already used it. You open your GitHub settings. You see eleven active PATs — some yours, some from teammates, some from integrations you set up last year. The names are things like `ci-deploy-2024-jan` and `my-laptop-token`. The scopes are listed but GitHub doesn't tell you which one matched. You start rotating everything. All eleven. You file a ticket. You spend the next four hours trying to figure out which token it was and whether anything actually happened.

The ticket doesn't close for a week, because you're still not sure.

New world: one command, 30 seconds, ticket closed.

The difference is an audit ledger that records every credential issuance from the moment it happens — not when you think to look, not in a log you have to grep, but in a queryable ledger keyed to a hash of the credential itself. When GitHub reports a leak, you hash the leaked token, look it up, and the complete chain of custody is there waiting for you.

## The forensics report

Here's what that command looks like:

```
$ akms forensics inspect ghp_ABCxyz

  Leaked credential found in audit ledger.  ✗ Blast radius: BOUNDED.

  ──────────────────────────────────────────────────────────────────
  Scope:         acmecorp/legacy-tool
                 (1 repo; contents:write + pull_requests:write)
  TTL applied:   8h
  Lifecycle:     issued  2026-04-13 15:20 UTC  (to frank@acmecorp)
                 expired 2026-04-13 23:20 UTC  ← credential already dead
                 leaked  2026-04-16 10:47 UTC  ← reported 63h after expiry

  Usage during live window (8 hours):
    15:22  clone acmecorp/legacy-tool       ✓ expected
    15:47  push branch migration-v3          ✓ expected
    16:31  open PR #47                       ✓ expected

  Post-expiry usage: NONE (credential was dead when leaked)

  ──────────────────────────────────────────────────────────────────
  ✓ Assessment: no damage — credential expired 63h before leak detection.
  ✓ Action required: none. GitHub has already revoked the dead token.
```

Walk through each section, because each one answers a specific panic:

**Blast radius.** The first line tells you scope. One repository. Two permissions. Not `repo:*`. Not admin. You know immediately that even a full compromise of this token couldn't touch anything outside `acmecorp/legacy-tool`, and couldn't touch org settings, secrets, or other repos. The blast radius was bounded at issuance, not invented after the fact.

**Lifecycle.** This is the money shot: `expired 2026-04-13 23:20 UTC — reported 63h after expiry`. The token was dead before anyone knew it was leaked. That gap — between when a credential becomes inert and when it gets detected — is where dynamic secrets pay off. Static PATs live forever; dynamic ones have a death date written into them before they're ever issued.

**Usage timeline.** Three operations, all during the live window, all consistent with the work that was requested. No anomalies. No off-hours access. No unexpected repos touched. Each operation is timestamped and labeled "expected" because AgentKMS evaluated the request against the rule that issued the token and knows what legitimate use looks like.

**Post-expiry usage.** None. The credential expired, GitHub enforced it, and nobody used a dead token against GitHub's API anyway. This line is the final answer to "was there malicious use?" Blank means no.

**Assessment.** No damage. No action required. Ticket closed.

Thirty seconds.

## How it works under the hood

Every time AgentKMS vends a credential, it writes an audit event before the credential leaves the system. That event contains:

- **CredentialUUID** — a stable identifier for this specific issuance, independent of the credential value
- **ProviderTokenHash** — SHA-256 of the actual credential value, so you can look it up by the leaked string without storing the plaintext
- **Scope** — exactly what was granted: which repositories, which permissions, which resource paths
- **CallerID** — who or what requested the credential (user, team, CI job, AI agent session)
- **RuleID** — which policy rule authorized the issuance, so you can find every other credential this rule could produce
- **IssuedAt** and **ExpiresAt** — baked in at issuance, not as advisory fields but as enforcement parameters

When GitHub secret scanning fires, one of two paths triggers the forensics report:

1. **Webhook.** GitHub sends a `secret_scanning_alert` webhook to the AgentKMS endpoint. The webhook payload contains the matched secret. AgentKMS hashes it immediately, queries the audit ledger by `ProviderTokenHash`, and enriches the credential record with a `DetectedAt` timestamp and a `source: github_secret_scanning` tag.

2. **Manual lookup.** You run `akms forensics inspect <token>`. Same hash, same lookup, same output. Useful when you find a token in a place that doesn't send webhooks — a pastebin link, a Slack message, a contractor's repository you discovered on your own.

Either way, the usage timeline comes from correlating GitHub's own audit log against the same `ProviderTokenHash`. GitHub's API exposes audit events per token; AgentKMS fetches them and joins them to the issuance record. You get the complete picture from two sources: what AgentKMS authorized (the issuance), and what GitHub recorded (the usage).

Three timestamps anchor everything: `IssuedAt`, `InvalidatedAt` (either `ExpiresAt` or the moment a manual revocation was recorded), and `DetectedAt`. The gap between `InvalidatedAt` and `DetectedAt` is the answer to the question engineering leadership will ask first: "does this matter?" A positive gap — credential expired before detection — and the answer is no.

## The engineering-manager lens

The same audit data supports a different query: anomaly detection.

The forensics report is a point-in-time view. Anomaly detection is continuous. Some examples of the alerts that come out of the same ledger:

```
⚠ frank@acmecorp — 47 GitHub PATs issued in the last hour (baseline: 3/day)
  Rule: acme/legacy-deploy  — same rule every time
  Opened: 10:14 UTC

⚠ Claude Code session agent-7a2f9 — 4 credential classes requested in session
  (p95 for this agent identity: 2)
  Credentials: github/pat, aws/staging, anthropic/api, slack/webhook

⚠ acme/legacy-deploy rule — first usage from IP 203.0.113.47 (never seen before)
  All prior usage: 10.0.0.0/8 (internal)
```

The first alert catches a credential stuffing loop or a runaway automation. The second catches an AI agent session that has branched into territory it shouldn't have access to — four credential classes where the baseline is two is worth a look even if the policy allowed all four. The third catches a compromised CI job or a stolen developer machine before the first damage is done.

You're not writing these detections from scratch. They fall out of the structured audit events that dynamic issuance already produces. The baseline is learned from historical data. The alerts are thresholds over moving windows. The hard work is having the data; the detections are mostly arithmetic.

## GitHub integration

The webhook flow deserves a closer look because it's where automated response lives.

When GitHub secret scanning finds a token and fires the webhook, AgentKMS does the following in sequence:

1. Hash the leaked credential value
2. Look up the matching audit record
3. Check `InvalidatedAt` — is the credential already dead?

**If already expired:** mark the alert as `auto-closed`, tag the credential record `detected_after_expiry`, send a notification to the team channel. No human escalation needed. This is the common case for short-TTL credentials — they're dead before anyone finds them.

**If still live:** immediately revoke the credential at the provider (a GitHub PAT revocation API call, an AWS key deactivation, whatever the provider supports), set `InvalidatedAt` to now, tag the record `revoked_on_detection`, and escalate to on-call. The window between detection and revocation is the time for the API round-trip. Usually under two seconds.

**If the provider doesn't support programmatic revocation:** emit a high-priority alert with the direct URL to revoke manually, pre-populated with the credential identifier. The human still has to click the button, but they're not hunting for which button.

The integration turns secret scanning from "scary email that starts a week-long investigation" into a signal that closes automatically or escalates with all context attached. Either way, the investigation is already done before you open the ticket.

## The combination that matters

Dynamic secrets and forensics are designed together, and the value compounds.

Dynamic secrets reduce blast radius: short TTLs, narrow scopes, single-use semantics where possible. They don't eliminate leaks — humans still paste things into the wrong places, CI logs still contain things they shouldn't, supply chains still misbehave. What dynamic secrets do is make most leaks irrelevant by the time they're detected.

Forensics eliminates the panic: chain-of-custody from issuance, automated assessment, closed alerts instead of open investigations. It doesn't prevent leaks either. What forensics does is make every leak answerable in 30 seconds instead of a week.

Together: leaks that don't matter, and the evidence to prove they don't matter when you have to explain it to someone who's nervous.

---

**Part 7** covers the plugin model that makes this extensible — how to add a new credential provider, a new audit sink, or a new policy engine without touching the AgentKMS core.
