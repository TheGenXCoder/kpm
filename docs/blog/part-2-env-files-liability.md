# Your .env files are a liability — even when they never leave your machine

## The false sense of security

Most developers have internalized one rule: **don't commit `.env` files to git.**

It's a good rule. It's also incomplete. Here's a common scenario I've watched play out:

A developer adds `.env` to `.gitignore`. They copy `.env.example` to `.env`, paste in their production database password, and start the server. An hour later, they hit a cryptic error and run `env | grep DATABASE` to debug. Their shell history now has the password. They `ssh` into a server to diff behavior. Their DataDog trace agent, running alongside their app, ingests the environment variables into its process metadata. They `docker ps --format '{{.Command}}'` to check running containers and see the password in the command line of a process they started with `docker run -e`.

The `.env` file never touched git. The password leaked anyway. Nine separate places, depending on which tools they happened to use that afternoon.

This is the problem with environment variables as a secrets mechanism: **they were designed for configuration, not for secrets.** They inherit from parent processes. They're visible to any process running as the same user. They show up in crash dumps, stack traces, logs, and observability pipelines. They leak via `ps`, `proc`, and process dumps.

## What plaintext in memory actually costs you

Here's a working demonstration. This is real; try it yourself.

```bash
# Set an "API key" the normal way
export ANTHROPIC_API_KEY="sk-fake-but-looks-real-for-this-demo"

# Now open another terminal as the same user and run:
ps eww | grep -o 'ANTHROPIC_API_KEY=[^ ]*'
ANTHROPIC_API_KEY=sk-fake-but-looks-real-for-this-demo
```

Any process running as you can read it. That includes:

- Your editor's language server
- Your AI coding assistant's background processes
- Any npm/pip/cargo install postinstall scripts you've ever run
- A browser extension that got compromised last month
- A trojanized `npm install` from a supply-chain attack you haven't heard about yet

None of these need root. None need to touch disk. They can all see your environment.

The usual answer is "well, if those are compromised, you have bigger problems." That answer doesn't age well. "Supply chain compromise" is no longer a hypothetical — it's a regular Monday. The solution isn't to trust those processes. The solution is to structure your secrets so that even a compromised same-user process can't extract them.

## Ciphertext by default

KPM's mode of operation is simple: **the string in your environment variable is not your secret.**

```bash
# In your .bashrc / .zshrc
eval "$(kpm shell-init)"
```

Open a new shell:

```bash
$ env | grep ANTHROPIC
ANTHROPIC_API_KEY=ENC[kpm:s1a2b3c4:SGVsbG8gd29ybGQgdGhpcyBpcyBub3QgYSByZWFsIGtleSBidXQgY2lwaGVydGV4dA==]
KPM_SESSION=s1a2b3c4
KPM_DECRYPT_SOCK=/tmp/kpm-s1a2b3c4.sock
```

The `ANTHROPIC_API_KEY` variable exists, has a reasonable-looking string in it, and would be found by any process that dumps your environment. **None of those processes can decrypt it.**

The ciphertext is AES-256-GCM with a session-specific key. That key lives only in the background listener process that KPM started when you ran `shell-init`. The listener is bound to a Unix domain socket with `0600` permissions, accessible only from processes running as your UID on the same machine — but even among those, only the one that holds the `KPM_DECRYPT_SOCK` path can connect.

## The just-in-time decrypt

When you actually need the real value, you use `kpm run`:

```bash
$ kpm run -- claude "add a contact form to the landing page"
```

Here's what happens:

1. KPM scans the environment of the `run` process (the shell it was invoked from) for `ENC[kpm:...]` blobs.
2. For each blob, it opens the UDS socket and requests decryption.
3. The listener decrypts the blob in its memory, writes the plaintext to the socket, then zeros its copy.
4. KPM reads the plaintext from the socket and builds a clean env map for the child.
5. KPM execs the child process (`claude`) with the clean env.
6. When the child exits, KPM closes the socket.

Claude sees a real `ANTHROPIC_API_KEY`. Your shell never did. The plaintext existed for microseconds, in a process that's gone as soon as the tool completes.

If someone dumps your shell's environment during this entire transaction — before, during, or after — they get ciphertext. The attack surface is the child process itself, for the exact duration of its work.

That's not zero. But it's a dramatically smaller surface than "anything running as me at any time."

## The "that's too convenient" check

I've watched this demo enough times to know the first question: "So KPM is just running a decrypt listener as me. What stops the malware from just asking the listener to decrypt?"

Three things:

1. **The socket is UID-scoped.** `kernel.SO_PEERCRED` checks mean only processes with your UID can even connect. That's not perfect — if your shell is compromised, same-UID processes can connect. But it means the attacker has to already be running on your machine, as you. That raises the bar meaningfully above "I read your environment."

2. **The session has a TTL.** By default 1 hour. The listener refuses decrypts after that. Steal the socket path, wait a day, no more decryption. You need the listener to still be alive, which means you need persistent access.

3. **The harder mode exists.** `kpm run --strict` doesn't hold a session key at all. Every decrypt request goes over mTLS to AgentKMS, gets individually audited, and can be denied in real time by server-side policy. For truly sensitive secrets, you can configure the listener to refuse local-only decrypts and always round-trip.

The default mode isn't "impenetrable." It's "meaningfully harder than plaintext env vars with a clearly better story for the threat models most people actually face." For the subset of secrets where "meaningfully harder" isn't enough, the strict mode is a flag away.

## What this looks like on camera

I built a demo app called `mock-codex` that mimics a real AI coding tool — it reads `ANTHROPIC_API_KEY` from the environment and pretends to call the API. It's useful because it won't cost you tokens and its behavior is predictable.

```bash
# Load the encrypted env
$ eval "$(kpm shell-init)"

# Your env has ciphertext
$ echo $ANTHROPIC_API_KEY
ENC[kpm:s1a2b3c4:SGVsbG8gd29ybGQgdGhpcyBpc24ndCBwbGFp...]

# Try to use the tool directly — it detects the ciphertext and refuses
$ mock-codex "fix the bug"
mock-codex v0.1 — AI coding assistant (demo)

Provider: Anthropic (key: ENC[...w==])

WARNING: API key is still encrypted (ENC[kpm:...]).
Run this tool with: kpm run -- mock-codex "your prompt"

# Run it through kpm
$ kpm run -- mock-codex "fix the bug"
mock-codex v0.1 — AI coding assistant (demo)

Provider: Anthropic (key: sk-d...ting)
Prompt: "fix the bug"

Connecting to API...
Response: The code looks good. Ship it.

# Back in your shell — still ciphertext
$ echo $ANTHROPIC_API_KEY
ENC[kpm:s1a2b3c4:SGVsbG8gd29ybGQgdGhpcyBpc24ndCBwbGFp...]
```

The shell never had the key. The tool got it for the duration of its work. When the tool exits, the plaintext is gone.

## What about `kpm env --plaintext`?

There's an escape hatch. If you need plaintext — for scripts that can't use `kpm run`, for legacy tools, for debugging — you pass `--plaintext`:

```bash
$ eval $(kpm env --from template --output shell --plaintext)
$ echo $ANTHROPIC_API_KEY
sk-ant-real-value-here
```

This is the old dangerous mode: plaintext env vars, all the risks we've described. It exists because you will occasionally need it. It's an explicit opt-in. The default — the thing your muscle memory learns — is ciphertext.

## Testing it at rest

I don't trust my own work unless I can prove it. The KPM test suite includes **adversarial fuzz tests** specifically for this:

- Write a secret with a known value (say, `sk-test-ADVERSARIAL-MARKER-abc123`).
- Run every read endpoint: `kpm list`, `kpm describe`, `kpm history`, `kpm show`, `kpm list --json`.
- Grep the output of every endpoint for the marker.
- Assert zero occurrences.

If any endpoint ever leaks a value, that test fails. As of v0.1.0, all endpoints pass. The test suite runs in CI and in our release gate. You can run it yourself against a fresh Docker container:

```bash
curl -sL https://raw.githubusercontent.com/TheGenXCoder/kpm/main/tests/run-tests.sh | bash
```

37 tests + 6 explicit security checks, 0 value leaks.

## The mental model

Think of it this way: the old model was "environment variables are secrets." The new model is "environment variables are *pointers to secrets.*" The pointer is safe to leak. Dereferencing the pointer requires a capability (the UDS socket, the session key) that lives in a constrained process. You dereference only at the moment of use, and only for the process that needs it.

This isn't novel cryptography. It's just applying a pattern (capabilities, least privilege, JIT) that security engineering has used for decades, to the ubiquitous-but-quietly-terrible practice of pasting secrets into environment variables.

## Try it

```bash
curl -sL kpm.catalyst9.ai/install | bash
kpm quickstart
kpm add test/demo
eval "$(kpm shell-init)"
echo $ANTHROPIC_API_KEY  # ciphertext
kpm run -- your-tool     # decrypts for that tool
```

Repo: [github.com/TheGenXCoder/kpm](https://github.com/TheGenXCoder/kpm)

---

**Part 3:** how I manage twelve client projects with one template tree, zero `.env` file shuffling, and automatic context switching via profile variables.
