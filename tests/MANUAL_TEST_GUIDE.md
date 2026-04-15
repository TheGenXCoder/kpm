# KPM v0.1.0 — Manual Test Guide

**Requirements:** Docker installed, internet access
**Time:** ~15 minutes
**Skill level:** Basic command line

## Setup

Start a fresh container. Nothing touches your machine.

```bash
docker run -it --rm archlinux:latest
```

You should see a root prompt. Install dependencies:

```bash
pacman -Sy --noconfirm go git curl
```

Install KPM:

```bash
curl -sL https://raw.githubusercontent.com/TheGenXCoder/kpm/main/scripts/install.sh | bash
```

**Verify:** You should see `==> Installed: kpm dev`

Run quickstart (sets up a local server, generates certs, seeds demo data):

```bash
kpm quickstart
```

**Verify:** You should see `KPM quickstart complete!` and a server PID.

Wait 2 seconds for the server to fully start:

```bash
sleep 2
```

---

## Test 1: Add a secret (interactive)

```bash
kpm add cloudflare/dns-token --tags dns,ci --description "My DNS token" --type api-token
```

It will prompt `Value:` with no echo (your typing is hidden). Type any value and press Enter.

**Expected:** `Stored cloudflare/dns-token v1 (tagged: dns, ci) [api-token]`

- [ ] PASS / FAIL

---

## Test 2: Add a secret (pipe — no typing)

```bash
echo "sk-test-anthropic-key" | kpm add anthropic/api-key --tags dev,ci
```

**Expected:** `Stored anthropic/api-key v1 (tagged: dev, ci) [api-token]`

Note: it auto-detected `api-token` from the `sk-` prefix.

- [ ] PASS / FAIL

---

## Test 3: Add a secret from a file

```bash
echo "-----BEGIN OPENSSH PRIVATE KEY-----
test-key-data
-----END OPENSSH PRIVATE KEY-----" > /tmp/test-key

kpm add ssh/deploy-key --from-file /tmp/test-key --description "Deploy key"
```

**Expected:** `Stored ssh/deploy-key v1 [ssh-key]`

Note: it auto-detected `ssh-key` from the file content.

- [ ] PASS / FAIL

---

## Test 4: List all secrets

```bash
kpm list
```

**Expected:** You should see 3 secrets grouped by service (anthropic, cloudflare, ssh), with types, tags, and descriptions. **You should NOT see any secret values.**

- [ ] PASS / FAIL
- [ ] Confirm: no secret values visible (no `sk-test`, no `PRIVATE KEY`, no token values)

---

## Test 5: List filtered by tag

```bash
kpm list --tag ci
```

**Expected:** Only secrets tagged `ci` appear (cloudflare/dns-token and anthropic/api-key). SSH key should NOT appear.

- [ ] PASS / FAIL

---

## Test 6: Describe a secret

```bash
kpm describe cloudflare/dns-token
```

**Expected:** Shows Type, Tags, Description, Created, Updated, Version. **No secret value shown.**

- [ ] PASS / FAIL
- [ ] Confirm: no secret value visible

---

## Test 7: View version history

```bash
kpm history cloudflare/dns-token
```

**Expected:** Shows `v1` with timestamp and `(current)`. **No secret value shown.**

- [ ] PASS / FAIL

---

## Test 8: Retrieve a secret value

```bash
kpm get cloudflare/dns-token
```

**Expected:** Prints the actual secret value you entered in Test 1.

- [ ] PASS / FAIL

---

## Test 9: Remove a secret

```bash
kpm remove anthropic/api-key
```

It will prompt for confirmation. Type `y` and press Enter.

**Expected:** `Removed anthropic/api-key`

- [ ] PASS / FAIL

---

## Test 10: Verify removal

```bash
kpm list
```

**Expected:** anthropic/api-key is gone. Only 2 secrets remain.

- [ ] PASS / FAIL

---

## Test 11: Show deleted secrets

```bash
kpm list --include-deleted
```

**Expected:** anthropic/api-key reappears, marked `DELETED`.

- [ ] PASS / FAIL

---

## Test 12: Template hierarchy

```bash
kpm tree
```

**Expected:** Shows template levels (User, Project) with template files and which secrets they reference. **No secret values shown.**

- [ ] PASS / FAIL

---

## Test 13: Encrypted env (secure default)

```bash
kpm env --from ~/.kpm/templates/shell-env.template
```

**Expected:** Output shows `ENC[kpm:...]` ciphertext blobs, NOT plaintext values. This is the secure default.

- [ ] PASS / FAIL
- [ ] Confirm: output is ciphertext, not readable values

---

## Test 14: Load ciphertext into your shell

```bash
eval $(kpm env --from ~/.kpm/templates/shell-env.template --output shell)
```

Now check what's in your environment:

```bash
echo $ANTHROPIC_API_KEY
```

**Expected:** Shows `ENC[kpm:...]` ciphertext. NOT a real API key.

- [ ] PASS / FAIL

---

## Test 15: Inspect managed secrets

```bash
kpm show
```

**Expected:** Shows session info, lists managed env vars as `encrypted`. **No values shown.**

- [ ] PASS / FAIL

---

## Test 16: JIT decrypt for a tool

```bash
kpm run -- sh -c 'echo "The app sees: $ANTHROPIC_API_KEY"'
```

**Expected:** The child process prints the ACTUAL value (decrypted), not ciphertext. Your shell still has ciphertext.

Verify your shell still has ciphertext:

```bash
echo $ANTHROPIC_API_KEY
```

**Expected:** Still `ENC[kpm:...]`.

- [ ] PASS / FAIL

---

## Test 17: mock-codex without kpm run (should fail)

```bash
mock-codex "fix the auth bug"
```

**Expected:** Fails with a warning that the API key is still encrypted. Suggests using `kpm run`.

- [ ] PASS / FAIL

---

## Test 18: mock-codex with kpm run (should work)

```bash
kpm run -- mock-codex "fix the auth bug"
```

**Expected:** mock-codex runs successfully, shows `Provider: Anthropic (key: sk-d...ting)` and `Response: The code looks good. Ship it.`

- [ ] PASS / FAIL

---

## Test 19: JSON output

```bash
kpm list --json
```

**Expected:** Well-formatted JSON array with service, name, type, tags, version fields. **No secret values.**

- [ ] PASS / FAIL
- [ ] Confirm: no secret values in JSON output

---

## Test 20: Help text

```bash
kpm --help
```

**Expected:** Clean help with all commands listed, global flags, and examples at the bottom.

- [ ] PASS / FAIL

---

## Security Summary

Review your answers above. These are the critical security checks:

| Check | Test(s) | Question |
|-------|---------|----------|
| List never shows values | 4, 5 | Did you see any secret values in list output? |
| Describe never shows values | 6 | Did you see the actual secret in describe? |
| History never shows values | 7 | Did you see the actual secret in history? |
| Env is ciphertext by default | 13, 14 | Was the output encrypted, not plaintext? |
| Show never shows values | 15 | Did kpm show display any real values? |
| JIT decrypt only for child | 16 | Did the child get plaintext while your shell kept ciphertext? |
| JSON never shows values | 19 | Did the JSON contain any secret values? |

**If ANY of these checks failed, stop and report it.**

---

## Results

```
Total tests: 20
PASS: ___
FAIL: ___

Tester name: ___________________
Date: ___________________
Notes: ___________________
```

---

## Cleanup

Just type `exit` to leave the container. It's destroyed automatically (`--rm` flag). Nothing was installed on your machine.
