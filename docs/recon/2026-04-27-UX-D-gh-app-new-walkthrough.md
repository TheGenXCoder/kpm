# UX-D: `kpm gh-app new` Interactive Walkthrough

**Date:** 2026-04-27
**Status:** Implemented, tests passing

---

## Files Modified

| File | Action | Purpose |
|------|--------|---------|
| `kpm/internal/kpm/ghapp.go` | Extended | Added `RunGhAppNew`, `GhAppNewDeps`, helper functions |
| `kpm/internal/kpm/ghapp_test.go` | Created | 6 tests covering all specified scenarios |

`cmd/kpm/main.go` required **no changes** — the existing `gh-app` early dispatch block routes `os.Args[2:]` directly into `RunGhApp`, which already calls `RunGhAppNew` for the `new` subcase.

---

## Design Decisions

### Dependency injection via `GhAppNewDeps`

All I/O side-effects are injectable:

```go
type GhAppNewDeps struct {
    Stdin           io.Reader
    OpenBrowser     func(url string) error
    GlobPEM         func(pattern string) ([]string, error)
    GitHubTransport http.RoundTripper
}
```

Production callers pass `nil`; `defaultDeps(nil)` fills in `os.Stdin`, the OS browser launcher, `filepath.Glob`, and `http.DefaultTransport`. Tests inject stubs without spawning real processes or hitting real URLs.

### No external dependencies

The GitHub App JWT is minted entirely with stdlib:
- `crypto/rsa` + `crypto/sha256` for RS256 signing
- `encoding/base64` (RawURLEncoding) for JWS segments
- `encoding/pem` + `crypto/x509` for PKCS#1 and PKCS#8 key parsing
- `net/http` for the token mint POST

No `golang-jwt/jwt` or similar package added.

### Verification flow

1. Parse the PEM → `rsa.PrivateKey`
2. Mint a GitHub App JWT (iat = now-60s, exp = iat+600s, iss = appID)
3. POST `https://api.github.com/app/installations/{installationID}/access_tokens`
4. On 2xx: log permissions, discard token, proceed to register
5. On error: surface message, offer re-prompt loop for App ID + Installation ID
6. On user decline: save inputs to `/tmp/agentkms-gh-app-<name>.json` and print retry hint

### Backward compatibility

`kpm gh-app register` (UX-B) is entirely unchanged. The `new` subcommand is a separate case in the `RunGhApp` switch.

---

## Tests Added (`ghapp_test.go`)

| Test | What it verifies |
|------|-----------------|
| `TestGhAppNew_FullFlow` | Happy path end-to-end: browser opens, prompts answered, single PEM match, verification succeeds (201), `RegisterGithubApp` called with correct App ID / Installation ID / PEM, stdout contains `ready` line |
| `TestGhAppNew_AppIDValidation` | Non-numeric, zero, and negative App IDs each trigger a re-prompt; final valid value is stored |
| `TestGhAppNew_PEMAutoDetect_NoMatches` | Empty glob → "No .private-key.pem files found" message → explicit path prompt → PEM read correctly |
| `TestGhAppNew_PEMAutoDetect_MultipleMatches` | Two-file glob → numbered list shown → user picks index 2 → correct PEM (matching key2) stored |
| `TestGhAppNew_VerificationFails_DoesNotStore` | GitHub returns 401 → error surfaced → user declines re-entry → exit non-zero → `/github-apps` POST never fired |
| `TestGhAppNew_BrowserOpenFailure_NotFatal` | `OpenBrowser` returns error → fallback message printed → flow continues → exit 0 |

All tests use `httptest.Server` with a `rewriteTransport` that rewrites the GitHub API URL host to the test server, so no real network access occurs.

---

## Sample Session Transcript

```
$ kpm gh-app new agentkms-blog-audit-rotator --homepage https://blog.catalyst9.ai

==> Step 1 of 5: open the GitHub App creation page

  Opening https://github.com/settings/apps/new ...

  (or paste this URL into a browser if it didn't open automatically)

==> Step 2 of 5: fill the form

  Name:                 agentkms-blog-audit-rotator
                        (copy-paste the name above into the "GitHub App name" field)

  Homepage URL:         https://blog.catalyst9.ai
                        (anything works — GitHub doesn't validate)

  Webhook → Active:     UNCHECK
                        (no webhooks needed for rotation)

  Permissions → Repository:
    Secrets:            Read and write    (REQUIRED)
    Actions:            Read and write    (recommended; enables verification)

  Where can this be installed?
                        Only on this account

  Click "Create GitHub App" at the bottom.

  Press Enter when the App is created and you're on the App settings
  page (you'll see "App ID" near the top of the page)...
[Enter]

==> Step 3 of 5: capture the App ID

  The App ID is shown near the top of the App settings page,
  labeled "App ID:" — it's a numeric value, typically 6-7 digits.

  Paste the App ID: 3512662

==> Step 4 of 5: generate and capture the private key

  Still on the App settings page, scroll down to "Private keys" and
  click "Generate a private key". A .pem file will download
  automatically (one-time download).

  We'll auto-detect it from your Downloads folder. If you saved it
  elsewhere, you can specify the path manually.

  Press Enter when the .pem file has finished downloading...
[Enter]

  Found: /Users/bert/Downloads/agentkms-blog-audit-rotator.2026-04-27.private-key.pem
  Use this file? [Y/n]: y

==> Step 5 of 5: install the App on a repository

  In the App settings page sidebar, click "Install App".

  Click "Install" next to your account, then "Only select repositories"
  and pick the repo this App should rotate credentials for.

  After installation, you'll be redirected to:

    https://github.com/settings/installations/<INSTALLATION_ID>

  The Installation ID is the last segment of that URL.

  Paste the Installation ID: 127321567

==> Verifying credentials...

  Token minted (App ID 3512662, install 127321567)
  Permissions: secrets=write, actions=write, metadata=read

==> Registering with AgentKMS

  Registered "agentkms-blog-audit-rotator"
    App ID:           3512662
    Installation ID:  127321567
    Private key:      stored (encrypted at rest)

==> Done. Next step:

    kpm cred register <binding-name> \
      --github-app agentkms-blog-audit-rotator \
      --target <owner>/<repo>:<SECRET_NAME>

ready app=agentkms-blog-audit-rotator app_id=3512662 installation_id=127321567
```

---

## Test Output

```
=== RUN   TestGhAppNew_FullFlow
--- PASS: TestGhAppNew_FullFlow (0.09s)
=== RUN   TestGhAppNew_AppIDValidation
--- PASS: TestGhAppNew_AppIDValidation (0.01s)
=== RUN   TestGhAppNew_PEMAutoDetect_NoMatches
--- PASS: TestGhAppNew_PEMAutoDetect_NoMatches (0.08s)
=== RUN   TestGhAppNew_PEMAutoDetect_MultipleMatches
--- PASS: TestGhAppNew_PEMAutoDetect_MultipleMatches (0.07s)
=== RUN   TestGhAppNew_VerificationFails_DoesNotStore
--- PASS: TestGhAppNew_VerificationFails_DoesNotStore (0.15s)
=== RUN   TestGhAppNew_BrowserOpenFailure_NotFatal
--- PASS: TestGhAppNew_BrowserOpenFailure_NotFatal (0.15s)
PASS
ok  github.com/TheGenXCoder/kpm/internal/kpm  0.868s

go build ./...  clean
go vet ./...    clean
go test ./...   all packages PASS
```

---

## Validation Checklist

- [x] `go build ./...` clean
- [x] `go vet ./...` clean
- [x] `go test ./...` all pass (including pre-existing tests)
- [x] `kpm gh-app --help` lists `new` subcommand
- [x] `kpm gh-app register` (UX-B) unmodified and still passing
- [x] No new external dependencies (`go.mod` unchanged)
- [x] No real GitHub API calls in tests
- [x] Browser failure is non-fatal
- [x] Invalid App ID / Installation ID re-prompts without storing
- [x] 401 from GitHub does not call RegisterGithubApp
- [x] Inputs saved to `/tmp/agentkms-gh-app-<name>.json` on failure for retry
