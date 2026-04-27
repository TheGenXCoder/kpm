# UX-C: First-class --github-app and --target flags for `kpm cred register`

**Date:** 2026-04-27
**Status:** Complete

---

## Objective

Reduce the most common credential-registration command from:

```bash
kpm cred register blog-audit \
  --provider github-pat \
  --provider-params '{"app_name":"blog-audit"}' \
  --destination "github-secret:TheGenXCoder/blog:CODE_REPO_READ_PAT:{\"writer_token\":\"...\"}" \
  --ttl 3600 \
  --manual-only=false \
  --scope generic
```

to:

```bash
kpm cred register blog-audit \
  --github-app agentkms-blog-audit-rotator \
  --target TheGenXCoder/blog:CODE_REPO_READ_PAT
```

---

## Files Modified

| File | Change |
|------|--------|
| `internal/kpm/cred.go` | Added `--github-app` and `--target` flag handling to `runCredRegister`; updated `credUsage` string |
| `internal/kpm/cred_test.go` | Added 9 new test functions covering all new flag behaviours |
| `docs/recon/2026-04-27-UX-C-first-class-flags.md` | This file (new) |

No other files were touched. AgentKMS and agentkms-pro were not modified.

---

## Implementation Details

### Pre-extraction pattern

`--target` follows the same pre-extraction approach already used for `--destination`: values are collected before `flag.Parse` so the flag can appear multiple times. This is necessary because Go's `flag.FlagSet` does not support repeated flags natively.

### `--github-app <name>` flag

Sets `--provider github-pat` and `--provider-params {"app_name":"<name>"}` internally.

Errors if `--provider` or `--provider-params` is also supplied (mutual exclusion enforced before applying defaults).

When active, defaults `--ttl` to `3600` (matching GitHub installation token TTL) unless the caller explicitly sets `--ttl`.

### `--target <kind>:<location>:<name>` flag

Sugar for `--destination <kind>:<location>:<name>` with no inline params. Writer tokens are self-bootstrapped by the orchestrator (UX-A) and must not appear in the binding.

Multiple `--target` flags are supported. `--target` and `--destination` may coexist; both contribute to the destination list.

### TTL sentinel

`--ttl` default changed from `0` to `-1` (sentinel meaning "caller did not set"). This lets `--github-app` detect whether to apply its 3600 default. After sugar expansion the sentinel is resolved to `0` for the non-github-app path, preserving backward compatibility.

### Backward compatibility

All existing low-level flags (`--provider`, `--provider-params`, `--destination`, `--ttl`, `--manual-only`, `--scope`, `--tag`) continue to work exactly as before.

---

## Tests Added

| Test | What it covers |
|------|---------------|
| `TestRunCredRegister_GithubApp_Sugar` | Sugar form produces correct `provider_kind`, `provider_params.app_name`, and default TTL=3600 |
| `TestRunCredRegister_GithubApp_LongFormEquivalence` | Sugar and explicit long-form produce identical bindings |
| `TestRunCredRegister_GithubApp_ConflictsWithProvider` | `--github-app` + `--provider` → error mentioning both flags |
| `TestRunCredRegister_GithubApp_ConflictsWithProviderParams` | `--github-app` + `--provider-params` → error mentioning both flags |
| `TestRunCredRegister_Target_NoParams` | `--target` produces destination with empty `Params` |
| `TestRunCredRegister_Target_Multiple` | Multiple `--target` flags → multiple destinations |
| `TestRunCredRegister_Target_AndDestination` | `--target` + `--destination` together → both destinations present |
| `TestRunCredRegister_GithubApp_DefaultTTL` | No explicit `--ttl` with `--github-app` → TTL=3600 |
| `TestRunCredRegister_GithubApp_ExplicitTTL` | Explicit `--ttl 7200` with `--github-app` overrides the sugar default |

---

## Test Output

```
=== RUN   TestRunCredRegister_GithubApp_Sugar
--- PASS: TestRunCredRegister_GithubApp_Sugar (0.00s)
=== RUN   TestRunCredRegister_GithubApp_LongFormEquivalence
--- PASS: TestRunCredRegister_GithubApp_LongFormEquivalence (0.00s)
=== RUN   TestRunCredRegister_GithubApp_ConflictsWithProvider
--- PASS: TestRunCredRegister_GithubApp_ConflictsWithProvider (0.00s)
=== RUN   TestRunCredRegister_GithubApp_ConflictsWithProviderParams
--- PASS: TestRunCredRegister_GithubApp_ConflictsWithProviderParams (0.00s)
=== RUN   TestRunCredRegister_Target_NoParams
--- PASS: TestRunCredRegister_Target_NoParams (0.00s)
=== RUN   TestRunCredRegister_Target_Multiple
--- PASS: TestRunCredRegister_Target_Multiple (0.00s)
=== RUN   TestRunCredRegister_Target_AndDestination
--- PASS: TestRunCredRegister_Target_AndDestination (0.00s)
=== RUN   TestRunCredRegister_GithubApp_DefaultTTL
--- PASS: TestRunCredRegister_GithubApp_DefaultTTL (0.00s)
=== RUN   TestRunCredRegister_GithubApp_ExplicitTTL
--- PASS: TestRunCredRegister_GithubApp_ExplicitTTL (0.00s)
PASS
ok  	github.com/TheGenXCoder/kpm/internal/kpm	0.374s
```

Full suite: `go test ./...` — all packages pass.

---

## Help Text Snippet

`kpm cred register --help` (flag.FlagSet output):

```
Usage of cred register:
  -github-app string
        GitHub App name; sugar for --provider github-pat --provider-params {"app_name":"<name>"}
  -manual-only
        mark binding as manual-only (default: true) (default true)
  -provider string
        credential provider kind (required unless --github-app is set)
  -provider-params string
        provider-specific parameters as JSON object (conflicts with --github-app)
  -scope string
        scope kind (e.g. llm-session, generic) (default "generic")
  -tag string
        comma-separated tags
  -ttl int
        TTL hint in seconds (-1 = use sugar default; 0 = provider default) (default -1)
```

Note: `--destination` and `--target` are pre-extracted before `flag.Parse` (same pattern as the existing `--destination` handling), so they do not appear in the `flag.FlagSet` usage output. They are documented in `credUsage` (the top-level `kpm cred --help` output) and in this file.

---

## Decisions

- `--github-app` sets `provider_kind=github-pat` (not `github-app-token`). This matches the kind string the GitHub plugin reports per the UX-C spec.
- `--target` intentionally produces `Params: nil` (empty), not an empty map. The server treats both as "no params". This is consistent with UX-A's writer-token self-bootstrap approach.
- The TTL sentinel (`-1`) is an internal implementation detail; callers never see it. External behavior: omitting `--ttl` with `--github-app` gives 3600; omitting it without `--github-app` gives 0 (provider default) — identical to the previous behavior.
