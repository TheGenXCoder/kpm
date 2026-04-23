# Design: `kpm scan` — process & environment secret scanner

**Date:** 2026-04-23
**Target release:** v0.3.x (minor release after v0.3.1)
**Status:** Approved for implementation

## Motivation

Secrets exposed via process environments are one of the most common — and most invisible — leaks on developer machines and CI runners. Any process running as the same user can read `/proc/<pid>/environ` (Linux) or invoke `ps -E` (macOS) and harvest API keys, tokens, and credentials from every other process that user owns.

KPM already solves this problem (encrypted env + per-tool allow-list via `kpm run --secure`). What it lacks is a tool that **names the problem** with the same clarity as it provides the solution.

`kpm scan shell` is that tool. It runs in one command, produces a dramatic before/after for demos, and doubles as a CI gate.

### Launch angle

- **LinkedIn demo:** 60 seconds from "you have a problem" to "KPM fixes it"
- **CI usage:** exit code 1 when secrets found → runnable as a pre-job check
- **Positioning:** elevates KPM from "secrets manager" to "secrets hygiene tool"

## Command surface

`scan` is a multi-mode dispatcher:

```
kpm scan shell              # scan running processes for exposed secrets (ships in this release)
kpm scan files <path>       # reserved — returns "not yet implemented"
kpm scan logs <path>        # reserved — returns "not yet implemented"
```

Shipping only `shell` now; stubs for `files` and `logs` reserve the surface and advertise roadmap intent without bloating scope.

## `kpm scan shell` — behavior

### Platform support

| OS     | Command                            | Notes                               |
|--------|------------------------------------|-------------------------------------|
| Linux  | `ps -eww -o pid,user,comm,command` with env via `/proc/<pid>/environ` | `ps eww` env column is truncated; reading `/proc` is cleaner and unambiguous |
| macOS  | `ps -E -o pid,user,comm,command=`  | `/proc` is not available on Darwin  |
| Other  | Error with clear message           | BSD/Windows not supported in v1     |

Platform detection via `runtime.GOOS`. On Linux, prefer `/proc/<pid>/environ` over `ps eww` output — it's NUL-delimited and not subject to ps column truncation.

### Scope

Default: **current user's processes only.**

- Linux: `ps -u $UID`
- macOS: `ps -U $(id -u)`

Rationale: matches the realistic attacker model (a local process running as you) and avoids "Permission denied" noise from other users' processes.

`--all-users` flag is **reserved but not implemented** in v1. When implemented, it will require elevation and skip inaccessible processes silently.

### Detection

Two-tier detection model.

#### High-confidence (default)

**Name patterns** (case-insensitive, glob-style):

- `*_KEY`, `*_TOKEN`, `*_SECRET`, `*_PASSWORD`, `*_PASSWD`
- `*_CREDENTIALS`, `*_API_KEY`, `*_ACCESS_KEY`
- `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`
- Explicit deny-list (never flagged): `SSH_AUTH_SOCK`, `GPG_TTY`, `LESSKEY`, `HISTFILE`, `PATH`

**Value patterns** (regex):

| Pattern                       | Vendor        |
|-------------------------------|---------------|
| `^sk-proj-[A-Za-z0-9_-]{20,}` | OpenAI (proj) |
| `^sk-[A-Za-z0-9]{20,}`        | OpenAI        |
| `^sk-ant-[A-Za-z0-9_-]{20,}`  | Anthropic     |
| `^gh[pousr]_[A-Za-z0-9]{36,}` | GitHub        |
| `^xox[baprs]-[A-Za-z0-9-]{10,}` | Slack       |
| `^AKIA[0-9A-Z]{16}$`          | AWS access key ID |
| `^eyJ[A-Za-z0-9_-]{10,}\.`    | JWT (rough)   |
| `-----BEGIN [A-Z ]+PRIVATE KEY-----` | PEM private key |

#### Paranoid (`--paranoid`)

Adds:

- Name patterns: `*PASS*`, `*AUTH*`, `*PRIVATE*`, `DATABASE_URL`, `*_URL` / `*_URI` where value contains `://[^:]+:[^@]+@` (URL with embedded credentials)
- High-entropy detector: Shannon entropy > 4.5 on values ≥ 20 chars, excluding common-word values (base64/hex-looking strings)

Paranoid mode is noisier by design — intended for thorough audits and paid-tier scan depth teasers.

### Output

#### Default (human table, stderr for banner, stdout for rows)

```
⚠  KPM scan: 14 secrets exposed across 6 processes

PID    USER   PROCESS          VARIABLE              PREVIEW
4291   bert   node             OPENAI_API_KEY        sk-proj-••••7f2a (51 chars)
4291   bert   node             GITHUB_TOKEN          ghp_••••9d1e (40 chars)
8821   bert   python           AWS_SECRET_ACCESS_KEY ••••xQ9/ (40 chars)

Any local process running as 'bert' can read these via /proc/<pid>/environ or `ps eww`.
KPM's encrypted env + per-tool allow-list prevents this leak.
  → kpm init    (encrypt your secrets)
  → kpm run     (inject only what each tool needs)
```

When zero secrets found:

```
✓  KPM scan: no exposed secrets found across 47 processes
```

#### `--json`

```json
{
  "scanned_processes": 47,
  "affected_processes": 6,
  "total_findings": 14,
  "mode": "default",
  "findings": [
    {
      "pid": 4291,
      "user": "bert",
      "process": "node",
      "command": "node server.js",
      "variable": "OPENAI_API_KEY",
      "detector": "value:openai-proj",
      "preview": "sk-proj-••••7f2a",
      "value_length": 51
    }
  ]
}
```

#### `--quiet`

No stdout. Exit code only. For CI gates.

### Redaction rules — non-negotiable

The scanner is itself a secret-exposure risk. Values are **never** emitted in full across any output format.

Redaction algorithm:

1. If value matches a known prefix pattern (e.g., `sk-proj-`, `ghp_`, `AKIA`): preserve prefix (up to 8 chars), show `••••`, then last 4 chars, then length.
2. Otherwise: show `••••` + last 4 chars + length.
3. Values under 12 chars: show `••••` + length only (no tail — too risky for short secrets).

Test assertion: the exact full-value string MUST NOT appear anywhere in scanner output. This is a unit-test invariant.

### Exit codes

| Code | Meaning                              |
|------|--------------------------------------|
| 0    | No secrets found                     |
| 1    | Secrets found                        |
| 2    | Execution error (ps failed, unsupported platform, etc.) |

### Flags

| Flag           | Purpose                                                   |
|----------------|-----------------------------------------------------------|
| `--paranoid`   | Expanded detection (more noise, more catches)             |
| `--json`       | JSON output instead of table                              |
| `--quiet`      | Suppress stdout; exit code only                           |
| `--all-users`  | Reserved; returns "not yet implemented" in v1             |
| `--help`, `-h` | Print command help (see Help text section)                |

## Help text

Modeled on `aws sts --help` — detailed, sectioned, example-rich. KPM's current help is brief; this raises the bar for `scan` and sets a template for future commands.

### `kpm scan --help`

```
NAME
    kpm-scan -- Scan for exposed secrets in processes, files, or logs

SYNOPSIS
    kpm scan <mode> [options]

DESCRIPTION
    Detects secrets exposed in common leak vectors. Each mode targets a
    different surface area:

        shell    Scan running processes for secrets in their environment
        files    Scan files for hardcoded secrets (not yet implemented)
        logs     Scan log output for leaked secrets (not yet implemented)

    See `kpm scan <mode> --help` for mode-specific options.

SEE ALSO
    kpm run --secure    Inject only allow-listed secrets into a command
    kpm init            Initialize encrypted secrets storage
```

### `kpm scan shell --help`

```
NAME
    kpm-scan-shell -- Scan running processes for exposed secrets

SYNOPSIS
    kpm scan shell [--paranoid] [--json | --quiet]

DESCRIPTION
    Inspects the environment of every process owned by the current user
    and reports any variables that appear to contain secrets. By default,
    uses high-confidence detectors (known vendor prefixes, standard
    secret-variable naming conventions). Values are always redacted in
    output — only previews and lengths are shown.

    This command is safe to run routinely. It does not modify state. It
    does not transmit any data off the machine. It reads only processes
    owned by the invoking user.

OPTIONS
    --paranoid
        Enable expanded detection rules: broader name patterns (*PASS*,
        *AUTH*, *PRIVATE*), URL-embedded credentials (user:pass@host),
        and high-entropy value heuristics. Produces more findings,
        including false positives. Recommended for periodic audits, not
        CI gates.

    --json
        Output findings as a JSON document instead of a human-readable
        table. Redaction rules still apply. Suitable for piping into
        other tools.

    --quiet
        Suppress all stdout. Only the exit code is set. Intended for CI
        gates where the exit code alone drives the decision.

    --all-users
        (Not yet implemented.) Scan processes owned by all users.
        Requires elevation.

EXIT STATUS
    0    No exposed secrets found.
    1    One or more exposed secrets found.
    2    Execution error (unsupported platform, ps command failed, etc.).

EXAMPLES
    Scan current user's processes:

        kpm scan shell

    Gate a CI job on zero exposed secrets:

        kpm scan shell --quiet || exit 1

    Produce JSON findings for a dashboard:

        kpm scan shell --json | jq '.findings[] | .variable'

    Thorough local audit:

        kpm scan shell --paranoid

SEE ALSO
    kpm run --secure    Inject only allow-listed secrets into a command
    kpm init            Initialize encrypted secrets storage
```

### Help text conventions for future commands

- Sections: `NAME`, `SYNOPSIS`, `DESCRIPTION`, `OPTIONS`, `EXIT STATUS`, `EXAMPLES`, `SEE ALSO`
- Each option: one blank line, then a short paragraph (wrapped to ~72 cols)
- At least 3 `EXAMPLES` that cover the 80% cases
- `SEE ALSO` cross-links related KPM commands

The top-level `kpm --help` stays compact (it's the index). Per-command `--help` goes deep.

## Architecture

### Package layout

```
cmd/kpm/main.go                 # new case: "scan"; dispatches to scan package
internal/scan/
    scan.go                     # package API, dispatcher, shared types
    shell.go                    # `scan shell` orchestration
    process_linux.go            # Linux: enumerate processes, read /proc
    process_darwin.go           # macOS: enumerate via ps -E
    process_stub.go             # other OS: return unsupported error
    detect.go                   # detectors: name-based, value-based, entropy
    detect_patterns.go          # pattern tables (exported for test visibility)
    redact.go                   # redaction (pure function, heavily tested)
    output.go                   # table / JSON formatters
    help.go                     # help text constants
```

Build tags: `//go:build linux` / `//go:build darwin` / `//go:build !linux && !darwin` on the three process files.

### Key interfaces

```go
// Process is what each platform adapter produces.
type Process struct {
    PID     int
    User    string
    Comm    string
    Command string
    Env     map[string]string
}

// ProcessSource abstracts enumeration per platform.
type ProcessSource interface {
    Enumerate(ctx context.Context, opts EnumOpts) ([]Process, error)
}

// Finding is one detected secret.
type Finding struct {
    Process  Process // without Env populated
    Variable string
    Detector string // e.g. "name:api-key", "value:openai-proj", "entropy"
    Value    string // raw — never emitted
}

// Detector inspects (name, value) and returns zero or more findings.
type Detector interface {
    Name() string
    Detect(name, value string) (matched bool, detectorID string)
}
```

### Data flow

1. `main.go` → `scan.Dispatch(args)` → routes on first positional arg
2. `shell.Run(opts)` → calls platform `ProcessSource.Enumerate()`
3. For each process, for each env var, run all enabled detectors
4. Collect findings; drop raw values before passing to output layer
5. Output layer formats with redaction — **never sees raw value**, only preview

**Security invariant:** raw values are discarded at the detection→output boundary. The output formatter physically cannot leak values because it never receives them.

## Testing strategy

### Validation-first

Tests land **before** implementation, per project convention.

### Unit tests

- **`redact_test.go`** — golden table of (input, expected_preview) for every known prefix and the unknown-prefix case. Assert raw never appears.
- **`detect_test.go`** — true-positive and true-negative fixtures for every pattern. Each pattern ships with both.
- **`output_test.go`** — golden files for table and JSON output given a fixed findings slice.

### Integration tests

- **`shell_integration_test.go`** — spawn a subprocess (`sleep 60`) with known env vars (including one fake `sk-...` value), invoke the enumerator against `os.Getpid()`'s children, assert detection + redaction. Clean up the subprocess. Linux + macOS via build tags.

### Platform stub tests

- On unsupported platforms, `kpm scan shell` exits 2 with the message: `kpm scan: unsupported platform: <goos>` and does not crash.

### The non-leak invariant test

One dedicated test that:

1. Spawns a subprocess with env var `LEAK_CANARY=verySecretCanaryValue123456`
2. Runs `kpm scan shell` programmatically, captures all stdout + stderr across all output modes (table, JSON, quiet)
3. Asserts `verySecretCanaryValue123456` appears in **none** of them

This test is the regression guard for the scanner-as-leak-vector risk.

## Blog & demo integration

- Blog Part 8 (forensics beat) can reference `kpm scan shell` as the "find the problem" half of the forensics story — you can't audit what you can't see
- LinkedIn demo: 60-sec screen capture — exposed env → `kpm scan shell` → KPM remediation → clean scan
- README: add `kpm scan shell` to the top-of-file three-command demo

## Non-goals (explicitly out of scope for v1)

- Scanning files on disk (`kpm scan files`) — reserved, not implemented
- Scanning log files (`kpm scan logs`) — reserved, not implemented
- Scanning other users' processes (`--all-users`) — reserved, requires elevation story
- Continuous/background scanning (daemon mode)
- Auto-remediation (taking action on findings)
- Integration with AgentKMS server for centralized scan results
- Windows support (no `/proc`, different process model; revisit if demand appears)

## Rollout

1. Spec approved (this doc)
2. Writing-plans skill produces validation-first implementation plan
3. Subagent dispatch per plan (tests first, impl second, review third)
4. Ship in a point release (v0.3.2 likely — coordinates with next KPM release)
5. LinkedIn post + 60-sec demo video

## Open questions

None remaining at spec stage. Any discovered during implementation → note in plan, not spec.
