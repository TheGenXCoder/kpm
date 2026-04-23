# Design: `kpm scan` — secrets scanner across processes, files, and logs

**Date:** 2026-04-23
**Target release:** v0.3.x (minor release after v0.3.1)
**Status:** Approved for implementation

## Motivation

Secrets leak in three high-frequency places on developer and CI systems:

1. **Process environments** — any local process running as you can read every other of your processes' env vars via `/proc/<pid>/environ` (Linux) or `ps -E` (macOS).
2. **Source files** — hardcoded API keys, tokens, and passwords committed into code, config, or fixtures.
3. **Logs** — stack traces, debug output, and error messages that print credentials verbatim into log files or CI output.

KPM already solves the first problem at the *prevention* layer (encrypted env + per-tool allow-list via `kpm run --secure`). What it lacks is a tool that **names the problem** with the same clarity as it provides the solution — and does so across all three leak surfaces, not just one.

`kpm scan` is that tool. One command, three modes, shared detection engine. Exits non-zero on findings so it's CI-gate ready. Values are always redacted so the scanner itself is not a leak vector.

### Launch angle

Three distinct demo stories against a unified codebase:

| Mode    | Audience             | Pitch                                                           |
|---------|----------------------|-----------------------------------------------------------------|
| `shell` | Developers           | "Every process you run leaks its env to every other of your processes." |
| `files` | Code reviewers, SRE  | "Before you review that PR, run `kpm scan files` — 30 seconds, zero hardcoded secrets checked."  |
| `logs`  | DevOps, incident response | "`tail -f app.log \| kpm scan logs` — catch leaks in real time."  |

Staggered LinkedIn release (one per mode across a week) keeps the narrative in feed without one-shotting the content.

## Command surface

`scan` is a multi-mode dispatcher. All three modes ship in this release.

```
kpm scan shell                   # scan running processes for exposed env secrets
kpm scan files [path...]         # scan files on disk for hardcoded secrets
kpm scan logs [path]             # scan a log file or stdin for leaked secrets
```

## Shared behavior (across all modes)

### Detection engine

Two-tier detection, identical across modes.

#### High-confidence (default)

**Name patterns** (case-insensitive; only applied where a "name" is extractable — env vars, `KEY=VALUE` lines, structured logs):

- `*_KEY`, `*_TOKEN`, `*_SECRET`, `*_PASSWORD`, `*_PASSWD`
- `*_CREDENTIALS`, `*_API_KEY`, `*_ACCESS_KEY`
- `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`
- Explicit deny-list (never flagged): `SSH_AUTH_SOCK`, `GPG_TTY`, `LESSKEY`, `HISTFILE`, `PATH`

**Value patterns** (regex; applied everywhere):

| Pattern                          | Vendor        |
|----------------------------------|---------------|
| `^sk-proj-[A-Za-z0-9_-]{20,}`    | OpenAI (proj) |
| `^sk-[A-Za-z0-9]{20,}`           | OpenAI        |
| `^sk-ant-[A-Za-z0-9_-]{20,}`     | Anthropic     |
| `^gh[pousr]_[A-Za-z0-9]{36,}`    | GitHub        |
| `^xox[baprs]-[A-Za-z0-9-]{10,}`  | Slack         |
| `^AKIA[0-9A-Z]{16}$`             | AWS access key ID |
| `^eyJ[A-Za-z0-9_-]{10,}\.`       | JWT (rough)   |
| `-----BEGIN [A-Z ]+PRIVATE KEY-----` | PEM private key |

#### Paranoid (`--paranoid`)

Adds:

- Name patterns: `*PASS*`, `*AUTH*`, `*PRIVATE*`, `DATABASE_URL`, `*_URL` / `*_URI` where value contains `://[^:]+:[^@]+@`
- High-entropy detector: Shannon entropy > 4.5 on values ≥ 20 chars, excluding common-word values (base64/hex-looking strings)

Paranoid is noisier by design. Good for audits; not recommended for CI gates.

### Redaction rules — non-negotiable

The scanner is itself a secret-exposure risk. Values are **never** emitted in full across any output format, any mode.

Redaction algorithm:

1. If value matches a known prefix pattern (e.g., `sk-proj-`, `ghp_`, `AKIA`): preserve prefix (up to 8 chars), show `••••`, then last 4 chars, then length.
2. Otherwise: show `••••` + last 4 chars + length.
3. Values under 12 chars: show `••••` + length only (no tail).

**Invariant:** the exact full-value string MUST NOT appear anywhere in scanner output. Enforced by a dedicated regression test (see Testing).

### Exit codes

| Code | Meaning                              |
|------|--------------------------------------|
| 0    | No secrets found                     |
| 1    | Secrets found                        |
| 2    | Execution error (unsupported platform, I/O failure, etc.) |

### Shared flags

| Flag           | Purpose                                                   |
|----------------|-----------------------------------------------------------|
| `--paranoid`   | Expanded detection (more noise, more catches)             |
| `--json`       | JSON output instead of table                              |
| `--quiet`      | Suppress stdout; exit code only                           |
| `--help`, `-h` | Print command help                                        |

## `kpm scan shell` — mode-specific behavior

### Platform support

| OS     | Source                              | Notes                               |
|--------|-------------------------------------|-------------------------------------|
| Linux  | `/proc/<pid>/environ`               | NUL-delimited, not subject to `ps` column truncation |
| macOS  | `ps -E -o pid,user,comm,command=`   | `/proc` is not available on Darwin  |
| Other  | Error; exit 2                       | BSD/Windows not supported in v1     |

Platform detection via `runtime.GOOS`.

### Scope

Default: **current user's processes only** (Linux: `ps -u $UID`; macOS: `ps -U $(id -u)`). Matches the realistic attacker model and avoids `Permission denied` noise.

`--all-users` is reserved; returns "not yet implemented" in v1.

### Output columns

`PID`, `USER`, `PROCESS`, `VARIABLE`, `PREVIEW`

### Example output

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

## `kpm scan files` — mode-specific behavior

### Scope

Default path: `.` (cwd). Multiple paths accepted: `kpm scan files ./src ./config`.

Default behavior:

- **Recurse** into directories
- **Respect `.gitignore`** if present (single-level at scan root; no parent/nested gitignore parsing — keep it simple)
- **Skip binaries** via NUL-byte detection in first 8KB
- Detect both **name patterns** (on `KEY=VALUE`, `key: value`, `"key": "value"` style lines) **and** **value patterns**

### Flags specific to `files`

| Flag                | Purpose                                                   |
|---------------------|-----------------------------------------------------------|
| `--recurse`         | Explicit recursion (default; no-op — present for CI clarity) |
| `--no-recurse`      | Scan only the specified directory level, don't descend    |
| `--max-depth <n>`   | Cap recursion depth (useful for monorepos)                |
| `--no-gitignore`    | Ignore `.gitignore` and scan everything                   |
| `--include-binary`  | Don't skip binary files                                   |
| `--exclude <glob>`  | Exclude paths matching glob (repeatable)                  |

### Output columns

`FILE`, `LINE`, `VARIABLE`, `PREVIEW`

When detection is value-only (no name on that line): `VARIABLE` column shows `-`.

### Example output

```
⚠  KPM scan: 3 secrets found across 2 files

FILE                    LINE  VARIABLE         PREVIEW
config/local.yaml       14    api_key          sk-proj-••••7f2a (51 chars)
config/local.yaml       17    slack_webhook    xoxb-••••d9e1 (57 chars)
scripts/deploy.sh       42    -                ghp_••••9d1e (40 chars)

Remediation:
  → Move these values to `kpm add <service>/<name>` and reference via env vars.
  → Rotate any credential that has been committed to git history.
```

## `kpm scan logs` — mode-specific behavior

### Scope

- Single input per invocation: a file path **or** stdin when no path is given or path is `-`
- **No recursion** (logs are streams, not trees)
- **Value-only detection by default** — plain log lines don't have `KEY=` structure, and value patterns alone catch the realistic cases (stack traces, debug dumps, echoed commands)

### Flags specific to `logs`

| Flag               | Purpose                                                    |
|--------------------|------------------------------------------------------------|
| `--include-names`  | Also run name patterns (useful for structured/JSON logs)   |
| `--follow`         | `tail -f` semantics — scan as lines arrive (stdin or file) |

### Output columns

`LINE`, `PREVIEW`, `SNIPPET` (trimmed + redacted context around the match)

### Example output

```
⚠  KPM scan: 2 secrets found in app.log

LINE    PREVIEW               SNIPPET
1247    sk-proj-••••7f2a      ...calling OpenAI with key=sk-proj-••••7f2a...
2891    ghp_••••9d1e          ...git clone https://user:ghp_••••9d1e@github.com/...
```

### Streaming

`kpm scan logs --follow` or piping from `tail -f`:

```
tail -f /var/log/app.log | kpm scan logs
```

Stdin mode auto-follows (reads until EOF). Exit code is determined at EOF (or on signal when streaming live).

## Help text

Modeled on `aws sts --help` — detailed, sectioned, example-rich. KPM's current help is terse; this raises the bar for `scan` and sets a template for future commands.

### `kpm scan --help`

```
NAME
    kpm-scan -- Scan for exposed secrets in processes, files, or logs

SYNOPSIS
    kpm scan <mode> [options]

DESCRIPTION
    Detects secrets exposed in common leak vectors. Each mode targets a
    different surface area but shares the same detection engine and
    redaction rules:

        shell    Scan running processes for secrets in their environment
        files    Scan files on disk for hardcoded secrets
        logs     Scan a log file or stdin for leaked secrets

    See `kpm scan <mode> --help` for mode-specific options.

GLOBAL OPTIONS
    --paranoid       Enable expanded detection (more findings, more false positives)
    --json           Emit JSON instead of a human-readable table
    --quiet          Suppress stdout; use exit code only

EXIT STATUS
    0    No exposed secrets found.
    1    One or more exposed secrets found.
    2    Execution error.

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
    and reports any variables that appear to contain secrets. Values are
    always redacted — only previews and lengths are shown.

    This command is safe to run routinely. It does not modify state, does
    not transmit data off the machine, and reads only processes owned by
    the invoking user.

OPTIONS
    --paranoid       Expanded detection rules.
    --json           JSON output.
    --quiet          Exit code only.
    --all-users      (Not yet implemented.) Scan all users' processes.

EXIT STATUS
    0    No exposed secrets found.
    1    Exposed secrets found.
    2    Execution error.

EXAMPLES
    Scan current user's processes:

        kpm scan shell

    Gate a CI job on zero exposed secrets:

        kpm scan shell --quiet || exit 1

    JSON for a dashboard:

        kpm scan shell --json | jq '.findings[] | .variable'

SEE ALSO
    kpm run --secure    Inject only allow-listed secrets into a command
```

### `kpm scan files --help`

```
NAME
    kpm-scan-files -- Scan files on disk for hardcoded secrets

SYNOPSIS
    kpm scan files [options] [path...]

DESCRIPTION
    Recursively scans files for secrets using both name-pattern (KEY=VALUE
    style lines) and value-pattern detection. Skips binary files and
    respects .gitignore by default.

    When no path is given, scans the current directory. Multiple paths
    may be provided.

OPTIONS
    --recurse           Explicit recursion (default; present for clarity).
    --no-recurse        Do not descend into subdirectories.
    --max-depth <n>     Cap recursion depth.
    --no-gitignore      Ignore .gitignore and scan everything.
    --include-binary    Scan binary files (default: skip).
    --exclude <glob>    Exclude paths matching glob (repeatable).
    --paranoid          Expanded detection rules.
    --json              JSON output.
    --quiet             Exit code only.

EXIT STATUS
    0    No hardcoded secrets found.
    1    Hardcoded secrets found.
    2    Execution error.

EXAMPLES
    Review a PR before you dig in:

        kpm scan files ./pr-branch

    Gate CI on zero hardcoded secrets:

        kpm scan files --quiet || exit 1

    Scan only the config directory, don't descend:

        kpm scan files --no-recurse ./config

    Shallow scan in a monorepo:

        kpm scan files --max-depth 2

    Exclude test fixtures:

        kpm scan files --exclude 'testdata/**' --exclude '*.test.js'

SEE ALSO
    kpm scan shell      Scan running processes
    kpm scan logs       Scan log files or stdin
```

### `kpm scan logs --help`

```
NAME
    kpm-scan-logs -- Scan a log file or stdin for leaked secrets

SYNOPSIS
    kpm scan logs [options] [path]
    <producer> | kpm scan logs [options]

DESCRIPTION
    Scans log output for secrets that have leaked into log lines (stack
    traces, debug dumps, echoed commands). By default, uses value-pattern
    detection only — log lines rarely have KEY=VALUE structure.

    When no path is given, reads from stdin. A path of '-' also means
    stdin.

OPTIONS
    --include-names     Also run name-pattern detection (useful for
                        structured/JSON logs with key:value pairs).
    --follow            tail -f semantics; scan lines as they arrive.
    --paranoid          Expanded detection rules.
    --json              JSON output.
    --quiet             Exit code only.

EXIT STATUS
    0    No leaked secrets found.
    1    Leaked secrets found.
    2    Execution error.

EXAMPLES
    Scan a log file:

        kpm scan logs /var/log/app.log

    Live-scan a tail stream:

        tail -f /var/log/app.log | kpm scan logs

    Follow a file directly:

        kpm scan logs --follow /var/log/app.log

    Scan CI output:

        some-build-command 2>&1 | kpm scan logs --quiet || echo "LEAK DETECTED"

    Structured JSON logs:

        kpm scan logs --include-names /var/log/app.json

SEE ALSO
    kpm scan shell      Scan running processes
    kpm scan files      Scan files on disk
```

### Help text conventions

- Sections: `NAME`, `SYNOPSIS`, `DESCRIPTION`, `OPTIONS`, `EXIT STATUS`, `EXAMPLES`, `SEE ALSO`
- Each option on its own line with a short wrapped description
- At least 3 `EXAMPLES` covering the 80% cases
- `SEE ALSO` cross-links related commands

The top-level `kpm --help` stays compact (it's the index). Per-command `--help` goes deep.

## Architecture

### Package layout

```
cmd/kpm/main.go                 # new case: "scan"; dispatches to scan package

internal/scan/
    scan.go                     # package API, dispatcher, shared types
    detect.go                   # detectors: name-based, value-based, entropy
    detect_patterns.go          # pattern tables
    redact.go                   # redaction (pure function, heavily tested)
    output.go                   # table + JSON formatters (mode-aware columns)
    help.go                     # help text constants for all modes

    source_shell.go             # shell-mode orchestrator
    source_shell_linux.go       # //go:build linux
    source_shell_darwin.go      # //go:build darwin
    source_shell_stub.go        # //go:build !linux && !darwin

    source_files.go             # filesystem walker + gitignore + binary skip
    source_files_gitignore.go   # minimal gitignore matcher (no parent traversal)

    source_logs.go              # stream scanner (file + stdin + follow)
```

### Key types

```go
// Finding is one detected secret. Mode-agnostic.
type Finding struct {
    Source    SourceRef  // discriminated union: ShellRef | FileRef | LogRef
    Variable  string     // empty for value-only hits
    Detector  string     // e.g. "name:api-key", "value:openai-proj", "entropy"
    Value     string     // raw; discarded before reaching output layer
}

type SourceRef interface {
    Kind() string // "shell" | "files" | "logs"
}

type ShellRef struct { PID int; User, Comm, Command string }
type FileRef  struct { Path string; Line int }
type LogRef   struct { Path string; Line int; Snippet string }

// Detector is the shared interface.
type Detector interface {
    Name() string
    Detect(name, value string) (matched bool, detectorID string)
}
```

### Data flow

1. `main.go` → `scan.Dispatch(args)` → routes on first positional arg (`shell`/`files`/`logs`)
2. Mode-specific source function enumerates items and yields `(name, value, SourceRef)` tuples
3. For each tuple, run all enabled detectors
4. Collect findings; **discard raw `Value`** before passing to output layer
5. Output layer formats with redaction — never sees raw values

**Security invariant:** raw values are discarded at the detection→output boundary. The output formatter physically cannot leak values because it never receives them.

## Testing strategy

### Validation-first

Tests land **before** implementation. Coordinator dispatches validation subagent first, then implementation subagent reads failing tests and makes them pass.

### Unit tests (shared engine)

- **`redact_test.go`** — golden table of (input, expected_preview) for every known prefix + unknown-prefix case. Assert raw never appears in any output.
- **`detect_test.go`** — true-positive and true-negative fixtures for every name and value pattern. Every pattern ships with both.
- **`output_test.go`** — golden files for table and JSON output given fixed findings slices, one per mode (shell, files, logs columns differ).

### Mode-specific tests

- **`source_shell_integration_test.go`** — spawns `sleep 60` subprocess with known env vars (including a fake `sk-...`), runs enumerator, asserts detection + redaction, cleans up. Build-tagged per OS.
- **`source_files_test.go`** — synthetic temp directory tree with planted secrets in files, binary files, `.gitignore`'d files, nested dirs at various depths. Verifies: recursion, binary skip, gitignore respect, `--max-depth`, `--exclude`, `--no-gitignore`.
- **`source_logs_test.go`** — feeds fixed log content through stdin and from a temp file. Verifies value-only detection default, `--include-names`, `--follow` (via a goroutine writer).

### Platform stub tests

- On unsupported platforms, `kpm scan shell` exits 2 with `kpm scan: unsupported platform: <goos>` and does not crash. `files` and `logs` work everywhere Go works.

### The non-leak invariant test

One dedicated test **per mode**:

1. Plant a canary value (`CANARY_verySecretValue123456`) in the source (env var for shell; temp file for files; stdin pipe for logs)
2. Run the scanner programmatically, capture all stdout + stderr across all output modes (table, JSON, quiet)
3. Assert the canary appears in **zero** of them

This is the scanner-as-leak-vector regression guard. It must pass for all three modes.

## Blog & demo integration

- **Blog Part 8 (forensics beat):** references `kpm scan` as the "find the problem" half of the forensics story — you can't audit what you can't see.
- **LinkedIn rollout:** three 60-sec demo videos across a week, one per mode, each with its own target audience.
- **README:** lift `kpm scan files ./` into the top-of-file three-command demo block; mention all three modes in the feature list.
- **CI example:** add a docs page showing `kpm scan files --quiet` as a pre-commit or pre-merge gate, and `kpm scan logs --quiet` in post-job log validation.

## Non-goals (explicitly out of scope for v1)

- Scanning other users' processes (`--all-users`) — reserved, requires elevation story
- Continuous/background scanning (daemon mode)
- Auto-remediation (taking action on findings)
- Integration with AgentKMS server for centralized scan results
- Windows support (no `/proc`, different process model; revisit if demand appears)
- Parent-directory or nested `.gitignore` parsing (single-level at scan root only)
- Compressed log formats (`.gz`, `.bz2`) — pipe through `zcat` for now
- Git history scanning (`truffleHog`-style) — that's a separate tool category

## Rollout

1. Spec approved (this doc)
2. Writing-plans skill produces validation-first implementation plan
3. Coordinator dispatches per plan:
   - Validation subagent (Sonnet) writes all tests
   - Implementation subagent (Sonnet) makes tests pass
   - Review subagent (Haiku) independent review
4. Ship in a point release (v0.3.2 likely)
5. Staggered LinkedIn rollout — one mode per post, one post every 2 days

## Open questions

None remaining at spec stage. Any discovered during implementation → note in plan, not spec.
