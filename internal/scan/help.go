package scan

const helpTop = `NAME
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

    See 'kpm scan <mode> --help' for mode-specific options.

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
`

const helpShell = `NAME
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
`

const helpFiles = `NAME
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
`

const helpLogs = `NAME
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
`

// HelpText returns the help screen for a mode. Empty mode returns the top-level help.
func HelpText(mode string) string {
	switch mode {
	case "shell":
		return helpShell
	case "files":
		return helpFiles
	case "logs":
		return helpLogs
	default:
		return helpTop
	}
}
