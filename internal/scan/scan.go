// Package scan detects secrets exposed in processes, files, and logs.
//
// The package is designed around a strict security invariant: raw secret
// values are discarded before reaching any output formatter. Callers must
// not add code paths that emit Finding.Value.
package scan

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
)

// Finding is one detected secret. Mode-agnostic.
type Finding struct {
	Source   SourceRef
	Variable string // empty for value-only hits (e.g., logs)
	Detector string // e.g. "name:api-key", "value:openai-proj", "entropy"
	Value    string // raw; MUST be discarded before output
}

// SourceRef is a discriminated union identifying where a finding came from.
type SourceRef interface {
	Kind() string // "shell" | "files" | "logs"
}

// ShellRef identifies a process.
type ShellRef struct {
	PID     int
	User    string
	Comm    string
	Command string
}

func (ShellRef) Kind() string { return "shell" }

// FileRef identifies a location in a file.
type FileRef struct {
	Path string
	Line int
}

func (FileRef) Kind() string { return "files" }

// LogRef identifies a line in a log.
type LogRef struct {
	Path    string // empty or "-" for stdin
	Line    int
	Snippet string // already-redacted context for output
}

func (LogRef) Kind() string { return "logs" }

// Mode selects detection strictness.
type Mode int

const (
	ModeDefault  Mode = 0 // high-confidence only
	ModeParanoid Mode = 1 // adds entropy + broader name patterns
)

// Detector inspects (name, value) and optionally returns a detector ID.
type Detector interface {
	Name() string
	Detect(name, value string) (matched bool, detectorID string)
}

// Result is returned by every source adapter.
type Result struct {
	Findings []Finding
	Scanned  int // total units scanned (processes, files, lines)
	Affected int // units with at least one finding
}

// Options passed through the dispatcher.
type Options struct {
	Mode  Mode
	JSON  bool
	Quiet bool
}

// Dispatch parses args after "scan" and routes to the appropriate mode.
// Returns exit code (0 no findings, 1 findings, 2 error).
func Dispatch(ctx context.Context, args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, HelpText(""))
		return 2
	}

	mode := args[0]
	rest := args[1:]

	for _, a := range rest {
		if a == "--help" || a == "-h" {
			fmt.Fprint(os.Stdout, HelpText(mode))
			return 0
		}
	}

	switch mode {
	case "--help", "-h", "help":
		fmt.Fprint(os.Stdout, HelpText(""))
		return 0
	case "shell":
		return dispatchShell(ctx, rest)
	case "files":
		return dispatchFiles(ctx, rest)
	case "logs":
		return dispatchLogs(ctx, rest)
	default:
		fmt.Fprintf(os.Stderr, "kpm scan: unknown mode %q\n\n%s", mode, HelpText(""))
		return 2
	}
}

func dispatchShell(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("scan shell", flag.ContinueOnError)
	paranoid := fs.Bool("paranoid", false, "")
	jsonOut := fs.Bool("json", false, "")
	quiet := fs.Bool("quiet", false, "")
	summary := fs.Bool("summary", false, "")
	allUsers := fs.Bool("all-users", false, "")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	opts := ShellOptions{Mode: modeFrom(*paranoid), AllUsers: *allUsers}
	result, err := RunShell(ctx, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "kpm scan: %v\n", err)
		return 2
	}
	return writeAndExit(result, *jsonOut, *quiet, *summary, "shell")
}

func dispatchFiles(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("scan files", flag.ContinueOnError)
	paranoid := fs.Bool("paranoid", false, "")
	jsonOut := fs.Bool("json", false, "")
	quiet := fs.Bool("quiet", false, "")
	summary := fs.Bool("summary", false, "")
	_ = fs.Bool("recurse", false, "")
	noRecurse := fs.Bool("no-recurse", false, "")
	maxDepth := fs.Int("max-depth", 0, "")
	noGitignore := fs.Bool("no-gitignore", false, "")
	includeBinary := fs.Bool("include-binary", false, "")
	var excludes multiString
	fs.Var(&excludes, "exclude", "")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	opts := FileOptions{
		Paths: fs.Args(), Mode: modeFrom(*paranoid),
		NoRecurse: *noRecurse, MaxDepth: *maxDepth,
		NoGitignore: *noGitignore, IncludeBinary: *includeBinary,
		Excludes: []string(excludes),
	}
	result, err := RunFiles(ctx, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "kpm scan: %v\n", err)
		return 2
	}
	return writeAndExit(result, *jsonOut, *quiet, *summary, "files")
}

func dispatchLogs(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("scan logs", flag.ContinueOnError)
	paranoid := fs.Bool("paranoid", false, "")
	jsonOut := fs.Bool("json", false, "")
	quiet := fs.Bool("quiet", false, "")
	summary := fs.Bool("summary", false, "")
	includeNames := fs.Bool("include-names", false, "")
	follow := fs.Bool("follow", false, "")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	path := ""
	if pargs := fs.Args(); len(pargs) > 0 {
		path = pargs[0]
	}
	opts := LogOptions{
		Path: path, Mode: modeFrom(*paranoid),
		IncludeNames: *includeNames, Follow: *follow,
	}
	result, err := RunLogs(ctx, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "kpm scan: %v\n", err)
		return 2
	}
	return writeAndExit(result, *jsonOut, *quiet, *summary, "logs")
}

func modeFrom(paranoid bool) Mode {
	if paranoid {
		return ModeParanoid
	}
	return ModeDefault
}

func writeAndExit(r Result, jsonOut, quiet, summary bool, kind string) int {
	if !quiet {
		switch {
		case summary && jsonOut:
			WriteSummaryJSON(os.Stdout, r)
		case summary:
			WriteSummaryTable(os.Stdout, r, kind)
		case jsonOut:
			WriteJSON(os.Stdout, r)
		default:
			WriteTable(os.Stdout, r)
		}
	}
	if len(r.Findings) > 0 {
		return 1
	}
	return 0
}

// multiString collects repeatable flag values.
type multiString []string

func (m *multiString) String() string     { return strings.Join(*m, ",") }
func (m *multiString) Set(v string) error { *m = append(*m, v); return nil }
