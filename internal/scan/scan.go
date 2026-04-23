// Package scan detects secrets exposed in processes, files, and logs.
//
// The package is designed around a strict security invariant: raw secret
// values are discarded before reaching any output formatter. Callers must
// not add code paths that emit Finding.Value.
package scan

import "context"

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

// Dispatch is the top-level entry point. Implemented in a later task.
func Dispatch(ctx context.Context, args []string) (exitCode int) {
	// Implemented in Task 7.
	panic("not implemented")
}
