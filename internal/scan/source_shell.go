package scan

import (
	"context"
	"errors"
)

// ShellOptions configures a shell-mode scan.
type ShellOptions struct {
	Mode     Mode
	AllUsers bool // reserved; returns ErrNotImplemented in v1
}

// ErrUnsupportedPlatform is returned on platforms we don't support.
var ErrUnsupportedPlatform = errors.New("kpm scan: unsupported platform")

// ErrNotImplemented is returned for reserved features.
var ErrNotImplemented = errors.New("not yet implemented")

// RunShell enumerates the current user's processes, runs detectors against
// each process's environment, and returns a Result.
func RunShell(ctx context.Context, opts ShellOptions) (Result, error) {
	if opts.AllUsers {
		return Result{}, ErrNotImplemented
	}
	procs, err := enumerateProcesses(ctx) // per-OS implementation
	if err != nil {
		return Result{}, err
	}
	detectors := DetectorsFor(opts.Mode)

	var findings []Finding
	affected := 0
	for _, p := range procs {
		hit := false
		for name, value := range p.Env {
			for _, d := range detectors {
				if m, id := d.Detect(name, value); m {
					findings = append(findings, Finding{
						Source: ShellRef{
							PID: p.PID, User: p.User, Comm: p.Comm, Command: p.Command,
						},
						Variable: name,
						Detector: id,
						Value:    value,
					})
					hit = true
					break // one detector hit is enough per (name, value)
				}
			}
		}
		if hit {
			affected++
		}
	}
	return Result{
		Findings: findings,
		Scanned:  len(procs),
		Affected: affected,
	}, nil
}

// process is the internal form produced by each OS adapter.
type process struct {
	PID     int
	User    string
	Comm    string
	Command string
	Env     map[string]string
}
