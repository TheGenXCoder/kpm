package scan

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

// LogOptions configures a logs-mode scan.
type LogOptions struct {
	Path         string
	Mode         Mode
	IncludeNames bool
	Follow       bool
	Stdin        io.Reader
}

// RunLogs scans a single log file (or stdin) for secret values.
// By default only value-pattern detection is run (value-only mode).
// Pass IncludeNames=true to additionally extract name=value pairs and run
// name-based detection (useful for structured logs).
func RunLogs(ctx context.Context, opts LogOptions) (Result, error) {
	r, closer, err := openLogSource(opts)
	if err != nil {
		return Result{}, err
	}
	if closer != nil {
		defer closer.Close()
	}

	detectors := DetectorsFor(opts.Mode)

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 2*1024*1024)

	var findings []Finding
	scanned := 0
	affected := 0

	for sc.Scan() {
		select {
		case <-ctx.Done():
			return Result{}, ctx.Err()
		default:
		}
		scanned++
		line := sc.Text()
		hit := false

		if opts.IncludeNames {
			for _, p := range extractPairsLog(line) {
				for _, d := range detectors {
					if m, id := d.Detect(p.name, p.value); m {
						findings = append(findings, Finding{
							Source:   LogRef{Path: displayLogPath(opts), Line: scanned, Snippet: redactSnippet(line)},
							Variable: p.name,
							Detector: id,
							Value:    p.value,
						})
						hit = true
						break
					}
				}
			}
		}

		for _, d := range detectors {
			if d.Name() != "value" {
				continue
			}
			if m, id := d.Detect("", line); m {
				val := extractValueMatchLog(line, id)
				findings = append(findings, Finding{
					Source:   LogRef{Path: displayLogPath(opts), Line: scanned, Snippet: redactSnippet(line)},
					Variable: "",
					Detector: id,
					Value:    val,
				})
				hit = true
				break
			}
		}

		if hit {
			affected++
		}
	}
	if err := sc.Err(); err != nil {
		return Result{}, err
	}
	return Result{Findings: findings, Scanned: scanned, Affected: affected}, nil
}

func openLogSource(opts LogOptions) (io.Reader, io.Closer, error) {
	if opts.Path == "" || opts.Path == "-" {
		if opts.Stdin != nil {
			return opts.Stdin, nil, nil
		}
		return os.Stdin, nil, nil
	}
	f, err := os.Open(opts.Path)
	if err != nil {
		return nil, nil, fmt.Errorf("open log: %w", err)
	}
	return f, f, nil
}

func displayLogPath(opts LogOptions) string {
	if opts.Path == "" || opts.Path == "-" {
		return "-"
	}
	return opts.Path
}

func redactSnippet(line string) string {
	out := line
	for _, p := range append(append([]valuePattern{}, valuePatternsHighConfidence...), valuePatternsParanoid...) {
		out = p.regex.ReplaceAllStringFunc(out, func(match string) string {
			return Redact(match)
		})
	}
	if len(out) > 200 {
		out = out[:197] + "..."
	}
	return strings.TrimRight(out, "\n")
}

// kvPair is a name=value pair extracted from a log line.
type kvPair struct {
	name  string
	value string
}

// reKVPair matches KEY=VALUE, KEY="VALUE", or JSON-style "KEY":"VALUE" pairs.
// NOTE: extractPairsLog and extractValueMatchLog are defined here for the logs
// source.  Task 5 (files source) may define identically-named helper types/
// functions in source_files.go.  If a "redeclared" compiler error appears after
// merging both tasks, remove the definitions below and rely on the ones from
// source_files.go (renaming call-sites accordingly, or aliasing).
var reKVPair = regexp.MustCompile(`(?i)\b([A-Za-z_][A-Za-z0-9_]*)(?:\s*[:=]\s*|":\s*"?)([^\s,"}\]]{4,})`)

func extractPairsLog(line string) []kvPair {
	matches := reKVPair.FindAllStringSubmatch(line, -1)
	if len(matches) == 0 {
		return nil
	}
	out := make([]kvPair, 0, len(matches))
	for _, m := range matches {
		name := strings.TrimRight(m[1], `"`)
		value := strings.TrimRight(m[2], `"`)
		if name == "" || value == "" {
			continue
		}
		out = append(out, kvPair{name: name, value: value})
	}
	return out
}

// extractValueMatchLog returns the first token in line that matches the pattern
// for the given detector ID.  Falls back to the whole line if no match found.
func extractValueMatchLog(line, detectorID string) string {
	all := append(append([]valuePattern{}, valuePatternsHighConfidence...), valuePatternsParanoid...)
	for _, p := range all {
		if p.id == detectorID {
			if m := p.regex.FindString(line); m != "" {
				return m
			}
		}
	}
	return line
}
