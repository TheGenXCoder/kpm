package scan

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type FileOptions struct {
	Paths         []string
	Mode          Mode
	NoRecurse     bool
	MaxDepth      int
	NoGitignore   bool
	IncludeBinary bool
	Excludes      []string
}

func RunFiles(ctx context.Context, opts FileOptions) (Result, error) {
	if len(opts.Paths) == 0 {
		opts.Paths = []string{"."}
	}
	defer func() { includeBinaryOverride = false }()
	includeBinaryOverride = opts.IncludeBinary

	detectors := DetectorsFor(opts.Mode)

	var findings []Finding
	scanned := 0
	affected := 0

	for _, root := range opts.Paths {
		rootAbs, err := filepath.Abs(root)
		if err != nil {
			return Result{}, err
		}
		info, err := os.Stat(rootAbs)
		if err != nil {
			return Result{}, err
		}

		var gi *Gitignore
		if !opts.NoGitignore && info.IsDir() {
			gi, _ = LoadGitignore(rootAbs)
		}

		err = walkPath(ctx, rootAbs, rootAbs, 0, opts, gi, func(path string) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			scanned++
			fileFindings, err := scanFile(path, detectors)
			if err != nil {
				return nil
			}
			if len(fileFindings) > 0 {
				affected++
				findings = append(findings, fileFindings...)
			}
			return nil
		})
		if err != nil {
			return Result{}, err
		}
	}
	return Result{Findings: findings, Scanned: scanned, Affected: affected}, nil
}

var includeBinaryOverride bool

func walkPath(ctx context.Context, scanRoot, current string, depth int, opts FileOptions, gi *Gitignore, visit func(path string) error) error {
	info, err := os.Stat(current)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return visit(current)
	}
	if opts.MaxDepth > 0 && depth > opts.MaxDepth {
		return nil
	}
	entries, err := os.ReadDir(current)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		full := filepath.Join(current, e.Name())
		if gi != nil {
			rel, _ := filepath.Rel(scanRoot, full)
			if gi.Match(filepath.ToSlash(rel)) {
				continue
			}
		}
		if matchAnyExclude(opts.Excludes, e.Name(), full) {
			continue
		}
		if e.IsDir() {
			if opts.NoRecurse {
				continue
			}
			if err := walkPath(ctx, scanRoot, full, depth+1, opts, gi, visit); err != nil {
				return err
			}
			continue
		}
		if err := visit(full); err != nil {
			return err
		}
	}
	return nil
}

func matchAnyExclude(patterns []string, name, full string) bool {
	for _, pat := range patterns {
		if m, _ := filepath.Match(pat, name); m {
			return true
		}
		if strings.HasSuffix(pat, "/**") {
			prefix := strings.TrimSuffix(pat, "/**")
			sep := string(filepath.Separator)
			if strings.Contains(full, sep+prefix+sep) || filepath.Base(filepath.Dir(full)) == prefix {
				return true
			}
		}
	}
	return false
}

func scanFile(path string, detectors []Detector) ([]Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	head := make([]byte, 8192)
	n, _ := f.Read(head)
	head = head[:n]
	if bytes.IndexByte(head, 0) >= 0 && !includeBinaryOverride {
		return nil, nil
	}
	_, _ = f.Seek(0, io.SeekStart)

	var findings []Finding
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		for _, p := range extractPairs(line) {
			for _, d := range detectors {
				if m, id := d.Detect(p.name, p.value); m {
					findings = append(findings, Finding{
						Source:   FileRef{Path: path, Line: lineNo},
						Variable: p.name,
						Detector: id,
						Value:    p.value,
					})
					break
				}
			}
		}
		for _, d := range detectors {
			if d.Name() != "value" {
				continue
			}
			if m, id := d.Detect("", line); m {
				if !hasDetectorAt(findings, path, lineNo, id) {
					findings = append(findings, Finding{
						Source:   FileRef{Path: path, Line: lineNo},
						Variable: "",
						Detector: id,
						Value:    extractValueMatch(line, id),
					})
				}
			}
		}
	}
	return findings, sc.Err()
}

func hasDetectorAt(existing []Finding, path string, line int, detID string) bool {
	for _, f := range existing {
		if fr, ok := f.Source.(FileRef); ok && fr.Path == path && fr.Line == line && f.Detector == detID {
			return true
		}
	}
	return false
}

func extractValueMatch(line, detID string) string {
	for _, p := range append(append([]valuePattern{}, valuePatternsHighConfidence...), valuePatternsParanoid...) {
		if p.id == detID {
			if m := p.regex.FindString(line); m != "" {
				return m
			}
		}
	}
	return line
}

type pair struct{ name, value string }

var (
	kvEqualsRegex = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["']?([^"'\s#]+)["']?`)
	kvColonRegex  = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)\s*:\s*["']?([^"'\s#]+)["']?`)
	kvJSONRegex   = regexp.MustCompile(`"([A-Za-z_][A-Za-z0-9_]*)"\s*:\s*"([^"]+)"`)
)

func extractPairs(line string) []pair {
	var pairs []pair
	for _, re := range []*regexp.Regexp{kvJSONRegex, kvEqualsRegex, kvColonRegex} {
		for _, m := range re.FindAllStringSubmatch(line, -1) {
			if len(m) >= 3 && m[1] != "" && m[2] != "" {
				pairs = append(pairs, pair{name: m[1], value: m[2]})
			}
		}
	}
	return pairs
}
