package scan

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// Gitignore is a minimal .gitignore matcher. Supports blank/comment lines,
// directory patterns (trailing /), suffix globs (*.log), and plain names
// matched against any path component. No negation, no anchored patterns,
// no nested .gitignore files.
type Gitignore struct {
	patterns []giPattern
}

type giPattern struct {
	raw    string
	isDir  bool
	isGlob bool
}

func LoadGitignore(root string) (*Gitignore, error) {
	f, err := os.Open(filepath.Join(root, ".gitignore"))
	if err != nil {
		if os.IsNotExist(err) {
			return &Gitignore{}, nil
		}
		return nil, err
	}
	defer f.Close()

	gi := &Gitignore{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p := giPattern{raw: line}
		if strings.HasSuffix(line, "/") {
			p.isDir = true
			p.raw = strings.TrimSuffix(line, "/")
		}
		if strings.Contains(p.raw, "*") {
			p.isGlob = true
		}
		gi.patterns = append(gi.patterns, p)
	}
	return gi, sc.Err()
}

func (g *Gitignore) Match(path string) bool {
	if g == nil || len(g.patterns) == 0 {
		return false
	}
	parts := strings.Split(path, "/")
	for _, p := range g.patterns {
		if p.isDir {
			for _, part := range parts {
				if part == p.raw {
					return true
				}
			}
			continue
		}
		if p.isGlob {
			if match, _ := filepath.Match(p.raw, parts[len(parts)-1]); match {
				return true
			}
			continue
		}
		for _, part := range parts {
			if part == p.raw {
				return true
			}
		}
	}
	return false
}
