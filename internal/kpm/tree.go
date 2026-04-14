package kpm

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// TemplateLevel represents a level in the template hierarchy.
type TemplateLevel struct {
	Label string // "Enterprise", "User", "Project"
	Dir   string // absolute path
}

// TemplateSummary is a parsed template with its secret references (no values).
type TemplateSummary struct {
	Name string
	Refs []string // e.g. ["llm/anthropic", "kv/db/prod#password"]
}

// DiscoverTemplateLevels returns the template hierarchy directories.
// Deduplicates: if two levels resolve to the same path, only the higher-priority one is shown.
func DiscoverTemplateLevels() []TemplateLevel {
	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()

	candidates := []TemplateLevel{
		{Label: "Enterprise", Dir: "/etc/catalyst9/.kpm/templates"},
		{Label: "User", Dir: filepath.Join(home, ".kpm", "templates")},
		{Label: "Project", Dir: filepath.Join(cwd, ".kpm", "templates")},
	}

	// Deduplicate by resolved absolute path.
	seen := map[string]bool{}
	var levels []TemplateLevel
	for _, c := range candidates {
		abs, _ := filepath.Abs(c.Dir)
		if seen[abs] {
			continue
		}
		seen[abs] = true
		levels = append(levels, c)
	}
	return levels
}

// ScanTemplates finds all .template files in a directory and extracts their KMS refs.
func ScanTemplates(dir string) ([]TemplateSummary, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var summaries []TemplateSummary
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".template") {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		f, err := os.Open(path)
		if err != nil {
			continue
		}

		parsed, err := ParseTemplate(f)
		f.Close()
		if err != nil {
			continue
		}

		var refs []string
		for _, e := range parsed {
			if e.IsKMSRef {
				ref := e.Ref.Type + "/" + e.Ref.Path
				if e.Ref.Key != "" {
					ref += "#" + e.Ref.Key
				}
				refs = append(refs, ref)
			}
		}

		summaries = append(summaries, TemplateSummary{
			Name: entry.Name(),
			Refs: refs,
		})
	}

	return summaries, nil
}

// PrintTree writes the template hierarchy tree to w.
func PrintTree(w io.Writer, levels []TemplateLevel) error {
	for i, level := range levels {
		if i > 0 {
			fmt.Fprintln(w)
		}
		fmt.Fprintf(w, "%s: %s\n", level.Label, level.Dir)

		summaries, err := ScanTemplates(level.Dir)
		if err != nil {
			fmt.Fprintf(w, "  (error: %v)\n", err)
			continue
		}

		if len(summaries) == 0 {
			fmt.Fprintln(w, "  (no templates found)")
			continue
		}

		for _, s := range summaries {
			secretWord := "secrets"
			if len(s.Refs) == 1 {
				secretWord = "secret"
			}
			fmt.Fprintf(w, "  %-25s %d %s [%s]\n", s.Name, len(s.Refs), secretWord, strings.Join(s.Refs, ", "))
		}
	}
	return nil
}
