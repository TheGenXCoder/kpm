package kpm

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// kmsRefPattern matches ${kms:type/path[#key][:-default]}.
// Groups: [1]=type (llm|kv), [2]=path, [3]=key (optional), [4]=default (optional).
var kmsRefPattern = regexp.MustCompile(`^\$\{kms:([a-z]+)/(.*?)(?:#([^:}]+))?(?::-(.*?))?\}$`)

// KMSReference is a parsed reference to a secret in AgentKMS.
type KMSReference struct {
	Type    string // "llm" or "kv"
	Path    string // e.g. "db/prod" or "openai"
	Key     string // e.g. "password" (empty for LLM refs)
	Default string // fallback value (empty if none)
}

// TemplateEntry is one line from a parsed .env.template.
type TemplateEntry struct {
	EnvKey     string       // env var name (e.g. "DB_PASSWORD")
	PlainValue []byte       // non-KMS value (for passthrough lines)
	IsKMSRef   bool         // true if value is a ${kms:...} reference
	Ref        KMSReference // populated only if IsKMSRef
}

// ParseKMSRef parses a single ${kms:...} reference string.
// Returns the parsed reference and true, or zero value and false if not a KMS ref.
func ParseKMSRef(s string) (KMSReference, bool) {
	m := kmsRefPattern.FindStringSubmatch(s)
	if m == nil {
		return KMSReference{}, false
	}
	return KMSReference{
		Type:    m[1],
		Path:    m[2],
		Key:     m[3],
		Default: m[4],
	}, true
}

// ParseTemplate reads an .env.template and returns parsed entries.
// Comment lines (starting with #) and blank lines are skipped.
// Plain KEY=value lines pass through. Lines with ${kms:...} values become KMS refs.
func ParseTemplate(r io.Reader) ([]TemplateEntry, error) {
	var entries []TemplateEntry
	scanner := bufio.NewScanner(r)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and blank lines.
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check for include directive (no KEY= prefix): ${kms:include/path}
		if strings.HasPrefix(line, "${kms:include/") {
			ref, ok := ParseKMSRef(line)
			if ok && ref.Type == "include" {
				entries = append(entries, TemplateEntry{
					EnvKey:   "", // no env key — this is an include directive
					IsKMSRef: true,
					Ref:      ref,
				})
				continue
			}
		}

		// Split on first '='.
		eqIdx := strings.IndexByte(line, '=')
		if eqIdx < 0 {
			return nil, fmt.Errorf("line %d: no '=' found in %q", lineNum, line)
		}

		key := line[:eqIdx]
		value := line[eqIdx+1:]

		ref, isRef := ParseKMSRef(value)
		if isRef {
			entries = append(entries, TemplateEntry{
				EnvKey:   key,
				IsKMSRef: true,
				Ref:      ref,
			})
		} else {
			entries = append(entries, TemplateEntry{
				EnvKey:     key,
				PlainValue: []byte(value),
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading template: %w", err)
	}

	return entries, nil
}

// ResolveTemplateWithIncludes reads a template file, resolves includes, and returns entries.
// Profile variables in include paths are resolved. Circular includes are detected.
// The override semantics: included entries come first; current template entries for
// the same EnvKey override (last-write-wins via deduplication at the end).
func ResolveTemplateWithIncludes(path string, profile Profile, seen map[string]bool) ([]TemplateEntry, error) {
	if seen == nil {
		seen = map[string]bool{}
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		absPath = path
	}
	if seen[absPath] {
		return nil, fmt.Errorf("circular include detected: %s", path)
	}
	seen[absPath] = true

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open template %s: %w", path, err)
	}
	defer f.Close()

	entries, err := ParseTemplate(f)
	if err != nil {
		return nil, err
	}

	// Process entries: expand includes, pass everything else through.
	// Included entries come before current-file entries (so current overrides for same key).
	var result []TemplateEntry
	var ownEntries []TemplateEntry

	for _, e := range entries {
		if e.IsKMSRef && e.Ref.Type == "include" {
			// Resolve profile variables in the include path.
			includePath := e.Ref.Path
			if profile != nil {
				resolved, err := profile.Resolve(includePath)
				if err != nil {
					return nil, fmt.Errorf("resolve include path %q: %w", includePath, err)
				}
				includePath = resolved
			}

			fullPath := findIncludeTemplate(includePath)
			if fullPath == "" {
				return nil, fmt.Errorf("include target %q not found (checked user and project templates)", includePath)
			}

			included, err := ResolveTemplateWithIncludes(fullPath, profile, seen)
			if err != nil {
				return nil, err
			}
			result = append(result, included...)
		} else {
			ownEntries = append(ownEntries, e)
		}
	}

	// Own entries come after includes; for duplicate keys, own entries win.
	result = append(result, ownEntries...)

	// Deduplicate: last entry for each key wins (own entries override includes).
	return deduplicateEntries(result), nil
}

// deduplicateEntries keeps the last entry for each EnvKey (later = higher priority).
// Entries without an EnvKey (include directives not yet expanded) are dropped.
func deduplicateEntries(entries []TemplateEntry) []TemplateEntry {
	seen := map[string]int{} // key -> index in result
	var result []TemplateEntry

	for _, e := range entries {
		if e.EnvKey == "" {
			continue // skip unexpanded include directives
		}
		if idx, exists := seen[e.EnvKey]; exists {
			result[idx] = e // overwrite earlier occurrence
		} else {
			seen[e.EnvKey] = len(result)
			result = append(result, e)
		}
	}
	return result
}

// ResolveProfileVarsInEntries resolves {{profile:...}} variables in KMS ref paths and keys.
// Call this after ResolveTemplateWithIncludes and before secret resolution.
func ResolveProfileVarsInEntries(entries []TemplateEntry, profile Profile) ([]TemplateEntry, error) {
	if profile == nil {
		return entries, nil
	}
	result := make([]TemplateEntry, len(entries))
	copy(result, entries)

	for i, e := range result {
		if e.IsKMSRef {
			resolvedPath, err := profile.Resolve(e.Ref.Path)
			if err != nil {
				return nil, fmt.Errorf("entry %q path: %w", e.EnvKey, err)
			}
			resolvedKey, err := profile.Resolve(e.Ref.Key)
			if err != nil {
				return nil, fmt.Errorf("entry %q key: %w", e.EnvKey, err)
			}
			result[i].Ref.Path = resolvedPath
			result[i].Ref.Key = resolvedKey
		} else {
			// Plain value — resolve profile variables in the value itself.
			resolvedValue, err := profile.Resolve(string(e.PlainValue))
			if err != nil {
				return nil, fmt.Errorf("entry %q value: %w", e.EnvKey, err)
			}
			result[i].PlainValue = []byte(resolvedValue)
		}
	}
	return result, nil
}

// findIncludeTemplate locates a template file by logical path.
// Checks project templates (.kpm/templates/) then user templates (ConfigDir/templates/).
// Appends .template suffix if not present.
func findIncludeTemplate(path string) string {
	if !strings.HasSuffix(path, ".template") {
		path = path + ".template"
	}

	// Check project templates first (higher priority)
	projectPath := filepath.Join(ProjectTemplatesDir(), path)
	if _, err := os.Stat(projectPath); err == nil {
		return projectPath
	}

	// Check user templates
	userPath := filepath.Join(TemplatesDir(), path)
	if _, err := os.Stat(userPath); err == nil {
		return userPath
	}

	return ""
}
