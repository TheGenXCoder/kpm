package kpm

import (
	"bufio"
	"fmt"
	"io"
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
