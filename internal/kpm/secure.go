package kpm

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Allowlist holds the parsed secure-allowlist.yaml content.
// Top-level keys are tool names; values are slices of allowed env var names.
type Allowlist struct {
	Tools map[string][]string `yaml:",inline"`
}

// AuditEvent records a single allow/deny decision made by FilterByAllowlistWithAudit.
type AuditEvent struct {
	// ToolName is the tool that was filtered (filepath.Base of argv[0]).
	ToolName string
	// EnvKey is the environment variable name that was evaluated.
	EnvKey string
	// Outcome is "allowed" or "denied".
	Outcome string
}

// allowlistFileName is the canonical file name for the per-tool allow-list.
const allowlistFileName = "secure-allowlist.yaml"

// LoadAllowlist finds and parses the secure-allowlist.yaml for the given tool,
// returning the slice of allowed env var names.
//
// Resolution order (first-wins):
//  1. $KPM_PROJECT_DIR/.kpm/secure-allowlist.yaml  (project-local; uses $KPM_PROJECT_DIR if set, else cwd)
//  2. ConfigDir()/secure-allowlist.yaml             (user-global)
//
// Returns (nil, error) when no allow-list file is found.
// Returns (nil, nil)   when the file exists but the tool has no entry.
// Returns ([]string,nil) when the tool has an entry (may be empty slice if explicitly set to []).
func LoadAllowlist(toolName string) ([]string, error) {
	// Determine project directory.
	projectDir := os.Getenv("KPM_PROJECT_DIR")
	if projectDir == "" {
		projectDir, _ = os.Getwd()
	}

	projectLocal := filepath.Join(projectDir, ".kpm", allowlistFileName)
	userGlobal := filepath.Join(ConfigDir(), allowlistFileName)

	// first-wins: project-local overrides user-global
	var filePath string
	if allowlistFileExists(projectLocal) {
		filePath = projectLocal
	} else if allowlistFileExists(userGlobal) {
		filePath = userGlobal
	} else {
		return nil, fmt.Errorf("--secure requires an allow-list; create .kpm/secure-allowlist.yaml or ~/.config/kpm/secure-allowlist.yaml")
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", allowlistFileName, err)
	}

	var al Allowlist
	al.Tools = make(map[string][]string)
	if err := yaml.Unmarshal(data, &al.Tools); err != nil {
		return nil, fmt.Errorf("parse %s: %w", allowlistFileName, err)
	}

	// Tool not in list → return nil slice, no error.
	// This signals "deny all" to the caller without being an error condition.
	vars, ok := al.Tools[toolName]
	if !ok {
		return nil, nil
	}
	return vars, nil
}

// FilterByAllowlist filters resolved entries by the given allow-list.
//
// Rules:
//   - Non-KMS entries (IsKMSRef=false) always pass through unconditionally.
//   - KMS entries pass only when their EnvKey is in allowed (exact match).
//   - When verbose is true, a kpm_audit line is written to stderr for each KMS entry.
//
// The function does NOT zero excluded entries' PlainValue — that is the caller's
// responsibility via the existing defer pattern.
func FilterByAllowlist(entries []ResolvedEntry, allowed []string, toolName string, verbose bool) []ResolvedEntry {
	filtered, events := filterCore(entries, allowed, toolName)
	if verbose {
		for _, ev := range events {
			if ev.Outcome == "denied" {
				fmt.Fprintf(os.Stderr, "kpm_audit action=secure_filter tool=%s var=%s outcome=denied\n",
					ev.ToolName, ev.EnvKey)
			} else {
				fmt.Fprintf(os.Stderr, "kpm_audit action=secure_allow  tool=%s var=%s outcome=allowed\n",
					ev.ToolName, ev.EnvKey)
			}
		}
	}
	return filtered
}

// FilterByAllowlistWithAudit is the auditable variant of FilterByAllowlist.
// It returns the filtered entries plus a slice of AuditEvent (one per KMS entry evaluated).
// Non-KMS entries are not included in audit events (they always pass through).
func FilterByAllowlistWithAudit(entries []ResolvedEntry, allowed []string, toolName string) ([]ResolvedEntry, []AuditEvent) {
	return filterCore(entries, allowed, toolName)
}

// filterCore is the shared implementation for FilterByAllowlist and FilterByAllowlistWithAudit.
func filterCore(entries []ResolvedEntry, allowed []string, toolName string) ([]ResolvedEntry, []AuditEvent) {
	allowSet := make(map[string]bool, len(allowed))
	for _, v := range allowed {
		allowSet[v] = true
	}

	result := make([]ResolvedEntry, 0, len(entries))
	var events []AuditEvent

	for _, e := range entries {
		// Non-KMS entries always pass through — they carry no KMS-resolved secret.
		if !e.IsKMSRef {
			result = append(result, e)
			continue
		}

		if allowSet[e.EnvKey] {
			result = append(result, e)
			events = append(events, AuditEvent{
				ToolName: toolName,
				EnvKey:   e.EnvKey,
				Outcome:  "allowed",
			})
		} else {
			events = append(events, AuditEvent{
				ToolName: toolName,
				EnvKey:   e.EnvKey,
				Outcome:  "denied",
			})
		}
	}

	return result, events
}

// allowlistFileExists returns true when path exists and is a regular file.
func allowlistFileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
