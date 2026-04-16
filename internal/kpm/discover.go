package kpm

import (
	"os"
	"path/filepath"
)

// DiscoverTemplate finds a template by command name.
// Resolution order:
//  1. Project-level: .kpm/templates/<cmd>.template (from cwd)
//  2. User-level flat: <ConfigDir>/templates/<cmd>.template
//  3. User-level subdirectories: ai/, infra/, db/, customers/
//
// Returns the first matching path, or "" if none found.
func DiscoverTemplate(cmdName string) string {
	filename := cmdName + ".template"

	// 1. Project level
	projectPath := filepath.Join(ProjectTemplatesDir(), filename)
	if fileExists(projectPath) {
		return projectPath
	}

	// 2. User level (flat)
	userPath := filepath.Join(TemplatesDir(), filename)
	if fileExists(userPath) {
		return userPath
	}

	// 3. User level subdirectories
	subdirs := []string{"ai", "infra", "db", "customers"}
	for _, sub := range subdirs {
		subPath := filepath.Join(TemplatesDir(), sub, filename)
		if fileExists(subPath) {
			return subPath
		}
	}

	return ""
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
