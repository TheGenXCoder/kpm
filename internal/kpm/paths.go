package kpm

import (
	"os"
	"path/filepath"
	"strings"
)

// ConfigDir returns the KPM config directory.
// Resolution: $KPM_CONFIG (if directory) > $XDG_CONFIG_HOME/kpm > ~/.config/kpm > ~/.kpm (legacy)
//
// Note: If $KPM_CONFIG points to a file (e.g. ~/.kpm/config-odev.yaml), use
// DefaultConfigPath() instead — it will return the file directly.
func ConfigDir() string {
	if d := os.Getenv("KPM_CONFIG"); d != "" {
		// If it looks like a file path (has extension or exists as file), treat
		// the parent as the config dir for other things (certs, templates).
		if strings.HasSuffix(d, ".yaml") || strings.HasSuffix(d, ".yml") {
			if fi, err := os.Stat(d); err == nil && !fi.IsDir() {
				return filepath.Dir(d)
			}
		}
		// Otherwise treat as directory (old behavior)
		return d
	}
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		p := filepath.Join(d, "kpm")
		if dirExists(p) {
			return p
		}
	}
	home, _ := os.UserHomeDir()

	// Check XDG default
	xdg := filepath.Join(home, ".config", "kpm")
	if dirExists(xdg) {
		return xdg
	}

	// Legacy fallback
	legacy := filepath.Join(home, ".kpm")
	if dirExists(legacy) {
		return legacy
	}

	// Default to XDG for new installs
	return xdg
}

// DataDir returns the KPM data directory (certs, sessions).
// Resolution: $KPM_DATA > $XDG_DATA_HOME/kpm > ~/.local/share/kpm > ~/.kpm (legacy)
func DataDir() string {
	if d := os.Getenv("KPM_DATA"); d != "" {
		return d
	}
	if d := os.Getenv("XDG_DATA_HOME"); d != "" {
		p := filepath.Join(d, "kpm")
		if dirExists(p) {
			return p
		}
	}
	home, _ := os.UserHomeDir()

	xdg := filepath.Join(home, ".local", "share", "kpm")
	if dirExists(xdg) {
		return xdg
	}

	legacy := filepath.Join(home, ".kpm")
	if dirExists(legacy) {
		return legacy
	}

	return xdg
}

// TemplatesDir returns the user-level templates directory.
func TemplatesDir() string {
	return filepath.Join(ConfigDir(), "templates")
}

// CertsDir returns the certs directory.
func CertsDir() string {
	return filepath.Join(DataDir(), "certs")
}

// SessionsDir returns the sessions directory.
func SessionsDir() string {
	return filepath.Join(DataDir(), "sessions")
}

// ProjectTemplatesDir returns the project-level templates directory (from cwd).
func ProjectTemplatesDir() string {
	cwd, _ := os.Getwd()
	return filepath.Join(cwd, ".kpm", "templates")
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
