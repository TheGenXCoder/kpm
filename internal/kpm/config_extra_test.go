package kpm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultConfigPath(t *testing.T) {
	customDir := t.TempDir()
	t.Setenv("KPM_CONFIG", customDir)

	path := DefaultConfigPath()
	expected := filepath.Join(customDir, "config.yaml")
	if path != expected {
		t.Errorf("DefaultConfigPath = %q, want %q", path, expected)
	}
}

func TestExpandHomeWithJustTilde(t *testing.T) {
	home, _ := os.UserHomeDir()
	result := expandHome("~")
	// filepath.Join(home, "") == home
	if result != home {
		t.Errorf("expandHome('~') = %q, want %q", result, home)
	}
}

func TestExpandHomeWithSlashPath(t *testing.T) {
	home, _ := os.UserHomeDir()
	result := expandHome("~/Documents/kpm")
	expected := filepath.Join(home, "/Documents/kpm")
	if result != expected {
		t.Errorf("expandHome('~/Documents/kpm') = %q, want %q", result, expected)
	}
}

func TestExpandHomeAbsolutePassthrough(t *testing.T) {
	abs := "/etc/ssl/certs/ca.crt"
	result := expandHome(abs)
	if result != abs {
		t.Errorf("expandHome with absolute path = %q, want %q", result, abs)
	}
}

func TestExpandHomeEmpty(t *testing.T) {
	result := expandHome("")
	if result != "" {
		t.Errorf("expandHome('') = %q, want empty string", result)
	}
}

func TestExpandHomeNonHomeRelative(t *testing.T) {
	// A path that doesn't start with ~ should pass through unchanged
	result := expandHome("relative/path/to/file")
	if result != "relative/path/to/file" {
		t.Errorf("expandHome('relative/path') = %q, want passthrough", result)
	}
}

func TestExpandHomeTildeOtherUser(t *testing.T) {
	// ~otheruser pattern — first char is ~ but second is not /
	// expandHome only handles "~" prefix without checking what comes after,
	// so ~otheruser gets expanded with home + "otheruser" stripped. Verify
	// behavior is consistent (not that it's correct — it expands naively).
	result := expandHome("~otheruser/data")
	// result will be filepath.Join(home, "otheruser/data") — document actual behavior
	home, _ := os.UserHomeDir()
	expected := filepath.Join(home, "otheruser/data")
	if result != expected {
		t.Errorf("expandHome('~otheruser/data') = %q, want %q", result, expected)
	}
}

func TestLoadConfigExpandsHomePaths(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	yaml := "server: https://localhost:8443\ncert: ~/certs/client.crt\nkey: ~/certs/client.key\nca: ~/certs/ca.crt\n"
	os.WriteFile(cfgPath, []byte(yaml), 0600)

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	// Verify ~ was expanded
	if strings.Contains(cfg.Cert, "~") {
		t.Errorf("Cert still contains ~: %q", cfg.Cert)
	}
	if strings.Contains(cfg.Key, "~") {
		t.Errorf("Key still contains ~: %q", cfg.Key)
	}
	if strings.Contains(cfg.CA, "~") {
		t.Errorf("CA still contains ~: %q", cfg.CA)
	}
}
