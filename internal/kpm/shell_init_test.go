package kpm

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestShellInitBash(t *testing.T) {
	// Create a fake config dir so shell-init doesn't bail
	home := t.TempDir()
	t.Setenv("KPM_CONFIG", home)
	os.WriteFile(filepath.Join(home, "config.yaml"), []byte("server: test\n"), 0644)

	var buf bytes.Buffer
	ShellInit(&buf, "bash")

	out := buf.String()
	if !strings.Contains(out, "KPM_LOADED=1") {
		t.Errorf("missing KPM_LOADED marker in bash output:\n%s", out)
	}
	if !strings.Contains(out, "kpm env") {
		t.Errorf("missing kpm env call in bash output:\n%s", out)
	}
}

func TestShellInitZsh(t *testing.T) {
	home := t.TempDir()
	t.Setenv("KPM_CONFIG", home)
	os.WriteFile(filepath.Join(home, "config.yaml"), []byte("server: test\n"), 0644)

	var buf bytes.Buffer
	ShellInit(&buf, "zsh")

	out := buf.String()
	if !strings.Contains(out, "KPM_LOADED=1") {
		t.Errorf("missing KPM_LOADED marker in zsh output:\n%s", out)
	}
}

func TestShellInitFish(t *testing.T) {
	home := t.TempDir()
	t.Setenv("KPM_CONFIG", home)
	os.WriteFile(filepath.Join(home, "config.yaml"), []byte("server: test\n"), 0644)

	var buf bytes.Buffer
	ShellInit(&buf, "fish")

	out := buf.String()
	if !strings.Contains(out, "set -gx KPM_LOADED") {
		t.Errorf("missing fish KPM_LOADED in output:\n%s", out)
	}
	if !strings.Contains(out, "kpm env") {
		t.Errorf("missing kpm env call in fish output:\n%s", out)
	}
}

func TestShellInitUnknownShellFallsBackToPosix(t *testing.T) {
	home := t.TempDir()
	t.Setenv("KPM_CONFIG", home)
	os.WriteFile(filepath.Join(home, "config.yaml"), []byte("server: test\n"), 0644)

	var buf bytes.Buffer
	ShellInit(&buf, "tcsh")

	out := buf.String()
	// Unknown shells fall back to POSIX format
	if !strings.Contains(out, "KPM_LOADED=1") {
		t.Errorf("unknown shell should fall back to posix hook:\n%s", out)
	}
}

func TestShellInitNotConfigured(t *testing.T) {
	home := t.TempDir()
	t.Setenv("KPM_CONFIG", home)
	// Don't create config.yaml

	var buf bytes.Buffer
	ShellInit(&buf, "bash")

	// Should output nothing to stdout (warning goes to stderr)
	if buf.Len() > 0 {
		t.Errorf("should output nothing when not configured, got: %s", buf.String())
	}
}

func TestShellInitAutoDetectsShell(t *testing.T) {
	home := t.TempDir()
	t.Setenv("KPM_CONFIG", home)
	t.Setenv("SHELL", "/bin/zsh")
	os.WriteFile(filepath.Join(home, "config.yaml"), []byte("server: test\n"), 0644)

	var buf bytes.Buffer
	ShellInit(&buf, "") // empty shell — should auto-detect from $SHELL

	out := buf.String()
	if !strings.Contains(out, "KPM_LOADED=1") {
		t.Errorf("auto-detected shell should produce POSIX hook:\n%s", out)
	}
}

func TestShellInitTemplatePathInOutput(t *testing.T) {
	home := t.TempDir()
	t.Setenv("KPM_CONFIG", home)
	os.WriteFile(filepath.Join(home, "config.yaml"), []byte("server: test\n"), 0644)

	var buf bytes.Buffer
	ShellInit(&buf, "bash")

	out := buf.String()
	expectedPath := filepath.Join(home, "templates", "shell-env.template")
	if !strings.Contains(out, expectedPath) {
		t.Errorf("expected template path %q in output:\n%s", expectedPath, out)
	}
}
