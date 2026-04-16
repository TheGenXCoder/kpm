package kpm

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigDirXDG(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // Windows compat
	t.Setenv("KPM_CONFIG", "")
	t.Setenv("XDG_CONFIG_HOME", "")

	// No dirs exist — should default to XDG
	dir := ConfigDir()
	if !filepath.IsAbs(dir) {
		t.Errorf("expected absolute path, got %q", dir)
	}
}

func TestConfigDirLegacyFallback(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("KPM_CONFIG", "")
	t.Setenv("XDG_CONFIG_HOME", "")

	// Create legacy dir only (no XDG dir)
	legacy := filepath.Join(home, ".kpm")
	os.MkdirAll(legacy, 0755)

	dir := ConfigDir()
	if dir != legacy {
		t.Errorf("expected legacy %q, got %q", legacy, dir)
	}
}

func TestConfigDirXDGPreferredOverLegacy(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("KPM_CONFIG", "")
	t.Setenv("XDG_CONFIG_HOME", "")

	// Create both dirs — XDG default should win
	xdg := filepath.Join(home, ".config", "kpm")
	os.MkdirAll(xdg, 0755)
	legacy := filepath.Join(home, ".kpm")
	os.MkdirAll(legacy, 0755)

	dir := ConfigDir()
	if dir != xdg {
		t.Errorf("expected XDG %q, got %q", xdg, dir)
	}
}

func TestConfigDirEnvOverride(t *testing.T) {
	custom := t.TempDir()
	t.Setenv("KPM_CONFIG", custom)

	dir := ConfigDir()
	if dir != custom {
		t.Errorf("expected %q, got %q", custom, dir)
	}
}

func TestConfigDirXDGHomeEnvOverride(t *testing.T) {
	home := t.TempDir()
	xdgHome := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("KPM_CONFIG", "")

	// Create the XDG_CONFIG_HOME/kpm dir
	xdgKpm := filepath.Join(xdgHome, "kpm")
	os.MkdirAll(xdgKpm, 0755)
	t.Setenv("XDG_CONFIG_HOME", xdgHome)

	dir := ConfigDir()
	if dir != xdgKpm {
		t.Errorf("expected XDG_CONFIG_HOME/kpm %q, got %q", xdgKpm, dir)
	}
}

func TestDataDirXDG(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("KPM_DATA", "")
	t.Setenv("XDG_DATA_HOME", "")

	dir := DataDir()
	if !filepath.IsAbs(dir) {
		t.Errorf("expected absolute path, got %q", dir)
	}
}

func TestDataDirLegacyFallback(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("KPM_DATA", "")
	t.Setenv("XDG_DATA_HOME", "")

	legacy := filepath.Join(home, ".kpm")
	os.MkdirAll(legacy, 0755)

	dir := DataDir()
	if dir != legacy {
		t.Errorf("expected legacy %q, got %q", legacy, dir)
	}
}

func TestDataDirEnvOverride(t *testing.T) {
	custom := t.TempDir()
	t.Setenv("KPM_DATA", custom)

	dir := DataDir()
	if dir != custom {
		t.Errorf("expected %q, got %q", custom, dir)
	}
}

func TestTemplatesDir(t *testing.T) {
	custom := t.TempDir()
	t.Setenv("KPM_CONFIG", custom)

	dir := TemplatesDir()
	expected := filepath.Join(custom, "templates")
	if dir != expected {
		t.Errorf("expected %q, got %q", expected, dir)
	}
}

func TestCertsDir(t *testing.T) {
	custom := t.TempDir()
	t.Setenv("KPM_DATA", custom)

	dir := CertsDir()
	expected := filepath.Join(custom, "certs")
	if dir != expected {
		t.Errorf("expected %q, got %q", expected, dir)
	}
}

func TestSessionsDir(t *testing.T) {
	custom := t.TempDir()
	t.Setenv("KPM_DATA", custom)

	dir := SessionsDir()
	expected := filepath.Join(custom, "sessions")
	if dir != expected {
		t.Errorf("expected %q, got %q", expected, dir)
	}
}
