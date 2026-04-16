package kpm

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProjectTemplatesDir(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(origDir)

	result := ProjectTemplatesDir()
	expected := filepath.Join(dir, ".kpm", "templates")
	// Resolve symlinks for comparison (macOS /var -> /private/var)
	resultResolved, _ := filepath.EvalSymlinks(filepath.Dir(result))
	expectedResolved, _ := filepath.EvalSymlinks(filepath.Dir(expected))
	if resultResolved != expectedResolved {
		t.Errorf("ProjectTemplatesDir = %q, want %q", result, expected)
	}
}

func TestDataDirXDGHomeEnvOverride(t *testing.T) {
	home := t.TempDir()
	xdgHome := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("KPM_DATA", "")

	// Create the XDG_DATA_HOME/kpm dir
	xdgKpm := filepath.Join(xdgHome, "kpm")
	os.MkdirAll(xdgKpm, 0755)
	t.Setenv("XDG_DATA_HOME", xdgHome)

	dir := DataDir()
	if dir != xdgKpm {
		t.Errorf("DataDir XDG_DATA_HOME/kpm = %q, want %q", dir, xdgKpm)
	}
}

func TestDataDirXDGPreferredOverLegacy(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("KPM_DATA", "")
	t.Setenv("XDG_DATA_HOME", "")

	// Create both dirs — XDG default should win
	xdg := filepath.Join(home, ".local", "share", "kpm")
	os.MkdirAll(xdg, 0755)
	legacy := filepath.Join(home, ".kpm")
	os.MkdirAll(legacy, 0755)

	dir := DataDir()
	if dir != xdg {
		t.Errorf("DataDir expected XDG %q, got %q", xdg, dir)
	}
}

func TestConfigDirXDGHomeNoDir(t *testing.T) {
	// XDG_CONFIG_HOME is set, but the kpm subdir doesn't exist
	// Should fall through to the default XDG path
	home := t.TempDir()
	xdgHome := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("KPM_CONFIG", "")
	t.Setenv("XDG_CONFIG_HOME", xdgHome)
	// Do NOT create xdgHome/kpm

	dir := ConfigDir()
	// Should not be xdgHome/kpm (doesn't exist), should be XDG default
	expected := filepath.Join(home, ".config", "kpm")
	if dir != expected {
		t.Errorf("ConfigDir without XDG dir = %q, want %q", dir, expected)
	}
}

func TestDataDirXDGHomeNoDir(t *testing.T) {
	home := t.TempDir()
	xdgHome := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("KPM_DATA", "")
	t.Setenv("XDG_DATA_HOME", xdgHome)
	// Do NOT create xdgHome/kpm

	dir := DataDir()
	expected := filepath.Join(home, ".local", "share", "kpm")
	if dir != expected {
		t.Errorf("DataDir without XDG dir = %q, want %q", dir, expected)
	}
}
