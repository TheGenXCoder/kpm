package kpm

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverTemplateProjectLevel(t *testing.T) {
	dir := t.TempDir()
	tmplDir := filepath.Join(dir, ".kpm", "templates")
	os.MkdirAll(tmplDir, 0755)
	templateFile := filepath.Join(tmplDir, "myapp.template")
	os.WriteFile(templateFile, []byte("content"), 0644)

	origDir, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(origDir)

	// Also set KPM_CONFIG to a temp dir so the user-level path doesn't interfere
	t.Setenv("KPM_CONFIG", t.TempDir())

	result := DiscoverTemplate("myapp")
	// Use EvalSymlinks for macOS /var -> /private/var comparison
	resultResolved, _ := filepath.EvalSymlinks(result)
	expectedResolved, _ := filepath.EvalSymlinks(templateFile)
	if resultResolved != expectedResolved {
		t.Errorf("DiscoverTemplate = %q, want %q", result, templateFile)
	}
}

func TestDiscoverTemplateUserLevelFlat(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("KPM_CONFIG", configDir)

	userTmplDir := filepath.Join(configDir, "templates")
	os.MkdirAll(userTmplDir, 0755)
	os.WriteFile(filepath.Join(userTmplDir, "claude.template"), []byte("content"), 0644)

	// Change to a directory without project-level templates
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(origDir)

	result := DiscoverTemplate("claude")
	if result != filepath.Join(userTmplDir, "claude.template") {
		t.Errorf("DiscoverTemplate = %q, want %q", result, filepath.Join(userTmplDir, "claude.template"))
	}
}

func TestDiscoverTemplateUserLevelSubdir(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("KPM_CONFIG", configDir)

	// Put template in ai/ subdir
	aiDir := filepath.Join(configDir, "templates", "ai")
	os.MkdirAll(aiDir, 0755)
	os.WriteFile(filepath.Join(aiDir, "gpt.template"), []byte("content"), 0644)

	dir := t.TempDir()
	origDir, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(origDir)

	result := DiscoverTemplate("gpt")
	if result != filepath.Join(aiDir, "gpt.template") {
		t.Errorf("DiscoverTemplate = %q, want %q", result, filepath.Join(aiDir, "gpt.template"))
	}
}

func TestDiscoverTemplateNotFound(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("KPM_CONFIG", configDir)

	dir := t.TempDir()
	origDir, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(origDir)

	result := DiscoverTemplate("does-not-exist")
	if result != "" {
		t.Errorf("DiscoverTemplate = %q, want empty string", result)
	}
}

func TestDiscoverTemplateProjectOverridesUser(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("KPM_CONFIG", configDir)

	// User-level template
	userTmplDir := filepath.Join(configDir, "templates")
	os.MkdirAll(userTmplDir, 0755)
	os.WriteFile(filepath.Join(userTmplDir, "myapp.template"), []byte("user-level"), 0644)

	// Project-level template in same dir
	dir := t.TempDir()
	projectTmplDir := filepath.Join(dir, ".kpm", "templates")
	os.MkdirAll(projectTmplDir, 0755)
	projectFile := filepath.Join(projectTmplDir, "myapp.template")
	os.WriteFile(projectFile, []byte("project-level"), 0644)

	origDir, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(origDir)

	result := DiscoverTemplate("myapp")
	// Use EvalSymlinks for macOS /var -> /private/var comparison
	resultResolved, _ := filepath.EvalSymlinks(result)
	expectedResolved, _ := filepath.EvalSymlinks(projectFile)
	if resultResolved != expectedResolved {
		t.Errorf("project level should override user level, got %q (want %q)", result, projectFile)
	}
}

func TestDiscoverTemplateInfraSubdir(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("KPM_CONFIG", configDir)

	infraDir := filepath.Join(configDir, "templates", "infra")
	os.MkdirAll(infraDir, 0755)
	os.WriteFile(filepath.Join(infraDir, "k8s.template"), []byte("content"), 0644)

	dir := t.TempDir()
	origDir, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(origDir)

	result := DiscoverTemplate("k8s")
	if result != filepath.Join(infraDir, "k8s.template") {
		t.Errorf("expected infra subdir template, got %q", result)
	}
}
