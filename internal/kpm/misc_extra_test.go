package kpm

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// === RunCommandWithEnv ===

func TestRunCommandWithEnvSuccess(t *testing.T) {
	env := append(os.Environ(), "KPM_TEST_VAR=hello")
	code, err := RunCommandWithEnv(context.Background(), env, "true", nil)
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
}

func TestRunCommandWithEnvNonZeroExit(t *testing.T) {
	code, err := RunCommandWithEnv(context.Background(), os.Environ(), "false", nil)
	if err != nil {
		t.Fatal(err)
	}
	if code == 0 {
		t.Error("expected non-zero exit code from 'false'")
	}
}

func TestRunCommandWithEnvNotFound(t *testing.T) {
	_, err := RunCommandWithEnv(context.Background(), os.Environ(), "/nonexistent/binary-xyz", nil)
	if err == nil {
		t.Fatal("expected error for nonexistent binary")
	}
}

// === SessionTTLRemaining ===

func TestSessionTTLRemainingNotFound(t *testing.T) {
	// Non-existent session should return 0
	ttl := SessionTTLRemaining("nonexistent-session-id-xyz", 3600)
	if ttl != 0 {
		t.Errorf("SessionTTLRemaining for nonexistent session = %v, want 0", ttl)
	}
}

func TestSessionTTLRemainingActive(t *testing.T) {
	// Create a fake session key file in the expected location
	home, _ := os.UserHomeDir()
	sessionID := "test-session-ttl-123"
	keyDir := filepath.Join(home, ".kpm", "sessions", sessionID)
	keyPath := filepath.Join(keyDir, "key")

	os.MkdirAll(keyDir, 0755)
	os.WriteFile(keyPath, []byte("fake-key-data"), 0600)
	defer os.RemoveAll(keyDir)

	ttl := SessionTTLRemaining(sessionID, 3600)
	if ttl <= 0 {
		t.Errorf("SessionTTLRemaining = %v, want positive duration", ttl)
	}
	if ttl > time.Duration(3600)*time.Second {
		t.Errorf("SessionTTLRemaining = %v, too large (> 3600s)", ttl)
	}
}

func TestSessionTTLRemainingExpired(t *testing.T) {
	// Create a fake session key file with old mtime
	home, _ := os.UserHomeDir()
	sessionID := "test-session-expired-456"
	keyDir := filepath.Join(home, ".kpm", "sessions", sessionID)
	keyPath := filepath.Join(keyDir, "key")

	os.MkdirAll(keyDir, 0755)
	os.WriteFile(keyPath, []byte("fake-key-data"), 0600)
	defer os.RemoveAll(keyDir)

	// Set mtime to 2 hours ago — 1 second TTL means it's expired
	pastTime := time.Now().Add(-2 * time.Hour)
	os.Chtimes(keyPath, pastTime, pastTime)

	ttl := SessionTTLRemaining(sessionID, 1) // 1 second TTL
	if ttl != 0 {
		t.Errorf("SessionTTLRemaining for expired session = %v, want 0", ttl)
	}
}

// === PrintShowWithProfile ===

func TestPrintShowWithProfileNoProfile(t *testing.T) {
	// Change to a temp dir with no .kpm/config.yaml
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(origDir)

	var buf bytes.Buffer
	secrets := []ManagedSecret{
		{Name: "OPENAI_API_KEY", SessionID: "sess123", BlobPreview: "ENC[kpm:...]"},
	}
	PrintShowWithProfile(&buf, secrets, "sess123", 30*time.Second, "")
	out := buf.String()
	if !strings.Contains(out, "OPENAI_API_KEY") {
		t.Errorf("expected OPENAI_API_KEY in output: %s", out)
	}
	// Should show the profile not found message since there's no .kpm/config.yaml
	if !strings.Contains(out, "Profile") {
		t.Errorf("expected 'Profile' section in output: %s", out)
	}
}

func TestPrintShowWithProfileWithProfile(t *testing.T) {
	dir := t.TempDir()
	kpmDir := filepath.Join(dir, ".kpm")
	os.MkdirAll(kpmDir, 0755)
	os.WriteFile(filepath.Join(kpmDir, "config.yaml"), []byte(
		"profile:\n  customer: acme\n  region: us-east\n",
	), 0644)

	origDir, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(origDir)

	var buf bytes.Buffer
	secrets := []ManagedSecret{
		{Name: "DB_PASSWORD", SessionID: "sess456", BlobPreview: "ENC[kpm:...]"},
	}
	PrintShowWithProfile(&buf, secrets, "sess456", 60*time.Second, "")
	out := buf.String()
	if !strings.Contains(out, "DB_PASSWORD") {
		t.Errorf("expected DB_PASSWORD in output: %s", out)
	}
	// Should show profile section
	if !strings.Contains(out, "Profile") {
		t.Errorf("expected 'Profile' section in output: %s", out)
	}
}

// === DiscoverTemplateLevels ===

func TestDiscoverTemplateLevels(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("KPM_CONFIG", configDir)

	dir := t.TempDir()
	origDir, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(origDir)

	levels := DiscoverTemplateLevels()
	if len(levels) == 0 {
		t.Fatal("expected at least one template level")
	}

	// Should always have User and Project levels
	hasUser := false
	hasProject := false
	for _, l := range levels {
		if l.Label == "User" {
			hasUser = true
		}
		if l.Label == "Project" {
			hasProject = true
		}
	}
	if !hasUser {
		t.Error("expected 'User' level in DiscoverTemplateLevels")
	}
	if !hasProject {
		t.Error("expected 'Project' level in DiscoverTemplateLevels")
	}
}

func TestDiscoverTemplateLevelsDeduplication(t *testing.T) {
	// When two levels resolve to the same path, deduplication removes the duplicate
	dir := t.TempDir()
	t.Setenv("KPM_CONFIG", filepath.Join(dir, ".kpm"))

	origDir, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(origDir)

	levels := DiscoverTemplateLevels()
	// Check that no two levels have the same directory path
	seen := map[string]bool{}
	for _, l := range levels {
		abs, _ := filepath.Abs(l.Dir)
		if seen[abs] {
			t.Errorf("duplicate level directory %q in DiscoverTemplateLevels", abs)
		}
		seen[abs] = true
	}
}

// === LoadProfileWithSources ===

func TestLoadProfileWithSourcesNoConfig(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(origDir)

	sources := LoadProfileWithSources()
	// With no .kpm/config.yaml in the path, should return empty or nil
	if sources == nil {
		sources = map[string]ProfileSource{}
	}
	// No error — empty map is fine
	_ = sources
}

func TestLoadProfileWithSourcesWithConfig(t *testing.T) {
	dir := t.TempDir()
	kpmDir := filepath.Join(dir, ".kpm")
	os.MkdirAll(kpmDir, 0755)
	os.WriteFile(filepath.Join(kpmDir, "config.yaml"), []byte(
		"profile:\n  customer: testcorp\n  region: eu-west\n",
	), 0644)

	origDir, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(origDir)

	sources := LoadProfileWithSources()
	if sources == nil {
		t.Fatal("expected non-nil sources")
	}
	if _, ok := sources["customer"]; !ok {
		t.Error("expected 'customer' key in profile sources")
	}
	if sources["customer"].Value != "testcorp" {
		t.Errorf("customer = %q, want testcorp", sources["customer"].Value)
	}
}

// === PushTemplates ===

func TestPushTemplatesEmptyDir(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	err := PushTemplates(&buf, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "0 template(s) pushed") {
		t.Errorf("expected '0 template(s) pushed' in output: %s", buf.String())
	}
}

func TestPushTemplatesNonExistentDir(t *testing.T) {
	var buf bytes.Buffer
	err := PushTemplates(&buf, "/nonexistent/templates/dir")
	if err == nil {
		t.Fatal("expected error for nonexistent directory")
	}
}

func TestPushTemplatesSkipsNonTemplateFiles(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "README.md"), []byte("docs"), 0644)
	os.WriteFile(filepath.Join(dir, "config.json"), []byte("{}"), 0644)

	var buf bytes.Buffer
	err := PushTemplates(&buf, dir)
	if err != nil {
		t.Fatal(err)
	}
	// No .template files = 0 pushed
	if !strings.Contains(buf.String(), "0 template(s) pushed") {
		t.Errorf("expected '0 template(s) pushed': %s", buf.String())
	}
}

func TestPushTemplatesWithTemplateFiles(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "myapp.template"), []byte("MYKEY=${kms:kv/myapp#key}\n"), 0644)

	var buf bytes.Buffer
	// PushTemplates calls `agentkms-dev` binary which likely doesn't exist in test env.
	// The function handles this by printing a warning and continuing.
	err := PushTemplates(&buf, dir)
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	// Either pushed successfully, or printed a warning about the missing binary
	// Either way the function returns nil — we just verify it ran
	if !strings.Contains(out, "template(s) pushed") {
		t.Errorf("expected 'template(s) pushed' in output: %s", out)
	}
}
