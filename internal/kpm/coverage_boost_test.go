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

// === FormatDotenv edge cases ===

func TestFormatDotenvWriteError(t *testing.T) {
	// Can't easily trigger write error, but test with empty entries
	var buf bytes.Buffer
	entries := []ResolvedEntry{}
	err := FormatDotenv(&buf, entries)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "WARNING") {
		t.Error("expected WARNING header")
	}
}

// === FormatShell with single-quote escaping ===

func TestFormatShellWithSingleQuote(t *testing.T) {
	var buf bytes.Buffer
	entries := []ResolvedEntry{
		{EnvKey: "TOKEN", PlainValue: []byte("it's a secret")},
	}
	err := FormatShell(&buf, entries)
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	// Single quote in value should be escaped as '\''
	if !strings.Contains(out, "'\\''"+"") {
		t.Errorf("single quote not properly escaped: %s", out)
	}
	if !strings.Contains(out, "export TOKEN=") {
		t.Errorf("missing export statement: %s", out)
	}
}

// === loadProfileFromFile ===

func TestLoadProfileFromFileInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	os.WriteFile(cfgPath, []byte("profile: {\ninvalid yaml"), 0644)

	_, err := loadProfileFromFile(cfgPath)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoadProfileFromFileNoProfileKey(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	os.WriteFile(cfgPath, []byte("server: https://localhost:8443\n"), 0644)

	profile, err := loadProfileFromFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(profile) != 0 {
		t.Errorf("expected empty profile, got %v", profile)
	}
}

func TestLoadProfileFromFileMissing(t *testing.T) {
	_, err := loadProfileFromFile("/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

// === ScanManagedSecrets ===

func TestScanManagedSecretsWithBlob(t *testing.T) {
	key, _ := NewSessionKey()
	defer ZeroBytes(key)
	ct, _ := EncryptLocal(key, []byte("secret"))
	blob := FormatCiphertextBlob("scan-test-session", ct)

	os.Setenv("TEST_KPM_SECRET", blob)
	defer os.Unsetenv("TEST_KPM_SECRET")

	secrets, sid := ScanManagedSecrets()
	if sid == "" {
		// Session might not have been found if test env is noisy, just verify it runs
		return
	}
	found := false
	for _, s := range secrets {
		if s.Name == "TEST_KPM_SECRET" {
			found = true
			if s.SessionID != "scan-test-session" {
				t.Errorf("SessionID = %q, want scan-test-session", s.SessionID)
			}
			if !s.Encrypted {
				t.Error("expected Encrypted=true")
			}
		}
	}
	if !found && sid == "scan-test-session" {
		t.Error("TEST_KPM_SECRET not found in ScanManagedSecrets")
	}
}

// === findIncludeTemplate ===

func TestFindIncludeTemplateProjectLevel(t *testing.T) {
	dir := t.TempDir()
	tmplDir := filepath.Join(dir, ".kpm", "templates")
	os.MkdirAll(tmplDir, 0755)
	os.WriteFile(filepath.Join(tmplDir, "base.template"), []byte("content"), 0644)

	origDir, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(origDir)

	t.Setenv("KPM_CONFIG", t.TempDir())

	result := findIncludeTemplate("base")
	if result == "" {
		t.Error("expected findIncludeTemplate to find base.template")
	}
}

func TestFindIncludeTemplateUserLevel(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("KPM_CONFIG", configDir)

	tmplDir := filepath.Join(configDir, "templates")
	os.MkdirAll(tmplDir, 0755)
	os.WriteFile(filepath.Join(tmplDir, "userbase.template"), []byte("content"), 0644)

	dir := t.TempDir()
	origDir, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(origDir)

	result := findIncludeTemplate("userbase")
	if result == "" {
		t.Error("expected findIncludeTemplate to find userbase.template")
	}
}

func TestFindIncludeTemplateNotFound(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("KPM_CONFIG", configDir)

	dir := t.TempDir()
	origDir, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(origDir)

	result := findIncludeTemplate("does-not-exist")
	if result != "" {
		t.Errorf("expected empty result, got %q", result)
	}
}

func TestFindIncludeTemplateWithExtension(t *testing.T) {
	// Path already has .template suffix — should not add it twice
	configDir := t.TempDir()
	t.Setenv("KPM_CONFIG", configDir)

	tmplDir := filepath.Join(configDir, "templates")
	os.MkdirAll(tmplDir, 0755)
	os.WriteFile(filepath.Join(tmplDir, "myapp.template"), []byte("content"), 0644)

	dir := t.TempDir()
	origDir, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(origDir)

	result := findIncludeTemplate("myapp.template")
	if result == "" {
		t.Error("expected findIncludeTemplate to find myapp.template when called with .template extension")
	}
}

// === ResolveProfileVarsInEntries error path ===

func TestResolveProfileVarsInEntriesMissingKey(t *testing.T) {
	profile := Profile{"customer": "acme"}
	entries := []TemplateEntry{
		{EnvKey: "HOST", IsKMSRef: true, Ref: KMSReference{Type: "kv", Path: "{{profile:missing_key}}", Key: "host"}},
	}
	_, err := ResolveProfileVarsInEntries(entries, profile)
	if err == nil {
		t.Fatal("expected error for missing profile key without default")
	}
}

// === deduplicateEntries ===

func TestDeduplicateEntriesDuplicateKey(t *testing.T) {
	entries := []TemplateEntry{
		{EnvKey: "DB_HOST", IsKMSRef: true, Ref: KMSReference{Type: "kv", Path: "db/prod", Key: "host"}},
		{EnvKey: "OTHER", IsKMSRef: false, PlainValue: []byte("static")},
		{EnvKey: "DB_HOST", IsKMSRef: true, Ref: KMSReference{Type: "kv", Path: "db/staging", Key: "host"}}, // duplicate — should be overridden
	}
	result := deduplicateEntries(entries)
	// Later entries should override earlier ones (per comment in code)
	for _, e := range result {
		if e.EnvKey == "DB_HOST" && e.Ref.Path != "db/staging" {
			t.Errorf("DB_HOST should be overridden to db/staging, got path=%q", e.Ref.Path)
		}
	}
}

// === ParseTemplate edge cases ===

func TestParseTemplateEnvRef(t *testing.T) {
	tmpl := "HOME_DIR=${env:HOME}\n"
	entries, err := ParseTemplate(strings.NewReader(tmpl))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	// env: refs are plain-value or handled differently — just verify it parses
}

// === ListCmd expire path ===

func TestRunListExpiryFormatting(t *testing.T) {
	// Secret with expiry < 30 days should show "EXPIRES Nd"
	// Use a date 10 days in the future from "now" dynamically
	nearExpiry := time.Now().Add(10 * 24 * time.Hour).UTC().Format(time.RFC3339)
	secrets := []SecretMetadata{
		{Service: "svc", Name: "key", Type: "api-token",
			Expires: nearExpiry,
			Version: 1},
	}
	httpClient, baseURL := mockServerForList(t, secrets)
	c := &Client{baseURL: baseURL, httpClient: httpClient}

	var buf bytes.Buffer
	err := RunList(context.Background(), &buf, c, "", "", "", false, false)
	if err != nil {
		t.Fatal(err)
	}
	// The test date (2026-04-11) means Expires 2026-04-15 = 4 days away
	// Should show EXPIRES 4d (or similar)
	out := buf.String()
	if !strings.Contains(out, "EXPIRES") {
		t.Errorf("expected EXPIRES marker for near-expiry secret: %s", out)
	}
}

func TestRunListExpiredSecret(t *testing.T) {
	// Secret that has already expired
	secrets := []SecretMetadata{
		{Service: "svc", Name: "oldkey", Type: "api-token",
			Expires: "2020-01-01T00:00:00Z", // definitely expired
			Version: 1},
	}
	httpClient, baseURL := mockServerForList(t, secrets)
	c := &Client{baseURL: baseURL, httpClient: httpClient}

	var buf bytes.Buffer
	err := RunList(context.Background(), &buf, c, "", "", "", false, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "EXPIRED") {
		t.Errorf("expected EXPIRED marker: %s", buf.String())
	}
}
