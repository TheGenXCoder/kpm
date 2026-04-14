package kpm

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	yaml := `server: https://agentkms.local:8443
cert: /tmp/client.crt
key: /tmp/client.key
ca: /tmp/ca.crt
default_template: .env.template
secure_mode: true
session_key_ttl: 120
`
	if err := os.WriteFile(cfgPath, []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Server != "https://agentkms.local:8443" {
		t.Errorf("Server = %q, want https://agentkms.local:8443", cfg.Server)
	}
	if cfg.SessionKeyTTL != 120 {
		t.Errorf("SessionKeyTTL = %d, want 120", cfg.SessionKeyTTL)
	}
	if !cfg.SecureMode {
		t.Error("SecureMode should be true")
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("server: https://localhost:8443\n"), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.SessionKeyTTL != 3600 {
		t.Errorf("default SessionKeyTTL = %d, want 3600", cfg.SessionKeyTTL)
	}
	if cfg.DefaultTemplate != ".env.template" {
		t.Errorf("default DefaultTemplate = %q, want .env.template", cfg.DefaultTemplate)
	}
}

func TestLoadConfigMissing(t *testing.T) {
	_, err := LoadConfig("/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing config")
	}
}
