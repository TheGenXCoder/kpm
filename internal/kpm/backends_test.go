package kpm

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSplitBackendRef(t *testing.T) {
	tests := []struct {
		in          string
		wantBackend string
		wantRest    string
	}{
		{"@mstr/uta/sandbox/foo", "mstr", "uta/sandbox/foo"},
		{"@local/cloudflare/token", "local", "cloudflare/token"},
		{"cloudflare/token", "", "cloudflare/token"},
		{"@mstr", "mstr", ""},
	}
	for _, tt := range tests {
		b, r := SplitBackendRef(tt.in)
		if b != tt.wantBackend || r != tt.wantRest {
			t.Errorf("SplitBackendRef(%q) = (%q, %q), want (%q, %q)", tt.in, b, r, tt.wantBackend, tt.wantRest)
		}
	}
}

func TestFinalizeBackends(t *testing.T) {
	cfg := &Config{
		DefaultBackend: "mstr",
		SessionKeyTTL:  3600,
		StepUpTTL:      300,
		CacheTTLSec:    900,
		Backends: map[string]*BackendConfig{
			"mstr": {Server: "https://agentkms-mstr.example.com"},
			"uta":  {Server: "https://agentkms-uta.example.com"},
		},
	}
	if err := cfg.FinalizeBackends(); err != nil {
		t.Fatal(err)
	}
	mstr, err := cfg.ConfigForBackend("mstr")
	if err != nil || mstr.Server != "https://agentkms-mstr.example.com" {
		t.Fatalf("mstr backend: %+v err=%v", mstr, err)
	}
	def, err := cfg.ConfigForBackend("")
	if err != nil || def.Server != mstr.Server {
		t.Fatalf("default backend should be mstr")
	}
	if _, err := cfg.ConfigForBackend("nope"); err == nil {
		t.Fatal("expected error for unknown backend")
	}
}

func TestLoadConfigBackendsWithCerts(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	yaml := `default_backend: mstr
backends:
  mstr:
    server: https://localhost:8443
    cert: ~/.kpm/certs/client.crt
    key: ~/.kpm/certs/client.key
    ca: ~/.kpm/certs/ca.crt
  local:
    server: https://127.0.0.1:8443
session_key_ttl: 3600
`
	if err := os.WriteFile(cfgPath, []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	sub, err := cfg.ConfigForBackend("")
	if err != nil {
		t.Fatalf("ConfigForBackend: %v", err)
	}
	if sub.Cert == "" || sub.Key == "" || sub.CA == "" {
		t.Fatalf("expected cert paths on default backend, got cert=%q key=%q ca=%q", sub.Cert, sub.Key, sub.CA)
	}
}
