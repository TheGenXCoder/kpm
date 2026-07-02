package kpm

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// RunLoginWithInvite implements `kpm login <invitecode>`.
func RunLoginWithInvite(ctx context.Context, stdout, stderr io.Writer, inviteCode string) int {
	payload, err := DecodeInvite(inviteCode)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	caPEM, err := FetchAndPinCA(ctx, payload.ServerURL, payload.CAFingerprint)
	if err != nil {
		fmt.Fprintf(stderr, "error: CA pin verification failed: %v\n", err)
		return 1
	}

	identityDir, err := IdentityDir(payload.ServerURL)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	if err := os.MkdirAll(identityDir, 0700); err != nil {
		fmt.Fprintf(stderr, "error: create identity dir: %v\n", err)
		return 1
	}
	caPath := filepath.Join(identityDir, "ca.crt")
	if err := os.WriteFile(caPath, caPEM, 0644); err != nil {
		fmt.Fprintf(stderr, "error: write CA: %v\n", err)
		return 1
	}

	tenant := payload.Tenant
	if tenant == "" {
		tenant = "catalyst9"
	}
	cfg := &Config{
		Server:      payload.ServerURL,
		CA:          caPath,
		TrustDomain: "catalyst9.local",
		Tenant:      tenant,
	}

	client, err := NewClientCAOnly(cfg.Server, cfg.CA)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	// Flags must precede the positional token (flag.Parse stops at the first
	// non-flag argument).
	enrollArgs := []string{"--force"}
	if payload.UserID != "" {
		enrollArgs = append(enrollArgs, "--user", payload.UserID)
	}
	enrollArgs = append(enrollArgs, payload.Token)
	if code := RunEnroll(ctx, stdout, stderr, &ClientEnrollAdapter{C: client}, identityDir, cfg, enrollArgs); code != 0 {
		return code
	}

	// Write minimal config (server only — cert paths resolved from identity dir).
	if err := WriteLoginConfig(payload.ServerURL, tenant); err != nil {
		fmt.Fprintf(stderr, "error: write config: %v\n", err)
		return 1
	}

	// Load full config with resolved identity paths for session login.
	fullCfg, err := LoadConfig(DefaultConfigPath())
	if err != nil {
		fmt.Fprintf(stderr, "error: load config: %v\n", err)
		return 1
	}
	fullClient, err := NewClient(fullCfg.Server, fullCfg.CA, fullCfg.Cert, fullCfg.Key)
	if err != nil {
		fmt.Fprintf(stderr, "error: build client: %v\n", err)
		return 1
	}
	if err := RunLogin(ctx, stderr, fullClient); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

// FetchAndPinCA downloads the CA from /.well-known/agentkms-ca and verifies SHA-256 pin.
func FetchAndPinCA(ctx context.Context, serverURL, fingerprint string) ([]byte, error) {
	fingerprint = strings.ToLower(strings.TrimSpace(fingerprint))
	u, err := url.Parse(strings.TrimRight(serverURL, "/"))
	if err != nil {
		return nil, err
	}
	caURL := u.String() + "/.well-known/agentkms-ca"

	// First hop: fetch CA over TLS without trusting the server cert yet.
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // pin verified below
	}
	client := &http.Client{Timeout: 15 * time.Second, Transport: tr}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, caURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch CA: HTTP %d", resp.StatusCode)
	}
	caPEM, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(caPEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM in CA response")
	}
	sum := sha256.Sum256(block.Bytes)
	got := hex.EncodeToString(sum[:])
	if got != fingerprint {
		return nil, fmt.Errorf("CA fingerprint mismatch (got %s, expected %s)", got, fingerprint)
	}
	return caPEM, nil
}

// WriteLoginConfig writes ~/.kpm/config.yaml with server-only fields.
func WriteLoginConfig(serverURL, tenant string) error {
	path := DefaultConfigPath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	if tenant == "" {
		tenant = "catalyst9"
	}
	content := fmt.Sprintf(`server: %q
default_template: .env.template
session_key_ttl: 3600
cache_ttl_sec: 900
trust_domain: catalyst9.local
tenant: %q
`, serverURL, tenant)
	return os.WriteFile(path, []byte(content), 0600)
}

// ResolveIdentityPaths populates Cert, Key, CA from ~/.kpm/identity/<server>/ when unset.
func (cfg *Config) ResolveIdentityPaths() error {
	if cfg.Server == "" {
		return nil
	}
	if cfg.Cert != "" && cfg.Key != "" && cfg.CA != "" {
		return nil
	}
	dir, err := IdentityDir(cfg.Server)
	if err != nil {
		return err
	}
	if cfg.Cert == "" {
		cfg.Cert = filepath.Join(dir, "client.crt")
	}
	if cfg.Key == "" {
		cfg.Key = filepath.Join(dir, "client.key")
	}
	if cfg.CA == "" {
		cfg.CA = filepath.Join(dir, "ca.crt")
	}
	cfg.Cert = ExpandHome(cfg.Cert)
	cfg.Key = ExpandHome(cfg.Key)
	cfg.CA = ExpandHome(cfg.CA)
	return nil
}

// IdentityDir returns ~/.kpm/identity/<normalized-server>/.
func IdentityDir(serverURL string) (string, error) {
	u, err := url.Parse(serverURL)
	if err != nil {
		return "", err
	}
	host := u.Host
	if host == "" {
		host = strings.TrimPrefix(u.Path, "/")
	}
	if host == "" {
		return "", fmt.Errorf("invalid server URL %q", serverURL)
	}
	safe := strings.NewReplacer(":", "_", "/", "_").Replace(host)
	return filepath.Join(DataDir(), "identity", safe), nil
}

// FingerprintCert returns SHA-256 hex of a PEM certificate (for tests).
func FingerprintCert(pemBytes []byte) (string, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return "", fmt.Errorf("invalid PEM")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return "", err
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:]), nil
}
