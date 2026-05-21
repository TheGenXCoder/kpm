package kpm_test

// device_test.go — tests for `kpm device list` and `kpm device revoke`.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TheGenXCoder/kpm/internal/kpm"
)

// ── stubDeviceClient ──────────────────────────────────────────────────────────

type stubDeviceClient struct {
	certs    []kpm.DeviceCertEntry
	listErr  error
	revokeOK bool
	revokeErr error
	revokedName string
}

func (s *stubDeviceClient) ListCerts(_ context.Context) ([]kpm.DeviceCertEntry, error) {
	return s.certs, s.listErr
}

func (s *stubDeviceClient) RevokeCert(_ context.Context, req kpm.CertRevokeRequest) error {
	s.revokedName = req.DeviceName
	if s.revokeErr != nil {
		return s.revokeErr
	}
	return nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

// writeFakeClientCert writes a self-signed cert with the given serial to
// certsDir/client.crt and returns the hex serial string.
func writeFakeClientCert(t *testing.T, certsDir string, serial int64) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "this-device"},
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	var buf bytes.Buffer
	pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.MkdirAll(certsDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certsDir, "client.crt"), buf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
	return strings.ToUpper(big.NewInt(serial).Text(16))
}

// ── device list tests ─────────────────────────────────────────────────────────

func TestDeviceListRendersTable(t *testing.T) {
	certs := []kpm.DeviceCertEntry{
		{DeviceName: "bert-tp-dev", Serial: "1A2B3C4D5E", IssuedAt: "2026-05-19T00:00:00Z", ExpiresAt: "2027-05-19T00:00:00Z", Revoked: false},
		{DeviceName: "bert-desktop", Serial: "7F8E9D0A1B", IssuedAt: "2026-05-20T00:00:00Z", ExpiresAt: "2027-05-20T00:00:00Z", Revoked: false},
		{DeviceName: "bert-old", Serial: "DEADBEEFFF", IssuedAt: "2026-03-01T00:00:00Z", ExpiresAt: "2027-03-01T00:00:00Z", Revoked: true},
	}
	stub := &stubDeviceClient{certs: certs}

	certsDir := t.TempDir()
	var stdout, stderr bytes.Buffer

	code := kpm.RunDeviceList(context.Background(), &stdout, &stderr, stub, certsDir, []string{})
	if code != 0 {
		t.Fatalf("RunDeviceList exit %d; stderr=%s", code, stderr.String())
	}

	out := stdout.String()
	if !strings.Contains(out, "bert-tp-dev") {
		t.Errorf("missing bert-tp-dev in output: %s", out)
	}
	if !strings.Contains(out, "bert-old") {
		t.Errorf("missing bert-old in output: %s", out)
	}
	if !strings.Contains(out, "revoked") {
		t.Errorf("missing 'revoked' status: %s", out)
	}
}

func TestDeviceListMarksThisDevice(t *testing.T) {
	certsDir := t.TempDir()
	serial := writeFakeClientCert(t, certsDir, 0x1A2B3C4D5E)

	certs := []kpm.DeviceCertEntry{
		{DeviceName: "this-device", Serial: serial, IssuedAt: "2026-05-19T00:00:00Z", ExpiresAt: "2027-05-19T00:00:00Z"},
		{DeviceName: "other-device", Serial: "FFFF0000", IssuedAt: "2026-05-19T00:00:00Z", ExpiresAt: "2027-05-19T00:00:00Z"},
	}
	stub := &stubDeviceClient{certs: certs}

	var stdout, stderr bytes.Buffer
	code := kpm.RunDeviceList(context.Background(), &stdout, &stderr, stub, certsDir, []string{})
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}

	out := stdout.String()
	if !strings.Contains(out, "<- this device") {
		t.Errorf("expected '<- this device' annotation, got:\n%s", out)
	}
}

func TestDeviceListJSONOutput(t *testing.T) {
	certs := []kpm.DeviceCertEntry{
		{DeviceName: "bert-tp-dev", Serial: "1A2B", IssuedAt: "2026-05-19T00:00:00Z", ExpiresAt: "2027-05-19T00:00:00Z"},
	}
	stub := &stubDeviceClient{certs: certs}

	certsDir := t.TempDir()
	var stdout, stderr bytes.Buffer

	code := kpm.RunDeviceList(context.Background(), &stdout, &stderr, stub, certsDir, []string{"--json"})
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}

	// Must be valid JSON.
	var rows []map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &rows); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %s", err, stdout.String())
	}
	if len(rows) != 1 {
		t.Errorf("expected 1 row, got %d", len(rows))
	}
	if rows[0]["device_name"] != "bert-tp-dev" {
		t.Errorf("wrong device_name: %v", rows[0]["device_name"])
	}
}

func TestDeviceListHTTPMock(t *testing.T) {
	// End-to-end via real HTTP mock server.
	certs := []kpm.DeviceCertEntry{
		{DeviceName: "alpha", Serial: "AABB", IssuedAt: "2026-05-20T00:00:00Z", ExpiresAt: "2027-05-20T00:00:00Z"},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/auth/session" && r.Method == http.MethodPost:
			json.NewEncoder(w).Encode(map[string]string{"token": "tok"})
		case r.URL.Path == "/auth/cert/list" && r.Method == http.MethodGet:
			json.NewEncoder(w).Encode(map[string]any{"certs": certs})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client, _ := kpm.NewClientInsecure(srv.URL)
	certsDir := t.TempDir()
	var stdout, stderr bytes.Buffer

	code := kpm.RunDevice(context.Background(), &stdout, &stderr, client, certsDir, []string{"list"})
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "alpha") {
		t.Errorf("missing device in output: %s", stdout.String())
	}
}

// ── device revoke tests ───────────────────────────────────────────────────────

func TestDeviceRevokeYesFlag(t *testing.T) {
	certs := []kpm.DeviceCertEntry{
		{DeviceName: "bert-desktop", Serial: "DEADBEEF"},
	}
	stub := &stubDeviceClient{certs: certs}

	certsDir := t.TempDir()
	var stdout, stderr bytes.Buffer

	code := kpm.RunDeviceRevoke(context.Background(), &stdout, &stderr, stub, certsDir,
		[]string{"--yes", "bert-desktop"})
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if stub.revokedName != "bert-desktop" {
		t.Errorf("expected revoked name = bert-desktop, got %q", stub.revokedName)
	}
	if !strings.Contains(stdout.String(), "Revoked") {
		t.Errorf("expected 'Revoked' in output: %s", stdout.String())
	}
}

func TestDeviceRevokeSelfBlocked(t *testing.T) {
	certsDir := t.TempDir()
	serial := writeFakeClientCert(t, certsDir, 0xABCD1234)

	certs := []kpm.DeviceCertEntry{
		{DeviceName: "this-device", Serial: serial},
	}
	stub := &stubDeviceClient{certs: certs}

	var stdout, stderr bytes.Buffer
	code := kpm.RunDeviceRevoke(context.Background(), &stdout, &stderr, stub, certsDir,
		[]string{"--yes", "this-device"})

	if code == 0 {
		t.Fatal("expected non-zero exit for self-revoke without --allow-self")
	}
	if !strings.Contains(stderr.String(), "allow-self") {
		t.Errorf("want '--allow-self' hint in stderr, got: %s", stderr.String())
	}
	if stub.revokedName != "" {
		t.Error("revoke should not have been called")
	}
}

func TestDeviceRevokeAllowSelf(t *testing.T) {
	certsDir := t.TempDir()
	serial := writeFakeClientCert(t, certsDir, 0xABCD1234)

	certs := []kpm.DeviceCertEntry{
		{DeviceName: "this-device", Serial: serial},
	}
	stub := &stubDeviceClient{certs: certs}

	var stdout, stderr bytes.Buffer
	code := kpm.RunDeviceRevoke(context.Background(), &stdout, &stderr, stub, certsDir,
		[]string{"--yes", "--allow-self", "this-device"})

	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if stub.revokedName != "this-device" {
		t.Errorf("expected revoked name = this-device, got %q", stub.revokedName)
	}
}

func TestDeviceRevoke401StepUp(t *testing.T) {
	certs := []kpm.DeviceCertEntry{
		{DeviceName: "some-device", Serial: "FFFF"},
	}
	stub := &stubDeviceClient{
		certs:     certs,
		revokeErr: fmt.Errorf("revoke cert: issue cert: 401 unauthorized"),
	}

	certsDir := t.TempDir()
	var stdout, stderr bytes.Buffer

	code := kpm.RunDeviceRevoke(context.Background(), &stdout, &stderr, stub, certsDir,
		[]string{"--yes", "some-device"})

	if code == 0 {
		t.Fatal("expected non-zero exit for 401")
	}
	if !strings.Contains(stderr.String(), "step-up") {
		t.Errorf("want step-up hint in stderr, got: %s", stderr.String())
	}
}

func TestDeviceRevokeHTTPMock(t *testing.T) {
	var revokedBody map[string]string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/auth/session" && r.Method == http.MethodPost:
			json.NewEncoder(w).Encode(map[string]string{"token": "tok"})
		case r.URL.Path == "/auth/cert/list" && r.Method == http.MethodGet:
			json.NewEncoder(w).Encode(map[string]any{
				"certs": []kpm.DeviceCertEntry{
					{DeviceName: "alpha", Serial: "AABB1122"},
				},
			})
		case r.URL.Path == "/auth/certificate/revoke" && r.Method == http.MethodPost:
			json.NewDecoder(r.Body).Decode(&revokedBody)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client, _ := kpm.NewClientInsecure(srv.URL)
	certsDir := t.TempDir()
	var stdout, stderr bytes.Buffer

	code := kpm.RunDevice(context.Background(), &stdout, &stderr, client, certsDir,
		[]string{"revoke", "--yes", "alpha"})
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if revokedBody["device_name"] != "alpha" {
		t.Errorf("server received device_name=%q, want alpha", revokedBody["device_name"])
	}
}

// ── device add tests ──────────────────────────────────────────────────────────

func TestRunDeviceAdd_HappyPath(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("KPM_DATA", tmp)

	// Pre-populate a persisted session with auth_strength = cert+human.
	expiresAt := time.Now().Add(15 * time.Minute)
	if err := kpm.SaveAuthSession(&kpm.AuthSession{
		Token:     "test-session-token",
		TokenType: "Bearer",
		SessionID: "test-jti",
		ExpiresAt: expiresAt,
		Claims: kpm.AuthClaims{
			UserID:       "bert",
			AuthStrength: "cert+human",
		},
	}); err != nil {
		t.Fatalf("SaveAuthSession: %v", err)
	}

	// Mock server responds with a bootstrap token.
	expectedToken := "78ab" + strings.Repeat("cd", 31) + "0f9" // 64 hex chars
	expectedExpiry := "2026-05-20T22:14:30Z"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/auth/bootstrap/issue" && r.Method == http.MethodPost:
			// Verify the request body.
			var body struct {
				DeviceNamePattern string `json:"device_name_pattern"`
				TTLSeconds        int    `json:"ttl_seconds"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, "bad body", http.StatusBadRequest)
				return
			}
			if body.DeviceNamePattern != "bert-desktop" {
				http.Error(w, "wrong device name", http.StatusBadRequest)
				return
			}
			if body.TTLSeconds != 3600 { // default 1h
				http.Error(w, "wrong ttl", http.StatusBadRequest)
				return
			}
			// Return the token.
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"bootstrap_token": expectedToken,
				"expires_at":      expectedExpiry,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client, _ := kpm.NewClientInsecure(srv.URL)
	var stdout, stderr bytes.Buffer

	code := kpm.RunDeviceAdd(context.Background(), &stdout, &stderr, client,
		[]string{"bert-desktop"})

	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr.String())
	}

	out := stdout.String()

	// Verify output contains the token.
	if !strings.Contains(out, expectedToken) {
		t.Errorf("token not found in output:\n%s", out)
	}

	// Verify output contains the expiry.
	if !strings.Contains(out, expectedExpiry) {
		t.Errorf("expiry not found in output:\n%s", out)
	}

	// Verify output contains the kpm enroll example.
	if !strings.Contains(out, "kpm enroll") {
		t.Errorf("kpm enroll example not found in output:\n%s", out)
	}

	// Verify it uses the UserID from the session.
	if !strings.Contains(out, "bert") {
		t.Errorf("user ID not found in output:\n%s", out)
	}

	// Verify it uses the device name.
	if !strings.Contains(out, "bert-desktop") {
		t.Errorf("device name not found in output:\n%s", out)
	}
}

func TestRunDeviceAdd_NoSession(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("KPM_DATA", tmp)
	// Don't save a session, so LoadAuthSession will fail.

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r) // Server should never be called.
	}))
	defer srv.Close()

	client, _ := kpm.NewClientInsecure(srv.URL)
	var stdout, stderr bytes.Buffer

	code := kpm.RunDeviceAdd(context.Background(), &stdout, &stderr, client,
		[]string{"bert-desktop"})

	if code == 0 {
		t.Fatal("expected non-zero exit when no session exists")
	}

	if !strings.Contains(stderr.String(), "kpm login") {
		t.Errorf("want 'kpm login' hint in stderr, got: %s", stderr.String())
	}
}

func TestRunDeviceAdd_ServerForbidden(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("KPM_DATA", tmp)

	// Pre-populate a persisted session with cert-only strength (not cert+human).
	expiresAt := time.Now().Add(15 * time.Minute)
	if err := kpm.SaveAuthSession(&kpm.AuthSession{
		Token:     "test-session-token",
		TokenType: "Bearer",
		SessionID: "test-jti",
		ExpiresAt: expiresAt,
		Claims: kpm.AuthClaims{
			UserID:       "bert",
			AuthStrength: "cert-only", // Not cert+human
		},
	}); err != nil {
		t.Fatalf("SaveAuthSession: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/auth/bootstrap/issue" && r.Method == http.MethodPost:
			// Return 403.
			http.Error(w, `{"error":"auth_strength too weak","code":"FORBIDDEN"}`, http.StatusForbidden)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client, _ := kpm.NewClientInsecure(srv.URL)
	var stdout, stderr bytes.Buffer

	code := kpm.RunDeviceAdd(context.Background(), &stdout, &stderr, client,
		[]string{"bert-desktop"})

	if code == 0 {
		t.Fatal("expected non-zero exit for 403")
	}

	if !strings.Contains(stderr.String(), "step-up") {
		t.Errorf("want 'step-up' hint in stderr, got: %s", stderr.String())
	}
}

func TestRunDeviceAdd_InvalidDeviceName(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("KPM_DATA", tmp)

	// Pre-populate a persisted session.
	expiresAt := time.Now().Add(15 * time.Minute)
	if err := kpm.SaveAuthSession(&kpm.AuthSession{
		Token:     "test-session-token",
		TokenType: "Bearer",
		SessionID: "test-jti",
		ExpiresAt: expiresAt,
		Claims: kpm.AuthClaims{
			UserID:       "bert",
			AuthStrength: "cert+human",
		},
	}); err != nil {
		t.Fatalf("SaveAuthSession: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("server should not be called for invalid device name")
	}))
	defer srv.Close()

	client, _ := kpm.NewClientInsecure(srv.URL)
	var stdout, stderr bytes.Buffer

	// Test with uppercase letters (invalid).
	code := kpm.RunDeviceAdd(context.Background(), &stdout, &stderr, client,
		[]string{"BAD-NAME"})

	if code != 2 {
		t.Fatalf("expected exit code 2 for invalid name, got %d", code)
	}

	if !strings.Contains(stderr.String(), "invalid device name") {
		t.Errorf("want 'invalid device name' message, got: %s", stderr.String())
	}

	// Test with spaces (invalid).
	var stdout2, stderr2 bytes.Buffer
	code = kpm.RunDeviceAdd(context.Background(), &stdout2, &stderr2, client,
		[]string{"bad name with spaces"})

	if code != 2 {
		t.Fatalf("expected exit code 2 for name with spaces, got %d", code)
	}
}

func TestRunDeviceAdd_CustomTTL(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("KPM_DATA", tmp)

	// Pre-populate a persisted session.
	expiresAt := time.Now().Add(15 * time.Minute)
	if err := kpm.SaveAuthSession(&kpm.AuthSession{
		Token:     "test-session-token",
		TokenType: "Bearer",
		SessionID: "test-jti",
		ExpiresAt: expiresAt,
		Claims: kpm.AuthClaims{
			UserID:       "bert",
			AuthStrength: "cert+human",
		},
	}); err != nil {
		t.Fatalf("SaveAuthSession: %v", err)
	}

	// Track the TTL sent by the client.
	var receivedTTL int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/auth/bootstrap/issue" && r.Method == http.MethodPost:
			var body struct {
				DeviceNamePattern string `json:"device_name_pattern"`
				TTLSeconds        int    `json:"ttl_seconds"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			receivedTTL = body.TTLSeconds

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"bootstrap_token": "test-token",
				"expires_at":      "2026-05-20T22:14:30Z",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client, _ := kpm.NewClientInsecure(srv.URL)
	var stdout, stderr bytes.Buffer

	// Use a custom TTL: 30 minutes.
	// Note: flags must come before the positional argument.
	code := kpm.RunDeviceAdd(context.Background(), &stdout, &stderr, client,
		[]string{"--ttl", "30m", "bert-desktop"})

	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr.String())
	}

	// Verify the TTL was sent correctly (30m = 1800 seconds).
	if receivedTTL != 1800 {
		t.Errorf("expected TTL 1800, got %d", receivedTTL)
	}
}
