package kpm_test

// enroll_test.go — tests for `kpm enroll`.
//
// All HTTP traffic is mocked via httptest.NewServer.  No real AgentKMS needed.

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

// ── helpers ───────────────────────────────────────────────────────────────────

// fakeCAPEM generates a self-signed CA cert PEM for tests.
func fakeCAPEM(t *testing.T) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-ca"},
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	var buf bytes.Buffer
	pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	return buf.String()
}

// newEnrollServer builds a test server simulating POST /auth/cert/issue.
// If statusCode != 200, it returns a JSON error with the given code.
func newEnrollServer(t *testing.T, statusCode int, resp *kpm.CertIssueResponse, capturedBody *map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/cert/issue" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if capturedBody != nil {
			json.NewDecoder(r.Body).Decode(capturedBody)
		}
		if statusCode != http.StatusOK {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(statusCode)
			switch statusCode {
			case http.StatusConflict:
				json.NewEncoder(w).Encode(map[string]string{"error": "already enrolled", "code": "DEVICE_CONFLICT"})
			case http.StatusUnauthorized:
				json.NewEncoder(w).Encode(map[string]string{"error": "bootstrap token invalid or already used", "code": "TOKEN_INVALID"})
			default:
				json.NewEncoder(w).Encode(map[string]string{"error": "server error"})
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
}

// stubEnrollClient is a minimal EnrollClient for unit tests that want
// to bypass HTTP entirely.
type stubEnrollClient struct {
	resp *kpm.CertIssueResponse
	err  error
}

func (s *stubEnrollClient) IssueCert(_ context.Context, _ kpm.CertIssueRequest) (*kpm.CertIssueResponse, error) {
	return s.resp, s.err
}

// Compile-time check that stubEnrollClient satisfies EnrollClient.
// We can't reference the interface from external test, so just rely on the RunEnroll call.

// ── tests ─────────────────────────────────────────────────────────────────────

// TestEnrollHappyPath verifies that on a 200 response the key, cert, and CA
// are written with correct permissions.
func TestEnrollHappyPath(t *testing.T) {
	caBlock := fakeCAPEM(t)

	// Build a fake leaf cert PEM.
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0xABCD),
		Subject:      pkix.Name{CommonName: "test-device"},
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, leafTmpl, &leafKey.PublicKey, leafKey)
	var leafBuf bytes.Buffer
	pem.Encode(&leafBuf, &pem.Block{Type: "CERTIFICATE", Bytes: leafDER})

	issueResp := &kpm.CertIssueResponse{
		Cert:      leafBuf.String(),
		CAChain:   []string{caBlock},
		Serial:    "ABCD",
		ExpiresAt: "2027-05-19T00:00:00Z",
	}

	var captured map[string]any
	srv := newEnrollServer(t, http.StatusOK, issueResp, &captured)
	defer srv.Close()

	certsDir := t.TempDir()
	var stdout, stderr bytes.Buffer

	client, _ := kpm.NewClientInsecure(srv.URL)
	exitCode := kpm.RunEnroll(
		context.Background(), &stdout, &stderr,
		&kpm.ClientEnrollAdapter{C: client},
		certsDir,
		&kpm.Config{TrustDomain: "test.local"},
		[]string{"--device", "test-device", "bootstrap-tok-123"},
	)

	if exitCode != 0 {
		t.Fatalf("RunEnroll exit %d; stderr=%s", exitCode, stderr.String())
	}

	// Check output.
	out := stdout.String()
	if !strings.Contains(out, "Enrolled device test-device") {
		t.Errorf("expected enrolled message, got: %s", out)
	}
	if !strings.Contains(out, "serial=ABCD") {
		t.Errorf("expected serial in output, got: %s", out)
	}

	// Verify files exist with correct perms.
	keyPath := filepath.Join(certsDir, "client.key")
	certPath := filepath.Join(certsDir, "client.crt")
	caPath := filepath.Join(certsDir, "ca.crt")

	checkPerm := func(path string, want os.FileMode) {
		t.Helper()
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		got := info.Mode().Perm()
		if got != want {
			t.Errorf("%s: perm %o, want %o", path, got, want)
		}
	}
	checkPerm(keyPath, 0600)
	checkPerm(certPath, 0644)
	checkPerm(caPath, 0644)

	// Verify key is PEM-encoded EC private key.
	keyData, _ := os.ReadFile(keyPath)
	block, _ := pem.Decode(keyData)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		t.Errorf("key file is not an EC PRIVATE KEY PEM, type=%q", func() string {
			if block == nil {
				return "<nil>"
			}
			return block.Type
		}())
	}

	// Verify server received the right device_name.
	if got, ok := captured["device_name"].(string); !ok || got != "test-device" {
		t.Errorf("server received device_name=%v, want test-device", captured["device_name"])
	}
	if got, ok := captured["bootstrap_token"].(string); !ok || got != "bootstrap-tok-123" {
		t.Errorf("server received bootstrap_token=%v, want bootstrap-tok-123", captured["bootstrap_token"])
	}
}

// TestEnroll409Conflict checks that a 409 from the server produces the right
// error message and writes no files.
func TestEnroll409Conflict(t *testing.T) {
	srv := newEnrollServer(t, http.StatusConflict, nil, nil)
	defer srv.Close()

	certsDir := t.TempDir()
	var stdout, stderr bytes.Buffer

	client, _ := kpm.NewClientInsecure(srv.URL)
	exitCode := kpm.RunEnroll(
		context.Background(), &stdout, &stderr,
		&kpm.ClientEnrollAdapter{C: client},
		certsDir,
		nil,
		[]string{"--device", "my-laptop", "bad-token"},
	)

	if exitCode == 0 {
		t.Fatal("expected non-zero exit for 409")
	}
	msg := stderr.String()
	if !strings.Contains(msg, "already enrolled") {
		t.Errorf("want 'already enrolled' in stderr, got: %s", msg)
	}
	if !strings.Contains(msg, "kpm device list") {
		t.Errorf("want hint about 'kpm device list' in stderr, got: %s", msg)
	}

	// No files should have been written.
	if _, err := os.Stat(filepath.Join(certsDir, "client.key")); !os.IsNotExist(err) {
		t.Error("client.key should not exist after 409")
	}
}

// TestEnrollExistingKeyNoForce checks that the command refuses when a key
// already exists and --force is not set.
func TestEnrollExistingKeyNoForce(t *testing.T) {
	certsDir := t.TempDir()

	// Pre-create a key file.
	if err := os.WriteFile(filepath.Join(certsDir, "client.key"), []byte("dummy"), 0600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer

	// Use a stub that would succeed if called — but it shouldn't be called.
	stub := &stubEnrollClient{}
	exitCode := kpm.RunEnroll(
		context.Background(), &stdout, &stderr,
		stub,
		certsDir,
		nil,
		[]string{"--device", "test", "tok"},
	)

	if exitCode == 0 {
		t.Fatal("expected non-zero exit when key exists and --force not set")
	}
	if !strings.Contains(stderr.String(), "--force") {
		t.Errorf("want '--force' hint in stderr, got: %s", stderr.String())
	}
}

// TestEnroll401BadToken verifies the user-friendly message for an invalid
// bootstrap token.
func TestEnroll401BadToken(t *testing.T) {
	srv := newEnrollServer(t, http.StatusUnauthorized, nil, nil)
	defer srv.Close()

	certsDir := t.TempDir()
	var stdout, stderr bytes.Buffer

	client, _ := kpm.NewClientInsecure(srv.URL)
	exitCode := kpm.RunEnroll(
		context.Background(), &stdout, &stderr,
		&kpm.ClientEnrollAdapter{C: client},
		certsDir,
		nil,
		[]string{"--device", "dev", "expired-token"},
	)

	if exitCode == 0 {
		t.Fatal("expected non-zero exit for 401")
	}
	if !strings.Contains(stderr.String(), "bootstrap token invalid") {
		t.Errorf("want bootstrap token message, got: %s", stderr.String())
	}
}
