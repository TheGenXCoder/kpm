package kpm_test

// ghapp_test.go — tests for the `kpm gh-app new` interactive walkthrough (UX-D).
//
// All tests use dependency injection via GhAppNewDeps to replace:
//   - Stdin (prompt reader) with a strings.Reader driven by pre-canned input
//   - OpenBrowser with a stub launcher
//   - GlobPEM with an in-memory glob function
//   - GitHubTransport with an httptest.Server transport
//
// No real GitHub API calls are made.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TheGenXCoder/kpm/internal/kpm"
)

// ── test fixtures ─────────────────────────────────────────────────────────────

// generateTestRSAKey creates a 2048-bit RSA key for test use.
func generateTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return key
}

// encodeTestPEM serialises an RSA private key to a PKCS#1 PEM block.
func encodeTestPEM(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	der := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
	return pem.EncodeToMemory(block)
}

// writePEMFile writes a PEM to a temp file and returns the path.
func writePEMFile(t *testing.T, key *rsa.PrivateKey, name string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, encodeTestPEM(t, key), 0600); err != nil {
		t.Fatalf("write PEM file: %v", err)
	}
	return path
}

// newGitHubAppTestServer builds an httptest.Server that simulates:
//   - POST /auth/session       — returns a bearer token (AgentKMS auth)
//   - POST /github-apps        — records the registration request, returns 201
//   - POST /app/installations/{id}/access_tokens — simulates GitHub's token endpoint
//
// githubStatus controls the HTTP status code returned by the GitHub token endpoint.
func newGitHubAppTestServer(t *testing.T, githubStatus int) (*httptest.Server, *kpm.RegisterGithubAppRequest) {
	t.Helper()
	var captured kpm.RegisterGithubAppRequest

	mux := http.NewServeMux()

	// AgentKMS auth endpoint.
	mux.HandleFunc("POST /auth/session", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"token": "test-token"})
	})

	// AgentKMS register endpoint.
	mux.HandleFunc("POST /github-apps", func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(kpm.GithubAppSummary{
			Name:           captured.Name,
			AppID:          captured.AppID,
			InstallationID: captured.InstallationID,
		})
	})

	// GitHub App token endpoint (any installation ID).
	mux.HandleFunc("/app/installations/", func(w http.ResponseWriter, r *http.Request) {
		if githubStatus == http.StatusCreated || githubStatus == http.StatusOK {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(githubStatus)
			json.NewEncoder(w).Encode(map[string]any{
				"token": "ghs_test_token_discard",
				"permissions": map[string]string{
					"secrets": "write",
					"actions": "write",
				},
			})
		} else {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(githubStatus)
			json.NewEncoder(w).Encode(map[string]string{
				"message": "Bad credentials",
			})
		}
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &captured
}

// newTestClientForGhApp creates a kpm.Client pointed at the given test server.
func newTestClientForGhApp(t *testing.T, srv *httptest.Server) *kpm.Client {
	t.Helper()
	c, err := kpm.NewClientInsecure(srv.URL)
	if err != nil {
		t.Fatalf("NewClientInsecure: %v", err)
	}
	return c
}

// stubTransportTo returns an http.RoundTripper that routes requests to srv.
// It rewrites the Host and scheme so that GitHub API URLs hit the test server.
func stubTransportTo(srv *httptest.Server) http.RoundTripper {
	return &rewriteTransport{base: srv.Client().Transport, srvURL: srv.URL}
}

type rewriteTransport struct {
	base   http.RoundTripper
	srvURL string
}

func (rt *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request so we don't mutate the original.
	clone := req.Clone(req.Context())
	// Repoint the URL to the test server, keeping path + query.
	clone.URL.Scheme = "http"
	clone.URL.Host = strings.TrimPrefix(rt.srvURL, "http://")
	return rt.base.RoundTrip(clone)
}

// ── TestGhAppNew_FullFlow ─────────────────────────────────────────────────────
//
// Drives the full happy-path: browser open → form instructions → App ID →
// PEM auto-detect (single match) → Installation ID → verify (201) → register.
// Asserts that RegisterGithubApp is called with the correct fields.
func TestGhAppNew_FullFlow(t *testing.T) {
	key := generateTestRSAKey(t)
	pemPath := writePEMFile(t, key, "my-app.private-key.pem")

	srv, captured := newGitHubAppTestServer(t, http.StatusCreated)
	client := newTestClientForGhApp(t, srv)

	// Canned stdin:
	//   Step 1 → Enter (past "press Enter when app created")
	//   Step 3 → App ID
	//   Step 4 → Enter (past "press Enter when downloaded")
	//           → Y (confirm auto-detected PEM)
	//   Step 5 → Installation ID
	input := strings.Join([]string{
		"",         // Step 2 → press Enter
		"3512662",  // Step 3 → App ID
		"",         // Step 4 → press Enter (download done)
		"y",        // Step 4 → confirm auto-detected PEM
		"127321567", // Step 5 → Installation ID
	}, "\n") + "\n"

	var w, errW bytes.Buffer
	deps := &kpm.GhAppNewDeps{
		Stdin:           strings.NewReader(input),
		OpenBrowser:     func(url string) error { return nil },
		GlobPEM:         func(pattern string) ([]string, error) { return []string{pemPath}, nil },
		GitHubTransport: stubTransportTo(srv),
	}

	code := kpm.RunGhAppNew(context.Background(), &w, &errW, client, []string{"my-app"}, deps)
	if code != 0 {
		t.Fatalf("exit code %d\nstderr: %s", code, errW.String())
	}

	// Verify the stdout "ready" line.
	stdout := w.String()
	if !strings.Contains(stdout, "ready") {
		t.Errorf("expected 'ready' in stdout, got: %q", stdout)
	}
	if !strings.Contains(stdout, "app=my-app") {
		t.Errorf("expected app name in stdout, got: %q", stdout)
	}

	// Verify RegisterGithubApp was called with correct fields.
	if captured.Name != "my-app" {
		t.Errorf("registered name: got %q want %q", captured.Name, "my-app")
	}
	if captured.AppID != 3512662 {
		t.Errorf("app_id: got %d want 3512662", captured.AppID)
	}
	if captured.InstallationID != 127321567 {
		t.Errorf("installation_id: got %d want 127321567", captured.InstallationID)
	}
	if len(captured.PrivateKeyPEM) == 0 {
		t.Error("private_key_pem: empty — PEM was not forwarded to register")
	}
}

// ── TestGhAppNew_AppIDValidation ──────────────────────────────────────────────
//
// Verifies that non-numeric, zero, and negative App IDs all trigger re-prompts
// without storing anything.
func TestGhAppNew_AppIDValidation(t *testing.T) {
	key := generateTestRSAKey(t)
	pemPath := writePEMFile(t, key, "val.private-key.pem")

	srv, captured := newGitHubAppTestServer(t, http.StatusCreated)
	client := newTestClientForGhApp(t, srv)

	// Feed three bad values before the valid one.
	input := strings.Join([]string{
		"",           // Step 2 → Enter
		"not-a-number", // bad App ID
		"0",            // zero — invalid
		"-5",           // negative — invalid
		"9988776",      // valid
		"",             // Step 4 → Enter (download)
		"y",            // confirm PEM
		"55443322",     // Installation ID
	}, "\n") + "\n"

	var w, errW bytes.Buffer
	deps := &kpm.GhAppNewDeps{
		Stdin:           strings.NewReader(input),
		OpenBrowser:     func(url string) error { return nil },
		GlobPEM:         func(pattern string) ([]string, error) { return []string{pemPath}, nil },
		GitHubTransport: stubTransportTo(srv),
	}

	code := kpm.RunGhAppNew(context.Background(), &w, &errW, client, []string{"val-app"}, deps)
	if code != 0 {
		t.Fatalf("exit code %d\nstderr: %s", code, errW.String())
	}

	// The correct App ID must have been stored.
	if captured.AppID != 9988776 {
		t.Errorf("app_id after re-prompts: got %d want 9988776", captured.AppID)
	}

	// The invalid entries must trigger re-prompt messages.
	errStr := errW.String()
	if !strings.Contains(errStr, "not-a-number") {
		t.Errorf("expected 'not-a-number' in validation error output")
	}
}

// ── TestGhAppNew_PEMAutoDetect_NoMatches ──────────────────────────────────────
//
// When no .pem files are found in ~/Downloads the user is prompted for an
// explicit path. The flow must not store anything if the path is supplied.
func TestGhAppNew_PEMAutoDetect_NoMatches(t *testing.T) {
	key := generateTestRSAKey(t)
	pemPath := writePEMFile(t, key, "explicit.private-key.pem")

	srv, captured := newGitHubAppTestServer(t, http.StatusCreated)
	client := newTestClientForGhApp(t, srv)

	input := strings.Join([]string{
		"",        // Step 2 → Enter
		"1111111", // App ID
		"",        // Step 4 → Enter (download done)
		pemPath,   // explicit PEM path (no auto-detect)
		"2222222", // Installation ID
	}, "\n") + "\n"

	var w, errW bytes.Buffer
	deps := &kpm.GhAppNewDeps{
		Stdin:           strings.NewReader(input),
		OpenBrowser:     func(url string) error { return nil },
		GlobPEM:         func(pattern string) ([]string, error) { return nil, nil }, // returns nothing
		GitHubTransport: stubTransportTo(srv),
	}

	code := kpm.RunGhAppNew(context.Background(), &w, &errW, client, []string{"no-match-app"}, deps)
	if code != 0 {
		t.Fatalf("exit code %d\nstderr: %s", code, errW.String())
	}

	// The "no files found" message must appear.
	if !strings.Contains(errW.String(), "No .private-key.pem files found") {
		t.Errorf("expected no-files message; stderr: %q", errW.String())
	}

	// Registration must have received a valid PEM.
	if len(captured.PrivateKeyPEM) == 0 {
		t.Error("expected non-empty PEM after explicit path entry")
	}
	if captured.AppID != 1111111 {
		t.Errorf("app_id: got %d want 1111111", captured.AppID)
	}
}

// ── TestGhAppNew_PEMAutoDetect_MultipleMatches ────────────────────────────────
//
// When multiple .pem files exist the user is shown a numbered list and picks
// by index. The correct file must be used for registration.
func TestGhAppNew_PEMAutoDetect_MultipleMatches(t *testing.T) {
	key1 := generateTestRSAKey(t)
	key2 := generateTestRSAKey(t)
	path1 := writePEMFile(t, key1, "first.private-key.pem")
	path2 := writePEMFile(t, key2, "second.private-key.pem")

	srv, captured := newGitHubAppTestServer(t, http.StatusCreated)
	client := newTestClientForGhApp(t, srv)

	// User picks the second file (index 2).
	input := strings.Join([]string{
		"",        // Step 2 → Enter
		"3333333", // App ID
		"",        // Step 4 → Enter (download done)
		"2",       // pick second file
		"4444444", // Installation ID
	}, "\n") + "\n"

	var w, errW bytes.Buffer
	deps := &kpm.GhAppNewDeps{
		Stdin:       strings.NewReader(input),
		OpenBrowser: func(url string) error { return nil },
		GlobPEM: func(pattern string) ([]string, error) {
			return []string{path1, path2}, nil
		},
		GitHubTransport: stubTransportTo(srv),
	}

	code := kpm.RunGhAppNew(context.Background(), &w, &errW, client, []string{"multi-app"}, deps)
	if code != 0 {
		t.Fatalf("exit code %d\nstderr: %s", code, errW.String())
	}

	// stderr should list both files.
	errStr := errW.String()
	if !strings.Contains(errStr, "[1]") || !strings.Contains(errStr, "[2]") {
		t.Errorf("expected numbered list in stderr; got: %q", errStr)
	}

	// The second file was selected — verify PEM content matches key2.
	expectedPEM := encodeTestPEM(t, key2)
	if !bytes.Equal(bytes.TrimSpace(captured.PrivateKeyPEM), bytes.TrimSpace(expectedPEM)) {
		t.Error("PEM stored does not match the selected file (index 2)")
	}
}

// ── TestGhAppNew_VerificationFails_DoesNotStore ───────────────────────────────
//
// When the GitHub API token mint returns 401, the register flow must NOT be
// called. The user is asked whether to re-enter values; if they decline, the
// command exits non-zero.
func TestGhAppNew_VerificationFails_DoesNotStore(t *testing.T) {
	key := generateTestRSAKey(t)
	pemPath := writePEMFile(t, key, "fail.private-key.pem")

	// GitHub returns 401 every time.
	srv, captured := newGitHubAppTestServer(t, http.StatusUnauthorized)
	client := newTestClientForGhApp(t, srv)

	// After the 401, user declines to re-enter ("n").
	input := strings.Join([]string{
		"",        // Step 2 → Enter
		"5555555", // App ID
		"",        // Step 4 → Enter (download)
		"y",       // confirm PEM
		"6666666", // Installation ID
		"n",       // decline re-entry after 401
	}, "\n") + "\n"

	var w, errW bytes.Buffer
	deps := &kpm.GhAppNewDeps{
		Stdin:           strings.NewReader(input),
		OpenBrowser:     func(url string) error { return nil },
		GlobPEM:         func(pattern string) ([]string, error) { return []string{pemPath}, nil },
		GitHubTransport: stubTransportTo(srv),
	}

	code := kpm.RunGhAppNew(context.Background(), &w, &errW, client, []string{"fail-app"}, deps)
	if code == 0 {
		t.Fatal("expected non-zero exit code when verification fails and user declines")
	}

	// RegisterGithubApp must NOT have been called — the captured request should
	// be zeroed because the POST /github-apps handler was never reached.
	if captured.Name != "" {
		t.Errorf("register was called despite verification failure; captured.Name = %q", captured.Name)
	}

	// The error output should mention the 401 response.
	if !strings.Contains(errW.String(), "401") && !strings.Contains(errW.String(), "Bad credentials") {
		t.Errorf("expected 401 error in stderr; got: %q", errW.String())
	}

	// Should mention retry hint.
	if !strings.Contains(errW.String(), "kpm gh-app register") {
		t.Errorf("expected retry hint in stderr; got: %q", errW.String())
	}
}

// ── TestGhAppNew_BrowserOpenFailure_NotFatal ──────────────────────────────────
//
// When the browser launcher returns an error the flow must continue normally,
// printing the URL for manual use. The command should succeed if all other
// inputs are valid.
func TestGhAppNew_BrowserOpenFailure_NotFatal(t *testing.T) {
	key := generateTestRSAKey(t)
	pemPath := writePEMFile(t, key, "browser-fail.private-key.pem")

	srv, _ := newGitHubAppTestServer(t, http.StatusCreated)
	client := newTestClientForGhApp(t, srv)

	input := strings.Join([]string{
		"",         // Step 2 → Enter
		"7777777",  // App ID
		"",         // Step 4 → Enter (download)
		"y",        // confirm PEM
		"8888888",  // Installation ID
	}, "\n") + "\n"

	var w, errW bytes.Buffer
	browserCalled := false
	deps := &kpm.GhAppNewDeps{
		Stdin: strings.NewReader(input),
		OpenBrowser: func(url string) error {
			browserCalled = true
			return fmt.Errorf("browser not available in test environment")
		},
		GlobPEM:         func(pattern string) ([]string, error) { return []string{pemPath}, nil },
		GitHubTransport: stubTransportTo(srv),
	}

	code := kpm.RunGhAppNew(context.Background(), &w, &errW, client, []string{"browser-fail-app"}, deps)
	if code != 0 {
		t.Fatalf("browser failure should be non-fatal; exit code %d\nstderr: %s", code, errW.String())
	}

	if !browserCalled {
		t.Error("expected OpenBrowser to be called")
	}

	// Must contain a fallback message about pasting the URL.
	errStr := errW.String()
	if !strings.Contains(errStr, "browser did not open") && !strings.Contains(errStr, "paste") {
		t.Errorf("expected fallback URL message in stderr; got: %q", errStr)
	}

	// Flow must still succeed.
	if !strings.Contains(w.String(), "ready") {
		t.Errorf("expected 'ready' in stdout; got: %q", w.String())
	}
}
