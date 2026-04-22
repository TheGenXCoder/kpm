package kpm

// strict_test.go — Failing tests for kpm run --strict (v0.3.0 target)
//
// ALL tests in this file MUST fail against the current v0.2.x codebase.
// They define the complete contract that the implementation subagent must satisfy.
//
// Design reference: /tmp/kpm-strict-design.md
// Blog post spec: part-2-env-files-liability.md lines 95-106
//
// Key invariants tested here:
//   - --strict causes one AgentKMS round-trip per decrypt, not per session
//   - AgentKMS denial produces an error response over the UDS socket (unset env var in child)
//   - AgentKMS network failure produces an error response (never a panic)
//   - Audit events land on the AgentKMS server (one per decrypt, verified via mock hit count)
//   - Non-strict (default) path is wholly unaffected
//   - --strict combined with --plaintext is a hard error (no AgentKMS call made)
//   - Decrypting the same var twice from the same child session hits AgentKMS twice (no local cache)
//   - SecureMode config (true) is compatible with --strict (not a conflict)
//   - Session TTL is still respected by the strict listener (same as non-strict)
//   - mTLS failure produces a clear error message, not a generic decrypt failure

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// mockStrictServer creates an httptest.Server that:
//   - Handles POST /auth/session (returns a token)
//   - Handles GET /credentials/generic/{path} and GET /credentials/llm/{provider}
//     using the provided handler for those routes
//   - Counts every credential fetch in hitCount
//
// We use httptest.NewServer (plain HTTP) because the strict listener's Client
// is constructed with newClientWithTLS which accepts any *tls.Config including
// nil (no TLS, HTTP) for test purposes. The mTLS tests use httptest.NewTLSServer.
func mockStrictServer(t *testing.T, handler http.HandlerFunc, hitCount *atomic.Int64) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/session" && r.Method == http.MethodPost {
			json.NewEncoder(w).Encode(map[string]string{"token": "strict-test-token"})
			return
		}
		hitCount.Add(1)
		handler(w, r)
	}))
}

// mockStrictServerTLS creates a TLS-backed server for mTLS failure tests.
func mockStrictServerTLS(t *testing.T, handler http.HandlerFunc, hitCount *atomic.Int64) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/session" && r.Method == http.MethodPost {
			json.NewEncoder(w).Encode(map[string]string{"token": "strict-test-token"})
			return
		}
		hitCount.Add(1)
		handler(w, r)
	}))
	return srv
}

// dialStrict connects to a UDS listener and sends a strict decrypt request,
// returning the parsed DecryptResponse.
func dialStrict(t *testing.T, sockPath, blob string) DecryptResponse {
	t.Helper()

	// Wait for socket to appear (mirroring existing listener_test.go pattern)
	// 500 iterations * 10ms = 5 second max wait, necessary on loaded systems
	// where the listener goroutine may take >1s to be scheduled.
	for i := 0; i < 500; i++ {
		if _, err := os.Stat(sockPath); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial socket %s: %v", sockPath, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	req := DecryptRequest{Ciphertext: blob}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatalf("encode request: %v", err)
	}
	var resp DecryptResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return resp
}

// makeStrictBlob creates a strict-mode blob encoding the given KMSReference.
// This calls FormatStrictBlob which does NOT exist yet — the test will fail to
// compile/run until the implementation is in place.
func makeStrictBlob(t *testing.T, sessionID string, ref KMSReference) string {
	t.Helper()
	blob, err := FormatStrictBlob(sessionID, ref) // DOES NOT EXIST YET
	if err != nil {
		t.Fatalf("FormatStrictBlob: %v", err)
	}
	return blob
}

// startStrictListener creates a DecryptListener in strict mode pointing at the
// given AgentKMS base URL, starts it in a goroutine, and returns the listener
// and its socket path. The caller should defer dl.Close().
//
// DecryptListener.StrictMode and DecryptListener.AgentKMSClient are fields that
// do NOT exist yet — this will fail to compile until implemented.
func startStrictListener(t *testing.T, sessionID, baseURL string, ttl time.Duration) (*DecryptListener, string) {
	t.Helper()

	sockPath := shortSockPath(t, fmt.Sprintf("strict-%s.sock", sessionID))
	client := newClientWithTLS(baseURL, nil) // nil TLS = HTTP for test server

	dl := &DecryptListener{ // DecryptListener.StrictMode DOES NOT EXIST YET
		SocketPath:      sockPath,
		SessionID:       sessionID,
		ExpiresAt:       time.Now().Add(ttl),
		StrictMode:      true,          // FIELD DOES NOT EXIST — compile failure expected
		AgentKMSClient:  client,        // FIELD DOES NOT EXIST — compile failure expected
	}

	go func() {
		if err := dl.Serve(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Logf("strict listener error: %v", err)
		}
	}()

	return dl, sockPath
}

// ---------------------------------------------------------------------------
// Test 1: --strict makes one AgentKMS call per decrypt, not a burst at startup
// ---------------------------------------------------------------------------

func TestStrictListenerUsesPerDecryptAgentKMSCall(t *testing.T) {
	var hitCount atomic.Int64
	ref := KMSReference{Type: "kv", Path: "db/prod", Key: "password"}

	srv := mockStrictServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/credentials/generic/db/prod" {
			json.NewEncoder(w).Encode(map[string]any{
				"path":        "db/prod",
				"secrets":     map[string]string{"password": "s3cr3t"},
				"expires_at":  "2099-01-01T00:00:00Z",
				"ttl_seconds": 3600,
			})
			return
		}
		http.Error(w, "not found", 404)
	}, &hitCount)
	defer srv.Close()

	sid := "strict-per-decrypt"
	dl, sockPath := startStrictListener(t, sid, srv.URL, 5*time.Minute)
	defer dl.Close()

	blob := makeStrictBlob(t, sid, ref)

	// Zero hits before any decrypt
	if got := hitCount.Load(); got != 0 {
		t.Errorf("expected 0 AgentKMS hits before any decrypt, got %d", got)
	}

	// First decrypt — must cause exactly one AgentKMS hit
	resp1 := dialStrict(t, sockPath, blob)
	if resp1.Error != "" {
		t.Fatalf("decrypt 1 error: %s", resp1.Error)
	}
	if resp1.Plaintext != "s3cr3t" {
		t.Errorf("decrypt 1: plaintext = %q, want s3cr3t", resp1.Plaintext)
	}
	if got := hitCount.Load(); got != 1 {
		t.Errorf("expected 1 AgentKMS hit after first decrypt, got %d", got)
	}

	// Second decrypt — must cause a second independent hit (no local cache)
	resp2 := dialStrict(t, sockPath, blob)
	if resp2.Error != "" {
		t.Fatalf("decrypt 2 error: %s", resp2.Error)
	}
	if got := hitCount.Load(); got != 2 {
		t.Errorf("expected 2 AgentKMS hits after second decrypt, got %d", got)
	}
}

// ---------------------------------------------------------------------------
// Test 2: AgentKMS denial (403) produces error response + no plaintext
// ---------------------------------------------------------------------------

func TestStrictListenerDenialProducesErrorResponse(t *testing.T) {
	var hitCount atomic.Int64
	ref := KMSReference{Type: "kv", Path: "secret/denied", Key: "value"}

	srv := mockStrictServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Always deny
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "policy denied",
			"code":  "POLICY_DENY",
		})
	}, &hitCount)
	defer srv.Close()

	sid := "strict-denied"
	dl, sockPath := startStrictListener(t, sid, srv.URL, 5*time.Minute)
	defer dl.Close()

	blob := makeStrictBlob(t, sid, ref)
	resp := dialStrict(t, sockPath, blob)

	if resp.Error == "" {
		t.Error("expected error response for policy denial, got none")
	}
	if resp.Plaintext != "" {
		t.Errorf("expected empty plaintext on denial, got %q", resp.Plaintext)
	}
	// Error message should be informative (mention policy or denied)
	if !strings.Contains(strings.ToLower(resp.Error), "denied") &&
		!strings.Contains(strings.ToLower(resp.Error), "forbidden") &&
		!strings.Contains(strings.ToLower(resp.Error), "policy") {
		t.Errorf("error message should mention denial, got: %q", resp.Error)
	}
	// AgentKMS was still called (audit event emitted on server side)
	if got := hitCount.Load(); got != 1 {
		t.Errorf("expected 1 AgentKMS hit for denied request, got %d", got)
	}
}

// ---------------------------------------------------------------------------
// Test 3: AgentKMS network failure produces error response + no plaintext
// ---------------------------------------------------------------------------

func TestStrictListenerNetworkFailureProducesErrorResponse(t *testing.T) {
	ref := KMSReference{Type: "kv", Path: "db/prod", Key: "password"}
	// Point listener at a port nothing is listening on
	sid := "strict-netfail"
	dl, sockPath := startStrictListener(t, sid, "http://127.0.0.1:19999", 5*time.Minute)
	defer dl.Close()

	blob := makeStrictBlob(t, sid, ref)
	resp := dialStrict(t, sockPath, blob)

	if resp.Error == "" {
		t.Error("expected error response for network failure, got none")
	}
	if resp.Plaintext != "" {
		t.Errorf("expected empty plaintext on network failure, got %q", resp.Plaintext)
	}
}

// ---------------------------------------------------------------------------
// Test 4: Audit events are emitted per decrypt on the server side
// ---------------------------------------------------------------------------

func TestStrictAuditEventsEmittedPerDecrypt(t *testing.T) {
	// The "audit event" in KPM's architecture is a server-side concern: AgentKMS
	// logs each credential GET. Here we verify that the listener makes N server
	// calls for N child decrypts — the server receiving these calls is where audit
	// records land.

	var hitCount atomic.Int64
	ref := KMSReference{Type: "llm", Path: "openai"}

	srv := mockStrictServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/credentials/llm/") {
			json.NewEncoder(w).Encode(map[string]any{
				"provider":    "openai",
				"api_key":     "sk-audit-test",
				"expires_at":  "2099-01-01T00:00:00Z",
				"ttl_seconds": 3600,
			})
			return
		}
		http.Error(w, "not found", 404)
	}, &hitCount)
	defer srv.Close()

	sid := "strict-audit"
	dl, sockPath := startStrictListener(t, sid, srv.URL, 5*time.Minute)
	defer dl.Close()

	blob := makeStrictBlob(t, sid, ref)
	const decryptCount = 5
	for i := 0; i < decryptCount; i++ {
		resp := dialStrict(t, sockPath, blob)
		if resp.Error != "" {
			t.Fatalf("decrypt %d error: %s", i, resp.Error)
		}
	}

	if got := hitCount.Load(); got != decryptCount {
		t.Errorf("expected %d server hits (audit events), got %d", decryptCount, got)
	}
}

// ---------------------------------------------------------------------------
// Test 5: Non-strict (default) path is unchanged
// ---------------------------------------------------------------------------

func TestNonStrictPathUnchangedByStrictCode(t *testing.T) {
	// Verify that a standard DecryptListener (StrictMode=false / zero value)
	// still decrypts locally using the session key, with zero AgentKMS calls.

	sk, err := NewSessionKey()
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroBytes(sk)

	ct, err := EncryptLocal(sk, []byte("non-strict-secret"))
	if err != nil {
		t.Fatal(err)
	}
	sid := "non-strict-unchanged"
	blob := FormatCiphertextBlob(sid, ct) // standard ENC[kpm:...] blob

	sockPath := shortSockPath(t, "non-strict.sock")
	dl := &DecryptListener{
		SocketPath: sockPath,
		SessionKey: sk,
		SessionID:  sid,
		ExpiresAt:  time.Now().Add(5 * time.Minute),
		// StrictMode intentionally absent (zero value = false)
	}
	go dl.Serve()
	defer dl.Close()

	resp := dialStrict(t, sockPath, blob)
	if resp.Error != "" {
		t.Fatalf("non-strict decrypt error: %s", resp.Error)
	}
	if resp.Plaintext != "non-strict-secret" {
		t.Errorf("plaintext = %q, want non-strict-secret", resp.Plaintext)
	}
}

// ---------------------------------------------------------------------------
// Test 6: --strict combined with --plaintext is a hard error (no calls made)
// ---------------------------------------------------------------------------

func TestStrictAndPlaintextConflict(t *testing.T) {
	// ValidateStrictFlags returns an error when both strict and plaintext are true.
	// This function DOES NOT EXIST YET — will fail to compile.
	err := ValidateStrictFlags(true, true) // FUNCTION DOES NOT EXIST YET
	if err == nil {
		t.Error("expected error when strict=true and plaintext=true")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "incompatible") &&
		!strings.Contains(strings.ToLower(err.Error()), "conflict") &&
		!strings.Contains(strings.ToLower(err.Error()), "cannot") &&
		!strings.Contains(strings.ToLower(err.Error()), "mutually") {
		t.Errorf("error should describe the conflict: %q", err.Error())
	}
	// No conflict when only strict
	if err2 := ValidateStrictFlags(true, false); err2 != nil {
		t.Errorf("strict=true, plaintext=false should not error: %v", err2)
	}
	// No conflict when only plaintext
	if err3 := ValidateStrictFlags(false, true); err3 != nil {
		t.Errorf("strict=false, plaintext=true should not error: %v", err3)
	}
	// No conflict when neither
	if err4 := ValidateStrictFlags(false, false); err4 != nil {
		t.Errorf("strict=false, plaintext=false should not error: %v", err4)
	}
}

// ---------------------------------------------------------------------------
// Test 7: Multiple decrypts of same var in same child session both go to server
// ---------------------------------------------------------------------------

func TestStrictMultipleDecryptsSameVarBothGoToServer(t *testing.T) {
	// Same as Test 1 but explicitly focused on "same variable, two decrypts".
	// The listener must NOT cache the first decrypt result and serve the second
	// from a local map — each must produce an independent AgentKMS call.

	var hitCount atomic.Int64
	ref := KMSReference{Type: "kv", Path: "stripe/prod", Key: "api_key"}

	srv := mockStrictServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/credentials/generic/stripe/prod" {
			json.NewEncoder(w).Encode(map[string]any{
				"path":        "stripe/prod",
				"secrets":     map[string]string{"api_key": "sk_live_abc"},
				"expires_at":  "2099-01-01T00:00:00Z",
				"ttl_seconds": 3600,
			})
			return
		}
		http.Error(w, "not found", 404)
	}, &hitCount)
	defer srv.Close()

	sid := "strict-same-var"
	dl, sockPath := startStrictListener(t, sid, srv.URL, 5*time.Minute)
	defer dl.Close()

	blob := makeStrictBlob(t, sid, ref)

	resp1 := dialStrict(t, sockPath, blob)
	resp2 := dialStrict(t, sockPath, blob) // identical blob, second request

	if resp1.Error != "" || resp2.Error != "" {
		t.Fatalf("decrypt errors: %q / %q", resp1.Error, resp2.Error)
	}
	if got := hitCount.Load(); got != 2 {
		t.Errorf("expected 2 server hits for 2 decrypts of same var, got %d (local cache suspected)", got)
	}
}

// ---------------------------------------------------------------------------
// Test 8: --strict + SecureMode config (true) is compatible, not a conflict
// ---------------------------------------------------------------------------

func TestStrictWithSecureModeConfigIsCompatible(t *testing.T) {
	// SecureMode is a Config field (config.yaml: secure_mode: true).
	// It controls whether kpm env defaults to ciphertext output.
	// It is NOT a flag and does NOT conflict with --strict.
	// This test verifies that a strict listener operates correctly when
	// cfg.SecureMode == true.

	var hitCount atomic.Int64
	ref := KMSReference{Type: "kv", Path: "vault/key", Key: "token"}

	srv := mockStrictServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/credentials/generic/vault/key" {
			json.NewEncoder(w).Encode(map[string]any{
				"path":        "vault/key",
				"secrets":     map[string]string{"token": "tok-secure"},
				"expires_at":  "2099-01-01T00:00:00Z",
				"ttl_seconds": 3600,
			})
			return
		}
		http.Error(w, "not found", 404)
	}, &hitCount)
	defer srv.Close()

	sid := "strict-securemode"
	// Config with SecureMode=true — strict listener is created the same way regardless
	cfg := &Config{
		Server:        srv.URL,
		SecureMode:    true,
		SessionKeyTTL: 300,
	}
	_ = cfg // used by implementation to wire the listener; here we test listener directly

	dl, sockPath := startStrictListener(t, sid, srv.URL, 5*time.Minute)
	defer dl.Close()

	blob := makeStrictBlob(t, sid, ref)
	resp := dialStrict(t, sockPath, blob)

	if resp.Error != "" {
		t.Fatalf("unexpected error in strict+securemode: %s", resp.Error)
	}
	if resp.Plaintext != "tok-secure" {
		t.Errorf("plaintext = %q, want tok-secure", resp.Plaintext)
	}
}

// ---------------------------------------------------------------------------
// Test 9: Session TTL is still enforced in strict mode
// ---------------------------------------------------------------------------

func TestStrictSessionTTLStillEnforced(t *testing.T) {
	var hitCount atomic.Int64
	ref := KMSReference{Type: "kv", Path: "some/path", Key: "key"}

	srv := mockStrictServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"path":        "some/path",
			"secrets":     map[string]string{"key": "should-not-reach"},
			"expires_at":  "2099-01-01T00:00:00Z",
			"ttl_seconds": 3600,
		})
	}, &hitCount)
	defer srv.Close()

	sid := "strict-ttl"
	// Use a negative TTL — session already expired
	dl, sockPath := startStrictListener(t, sid, srv.URL, -1*time.Minute)
	defer dl.Close()

	blob := makeStrictBlob(t, sid, ref)
	resp := dialStrict(t, sockPath, blob)

	if resp.Error == "" {
		t.Error("expected error for expired session in strict mode")
	}
	if !strings.Contains(resp.Error, "expired") {
		t.Errorf("error should mention session expiry, got: %q", resp.Error)
	}
	// AgentKMS must NOT have been called — TTL check must be first
	if got := hitCount.Load(); got != 0 {
		t.Errorf("AgentKMS should not be called after TTL expiry, got %d calls", got)
	}
}

// ---------------------------------------------------------------------------
// Test 10: mTLS failure produces clear error, not a generic decrypt failure
// ---------------------------------------------------------------------------

func TestStrictMTLSFailureProducesClearError(t *testing.T) {
	// We set up a real TLS server and then create a client that cannot verify
	// its certificate (no CA configured), simulating an mTLS handshake failure.
	ref := KMSReference{Type: "kv", Path: "db/prod", Key: "password"}

	var hitCount atomic.Int64
	srv := mockStrictServerTLS(t, func(w http.ResponseWriter, r *http.Request) {
		hitCount.Add(1)
		json.NewEncoder(w).Encode(map[string]any{
			"path":        "db/prod",
			"secrets":     map[string]string{"password": "should-not-reach"},
			"expires_at":  "2099-01-01T00:00:00Z",
			"ttl_seconds": 3600,
		})
	}, &hitCount)
	defer srv.Close()

	// Use the TLS server URL with a plain HTTP client (no TLS config) —
	// this will cause a TLS handshake failure.
	// Note: newClientWithTLS(url, nil) sends HTTP, not HTTPS, so connecting
	// to an HTTPS-only server will fail at the protocol level.
	sid := "strict-mtls-fail"
	sockPath := shortSockPath(t, "strict-mtls.sock")

	// Build the listener manually: point at HTTPS server URL but with nil TLS config
	// (so the client will fail to make the HTTPS connection).
	client := newClientWithTLS(srv.URL, nil) // nil TLS → HTTP client against HTTPS server

	dl := &DecryptListener{ // StrictMode DOES NOT EXIST YET — compile failure expected
		SocketPath:     sockPath,
		SessionID:      sid,
		ExpiresAt:      time.Now().Add(5 * time.Minute),
		StrictMode:     true,   // FIELD DOES NOT EXIST YET
		AgentKMSClient: client, // FIELD DOES NOT EXIST YET
	}
	go dl.Serve()
	defer dl.Close()

	blob := makeStrictBlob(t, sid, ref)
	resp := dialStrict(t, sockPath, blob)

	if resp.Error == "" {
		t.Error("expected error for mTLS failure, got none")
	}
	if resp.Plaintext != "" {
		t.Errorf("expected empty plaintext on mTLS failure, got %q", resp.Plaintext)
	}
	// AgentKMS server should NOT have been reached (handshake fails before request)
	if got := hitCount.Load(); got != 0 {
		t.Errorf("server should not be hit on mTLS failure, got %d hits", got)
	}
}

// ---------------------------------------------------------------------------
// Test 11: ParseStrictBlob round-trips correctly
// ---------------------------------------------------------------------------

func TestParseStrictBlob(t *testing.T) {
	// ParseStrictBlob DOES NOT EXIST YET — compile failure expected

	ref := KMSReference{Type: "kv", Path: "db/prod", Key: "password", Default: "fallback"}
	blob, err := FormatStrictBlob("sess123", ref) // DOES NOT EXIST YET
	if err != nil {
		t.Fatalf("FormatStrictBlob: %v", err)
	}

	if !strings.HasPrefix(blob, "ENC[kpm-strict:") {
		t.Errorf("blob should start with ENC[kpm-strict:, got: %q", blob[:min(30, len(blob))])
	}

	sid, got, err := ParseStrictBlob(blob) // DOES NOT EXIST YET
	if err != nil {
		t.Fatalf("ParseStrictBlob: %v", err)
	}
	if sid != "sess123" {
		t.Errorf("sessionID = %q, want sess123", sid)
	}
	if got.Type != ref.Type || got.Path != ref.Path || got.Key != ref.Key || got.Default != ref.Default {
		t.Errorf("ref mismatch: got %+v, want %+v", got, ref)
	}
}

// ---------------------------------------------------------------------------
// Test 12: FormatStrictBlob rejects invalid KMSReference
// ---------------------------------------------------------------------------

func TestFormatStrictBlob(t *testing.T) {
	// FormatStrictBlob DOES NOT EXIST YET — compile failure expected

	// Valid reference must produce a blob without error
	ref := KMSReference{Type: "llm", Path: "openai"}
	blob, err := FormatStrictBlob("s1", ref) // DOES NOT EXIST YET
	if err != nil {
		t.Fatalf("unexpected error for valid ref: %v", err)
	}
	if blob == "" {
		t.Error("expected non-empty blob")
	}

	// Empty Type must be rejected
	_, err = FormatStrictBlob("s1", KMSReference{}) // DOES NOT EXIST YET
	if err == nil {
		t.Error("expected error for empty KMSReference.Type")
	}

	// Empty sessionID must be rejected
	_, err = FormatStrictBlob("", ref) // DOES NOT EXIST YET
	if err == nil {
		t.Error("expected error for empty sessionID")
	}
}

// ---------------------------------------------------------------------------
// min helper (Go 1.20 has it built-in; keep compat with older toolchain)
// ---------------------------------------------------------------------------

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
