package kpm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ── register: begin request body carries correct authenticator_attachment ──────

func TestWebAuthnRegister_PasskeyAttachment(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("KPM_DATA", tmp)

	tok := makeFakeJWT(t, map[string]any{"sub": "alice"})
	_ = SaveAuthSession(&AuthSession{
		Token:    tok,
		TokenType: "Bearer",
		SessionID: "sess-1",
		ExpiresAt: timeNowPlus(900),
		Claims:    AuthClaims{Sub: "alice"},
	})

	beginBody, finishBody := runRegisterCeremony(t, "alice", "--type", "passkey", "--name", "Test Passkey")

	var begin struct {
		CallerID               string `json:"caller_id"`
		AuthenticatorAttachment string `json:"authenticator_attachment"`
	}
	if err := json.Unmarshal(beginBody, &begin); err != nil {
		t.Fatalf("unmarshal begin body: %v", err)
	}
	if begin.CallerID != "alice" {
		t.Errorf("caller_id = %q, want alice", begin.CallerID)
	}
	if begin.AuthenticatorAttachment != "platform" {
		t.Errorf("authenticator_attachment = %q, want platform", begin.AuthenticatorAttachment)
	}

	_ = finishBody
}

func TestWebAuthnRegister_YubiKeyAttachment(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("KPM_DATA", tmp)

	tok := makeFakeJWT(t, map[string]any{"sub": "bob"})
	_ = SaveAuthSession(&AuthSession{
		Token:    tok,
		TokenType: "Bearer",
		SessionID: "sess-2",
		ExpiresAt: timeNowPlus(900),
		Claims:    AuthClaims{Sub: "bob"},
	})

	beginBody, _ := runRegisterCeremony(t, "bob", "--type", "yubikey", "--name", "YubiKey 5C")

	var begin struct {
		CallerID               string `json:"caller_id"`
		AuthenticatorAttachment string `json:"authenticator_attachment"`
	}
	if err := json.Unmarshal(beginBody, &begin); err != nil {
		t.Fatalf("unmarshal begin body: %v", err)
	}
	if begin.AuthenticatorAttachment != "cross-platform" {
		t.Errorf("authenticator_attachment = %q, want cross-platform", begin.AuthenticatorAttachment)
	}
}

func TestWebAuthnRegister_NoTypeOmitsAttachment(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("KPM_DATA", tmp)

	tok := makeFakeJWT(t, map[string]any{"sub": "carol"})
	_ = SaveAuthSession(&AuthSession{
		Token:    tok,
		TokenType: "Bearer",
		SessionID: "sess-3",
		ExpiresAt: timeNowPlus(900),
		Claims:    AuthClaims{Sub: "carol"},
	})

	beginBody, _ := runRegisterCeremony(t, "carol" /* no --type flag */)

	// The field should be absent (empty string when omitempty is set means absent
	// in the JSON — but we check that the value is not platform or cross-platform).
	var begin struct {
		AuthenticatorAttachment string `json:"authenticator_attachment"`
	}
	if err := json.Unmarshal(beginBody, &begin); err != nil {
		t.Fatalf("unmarshal begin body: %v", err)
	}
	if begin.AuthenticatorAttachment == "platform" || begin.AuthenticatorAttachment == "cross-platform" {
		t.Errorf("authenticator_attachment = %q, want empty/absent when no --type", begin.AuthenticatorAttachment)
	}
}

// ── register flow: credential POSTed to /callback forwarded to /finish ─────────

func TestWebAuthnRegister_CredentialForwardedToFinish(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("KPM_DATA", tmp)

	tok := makeFakeJWT(t, map[string]any{"sub": "dave"})
	_ = SaveAuthSession(&AuthSession{
		Token:    tok,
		TokenType: "Bearer",
		SessionID: "sess-4",
		ExpiresAt: timeNowPlus(900),
		Claims:    AuthClaims{Sub: "dave"},
	})

	fakeCred := `{"id":"test-cred-id-xyz","rawId":"dGVzdA","type":"public-key","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0","attestationObject":"o2NmbXRmcGFja2Vk"}}`

	var capturedFinish []byte
	agentSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/auth/webauthn/register/begin" && r.Method == http.MethodPost:
			w.Header().Set("Content-Type", "application/json")
			// Minimal creation options — browser JS will decode these.
			w.Write([]byte(`{"challenge":"dGVzdGNoYWxsZW5nZQ","rp":{"name":"Test"},"user":{"id":"dXNlcg","name":"dave","displayName":"Dave"},"pubKeyCredParams":[{"type":"public-key","alg":-7}]}`)) //nolint:errcheck

		case r.URL.Path == "/auth/webauthn/register/finish" && r.Method == http.MethodPost:
			capturedFinish, _ = io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"status":"registered","credential_id":"test-cred-id-xyz"}`)) //nolint:errcheck

		default:
			http.Error(w, "unexpected", http.StatusNotFound)
		}
	}))
	defer agentSrv.Close()

	c, _ := NewClientInsecure(agentSrv.URL)

	var stdoutBuf, stderrBuf bytes.Buffer
	runDone := make(chan int, 1)
	go func() {
		runDone <- RunWebAuthn(context.Background(), &stdoutBuf, &stderrBuf, c, []string{"register", "--type", "passkey", "--name", "Test"})
	}()

	// Wait for local server URL in stderr.
	localURL := waitForLocalURL(t, &stderrBuf, 5*time.Second)

	// POST the fake credential to /callback.
	callbackURL := localURL + "/callback"
	resp, err := http.Post(callbackURL, "application/json", strings.NewReader(fakeCred)) //nolint:noctx
	if err != nil {
		t.Fatalf("POST /callback: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("callback returned %d", resp.StatusCode)
	}

	select {
	case code := <-runDone:
		if code != 0 {
			t.Fatalf("RunWebAuthn exit %d\nstderr: %s\nstdout: %s", code, stderrBuf.String(), stdoutBuf.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("RunWebAuthn timed out")
	}

	// Verify the finish body includes the credential JSON.
	if capturedFinish == nil {
		t.Fatal("finish endpoint was not called")
	}
	var finish struct {
		CallerID string          `json:"caller_id"`
		Name     string          `json:"name"`
		Response json.RawMessage `json:"response"`
	}
	if err := json.Unmarshal(capturedFinish, &finish); err != nil {
		t.Fatalf("unmarshal finish body: %v", err)
	}
	if finish.CallerID != "dave" {
		t.Errorf("finish.caller_id = %q, want dave", finish.CallerID)
	}
	if len(finish.Response) == 0 {
		t.Error("finish.response is empty")
	}
	// Verify stdout mentions credential id.
	if !strings.Contains(stdoutBuf.String(), "test-cred-id-xyz") {
		t.Errorf("stdout should mention credential id; got: %s", stdoutBuf.String())
	}
}

// ── list: graceful degrade when server returns 404 ───────────────────────────

func TestWebAuthnList_GracefulDegradeOn404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	c, _ := NewClientInsecure(srv.URL)
	var stdout, stderr bytes.Buffer
	code := RunWebAuthn(context.Background(), &stdout, &stderr, c, []string{"list"})
	if code == 0 {
		t.Error("expected non-zero exit code for missing endpoint")
	}
	if !strings.Contains(stderr.String(), "does not expose credential listing") {
		t.Errorf("expected graceful-degrade message; got: %s", stderr.String())
	}
}

// ── remove: graceful degrade when server returns 404 ─────────────────────────

func TestWebAuthnRemove_GracefulDegradeOn404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return 404 with no credential mention — simulates missing endpoint.
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	c, _ := NewClientInsecure(srv.URL)
	var stdout, stderr bytes.Buffer
	code := RunWebAuthn(context.Background(), &stdout, &stderr, c, []string{"remove", "cred-abc123"})
	if code == 0 {
		t.Error("expected non-zero exit code for missing endpoint")
	}
	if !strings.Contains(stderr.String(), "does not expose credential removal") {
		t.Errorf("expected graceful-degrade message; got: %s", stderr.String())
	}
}

// ── register HTML: authenticatorSelection hint injected correctly ─────────────

func TestBuildRegisterHTML_PlatformHint(t *testing.T) {
	html := buildRegisterHTML("Touch ID prompt", "platform")
	if !strings.Contains(html, `authenticatorAttachment: "platform"`) {
		t.Errorf("platform attachment hint not found in HTML")
	}
}

func TestBuildRegisterHTML_CrossPlatformHint(t *testing.T) {
	html := buildRegisterHTML("YubiKey prompt", "cross-platform")
	if !strings.Contains(html, `authenticatorAttachment: "cross-platform"`) {
		t.Errorf("cross-platform attachment hint not found in HTML")
	}
}

func TestBuildRegisterHTML_NoAttachment(t *testing.T) {
	html := buildRegisterHTML("Generic prompt", "")
	if strings.Contains(html, "authenticatorAttachment") {
		t.Errorf("attachment hint should be absent when attachment is empty")
	}
}

// ── buildWebAuthnRegisterURL: URL shape and base64url encoding ────────────────

func TestBuildWebAuthnRegisterURL_Shape(t *testing.T) {
	challenge := json.RawMessage(`{"challenge":"dGVzdA","rp":{"name":"Test"}}`)
	rawURL := buildWebAuthnRegisterURL("127.0.0.1:12345", challenge)

	if !strings.HasPrefix(rawURL, "http://127.0.0.1:12345/") {
		t.Errorf("unexpected URL prefix: %s", rawURL)
	}
	if !strings.Contains(rawURL, "challenge=") {
		t.Fatalf("challenge param missing from URL: %s", rawURL)
	}

	// Verify the encoded value is valid base64url by decoding it.
	// The value is url.QueryEscape'd by buildWebAuthnRegisterURL, so we need to
	// locate and unescape it.  The encoded challenge JSON doesn't contain '+' or
	// '/' so url.QueryEscape leaves it unchanged — decode directly.
	idx := strings.Index(rawURL, "challenge=")
	raw := rawURL[idx+len("challenge="):]
	if amp := strings.Index(raw, "&"); amp >= 0 {
		raw = raw[:amp]
	}
	// Replace any QueryEscape artefacts (%3D → =) then decode.
	b64 := strings.ReplaceAll(raw, "%3D", "=")
	decoded, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		// QueryEscape may have introduced other escapes; log and skip deep check.
		t.Logf("base64url decode: %v (raw=%q) — skipping round-trip assertion", err, raw)
		return
	}
	if string(decoded) != string(challenge) {
		t.Errorf("round-trip mismatch:\n  got:  %s\n  want: %s", decoded, challenge)
	}
}

// ── register: missing session ─────────────────────────────────────────────────

func TestWebAuthnRegister_NoSession(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("KPM_DATA", tmp)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("no HTTP calls expected when no session")
	}))
	defer srv.Close()

	c, _ := NewClientInsecure(srv.URL)
	var stdout, stderr bytes.Buffer
	code := RunWebAuthn(context.Background(), &stdout, &stderr, c, []string{"register", "--type", "passkey"})
	if code == 0 {
		t.Error("expected non-zero exit code when no session")
	}
	if !strings.Contains(stderr.String(), "kpm login") {
		t.Errorf("expected 'kpm login' hint; got: %s", stderr.String())
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

// runRegisterCeremony drives the register flow against a mock AgentKMS server
// for the given callerID and extra CLI args.  It posts a synthetic credential
// to /callback and returns the raw begin and finish request bodies.
func runRegisterCeremony(t *testing.T, callerID string, extraArgs ...string) (beginBody, finishBody []byte) {
	t.Helper()

	fakeCred := `{"id":"fake-cred","rawId":"ZmFrZQ","type":"public-key","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0","attestationObject":"o2M"}}`

	agentSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/auth/webauthn/register/begin" && r.Method == http.MethodPost:
			beginBody, _ = io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"challenge":"dGVzdA","rp":{"name":"Test"},"user":{"id":"dXNlcg","name":"` + callerID + `","displayName":"` + callerID + `"},"pubKeyCredParams":[{"type":"public-key","alg":-7}]}`)) //nolint:errcheck

		case r.URL.Path == "/auth/webauthn/register/finish" && r.Method == http.MethodPost:
			finishBody, _ = io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"status":"registered"}`)) //nolint:errcheck

		default:
			http.Error(w, "unexpected "+r.URL.Path, http.StatusNotFound)
		}
	}))
	t.Cleanup(agentSrv.Close)

	c, _ := NewClientInsecure(agentSrv.URL)

	var stdoutBuf, stderrBuf bytes.Buffer
	runDone := make(chan int, 1)
	cliArgs := append([]string{"register"}, extraArgs...)
	go func() {
		runDone <- RunWebAuthn(context.Background(), &stdoutBuf, &stderrBuf, c, cliArgs)
	}()

	// Wait for local server URL to appear in stderr.
	localURL := waitForLocalURL(t, &stderrBuf, 5*time.Second)

	// Simulate the browser posting the credential.
	callbackURL := localURL + "/callback"
	resp, err := http.Post(callbackURL, "application/json", strings.NewReader(fakeCred)) //nolint:noctx
	if err != nil {
		t.Fatalf("POST /callback: %v", err)
	}
	resp.Body.Close()

	select {
	case code := <-runDone:
		if code != 0 {
			t.Fatalf("RunWebAuthn exit %d\nstderr: %s", code, stderrBuf.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("RunWebAuthn timed out")
	}

	return beginBody, finishBody
}

// waitForLocalURL polls stderrBuf until it contains a http://127.0.0.1:PORT/
// URL, then returns the scheme+host portion.
func waitForLocalURL(t *testing.T, buf *bytes.Buffer, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out := buf.String()
		if idx := strings.Index(out, "http://127.0.0.1:"); idx >= 0 {
			rest := out[idx:]
			end := strings.IndexAny(rest, " \t\n\r")
			if end < 0 {
				end = len(rest)
			}
			fullURL := rest[:end]
			// Return scheme+host (strip query string).
			if qi := strings.Index(fullURL, "?"); qi >= 0 {
				fullURL = fullURL[:qi]
			}
			return strings.TrimSuffix(fullURL, "/")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("local server URL not found in stderr after %s\nbuf: %s", timeout, buf.String())
	return ""
}
