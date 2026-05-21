package kpm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// ── callback handler unit test ────────────────────────────────────────────────

// TestCallbackHandler_DeliverstAssertionToChannel verifies that a valid JSON
// POST to /callback is surfaced on the assertion channel and the handler
// returns HTTP 200.
func TestCallbackHandler_DeliverstAssertionToChannel(t *testing.T) {
	ch := make(chan json.RawMessage, 1)
	handler := buildStepUpHandler(json.RawMessage(`{}`), ch)

	assertion := `{"id":"test-id","type":"public-key"}`
	req := httptest.NewRequest(http.MethodPost, "/callback",
		strings.NewReader(assertion))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	select {
	case got := <-ch:
		if string(got) != assertion {
			t.Errorf("assertion = %q, want %q", string(got), assertion)
		}
	default:
		t.Fatal("assertion not delivered to channel")
	}
}

// TestCallbackHandler_InvalidJSONReturns400 verifies that malformed JSON
// bodies are rejected before reaching the channel.
func TestCallbackHandler_InvalidJSONReturns400(t *testing.T) {
	ch := make(chan json.RawMessage, 1)
	handler := buildStepUpHandler(json.RawMessage(`{}`), ch)

	req := httptest.NewRequest(http.MethodPost, "/callback",
		strings.NewReader("not-json{{{"))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
	if len(ch) != 0 {
		t.Error("channel should be empty after invalid JSON")
	}
}

// TestCallbackHandler_DuplicatePostDropped verifies that a second POST to
// /callback (after the channel is already full) is accepted with 200 but
// silently discarded — the channel holds only the first assertion.
func TestCallbackHandler_DuplicatePostDropped(t *testing.T) {
	ch := make(chan json.RawMessage, 1)
	handler := buildStepUpHandler(json.RawMessage(`{}`), ch)

	post := func(body string) int {
		req := httptest.NewRequest(http.MethodPost, "/callback", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr.Code
	}

	first := `{"id":"first"}`
	second := `{"id":"second"}`

	if code := post(first); code != http.StatusOK {
		t.Fatalf("first POST: expected 200, got %d", code)
	}
	if code := post(second); code != http.StatusOK {
		t.Fatalf("second POST: expected 200, got %d", code)
	}

	got := <-ch
	if string(got) != first {
		t.Errorf("channel holds %q, want first assertion %q", string(got), first)
	}
	if len(ch) != 0 {
		t.Error("channel should be empty — second assertion should have been dropped")
	}
}

// TestCallbackHandler_GetOnCallbackReturns405 verifies that the /callback
// route rejects GET requests.
func TestCallbackHandler_GetOnCallbackReturns405(t *testing.T) {
	ch := make(chan json.RawMessage, 1)
	handler := buildStepUpHandler(json.RawMessage(`{}`), ch)

	req := httptest.NewRequest(http.MethodGet, "/callback", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}

// ── challenge URL encoding unit test ──────────────────────────────────────────

// TestBuildStepUpURL_ChallengeRoundTrips verifies that the ?challenge=…
// query parameter is base64url-encoded and that the same bytes survive a
// round-trip through base64url decode.
func TestBuildStepUpURL_ChallengeRoundTrips(t *testing.T) {
	// Use a challenge JSON that contains a binary-ish challenge field.
	challengeJSON := json.RawMessage(`{"challenge":"dGVzdGNoYWxsZW5nZQ","timeout":60000}`)
	addr := "127.0.0.1:39999"

	rawURL := buildStepUpURL(addr, challengeJSON)

	if !strings.HasPrefix(rawURL, "http://localhost:39999/") {
		t.Errorf("URL has unexpected prefix: %s", rawURL)
	}
	if !strings.Contains(rawURL, "challenge=") {
		t.Fatalf("URL missing challenge param: %s", rawURL)
	}

	// Parse the URL properly to get the decoded query param value.
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	encodedChallenge := parsed.Query().Get("challenge")
	if encodedChallenge == "" {
		t.Fatalf("challenge param empty after URL parse")
	}

	// The value is base64url-encoded (RawURL = no padding).
	decoded, err := base64.RawURLEncoding.DecodeString(encodedChallenge)
	if err != nil {
		t.Fatalf("base64url decode failed: %v (encoded: %q)", err, encodedChallenge)
	}

	if string(decoded) != string(challengeJSON) {
		t.Errorf("round-trip mismatch:\n  got:  %s\n  want: %s", decoded, challengeJSON)
	}
}

// TestBuildStepUpURL_Base64URLNoPadding verifies that the encoded challenge
// does not contain standard base64 padding characters that would break the
// JS b64url() decoder.
func TestBuildStepUpURL_Base64URLNoPadding(t *testing.T) {
	challengeJSON := json.RawMessage(`{"challenge":"abc","timeout":30000}`)
	rawURL := buildStepUpURL("127.0.0.1:1234", challengeJSON)

	// Extract raw encoded value (before URL-decoding).
	idx := strings.Index(rawURL, "challenge=")
	if idx < 0 {
		t.Fatal("challenge param missing")
	}
	encoded := rawURL[idx+len("challenge="):]

	// The raw base64url value in the URL must not contain '=' (padding).
	// url.QueryEscape encodes '=' as '%3D', so check for neither.
	if strings.Contains(encoded, "=") {
		t.Errorf("encoded challenge contains raw '=' padding (not URL-safe): %s", encoded)
	}
}

// ── localhostURL: step-up browser URL uses localhost, not 127.0.0.1 ──────────

// TestBuildStepUpURL_UsesLocalhost verifies that buildStepUpURL rewrites the
// "127.0.0.1:<port>" bind address to "localhost:<port>" so the browser's
// WebAuthn ceremony sees effective domain "localhost" (matching the server RPID).
func TestBuildStepUpURL_UsesLocalhost(t *testing.T) {
	challengeJSON := json.RawMessage(`{"challenge":"dGVzdA","timeout":60000}`)
	rawURL := buildStepUpURL("127.0.0.1:12345", challengeJSON)

	if strings.HasPrefix(rawURL, "http://127.0.0.1:") {
		t.Errorf("step-up URL uses 127.0.0.1; want localhost. URL: %s", rawURL)
	}
	if !strings.HasPrefix(rawURL, "http://localhost:12345/") {
		t.Errorf("step-up URL does not start with http://localhost:12345/. URL: %s", rawURL)
	}
}

// TestRunStepUp_OpensLocalhostNot127 drives RunStepUp end-to-end and asserts
// the URL printed to stderr (and handed to the browser) uses "localhost".
func TestRunStepUp_OpensLocalhostNot127(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("KPM_DATA", tmp)

	tok := makeFakeJWT(t, map[string]any{"sub": "grace", "as": "cert-only"})
	_ = SaveAuthSession(&AuthSession{
		Token:     tok,
		TokenType: "Bearer",
		SessionID: "sess-lh-test",
		ExpiresAt: timeNowPlus(900),
		Claims:    AuthClaims{Sub: "grace", AuthStrength: "cert-only"},
	})

	upgradedTok := makeFakeJWT(t, map[string]any{"sub": "grace", "as": "cert+human"})

	agentSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/auth/webauthn/auth/begin" && r.Method == http.MethodPost:
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"challenge":"dGVzdA","timeout":60000,"rpId":"localhost","allowCredentials":[]}`)) //nolint:errcheck
		case r.URL.Path == "/auth/webauthn/auth/finish" && r.Method == http.MethodPost:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(SessionResponse{ //nolint:errcheck
				Token: upgradedTok, TokenType: "Bearer", ExpiresIn: 3600, SessionID: "sess-lh-upgraded",
			})
		default:
			http.Error(w, "unexpected "+r.URL.Path, http.StatusNotFound)
		}
	}))
	defer agentSrv.Close()

	c, _ := NewClientInsecure(agentSrv.URL)
	var stderrBuf bytes.Buffer
	runDone := make(chan error, 1)
	go func() { runDone <- RunStepUp(context.Background(), &stderrBuf, c) }()

	// Poll until the "Opening browser" URL appears in stderr.
	deadline := time.Now().Add(5 * time.Second)
	var browserURL string
	for time.Now().Before(deadline) {
		out := stderrBuf.String()
		if idx := strings.Index(out, "http://localhost:"); idx >= 0 {
			rest := out[idx:]
			end := strings.IndexAny(rest, " \t\n\r")
			if end < 0 {
				end = len(rest)
			}
			browserURL = rest[:end]
			break
		}
		if strings.Contains(out, "http://127.0.0.1:") {
			t.Fatalf("step-up URL uses 127.0.0.1; want localhost\nstderr: %s", out)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if browserURL == "" {
		select {
		case err := <-runDone:
			t.Fatalf("RunStepUp exited before server ready: %v\nstderr: %s", err, stderrBuf.String())
		default:
		}
		t.Fatalf("localhost URL not found in stderr after 5s\nstderr: %s", stderrBuf.String())
	}

	if !strings.HasPrefix(browserURL, "http://localhost:") {
		t.Errorf("browser URL = %q, want http://localhost:<port>/...", browserURL)
	}

	// Drive the ceremony to completion so the goroutine exits cleanly.
	if qi := strings.Index(browserURL, "?"); qi >= 0 {
		browserURL = browserURL[:qi]
	}
	callbackURL := strings.TrimSuffix(browserURL, "/") + "/callback"
	fakeAssertion := `{"id":"cred-grace","rawId":"Z3JhY2U","type":"public-key","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0","authenticatorData":"AAAA","signature":"AAAA","userHandle":null}}`
	resp, err := http.Post(callbackURL, "application/json", strings.NewReader(fakeAssertion)) //nolint:noctx
	if err != nil {
		t.Fatalf("POST /callback: %v", err)
	}
	resp.Body.Close()

	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("RunStepUp error: %v\nstderr: %s", err, stderrBuf.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("RunStepUp timed out\nstderr: %s", stderrBuf.String())
	}
}

// ── RunStepUp integration-style test against httptest servers ─────────────────

// TestRunStepUp_NoSession errors when there is no persisted session.
func TestRunStepUp_NoSession(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("KPM_DATA", tmp)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("no HTTP calls expected — no session exists")
	}))
	defer srv.Close()

	c, _ := NewClientInsecure(srv.URL)
	err := RunStepUp(context.Background(), io.Discard, c)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "run 'kpm login' first") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestRunStepUp_FullCeremony drives the complete step-up flow using two
// httptest servers: one for the AgentKMS API endpoints and one that simulates
// the WebAuthn local HTTP server by posting the assertion directly via HTTP.
//
// This test bypasses the real browser: it locates the one-shot server address
// from the begin/finish interception, then manually POSTs the assertion to
// /callback as if the browser had completed the ceremony.
func TestRunStepUp_FullCeremony(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("KPM_DATA", tmp)

	// Pre-populate a cert-only session.
	initialToken := makeFakeJWT(t, map[string]any{
		"sub": "bert",
		"as":  "cert-only",
	})
	_ = SaveAuthSession(&AuthSession{
		Token:     initialToken,
		TokenType: "Bearer",
		SessionID: "sess-before",
		ExpiresAt: timeNowPlus(900),
		Claims: AuthClaims{
			Sub:          "bert",
			AuthStrength: "cert-only",
		},
	})

	upgradedToken := makeFakeJWT(t, map[string]any{
		"sub": "bert",
		"as":  "cert+human",
	})

	var beginCalled, finishCalled bool
	agentSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/auth/webauthn/auth/begin" && r.Method == http.MethodPost:
			var req struct{ CallerID string `json:"caller_id"` }
			json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck
			if req.CallerID != "bert" {
				http.Error(w, "wrong caller_id", http.StatusBadRequest)
				return
			}
			beginCalled = true
			// Return a minimal challenge JSON.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"challenge":"dGVzdA","timeout":60000,"rpId":"localhost","allowCredentials":[]}`)) //nolint:errcheck

		case r.URL.Path == "/auth/webauthn/auth/finish" && r.Method == http.MethodPost:
			var req struct {
				CallerID string          `json:"caller_id"`
				Response json.RawMessage `json:"response"`
			}
			json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck
			if req.CallerID != "bert" {
				http.Error(w, "wrong caller_id", http.StatusBadRequest)
				return
			}
			if len(req.Response) == 0 {
				http.Error(w, "empty response", http.StatusBadRequest)
				return
			}
			finishCalled = true
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(SessionResponse{ //nolint:errcheck
				Token:     upgradedToken,
				TokenType: "Bearer",
				ExpiresIn: 3600,
				SessionID: "sess-upgraded",
			})

		default:
			http.Error(w, "unexpected", http.StatusNotFound)
		}
	}))
	defer agentSrv.Close()

	c, _ := NewClientInsecure(agentSrv.URL)

	// We intercept the browser-open call by running RunStepUp in a goroutine
	// and posting to /callback ourselves once the local server is up.
	//
	// To post to the local server we need its address.  We do this by
	// instrumenting the flow: RunStepUp prints the URL to stderr; we capture
	// that and extract the host:port, then POST the fake assertion.
	var stderrBuf bytes.Buffer
	runDone := make(chan error, 1)

	go func() {
		runDone <- RunStepUp(context.Background(), &stderrBuf, c)
	}()

	// Poll until we see the URL in stderr output (the server must be listening).
	var localURL string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		out := stderrBuf.String()
		if idx := strings.Index(out, "http://localhost:"); idx >= 0 {
			// Extract the full URL up to the first whitespace.
			rest := out[idx:]
			end := strings.IndexAny(rest, " \t\n\r")
			if end < 0 {
				end = len(rest)
			}
			localURL = rest[:end]
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if localURL == "" {
		// Drain error channel before failing.
		select {
		case err := <-runDone:
			t.Fatalf("RunStepUp exited before local server was ready: %v\nstderr: %s", err, stderrBuf.String())
		default:
		}
		t.Fatalf("local server URL not found in stderr after 5s\nstderr: %s", stderrBuf.String())
	}

	// Extract just the scheme+host from the URL (strip ?challenge=… etc).
	u := localURL
	if qi := strings.Index(u, "?"); qi >= 0 {
		u = u[:qi]
	}
	callbackURL := strings.TrimSuffix(u, "/") + "/callback"

	fakeAssertion := `{"id":"cred-id","rawId":"Y3JlZC1pZA","type":"public-key","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0","authenticatorData":"AAAA","signature":"AAAA","userHandle":null}}`
	resp, err := http.Post(callbackURL, "application/json", //nolint:noctx
		strings.NewReader(fakeAssertion))
	if err != nil {
		t.Fatalf("POST /callback: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /callback: expected 200, got %d", resp.StatusCode)
	}

	// Wait for RunStepUp to complete.
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("RunStepUp returned error: %v\nstderr: %s", err, stderrBuf.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("RunStepUp timed out\nstderr: %s", stderrBuf.String())
	}

	if !beginCalled {
		t.Error("begin endpoint was not called")
	}
	if !finishCalled {
		t.Error("finish endpoint was not called")
	}

	// Verify the persisted session was upgraded.
	got, err := LoadAuthSession()
	if err != nil {
		t.Fatalf("LoadAuthSession: %v", err)
	}
	if got.SessionID != "sess-upgraded" {
		t.Errorf("session_id = %q, want sess-upgraded", got.SessionID)
	}
	if got.Claims.AuthStrength != "cert+human" {
		t.Errorf("auth_strength = %q, want cert+human", got.Claims.AuthStrength)
	}
	if !strings.Contains(stderrBuf.String(), "cert+human") {
		t.Errorf("stderr should mention cert+human; got: %s", stderrBuf.String())
	}
}
