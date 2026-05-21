// Package kpm — WebAuthn step-up authentication.
//
// RunStepUp implements `kpm login --step-up`.  It upgrades an existing
// cert-only session to cert+human by driving a WebAuthn ceremony through the
// user's default browser.
//
// Flow:
//  1. Load the persisted session (precondition: must exist and not be expired).
//  2. POST /auth/webauthn/auth/begin with {caller_id: <session sub>} to obtain
//     the server challenge JSON.
//  3. Start a one-shot local HTTP server on 127.0.0.1:<ephemeral-port> with two
//     routes:
//     - GET /  — HTML page with inline JS that calls navigator.credentials.get,
//               receives the base64url-encoded challenge via ?challenge=… query
//               param, and POSTs the assertion to /callback.
//     - POST /callback — receives the assertion JSON, surfaces it on a channel.
//  4. Open the browser at the local URL (xdg-open / open / cmd /c start).
//  5. Wait up to 120 s for the assertion.
//  6. POST /auth/webauthn/auth/finish with {caller_id: …, response: <assertion>}
//     over the mTLS client.
//  7. Overwrite ~/.kpm/sessions/current.json with the new cert+human session.
//  8. Print a one-line confirmation with the new expiry.
//
// The local server uses plain HTTP (not HTTPS).  Browsers permit WebAuthn on
// http://localhost per the W3C WebAuthn spec; a localhost TLS cert is neither
// required nor desirable here.
//
// The WebAuthn challenge is binary (base64url from the server).  We pass the
// entire challenge JSON — the raw bytes the server returned — through as a
// base64url query parameter so the JS page can decode it without any Go-side
// knowledge of the internal WebAuthn JSON shape.

package kpm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// stepUpTimeout is how long we wait for the user to complete the browser
// ceremony before giving up.
const stepUpTimeout = 120 * time.Second

// stepUpHTML is the one-shot browser page.  It receives the raw WebAuthn
// challenge JSON (base64url-encoded) via ?challenge=…, decodes it, calls
// navigator.credentials.get, then POSTs the assertion back to /callback.
//
// The base64url decoding helper mirrors the standard encoding used by all
// WebAuthn libraries: characters 62/63 are - and _, no padding.
const stepUpHTML = `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>KPM Step-Up</title></head>
<body>
<p id="status">Preparing WebAuthn challenge…</p>
<script>
// base64url → Uint8Array
function b64url(s) {
  s = s.replace(/-/g,'+').replace(/_/g,'/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}

// Uint8Array → base64url (no padding)
function toB64url(buf) {
  let bin = '';
  new Uint8Array(buf).forEach(b => bin += String.fromCharCode(b));
  return btoa(bin).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
}

async function run() {
  const status = document.getElementById('status');
  try {
    const params = new URLSearchParams(window.location.search);
    const enc = params.get('challenge');
    if (!enc) { status.textContent = 'Error: missing challenge param.'; return; }

    // The challenge param is the raw server JSON encoded as base64url.
    // The go-webauthn server returns {"publicKey": {...options...}}, so unwrap
    // if present; tolerate the older flat shape too.
    let opts = JSON.parse(new TextDecoder().decode(b64url(enc)));
    if (opts && opts.publicKey) opts = opts.publicKey;

    // Convert base64url challenge bytes to ArrayBuffer for the browser API.
    opts.challenge = b64url(opts.challenge).buffer;

    // Convert allowCredentials id fields if present.
    if (opts.allowCredentials) {
      opts.allowCredentials = opts.allowCredentials.map(c => ({
        ...c,
        id: b64url(c.id).buffer,
      }));
    }

    status.textContent = 'Touch your security key…';
    const cred = await navigator.credentials.get({ publicKey: opts });

    // Serialise assertion to the shape AgentKMS expects: base64url-encoded
    // binary fields, matching webauthn.AuthenticationResponseJSON.
    const assertion = {
      id: cred.id,
      rawId: toB64url(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON:    toB64url(cred.response.clientDataJSON),
        authenticatorData: toB64url(cred.response.authenticatorData),
        signature:         toB64url(cred.response.signature),
        userHandle:        cred.response.userHandle ? toB64url(cred.response.userHandle) : null,
      },
    };

    const r = await fetch('/callback', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(assertion),
    });
    if (r.ok) {
      status.textContent = 'Step-up complete — you can close this tab.';
    } else {
      status.textContent = 'Callback error: ' + r.status;
    }
  } catch(e) {
    status.textContent = 'Error: ' + e.message;
  }
}
run();
</script>
</body>
</html>`

// RunStepUp implements `kpm login --step-up`.
//
// stderr receives human-readable progress messages.
// client is the mTLS-enabled AgentKMS client (required for /auth/webauthn/auth/finish).
func RunStepUp(ctx context.Context, stderr io.Writer, client *Client) error {
	// 1. Precondition: an active session must exist.
	s, err := LoadAuthSession()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("step-up requires an active session — run 'kpm login' first")
		}
		return fmt.Errorf("step-up: load session: %w", err)
	}

	// The CallerID used in the WebAuthn ceremony is the session's Sub claim
	// (which the server documents as "CallerID: UserID when known, else cert CN").
	callerID := s.Claims.Sub
	if callerID == "" {
		return fmt.Errorf("step-up: session has no subject claim (sub) — re-run 'kpm login'")
	}

	// 2. Begin: obtain the WebAuthn challenge from the server.
	challengeJSON, err := webAuthnBegin(ctx, client, callerID)
	if err != nil {
		return fmt.Errorf("step-up: begin: %w", err)
	}

	// 3. Start the one-shot local HTTP server.
	assertionCh := make(chan json.RawMessage, 1)
	errCh := make(chan error, 1)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("step-up: open local port: %w", err)
	}

	srv := &http.Server{
		Handler: buildStepUpHandler(challengeJSON, assertionCh),
	}
	go func() {
		if serveErr := srv.Serve(ln); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errCh <- serveErr
		}
	}()
	defer srv.Close() //nolint:errcheck

	// 4. Open the browser.
	localURL := buildStepUpURL(ln.Addr().String(), challengeJSON)
	fmt.Fprintf(stderr, "Opening browser for WebAuthn step-up: %s\n", localURL)
	if err := openBrowser(localURL); err != nil {
		fmt.Fprintf(stderr, "Could not open browser automatically — please open this URL manually:\n  %s\n", localURL)
	}

	// 5. Wait for the assertion (or timeout).
	fmt.Fprintf(stderr, "Waiting for WebAuthn ceremony (timeout: %s)…\n", stepUpTimeout)
	timeoutCtx, cancel := context.WithTimeout(ctx, stepUpTimeout)
	defer cancel()

	var assertion json.RawMessage
	select {
	case assertion = <-assertionCh:
		// ceremony complete
	case err := <-errCh:
		return fmt.Errorf("step-up: local server error: %w", err)
	case <-timeoutCtx.Done():
		return fmt.Errorf("step-up: timed out waiting for WebAuthn ceremony")
	}

	// 6. Finish: exchange the assertion for a cert+human session token.
	sr, err := webAuthnFinish(ctx, client, callerID, assertion)
	if err != nil {
		return fmt.Errorf("step-up: finish: %w", err)
	}

	// 7. Persist the new session (overwrites current.json).
	claims := DecodeJWTClaims(sr.Token)
	expiresAt := time.Now().Add(time.Duration(sr.ExpiresIn) * time.Second)
	if err := SaveAuthSession(&AuthSession{
		Token:     sr.Token,
		TokenType: sr.TokenType,
		SessionID: sr.SessionID,
		ExpiresAt: expiresAt,
		Claims:    claims,
	}); err != nil {
		return fmt.Errorf("step-up: persist session: %w", err)
	}

	// 8. Print confirmation.
	fmt.Fprintf(stderr, "Step-up complete. Session now cert+human (expires in %s).\n",
		formatRemaining(time.Until(expiresAt)))
	return nil
}

// webAuthnBegin POSTs /auth/webauthn/auth/begin and returns the raw challenge
// JSON bytes returned by the server.
func webAuthnBegin(ctx context.Context, client *Client, callerID string) (json.RawMessage, error) {
	body := struct {
		CallerID string `json:"caller_id"`
	}{CallerID: callerID}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		return nil, fmt.Errorf("encode begin request: %w", err)
	}

	// /begin is lenient on mTLS (per the server handler comment), but we send
	// the mTLS client anyway — the token is set after EnsureAuth is called by
	// doPost, but we don't want ensureAuth side effects here.  Use the raw
	// httpClient to avoid automatic /auth/session re-auth.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		client.baseURL+"/auth/webauthn/auth/begin", &buf)
	if err != nil {
		return nil, fmt.Errorf("build begin request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// Include current bearer if we have one (best-effort; begin doesn't require it).
	if client.token != "" {
		req.Header.Set("Authorization", "Bearer "+client.token)
	}

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("begin request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, serverError(resp, "webauthn/auth/begin")
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read begin response: %w", err)
	}
	return json.RawMessage(raw), nil
}

// webAuthnFinish POSTs /auth/webauthn/auth/finish and returns the new session
// response.  The /finish endpoint requires a valid mTLS client certificate.
func webAuthnFinish(ctx context.Context, client *Client, callerID string, assertion json.RawMessage) (*SessionResponse, error) {
	body := struct {
		CallerID string          `json:"caller_id"`
		Response json.RawMessage `json:"response"`
	}{
		CallerID: callerID,
		Response: assertion,
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		return nil, fmt.Errorf("encode finish request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		client.baseURL+"/auth/webauthn/auth/finish", &buf)
	if err != nil {
		return nil, fmt.Errorf("build finish request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// /finish requires a bearer token in addition to mTLS.
	if client.token != "" {
		req.Header.Set("Authorization", "Bearer "+client.token)
	}

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("finish request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, serverError(resp, "webauthn/auth/finish")
	}

	var sr SessionResponse
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		return nil, fmt.Errorf("decode finish response: %w", err)
	}
	return &sr, nil
}

// buildStepUpURL constructs the URL the browser should open.  The challenge
// JSON is base64url-encoded into the ?challenge query parameter so the inline
// JS can decode it without any server-side templating.
//
// The addr is rewritten from "127.0.0.1:<port>" to "localhost:<port>" so that
// the browser's WebAuthn ceremony sees effective domain "localhost", which
// matches the server's RPID.  The listener still binds to 127.0.0.1 for
// security; only the URL handed to the browser is rewritten.
func buildStepUpURL(addr string, challengeJSON json.RawMessage) string {
	encoded := base64.RawURLEncoding.EncodeToString(challengeJSON)
	u := &url.URL{
		Scheme:   "http",
		Host:     localhostURL(addr),
		Path:     "/",
		RawQuery: "challenge=" + url.QueryEscape(encoded),
	}
	return u.String()
}

// localhostURL replaces a "127.0.0.1:<port>" addr with "localhost:<port>" so
// the browser-side WebAuthn ceremony's effective domain is "localhost"
// (matching the server's RPID), not "127.0.0.1".
func localhostURL(addr string) string {
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return "localhost" + addr[i:]
	}
	return addr
}

// buildStepUpHandler returns an http.Handler that serves the WebAuthn ceremony
// page (GET /) and the assertion callback (POST /callback).
//
// On a successful POST /callback the assertion is sent on assertionCh (non-blocking,
// buffered-1) and the server responds 200.  Subsequent POSTs after the channel is
// full are acknowledged but ignored.
func buildStepUpHandler(challengeJSON json.RawMessage, assertionCh chan<- json.RawMessage) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, stepUpHTML)
	})

	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
		if err != nil {
			http.Error(w, "read error", http.StatusInternalServerError)
			return
		}
		if !json.Valid(body) {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		// Non-blocking send: if the channel is already full (duplicate callback),
		// silently discard.
		select {
		case assertionCh <- json.RawMessage(body):
		default:
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "Step-up complete — you can close this tab.")
	})

	return mux
}

// openBrowser shells out to the platform's default browser opener.
// Returns an error if the exec fails; callers should fall back to printing
// the URL.
func openBrowser(rawURL string) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
		args = []string{rawURL}
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start", rawURL}
	default:
		// Linux and everything else.
		cmd = "xdg-open"
		args = []string{rawURL}
	}

	return exec.Command(cmd, args...).Start()
}
