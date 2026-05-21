// Package kpm — WebAuthn credential management (register / list / remove).
//
// RunWebAuthn dispatches the three subcommands:
//
//	kpm webauthn register [--type passkey|yubikey] [--name "..."] [--user <id>]
//	kpm webauthn list
//	kpm webauthn remove <credential-id>
//
// The register ceremony uses the same local-HTTP-server pattern as RunStepUp
// (see step_up.go): ephemeral 127.0.0.1 port, browser-open, /callback.
// The list and remove subcommands call server endpoints that do not yet exist
// in AgentKMS; they degrade gracefully with an actionable error when the
// server returns 404.

package kpm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// webAuthnTimeout mirrors the step-up timeout: 120 seconds for the browser
// ceremony.
const webAuthnTimeout = stepUpTimeout

// RunWebAuthn is the entry point for `kpm webauthn <subcommand> [args...]`.
// Returns an exit code; the caller os.Exit's with it.
func RunWebAuthn(ctx context.Context, stdout, stderr io.Writer, client *Client, args []string) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, webAuthnUsage)
		return 1
	}
	sub := args[0]
	rest := args[1:]

	switch sub {
	case "register":
		return runWebAuthnRegister(ctx, stdout, stderr, client, rest)
	case "list":
		return runWebAuthnList(ctx, stdout, stderr, client, rest)
	case "remove":
		return runWebAuthnRemove(ctx, stdout, stderr, client, rest)
	case "help", "--help", "-h":
		fmt.Fprint(stderr, webAuthnUsage)
		return 0
	default:
		fmt.Fprintf(stderr, "kpm webauthn: unknown subcommand %q\n\n%s", sub, webAuthnUsage)
		return 1
	}
}

const webAuthnUsage = `kpm webauthn — manage WebAuthn credentials (passkeys and YubiKeys)

Usage:
  kpm webauthn register [--type passkey|yubikey] [--name <friendly-name>] [--user <caller-id>]
  kpm webauthn list
  kpm webauthn remove <credential-id>

Options for register:
  --type passkey      Use the device's built-in authenticator (Touch ID / Windows Hello).
  --type yubikey      Use a roaming authenticator (YubiKey, USB/NFC/BLE key).
  --name <name>       Friendly name stored with the credential.
  --user <id>         Caller ID to register for (defaults to the active session sub).

Examples:
  kpm webauthn register --type passkey --name "laptop Touch ID"
  kpm webauthn register --type yubikey --name "YubiKey 5C"
  kpm webauthn list
  kpm webauthn remove cred-abc123
`

// ── register ──────────────────────────────────────────────────────────────────

func runWebAuthnRegister(ctx context.Context, stdout, stderr io.Writer, client *Client, args []string) int {
	fs := flag.NewFlagSet("webauthn register", flag.ContinueOnError)
	fs.SetOutput(stderr)
	typeFlag := fs.String("type", "", "authenticator type: passkey or yubikey")
	nameFlag := fs.String("name", "", "friendly name for this credential")
	userFlag := fs.String("user", "", "caller-id to register for (default: active session sub)")

	if err := fs.Parse(args); err != nil {
		return 1
	}

	// Resolve authenticator attachment hint from --type.
	var attachment string
	switch strings.ToLower(*typeFlag) {
	case "passkey":
		attachment = "platform"
	case "yubikey":
		attachment = "cross-platform"
	case "":
		attachment = ""
	default:
		fmt.Fprintf(stderr, "kpm webauthn register: unknown --type %q (use passkey or yubikey)\n", *typeFlag)
		return 1
	}

	// Resolve caller ID: --user flag > active session sub.
	callerID := *userFlag
	if callerID == "" {
		s, err := LoadAuthSession()
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				fmt.Fprintln(stderr, "error: no active session — run 'kpm login' first")
				return 1
			}
			fmt.Fprintf(stderr, "error: load session: %v\n", err)
			return 1
		}
		callerID = s.Claims.Sub
		if callerID == "" {
			fmt.Fprintln(stderr, "error: session has no subject claim — re-run 'kpm login'")
			return 1
		}
	}

	credName := *nameFlag
	if credName == "" {
		switch *typeFlag {
		case "passkey":
			credName = "passkey"
		case "yubikey":
			credName = "YubiKey"
		default:
			credName = "webauthn-credential"
		}
	}

	// 1. Begin registration: get challenge from server.
	challengeJSON, err := webAuthnRegisterBegin(ctx, client, callerID, attachment)
	if err != nil {
		fmt.Fprintf(stderr, "error: register/begin: %v\n", err)
		return 1
	}

	// 2. Spin up one-shot local server.
	credCh := make(chan json.RawMessage, 1)
	errCh := make(chan error, 1)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(stderr, "error: open local port: %v\n", err)
		return 1
	}

	statusText := statusTextForType(*typeFlag)
	srv := &http.Server{
		Handler: buildWebAuthnRegisterHandler(challengeJSON, attachment, statusText, credCh),
	}
	go func() {
		if serveErr := srv.Serve(ln); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errCh <- serveErr
		}
	}()
	defer srv.Close() //nolint:errcheck

	// 3. Open browser.
	localURL := buildWebAuthnRegisterURL(ln.Addr().String(), challengeJSON)
	fmt.Fprintf(stderr, "Opening browser for WebAuthn registration: %s\n", localURL)
	if err := openBrowser(localURL); err != nil {
		fmt.Fprintf(stderr, "Could not open browser automatically — please open this URL manually:\n  %s\n", localURL)
	}

	// 4. Wait for credential from browser ceremony.
	fmt.Fprintf(stderr, "Waiting for WebAuthn ceremony (timeout: %s)…\n", webAuthnTimeout)
	timeoutCtx, cancel := context.WithTimeout(ctx, webAuthnTimeout)
	defer cancel()

	var credJSON json.RawMessage
	select {
	case credJSON = <-credCh:
		// ceremony complete
	case serveErr := <-errCh:
		fmt.Fprintf(stderr, "error: local server: %v\n", serveErr)
		return 1
	case <-timeoutCtx.Done():
		fmt.Fprintln(stderr, "error: timed out waiting for WebAuthn ceremony")
		return 1
	}

	// 5. Finish registration: send credential to server.
	credID, err := webAuthnRegisterFinish(ctx, client, callerID, credName, credJSON)
	if err != nil {
		fmt.Fprintf(stderr, "error: register/finish: %v\n", err)
		return 1
	}

	// Abbreviate the credential ID for display (first 16 chars + "…").
	displayID := credID
	if len(displayID) > 16 {
		displayID = displayID[:16] + "…"
	}

	typeLabel := *typeFlag
	if typeLabel == "" {
		typeLabel = "credential"
	}
	fmt.Fprintf(stdout, "Registered %s %q (credential id: %s)\n", typeLabel, credName, displayID)
	return 0
}

// statusTextForType returns the instruction text shown in the browser page.
func statusTextForType(typ string) string {
	switch strings.ToLower(typ) {
	case "passkey":
		return "Use Touch ID / Windows Hello / your device biometrics to register…"
	case "yubikey":
		return "Touch your YubiKey to register…"
	default:
		return "Choose your authenticator to register…"
	}
}

// webAuthnRegisterBegin POSTs /auth/webauthn/register/begin and returns the
// raw PublicKeyCredentialCreationOptions JSON from the server.
//
// We include authenticator_attachment as a forward-compatible field; existing
// server versions will ignore it (unknown fields in JSON bodies are dropped).
func webAuthnRegisterBegin(ctx context.Context, client *Client, callerID, attachment string) (json.RawMessage, error) {
	if err := client.ensureAuth(ctx); err != nil {
		return nil, fmt.Errorf("ensure auth: %w", err)
	}

	body := struct {
		CallerID               string `json:"caller_id"`
		AuthenticatorAttachment string `json:"authenticator_attachment,omitempty"`
	}{
		CallerID:               callerID,
		AuthenticatorAttachment: attachment,
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		return nil, fmt.Errorf("encode begin request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		client.baseURL+"/auth/webauthn/register/begin", &buf)
	if err != nil {
		return nil, fmt.Errorf("build begin request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+client.token)

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("begin request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, serverError(resp, "webauthn/register/begin")
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read begin response: %w", err)
	}
	return json.RawMessage(raw), nil
}

// webAuthnRegisterFinish POSTs /auth/webauthn/register/finish with the
// completed credential.  Returns the credential ID string on success.
func webAuthnRegisterFinish(ctx context.Context, client *Client, callerID, name string, credJSON json.RawMessage) (string, error) {
	if err := client.ensureAuth(ctx); err != nil {
		return "", fmt.Errorf("ensure auth: %w", err)
	}

	body := struct {
		CallerID string          `json:"caller_id"`
		Name     string          `json:"name"`
		Response json.RawMessage `json:"response"`
	}{
		CallerID: callerID,
		Name:     name,
		Response: credJSON,
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		return "", fmt.Errorf("encode finish request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		client.baseURL+"/auth/webauthn/register/finish", &buf)
	if err != nil {
		return "", fmt.Errorf("build finish request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+client.token)

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("finish request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", serverError(resp, "webauthn/register/finish")
	}

	// The server returns {"status":"registered"} today.  We also check for an
	// optional "credential_id" field for forward compatibility.
	var result struct {
		Status       string `json:"status"`
		CredentialID string `json:"credential_id,omitempty"`
	}
	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read finish response: %w", err)
	}
	if err := json.Unmarshal(rawBody, &result); err != nil {
		return "", fmt.Errorf("decode finish response: %w", err)
	}

	// If the server returned a credential_id, use it.  Otherwise extract from
	// the credential JSON the browser sent us (field "id").
	if result.CredentialID != "" {
		return result.CredentialID, nil
	}
	var cred struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(credJSON, &cred); err == nil && cred.ID != "" {
		return cred.ID, nil
	}
	return "(unknown)", nil
}

// buildWebAuthnRegisterURL constructs the browser URL for the registration
// ceremony.  The full PublicKeyCredentialCreationOptions JSON is base64url-
// encoded into the ?challenge query param (same encoding as RunStepUp).
//
// The addr is rewritten from "127.0.0.1:<port>" to "localhost:<port>" via
// localhostURL so that the browser's WebAuthn ceremony sees effective domain
// "localhost" (matching the server's RPID).
func buildWebAuthnRegisterURL(addr string, challengeJSON json.RawMessage) string {
	encoded := base64.RawURLEncoding.EncodeToString(challengeJSON)
	u := &url.URL{
		Scheme:   "http",
		Host:     localhostURL(addr),
		Path:     "/",
		RawQuery: "challenge=" + url.QueryEscape(encoded),
	}
	return u.String()
}

// buildWebAuthnRegisterHandler returns an http.Handler that serves the
// registration ceremony page (GET /) and the credential callback (POST /callback).
func buildWebAuthnRegisterHandler(challengeJSON json.RawMessage, attachment, statusText string, credCh chan<- json.RawMessage) http.Handler {
	page := buildRegisterHTML(statusText, attachment)

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, page)
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
		select {
		case credCh <- json.RawMessage(body):
		default:
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "Registration complete — you can close this tab.")
	})

	return mux
}

// buildRegisterHTML constructs the HTML/JS page for the credential-creation
// ceremony.  The page reads the PublicKeyCredentialCreationOptions from the
// ?challenge query param (base64url-encoded), calls navigator.credentials.create,
// and POSTs the new credential JSON to /callback.
//
// attachment is the authenticatorAttachment hint ("platform", "cross-platform",
// or "" to omit it from the authenticatorSelection object).
func buildRegisterHTML(statusText, attachment string) string {
	// Build the authenticatorSelection snippet.  We only inject the attachment
	// when explicitly requested; omitting it lets the browser/platform pick.
	var attachmentSnippet string
	if attachment != "" {
		attachmentSnippet = fmt.Sprintf(`, authenticatorSelection: { authenticatorAttachment: %q }`, attachment)
	}

	return `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>KPM WebAuthn Register</title></head>
<body>
<p id="status">` + statusText + `</p>
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

    // Decode the full PublicKeyCredentialCreationOptions JSON.
    // The go-webauthn server returns {"publicKey": {...options...}}, so unwrap
    // if present; tolerate the older flat shape too.
    let opts = JSON.parse(new TextDecoder().decode(b64url(enc)));
    if (opts && opts.publicKey) opts = opts.publicKey;

    // Convert base64url-encoded binary fields to ArrayBuffer for the browser API.
    opts.challenge = b64url(opts.challenge).buffer;
    if (opts.user && opts.user.id) {
      opts.user.id = b64url(opts.user.id).buffer;
    }
    if (opts.excludeCredentials) {
      opts.excludeCredentials = opts.excludeCredentials.map(c => ({
        ...c,
        id: b64url(c.id).buffer,
      }));
    }

    const cred = await navigator.credentials.create({
      publicKey: opts` + attachmentSnippet + `
    });

    // Serialise attestation to the shape AgentKMS expects.
    const attestation = {
      id: cred.id,
      rawId: toB64url(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON:    toB64url(cred.response.clientDataJSON),
        attestationObject: toB64url(cred.response.attestationObject),
      },
    };

    const r = await fetch('/callback', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(attestation),
    });
    if (r.ok) {
      status.textContent = 'Registration complete — you can close this tab.';
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
}

// ── list ──────────────────────────────────────────────────────────────────────

// webAuthnCredential is the client-side shape of a WebAuthn credential summary
// returned by GET /auth/webauthn/credentials.
type webAuthnCredential struct {
	ID        string `json:"id"`
	Name      string `json:"name,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
	LastUsed  string `json:"last_used_at,omitempty"`
	Type      string `json:"authenticator_type,omitempty"` // "platform" | "cross-platform" | ""
	AAGUID    string `json:"aaguid,omitempty"`
}

func runWebAuthnList(ctx context.Context, stdout, stderr io.Writer, client *Client, args []string) int {
	_ = args // no flags for list

	if err := client.ensureAuth(ctx); err != nil {
		fmt.Fprintf(stderr, "error: ensure auth: %v\n", err)
		return 1
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		client.baseURL+"/auth/webauthn/credentials", nil)
	if err != nil {
		fmt.Fprintf(stderr, "error: build list request: %v\n", err)
		return 1
	}
	req.Header.Set("Authorization", "Bearer "+client.token)

	resp, err := client.httpClient.Do(req)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		fmt.Fprintln(stderr, "error: server does not expose credential listing — open an issue at https://github.com/TheGenXCoder/kpm/issues")
		return 1
	}
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(stderr, "error: %v\n", serverError(resp, "webauthn/credentials list"))
		return 1
	}

	var body struct {
		Credentials []webAuthnCredential `json:"credentials"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		fmt.Fprintf(stderr, "error: decode response: %v\n", err)
		return 1
	}

	creds := body.Credentials
	if len(creds) == 0 {
		fmt.Fprintln(stdout, "No WebAuthn credentials registered. Add one with: kpm webauthn register")
		return 0
	}

	fmt.Fprintf(stdout, "%-36s %-20s %-12s %-22s %s\n", "CREDENTIAL ID", "NAME", "TYPE", "CREATED", "LAST USED")
	fmt.Fprintln(stdout, strings.Repeat("-", 100))
	for _, c := range creds {
		id := c.ID
		if len(id) > 36 {
			id = id[:33] + "…"
		}
		typ := c.Type
		if typ == "" {
			typ = "-"
		}
		created := c.CreatedAt
		if created == "" {
			created = "-"
		}
		lastUsed := c.LastUsed
		if lastUsed == "" {
			lastUsed = "-"
		}
		name := c.Name
		if name == "" {
			name = "-"
		}
		fmt.Fprintf(stdout, "%-36s %-20s %-12s %-22s %s\n", id, name, typ, created, lastUsed)
	}
	fmt.Fprintf(stdout, "\n%d credential(s)\n", len(creds))
	return 0
}

// ── remove ────────────────────────────────────────────────────────────────────

func runWebAuthnRemove(ctx context.Context, stdout, stderr io.Writer, client *Client, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "kpm webauthn remove: credential-id is required")
		fmt.Fprint(stderr, webAuthnUsage)
		return 1
	}
	// First non-flag arg is the credential ID.
	var credID string
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			credID = a
			break
		}
	}
	if credID == "" {
		fmt.Fprintln(stderr, "kpm webauthn remove: credential-id is required")
		return 1
	}

	if err := client.ensureAuth(ctx); err != nil {
		fmt.Fprintf(stderr, "error: ensure auth: %v\n", err)
		return 1
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
		client.baseURL+"/auth/webauthn/credentials/"+url.PathEscape(credID), nil)
	if err != nil {
		fmt.Fprintf(stderr, "error: build remove request: %v\n", err)
		return 1
	}
	req.Header.Set("Authorization", "Bearer "+client.token)

	resp, err := client.httpClient.Do(req)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// Two possibilities: endpoint missing or credential not found.
		// If the body mentions "credential", treat as credential-not-found.
		body, _ := io.ReadAll(resp.Body)
		if strings.Contains(strings.ToLower(string(body)), "credential") {
			fmt.Fprintf(stderr, "error: credential %q not found\n", credID)
		} else {
			fmt.Fprintln(stderr, "error: server does not expose credential removal — open an issue at https://github.com/TheGenXCoder/kpm/issues")
		}
		return 1
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		fmt.Fprintf(stderr, "error: %v\n", serverError(resp, "webauthn/credentials remove"))
		return 1
	}

	fmt.Fprintf(stdout, "Removed credential %q\n", credID)
	return 0
}
