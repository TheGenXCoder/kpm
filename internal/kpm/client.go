package kpm

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/TheGenXCoder/kpm/pkg/tlsutil"
)

// serverErrorResponse matches the JSON error shape returned by AgentKMS.
type serverErrorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

// serverError builds a user-friendly error from a non-OK HTTP response.
// It reads the response body (which is JSON), extracts the "error" and "code"
// fields, and returns a formatted error. If the body isn't parseable, it
// falls back to "server returned {status}".
//
// The response body is consumed (caller should not read it again).
func serverError(resp *http.Response, operation string) error {
	body, _ := io.ReadAll(resp.Body)
	var sr serverErrorResponse
	if json.Unmarshal(body, &sr) == nil && sr.Error != "" {
		if sr.Code != "" {
			return fmt.Errorf("%s: %s (%s)", operation, sr.Error, sr.Code)
		}
		return fmt.Errorf("%s: %s", operation, sr.Error)
	}
	// Couldn't parse — fall back to status code.
	// Common HTTP status codes with friendly hints:
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return fmt.Errorf("%s: unauthorized (401) — check your mTLS certificates", operation)
	case http.StatusForbidden:
		return fmt.Errorf("%s: forbidden (403) — access denied by policy", operation)
	case http.StatusNotFound:
		return fmt.Errorf("%s: not found (404)", operation)
	case http.StatusTooManyRequests:
		return fmt.Errorf("%s: rate limited (429) — try again in a moment", operation)
	case http.StatusInternalServerError:
		return fmt.Errorf("%s: server error (500) — check server logs", operation)
	case http.StatusServiceUnavailable:
		return fmt.Errorf("%s: service unavailable (503) — is AgentKMS running?", operation)
	default:
		return fmt.Errorf("%s: server returned %d", operation, resp.StatusCode)
	}
}

// LLMCredential is the response from GET /credentials/llm/{provider}.
type LLMCredential struct {
	Provider   string
	APIKey     []byte // SECURITY: call ZeroBytes in defer after use
	ExpiresAt  string
	TTLSeconds int
}

// GenericCredential is the response from GET /credentials/generic/{path}.
type GenericCredential struct {
	Path       string
	Secrets    map[string][]byte // SECURITY: call ZeroMap in defer after use
	ExpiresAt  string
	TTLSeconds int
}

// Client talks to an AgentKMS server over mTLS.
//
// Authentication state is layered:
//
//  1. If a persisted auth session (see auth_session.go) exists and is not
//     expired, the client uses its token transparently.  When the persisted
//     session is within 60s of expiry it is refreshed via /auth/refresh and
//     the new session re-persisted.
//
//  2. Otherwise the client falls back to the legacy per-request flow:
//     Authenticate() does POST /auth/session over mTLS and the resulting
//     token lives only in memory for the duration of the process.
//
// The fallback's token is NEVER persisted — only sessions explicitly minted
// by `kpm login` (which calls Authenticate then SaveAuthSession directly)
// outlive a single process.
type Client struct {
	baseURL    string
	httpClient *http.Client
	token      string // Bearer token from POST /auth/session

	// sessionLoaded gates the at-most-once attempt to load a persisted
	// session.  Subsequent requests reuse c.token (and refresh in place
	// when expiry < 60s away).
	sessionLoaded bool

	// expiresAt mirrors the persisted session's expiry, used to decide
	// when to call /auth/refresh.  Zero when the in-memory token came
	// from the fallback /auth/session call (we don't know its expiry
	// without parsing the JWT, and we don't need to — fallback tokens
	// are short-lived and one-shot per process).
	expiresAt time.Time
}

// NewClient creates an AgentKMS client from cert file paths.
func NewClient(baseURL, caPath, certPath, keyPath string) (*Client, error) {
	ca, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read CA %s: %w", caPath, err)
	}
	cert, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read cert %s: %w", certPath, err)
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read key %s: %w", keyPath, err)
	}

	tlsCfg, err := tlsutil.ClientTLSConfig(ca, cert, key)
	if err != nil {
		return nil, fmt.Errorf("TLS config: %w", err)
	}

	return newClientWithTLS(baseURL, tlsCfg), nil
}

func newClientWithTLS(baseURL string, tlsCfg *tls.Config) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: tlsCfg,
			},
		},
	}
}

// NewClientInsecure creates an AgentKMS client without mTLS. Only for use in
// unit tests against httptest.Server. Never use in production.
func NewClientInsecure(baseURL string) (*Client, error) {
	return &Client{
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}, nil
}

// NewClientCAOnly creates an AgentKMS client that verifies the server cert
// against caPath but does NOT present a client cert. Used by `kpm enroll`
// (mode-1 bootstrap-token path) where the caller does not yet have an mTLS
// identity but still needs to talk to a real production AgentKMS over TLS.
func NewClientCAOnly(baseURL, caPath string) (*Client, error) {
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read CA %s: %w", caPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("no PEM blocks in %s", caPath)
	}
	tlsCfg := &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}
	return newClientWithTLS(baseURL, tlsCfg), nil
}

// SessionResponse is the wire shape of /auth/session and /auth/refresh.
// Exported so that the `kpm login` command can call Authenticate and then
// persist the full response (including expires_in + session_id) without
// duplicating the HTTP plumbing.
type SessionResponse struct {
	Token     string `json:"token"`
	TokenType string `json:"token_type"`
	ExpiresIn int    `json:"expires_in"`
	SessionID string `json:"session_id"`
}

// Authenticate obtains a bearer token via POST /auth/session (mTLS).
// Called automatically on first request if no token is set.
//
// On success the token is set on the client AND the parsed response is
// returned so callers (notably `kpm login`) can persist it.
func (c *Client) Authenticate(ctx context.Context) (*SessionResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/auth/session", nil)
	if err != nil {
		return nil, fmt.Errorf("build auth request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("auth request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, serverError(resp, "authenticate")
	}

	var body SessionResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode auth response: %w", err)
	}
	c.token = body.Token
	if body.ExpiresIn > 0 {
		c.expiresAt = time.Now().Add(time.Duration(body.ExpiresIn) * time.Second)
	}
	return &body, nil
}

// Refresh exchanges the current bearer token for a fresh one via
// POST /auth/refresh.  Called automatically when a persisted session is
// loaded with less than 60s of life left.
//
// On success the in-memory token is replaced and the parsed response is
// returned so `kpm login`/the auto-refresh path can persist it.
func (c *Client) Refresh(ctx context.Context) (*SessionResponse, error) {
	if c.token == "" {
		return nil, fmt.Errorf("refresh: no bearer token to refresh")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/auth/refresh", nil)
	if err != nil {
		return nil, fmt.Errorf("build refresh request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("refresh request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, serverError(resp, "refresh")
	}

	var body SessionResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode refresh response: %w", err)
	}
	c.token = body.Token
	if body.ExpiresIn > 0 {
		c.expiresAt = time.Now().Add(time.Duration(body.ExpiresIn) * time.Second)
	}
	return &body, nil
}

// RevokeCurrent issues POST /auth/revoke with the current bearer token.
// A 401 from the server is treated as "already revoked / expired" and
// returned as a sentinel so callers can proceed idempotently.
func (c *Client) RevokeCurrent(ctx context.Context) error {
	if c.token == "" {
		return fmt.Errorf("revoke: no bearer token to revoke")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/auth/revoke", nil)
	if err != nil {
		return fmt.Errorf("build revoke request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("revoke request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK:
		return nil
	case http.StatusUnauthorized:
		// Token already expired or unknown — treat as already revoked.
		return ErrAlreadyRevoked
	default:
		return serverError(resp, "revoke")
	}
}

// ErrAlreadyRevoked is returned by RevokeCurrent when the server responds
// 401, indicating the token has already expired or been revoked.  Callers
// should treat this as a successful idempotent revoke.
var ErrAlreadyRevoked = fmt.Errorf("token already revoked or expired")

// SetToken sets the bearer token directly without doing /auth/session.
// Used by the persisted-session path to "adopt" a token loaded from disk.
// expiresAt is the absolute expiry of the token (used to decide whether
// to refresh on the next request).
func (c *Client) SetToken(token string, expiresAt time.Time) {
	c.token = token
	c.expiresAt = expiresAt
	c.sessionLoaded = true
}

// ensureAuth makes sure the client has a usable bearer token before issuing
// a request.  Precedence:
//
//  1. If we already have a token in memory and it isn't near expiry, use it.
//  2. If we have one within 60s of expiry, refresh it and persist the new
//     session (only when sessionLoaded — i.e. token came from disk).
//  3. Otherwise, try once to load a persisted session from disk.
//  4. Falling back to a fresh per-request /auth/session call.  This token
//     is NOT persisted.
//
// The 60-second threshold balances "don't waste an RTT preemptively" against
// "don't ship a request that's going to come back 401."
func (c *Client) ensureAuth(ctx context.Context) error {
	const refreshThreshold = 60 * time.Second

	// (1) In-memory token still good?
	if c.token != "" {
		if c.expiresAt.IsZero() || time.Until(c.expiresAt) > refreshThreshold {
			return nil
		}
		// (2) Within the refresh window — only refresh when the token came
		// from a persisted session.  Fallback tokens have an empty expiresAt
		// and never reach this branch.
		if c.sessionLoaded {
			sr, err := c.Refresh(ctx)
			if err != nil {
				// Refresh failed — fall through to a fresh /auth/session.
				c.token = ""
				c.expiresAt = time.Time{}
				return c.fallbackAuth(ctx)
			}
			// Persist the refreshed session so subsequent commands pick it up.
			_ = SaveAuthSession(&AuthSession{
				Token:     sr.Token,
				TokenType: sr.TokenType,
				SessionID: sr.SessionID,
				ExpiresAt: time.Now().Add(time.Duration(sr.ExpiresIn) * time.Second),
				Claims:    DecodeJWTClaims(sr.Token),
			})
			return nil
		}
		// In-memory only and near-expiry: just re-authenticate.
		return c.fallbackAuth(ctx)
	}

	// (3) First call this process — try the persisted session.
	if !c.sessionLoaded {
		c.sessionLoaded = true
		if s, err := LoadAuthSession(); err == nil {
			c.token = s.Token
			c.expiresAt = s.ExpiresAt
			// If the loaded session is near expiry, refresh now.
			if time.Until(c.expiresAt) <= refreshThreshold {
				sr, rerr := c.Refresh(ctx)
				if rerr == nil {
					_ = SaveAuthSession(&AuthSession{
						Token:     sr.Token,
						TokenType: sr.TokenType,
						SessionID: sr.SessionID,
						ExpiresAt: time.Now().Add(time.Duration(sr.ExpiresIn) * time.Second),
						Claims:    DecodeJWTClaims(sr.Token),
					})
					return nil
				}
				// Refresh failed — discard and fall back.
				c.token = ""
				c.expiresAt = time.Time{}
			} else {
				return nil
			}
		}
	}

	// (4) Fallback: transient per-request /auth/session.
	return c.fallbackAuth(ctx)
}

// fallbackAuth performs a one-shot /auth/session call without persisting
// the resulting session.
func (c *Client) fallbackAuth(ctx context.Context) error {
	_, err := c.Authenticate(ctx)
	return err
}

func (c *Client) doGet(ctx context.Context, url string) (*http.Response, error) {
	if err := c.ensureAuth(ctx); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	return c.httpClient.Do(req)
}

func (c *Client) doPost(ctx context.Context, url string, body any) (*http.Response, error) {
	if err := c.ensureAuth(ctx); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		return nil, fmt.Errorf("encode body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, &buf)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	return c.httpClient.Do(req)
}

func (c *Client) doDelete(ctx context.Context, url string) (*http.Response, error) {
	if err := c.ensureAuth(ctx); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	return c.httpClient.Do(req)
}

// FetchLLM retrieves an LLM provider credential.
func (c *Client) FetchLLM(ctx context.Context, provider string) (*LLMCredential, error) {
	url := c.baseURL + "/credentials/llm/" + provider

	resp, err := c.doGet(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("fetch LLM credential: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, serverError(resp, "fetch LLM "+provider)
	}

	var body struct {
		Provider   string `json:"provider"`
		APIKey     string `json:"api_key"`
		ExpiresAt  string `json:"expires_at"`
		TTLSeconds int    `json:"ttl_seconds"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &LLMCredential{
		Provider:   body.Provider,
		APIKey:     []byte(body.APIKey),
		ExpiresAt:  body.ExpiresAt,
		TTLSeconds: body.TTLSeconds,
	}, nil
}

// FetchRegistrySecret retrieves a secret stored via the KPM registry (POST /secrets/{path}).
// Reads from the registry's /secrets/ endpoint (not /credentials/generic/).
func (c *Client) FetchRegistrySecret(ctx context.Context, path string) (map[string][]byte, error) {
	url := c.baseURL + "/secrets/" + path

	resp, err := c.doGet(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("fetch registry secret: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("secret not found: %s", path)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, serverError(resp, "fetch "+path)
	}

	// Server returns a flat map: {"value": "secret"} or {"field1": "val1", "field2": "val2"}
	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	out := make(map[string][]byte, len(body))
	for k, v := range body {
		out[k] = []byte(v)
	}
	return out, nil
}

// ── Binding endpoints ─────────────────────────────────────────────────────────

// RegisterBinding registers (creates or replaces) a credential binding.
func (c *Client) RegisterBinding(ctx context.Context, b CredentialBinding) (*CredentialBinding, error) {
	url := c.baseURL + "/bindings"
	resp, err := c.doPost(ctx, url, b)
	if err != nil {
		return nil, fmt.Errorf("register binding: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, serverError(resp, "register binding "+b.Name)
	}

	var out CredentialBinding
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode register binding response: %w", err)
	}
	return &out, nil
}

// ListBindings returns binding summaries, optionally filtered by tag.
func (c *Client) ListBindings(ctx context.Context, tag string) ([]BindingSummary, error) {
	u := c.baseURL + "/bindings"
	if tag != "" {
		u += "?tag=" + tag
	}
	resp, err := c.doGet(ctx, u)
	if err != nil {
		return nil, fmt.Errorf("list bindings: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, serverError(resp, "list bindings")
	}

	var body struct {
		Bindings []BindingSummary `json:"bindings"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode list bindings response: %w", err)
	}
	return body.Bindings, nil
}

// GetBinding retrieves the full credential binding by name.
func (c *Client) GetBinding(ctx context.Context, name string) (*CredentialBinding, error) {
	resp, err := c.doGet(ctx, c.baseURL+"/bindings/"+name)
	if err != nil {
		return nil, fmt.Errorf("get binding: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, serverError(resp, "get binding "+name)
	}

	var out CredentialBinding
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode get binding response: %w", err)
	}
	return &out, nil
}

// RotateBinding triggers a manual one-shot rotation for the named binding.
func (c *Client) RotateBinding(ctx context.Context, name string) (*RotateResponse, error) {
	resp, err := c.doPost(ctx, c.baseURL+"/bindings/"+name+"/rotate", nil)
	if err != nil {
		return nil, fmt.Errorf("rotate binding: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, serverError(resp, "rotate binding "+name)
	}

	var out RotateResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode rotate response: %w", err)
	}
	return &out, nil
}

// RemoveBinding removes a credential binding.
// If purge is true the binding is hard-deleted; otherwise it is soft-deleted
// (server semantics may vary — current server implementation always hard-deletes
// bindings, so purge is a signal for future soft-delete support).
func (c *Client) RemoveBinding(ctx context.Context, name string, purge bool) error {
	u := c.baseURL + "/bindings/" + name
	if purge {
		u += "?purge=true"
	}
	resp, err := c.doDelete(ctx, u)
	if err != nil {
		return fmt.Errorf("remove binding: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return serverError(resp, "remove binding "+name)
	}
	return nil
}

// ── GitHub App endpoints ──────────────────────────────────────────────────────

// GithubAppSummary is the list-endpoint shape for GitHub App registrations.
// The private key is never included in any list or inspect response.
type GithubAppSummary struct {
	Name           string `json:"name"`
	AppID          int64  `json:"app_id"`
	InstallationID int64  `json:"installation_id"`
}

// RegisterGithubAppRequest is the POST /github-apps request body.
type RegisterGithubAppRequest struct {
	Name           string `json:"name"`
	AppID          int64  `json:"app_id"`
	InstallationID int64  `json:"installation_id"`
	PrivateKeyPEM  []byte `json:"private_key_pem"`
}

// RegisterGithubApp registers a GitHub App installation with AgentKMS.
// privateKeyPEM contains the PEM-encoded RSA private key and is sent over
// the mTLS connection. The server stores it encrypted at rest; it is never
// returned in any subsequent response.
func (c *Client) RegisterGithubApp(ctx context.Context, req RegisterGithubAppRequest) (*GithubAppSummary, error) {
	resp, err := c.doPost(ctx, c.baseURL+"/github-apps", req)
	if err != nil {
		return nil, fmt.Errorf("register github app: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, serverError(resp, "register github app "+req.Name)
	}

	var out GithubAppSummary
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode register github app response: %w", err)
	}
	return &out, nil
}

// ListGithubApps returns summaries of all registered GitHub App installations.
func (c *Client) ListGithubApps(ctx context.Context) ([]GithubAppSummary, error) {
	resp, err := c.doGet(ctx, c.baseURL+"/github-apps")
	if err != nil {
		return nil, fmt.Errorf("list github apps: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, serverError(resp, "list github apps")
	}

	var body struct {
		Apps []GithubAppSummary `json:"apps"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode list github apps response: %w", err)
	}
	return body.Apps, nil
}

// GetGithubApp retrieves the summary for a single GitHub App by name.
// The private key is never returned.
func (c *Client) GetGithubApp(ctx context.Context, name string) (*GithubAppSummary, error) {
	resp, err := c.doGet(ctx, c.baseURL+"/github-apps/"+name)
	if err != nil {
		return nil, fmt.Errorf("get github app: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, serverError(resp, "get github app "+name)
	}

	var out GithubAppSummary
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode get github app response: %w", err)
	}
	return &out, nil
}

// RemoveGithubApp removes a registered GitHub App by name.
func (c *Client) RemoveGithubApp(ctx context.Context, name string) error {
	resp, err := c.doDelete(ctx, c.baseURL+"/github-apps/"+name)
	if err != nil {
		return fmt.Errorf("remove github app: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return serverError(resp, "remove github app "+name)
	}
	return nil
}

// FetchGeneric retrieves a generic credential set at the given path.
func (c *Client) FetchGeneric(ctx context.Context, path string) (*GenericCredential, error) {
	url := c.baseURL + "/credentials/generic/" + path

	resp, err := c.doGet(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("fetch generic credential: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, serverError(resp, "fetch generic/"+path)
	}

	var body struct {
		Path       string            `json:"path"`
		Secrets    map[string]string `json:"secrets"`
		ExpiresAt  string            `json:"expires_at"`
		TTLSeconds int               `json:"ttl_seconds"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	secrets := make(map[string][]byte, len(body.Secrets))
	for k, v := range body.Secrets {
		secrets[k] = []byte(v)
	}

	return &GenericCredential{
		Path:       body.Path,
		Secrets:    secrets,
		ExpiresAt:  body.ExpiresAt,
		TTLSeconds: body.TTLSeconds,
	}, nil
}

// BootstrapTokenResponse is the response from POST /auth/bootstrap/issue.
type BootstrapTokenResponse struct {
	Token     string    `json:"bootstrap_token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// RequestBootstrapToken requests a bootstrap token for a new device.
// The caller must have a persisted session token with sufficient auth strength.
func (c *Client) RequestBootstrapToken(ctx context.Context, devicePattern string, ttl time.Duration) (*BootstrapTokenResponse, error) {
	if err := c.ensureAuth(ctx); err != nil {
		return nil, err
	}

	body := struct {
		DeviceNamePattern string `json:"device_name_pattern"`
		TTLSeconds        int    `json:"ttl_seconds"`
	}{
		DeviceNamePattern: devicePattern,
		TTLSeconds:        int(ttl.Seconds()),
	}

	resp, err := c.doPost(ctx, c.baseURL+"/auth/bootstrap/issue", body)
	if err != nil {
		return nil, fmt.Errorf("request bootstrap token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, serverError(resp, "request bootstrap token")
	}

	var result BootstrapTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode bootstrap token response: %w", err)
	}

	return &result, nil
}
