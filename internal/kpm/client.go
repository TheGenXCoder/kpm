package kpm

import (
	"bytes"
	"context"
	"crypto/tls"
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
type Client struct {
	baseURL    string
	httpClient *http.Client
	token      string // Bearer token from POST /auth/session
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

// Authenticate obtains a bearer token via POST /auth/session (mTLS).
// Called automatically on first request if no token is set.
func (c *Client) Authenticate(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/auth/session", nil)
	if err != nil {
		return fmt.Errorf("build auth request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("auth request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return serverError(resp, "authenticate")
	}

	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return fmt.Errorf("decode auth response: %w", err)
	}
	c.token = body.Token
	return nil
}

func (c *Client) ensureAuth(ctx context.Context) error {
	if c.token == "" {
		return c.Authenticate(ctx)
	}
	return nil
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
