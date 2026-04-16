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
