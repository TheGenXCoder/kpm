package kpm

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/TheGenXCoder/kpm/pkg/tlsutil"
)

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
		return fmt.Errorf("auth failed: server returned %d", resp.StatusCode)
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

// FetchLLM retrieves an LLM provider credential.
func (c *Client) FetchLLM(ctx context.Context, provider string) (*LLMCredential, error) {
	url := c.baseURL + "/credentials/llm/" + provider

	resp, err := c.doGet(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("fetch LLM credential: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %d for llm/%s", resp.StatusCode, provider)
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

// FetchGeneric retrieves a generic credential set at the given path.
func (c *Client) FetchGeneric(ctx context.Context, path string) (*GenericCredential, error) {
	url := c.baseURL + "/credentials/generic/" + path

	resp, err := c.doGet(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("fetch generic credential: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %d for generic/%s", resp.StatusCode, path)
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
