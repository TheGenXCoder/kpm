# KPM Go Rewrite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrite key-pair-manager as `cmd/kpm` inside the AgentKMS repo with template-based .env replacement and three injection modes (plaintext, --secure, --secure-strict).

**Architecture:** KPM is a Go binary at `cmd/kpm/` that reuses `pkg/tlsutil` for mTLS and talks to AgentKMS over HTTPS. New logic lives in `internal/kpm/` (template parser, client, injector, cache, UDS listener). No new external dependencies for the MVP (Tasks 1-7). `go-keyring` and `golang.org/x/sys/unix` added only when cache/UDS security tasks are reached.

**Tech Stack:** Go 1.25, stdlib `flag` + subcommand dispatch (no Cobra — respects go.mod dep policy), `pkg/tlsutil` for mTLS, `crypto/aes` + `crypto/cipher` for AES-256-GCM session key encryption.

**Spec:** `docs/kpm-unified-design.md`

**Existing code to reuse:**
- `pkg/tlsutil.ClientTLSConfig(caCertPEM, clientCertPEM, clientKeyPEM []byte) (*tls.Config, error)` — mTLS client config
- `cmd/cli/main.go` — existing pattern for mTLS HTTP client + `exec.Command` with env injection
- API: `GET /credentials/llm/{provider}` → `{"api_key","expires_at","ttl_seconds"}`
- API: `GET /credentials/generic/{path}` → `{"path","secrets":{},"expires_at","ttl_seconds"}`
- API: `POST /encrypt/{keyid}` → `{"plaintext":"<b64>"}` → `{"ciphertext":"<b64>","key_version":N}`
- API: `POST /decrypt/{keyid}` → `{"ciphertext":"<b64>"}` → `{"plaintext":"<b64>"}`

---

## File Structure

```
cmd/kpm/
  main.go                    — subcommand dispatch, global flags, config loading

internal/kpm/
  config.go                  — Config struct, YAML loading, defaults
  config_test.go
  template.go                — KMSReference, ResolvedEntry, template parser
  template_test.go
  client.go                  — AgentKMS HTTP client (wraps pkg/tlsutil)
  client_test.go
  resolver.go                — connects parser to client, batch dedup
  resolver_test.go
  export.go                  — kpm export command logic
  export_test.go
  runner.go                  — kpm run command logic (exec with env)
  runner_test.go
  zero.go                    — zeroing helpers for []byte
  zero_test.go
  encrypt.go                 — session key management, local AES-256-GCM encrypt/decrypt
  encrypt_test.go
  listener.go                — UDS decrypt listener
  listener_test.go
  cache.go                   — local keychain cache (go-keyring)
  cache_test.go
```

---

## Task 1: Zeroing Helpers

**Files:**
- Create: `internal/kpm/zero.go`
- Create: `internal/kpm/zero_test.go`

Security-critical foundation. Everything else depends on proper zeroing.

- [ ] **Step 1: Write the failing test**

Create `internal/kpm/zero_test.go`:

```go
package kpm

import (
	"bytes"
	"testing"
)

func TestZeroBytes(t *testing.T) {
	secret := []byte("super-secret-api-key")
	original := make([]byte, len(secret))
	copy(original, secret)

	ZeroBytes(secret)

	if bytes.Equal(secret, original) {
		t.Fatal("ZeroBytes did not overwrite the buffer")
	}
	for i, b := range secret {
		if b != 0 {
			t.Fatalf("byte %d is %d, want 0", i, b)
		}
	}
}

func TestZeroBytesNil(t *testing.T) {
	// Must not panic on nil.
	ZeroBytes(nil)
}

func TestZeroMap(t *testing.T) {
	m := map[string][]byte{
		"password": []byte("s3cret"),
		"token":    []byte("tok-abc"),
	}
	ZeroMap(m)
	for k, v := range m {
		for i, b := range v {
			if b != 0 {
				t.Fatalf("key %q byte %d is %d, want 0", k, i, b)
			}
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/BertSmith/personal/projects/pi.dev/agentkms && go test ./internal/kpm/ -run TestZero -v`
Expected: FAIL — package doesn't exist yet.

- [ ] **Step 3: Write minimal implementation**

Create `internal/kpm/zero.go`:

```go
// Package kpm implements the KPM local secrets CLI.
package kpm

// ZeroBytes overwrites b with zeros. Call in defer after using secret material.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ZeroMap zeros all values in a map[string][]byte.
func ZeroMap(m map[string][]byte) {
	for _, v := range m {
		ZeroBytes(v)
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/BertSmith/personal/projects/pi.dev/agentkms && go test ./internal/kpm/ -run TestZero -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
cd /Users/BertSmith/personal/projects/pi.dev/agentkms
git add internal/kpm/zero.go internal/kpm/zero_test.go
git commit -m "feat(kpm): add zeroing helpers for secret material"
```

---

## Task 2: Config

**Files:**
- Create: `internal/kpm/config.go`
- Create: `internal/kpm/config_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/kpm/config_test.go`:

```go
package kpm

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	yaml := `server: https://agentkms.local:8443
cert: /tmp/client.crt
key: /tmp/client.key
ca: /tmp/ca.crt
default_template: .env.template
secure_mode: true
session_key_ttl: 120
`
	if err := os.WriteFile(cfgPath, []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Server != "https://agentkms.local:8443" {
		t.Errorf("Server = %q, want https://agentkms.local:8443", cfg.Server)
	}
	if cfg.SessionKeyTTL != 120 {
		t.Errorf("SessionKeyTTL = %d, want 120", cfg.SessionKeyTTL)
	}
	if !cfg.SecureMode {
		t.Error("SecureMode should be true")
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("server: https://localhost:8443\n"), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.SessionKeyTTL != 300 {
		t.Errorf("default SessionKeyTTL = %d, want 300", cfg.SessionKeyTTL)
	}
	if cfg.DefaultTemplate != ".env.template" {
		t.Errorf("default DefaultTemplate = %q, want .env.template", cfg.DefaultTemplate)
	}
}

func TestLoadConfigMissing(t *testing.T) {
	_, err := LoadConfig("/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing config")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/BertSmith/personal/projects/pi.dev/agentkms && go test ./internal/kpm/ -run TestLoadConfig -v`
Expected: FAIL — `LoadConfig` not defined.

- [ ] **Step 3: Write minimal implementation**

Create `internal/kpm/config.go`:

```go
package kpm

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config holds KPM CLI configuration.
type Config struct {
	Server          string `yaml:"server"`
	Cert            string `yaml:"cert"`
	Key             string `yaml:"key"`
	CA              string `yaml:"ca"`
	DefaultTemplate string `yaml:"default_template"`
	SecureMode      bool   `yaml:"secure_mode"`
	SessionKeyTTL   int    `yaml:"session_key_ttl"`
}

// DefaultConfigPath returns ~/.kpm/config.yaml.
func DefaultConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".kpm", "config.yaml")
}

// LoadConfig reads and parses a YAML config file. Applies defaults for unset fields.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	// Defaults
	if cfg.DefaultTemplate == "" {
		cfg.DefaultTemplate = ".env.template"
	}
	if cfg.SessionKeyTTL <= 0 {
		cfg.SessionKeyTTL = 300
	}

	return cfg, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/BertSmith/personal/projects/pi.dev/agentkms && go test ./internal/kpm/ -run TestLoadConfig -v`
Expected: PASS (3 tests). `gopkg.in/yaml.v3` is already in go.mod.

- [ ] **Step 5: Commit**

```bash
cd /Users/BertSmith/personal/projects/pi.dev/agentkms
git add internal/kpm/config.go internal/kpm/config_test.go
git commit -m "feat(kpm): config loading with YAML and defaults"
```

---

## Task 3: Template Parser

**Files:**
- Create: `internal/kpm/template.go`
- Create: `internal/kpm/template_test.go`

This is the core of the .env.template story.

- [ ] **Step 1: Write the failing test**

Create `internal/kpm/template_test.go`:

```go
package kpm

import (
	"strings"
	"testing"
)

func TestParseKMSRef(t *testing.T) {
	tests := []struct {
		input string
		want  KMSReference
		ok    bool
	}{
		{
			input: "${kms:llm/openai}",
			want:  KMSReference{Type: "llm", Path: "openai", Key: "", Default: ""},
			ok:    true,
		},
		{
			input: "${kms:kv/db/prod#password}",
			want:  KMSReference{Type: "kv", Path: "db/prod", Key: "password", Default: ""},
			ok:    true,
		},
		{
			input: "${kms:kv/db/prod#host:-localhost}",
			want:  KMSReference{Type: "kv", Path: "db/prod", Key: "host", Default: "localhost"},
			ok:    true,
		},
		{
			input: "${kms:kv/app/config#port:-8080}",
			want:  KMSReference{Type: "kv", Path: "app/config", Key: "port", Default: "8080"},
			ok:    true,
		},
		{
			input: "plain-value",
			ok:    false,
		},
		{
			input: "${env:HOME}",
			ok:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			ref, ok := ParseKMSRef(tt.input)
			if ok != tt.ok {
				t.Fatalf("ParseKMSRef(%q) ok = %v, want %v", tt.input, ok, tt.ok)
			}
			if !ok {
				return
			}
			if ref != tt.want {
				t.Errorf("ParseKMSRef(%q) = %+v, want %+v", tt.input, ref, tt.want)
			}
		})
	}
}

func TestParseTemplate(t *testing.T) {
	input := `# comment line
APP_NAME=my-service
LOG_LEVEL=info
DB_PASSWORD=${kms:kv/db/prod#password}
DB_HOST=${kms:kv/db/prod#host}
OPENAI_KEY=${kms:llm/openai}
FALLBACK=${kms:kv/app/config#port:-8080}
`
	entries, err := ParseTemplate(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}

	if len(entries) != 6 {
		t.Fatalf("got %d entries, want 6", len(entries))
	}

	// Plain values
	if entries[0].EnvKey != "APP_NAME" || entries[0].IsKMSRef {
		t.Errorf("entry 0: want plain APP_NAME, got %+v", entries[0])
	}
	if string(entries[0].PlainValue) != "my-service" {
		t.Errorf("entry 0 value = %q, want my-service", entries[0].PlainValue)
	}

	// KMS ref: kv with key
	if entries[2].EnvKey != "DB_PASSWORD" || !entries[2].IsKMSRef {
		t.Errorf("entry 2: want KMS ref DB_PASSWORD, got %+v", entries[2])
	}
	if entries[2].Ref.Type != "kv" || entries[2].Ref.Path != "db/prod" || entries[2].Ref.Key != "password" {
		t.Errorf("entry 2 ref = %+v", entries[2].Ref)
	}

	// KMS ref: llm
	if entries[4].Ref.Type != "llm" || entries[4].Ref.Path != "openai" {
		t.Errorf("entry 4 ref = %+v", entries[4].Ref)
	}

	// KMS ref with default
	if entries[5].Ref.Default != "8080" {
		t.Errorf("entry 5 default = %q, want 8080", entries[5].Ref.Default)
	}
}

func TestParseTemplateEmpty(t *testing.T) {
	entries, err := ParseTemplate(strings.NewReader(""))
	if err != nil {
		t.Fatalf("ParseTemplate empty: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("got %d entries for empty input, want 0", len(entries))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/BertSmith/personal/projects/pi.dev/agentkms && go test ./internal/kpm/ -run TestParse -v`
Expected: FAIL — types not defined.

- [ ] **Step 3: Write minimal implementation**

Create `internal/kpm/template.go`:

```go
package kpm

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// kmsRefPattern matches ${kms:type/path[#key][:-default]}.
// Groups: [1]=type (llm|kv), [2]=path, [3]=key (optional), [4]=default (optional).
var kmsRefPattern = regexp.MustCompile(`^\$\{kms:([a-z]+)/(.*?)(?:#([^:}]+))?(?::-(.*?))?\}$`)

// kmsInlinePattern matches ${kms:...} anywhere in a value string.
var kmsInlinePattern = regexp.MustCompile(`\$\{kms:([a-z]+)/(.*?)(?:#([^:}]+))?(?::-(.*?))?\}`)

// KMSReference is a parsed reference to a secret in AgentKMS.
type KMSReference struct {
	Type    string // "llm" or "kv"
	Path    string // e.g. "db/prod" or "openai"
	Key     string // e.g. "password" (empty for LLM refs)
	Default string // fallback value (empty if none)
}

// TemplateEntry is one line from a parsed .env.template.
type TemplateEntry struct {
	EnvKey     string       // env var name (e.g. "DB_PASSWORD")
	PlainValue []byte       // non-KMS value (for passthrough lines)
	IsKMSRef   bool         // true if value is a ${kms:...} reference
	Ref        KMSReference // populated only if IsKMSRef
	Source     string       // set by resolver: "agentkms", "cache", "default"
}

// ParseKMSRef parses a single ${kms:...} reference string.
// Returns the parsed reference and true, or zero value and false if not a KMS ref.
func ParseKMSRef(s string) (KMSReference, bool) {
	m := kmsRefPattern.FindStringSubmatch(s)
	if m == nil {
		return KMSReference{}, false
	}
	return KMSReference{
		Type:    m[1],
		Path:    m[2],
		Key:     m[3],
		Default: m[4],
	}, true
}

// ParseTemplate reads an .env.template and returns parsed entries.
// Comment lines (starting with #) and blank lines are skipped.
// Plain KEY=value lines pass through. Lines with ${kms:...} values become KMS refs.
func ParseTemplate(r io.Reader) ([]TemplateEntry, error) {
	var entries []TemplateEntry
	scanner := bufio.NewScanner(r)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and blank lines.
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Split on first '='.
		eqIdx := strings.IndexByte(line, '=')
		if eqIdx < 0 {
			return nil, fmt.Errorf("line %d: no '=' found in %q", lineNum, line)
		}

		key := line[:eqIdx]
		value := line[eqIdx+1:]

		ref, isRef := ParseKMSRef(value)
		if isRef {
			entries = append(entries, TemplateEntry{
				EnvKey:   key,
				IsKMSRef: true,
				Ref:      ref,
			})
		} else {
			entries = append(entries, TemplateEntry{
				EnvKey:     key,
				PlainValue: []byte(value),
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading template: %w", err)
	}

	return entries, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/BertSmith/personal/projects/pi.dev/agentkms && go test ./internal/kpm/ -run TestParse -v`
Expected: PASS (all tests)

- [ ] **Step 5: Commit**

```bash
cd /Users/BertSmith/personal/projects/pi.dev/agentkms
git add internal/kpm/template.go internal/kpm/template_test.go
git commit -m "feat(kpm): template parser for .env.template files"
```

---

## Task 4: AgentKMS HTTP Client

**Files:**
- Create: `internal/kpm/client.go`
- Create: `internal/kpm/client_test.go`

Wraps `pkg/tlsutil.ClientTLSConfig` and hits the credential + encrypt/decrypt endpoints.

- [ ] **Step 1: Write the failing test**

Create `internal/kpm/client_test.go`:

```go
package kpm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientFetchLLM(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/credentials/llm/openai" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.Error(w, "not found", 404)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"provider":    "openai",
			"api_key":     "sk-test-key-123",
			"expires_at":  "2026-04-12T00:00:00Z",
			"ttl_seconds": 3600,
		})
	}))
	defer srv.Close()

	c := &Client{
		baseURL:    srv.URL,
		httpClient: srv.Client(),
	}

	cred, err := c.FetchLLM(context.Background(), "openai")
	if err != nil {
		t.Fatalf("FetchLLM: %v", err)
	}
	if string(cred.APIKey) != "sk-test-key-123" {
		t.Errorf("APIKey = %q, want sk-test-key-123", cred.APIKey)
	}
	defer ZeroBytes(cred.APIKey)
}

func TestClientFetchGeneric(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/credentials/generic/db/prod" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.Error(w, "not found", 404)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"path": "db/prod",
			"secrets": map[string]string{
				"password": "s3cret",
				"host":     "db.prod.internal",
			},
			"expires_at":  "2026-04-12T00:00:00Z",
			"ttl_seconds": 3600,
		})
	}))
	defer srv.Close()

	c := &Client{
		baseURL:    srv.URL,
		httpClient: srv.Client(),
	}

	cred, err := c.FetchGeneric(context.Background(), "db/prod")
	if err != nil {
		t.Fatalf("FetchGeneric: %v", err)
	}
	defer ZeroMap(cred.Secrets)

	if string(cred.Secrets["password"]) != "s3cret" {
		t.Errorf("password = %q, want s3cret", cred.Secrets["password"])
	}
	if string(cred.Secrets["host"]) != "db.prod.internal" {
		t.Errorf("host = %q, want db.prod.internal", cred.Secrets["host"])
	}
}

func TestClientFetchGenericNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"not found"}`, 404)
	}))
	defer srv.Close()

	c := &Client{
		baseURL:    srv.URL,
		httpClient: srv.Client(),
	}

	_, err := c.FetchGeneric(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for 404")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/BertSmith/personal/projects/pi.dev/agentkms && go test ./internal/kpm/ -run TestClient -v`
Expected: FAIL — `Client` type not defined.

- [ ] **Step 3: Write minimal implementation**

Create `internal/kpm/client.go`:

```go
package kpm

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/agentkms/agentkms/pkg/tlsutil"
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

// FetchLLM retrieves an LLM provider credential.
func (c *Client) FetchLLM(ctx context.Context, provider string) (*LLMCredential, error) {
	url := c.baseURL + "/credentials/llm/" + provider

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/BertSmith/personal/projects/pi.dev/agentkms && go test ./internal/kpm/ -run TestClient -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
cd /Users/BertSmith/personal/projects/pi.dev/agentkms
git add internal/kpm/client.go internal/kpm/client_test.go
git commit -m "feat(kpm): AgentKMS HTTP client with mTLS"
```

---

## Task 5: Resolver (Connects Parser to Client)

**Files:**
- Create: `internal/kpm/resolver.go`
- Create: `internal/kpm/resolver_test.go`

Takes `[]TemplateEntry` from the parser, batches API calls, and fills in resolved values.

- [ ] **Step 1: Write the failing test**

Create `internal/kpm/resolver_test.go`:

```go
package kpm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestResolve(t *testing.T) {
	calls := map[string]int{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls[r.URL.Path]++
		switch r.URL.Path {
		case "/credentials/llm/openai":
			json.NewEncoder(w).Encode(map[string]any{
				"provider": "openai", "api_key": "sk-openai",
				"expires_at": "2026-04-12T00:00:00Z", "ttl_seconds": 3600,
			})
		case "/credentials/generic/db/prod":
			json.NewEncoder(w).Encode(map[string]any{
				"path": "db/prod",
				"secrets": map[string]string{
					"password": "s3cret",
					"host":     "db.prod.internal",
				},
				"expires_at": "2026-04-12T00:00:00Z", "ttl_seconds": 3600,
			})
		default:
			http.Error(w, "not found", 404)
		}
	}))
	defer srv.Close()

	client := &Client{baseURL: srv.URL, httpClient: srv.Client()}

	tmpl := `APP_NAME=my-service
DB_PASSWORD=${kms:kv/db/prod#password}
DB_HOST=${kms:kv/db/prod#host}
OPENAI_KEY=${kms:llm/openai}
`
	entries, err := ParseTemplate(strings.NewReader(tmpl))
	if err != nil {
		t.Fatal(err)
	}

	resolved, err := Resolve(context.Background(), client, entries)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	// Verify values.
	want := map[string]string{
		"APP_NAME":    "my-service",
		"DB_PASSWORD": "s3cret",
		"DB_HOST":     "db.prod.internal",
		"OPENAI_KEY":  "sk-openai",
	}
	for _, e := range resolved {
		expected, ok := want[e.EnvKey]
		if !ok {
			t.Errorf("unexpected entry: %s", e.EnvKey)
			continue
		}
		if string(e.PlainValue) != expected {
			t.Errorf("%s = %q, want %q", e.EnvKey, e.PlainValue, expected)
		}
	}

	// Verify batch: db/prod fetched only once despite 2 refs.
	if calls["/credentials/generic/db/prod"] != 1 {
		t.Errorf("generic/db/prod called %d times, want 1", calls["/credentials/generic/db/prod"])
	}
}

func TestResolveWithDefault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", 404)
	}))
	defer srv.Close()

	client := &Client{baseURL: srv.URL, httpClient: srv.Client()}

	entries, _ := ParseTemplate(strings.NewReader("PORT=${kms:kv/app/config#port:-8080}\n"))

	resolved, err := Resolve(context.Background(), client, entries)
	if err != nil {
		t.Fatalf("Resolve with default: %v", err)
	}
	if string(resolved[0].PlainValue) != "8080" {
		t.Errorf("PORT = %q, want 8080 (default)", resolved[0].PlainValue)
	}
	if resolved[0].Source != "default" {
		t.Errorf("Source = %q, want default", resolved[0].Source)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/BertSmith/personal/projects/pi.dev/agentkms && go test ./internal/kpm/ -run TestResolve -v`
Expected: FAIL — `Resolve` not defined.

- [ ] **Step 3: Write minimal implementation**

Create `internal/kpm/resolver.go`:

```go
package kpm

import (
	"context"
	"fmt"
)

// ResolvedEntry is a template entry with its value filled in.
type ResolvedEntry struct {
	EnvKey     string
	PlainValue []byte // SECURITY: call ZeroBytes after use
	IsKMSRef   bool
	Ref        KMSReference
	Source     string // "agentkms", "cache", "default", or "" (passthrough)
}

// Resolve takes parsed template entries and fetches all KMS values.
// It batches requests: multiple refs to the same KV path produce one API call.
func Resolve(ctx context.Context, client *Client, entries []TemplateEntry) ([]ResolvedEntry, error) {
	// Group KV refs by path for batching.
	type kvResult struct {
		secrets map[string][]byte
		err     error
	}
	kvCache := map[string]*kvResult{}

	// Prefetch: collect unique KV paths.
	for _, e := range entries {
		if !e.IsKMSRef || e.Ref.Type != "kv" {
			continue
		}
		if _, ok := kvCache[e.Ref.Path]; !ok {
			cred, err := client.FetchGeneric(ctx, e.Ref.Path)
			if err != nil {
				kvCache[e.Ref.Path] = &kvResult{err: err}
			} else {
				kvCache[e.Ref.Path] = &kvResult{secrets: cred.Secrets}
			}
		}
	}

	// LLM cache (one call per provider).
	llmCache := map[string]*LLMCredential{}

	resolved := make([]ResolvedEntry, 0, len(entries))
	for _, e := range entries {
		re := ResolvedEntry{
			EnvKey:   e.EnvKey,
			IsKMSRef: e.IsKMSRef,
			Ref:      e.Ref,
		}

		if !e.IsKMSRef {
			re.PlainValue = make([]byte, len(e.PlainValue))
			copy(re.PlainValue, e.PlainValue)
			resolved = append(resolved, re)
			continue
		}

		switch e.Ref.Type {
		case "kv":
			result := kvCache[e.Ref.Path]
			if result.err != nil {
				if e.Ref.Default != "" {
					re.PlainValue = []byte(e.Ref.Default)
					re.Source = "default"
					resolved = append(resolved, re)
					continue
				}
				return nil, fmt.Errorf("resolve %s: %w", e.EnvKey, result.err)
			}
			val, ok := result.secrets[e.Ref.Key]
			if !ok {
				if e.Ref.Default != "" {
					re.PlainValue = []byte(e.Ref.Default)
					re.Source = "default"
					resolved = append(resolved, re)
					continue
				}
				return nil, fmt.Errorf("resolve %s: key %q not found at path %q", e.EnvKey, e.Ref.Key, e.Ref.Path)
			}
			re.PlainValue = make([]byte, len(val))
			copy(re.PlainValue, val)
			re.Source = "agentkms"

		case "llm":
			if _, ok := llmCache[e.Ref.Path]; !ok {
				cred, err := client.FetchLLM(ctx, e.Ref.Path)
				if err != nil {
					if e.Ref.Default != "" {
						re.PlainValue = []byte(e.Ref.Default)
						re.Source = "default"
						resolved = append(resolved, re)
						continue
					}
					return nil, fmt.Errorf("resolve %s: %w", e.EnvKey, err)
				}
				llmCache[e.Ref.Path] = cred
			}
			cred := llmCache[e.Ref.Path]
			re.PlainValue = make([]byte, len(cred.APIKey))
			copy(re.PlainValue, cred.APIKey)
			re.Source = "agentkms"

		default:
			return nil, fmt.Errorf("resolve %s: unknown ref type %q", e.EnvKey, e.Ref.Type)
		}

		resolved = append(resolved, re)
	}

	return resolved, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/BertSmith/personal/projects/pi.dev/agentkms && go test ./internal/kpm/ -run TestResolve -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
cd /Users/BertSmith/personal/projects/pi.dev/agentkms
git add internal/kpm/resolver.go internal/kpm/resolver_test.go
git commit -m "feat(kpm): resolver with batch dedup for KV paths"
```

---

## Task 6: Export Command

**Files:**
- Create: `internal/kpm/export.go`
- Create: `internal/kpm/export_test.go`

Output resolved entries as dotenv, shell, or JSON.

- [ ] **Step 1: Write the failing test**

Create `internal/kpm/export_test.go`:

```go
package kpm

import (
	"bytes"
	"testing"
)

func TestFormatDotenv(t *testing.T) {
	entries := []ResolvedEntry{
		{EnvKey: "APP_NAME", PlainValue: []byte("my-service")},
		{EnvKey: "DB_PASSWORD", PlainValue: []byte("s3cret"), IsKMSRef: true, Source: "agentkms"},
	}

	var buf bytes.Buffer
	if err := FormatDotenv(&buf, entries); err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	if !bytes.Contains([]byte(out), []byte("# WARNING")) {
		t.Error("missing warning header")
	}
	if !bytes.Contains([]byte(out), []byte("APP_NAME=my-service")) {
		t.Error("missing APP_NAME")
	}
	if !bytes.Contains([]byte(out), []byte("DB_PASSWORD=s3cret")) {
		t.Error("missing DB_PASSWORD")
	}
}

func TestFormatShell(t *testing.T) {
	entries := []ResolvedEntry{
		{EnvKey: "DB_PASSWORD", PlainValue: []byte("s3cret")},
	}

	var buf bytes.Buffer
	if err := FormatShell(&buf, entries); err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	if !bytes.Contains([]byte(out), []byte("export DB_PASSWORD='s3cret'")) {
		t.Errorf("unexpected shell output: %s", out)
	}
}

func TestFormatJSON(t *testing.T) {
	entries := []ResolvedEntry{
		{EnvKey: "APP", PlainValue: []byte("test")},
		{EnvKey: "KEY", PlainValue: []byte("val")},
	}

	var buf bytes.Buffer
	if err := FormatJSON(&buf, entries); err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	if !bytes.Contains([]byte(out), []byte(`"APP"`)) {
		t.Errorf("missing APP in JSON: %s", out)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/BertSmith/personal/projects/pi.dev/agentkms && go test ./internal/kpm/ -run TestFormat -v`
Expected: FAIL — functions not defined.

- [ ] **Step 3: Write minimal implementation**

Create `internal/kpm/export.go`:

```go
package kpm

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// FormatDotenv writes entries as KEY=value lines with a warning header.
func FormatDotenv(w io.Writer, entries []ResolvedEntry) error {
	fmt.Fprintln(w, "# WARNING: contains plaintext secrets — do not commit")
	fmt.Fprintln(w, "# Generated by kpm export")
	fmt.Fprintln(w)
	for _, e := range entries {
		if _, err := fmt.Fprintf(w, "%s=%s\n", e.EnvKey, e.PlainValue); err != nil {
			return err
		}
	}
	return nil
}

// FormatShell writes entries as export KEY='value' lines.
// Single quotes prevent shell expansion; embedded single quotes are escaped.
func FormatShell(w io.Writer, entries []ResolvedEntry) error {
	for _, e := range entries {
		escaped := strings.ReplaceAll(string(e.PlainValue), "'", "'\\''")
		if _, err := fmt.Fprintf(w, "export %s='%s'\n", e.EnvKey, escaped); err != nil {
			return err
		}
	}
	return nil
}

// FormatJSON writes entries as a JSON object {"KEY": "value", ...}.
func FormatJSON(w io.Writer, entries []ResolvedEntry) error {
	m := make(map[string]string, len(entries))
	for _, e := range entries {
		m[e.EnvKey] = string(e.PlainValue)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(m)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/BertSmith/personal/projects/pi.dev/agentkms && go test ./internal/kpm/ -run TestFormat -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
cd /Users/BertSmith/personal/projects/pi.dev/agentkms
git add internal/kpm/export.go internal/kpm/export_test.go
git commit -m "feat(kpm): export formatters (dotenv, shell, JSON)"
```

---

## Task 7: Runner (kpm run — exec with env)

**Files:**
- Create: `internal/kpm/runner.go`
- Create: `internal/kpm/runner_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/kpm/runner_test.go`:

```go
package kpm

import (
	"context"
	"os"
	"runtime"
	"testing"
)

func TestBuildEnv(t *testing.T) {
	entries := []ResolvedEntry{
		{EnvKey: "APP_NAME", PlainValue: []byte("test")},
		{EnvKey: "SECRET", PlainValue: []byte("s3cret")},
	}

	env := BuildEnv(entries)

	found := map[string]bool{}
	for _, e := range env {
		if e == "APP_NAME=test" {
			found["APP_NAME"] = true
		}
		if e == "SECRET=s3cret" {
			found["SECRET"] = true
		}
	}
	if !found["APP_NAME"] || !found["SECRET"] {
		t.Errorf("missing expected env vars in %v", env)
	}

	// Should also include inherited env.
	if len(env) <= 2 {
		t.Error("expected inherited env vars too")
	}
}

func TestRunCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skip on windows")
	}

	entries := []ResolvedEntry{
		{EnvKey: "KPM_TEST_VAR", PlainValue: []byte("hello")},
	}

	// Run a command that prints our env var.
	exitCode, err := RunCommand(context.Background(), entries, "sh", []string{"-c", "echo $KPM_TEST_VAR"})
	if err != nil {
		t.Fatalf("RunCommand: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exit code = %d, want 0", exitCode)
	}
}

func TestRunCommandFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skip on windows")
	}

	entries := []ResolvedEntry{}
	exitCode, err := RunCommand(context.Background(), entries, "sh", []string{"-c", "exit 42"})
	if err != nil {
		t.Fatalf("RunCommand: %v", err)
	}
	if exitCode != 42 {
		t.Errorf("exit code = %d, want 42", exitCode)
	}
}

func TestRunCommandNotFound(t *testing.T) {
	entries := []ResolvedEntry{}
	_, err := RunCommand(context.Background(), entries, "/nonexistent/binary", nil)
	if err == nil {
		t.Fatal("expected error for missing binary")
	}
}

func init() {
	// Ensure tests have a clean PATH.
	_ = os.Getenv("PATH")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/BertSmith/personal/projects/pi.dev/agentkms && go test ./internal/kpm/ -run "TestBuildEnv|TestRunCommand" -v`
Expected: FAIL — functions not defined.

- [ ] **Step 3: Write minimal implementation**

Create `internal/kpm/runner.go`:

```go
package kpm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
)

// BuildEnv creates a process environment from resolved entries.
// Inherits the current process env, then overlays the resolved values.
func BuildEnv(entries []ResolvedEntry) []string {
	env := os.Environ()
	for _, e := range entries {
		env = append(env, fmt.Sprintf("%s=%s", e.EnvKey, e.PlainValue))
	}
	return env
}

// RunCommand executes a command with resolved entries injected as env vars.
// Returns the exit code. Stdin, stdout, and stderr are inherited.
func RunCommand(ctx context.Context, entries []ResolvedEntry, name string, args []string) (int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = BuildEnv(entries)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err == nil {
		return 0, nil
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), nil
	}

	return -1, fmt.Errorf("run %s: %w", name, err)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/BertSmith/personal/projects/pi.dev/agentkms && go test ./internal/kpm/ -run "TestBuildEnv|TestRunCommand" -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
cd /Users/BertSmith/personal/projects/pi.dev/agentkms
git add internal/kpm/runner.go internal/kpm/runner_test.go
git commit -m "feat(kpm): command runner with env injection"
```

---

## Task 8: CLI Entry Point (cmd/kpm/main.go)

**Files:**
- Create: `cmd/kpm/main.go`

Wires everything together with a subcommand dispatcher. Uses stdlib `flag` (no Cobra — respects the dependency policy in go.mod).

- [ ] **Step 1: Create the CLI entry point**

Create `cmd/kpm/main.go`:

```go
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/agentkms/agentkms/internal/kpm"
)

const usage = `kpm — secure secrets CLI backed by AgentKMS

Usage:
  kpm export [flags]              Resolve template and output env vars
  kpm run [flags] -- <cmd> [args] Resolve template and run command with env
  kpm get <ref>                   Fetch a single secret
  kpm init                        Create ~/.kpm/config.yaml
  kpm version                     Print version

Global flags:
  --config <path>   Config file (default: ~/.kpm/config.yaml)
  --server <url>    AgentKMS server URL (overrides config)
  --cert <path>     mTLS client cert (overrides config)
  --key <path>      mTLS client key (overrides config)
  --ca <path>       CA cert for AgentKMS
  --verbose         Debug output (never prints secrets)
`

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	subcmd := os.Args[1]

	// Parse global flags from remaining args.
	fs := flag.NewFlagSet("kpm", flag.ExitOnError)
	configPath := fs.String("config", kpm.DefaultConfigPath(), "config file path")
	serverFlag := fs.String("server", "", "AgentKMS server URL")
	certFlag := fs.String("cert", "", "mTLS client cert path")
	keyFlag := fs.String("key", "", "mTLS client key path")
	caFlag := fs.String("ca", "", "CA cert path")
	verbose := fs.Bool("verbose", false, "debug output")

	// Subcommand-specific flags.
	templateFlag := fs.String("from", "", "template file path")
	outputFlag := fs.String("output", "dotenv", "output format: dotenv, shell, json")
	// secure flags (wired in Tasks 9+)
	_ = fs.Bool("secure", false, "enable ciphertext injection mode")
	_ = fs.Bool("secure-strict", false, "enable strict ciphertext mode (network per decrypt)")

	switch subcmd {
	case "version":
		fmt.Println("kpm", version)
		return
	case "help", "--help", "-h":
		fmt.Fprint(os.Stderr, usage)
		return
	case "export", "run", "get", "init":
		// Parse flags after subcmd.
		if err := fs.Parse(os.Args[2:]); err != nil {
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n%s", subcmd, usage)
		os.Exit(1)
	}

	// Load config (best-effort — flags override).
	cfg := &kpm.Config{}
	if data, err := os.ReadFile(*configPath); err == nil {
		loaded, loadErr := kpm.LoadConfig(*configPath)
		if loadErr == nil {
			cfg = loaded
		} else if *verbose {
			fmt.Fprintf(os.Stderr, "warning: config parse error: %v\n", loadErr)
		}
		_ = data
	}

	// Flag overrides.
	if *serverFlag != "" {
		cfg.Server = *serverFlag
	}
	if *certFlag != "" {
		cfg.Cert = *certFlag
	}
	if *keyFlag != "" {
		cfg.Key = *keyFlag
	}
	if *caFlag != "" {
		cfg.CA = *caFlag
	}

	ctx := context.Background()

	switch subcmd {
	case "init":
		runInit(cfg, *configPath)

	case "export":
		tmplPath := *templateFlag
		if tmplPath == "" {
			tmplPath = cfg.DefaultTemplate
		}
		runExport(ctx, cfg, tmplPath, *outputFlag, *verbose)

	case "run":
		tmplPath := *templateFlag
		if tmplPath == "" {
			tmplPath = cfg.DefaultTemplate
		}
		// Everything after "--" (or remaining args) is the command.
		cmdArgs := fs.Args()
		if len(cmdArgs) == 0 {
			fmt.Fprintln(os.Stderr, "kpm run: no command specified")
			os.Exit(1)
		}
		runRun(ctx, cfg, tmplPath, cmdArgs, *verbose)

	case "get":
		args := fs.Args()
		if len(args) == 0 {
			fmt.Fprintln(os.Stderr, "kpm get: no reference specified")
			os.Exit(1)
		}
		runGet(ctx, cfg, args[0], *verbose)
	}
}

func buildClient(cfg *kpm.Config) *kpm.Client {
	if cfg.Server == "" || cfg.Cert == "" || cfg.Key == "" || cfg.CA == "" {
		fmt.Fprintln(os.Stderr, "error: server, cert, key, and ca are required (set via config or flags)")
		fmt.Fprintln(os.Stderr, "run: kpm init")
		os.Exit(1)
	}
	client, err := kpm.NewClient(cfg.Server, cfg.CA, cfg.Cert, cfg.Key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating client: %v\n", err)
		os.Exit(1)
	}
	return client
}

func runExport(ctx context.Context, cfg *kpm.Config, tmplPath, format string, verbose bool) {
	f, err := os.Open(tmplPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening template %s: %v\n", tmplPath, err)
		os.Exit(1)
	}
	defer f.Close()

	entries, err := kpm.ParseTemplate(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing template: %v\n", err)
		os.Exit(1)
	}

	client := buildClient(cfg)
	resolved, err := kpm.Resolve(ctx, client, entries)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error resolving secrets: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		for i := range resolved {
			kpm.ZeroBytes(resolved[i].PlainValue)
		}
	}()

	if verbose {
		kmsCount := 0
		for _, e := range resolved {
			if e.IsKMSRef {
				kmsCount++
			}
		}
		fmt.Fprintf(os.Stderr, "✓ Resolved %d secrets from AgentKMS\n", kmsCount)
	}

	switch strings.ToLower(format) {
	case "dotenv":
		err = kpm.FormatDotenv(os.Stdout, resolved)
	case "shell":
		err = kpm.FormatShell(os.Stdout, resolved)
	case "json":
		err = kpm.FormatJSON(os.Stdout, resolved)
	default:
		fmt.Fprintf(os.Stderr, "unknown format: %s (use dotenv, shell, or json)\n", format)
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error writing output: %v\n", err)
		os.Exit(1)
	}
}

func runRun(ctx context.Context, cfg *kpm.Config, tmplPath string, cmdArgs []string, verbose bool) {
	f, err := os.Open(tmplPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening template %s: %v\n", tmplPath, err)
		os.Exit(1)
	}
	defer f.Close()

	entries, err := kpm.ParseTemplate(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing template: %v\n", err)
		os.Exit(1)
	}

	client := buildClient(cfg)
	resolved, err := kpm.Resolve(ctx, client, entries)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error resolving secrets: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		for i := range resolved {
			kpm.ZeroBytes(resolved[i].PlainValue)
		}
	}()

	if verbose {
		kmsCount := 0
		for _, e := range resolved {
			if e.IsKMSRef {
				kmsCount++
			}
		}
		fmt.Fprintf(os.Stderr, "✓ Resolved %d secrets from AgentKMS\n", kmsCount)
		fmt.Fprintf(os.Stderr, "✓ Injecting plaintext env vars\n")
	}

	exitCode, err := kpm.RunCommand(ctx, resolved, cmdArgs[0], cmdArgs[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	os.Exit(exitCode)
}

func runGet(ctx context.Context, cfg *kpm.Config, ref string, verbose bool) {
	parsed, ok := kpm.ParseKMSRef("${kms:" + ref + "}")
	if !ok {
		fmt.Fprintf(os.Stderr, "invalid reference: %s\nFormat: kv/path#key or llm/provider\n", ref)
		os.Exit(1)
	}

	client := buildClient(cfg)

	switch parsed.Type {
	case "llm":
		cred, err := client.FetchLLM(ctx, parsed.Path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		defer kpm.ZeroBytes(cred.APIKey)
		os.Stdout.Write(cred.APIKey)

	case "kv":
		cred, err := client.FetchGeneric(ctx, parsed.Path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		defer kpm.ZeroMap(cred.Secrets)

		if parsed.Key == "" {
			// Print all keys.
			for k, v := range cred.Secrets {
				fmt.Fprintf(os.Stdout, "%s=%s\n", k, v)
			}
		} else {
			val, ok := cred.Secrets[parsed.Key]
			if !ok {
				fmt.Fprintf(os.Stderr, "key %q not found at path %q\n", parsed.Key, parsed.Path)
				os.Exit(1)
			}
			os.Stdout.Write(val)
		}

	default:
		fmt.Fprintf(os.Stderr, "unknown ref type: %s\n", parsed.Type)
		os.Exit(1)
	}
}

func runInit(cfg *kpm.Config, path string) {
	if _, err := os.Stat(path); err == nil {
		fmt.Fprintf(os.Stderr, "config already exists: %s\n", path)
		os.Exit(1)
	}

	dir := path[:strings.LastIndex(path, "/")]
	if err := os.MkdirAll(dir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "error creating config dir: %v\n", err)
		os.Exit(1)
	}

	template := `# KPM Configuration
# Generated by: kpm init
server: https://127.0.0.1:8443
cert: ~/.kpm/certs/client.crt
key: ~/.kpm/certs/client.key
ca: ~/.kpm/certs/ca.crt
default_template: .env.template
secure_mode: false
session_key_ttl: 300
`
	if err := os.WriteFile(path, []byte(template), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "error writing config: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "✓ Config written to %s\n", path)
	fmt.Fprintln(os.Stderr, "  Edit it with your AgentKMS server details and cert paths.")
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cd /Users/BertSmith/personal/projects/pi.dev/agentkms && go build ./cmd/kpm/`
Expected: builds successfully, produces `kpm` binary.

- [ ] **Step 3: Smoke test**

Run: `cd /Users/BertSmith/personal/projects/pi.dev/agentkms && ./kpm version && ./kpm help`
Expected: prints version and usage.

- [ ] **Step 4: Commit**

```bash
cd /Users/BertSmith/personal/projects/pi.dev/agentkms
git add cmd/kpm/main.go
git commit -m "feat(kpm): CLI entry point with export, run, get, init subcommands"
```

---

## Task 9: End-to-End Integration Test

**Files:**
- Create: `internal/kpm/integration_test.go`

Spins up a mock AgentKMS server and runs the full pipeline: parse → resolve → export.

- [ ] **Step 1: Write the integration test**

Create `internal/kpm/integration_test.go`:

```go
package kpm

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIntegrationExportPipeline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/credentials/llm/openai":
			json.NewEncoder(w).Encode(map[string]any{
				"provider": "openai", "api_key": "sk-test-openai",
				"expires_at": "2026-04-12T00:00:00Z", "ttl_seconds": 3600,
			})
		case "/credentials/llm/anthropic":
			json.NewEncoder(w).Encode(map[string]any{
				"provider": "anthropic", "api_key": "sk-ant-test",
				"expires_at": "2026-04-12T00:00:00Z", "ttl_seconds": 3600,
			})
		case "/credentials/generic/db/prod":
			json.NewEncoder(w).Encode(map[string]any{
				"path": "db/prod",
				"secrets": map[string]string{
					"password": "s3cret-pg-pass",
					"host":     "db.prod.internal",
					"port":     "5432",
				},
				"expires_at": "2026-04-12T00:00:00Z", "ttl_seconds": 3600,
			})
		default:
			http.Error(w, "not found", 404)
		}
	}))
	defer srv.Close()

	template := `# my-app/.env.template
APP_NAME=my-service
LOG_LEVEL=info
DB_HOST=${kms:kv/db/prod#host}
DB_PORT=${kms:kv/db/prod#port}
DB_PASSWORD=${kms:kv/db/prod#password}
OPENAI_API_KEY=${kms:llm/openai}
ANTHROPIC_API_KEY=${kms:llm/anthropic}
`

	// Parse.
	entries, err := ParseTemplate(strings.NewReader(template))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 7 {
		t.Fatalf("parsed %d entries, want 7", len(entries))
	}

	// Resolve.
	client := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	resolved, err := Resolve(context.Background(), client, entries)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for i := range resolved {
			ZeroBytes(resolved[i].PlainValue)
		}
	}()

	// Format as dotenv.
	var buf bytes.Buffer
	if err := FormatDotenv(&buf, resolved); err != nil {
		t.Fatal(err)
	}

	output := buf.String()

	// Verify all values present.
	checks := map[string]string{
		"APP_NAME=my-service":               "plain passthrough",
		"DB_HOST=db.prod.internal":          "KV ref with key",
		"DB_PASSWORD=s3cret-pg-pass":        "KV ref password",
		"OPENAI_API_KEY=sk-test-openai":     "LLM ref",
		"ANTHROPIC_API_KEY=sk-ant-test":     "LLM ref",
	}
	for check, desc := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("missing %s (%s) in output:\n%s", check, desc, output)
		}
	}

	// Verify zeroing works.
	for i := range resolved {
		ZeroBytes(resolved[i].PlainValue)
	}
	for _, e := range resolved {
		for _, b := range e.PlainValue {
			if b != 0 {
				t.Fatalf("PlainValue for %s not zeroed", e.EnvKey)
			}
		}
	}
}
```

- [ ] **Step 2: Run integration test**

Run: `cd /Users/BertSmith/personal/projects/pi.dev/agentkms && go test ./internal/kpm/ -run TestIntegration -v`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
cd /Users/BertSmith/personal/projects/pi.dev/agentkms
git add internal/kpm/integration_test.go
git commit -m "test(kpm): end-to-end integration test for export pipeline"
```

---

## Task 10: Local Encrypt/Decrypt (Session Key for --secure mode)

**Files:**
- Create: `internal/kpm/encrypt.go`
- Create: `internal/kpm/encrypt_test.go`

AES-256-GCM envelope encryption using Go stdlib. No new dependencies.

- [ ] **Step 1: Write the failing test**

Create `internal/kpm/encrypt_test.go`:

```go
package kpm

import (
	"bytes"
	"strings"
	"testing"
)

func TestNewSessionKey(t *testing.T) {
	sk, err := NewSessionKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(sk) != 32 {
		t.Fatalf("session key length = %d, want 32", len(sk))
	}
	defer ZeroBytes(sk)

	// Two keys should differ.
	sk2, _ := NewSessionKey()
	defer ZeroBytes(sk2)
	if bytes.Equal(sk, sk2) {
		t.Error("two session keys should not be equal")
	}
}

func TestEncryptDecryptLocal(t *testing.T) {
	sk, err := NewSessionKey()
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroBytes(sk)

	plaintext := []byte("super-secret-api-key")
	ciphertext, err := EncryptLocal(sk, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	// Ciphertext should be different from plaintext.
	if bytes.Equal(ciphertext, plaintext) {
		t.Error("ciphertext equals plaintext")
	}

	// Decrypt should recover original.
	recovered, err := DecryptLocal(sk, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroBytes(recovered)

	if !bytes.Equal(recovered, plaintext) {
		t.Errorf("recovered = %q, want %q", recovered, plaintext)
	}
}

func TestEncryptLocalProducesBlobFormat(t *testing.T) {
	sk, _ := NewSessionKey()
	defer ZeroBytes(sk)

	ct, err := EncryptLocal(sk, []byte("test"))
	if err != nil {
		t.Fatal(err)
	}

	blob := FormatCiphertextBlob("sess123", ct)
	if !strings.HasPrefix(blob, "ENC[kpm:") {
		t.Errorf("blob format wrong: %s", blob)
	}

	sid, raw, err := ParseCiphertextBlob(blob)
	if err != nil {
		t.Fatal(err)
	}
	if sid != "sess123" {
		t.Errorf("session ID = %q, want sess123", sid)
	}
	if !bytes.Equal(raw, ct) {
		t.Error("parsed ciphertext doesn't match original")
	}
}

func TestDecryptLocalWrongKey(t *testing.T) {
	sk1, _ := NewSessionKey()
	sk2, _ := NewSessionKey()
	defer ZeroBytes(sk1)
	defer ZeroBytes(sk2)

	ct, _ := EncryptLocal(sk1, []byte("secret"))
	_, err := DecryptLocal(sk2, ct)
	if err == nil {
		t.Error("expected error decrypting with wrong key")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/BertSmith/personal/projects/pi.dev/agentkms && go test ./internal/kpm/ -run "TestNewSession|TestEncrypt|TestDecrypt" -v`
Expected: FAIL — functions not defined.

- [ ] **Step 3: Write minimal implementation**

Create `internal/kpm/encrypt.go`:

```go
package kpm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
)

// NewSessionKey generates a random 32-byte AES-256 key.
func NewSessionKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate session key: %w", err)
	}
	return key, nil
}

// EncryptLocal encrypts plaintext with AES-256-GCM using the given key.
// Returns nonce || ciphertext (nonce is 12 bytes prepended).
func EncryptLocal(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// DecryptLocal decrypts ciphertext (nonce || ciphertext) with AES-256-GCM.
func DecryptLocal(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}

// FormatCiphertextBlob wraps raw ciphertext in the KPM envelope format:
// ENC[kpm:<sessionID>:<base64-ciphertext>]
func FormatCiphertextBlob(sessionID string, ciphertext []byte) string {
	return fmt.Sprintf("ENC[kpm:%s:%s]", sessionID, base64.StdEncoding.EncodeToString(ciphertext))
}

// ParseCiphertextBlob extracts session ID and raw ciphertext from an ENC[kpm:...] blob.
func ParseCiphertextBlob(blob string) (sessionID string, ciphertext []byte, err error) {
	if !strings.HasPrefix(blob, "ENC[kpm:") || !strings.HasSuffix(blob, "]") {
		return "", nil, fmt.Errorf("invalid blob format: %q", blob)
	}
	inner := blob[8 : len(blob)-1] // strip "ENC[kpm:" and "]"
	parts := strings.SplitN(inner, ":", 2)
	if len(parts) != 2 {
		return "", nil, fmt.Errorf("invalid blob: expected sessionID:ciphertext in %q", inner)
	}
	ct, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	return parts[0], ct, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/BertSmith/personal/projects/pi.dev/agentkms && go test ./internal/kpm/ -run "TestNewSession|TestEncrypt|TestDecrypt" -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
cd /Users/BertSmith/personal/projects/pi.dev/agentkms
git add internal/kpm/encrypt.go internal/kpm/encrypt_test.go
git commit -m "feat(kpm): AES-256-GCM local encrypt/decrypt for --secure mode"
```

---

## Task 11: UDS Decrypt Listener

**Files:**
- Create: `internal/kpm/listener.go`
- Create: `internal/kpm/listener_test.go`

Unix domain socket listener for JIT decrypt. Language-agnostic: any process that connects to the socket can request decryption.

- [ ] **Step 1: Write the failing test**

Create `internal/kpm/listener_test.go`:

```go
package kpm

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDecryptListener(t *testing.T) {
	sk, err := NewSessionKey()
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroBytes(sk)

	// Encrypt a test value.
	ct, err := EncryptLocal(sk, []byte("my-secret"))
	if err != nil {
		t.Fatal(err)
	}
	blob := FormatCiphertextBlob("test-session", ct)

	// Start listener.
	sockPath := filepath.Join(t.TempDir(), "kpm-test.sock")
	dl := &DecryptListener{
		SocketPath: sockPath,
		SessionKey: sk,
		SessionID:  "test-session",
		ExpiresAt:  time.Now().Add(5 * time.Minute),
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- dl.Serve()
	}()

	// Wait for socket.
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(sockPath); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Connect and decrypt.
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}

	req := DecryptRequest{Ciphertext: blob}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatal(err)
	}

	var resp DecryptResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	conn.Close()

	if resp.Error != "" {
		t.Fatalf("decrypt error: %s", resp.Error)
	}
	if resp.Plaintext != "my-secret" {
		t.Errorf("plaintext = %q, want my-secret", resp.Plaintext)
	}

	// Shutdown.
	dl.Close()
}

func TestDecryptListenerExpired(t *testing.T) {
	sk, _ := NewSessionKey()
	defer ZeroBytes(sk)

	ct, _ := EncryptLocal(sk, []byte("test"))
	blob := FormatCiphertextBlob("sess", ct)

	sockPath := filepath.Join(t.TempDir(), "kpm-expired.sock")
	dl := &DecryptListener{
		SocketPath: sockPath,
		SessionKey: sk,
		SessionID:  "sess",
		ExpiresAt:  time.Now().Add(-1 * time.Minute), // already expired
	}

	go dl.Serve()
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(sockPath); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	json.NewEncoder(conn).Encode(DecryptRequest{Ciphertext: blob})

	var resp DecryptResponse
	json.NewDecoder(conn).Decode(&resp)
	conn.Close()
	dl.Close()

	if resp.Error == "" {
		t.Error("expected error for expired session")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/BertSmith/personal/projects/pi.dev/agentkms && go test ./internal/kpm/ -run TestDecryptListener -v`
Expected: FAIL — types not defined.

- [ ] **Step 3: Write minimal implementation**

Create `internal/kpm/listener.go`:

```go
package kpm

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

// DecryptRequest is the JSON request sent to the UDS listener.
type DecryptRequest struct {
	Ciphertext string `json:"ciphertext"` // ENC[kpm:sid:base64] blob
}

// DecryptResponse is the JSON response from the UDS listener.
type DecryptResponse struct {
	Plaintext string `json:"plaintext,omitempty"` // SECURITY: held briefly
	Error     string `json:"error,omitempty"`
}

// DecryptListener serves JIT decrypt requests over a Unix domain socket.
type DecryptListener struct {
	SocketPath string
	SessionKey []byte    // SECURITY: lives only in this process
	SessionID  string
	ExpiresAt  time.Time

	listener net.Listener
	mu       sync.Mutex
	closed   bool
}

// Serve starts the UDS listener. Blocks until Close() is called.
func (dl *DecryptListener) Serve() error {
	// Remove stale socket.
	os.Remove(dl.SocketPath)

	ln, err := net.Listen("unix", dl.SocketPath)
	if err != nil {
		return fmt.Errorf("listen %s: %w", dl.SocketPath, err)
	}

	// Restrict permissions: owner only.
	if err := os.Chmod(dl.SocketPath, 0600); err != nil {
		ln.Close()
		return fmt.Errorf("chmod socket: %w", err)
	}

	dl.mu.Lock()
	dl.listener = ln
	dl.mu.Unlock()

	for {
		conn, err := ln.Accept()
		if err != nil {
			dl.mu.Lock()
			wasClosed := dl.closed
			dl.mu.Unlock()
			if wasClosed {
				return nil
			}
			continue
		}
		go dl.handleConn(conn)
	}
}

func (dl *DecryptListener) handleConn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	var req DecryptRequest
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		json.NewEncoder(conn).Encode(DecryptResponse{Error: "invalid request"})
		return
	}

	// Check session expiry.
	if time.Now().After(dl.ExpiresAt) {
		json.NewEncoder(conn).Encode(DecryptResponse{Error: "session expired"})
		return
	}

	// Parse blob.
	sid, ct, err := ParseCiphertextBlob(req.Ciphertext)
	if err != nil {
		json.NewEncoder(conn).Encode(DecryptResponse{Error: "invalid ciphertext format"})
		return
	}
	if sid != dl.SessionID {
		json.NewEncoder(conn).Encode(DecryptResponse{Error: "session ID mismatch"})
		return
	}

	// Decrypt.
	plain, err := DecryptLocal(dl.SessionKey, ct)
	if err != nil {
		json.NewEncoder(conn).Encode(DecryptResponse{Error: "decrypt failed"})
		return
	}
	defer ZeroBytes(plain)

	json.NewEncoder(conn).Encode(DecryptResponse{Plaintext: string(plain)})
}

// Close stops the listener and removes the socket file.
func (dl *DecryptListener) Close() {
	dl.mu.Lock()
	dl.closed = true
	if dl.listener != nil {
		dl.listener.Close()
	}
	dl.mu.Unlock()
	os.Remove(dl.SocketPath)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/BertSmith/personal/projects/pi.dev/agentkms && go test ./internal/kpm/ -run TestDecryptListener -v -timeout 30s`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
cd /Users/BertSmith/personal/projects/pi.dev/agentkms
git add internal/kpm/listener.go internal/kpm/listener_test.go
git commit -m "feat(kpm): UDS decrypt listener for --secure JIT mode"
```

---

## Task 12: Wire --secure Mode into CLI

**Files:**
- Modify: `cmd/kpm/main.go`

Integrate session key generation, ciphertext injection, and UDS listener into `kpm run --secure` and `kpm export --secure`.

- [ ] **Step 1: Add secure export path to runExport**

In `cmd/kpm/main.go`, replace the `runExport` function with a version that checks the `--secure` flag and encrypts values before output:

```go
func runExport(ctx context.Context, cfg *kpm.Config, tmplPath, format string, secure bool, verbose bool) {
	f, err := os.Open(tmplPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening template %s: %v\n", tmplPath, err)
		os.Exit(1)
	}
	defer f.Close()

	entries, err := kpm.ParseTemplate(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing template: %v\n", err)
		os.Exit(1)
	}

	client := buildClient(cfg)
	resolved, err := kpm.Resolve(ctx, client, entries)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error resolving secrets: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		for i := range resolved {
			kpm.ZeroBytes(resolved[i].PlainValue)
		}
	}()

	kmsCount := 0
	for _, e := range resolved {
		if e.IsKMSRef {
			kmsCount++
		}
	}

	if secure {
		// Generate session key and encrypt all KMS values.
		sk, err := kpm.NewSessionKey()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error generating session key: %v\n", err)
			os.Exit(1)
		}
		defer kpm.ZeroBytes(sk)

		sessionID := fmt.Sprintf("s%x", sk[:4]) // short ID from key prefix
		for i := range resolved {
			if !resolved[i].IsKMSRef {
				continue
			}
			ct, err := kpm.EncryptLocal(sk, resolved[i].PlainValue)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error encrypting %s: %v\n", resolved[i].EnvKey, err)
				os.Exit(1)
			}
			kpm.ZeroBytes(resolved[i].PlainValue)
			resolved[i].PlainValue = []byte(kpm.FormatCiphertextBlob(sessionID, ct))
		}

		if verbose {
			fmt.Fprintf(os.Stderr, "✓ Resolved %d secrets from AgentKMS\n", kmsCount)
			fmt.Fprintf(os.Stderr, "✓ Encrypted values (AES-256-GCM, session: %s)\n", sessionID)
		}
	} else if verbose {
		fmt.Fprintf(os.Stderr, "✓ Resolved %d secrets from AgentKMS\n", kmsCount)
	}

	switch strings.ToLower(format) {
	case "dotenv":
		if secure {
			// No warning — values are encrypted.
			for _, e := range resolved {
				fmt.Fprintf(os.Stdout, "%s=%s\n", e.EnvKey, e.PlainValue)
			}
		} else {
			err = kpm.FormatDotenv(os.Stdout, resolved)
		}
	case "shell":
		err = kpm.FormatShell(os.Stdout, resolved)
	case "json":
		err = kpm.FormatJSON(os.Stdout, resolved)
	default:
		fmt.Fprintf(os.Stderr, "unknown format: %s\n", format)
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error writing output: %v\n", err)
		os.Exit(1)
	}
}
```

- [ ] **Step 2: Add secure run path with UDS listener to runRun**

In `cmd/kpm/main.go`, replace `runRun` with:

```go
func runRun(ctx context.Context, cfg *kpm.Config, tmplPath string, cmdArgs []string, secure, secureStrict, verbose bool) {
	f, err := os.Open(tmplPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening template %s: %v\n", tmplPath, err)
		os.Exit(1)
	}
	defer f.Close()

	entries, err := kpm.ParseTemplate(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing template: %v\n", err)
		os.Exit(1)
	}

	client := buildClient(cfg)
	resolved, err := kpm.Resolve(ctx, client, entries)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error resolving secrets: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		for i := range resolved {
			kpm.ZeroBytes(resolved[i].PlainValue)
		}
	}()

	kmsCount := 0
	for _, e := range resolved {
		if e.IsKMSRef {
			kmsCount++
		}
	}

	if secure || secureStrict {
		sk, err := kpm.NewSessionKey()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		defer kpm.ZeroBytes(sk)

		sessionID := fmt.Sprintf("s%x", sk[:4])
		ttl := time.Duration(cfg.SessionKeyTTL) * time.Second

		// Encrypt all KMS-resolved values.
		for i := range resolved {
			if !resolved[i].IsKMSRef {
				continue
			}
			ct, err := kpm.EncryptLocal(sk, resolved[i].PlainValue)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error encrypting %s: %v\n", resolved[i].EnvKey, err)
				os.Exit(1)
			}
			kpm.ZeroBytes(resolved[i].PlainValue)
			resolved[i].PlainValue = []byte(kpm.FormatCiphertextBlob(sessionID, ct))
		}

		// Start UDS listener.
		sockPath := filepath.Join(os.TempDir(), fmt.Sprintf("kpm-%s.sock", sessionID))
		dl := &kpm.DecryptListener{
			SocketPath: sockPath,
			SessionKey: sk,
			SessionID:  sessionID,
			ExpiresAt:  time.Now().Add(ttl),
		}
		defer dl.Close()

		go func() {
			if err := dl.Serve(); err != nil {
				fmt.Fprintf(os.Stderr, "listener error: %v\n", err)
			}
		}()

		// Wait briefly for socket.
		for i := 0; i < 50; i++ {
			if _, statErr := os.Stat(sockPath); statErr == nil {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}

		// Add socket path to resolved entries.
		resolved = append(resolved, kpm.ResolvedEntry{
			EnvKey:     "KPM_DECRYPT_SOCK",
			PlainValue: []byte(sockPath),
		})

		if verbose {
			fmt.Fprintf(os.Stderr, "✓ Resolved %d secrets from AgentKMS\n", kmsCount)
			fmt.Fprintf(os.Stderr, "✓ Session key acquired (TTL: %ds)\n", cfg.SessionKeyTTL)
			fmt.Fprintf(os.Stderr, "✓ Encrypting values (AES-256-GCM)\n")
			fmt.Fprintf(os.Stderr, "✓ Decrypt listener started (socket: %s)\n", sockPath)
		}
	} else if verbose {
		fmt.Fprintf(os.Stderr, "✓ Resolved %d secrets from AgentKMS\n", kmsCount)
		fmt.Fprintf(os.Stderr, "✓ Injecting plaintext env vars\n")
	}

	exitCode, err := kpm.RunCommand(ctx, resolved, cmdArgs[0], cmdArgs[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	os.Exit(exitCode)
}
```

- [ ] **Step 3: Update the switch/case to pass secure flags**

In `main()`, update the `export` and `run` cases to read and pass the secure flags:

```go
	// Change these lines at the top of main():
	secureFlag := fs.Bool("secure", false, "enable ciphertext injection mode")
	secureStrictFlag := fs.Bool("secure-strict", false, "enable strict ciphertext mode")

	// ... in the switch:
	case "export":
		// ...
		runExport(ctx, cfg, tmplPath, *outputFlag, *secureFlag, *verbose)

	case "run":
		// ...
		runRun(ctx, cfg, tmplPath, cmdArgs, *secureFlag, *secureStrictFlag, *verbose)
```

- [ ] **Step 4: Add missing imports**

Add `"path/filepath"` and `"time"` to the import block in `cmd/kpm/main.go`.

- [ ] **Step 5: Verify it compiles**

Run: `cd /Users/BertSmith/personal/projects/pi.dev/agentkms && go build ./cmd/kpm/`
Expected: builds successfully.

- [ ] **Step 6: Commit**

```bash
cd /Users/BertSmith/personal/projects/pi.dev/agentkms
git add cmd/kpm/main.go
git commit -m "feat(kpm): wire --secure and --secure-strict modes into CLI"
```

---

## Task 13: kpm decrypt Command

**Files:**
- Modify: `cmd/kpm/main.go`

Add the `decrypt` subcommand that reads a ciphertext blob and returns plaintext via the UDS listener.

- [ ] **Step 1: Add decrypt subcommand to main()**

Add `"decrypt"` to the switch case list and implement `runDecrypt`:

```go
// In the switch for valid subcommands:
case "export", "run", "get", "init", "decrypt":

// In the command dispatch switch:
case "decrypt":
    args := fs.Args()
    var blob string
    envVar := fs.Lookup("env")
    if envVar != nil && envVar.Value.String() != "" {
        blob = os.Getenv(envVar.Value.String())
    } else if len(args) > 0 {
        blob = args[0]
    } else {
        fmt.Fprintln(os.Stderr, "kpm decrypt: provide a ciphertext blob or --env VAR_NAME")
        os.Exit(1)
    }
    runDecrypt(blob)
```

Add the `--env` flag to the flag set:

```go
envFlag := fs.String("env", "", "read ciphertext from this env var name")
```

Implement `runDecrypt`:

```go
func runDecrypt(blob string) {
	sockPath := os.Getenv("KPM_DECRYPT_SOCK")
	if sockPath == "" {
		fmt.Fprintln(os.Stderr, "error: KPM_DECRYPT_SOCK not set (not running under kpm run --secure?)")
		os.Exit(1)
	}

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error connecting to decrypt socket: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	req := struct {
		Ciphertext string `json:"ciphertext"`
	}{Ciphertext: blob}

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		fmt.Fprintf(os.Stderr, "error sending request: %v\n", err)
		os.Exit(1)
	}

	var resp struct {
		Plaintext string `json:"plaintext"`
		Error     string `json:"error"`
	}
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		fmt.Fprintf(os.Stderr, "error reading response: %v\n", err)
		os.Exit(1)
	}

	if resp.Error != "" {
		fmt.Fprintf(os.Stderr, "decrypt error: %s\n", resp.Error)
		os.Exit(1)
	}

	fmt.Print(resp.Plaintext)
}
```

Add `"encoding/json"` and `"net"` to imports.

- [ ] **Step 2: Verify it compiles**

Run: `cd /Users/BertSmith/personal/projects/pi.dev/agentkms && go build ./cmd/kpm/`
Expected: builds successfully.

- [ ] **Step 3: Commit**

```bash
cd /Users/BertSmith/personal/projects/pi.dev/agentkms
git add cmd/kpm/main.go
git commit -m "feat(kpm): add decrypt subcommand for JIT secret retrieval"
```

---

## Milestone: Weekend MVP Complete

At this point you have:

1. **`kpm export --from .env.template`** — plaintext .env replacement (Demo 1)
2. **`kpm export --from .env.template --secure`** — ciphertext output (Demo 2)
3. **`kpm run -- myapp`** — plaintext injection (Demo 1)
4. **`kpm run --secure -- myapp`** — ciphertext + UDS listener (Demo 2)
5. **`kpm get kv/db/prod#password`** — quick single-secret fetch
6. **`kpm decrypt`** — JIT decrypt via UDS socket
7. **`kpm init`** — first-time config setup

This is sufficient for both planned videos:
- Video 1: "Your .env Files Are a Liability" (Demos 1 + 2)
- Video 2: "SSH Keys Don't Belong on Your Laptop" (Demo 4 using `kpm get`)

---

## Post-Weekend Tasks (Not Detailed Here)

These build on the foundation above and follow the same patterns:

- **`--secure-strict` mode**: Modify `listener.go` to proxy decrypt requests through the AgentKMS `/decrypt` endpoint instead of using a local session key. Add `StrictMode bool` and `Client *Client` fields to `DecryptListener`.
- **Cache layer**: Add `internal/kpm/cache.go` with `go-keyring` integration. `go get github.com/zalando/go-keyring`. Implement `CacheBackend` interface. Wire into resolver as fallback when AgentKMS is unreachable.
- **`kpm cache list|clear`**: Add subcommands to main.go.
- **`kpm store`/`kpm list` legacy compat**: Local keychain operations without AgentKMS.
- **UDS credential checking**: Add `golang.org/x/sys/unix` for UID validation in listener.
- **`cache_policy` server addition**: ~15 lines in `internal/api/credentials.go` to add the field to `genericCredentialResponse`.
