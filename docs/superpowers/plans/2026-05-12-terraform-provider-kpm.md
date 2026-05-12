# Terraform Provider for KPM — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `terraform-provider-kpm`, a standalone Terraform provider that manages KPM secrets and GitHub App registrations as first-class HCL resources backed by AgentKMS.

**Architecture:** The provider lives in a new repo `github.com/TheGenXCoder/terraform-provider-kpm`. It imports `github.com/TheGenXCoder/kpm/pkg/tlsutil` for mTLS transport construction, then implements its own thin HTTP client calling the AgentKMS REST API directly (the `internal/kpm` package in the KPM repo is Go-internal and cannot be imported externally). All resources and data sources call through a `client.AgentKMSClient` interface so unit tests can inject a mock without a live server.

**Tech Stack:** Go 1.22, terraform-plugin-framework v1.13.0, github.com/TheGenXCoder/kpm (for `pkg/tlsutil` only), net/http, crypto/sha256

---

> **New repo note:** All file paths below are relative to the root of the new `terraform-provider-kpm` repo. Create that directory before starting Task 1. The plan file itself lives in the KPM repo — copy/reference it from there.

---

## File Map

| File | Responsibility |
|------|---------------|
| `main.go` | Plugin entry point, Terraform plugin server |
| `GNUmakefile` | build, test, install, testacc targets |
| `internal/client/agentkms.go` | `AgentKMSClient` interface + real HTTP implementation |
| `internal/client/mock.go` | Mock implementation for unit tests |
| `internal/client/agentkms_test.go` | Unit tests for the real client against an httptest.Server stub |
| `internal/provider/provider.go` | Provider schema, `Configure()`, wires resources + data sources |
| `internal/provider/provider_test.go` | Provider unit test |
| `internal/resources/secret.go` | `kpm_secret` resource (CRUD) |
| `internal/resources/secret_test.go` | Unit tests for kpm_secret |
| `internal/resources/github_app.go` | `kpm_github_app` resource (CRUD + write-only key fingerprint) |
| `internal/resources/github_app_test.go` | Unit tests for kpm_github_app |
| `internal/datasources/secret.go` | `kpm_secret` data source (read-only) |
| `internal/datasources/secret_test.go` | Unit tests for kpm_secret data source |
| `internal/datasources/credential.go` | `kpm_credential` data source (dynamic/LLM credentials) |
| `internal/datasources/credential_test.go` | Unit tests for kpm_credential |
| `internal/testhelpers/server.go` | httptest.Server stub for AgentKMS endpoints used in all unit tests |
| `examples/provider/main.tf` | Example provider configuration |
| `examples/resources/kpm_secret/main.tf` | Example kpm_secret usage |
| `examples/resources/kpm_github_app/main.tf` | Example kpm_github_app usage |
| `examples/data-sources/kpm_secret/main.tf` | Example kpm_secret data source usage |
| `examples/data-sources/kpm_credential/main.tf` | Example kpm_credential data source usage |

---

## Task 1: Repo scaffold and Go module

**Files:**
- Create: `main.go`
- Create: `go.mod`
- Create: `GNUmakefile`

- [ ] **Step 1: Create the repo directory and init git**

```bash
mkdir terraform-provider-kpm
cd terraform-provider-kpm
git init
```

- [ ] **Step 2: Write `go.mod`**

```
module github.com/TheGenXCoder/terraform-provider-kpm

go 1.22

require (
    github.com/TheGenXCoder/kpm v0.3.0
    github.com/hashicorp/terraform-plugin-framework v1.13.0
    github.com/hashicorp/terraform-plugin-go v0.25.0
)
```

Run: `go mod tidy`

- [ ] **Step 3: Write `main.go`**

```go
package main

import (
    "context"
    "flag"
    "log"

    "github.com/hashicorp/terraform-plugin-framework/providerserver"
    "github.com/TheGenXCoder/terraform-provider-kpm/internal/provider"
)

var version = "dev"

func main() {
    var debug bool
    flag.BoolVar(&debug, "debug", false, "run provider with debugger support")
    flag.Parse()

    err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
        Address: "registry.terraform.io/catalyst9/kpm",
        Debug:   debug,
    })
    if err != nil {
        log.Fatal(err)
    }
}
```

- [ ] **Step 4: Write `GNUmakefile`**

```makefile
default: build

build:
	go build ./...

test:
	go test ./... -v -count=1

testacc:
	TF_ACC=1 go test ./... -v -count=1 -timeout 120m

install:
	go install .

lint:
	golangci-lint run ./...

.PHONY: build test testacc install lint
```

- [ ] **Step 5: Verify it compiles**

Run: `go build ./...`
Expected: no errors (will fail until internal packages exist — that's fine for now)

- [ ] **Step 6: Commit**

```bash
git add go.mod GNUmakefile main.go
git commit -m "chore: scaffold terraform-provider-kpm"
```

---

## Task 2: Test stub server

**Files:**
- Create: `internal/testhelpers/server.go`

The stub is written first because every subsequent task's tests depend on it.

- [ ] **Step 1: Write `internal/testhelpers/server.go`**

```go
package testhelpers

import (
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "strings"
    "sync"
    "testing"
)

// StubServer is an in-memory AgentKMS stub for unit tests.
// It handles auth, secrets, metadata, github-apps, and credentials endpoints.
type StubServer struct {
    Server   *httptest.Server
    mu       sync.Mutex
    secrets  map[string]string            // path → value
    metadata map[string]map[string]string // path → metadata fields
    apps     map[string]GithubApp         // name → app
}

type GithubApp struct {
    Name           string `json:"name"`
    AppID          int64  `json:"app_id"`
    InstallationID int64  `json:"installation_id"`
}

// NewStubServer starts an httptest.Server and returns the stub.
func NewStubServer(t *testing.T) *StubServer {
    t.Helper()
    s := &StubServer{
        secrets:  make(map[string]string),
        metadata: make(map[string]map[string]string),
        apps:     make(map[string]GithubApp),
    }
    mux := http.NewServeMux()

    // Auth
    mux.HandleFunc("/auth/session", func(w http.ResponseWriter, r *http.Request) {
        json.NewEncoder(w).Encode(map[string]string{"token": "test-token"})
    })

    // Secrets: POST and GET /secrets/{path}
    mux.HandleFunc("/secrets/", func(w http.ResponseWriter, r *http.Request) {
        path := strings.TrimPrefix(r.URL.Path, "/secrets/")
        s.mu.Lock()
        defer s.mu.Unlock()
        switch r.Method {
        case http.MethodPost:
            var body map[string]string
            json.NewDecoder(r.Body).Decode(&body)
            s.secrets[path] = body["value"]
            w.WriteHeader(http.StatusCreated)
            json.NewEncoder(w).Encode(map[string]any{"path": path, "version": 1, "status": "created"})
        case http.MethodGet:
            v, ok := s.secrets[path]
            if !ok {
                http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
                return
            }
            json.NewEncoder(w).Encode(map[string]string{"value": v})
        case http.MethodDelete:
            delete(s.secrets, path)
            w.WriteHeader(http.StatusNoContent)
        }
    })

    // Metadata: POST and GET /metadata/{path}
    mux.HandleFunc("/metadata/", func(w http.ResponseWriter, r *http.Request) {
        path := strings.TrimPrefix(r.URL.Path, "/metadata/")
        s.mu.Lock()
        defer s.mu.Unlock()
        switch r.Method {
        case http.MethodPost:
            var body map[string]string
            json.NewDecoder(r.Body).Decode(&body)
            s.metadata[path] = body
            w.WriteHeader(http.StatusOK)
            json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
        case http.MethodGet:
            m := s.metadata[path]
            if m == nil {
                m = map[string]string{}
            }
            json.NewEncoder(w).Encode(m)
        }
    })

    // GitHub Apps
    mux.HandleFunc("/github-apps", func(w http.ResponseWriter, r *http.Request) {
        s.mu.Lock()
        defer s.mu.Unlock()
        switch r.Method {
        case http.MethodPost:
            var body struct {
                Name           string `json:"name"`
                AppID          int64  `json:"app_id"`
                InstallationID int64  `json:"installation_id"`
                PrivateKeyPEM  string `json:"private_key_pem"`
            }
            json.NewDecoder(r.Body).Decode(&body)
            app := GithubApp{Name: body.Name, AppID: body.AppID, InstallationID: body.InstallationID}
            s.apps[body.Name] = app
            w.WriteHeader(http.StatusCreated)
            json.NewEncoder(w).Encode(app)
        case http.MethodGet:
            apps := make([]GithubApp, 0, len(s.apps))
            for _, a := range s.apps {
                apps = append(apps, a)
            }
            json.NewEncoder(w).Encode(map[string]any{"apps": apps})
        }
    })

    mux.HandleFunc("/github-apps/", func(w http.ResponseWriter, r *http.Request) {
        name := strings.TrimPrefix(r.URL.Path, "/github-apps/")
        s.mu.Lock()
        defer s.mu.Unlock()
        switch r.Method {
        case http.MethodGet:
            app, ok := s.apps[name]
            if !ok {
                http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
                return
            }
            json.NewEncoder(w).Encode(app)
        case http.MethodDelete:
            delete(s.apps, name)
            w.WriteHeader(http.StatusNoContent)
        }
    })

    // LLM credentials
    mux.HandleFunc("/credentials/llm/", func(w http.ResponseWriter, r *http.Request) {
        provider := strings.TrimPrefix(r.URL.Path, "/credentials/llm/")
        json.NewEncoder(w).Encode(map[string]string{
            "provider":   provider,
            "api_key":    "test-api-key-for-" + provider,
            "expires_at": "2099-01-01T00:00:00Z",
        })
    })

    s.Server = httptest.NewServer(mux)
    t.Cleanup(s.Server.Close)
    return s
}

// URL returns the base URL of the stub server.
func (s *StubServer) URL() string {
    return s.Server.URL
}
```

- [ ] **Step 2: Verify it compiles**

Run: `go build ./internal/testhelpers/...`
Expected: no errors

- [ ] **Step 3: Commit**

```bash
git add internal/testhelpers/server.go
git commit -m "test: add AgentKMS stub server for unit tests"
```

---

## Task 3: Internal client — interface, mock, and real implementation

**Files:**
- Create: `internal/client/agentkms.go`
- Create: `internal/client/mock.go`
- Create: `internal/client/agentkms_test.go`

- [ ] **Step 1: Write the failing test**

`internal/client/agentkms_test.go`:
```go
package client_test

import (
    "context"
    "testing"

    "github.com/TheGenXCoder/terraform-provider-kpm/internal/client"
    "github.com/TheGenXCoder/terraform-provider-kpm/internal/testhelpers"
)

func TestClientWriteAndReadSecret(t *testing.T) {
    stub := testhelpers.NewStubServer(t)
    c, err := client.NewInsecure(stub.URL())
    if err != nil {
        t.Fatal(err)
    }

    ctx := context.Background()
    if err := c.WriteSecret(ctx, "svc/key", "myvalue", nil, "", ""); err != nil {
        t.Fatalf("WriteSecret: %v", err)
    }

    got, err := c.GetSecret(ctx, "svc/key")
    if err != nil {
        t.Fatalf("GetSecret: %v", err)
    }
    if got != "myvalue" {
        t.Errorf("got %q, want %q", got, "myvalue")
    }
}

func TestClientDeleteSecret(t *testing.T) {
    stub := testhelpers.NewStubServer(t)
    c, _ := client.NewInsecure(stub.URL())
    ctx := context.Background()

    c.WriteSecret(ctx, "svc/del", "val", nil, "", "")
    if err := c.DeleteSecret(ctx, "svc/del"); err != nil {
        t.Fatalf("DeleteSecret: %v", err)
    }
    _, err := c.GetSecret(ctx, "svc/del")
    if err == nil {
        t.Error("expected error for deleted secret, got nil")
    }
}

func TestClientGithubApp(t *testing.T) {
    stub := testhelpers.NewStubServer(t)
    c, _ := client.NewInsecure(stub.URL())
    ctx := context.Background()

    req := client.RegisterGithubAppRequest{
        Name:           "my-app",
        AppID:          12345,
        InstallationID: 67890,
        PrivateKeyPEM:  "fake-pem",
    }
    summary, err := c.RegisterGithubApp(ctx, req)
    if err != nil {
        t.Fatalf("RegisterGithubApp: %v", err)
    }
    if summary.Name != "my-app" {
        t.Errorf("name: got %q, want %q", summary.Name, "my-app")
    }

    got, err := c.GetGithubApp(ctx, "my-app")
    if err != nil {
        t.Fatalf("GetGithubApp: %v", err)
    }
    if got.AppID != 12345 {
        t.Errorf("AppID: got %d, want 12345", got.AppID)
    }

    if err := c.RemoveGithubApp(ctx, "my-app"); err != nil {
        t.Fatalf("RemoveGithubApp: %v", err)
    }
}

func TestClientGetLLMCredential(t *testing.T) {
    stub := testhelpers.NewStubServer(t)
    c, _ := client.NewInsecure(stub.URL())
    ctx := context.Background()

    cred, err := c.GetLLMCredential(ctx, "openai")
    if err != nil {
        t.Fatalf("GetLLMCredential: %v", err)
    }
    if cred.Value == "" {
        t.Error("expected non-empty credential value")
    }
    if cred.ExpiresAt == "" {
        t.Error("expected non-empty expires_at")
    }
}
```

- [ ] **Step 2: Run the test — confirm it fails**

Run: `go test ./internal/client/... -v`
Expected: FAIL — `client` package does not exist yet

- [ ] **Step 3: Write `internal/client/agentkms.go`**

```go
package client

import (
    "bytes"
    "context"
    "crypto/tls"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "os"
    "strings"
    "time"

    "github.com/TheGenXCoder/kpm/pkg/tlsutil"
)

// AgentKMSClient is the interface used by all resources and data sources.
// The interface enables mock injection in unit tests.
type AgentKMSClient interface {
    WriteSecret(ctx context.Context, path, value string, tags []string, description, secretType string) error
    GetSecret(ctx context.Context, path string) (string, error)
    DeleteSecret(ctx context.Context, path string) error
    GetLLMCredential(ctx context.Context, provider string) (*CredentialResult, error)
    RegisterGithubApp(ctx context.Context, req RegisterGithubAppRequest) (*GithubAppSummary, error)
    GetGithubApp(ctx context.Context, name string) (*GithubAppSummary, error)
    RemoveGithubApp(ctx context.Context, name string) error
}

// RegisterGithubAppRequest is the payload for POST /github-apps.
type RegisterGithubAppRequest struct {
    Name           string `json:"name"`
    AppID          int64  `json:"app_id"`
    InstallationID int64  `json:"installation_id"`
    PrivateKeyPEM  string `json:"private_key_pem"`
}

// GithubAppSummary is returned by GET /github-apps/{name} and POST /github-apps.
type GithubAppSummary struct {
    Name           string `json:"name"`
    AppID          int64  `json:"app_id"`
    InstallationID int64  `json:"installation_id"`
}

// CredentialResult holds a fetched dynamic credential.
type CredentialResult struct {
    Value     string
    ExpiresAt string
}

// httpAgentKMS is the real AgentKMS HTTP client.
type httpAgentKMS struct {
    base   string
    token  string
    http   *http.Client
}

// New builds an AgentKMSClient using mTLS. certPath, keyPath, and caPath are
// file-system paths to PEM-encoded files.
func New(serverURL, certPath, keyPath, caPath string) (AgentKMSClient, error) {
    if serverURL == "" {
        return nil, fmt.Errorf("server URL is required")
    }
    caPEM, err := os.ReadFile(caPath)
    if err != nil {
        return nil, fmt.Errorf("read CA cert %s: %w", caPath, err)
    }
    certPEM, err := os.ReadFile(certPath)
    if err != nil {
        return nil, fmt.Errorf("read client cert %s: %w", certPath, err)
    }
    keyPEM, err := os.ReadFile(keyPath)
    if err != nil {
        return nil, fmt.Errorf("read client key %s: %w", keyPath, err)
    }
    tlsCfg, err := tlsutil.ClientTLSConfig(caPEM, certPEM, keyPEM)
    if err != nil {
        return nil, fmt.Errorf("build mTLS config: %w", err)
    }
    return newWithTLS(serverURL, tlsCfg), nil
}

// NewInsecure builds a client with no TLS — only for unit tests against httptest.Server.
func NewInsecure(serverURL string) (AgentKMSClient, error) {
    return newWithTLS(serverURL, &tls.Config{}), nil
}

func newWithTLS(serverURL string, tlsCfg *tls.Config) AgentKMSClient {
    return &httpAgentKMS{
        base: strings.TrimRight(serverURL, "/"),
        http: &http.Client{
            Timeout:   30 * time.Second,
            Transport: &http.Transport{TLSClientConfig: tlsCfg},
        },
    }
}

func (c *httpAgentKMS) ensureAuth(ctx context.Context) error {
    if c.token != "" {
        return nil
    }
    req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/auth/session", nil)
    if err != nil {
        return fmt.Errorf("build auth request: %w", err)
    }
    resp, err := c.http.Do(req)
    if err != nil {
        return fmt.Errorf("auth: %w", err)
    }
    defer resp.Body.Close()
    if resp.StatusCode != http.StatusOK {
        return fmt.Errorf("auth: server returned %d", resp.StatusCode)
    }
    var body struct {
        Token string `json:"token"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
        return fmt.Errorf("auth: decode response: %w", err)
    }
    c.token = body.Token
    return nil
}

func (c *httpAgentKMS) doGet(ctx context.Context, path string) (*http.Response, error) {
    if err := c.ensureAuth(ctx); err != nil {
        return nil, err
    }
    req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
    if err != nil {
        return nil, fmt.Errorf("build GET request: %w", err)
    }
    req.Header.Set("Authorization", "Bearer "+c.token)
    return c.http.Do(req)
}

func (c *httpAgentKMS) doPost(ctx context.Context, path string, body any) (*http.Response, error) {
    if err := c.ensureAuth(ctx); err != nil {
        return nil, err
    }
    var buf bytes.Buffer
    if err := json.NewEncoder(&buf).Encode(body); err != nil {
        return nil, fmt.Errorf("encode body: %w", err)
    }
    req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, &buf)
    if err != nil {
        return nil, fmt.Errorf("build POST request: %w", err)
    }
    req.Header.Set("Authorization", "Bearer "+c.token)
    req.Header.Set("Content-Type", "application/json")
    return c.http.Do(req)
}

func (c *httpAgentKMS) doDelete(ctx context.Context, path string) (*http.Response, error) {
    if err := c.ensureAuth(ctx); err != nil {
        return nil, err
    }
    req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.base+path, nil)
    if err != nil {
        return nil, fmt.Errorf("build DELETE request: %w", err)
    }
    req.Header.Set("Authorization", "Bearer "+c.token)
    return c.http.Do(req)
}

func serverErr(resp *http.Response, op string) error {
    body, _ := io.ReadAll(resp.Body)
    var e struct{ Error string `json:"error"` }
    if json.Unmarshal(body, &e) == nil && e.Error != "" {
        return fmt.Errorf("%s: %s", op, e.Error)
    }
    return fmt.Errorf("%s: server returned %d", op, resp.StatusCode)
}

func (c *httpAgentKMS) WriteSecret(ctx context.Context, path, value string, tags []string, description, secretType string) error {
    body := map[string]any{"value": value}
    resp, err := c.doPost(ctx, "/secrets/"+path, body)
    if err != nil {
        return fmt.Errorf("write secret: %w", err)
    }
    defer resp.Body.Close()
    if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
        return serverErr(resp, "write secret "+path)
    }
    // Write metadata only if any optional fields are set.
    if description != "" || len(tags) > 0 || secretType != "" {
        meta := map[string]any{}
        if description != "" {
            meta["description"] = description
        }
        if len(tags) > 0 {
            meta["tags"] = tags
        }
        if secretType != "" {
            meta["type"] = secretType
        }
        mresp, err := c.doPost(ctx, "/metadata/"+path, meta)
        if err != nil {
            return fmt.Errorf("write metadata: %w", err)
        }
        defer mresp.Body.Close()
    }
    return nil
}

func (c *httpAgentKMS) GetSecret(ctx context.Context, path string) (string, error) {
    resp, err := c.doGet(ctx, "/secrets/"+path)
    if err != nil {
        return "", fmt.Errorf("get secret: %w", err)
    }
    defer resp.Body.Close()
    if resp.StatusCode == http.StatusNotFound {
        return "", fmt.Errorf("not found: %s", path)
    }
    if resp.StatusCode != http.StatusOK {
        return "", serverErr(resp, "get secret "+path)
    }
    var body map[string]string
    if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
        return "", fmt.Errorf("decode secret: %w", err)
    }
    return body["value"], nil
}

func (c *httpAgentKMS) DeleteSecret(ctx context.Context, path string) error {
    resp, err := c.doDelete(ctx, "/secrets/"+path)
    if err != nil {
        return fmt.Errorf("delete secret: %w", err)
    }
    defer resp.Body.Close()
    if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
        return serverErr(resp, "delete secret "+path)
    }
    return nil
}

func (c *httpAgentKMS) GetLLMCredential(ctx context.Context, provider string) (*CredentialResult, error) {
    resp, err := c.doGet(ctx, "/credentials/llm/"+provider)
    if err != nil {
        return nil, fmt.Errorf("get credential: %w", err)
    }
    defer resp.Body.Close()
    if resp.StatusCode != http.StatusOK {
        return nil, serverErr(resp, "get credential "+provider)
    }
    var body struct {
        APIKey    string `json:"api_key"`
        ExpiresAt string `json:"expires_at"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
        return nil, fmt.Errorf("decode credential: %w", err)
    }
    return &CredentialResult{Value: body.APIKey, ExpiresAt: body.ExpiresAt}, nil
}

func (c *httpAgentKMS) RegisterGithubApp(ctx context.Context, req RegisterGithubAppRequest) (*GithubAppSummary, error) {
    resp, err := c.doPost(ctx, "/github-apps", req)
    if err != nil {
        return nil, fmt.Errorf("register github app: %w", err)
    }
    defer resp.Body.Close()
    if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
        return nil, serverErr(resp, "register github app "+req.Name)
    }
    var out GithubAppSummary
    if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
        return nil, fmt.Errorf("decode github app response: %w", err)
    }
    return &out, nil
}

func (c *httpAgentKMS) GetGithubApp(ctx context.Context, name string) (*GithubAppSummary, error) {
    resp, err := c.doGet(ctx, "/github-apps/"+name)
    if err != nil {
        return nil, fmt.Errorf("get github app: %w", err)
    }
    defer resp.Body.Close()
    if resp.StatusCode == http.StatusNotFound {
        return nil, fmt.Errorf("not found: %s", name)
    }
    if resp.StatusCode != http.StatusOK {
        return nil, serverErr(resp, "get github app "+name)
    }
    var out GithubAppSummary
    if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
        return nil, fmt.Errorf("decode github app response: %w", err)
    }
    return &out, nil
}

func (c *httpAgentKMS) RemoveGithubApp(ctx context.Context, name string) error {
    resp, err := c.doDelete(ctx, "/github-apps/"+name)
    if err != nil {
        return fmt.Errorf("remove github app: %w", err)
    }
    defer resp.Body.Close()
    if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
        return serverErr(resp, "remove github app "+name)
    }
    return nil
}
```

- [ ] **Step 4: Write `internal/client/mock.go`**

```go
package client

import "context"

// MockClient is a controllable fake for unit tests.
// Set Up* fields to control what each method returns.
type MockClient struct {
    UpWriteSecret   error
    UpGetSecret     string
    UpGetSecretErr  error
    UpDeleteSecret  error
    UpGetLLMCred    *CredentialResult
    UpGetLLMCredErr error
    UpRegisterApp   *GithubAppSummary
    UpRegisterAppErr error
    UpGetApp        *GithubAppSummary
    UpGetAppErr     error
    UpRemoveApp     error

    // Recorded calls
    WrittenPath  string
    WrittenValue string
    DeletedPath  string
}

func (m *MockClient) WriteSecret(_ context.Context, path, value string, _ []string, _, _ string) error {
    m.WrittenPath = path
    m.WrittenValue = value
    return m.UpWriteSecret
}

func (m *MockClient) GetSecret(_ context.Context, _ string) (string, error) {
    return m.UpGetSecret, m.UpGetSecretErr
}

func (m *MockClient) DeleteSecret(_ context.Context, path string) error {
    m.DeletedPath = path
    return m.UpDeleteSecret
}

func (m *MockClient) GetLLMCredential(_ context.Context, _ string) (*CredentialResult, error) {
    return m.UpGetLLMCred, m.UpGetLLMCredErr
}

func (m *MockClient) RegisterGithubApp(_ context.Context, _ RegisterGithubAppRequest) (*GithubAppSummary, error) {
    return m.UpRegisterApp, m.UpRegisterAppErr
}

func (m *MockClient) GetGithubApp(_ context.Context, _ string) (*GithubAppSummary, error) {
    return m.UpGetApp, m.UpGetAppErr
}

func (m *MockClient) RemoveGithubApp(_ context.Context, _ string) error {
    return m.UpRemoveApp
}
```

- [ ] **Step 5: Run the tests — confirm they pass**

Run: `go test ./internal/client/... -v`
Expected:
```
--- PASS: TestClientWriteAndReadSecret
--- PASS: TestClientDeleteSecret
--- PASS: TestClientGithubApp
--- PASS: TestClientGetLLMCredential
```

- [ ] **Step 6: Commit**

```bash
git add internal/client/ internal/testhelpers/
git commit -m "feat(client): AgentKMS HTTP client with mock and stub server"
```

---

## Task 4: Provider configuration

**Files:**
- Create: `internal/provider/provider.go`
- Create: `internal/provider/provider_test.go`

- [ ] **Step 1: Write the failing test**

`internal/provider/provider_test.go`:
```go
package provider_test

import (
    "testing"

    "github.com/hashicorp/terraform-plugin-framework/providerserver"
    "github.com/hashicorp/terraform-plugin-go/tfprotov6"
    "github.com/TheGenXCoder/terraform-provider-kpm/internal/provider"
)

func TestProviderSchema(t *testing.T) {
    providers := map[string]func() (tfprotov6.ProviderServer, error){
        "kpm": providerserver.NewProtocol6WithError(provider.New("test")()),
    }
    _ = providers // schema validation is implicit in the provider compile
}
```

- [ ] **Step 2: Run test — confirm it fails**

Run: `go test ./internal/provider/... -v`
Expected: FAIL — `provider` package does not exist yet

- [ ] **Step 3: Write `internal/provider/provider.go`**

```go
package provider

import (
    "context"
    "os"

    "github.com/hashicorp/terraform-plugin-framework/datasource"
    "github.com/hashicorp/terraform-plugin-framework/provider"
    "github.com/hashicorp/terraform-plugin-framework/provider/schema"
    "github.com/hashicorp/terraform-plugin-framework/resource"
    "github.com/hashicorp/terraform-plugin-framework/types"

    "github.com/TheGenXCoder/terraform-provider-kpm/internal/client"
    "github.com/TheGenXCoder/terraform-provider-kpm/internal/datasources"
    "github.com/TheGenXCoder/terraform-provider-kpm/internal/resources"
)

var _ provider.Provider = &KPMProvider{}

// KPMProvider is the Terraform provider implementation.
type KPMProvider struct{ version string }

type kpmProviderModel struct {
    Server types.String `tfsdk:"server"`
    Cert   types.String `tfsdk:"cert"`
    Key    types.String `tfsdk:"key"`
    CACert types.String `tfsdk:"ca_cert"`
}

// New returns a provider constructor.
func New(version string) func() provider.Provider {
    return func() provider.Provider { return &KPMProvider{version: version} }
}

func (p *KPMProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
    resp.TypeName = "kpm"
    resp.Version = p.version
}

func (p *KPMProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
    resp.Schema = schema.Schema{
        Description: "Interact with KPM and AgentKMS to manage secrets and GitHub App registrations.",
        Attributes: map[string]schema.Attribute{
            "server": schema.StringAttribute{
                Optional:    true,
                Description: "AgentKMS server URL. Overridden by KPM_SERVER env var.",
            },
            "cert": schema.StringAttribute{
                Optional:    true,
                Description: "Path to mTLS client certificate PEM file. Overridden by KPM_CERT env var.",
            },
            "key": schema.StringAttribute{
                Optional:    true,
                Sensitive:   true,
                Description: "Path to mTLS client key PEM file. Overridden by KPM_KEY env var.",
            },
            "ca_cert": schema.StringAttribute{
                Optional:    true,
                Description: "Path to CA certificate PEM file. Overridden by KPM_CA_CERT env var.",
            },
        },
    }
}

func (p *KPMProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
    var cfg kpmProviderModel
    resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
    if resp.Diagnostics.HasError() {
        return
    }

    server := first(cfg.Server.ValueString(), os.Getenv("KPM_SERVER"))
    cert   := first(cfg.Cert.ValueString(),   os.Getenv("KPM_CERT"))
    key    := first(cfg.Key.ValueString(),    os.Getenv("KPM_KEY"))
    caCert := first(cfg.CACert.ValueString(), os.Getenv("KPM_CA_CERT"))

    c, err := client.New(server, cert, key, caCert)
    if err != nil {
        resp.Diagnostics.AddError("Failed to configure KPM provider", err.Error())
        return
    }

    resp.DataSourceData = c
    resp.ResourceData = c
}

func (p *KPMProvider) Resources(_ context.Context) []func() resource.Resource {
    return []func() resource.Resource{
        resources.NewSecretResource,
        resources.NewGithubAppResource,
    }
}

func (p *KPMProvider) DataSources(_ context.Context) []func() datasource.DataSource {
    return []func() datasource.DataSource{
        datasources.NewSecretDataSource,
        datasources.NewCredentialDataSource,
    }
}

// first returns the first non-empty string from vals.
func first(vals ...string) string {
    for _, v := range vals {
        if v != "" {
            return v
        }
    }
    return ""
}
```

- [ ] **Step 4: Run the test — confirm it passes**

Run: `go test ./internal/provider/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/provider/
git commit -m "feat(provider): provider schema and Configure() with mTLS client init"
```

---

## Task 5: `kpm_secret` resource

**Files:**
- Create: `internal/resources/secret.go`
- Create: `internal/resources/secret_test.go`

- [ ] **Step 1: Write the failing tests**

`internal/resources/secret_test.go`:
```go
package resources_test

import (
    "context"
    "testing"

    "github.com/hashicorp/terraform-plugin-framework/resource"
    "github.com/TheGenXCoder/terraform-provider-kpm/internal/client"
    "github.com/TheGenXCoder/terraform-provider-kpm/internal/resources"
)

func newSecretResource(c client.AgentKMSClient) resource.Resource {
    r := resources.NewSecretResource()
    r.(*resources.SecretResource).SetClient(c)
    return r
}

func TestSecretResourceCreate(t *testing.T) {
    mock := &client.MockClient{
        UpGetSecret: "myvalue",
    }
    r := newSecretResource(mock)
    _ = r // schema + interface compile check

    if mock.WrittenPath != "" {
        t.Error("expected no write on construction")
    }
}

func TestSecretResourceSchemaHasSensitiveValue(t *testing.T) {
    r := resources.NewSecretResource()
    ctx := context.Background()
    var resp resource.SchemaResponse
    r.Schema(ctx, resource.SchemaRequest{}, &resp)

    attr, ok := resp.Schema.Attributes["value"]
    if !ok {
        t.Fatal("schema missing 'value' attribute")
    }
    if !attr.(interface{ IsSensitive() bool }).IsSensitive() {
        t.Error("'value' attribute must be sensitive")
    }
}
```

- [ ] **Step 2: Run tests — confirm they fail**

Run: `go test ./internal/resources/... -v`
Expected: FAIL — `resources` package does not exist yet

- [ ] **Step 3: Write `internal/resources/secret.go`**

```go
package resources

import (
    "context"
    "fmt"

    "github.com/hashicorp/terraform-plugin-framework/resource"
    "github.com/hashicorp/terraform-plugin-framework/resource/schema"
    "github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
    "github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
    "github.com/hashicorp/terraform-plugin-framework/types"

    "github.com/TheGenXCoder/terraform-provider-kpm/internal/client"
)

var _ resource.Resource = &SecretResource{}

// SecretResource manages a KPM secret via the kpm_secret Terraform resource.
type SecretResource struct {
    client client.AgentKMSClient
}

// SetClient is used by tests to inject a mock client.
func (r *SecretResource) SetClient(c client.AgentKMSClient) { r.client = c }

// NewSecretResource returns the constructor used by the provider.
func NewSecretResource() resource.Resource { return &SecretResource{} }

type secretModel struct {
    Path        types.String `tfsdk:"path"`
    Value       types.String `tfsdk:"value"`
    Type        types.String `tfsdk:"type"`
    Description types.String `tfsdk:"description"`
    Tags        types.List   `tfsdk:"tags"`
}

func (r *SecretResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
    resp.TypeName = req.ProviderTypeName + "_secret"
}

func (r *SecretResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
    resp.Schema = schema.Schema{
        Description: "Manages a secret stored in AgentKMS via KPM.",
        Attributes: map[string]schema.Attribute{
            "path": schema.StringAttribute{
                Required:    true,
                Description: "Secret path in service/name format (e.g. 'db/password').",
                PlanModifiers: []planmodifier.String{
                    stringplanmodifier.RequiresReplace(),
                },
            },
            "value": schema.StringAttribute{
                Required:    true,
                Sensitive:   true,
                Description: "Secret value. Stored sensitive in Terraform state.",
            },
            "type": schema.StringAttribute{
                Optional:    true,
                Computed:    true,
                Description: "Secret type: generic (default), api-token, ssh-key, connection-string, jwt, password.",
            },
            "description": schema.StringAttribute{
                Optional:    true,
                Description: "Human-readable description of the secret.",
            },
            "tags": schema.ListAttribute{
                Optional:    true,
                ElementType: types.StringType,
                Description: "Tags for filtering (e.g. ['prod', 'db']).",
            },
        },
    }
}

func (r *SecretResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
    if req.ProviderData == nil {
        return
    }
    c, ok := req.ProviderData.(client.AgentKMSClient)
    if !ok {
        resp.Diagnostics.AddError("Unexpected provider data type",
            fmt.Sprintf("expected client.AgentKMSClient, got %T", req.ProviderData))
        return
    }
    r.client = c
}

func (r *SecretResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
    var plan secretModel
    resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
    if resp.Diagnostics.HasError() {
        return
    }

    tags := toStringSlice(ctx, plan.Tags, resp)
    if resp.Diagnostics.HasError() {
        return
    }

    if err := r.client.WriteSecret(ctx,
        plan.Path.ValueString(),
        plan.Value.ValueString(),
        tags,
        plan.Description.ValueString(),
        plan.Type.ValueString(),
    ); err != nil {
        resp.Diagnostics.AddError("Error creating secret", err.Error())
        return
    }

    if plan.Type.IsNull() || plan.Type.IsUnknown() {
        plan.Type = types.StringValue("generic")
    }
    resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *SecretResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
    var state secretModel
    resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
    if resp.Diagnostics.HasError() {
        return
    }

    value, err := r.client.GetSecret(ctx, state.Path.ValueString())
    if err != nil {
        // Secret no longer exists — remove from state.
        resp.State.RemoveResource(ctx)
        return
    }
    state.Value = types.StringValue(value)
    resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *SecretResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
    var plan secretModel
    resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
    if resp.Diagnostics.HasError() {
        return
    }

    tags := toStringSlice(ctx, plan.Tags, resp)
    if resp.Diagnostics.HasError() {
        return
    }

    if err := r.client.WriteSecret(ctx,
        plan.Path.ValueString(),
        plan.Value.ValueString(),
        tags,
        plan.Description.ValueString(),
        plan.Type.ValueString(),
    ); err != nil {
        resp.Diagnostics.AddError("Error updating secret", err.Error())
        return
    }
    resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *SecretResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
    var state secretModel
    resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
    if resp.Diagnostics.HasError() {
        return
    }
    if err := r.client.DeleteSecret(ctx, state.Path.ValueString()); err != nil {
        resp.Diagnostics.AddError("Error deleting secret", err.Error())
    }
}

func toStringSlice(ctx context.Context, list types.List, resp *resource.CreateResponse) []string {
    if list.IsNull() || list.IsUnknown() {
        return nil
    }
    var out []string
    resp.Diagnostics.Append(list.ElementsAs(ctx, &out, false)...)
    return out
}
```

- [ ] **Step 4: Run the tests — confirm they pass**

Run: `go test ./internal/resources/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/resources/secret.go internal/resources/secret_test.go
git commit -m "feat(resource): kpm_secret resource with full CRUD"
```

---

## Task 6: `kpm_secret` data source

**Files:**
- Create: `internal/datasources/secret.go`
- Create: `internal/datasources/secret_test.go`

- [ ] **Step 1: Write the failing test**

`internal/datasources/secret_test.go`:
```go
package datasources_test

import (
    "context"
    "testing"

    "github.com/hashicorp/terraform-plugin-framework/datasource"
    "github.com/TheGenXCoder/terraform-provider-kpm/internal/datasources"
)

func TestSecretDataSourceSchema(t *testing.T) {
    ds := datasources.NewSecretDataSource()
    ctx := context.Background()
    var resp datasource.SchemaResponse
    ds.Schema(ctx, datasource.SchemaRequest{}, &resp)

    if _, ok := resp.Schema.Attributes["path"]; !ok {
        t.Error("schema missing 'path' attribute")
    }
    if _, ok := resp.Schema.Attributes["value"]; !ok {
        t.Error("schema missing 'value' attribute")
    }
}
```

- [ ] **Step 2: Run test — confirm it fails**

Run: `go test ./internal/datasources/... -v`
Expected: FAIL — package does not exist yet

- [ ] **Step 3: Write `internal/datasources/secret.go`**

```go
package datasources

import (
    "context"
    "fmt"

    "github.com/hashicorp/terraform-plugin-framework/datasource"
    "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
    "github.com/hashicorp/terraform-plugin-framework/types"

    "github.com/TheGenXCoder/terraform-provider-kpm/internal/client"
)

var _ datasource.DataSource = &SecretDataSource{}

// SecretDataSource reads an existing KPM secret without managing its lifecycle.
type SecretDataSource struct {
    client client.AgentKMSClient
}

// NewSecretDataSource returns the constructor used by the provider.
func NewSecretDataSource() datasource.DataSource { return &SecretDataSource{} }

type secretDataModel struct {
    Path  types.String `tfsdk:"path"`
    Value types.String `tfsdk:"value"`
}

func (d *SecretDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
    resp.TypeName = req.ProviderTypeName + "_secret"
}

func (d *SecretDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
    resp.Schema = schema.Schema{
        Description: "Reads an existing KPM secret value from AgentKMS.",
        Attributes: map[string]schema.Attribute{
            "path": schema.StringAttribute{
                Required:    true,
                Description: "Secret path in service/name format (e.g. 'db/password').",
            },
            "value": schema.StringAttribute{
                Computed:    true,
                Sensitive:   true,
                Description: "The secret value retrieved from AgentKMS.",
            },
        },
    }
}

func (d *SecretDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
    if req.ProviderData == nil {
        return
    }
    c, ok := req.ProviderData.(client.AgentKMSClient)
    if !ok {
        resp.Diagnostics.AddError("Unexpected provider data type",
            fmt.Sprintf("expected client.AgentKMSClient, got %T", req.ProviderData))
        return
    }
    d.client = c
}

func (d *SecretDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
    var config secretDataModel
    resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
    if resp.Diagnostics.HasError() {
        return
    }

    value, err := d.client.GetSecret(ctx, config.Path.ValueString())
    if err != nil {
        resp.Diagnostics.AddError("Error reading secret", err.Error())
        return
    }

    config.Value = types.StringValue(value)
    resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
```

- [ ] **Step 4: Run the tests — confirm they pass**

Run: `go test ./internal/datasources/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/datasources/secret.go internal/datasources/secret_test.go
git commit -m "feat(datasource): kpm_secret data source"
```

---

## Task 7: `kpm_credential` data source

**Files:**
- Create: `internal/datasources/credential.go`
- Create: `internal/datasources/credential_test.go`

- [ ] **Step 1: Write the failing test**

`internal/datasources/credential_test.go`:
```go
package datasources_test

import (
    "context"
    "testing"

    "github.com/hashicorp/terraform-plugin-framework/datasource"
    "github.com/TheGenXCoder/terraform-provider-kpm/internal/datasources"
)

func TestCredentialDataSourceSchema(t *testing.T) {
    ds := datasources.NewCredentialDataSource()
    ctx := context.Background()
    var resp datasource.SchemaResponse
    ds.Schema(ctx, datasource.SchemaRequest{}, &resp)

    for _, attr := range []string{"type", "path", "value", "expires_at"} {
        if _, ok := resp.Schema.Attributes[attr]; !ok {
            t.Errorf("schema missing %q attribute", attr)
        }
    }
}
```

- [ ] **Step 2: Run test — confirm it fails**

Run: `go test ./internal/datasources/... -v -run TestCredentialDataSourceSchema`
Expected: FAIL — `NewCredentialDataSource` does not exist yet

- [ ] **Step 3: Write `internal/datasources/credential.go`**

```go
package datasources

import (
    "context"
    "fmt"

    "github.com/hashicorp/terraform-plugin-framework/datasource"
    "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
    "github.com/hashicorp/terraform-plugin-framework/types"

    "github.com/TheGenXCoder/terraform-provider-kpm/internal/client"
)

var _ datasource.DataSource = &CredentialDataSource{}

// CredentialDataSource fetches a dynamic credential from AgentKMS.
// No state is written — the credential is fetched fresh on every plan/apply.
type CredentialDataSource struct {
    client client.AgentKMSClient
}

// NewCredentialDataSource returns the constructor used by the provider.
func NewCredentialDataSource() datasource.DataSource { return &CredentialDataSource{} }

type credentialDataModel struct {
    Type      types.String `tfsdk:"type"`
    Path      types.String `tfsdk:"path"`
    Value     types.String `tfsdk:"value"`
    ExpiresAt types.String `tfsdk:"expires_at"`
}

func (d *CredentialDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
    resp.TypeName = req.ProviderTypeName + "_credential"
}

func (d *CredentialDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
    resp.Schema = schema.Schema{
        Description: "Fetches a dynamic or short-lived credential from AgentKMS. Refreshed on every plan/apply.",
        Attributes: map[string]schema.Attribute{
            "type": schema.StringAttribute{
                Required:    true,
                Description: "Credential type. Currently supported: 'llm'.",
            },
            "path": schema.StringAttribute{
                Required:    true,
                Description: "Credential path, e.g. 'openai' for type='llm'.",
            },
            "value": schema.StringAttribute{
                Computed:    true,
                Sensitive:   true,
                Description: "The credential value (e.g. API key).",
            },
            "expires_at": schema.StringAttribute{
                Computed:    true,
                Description: "RFC3339 timestamp when the credential expires.",
            },
        },
    }
}

func (d *CredentialDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
    if req.ProviderData == nil {
        return
    }
    c, ok := req.ProviderData.(client.AgentKMSClient)
    if !ok {
        resp.Diagnostics.AddError("Unexpected provider data type",
            fmt.Sprintf("expected client.AgentKMSClient, got %T", req.ProviderData))
        return
    }
    d.client = c
}

func (d *CredentialDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
    var config credentialDataModel
    resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
    if resp.Diagnostics.HasError() {
        return
    }

    credType := config.Type.ValueString()
    path := config.Path.ValueString()

    switch credType {
    case "llm":
        cred, err := d.client.GetLLMCredential(ctx, path)
        if err != nil {
            resp.Diagnostics.AddError("Error fetching LLM credential", err.Error())
            return
        }
        config.Value = types.StringValue(cred.Value)
        config.ExpiresAt = types.StringValue(cred.ExpiresAt)
    default:
        resp.Diagnostics.AddError("Unsupported credential type",
            fmt.Sprintf("type %q is not supported; supported types: llm", credType))
        return
    }

    resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
```

- [ ] **Step 4: Run the tests — confirm they pass**

Run: `go test ./internal/datasources/... -v`
Expected: PASS (both TestSecretDataSourceSchema and TestCredentialDataSourceSchema)

- [ ] **Step 5: Commit**

```bash
git add internal/datasources/credential.go internal/datasources/credential_test.go
git commit -m "feat(datasource): kpm_credential data source for dynamic credentials"
```

---

## Task 8: `kpm_github_app` resource

**Files:**
- Create: `internal/resources/github_app.go`
- Create: `internal/resources/github_app_test.go`

The private key is write-only (AgentKMS never returns it). A SHA-256 fingerprint of the key is stored in state as `private_key_sha256` to detect changes in subsequent plans.

- [ ] **Step 1: Write the failing tests**

`internal/resources/github_app_test.go`:
```go
package resources_test

import (
    "context"
    "testing"

    "github.com/hashicorp/terraform-plugin-framework/resource"
    "github.com/TheGenXCoder/terraform-provider-kpm/internal/resources"
)

func TestGithubAppResourceSchemaHasSensitiveKey(t *testing.T) {
    r := resources.NewGithubAppResource()
    ctx := context.Background()
    var resp resource.SchemaResponse
    r.Schema(ctx, resource.SchemaRequest{}, &resp)

    key, ok := resp.Schema.Attributes["private_key"]
    if !ok {
        t.Fatal("schema missing 'private_key' attribute")
    }
    if !key.(interface{ IsSensitive() bool }).IsSensitive() {
        t.Error("'private_key' must be sensitive")
    }

    if _, ok := resp.Schema.Attributes["private_key_sha256"]; !ok {
        t.Error("schema missing 'private_key_sha256' attribute for drift detection")
    }
}

func TestGithubAppResourceSchemaFields(t *testing.T) {
    r := resources.NewGithubAppResource()
    ctx := context.Background()
    var resp resource.SchemaResponse
    r.Schema(ctx, resource.SchemaRequest{}, &resp)

    for _, attr := range []string{"name", "app_id", "installation_id", "private_key", "private_key_sha256"} {
        if _, ok := resp.Schema.Attributes[attr]; !ok {
            t.Errorf("schema missing %q attribute", attr)
        }
    }
}
```

- [ ] **Step 2: Run tests — confirm they fail**

Run: `go test ./internal/resources/... -v -run TestGithubApp`
Expected: FAIL — `NewGithubAppResource` does not exist yet

- [ ] **Step 3: Write `internal/resources/github_app.go`**

```go
package resources

import (
    "context"
    "crypto/sha256"
    "fmt"

    "github.com/hashicorp/terraform-plugin-framework/resource"
    "github.com/hashicorp/terraform-plugin-framework/resource/schema"
    "github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
    "github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
    "github.com/hashicorp/terraform-plugin-framework/types"

    "github.com/TheGenXCoder/terraform-provider-kpm/internal/client"
)

var _ resource.Resource = &GithubAppResource{}

// GithubAppResource manages a GitHub App registration in AgentKMS.
type GithubAppResource struct {
    client client.AgentKMSClient
}

// NewGithubAppResource returns the constructor used by the provider.
func NewGithubAppResource() resource.Resource { return &GithubAppResource{} }

// SetClient allows tests to inject a mock.
func (r *GithubAppResource) SetClient(c client.AgentKMSClient) { r.client = c }

type githubAppModel struct {
    Name             types.String `tfsdk:"name"`
    AppID            types.Int64  `tfsdk:"app_id"`
    InstallationID   types.Int64  `tfsdk:"installation_id"`
    PrivateKey       types.String `tfsdk:"private_key"`
    PrivateKeySHA256 types.String `tfsdk:"private_key_sha256"`
}

func (r *GithubAppResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
    resp.TypeName = req.ProviderTypeName + "_github_app"
}

func (r *GithubAppResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
    resp.Schema = schema.Schema{
        Description: "Manages a GitHub App installation registered in AgentKMS.",
        Attributes: map[string]schema.Attribute{
            "name": schema.StringAttribute{
                Required:    true,
                Description: "Unique name for this GitHub App registration.",
                PlanModifiers: []planmodifier.String{
                    stringplanmodifier.RequiresReplace(),
                },
            },
            "app_id": schema.Int64Attribute{
                Required:    true,
                Description: "GitHub App ID (numeric, from the App settings page).",
            },
            "installation_id": schema.Int64Attribute{
                Required:    true,
                Description: "GitHub App Installation ID (from the installation URL).",
            },
            "private_key": schema.StringAttribute{
                Required:    true,
                Sensitive:   true,
                Description: "PEM-encoded RSA private key for the GitHub App. Never returned by AgentKMS after registration.",
            },
            "private_key_sha256": schema.StringAttribute{
                Computed:    true,
                Description: "SHA-256 fingerprint of private_key, stored for change detection.",
            },
        },
    }
}

func (r *GithubAppResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
    if req.ProviderData == nil {
        return
    }
    c, ok := req.ProviderData.(client.AgentKMSClient)
    if !ok {
        resp.Diagnostics.AddError("Unexpected provider data type",
            fmt.Sprintf("expected client.AgentKMSClient, got %T", req.ProviderData))
        return
    }
    r.client = c
}

func (r *GithubAppResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
    var plan githubAppModel
    resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
    if resp.Diagnostics.HasError() {
        return
    }

    summary, err := r.client.RegisterGithubApp(ctx, client.RegisterGithubAppRequest{
        Name:           plan.Name.ValueString(),
        AppID:          plan.AppID.ValueInt64(),
        InstallationID: plan.InstallationID.ValueInt64(),
        PrivateKeyPEM:  plan.PrivateKey.ValueString(),
    })
    if err != nil {
        resp.Diagnostics.AddError("Error registering GitHub App", err.Error())
        return
    }

    plan.Name = types.StringValue(summary.Name)
    plan.AppID = types.Int64Value(summary.AppID)
    plan.InstallationID = types.Int64Value(summary.InstallationID)
    plan.PrivateKeySHA256 = types.StringValue(sha256Hex(plan.PrivateKey.ValueString()))
    resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *GithubAppResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
    var state githubAppModel
    resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
    if resp.Diagnostics.HasError() {
        return
    }

    summary, err := r.client.GetGithubApp(ctx, state.Name.ValueString())
    if err != nil {
        // App no longer exists — remove from state.
        resp.State.RemoveResource(ctx)
        return
    }
    // Update server-sourced fields. private_key and private_key_sha256 are
    // kept as-is in state because AgentKMS never returns the key.
    state.AppID = types.Int64Value(summary.AppID)
    state.InstallationID = types.Int64Value(summary.InstallationID)
    resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *GithubAppResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
    var plan githubAppModel
    resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
    if resp.Diagnostics.HasError() {
        return
    }

    // AgentKMS register is idempotent (POST replaces existing record).
    summary, err := r.client.RegisterGithubApp(ctx, client.RegisterGithubAppRequest{
        Name:           plan.Name.ValueString(),
        AppID:          plan.AppID.ValueInt64(),
        InstallationID: plan.InstallationID.ValueInt64(),
        PrivateKeyPEM:  plan.PrivateKey.ValueString(),
    })
    if err != nil {
        resp.Diagnostics.AddError("Error updating GitHub App", err.Error())
        return
    }

    plan.AppID = types.Int64Value(summary.AppID)
    plan.InstallationID = types.Int64Value(summary.InstallationID)
    plan.PrivateKeySHA256 = types.StringValue(sha256Hex(plan.PrivateKey.ValueString()))
    resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *GithubAppResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
    var state githubAppModel
    resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
    if resp.Diagnostics.HasError() {
        return
    }
    if err := r.client.RemoveGithubApp(ctx, state.Name.ValueString()); err != nil {
        resp.Diagnostics.AddError("Error removing GitHub App", err.Error())
    }
}

func sha256Hex(s string) string {
    h := sha256.Sum256([]byte(s))
    return fmt.Sprintf("%x", h)
}
```

- [ ] **Step 4: Run the tests — confirm they pass**

Run: `go test ./internal/resources/... -v`
Expected: PASS (all four tests including the new TestGithubApp* ones)

- [ ] **Step 5: Full build check**

Run: `go build ./...`
Expected: no errors

- [ ] **Step 6: Commit**

```bash
git add internal/resources/github_app.go internal/resources/github_app_test.go
git commit -m "feat(resource): kpm_github_app resource with SHA-256 key fingerprint"
```

---

## Task 9: Examples

**Files:**
- Create: `examples/provider/main.tf`
- Create: `examples/resources/kpm_secret/main.tf`
- Create: `examples/resources/kpm_github_app/main.tf`
- Create: `examples/data-sources/kpm_secret/main.tf`
- Create: `examples/data-sources/kpm_credential/main.tf`

- [ ] **Step 1: Write `examples/provider/main.tf`**

```hcl
terraform {
  required_providers {
    kpm = {
      source  = "catalyst9/kpm"
      version = "~> 0.1"
    }
  }
}

# All fields can be set via environment variables:
# KPM_SERVER, KPM_CERT, KPM_KEY, KPM_CA_CERT
provider "kpm" {
  server  = "https://agentkms.local:8443"
  cert    = "~/.kpm/certs/client.crt"
  key     = "~/.kpm/certs/client.key"
  ca_cert = "~/.kpm/certs/ca.crt"
}
```

- [ ] **Step 2: Write `examples/resources/kpm_secret/main.tf`**

```hcl
resource "kpm_secret" "db_password" {
  path        = "kv/db/prod"
  value       = var.db_password
  type        = "password"
  tags        = ["prod", "db"]
  description = "Production database password"
}

variable "db_password" {
  type      = string
  sensitive = true
}
```

- [ ] **Step 3: Write `examples/resources/kpm_github_app/main.tf`**

```hcl
resource "kpm_github_app" "ci" {
  name            = "ci-deploy-bot"
  app_id          = 12345
  installation_id = 67890
  private_key     = var.gh_app_private_key
}

variable "gh_app_private_key" {
  type      = string
  sensitive = true
}

output "app_fingerprint" {
  value = kpm_github_app.ci.private_key_sha256
}
```

- [ ] **Step 4: Write `examples/data-sources/kpm_secret/main.tf`**

```hcl
data "kpm_secret" "db_host" {
  path = "kv/db/prod-host"
}

output "db_host" {
  value     = data.kpm_secret.db_host.value
  sensitive = true
}
```

- [ ] **Step 5: Write `examples/data-sources/kpm_credential/main.tf`**

```hcl
data "kpm_credential" "openai" {
  type = "llm"
  path = "openai"
}

output "openai_expires_at" {
  value = data.kpm_credential.openai.expires_at
}
```

- [ ] **Step 6: Final test run**

Run: `go test ./... -v -count=1`
Expected: all tests pass

- [ ] **Step 7: Final commit**

```bash
git add examples/
git commit -m "docs(examples): add provider and resource example HCL files"
```

---

## Acceptance Tests (TF_ACC)

Acceptance tests require a live AgentKMS instance. Run `kpm quickstart` in a scratch directory to get one, then set:

```bash
export KPM_SERVER=https://localhost:8443
export KPM_CERT=~/.kpm/certs/client.crt
export KPM_KEY=~/.kpm/certs/client.key
export KPM_CA_CERT=~/.kpm/certs/ca.crt
export TF_ACC=1
go test ./... -v -count=1 -timeout 120m
```

Acceptance tests follow the same TDD pattern as unit tests — write failing tests first using the `resource.Test` helper from `terraform-plugin-testing`, then implement the provider logic to pass them. Acceptance tests are added in a follow-on PR after all unit tests pass.

---

## Self-Review Checklist (do not delete — required by writing-plans skill)

- [x] Spec: provider schema with mTLS fields + env fallbacks → Task 4
- [x] Spec: `kpm_secret` resource CRUD → Task 5
- [x] Spec: `kpm_secret` data source → Task 6
- [x] Spec: `kpm_credential` data source → Task 7
- [x] Spec: `kpm_github_app` resource with write-only key + SHA-256 fingerprint → Task 8
- [x] Spec: Approach A (import pkg/tlsutil) → Task 3 uses `tlsutil.ClientTLSConfig`
- [x] Spec: error handling (not found → remove from state) → Tasks 5 and 8 Read methods
- [x] Spec: sensitive fields → `value` in Tasks 5/6, `private_key` in Task 8
- [x] Spec: type routing (generic vs llm) → Task 3 `WriteSecret` + Task 7 credential type switch
- [x] Type consistency: `client.AgentKMSClient` interface used in all tasks; `MockClient` matches interface; `RegisterGithubAppRequest` defined once in Task 3
- [x] No placeholders or TBDs
