package kpm

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
)

// stdinWith replaces os.Stdin with a pipe fed with the given content for the duration of f.
// It restores os.Stdin after f returns.
func stdinWith(t *testing.T, content string, f func()) {
	t.Helper()
	origStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = r
	w.WriteString(content)
	w.Close()
	defer func() {
		os.Stdin = origStdin
		r.Close()
	}()
	f()
}

// mockServerForAdd builds a server that handles: auth, GetMetadata, WriteSecret, WriteMetadata.
func mockServerForAdd(t *testing.T, existingMeta *SecretMetadata) (*http.Client, string) {
	t.Helper()
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		// GetMetadata
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/metadata/") {
			if existingMeta != nil {
				json.NewEncoder(w).Encode(existingMeta)
			} else {
				http.Error(w, "not found", 404)
			}
			return
		}
		// WriteSecret
		if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/secrets/") {
			json.NewEncoder(w).Encode(WriteResult{Path: r.URL.Path[9:], Version: 1, Status: "created"})
			return
		}
		// WriteMetadata
		if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/metadata/") {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Error(w, "not found", 404)
	})
	return srv.Client(), srv.URL
}

// === RunAdd tests ===

func TestRunAddMissingPath(t *testing.T) {
	var buf bytes.Buffer
	err := RunAdd(context.Background(), &buf, &Client{}, AddOptions{Path: ""})
	if err == nil || !strings.Contains(err.Error(), "path required") {
		t.Errorf("expected 'path required' error, got: %v", err)
	}
}

func TestRunAddNoSlashInPath(t *testing.T) {
	var buf bytes.Buffer
	err := RunAdd(context.Background(), &buf, &Client{}, AddOptions{Path: "noslash"})
	if err == nil || !strings.Contains(err.Error(), "service/name") {
		t.Errorf("expected 'service/name' error, got: %v", err)
	}
}

func TestRunAddEmptyValue(t *testing.T) {
	httpClient, baseURL := mockServerForAdd(t, nil)
	c := &Client{baseURL: baseURL, httpClient: httpClient}

	var buf bytes.Buffer
	// Provide empty value via stdin (non-terminal path)
	stdinWith(t, "\n", func() {
		err := RunAdd(context.Background(), &buf, c, AddOptions{Path: "cloudflare/token"})
		if err == nil || !strings.Contains(err.Error(), "empty value") {
			t.Errorf("expected 'empty value' error, got: %v", err)
		}
	})
}

func TestRunAddSuccessFromStdin(t *testing.T) {
	httpClient, baseURL := mockServerForAdd(t, nil)
	c := &Client{baseURL: baseURL, httpClient: httpClient}

	var buf bytes.Buffer
	stdinWith(t, "my-secret-value", func() {
		err := RunAdd(context.Background(), &buf, c, AddOptions{Path: "cloudflare/token"})
		if err != nil {
			t.Fatalf("RunAdd: %v", err)
		}
	})
	out := buf.String()
	if !strings.Contains(out, "cloudflare/token") {
		t.Errorf("output missing path: %s", out)
	}
	if !strings.Contains(out, "v1") {
		t.Errorf("output missing version: %s", out)
	}
}

func TestRunAddWithExplicitType(t *testing.T) {
	httpClient, baseURL := mockServerForAdd(t, nil)
	c := &Client{baseURL: baseURL, httpClient: httpClient}

	var buf bytes.Buffer
	stdinWith(t, "sk-openai-key-123", func() {
		err := RunAdd(context.Background(), &buf, c, AddOptions{
			Path: "openai/api-key",
			Type: "api-key",
		})
		if err != nil {
			t.Fatalf("RunAdd: %v", err)
		}
	})
	out := buf.String()
	if !strings.Contains(out, "api-key") {
		t.Errorf("output missing type: %s", out)
	}
}

func TestRunAddWithTags(t *testing.T) {
	httpClient, baseURL := mockServerForAdd(t, nil)
	c := &Client{baseURL: baseURL, httpClient: httpClient}

	var buf bytes.Buffer
	stdinWith(t, "my-secret-value", func() {
		err := RunAdd(context.Background(), &buf, c, AddOptions{
			Path: "github/pat",
			Tags: []string{"production", "ci"},
		})
		if err != nil {
			t.Fatalf("RunAdd: %v", err)
		}
	})
	out := buf.String()
	if !strings.Contains(out, "production") || !strings.Contains(out, "ci") {
		t.Errorf("output missing tags: %s", out)
	}
}

func TestRunAddFromFile(t *testing.T) {
	dir := t.TempDir()
	secretFile := dir + "/secret.txt"
	os.WriteFile(secretFile, []byte("file-secret-value"), 0600)

	httpClient, baseURL := mockServerForAdd(t, nil)
	c := &Client{baseURL: baseURL, httpClient: httpClient}

	var buf bytes.Buffer
	err := RunAdd(context.Background(), &buf, c, AddOptions{
		Path:     "myservice/cert",
		FromFile: secretFile,
	})
	if err != nil {
		t.Fatalf("RunAdd from file: %v", err)
	}
	if !strings.Contains(buf.String(), "myservice/cert") {
		t.Errorf("output missing path: %s", buf.String())
	}
}

func TestRunAddFromFileMissing(t *testing.T) {
	var buf bytes.Buffer
	c := &Client{baseURL: "http://localhost", httpClient: http.DefaultClient}
	err := RunAdd(context.Background(), &buf, c, AddOptions{
		Path:     "myservice/cert",
		FromFile: "/nonexistent/secret.txt",
	})
	if err == nil || !strings.Contains(err.Error(), "read file") {
		t.Errorf("expected 'read file' error, got: %v", err)
	}
}

func TestRunAddExistingConfirmedUpdate(t *testing.T) {
	existing := &SecretMetadata{Path: "cloudflare/token", Service: "cloudflare", Name: "token", Version: 2}
	httpClient, baseURL := mockServerForAdd(t, existing)
	c := &Client{baseURL: baseURL, httpClient: httpClient}

	// Write the value to a temp file to avoid the bufio stdin buffering issue:
	// bufio.NewReader reads ahead from the pipe for the confirmation prompt,
	// which then leaves nothing for io.ReadAll in the value-reading path.
	dir := t.TempDir()
	secretFile := dir + "/update-value.txt"
	os.WriteFile(secretFile, []byte("updated-secret-value"), 0600)

	var buf bytes.Buffer
	stdinWith(t, "y\n", func() {
		err := RunAdd(context.Background(), &buf, c, AddOptions{
			Path:     "cloudflare/token",
			FromFile: secretFile,
		})
		if err != nil {
			t.Fatalf("RunAdd confirmed update: %v", err)
		}
	})
	out := buf.String()
	if !strings.Contains(out, "cloudflare/token") {
		t.Errorf("output missing path: %s", out)
	}
}

func TestRunAddExistingCancelledUpdate(t *testing.T) {
	existing := &SecretMetadata{Path: "cloudflare/token", Service: "cloudflare", Name: "token", Version: 1}
	httpClient, baseURL := mockServerForAdd(t, existing)
	c := &Client{baseURL: baseURL, httpClient: httpClient}

	var buf bytes.Buffer
	stdinWith(t, "n\n", func() {
		err := RunAdd(context.Background(), &buf, c, AddOptions{Path: "cloudflare/token"})
		if err == nil || !strings.Contains(err.Error(), "cancelled") {
			t.Errorf("expected 'cancelled' error, got: %v", err)
		}
	})
}

// === RunList tests ===

func mockServerForList(t *testing.T, secrets []SecretMetadata) (*http.Client, string) {
	t.Helper()
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/metadata" {
			json.NewEncoder(w).Encode(map[string]any{"secrets": secrets})
			return
		}
		http.Error(w, "not found", 404)
	})
	return srv.Client(), srv.URL
}

func TestRunListEmpty(t *testing.T) {
	httpClient, baseURL := mockServerForList(t, []SecretMetadata{})
	c := &Client{baseURL: baseURL, httpClient: httpClient}

	var buf bytes.Buffer
	err := RunList(context.Background(), &buf, c, "", "", "", false, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No secrets found") {
		t.Errorf("expected 'No secrets found' message, got: %s", buf.String())
	}
}

func TestRunListFilterByService(t *testing.T) {
	secrets := []SecretMetadata{
		{Service: "cloudflare", Name: "token", Type: "api-token", Version: 1},
		{Service: "github", Name: "pat", Type: "api-token", Version: 1},
	}
	httpClient, baseURL := mockServerForList(t, secrets)
	c := &Client{baseURL: baseURL, httpClient: httpClient}

	var buf bytes.Buffer
	err := RunList(context.Background(), &buf, c, "cloudflare", "", "", false, false)
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "cloudflare") {
		t.Errorf("output missing cloudflare: %s", out)
	}
	if strings.Contains(out, "github") {
		t.Errorf("output should not contain github: %s", out)
	}
}

func TestRunListFilterByTag(t *testing.T) {
	secrets := []SecretMetadata{
		{Service: "cloudflare", Name: "token", Tags: []string{"production"}, Version: 1},
		{Service: "github", Name: "pat", Tags: []string{"ci"}, Version: 1},
	}
	httpClient, baseURL := mockServerForList(t, secrets)
	c := &Client{baseURL: baseURL, httpClient: httpClient}

	var buf bytes.Buffer
	err := RunList(context.Background(), &buf, c, "", "production", "", false, false)
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "cloudflare") {
		t.Errorf("expected cloudflare in output: %s", out)
	}
	if strings.Contains(out, "github") {
		t.Errorf("github should be filtered out: %s", out)
	}
}

func TestRunListFilterByType(t *testing.T) {
	secrets := []SecretMetadata{
		{Service: "cloudflare", Name: "token", Type: "api-token", Version: 1},
		{Service: "db", Name: "password", Type: "password", Version: 1},
	}
	httpClient, baseURL := mockServerForList(t, secrets)
	c := &Client{baseURL: baseURL, httpClient: httpClient}

	var buf bytes.Buffer
	err := RunList(context.Background(), &buf, c, "", "", "password", false, false)
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "db") {
		t.Errorf("expected db in output: %s", out)
	}
	if strings.Contains(out, "cloudflare") {
		t.Errorf("cloudflare should be filtered out: %s", out)
	}
}

func TestRunListJSONOutput(t *testing.T) {
	secrets := []SecretMetadata{
		{Service: "cloudflare", Name: "token", Type: "api-token", Version: 1},
	}
	httpClient, baseURL := mockServerForList(t, secrets)
	c := &Client{baseURL: baseURL, httpClient: httpClient}

	var buf bytes.Buffer
	err := RunList(context.Background(), &buf, c, "", "", "", false, true)
	if err != nil {
		t.Fatal(err)
	}
	// Should be valid JSON
	var result []SecretMetadata
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Errorf("JSON output invalid: %v\n%s", err, buf.String())
	}
}

func TestRunListNoMatchFilter(t *testing.T) {
	secrets := []SecretMetadata{
		{Service: "cloudflare", Name: "token", Type: "api-token", Version: 1},
	}
	httpClient, baseURL := mockServerForList(t, secrets)
	c := &Client{baseURL: baseURL, httpClient: httpClient}

	var buf bytes.Buffer
	err := RunList(context.Background(), &buf, c, "nonexistent", "", "", false, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No secrets match") {
		t.Errorf("expected 'No secrets match' message, got: %s", buf.String())
	}
}

func TestRunListIncludeDeleted(t *testing.T) {
	secrets := []SecretMetadata{
		{Service: "cloudflare", Name: "token", Type: "api-token", Version: 1},
		{Service: "oldservice", Name: "old-token", Type: "api-token", Version: 1, Deleted: true},
	}
	httpClient, baseURL := mockServerForList(t, secrets)
	c := &Client{baseURL: baseURL, httpClient: httpClient}

	var buf bytes.Buffer
	err := RunList(context.Background(), &buf, c, "", "", "", true, false)
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "DELETED") {
		t.Errorf("expected DELETED in output: %s", out)
	}
}

func TestRunListEmptyTagsAndDescription(t *testing.T) {
	// Test formatting edge cases: empty tags, empty description
	secrets := []SecretMetadata{
		{Service: "svc", Name: "key", Type: "", Tags: nil, Description: "", Version: 3},
	}
	httpClient, baseURL := mockServerForList(t, secrets)
	c := &Client{baseURL: baseURL, httpClient: httpClient}

	var buf bytes.Buffer
	err := RunList(context.Background(), &buf, c, "", "", "", false, false)
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "svc") {
		t.Errorf("expected svc in output: %s", out)
	}
	// Should show "generic" type for empty type
	if !strings.Contains(out, "generic") {
		t.Errorf("expected generic type for empty type: %s", out)
	}
}

func TestRunListLongDescription(t *testing.T) {
	// Descriptions >30 chars should be truncated
	secrets := []SecretMetadata{
		{Service: "svc", Name: "key", Type: "api-token",
			Description: "This is a very long description that exceeds thirty characters",
			Version:     1},
	}
	httpClient, baseURL := mockServerForList(t, secrets)
	c := &Client{baseURL: baseURL, httpClient: httpClient}

	var buf bytes.Buffer
	err := RunList(context.Background(), &buf, c, "", "", "", false, false)
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "...") {
		t.Errorf("expected truncation with '...' in output: %s", out)
	}
}

// === RunDescribe tests ===

func mockServerForDescribe(t *testing.T, meta *SecretMetadata) (*http.Client, string) {
	t.Helper()
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/metadata/") {
			if meta == nil {
				http.Error(w, "not found", 404)
				return
			}
			json.NewEncoder(w).Encode(meta)
			return
		}
		http.Error(w, "not found", 404)
	})
	return srv.Client(), srv.URL
}

func TestRunDescribeNotFound(t *testing.T) {
	httpClient, baseURL := mockServerForDescribe(t, nil)
	c := &Client{baseURL: baseURL, httpClient: httpClient}

	var buf bytes.Buffer
	err := RunDescribe(context.Background(), &buf, c, "nonexistent/path")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' error, got: %v", err)
	}
}

func TestRunDescribeShowsMetadata(t *testing.T) {
	meta := &SecretMetadata{
		Path:        "cloudflare/token",
		Service:     "cloudflare",
		Name:        "token",
		Type:        "api-token",
		Tags:        []string{"production", "dns"},
		Description: "Cloudflare DNS API token",
		Created:     "2026-01-01T00:00:00Z",
		Updated:     "2026-04-01T00:00:00Z",
		Version:     3,
	}
	httpClient, baseURL := mockServerForDescribe(t, meta)
	c := &Client{baseURL: baseURL, httpClient: httpClient}

	var buf bytes.Buffer
	err := RunDescribe(context.Background(), &buf, c, "cloudflare/token")
	if err != nil {
		t.Fatalf("RunDescribe: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "cloudflare") {
		t.Errorf("missing service in output: %s", out)
	}
	if !strings.Contains(out, "api-token") {
		t.Errorf("missing type in output: %s", out)
	}
	if !strings.Contains(out, "production") || !strings.Contains(out, "dns") {
		t.Errorf("missing tags in output: %s", out)
	}
	if !strings.Contains(out, "Cloudflare DNS API token") {
		t.Errorf("missing description in output: %s", out)
	}
	if !strings.Contains(out, "3") {
		t.Errorf("missing version in output: %s", out)
	}
}

func TestRunDescribeNeverShowsValue(t *testing.T) {
	meta := &SecretMetadata{
		Path:    "myservice/secret",
		Service: "myservice",
		Name:    "secret",
		Version: 1,
		Created: "2026-01-01T00:00:00Z",
		Updated: "2026-01-01T00:00:00Z",
	}
	httpClient, baseURL := mockServerForDescribe(t, meta)
	c := &Client{baseURL: baseURL, httpClient: httpClient}

	var buf bytes.Buffer
	err := RunDescribe(context.Background(), &buf, c, "myservice/secret")
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	// These strings should NOT appear in describe output (values, not metadata)
	for _, forbidden := range []string{"value", "plaintext", "sk-", "password"} {
		if strings.Contains(strings.ToLower(out), forbidden) {
			t.Errorf("describe output contains forbidden term %q: %s", forbidden, out)
		}
	}
}

func TestRunDescribeDeletedSecret(t *testing.T) {
	meta := &SecretMetadata{
		Path:    "myservice/deleted",
		Service: "myservice",
		Name:    "deleted",
		Version: 1,
		Created: "2026-01-01T00:00:00Z",
		Updated: "2026-01-01T00:00:00Z",
		Deleted: true,
	}
	httpClient, baseURL := mockServerForDescribe(t, meta)
	c := &Client{baseURL: baseURL, httpClient: httpClient}

	var buf bytes.Buffer
	err := RunDescribe(context.Background(), &buf, c, "myservice/deleted")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "DELETED") {
		t.Errorf("expected DELETED status in output: %s", buf.String())
	}
}

// === RunHistory tests ===

func mockServerForHistory(t *testing.T, versions []VersionEntry, notFound bool) (*http.Client, string) {
	t.Helper()
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("action") == "history" {
			if notFound {
				http.Error(w, "not found", 404)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"versions": versions})
			return
		}
		http.Error(w, "not found", 404)
	})
	return srv.Client(), srv.URL
}

func TestRunHistorySingleVersion(t *testing.T) {
	versions := []VersionEntry{
		{Version: 1, Created: "2026-01-01T00:00:00Z", Caller: "bert"},
	}
	httpClient, baseURL := mockServerForHistory(t, versions, false)
	c := &Client{baseURL: baseURL, httpClient: httpClient}

	var buf bytes.Buffer
	err := RunHistory(context.Background(), &buf, c, "myservice/secret")
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "1 version") {
		t.Errorf("expected '1 version' in output: %s", out)
	}
	if !strings.Contains(out, "bert") {
		t.Errorf("expected caller in output: %s", out)
	}
}

func TestRunHistoryMultipleVersions(t *testing.T) {
	versions := []VersionEntry{
		{Version: 1, Created: "2026-01-01T00:00:00Z", Caller: "bert"},
		{Version: 2, Created: "2026-02-01T00:00:00Z", Caller: "ci-bot"},
		{Version: 3, Created: "2026-03-01T00:00:00Z", Caller: "bert"},
	}
	httpClient, baseURL := mockServerForHistory(t, versions, false)
	c := &Client{baseURL: baseURL, httpClient: httpClient}

	var buf bytes.Buffer
	err := RunHistory(context.Background(), &buf, c, "myservice/secret")
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "3 version") {
		t.Errorf("expected '3 version' in output: %s", out)
	}
	if !strings.Contains(out, "(current)") {
		t.Errorf("expected '(current)' marker in output: %s", out)
	}
}

func TestRunHistoryServerError(t *testing.T) {
	httpClient, baseURL := mockServerForHistory(t, nil, true)
	c := &Client{baseURL: baseURL, httpClient: httpClient}

	var buf bytes.Buffer
	err := RunHistory(context.Background(), &buf, c, "nonexistent/secret")
	if err == nil {
		t.Fatal("expected error for history fetch failure")
	}
}

func TestRunHistoryEmptyVersions(t *testing.T) {
	httpClient, baseURL := mockServerForHistory(t, []VersionEntry{}, false)
	c := &Client{baseURL: baseURL, httpClient: httpClient}

	var buf bytes.Buffer
	err := RunHistory(context.Background(), &buf, c, "myservice/secret")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "no version history") {
		t.Errorf("expected 'no version history' in output: %s", buf.String())
	}
}

func TestRunHistoryNeverShowsValues(t *testing.T) {
	versions := []VersionEntry{
		{Version: 1, Created: "2026-01-01T00:00:00Z", Caller: "bert"},
	}
	httpClient, baseURL := mockServerForHistory(t, versions, false)
	c := &Client{baseURL: baseURL, httpClient: httpClient}

	var buf bytes.Buffer
	err := RunHistory(context.Background(), &buf, c, "myservice/secret")
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	// History should only contain version numbers, timestamps, caller — not values
	for _, forbidden := range []string{"sk-", "password", "secret-value", "api_key"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("history output contains forbidden value %q: %s", forbidden, out)
		}
	}
}

// === RunRemove tests ===

func mockServerForRemove(t *testing.T, meta *SecretMetadata) (*http.Client, string) {
	t.Helper()
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/metadata/") {
			if meta == nil {
				http.Error(w, "not found", 404)
				return
			}
			json.NewEncoder(w).Encode(meta)
			return
		}
		if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/secrets/") {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
			return
		}
		http.Error(w, "not found", 404)
	})
	return srv.Client(), srv.URL
}

func TestRunRemoveNotFound(t *testing.T) {
	httpClient, baseURL := mockServerForRemove(t, nil)
	c := &Client{baseURL: baseURL, httpClient: httpClient}

	var buf bytes.Buffer
	stdinWith(t, "y\n", func() {
		err := RunRemove(context.Background(), &buf, c, "nonexistent/path", false)
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Errorf("expected 'not found' error, got: %v", err)
		}
	})
}

func TestRunRemoveCancelled(t *testing.T) {
	meta := &SecretMetadata{Path: "cloudflare/token", Service: "cloudflare", Name: "token", Version: 1}
	httpClient, baseURL := mockServerForRemove(t, meta)
	c := &Client{baseURL: baseURL, httpClient: httpClient}

	var buf bytes.Buffer
	stdinWith(t, "n\n", func() {
		err := RunRemove(context.Background(), &buf, c, "cloudflare/token", false)
		if err == nil || !strings.Contains(err.Error(), "cancelled") {
			t.Errorf("expected 'cancelled' error, got: %v", err)
		}
	})
}

func TestRunRemoveSoftDelete(t *testing.T) {
	meta := &SecretMetadata{Path: "cloudflare/token", Service: "cloudflare", Name: "token", Version: 2}
	httpClient, baseURL := mockServerForRemove(t, meta)
	c := &Client{baseURL: baseURL, httpClient: httpClient}

	var buf bytes.Buffer
	stdinWith(t, "y\n", func() {
		err := RunRemove(context.Background(), &buf, c, "cloudflare/token", false)
		if err != nil {
			t.Fatalf("RunRemove: %v", err)
		}
	})
	if !strings.Contains(buf.String(), "Removed") {
		t.Errorf("expected 'Removed' in output: %s", buf.String())
	}
}

func TestRunRemovePurge(t *testing.T) {
	meta := &SecretMetadata{Path: "cloudflare/token", Service: "cloudflare", Name: "token", Version: 1}
	httpClient, baseURL := mockServerForRemove(t, meta)
	c := &Client{baseURL: baseURL, httpClient: httpClient}

	var buf bytes.Buffer
	stdinWith(t, "y\n", func() {
		err := RunRemove(context.Background(), &buf, c, "cloudflare/token", true)
		if err != nil {
			t.Fatalf("RunRemove purge: %v", err)
		}
	})
	out := buf.String()
	if !strings.Contains(out, "Purged") {
		t.Errorf("expected 'Purged' in output: %s", out)
	}
}
