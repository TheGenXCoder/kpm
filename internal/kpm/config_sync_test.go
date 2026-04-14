package kpm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// TestPullIndividualTemplates_found verifies that a template stored in AgentKMS
// is fetched, base64-decoded, and written to the destination directory.
func TestPullIndividualTemplates_found(t *testing.T) {
	content := "ANTHROPIC_API_KEY=${kms:llm/anthropic}\nOPENAI_API_KEY=${kms:llm/openai}\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(content))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/session":
			json.NewEncoder(w).Encode(map[string]string{"token": "test-token"})
		case "/credentials/generic/kpm/templates/shell-env":
			json.NewEncoder(w).Encode(map[string]any{
				"path": "kpm/templates/shell-env",
				"secrets": map[string]string{
					"content":  encoded,
					"filename": "shell-env.template",
				},
				"expires_at": "2026-04-15T00:00:00Z",
				"ttl_seconds": 3600,
			})
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	dir := t.TempDir()

	var buf bytes.Buffer
	err := pullIndividualTemplates(context.Background(), &buf, client, dir)
	if err != nil {
		t.Fatalf("pullIndividualTemplates: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "shell-env.template"))
	if err != nil {
		t.Fatalf("reading pulled template: %v", err)
	}
	if string(data) != content {
		t.Errorf("content = %q, want %q", data, content)
	}
	if !bytes.Contains(buf.Bytes(), []byte("shell-env.template")) {
		t.Errorf("expected output to mention shell-env.template, got: %s", buf.String())
	}
}

// TestPullIndividualTemplates_none verifies that when no templates exist the
// function returns nil (not an error) and prints a helpful hint.
func TestPullIndividualTemplates_none(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/session" {
			json.NewEncoder(w).Encode(map[string]string{"token": "test-token"})
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	client := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	dir := t.TempDir()

	var buf bytes.Buffer
	err := pullIndividualTemplates(context.Background(), &buf, client, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("no templates found")) {
		t.Errorf("expected 'no templates found' hint, got: %s", buf.String())
	}
}

// TestPullIndividualTemplates_rawContent verifies fallback when content is not
// base64-encoded (e.g. stored raw by a future write endpoint).
func TestPullIndividualTemplates_rawContent(t *testing.T) {
	rawContent := "RAW=${kms:kv/something}\n"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/session":
			json.NewEncoder(w).Encode(map[string]string{"token": "test-token"})
		case "/credentials/generic/kpm/templates/env":
			json.NewEncoder(w).Encode(map[string]any{
				"path": "kpm/templates/env",
				"secrets": map[string]string{
					"content": rawContent, // not base64
				},
				"expires_at":  "2026-04-15T00:00:00Z",
				"ttl_seconds": 3600,
			})
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	dir := t.TempDir()

	var buf bytes.Buffer
	err := pullIndividualTemplates(context.Background(), &buf, client, dir)
	if err != nil {
		t.Fatalf("pullIndividualTemplates: %v", err)
	}

	// filename derived from key name when "filename" field is absent
	data, err := os.ReadFile(filepath.Join(dir, "env.template"))
	if err != nil {
		t.Fatalf("reading pulled template: %v", err)
	}
	if string(data) != rawContent {
		t.Errorf("content = %q, want %q", data, rawContent)
	}
}

// TestPullTemplates delegates to pullIndividualTemplates; smoke-test the public
// entry point.
func TestPullTemplates(t *testing.T) {
	content := "KEY=${kms:llm/openai}\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(content))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/session":
			json.NewEncoder(w).Encode(map[string]string{"token": "test-token"})
		case "/credentials/generic/kpm/templates/shell-env":
			json.NewEncoder(w).Encode(map[string]any{
				"path": "kpm/templates/shell-env",
				"secrets": map[string]string{
					"content":  encoded,
					"filename": "shell-env.template",
				},
				"expires_at":  "2026-04-15T00:00:00Z",
				"ttl_seconds": 3600,
			})
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	dir := t.TempDir()

	var buf bytes.Buffer
	if err := PullTemplates(context.Background(), &buf, client, dir); err != nil {
		t.Fatalf("PullTemplates: %v", err)
	}
	if _, err := os.ReadFile(filepath.Join(dir, "shell-env.template")); err != nil {
		t.Fatalf("expected shell-env.template to exist: %v", err)
	}
}
