package kpm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// mockServer creates a test server that handles auth + custom routes.
func mockServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle auth endpoint.
		if r.URL.Path == "/auth/session" && r.Method == http.MethodPost {
			json.NewEncoder(w).Encode(map[string]string{"token": "test-token"})
			return
		}
		handler(w, r)
	}))
}

func TestClientFetchLLM(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
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
	})
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
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
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
	})
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
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"not found"}`, 404)
	})
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
