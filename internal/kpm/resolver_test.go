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
		if r.URL.Path == "/auth/session" {
			json.NewEncoder(w).Encode(map[string]string{"token": "t"})
			return
		}
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
		if r.URL.Path == "/auth/session" {
			json.NewEncoder(w).Encode(map[string]string{"token": "t"})
			return
		}
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
