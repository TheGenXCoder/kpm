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
		if r.URL.Path == "/auth/session" {
			json.NewEncoder(w).Encode(map[string]string{"token": "t"})
			return
		}
		switch r.URL.Path {
		case "/credentials/llm/openai":
			json.NewEncoder(w).Encode(map[string]any{
				"provider":   "openai",
				"api_key":    "sk-test-openai",
				"expires_at": "2026-04-12T00:00:00Z",
				"ttl_seconds": 3600,
			})
		case "/credentials/llm/anthropic":
			json.NewEncoder(w).Encode(map[string]any{
				"provider":   "anthropic",
				"api_key":    "sk-ant-test",
				"expires_at": "2026-04-12T00:00:00Z",
				"ttl_seconds": 3600,
			})
		case "/credentials/generic/db/prod":
			json.NewEncoder(w).Encode(map[string]any{
				"path": "db/prod",
				"secrets": map[string]string{
					"password": "s3cret-pg-pass",
					"host":     "db.prod.internal",
					"port":     "5432",
				},
				"expires_at": "2026-04-12T00:00:00Z",
				"ttl_seconds": 3600,
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
		"APP_NAME=my-service":           "plain passthrough",
		"DB_HOST=db.prod.internal":      "KV ref with key",
		"DB_PORT=5432":                  "KV ref port",
		"DB_PASSWORD=s3cret-pg-pass":    "KV ref password",
		"OPENAI_API_KEY=sk-test-openai": "LLM ref",
		"ANTHROPIC_API_KEY=sk-ant-test": "LLM ref",
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
