package kpm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func mockResolverServer(handlers map[string]http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/session" {
			json.NewEncoder(w).Encode(map[string]string{"token": "t"})
			return
		}
		if h, ok := handlers[r.URL.Path]; ok {
			h(w, r)
			return
		}
		http.Error(w, "not found", 404)
	}))
}

func TestResolveKVMissingKeyFallsToDefault(t *testing.T) {
	srv := mockResolverServer(map[string]http.HandlerFunc{
		"/credentials/generic/app/config": func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{
				"path":    "app/config",
				"secrets": map[string]string{"other_key": "value"},
			})
		},
	})
	defer srv.Close()

	client := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	entries, _ := ParseTemplate(strings.NewReader("PORT=${kms:kv/app/config#missing_key:-9090}\n"))
	resolved, err := Resolve(context.Background(), client, entries)
	if err != nil {
		t.Fatal(err)
	}
	if string(resolved[0].PlainValue) != "9090" {
		t.Errorf("PORT = %q, want 9090 (default for missing key)", resolved[0].PlainValue)
	}
}

func TestResolveKVMissingKeyNoDefaultErrors(t *testing.T) {
	srv := mockResolverServer(map[string]http.HandlerFunc{
		"/credentials/generic/app/config": func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{
				"path":    "app/config",
				"secrets": map[string]string{"other_key": "value"},
			})
		},
	})
	defer srv.Close()

	client := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	entries, _ := ParseTemplate(strings.NewReader("PORT=${kms:kv/app/config#missing_key}\n"))
	_, err := Resolve(context.Background(), client, entries)
	if err == nil {
		t.Fatal("expected error for missing key without default")
	}
}

func TestResolveKVFetchErrorFallsToDefault(t *testing.T) {
	srv := mockResolverServer(map[string]http.HandlerFunc{
		// 404 for the KV path
	})
	defer srv.Close()

	client := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	entries, _ := ParseTemplate(strings.NewReader("DB=${kms:kv/nonexistent/path#key:-fallback}\n"))
	resolved, err := Resolve(context.Background(), client, entries)
	if err != nil {
		t.Fatal(err)
	}
	if string(resolved[0].PlainValue) != "fallback" {
		t.Errorf("DB = %q, want fallback", resolved[0].PlainValue)
	}
}

func TestResolveKVFetchErrorNoDefaultErrors(t *testing.T) {
	srv := mockResolverServer(nil)
	defer srv.Close()

	client := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	entries, _ := ParseTemplate(strings.NewReader("DB=${kms:kv/nonexistent/path#key}\n"))
	_, err := Resolve(context.Background(), client, entries)
	if err == nil {
		t.Fatal("expected error for fetch failure without default")
	}
}

func TestResolveLLMFetchErrorFallsToDefault(t *testing.T) {
	srv := mockResolverServer(nil)
	defer srv.Close()

	client := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	entries, _ := ParseTemplate(strings.NewReader("OPENAI_KEY=${kms:llm/openai:-default-key}\n"))
	resolved, err := Resolve(context.Background(), client, entries)
	if err != nil {
		t.Fatal(err)
	}
	if string(resolved[0].PlainValue) != "default-key" {
		t.Errorf("OPENAI_KEY = %q, want default-key", resolved[0].PlainValue)
	}
}

func TestResolveLLMFetchErrorNoDefaultErrors(t *testing.T) {
	srv := mockResolverServer(nil)
	defer srv.Close()

	client := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	entries, _ := ParseTemplate(strings.NewReader("OPENAI_KEY=${kms:llm/openai}\n"))
	_, err := Resolve(context.Background(), client, entries)
	if err == nil {
		t.Fatal("expected error for LLM fetch failure without default")
	}
}

func TestResolvePlainValue(t *testing.T) {
	srv := mockResolverServer(nil)
	defer srv.Close()

	client := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	entries, _ := ParseTemplate(strings.NewReader("APP_NAME=static-value\n"))
	resolved, err := Resolve(context.Background(), client, entries)
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) != 1 {
		t.Fatalf("expected 1 resolved entry, got %d", len(resolved))
	}
	if string(resolved[0].PlainValue) != "static-value" {
		t.Errorf("APP_NAME = %q, want static-value", resolved[0].PlainValue)
	}
	if resolved[0].Source != "" {
		t.Errorf("Source = %q, want empty for plain value", resolved[0].Source)
	}
}

func TestResolveRegistryPathWithValueField(t *testing.T) {
	srv := mockResolverServer(map[string]http.HandlerFunc{
		"/secrets/cloudflare/token": func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]string{"value": "cf-token-xyz"})
		},
	})
	defer srv.Close()

	client := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	// Registry path (no kv/ or llm/ prefix)
	entries, _ := ParseTemplate(strings.NewReader("CF_TOKEN=${kms:cloudflare/token}\n"))
	resolved, err := Resolve(context.Background(), client, entries)
	if err != nil {
		t.Fatal(err)
	}
	if string(resolved[0].PlainValue) != "cf-token-xyz" {
		t.Errorf("CF_TOKEN = %q, want cf-token-xyz", resolved[0].PlainValue)
	}
}

func TestResolveRegistryPathWithSpecificField(t *testing.T) {
	srv := mockResolverServer(map[string]http.HandlerFunc{
		"/secrets/db/creds": func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]string{
				"username": "admin",
				"password": "s3cret",
			})
		},
	})
	defer srv.Close()

	client := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	entries, _ := ParseTemplate(strings.NewReader("DB_PASS=${kms:db/creds#password}\n"))
	resolved, err := Resolve(context.Background(), client, entries)
	if err != nil {
		t.Fatal(err)
	}
	if string(resolved[0].PlainValue) != "s3cret" {
		t.Errorf("DB_PASS = %q, want s3cret", resolved[0].PlainValue)
	}
}

func TestResolveRegistryPathMissingField(t *testing.T) {
	srv := mockResolverServer(map[string]http.HandlerFunc{
		"/secrets/db/creds": func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]string{"username": "admin"})
		},
	})
	defer srv.Close()

	client := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	entries, _ := ParseTemplate(strings.NewReader("DB_PASS=${kms:db/creds#nonexistent}\n"))
	_, err := Resolve(context.Background(), client, entries)
	if err == nil {
		t.Fatal("expected error for missing field")
	}
}

func TestResolveRegistryPathNoValueFieldOrKey(t *testing.T) {
	// Multi-field secret, no "value" field, no specific key requested
	srv := mockResolverServer(map[string]http.HandlerFunc{
		"/secrets/db/creds": func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]string{
				"username": "admin",
				"password": "s3cret",
			})
		},
	})
	defer srv.Close()

	client := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	entries, _ := ParseTemplate(strings.NewReader("DB_CREDS=${kms:db/creds}\n"))
	_, err := Resolve(context.Background(), client, entries)
	if err == nil {
		t.Fatal("expected error for multi-field secret without key")
	}
}

func TestResolveRegistryFetchErrorWithDefault(t *testing.T) {
	srv := mockResolverServer(nil)
	defer srv.Close()

	client := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	entries, _ := ParseTemplate(strings.NewReader("TOKEN=${kms:cloudflare/token:-fallback-token}\n"))
	resolved, err := Resolve(context.Background(), client, entries)
	if err != nil {
		t.Fatal(err)
	}
	if string(resolved[0].PlainValue) != "fallback-token" {
		t.Errorf("TOKEN = %q, want fallback-token", resolved[0].PlainValue)
	}
}

func TestResolveLLMCaching(t *testing.T) {
	callCount := 0
	srv := mockResolverServer(map[string]http.HandlerFunc{
		"/credentials/llm/anthropic": func(w http.ResponseWriter, r *http.Request) {
			callCount++
			json.NewEncoder(w).Encode(map[string]any{
				"provider":    "anthropic",
				"api_key":     "sk-ant-key",
				"expires_at":  "",
				"ttl_seconds": 3600,
			})
		},
	})
	defer srv.Close()

	client := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	// Two entries referencing same LLM provider
	tmpl := "KEY1=${kms:llm/anthropic}\nKEY2=${kms:llm/anthropic}\n"
	entries, _ := ParseTemplate(strings.NewReader(tmpl))
	_, err := Resolve(context.Background(), client, entries)
	if err != nil {
		t.Fatal(err)
	}
	if callCount != 1 {
		t.Errorf("LLM API called %d times, want 1 (should cache)", callCount)
	}
}
