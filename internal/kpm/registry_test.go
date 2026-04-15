package kpm

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestWriteSecret(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/secrets/cloudflare/dns-token" {
			http.Error(w, "not found", 404)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"path": "cloudflare/dns-token", "version": 1, "status": "created",
		})
	})
	defer srv.Close()

	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	result, err := c.WriteSecret(context.Background(), "cloudflare/dns-token", []byte("test-value"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Version != 1 {
		t.Errorf("version = %d, want 1", result.Version)
	}
	if result.Status != "created" {
		t.Errorf("status = %q, want created", result.Status)
	}
}

func TestListMetadata(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/metadata" {
			http.Error(w, "not found", 404)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"secrets": []map[string]any{
				{"service": "cloudflare", "name": "dns-token", "type": "api-token", "version": 1},
				{"service": "github", "name": "pat", "type": "api-token", "version": 2},
			},
		})
	})
	defer srv.Close()

	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	secrets, err := c.ListMetadata(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets) != 2 {
		t.Fatalf("got %d secrets, want 2", len(secrets))
	}
	if secrets[0].Service != "cloudflare" {
		t.Errorf("first service = %q", secrets[0].Service)
	}
}

func TestGetMetadataNotFound(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", 404)
	})
	defer srv.Close()

	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	meta, err := c.GetMetadata(context.Background(), "nonexistent/path")
	if err != nil {
		t.Fatal(err)
	}
	if meta != nil {
		t.Error("expected nil for not found")
	}
}

func TestDeleteSecret(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "wrong method", 405)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
	})
	defer srv.Close()

	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	err := c.DeleteSecret(context.Background(), "test/secret", false)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGetHistory(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("action") != "history" {
			http.Error(w, "not found", 404)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"versions": []map[string]any{
				{"version": 1, "created": "2026-04-14T10:00:00Z", "caller": "bert"},
				{"version": 2, "created": "2026-04-14T12:00:00Z", "caller": "bert"},
			},
		})
	})
	defer srv.Close()

	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	versions, err := c.GetHistory(context.Background(), "test/secret")
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 2 {
		t.Fatalf("got %d versions, want 2", len(versions))
	}
}
