package kpm

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestWriteMetadataSuccess(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/metadata/cloudflare/token" {
			http.Error(w, "not found", 404)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	defer srv.Close()

	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	err := c.WriteMetadata(context.Background(), "cloudflare/token", "DNS token", []string{"prod"}, "api-token", "")
	if err != nil {
		t.Fatalf("WriteMetadata: %v", err)
	}
}

func TestWriteMetadataServerError(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	})
	defer srv.Close()

	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	err := c.WriteMetadata(context.Background(), "cloudflare/token", "", nil, "", "")
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestWriteSecretFieldsSuccess(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/secrets/db/creds" {
			http.Error(w, "not found", 404)
			return
		}
		json.NewEncoder(w).Encode(WriteResult{Path: "db/creds", Version: 1, Status: "created"})
	})
	defer srv.Close()

	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	result, err := c.WriteSecretFields(context.Background(), "db/creds", map[string]string{
		"username": "admin",
		"password": "s3cret",
	})
	if err != nil {
		t.Fatalf("WriteSecretFields: %v", err)
	}
	if result.Version != 1 {
		t.Errorf("version = %d, want 1", result.Version)
	}
}

func TestWriteSecretFieldsServerError(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	})
	defer srv.Close()

	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	_, err := c.WriteSecretFields(context.Background(), "db/creds", map[string]string{"k": "v"})
	if err == nil {
		t.Fatal("expected error for 500")
	}
}

func TestGetMetadataSuccess(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/metadata/cloudflare/token" {
			json.NewEncoder(w).Encode(SecretMetadata{
				Path:    "cloudflare/token",
				Service: "cloudflare",
				Name:    "token",
				Type:    "api-token",
				Version: 5,
			})
			return
		}
		http.Error(w, "not found", 404)
	})
	defer srv.Close()

	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	meta, err := c.GetMetadata(context.Background(), "cloudflare/token")
	if err != nil {
		t.Fatal(err)
	}
	if meta == nil {
		t.Fatal("expected non-nil metadata")
	}
	if meta.Version != 5 {
		t.Errorf("version = %d, want 5", meta.Version)
	}
}

func TestGetMetadataServerError(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	})
	defer srv.Close()

	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	_, err := c.GetMetadata(context.Background(), "some/path")
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestGetMetadataPopulatesServiceName(t *testing.T) {
	// Returns metadata with only Path set (no Service/Name), verify populateServiceName is called
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(SecretMetadata{
			Path:    "myservice/mykey",
			Version: 1,
		})
	})
	defer srv.Close()

	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	meta, err := c.GetMetadata(context.Background(), "myservice/mykey")
	if err != nil {
		t.Fatal(err)
	}
	if meta.Service != "myservice" {
		t.Errorf("Service = %q, want myservice", meta.Service)
	}
	if meta.Name != "mykey" {
		t.Errorf("Name = %q, want mykey", meta.Name)
	}
}

func TestPopulateServiceNameAlreadySet(t *testing.T) {
	m := &SecretMetadata{Service: "existing", Name: "name", Path: "different/path"}
	m.populateServiceName()
	if m.Service != "existing" || m.Name != "name" {
		t.Errorf("pre-set service/name should not be overwritten, got %q/%q", m.Service, m.Name)
	}
}

func TestPopulateServiceNameNoSlash(t *testing.T) {
	m := &SecretMetadata{Path: "onlyone"}
	m.populateServiceName()
	if m.Service != "onlyone" {
		t.Errorf("Service = %q, want onlyone", m.Service)
	}
	if m.Name != "" {
		t.Errorf("Name = %q, want empty", m.Name)
	}
}

func TestPopulateServiceNameEmpty(t *testing.T) {
	m := &SecretMetadata{Path: ""}
	m.populateServiceName()
	if m.Service != "" || m.Name != "" {
		t.Errorf("empty path should leave service/name empty")
	}
}

func TestListMetadataIncludeDeleted(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("include_deleted") != "true" {
			http.Error(w, "missing param", 400)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"secrets": []map[string]any{
				{"service": "cloudflare", "name": "old-token", "version": 1, "deleted": true},
			},
		})
	})
	defer srv.Close()

	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	secrets, err := c.ListMetadata(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets) != 1 {
		t.Fatalf("expected 1 secret, got %d", len(secrets))
	}
	if !secrets[0].Deleted {
		t.Error("expected deleted secret")
	}
}

func TestListMetadataServerError(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	})
	defer srv.Close()

	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	_, err := c.ListMetadata(context.Background(), false)
	if err == nil {
		t.Fatal("expected error for 500")
	}
}

func TestWriteSecretServerError(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	})
	defer srv.Close()

	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	_, err := c.WriteSecret(context.Background(), "myservice/key", []byte("value"))
	if err == nil {
		t.Fatal("expected error for 500")
	}
}

func TestDeleteSecretServerError(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	})
	defer srv.Close()

	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	err := c.DeleteSecret(context.Background(), "myservice/key", false)
	if err == nil {
		t.Fatal("expected error for 500")
	}
}

func TestGetHistoryServerError(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	})
	defer srv.Close()

	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	_, err := c.GetHistory(context.Background(), "myservice/key")
	if err == nil {
		t.Fatal("expected error for 500")
	}
}

func TestDeleteSecretPurge(t *testing.T) {
	purgeQuerySeen := false
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("purge") == "true" {
			purgeQuerySeen = true
		}
		w.WriteHeader(http.StatusOK)
	})
	defer srv.Close()

	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	err := c.DeleteSecret(context.Background(), "myservice/key", true)
	if err != nil {
		t.Fatal(err)
	}
	if !purgeQuerySeen {
		t.Error("purge=true query param not sent")
	}
}
