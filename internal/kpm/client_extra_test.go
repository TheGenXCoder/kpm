package kpm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// mockServerNoAuth creates a test server without an automatic auth handler,
// so we can test authentication failure paths.
func mockServerNoAuth(handler http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(handler)
}

// --- Authenticate error paths ---

func TestAuthenticateNon200(t *testing.T) {
	srv := mockServerNoAuth(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
	defer srv.Close()

	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	err := c.Authenticate(context.Background())
	if err == nil {
		t.Fatal("expected error for non-200 auth response")
	}
}

func TestAuthenticateMalformedJSON(t *testing.T) {
	srv := mockServerNoAuth(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{not valid json"))
	})
	defer srv.Close()

	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	err := c.Authenticate(context.Background())
	if err == nil {
		t.Fatal("expected error for malformed JSON in auth response")
	}
}

func TestAuthenticateSuccess(t *testing.T) {
	srv := mockServerNoAuth(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"token": "my-token-xyz"})
	})
	defer srv.Close()

	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	err := c.Authenticate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if c.token != "my-token-xyz" {
		t.Errorf("token = %q, want my-token-xyz", c.token)
	}
}

func TestAuthenticateServerDown(t *testing.T) {
	// Point at a port that should refuse connections
	c := &Client{baseURL: "http://127.0.0.1:19999", httpClient: http.DefaultClient}
	err := c.Authenticate(context.Background())
	if err == nil {
		t.Fatal("expected error connecting to closed port")
	}
}

// --- doGet/doPost/doDelete when auth fails ---

func TestDoGetAuthFailure(t *testing.T) {
	srv := mockServerNoAuth(func(w http.ResponseWriter, r *http.Request) {
		// Always fail auth
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
	defer srv.Close()

	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	_, err := c.doGet(context.Background(), srv.URL+"/anything")
	if err == nil {
		t.Fatal("expected error when auth fails for doGet")
	}
}

func TestDoPostAuthFailure(t *testing.T) {
	srv := mockServerNoAuth(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
	defer srv.Close()

	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	_, err := c.doPost(context.Background(), srv.URL+"/anything", map[string]string{"k": "v"})
	if err == nil {
		t.Fatal("expected error when auth fails for doPost")
	}
}

func TestDoDeleteAuthFailure(t *testing.T) {
	srv := mockServerNoAuth(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
	defer srv.Close()

	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	_, err := c.doDelete(context.Background(), srv.URL+"/anything")
	if err == nil {
		t.Fatal("expected error when auth fails for doDelete")
	}
}

// --- FetchLLM error paths ---

func TestFetchLLMServerError(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	})
	defer srv.Close()

	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	_, err := c.FetchLLM(context.Background(), "openai")
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestFetchLLMMalformedJSON(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{broken"))
	})
	defer srv.Close()

	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	_, err := c.FetchLLM(context.Background(), "openai")
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestFetchLLMEmptyAPIKey(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"provider":    "openai",
			"api_key":     "",
			"expires_at":  "",
			"ttl_seconds": 0,
		})
	})
	defer srv.Close()

	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	cred, err := c.FetchLLM(context.Background(), "openai")
	// Current behavior: empty api_key is not an error — it's returned as-is
	if err != nil {
		t.Fatal(err)
	}
	if len(cred.APIKey) != 0 {
		t.Errorf("expected empty APIKey, got %q", cred.APIKey)
	}
}

// --- FetchRegistrySecret ---

func TestFetchRegistrySecretSuccess(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/secrets/myservice/mytoken" {
			http.Error(w, "not found", 404)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{
			"value": "registry-secret-value",
		})
	})
	defer srv.Close()

	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	result, err := c.FetchRegistrySecret(context.Background(), "myservice/mytoken")
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroMap(result)
	if string(result["value"]) != "registry-secret-value" {
		t.Errorf("value = %q, want registry-secret-value", result["value"])
	}
}

func TestFetchRegistrySecretNotFound(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	defer srv.Close()

	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	_, err := c.FetchRegistrySecret(context.Background(), "nonexistent/path")
	if err == nil {
		t.Fatal("expected error for 404")
	}
}

func TestFetchRegistrySecretServerError(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	})
	defer srv.Close()

	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	_, err := c.FetchRegistrySecret(context.Background(), "some/path")
	if err == nil {
		t.Fatal("expected error for 500")
	}
}

func TestFetchRegistrySecretMalformedJSON(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{bad json"))
	})
	defer srv.Close()

	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	_, err := c.FetchRegistrySecret(context.Background(), "some/path")
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestFetchRegistrySecretMultiField(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"username": "admin",
			"password": "hunter2",
		})
	})
	defer srv.Close()

	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	result, err := c.FetchRegistrySecret(context.Background(), "db/creds")
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroMap(result)
	if string(result["username"]) != "admin" {
		t.Errorf("username = %q, want admin", result["username"])
	}
	if string(result["password"]) != "hunter2" {
		t.Errorf("password = %q, want hunter2", result["password"])
	}
}

// --- ensureAuth skips if token already set ---

func TestEnsureAuthSkipsIfTokenSet(t *testing.T) {
	callCount := 0
	srv := mockServerNoAuth(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/session" {
			callCount++
			json.NewEncoder(w).Encode(map[string]string{"token": "new-token"})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"ok": "yes"})
	})
	defer srv.Close()

	c := &Client{baseURL: srv.URL, httpClient: srv.Client(), token: "existing-token"}
	// Calling doGet should not trigger auth since token is already set
	resp, err := c.doGet(context.Background(), srv.URL+"/anything")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if callCount != 0 {
		t.Errorf("auth was called %d times, want 0 (token already set)", callCount)
	}
}
