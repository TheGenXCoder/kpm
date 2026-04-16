package kpm

import (
	"context"
	"net/http"
	"testing"
)

func TestWriteSecretMalformedJSON(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{bad json"))
	})
	defer srv.Close()

	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	_, err := c.WriteSecret(context.Background(), "test/path", []byte("value"))
	if err == nil {
		t.Fatal("expected error for malformed JSON response from WriteSecret")
	}
}

func TestWriteSecretFieldsMalformedJSON(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("{not valid"))
	})
	defer srv.Close()

	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	_, err := c.WriteSecretFields(context.Background(), "test/path", map[string]string{"k": "v"})
	if err == nil {
		t.Fatal("expected error for malformed JSON response from WriteSecretFields")
	}
}

func TestGetHistoryMalformedJSON(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{invalid"))
	})
	defer srv.Close()

	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	_, err := c.GetHistory(context.Background(), "test/secret")
	if err == nil {
		t.Fatal("expected error for malformed JSON from GetHistory")
	}
}

func TestListMetadataMalformedJSON(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{bad"))
	})
	defer srv.Close()

	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	_, err := c.ListMetadata(context.Background(), false)
	if err == nil {
		t.Fatal("expected error for malformed JSON from ListMetadata")
	}
}

func TestGetMetadataMalformedJSON(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{bad"))
	})
	defer srv.Close()

	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	_, err := c.GetMetadata(context.Background(), "some/path")
	if err == nil {
		t.Fatal("expected error for malformed JSON from GetMetadata")
	}
}

func TestFetchGenericMalformedJSON(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{bad"))
	})
	defer srv.Close()

	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	_, err := c.FetchGeneric(context.Background(), "db/prod")
	if err == nil {
		t.Fatal("expected error for malformed JSON from FetchGeneric")
	}
}

func TestWriteMetadataMalformedResponse(t *testing.T) {
	// WriteMetadata doesn't decode the response body, just checks status code
	// Test that non-200/201 causes an error
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		http.Error(w, "not found", 404)
	})
	defer srv.Close()

	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}
	err := c.WriteMetadata(context.Background(), "test/path", "desc", nil, "api-token", "")
	if err == nil {
		t.Fatal("expected error for 400 response from WriteMetadata")
	}
}
