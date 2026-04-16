package kpm

import (
	"context"
	"testing"
)

// doGet/doPost/doDelete have an uncovered path: http.NewRequestWithContext fails
// for invalid URLs. Null byte in URL triggers this.

func TestDoGetInvalidURL(t *testing.T) {
	c := &Client{baseURL: "http://localhost", httpClient: nil, token: "tok"}
	// Null byte in URL causes http.NewRequestWithContext to fail
	_, err := c.doGet(context.Background(), "http://localhost/path\x00invalid")
	if err == nil {
		t.Fatal("expected error for invalid URL with null byte")
	}
}

func TestDoPostInvalidURL(t *testing.T) {
	c := &Client{baseURL: "http://localhost", httpClient: nil, token: "tok"}
	_, err := c.doPost(context.Background(), "http://localhost/path\x00invalid", map[string]string{"k": "v"})
	if err == nil {
		t.Fatal("expected error for invalid URL with null byte")
	}
}

func TestDoDeleteInvalidURL(t *testing.T) {
	c := &Client{baseURL: "http://localhost", httpClient: nil, token: "tok"}
	_, err := c.doDelete(context.Background(), "http://localhost/path\x00invalid")
	if err == nil {
		t.Fatal("expected error for invalid URL with null byte")
	}
}
