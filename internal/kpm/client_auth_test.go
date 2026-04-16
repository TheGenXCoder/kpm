package kpm

import (
	"context"
	"testing"
)

func TestAuthenticateInvalidURL(t *testing.T) {
	// Create client with a baseURL containing null byte — the request construction fails
	c := &Client{
		baseURL:    "http://localhost\x00invalid",
		httpClient: nil,
	}
	err := c.Authenticate(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid base URL in Authenticate")
	}
}
