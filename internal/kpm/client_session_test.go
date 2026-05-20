package kpm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestClient_PersistedSessionIsReused proves the core acceptance criterion:
// once a session is on disk, subsequent Client constructions hit the
// per-command lookup path and do NOT call /auth/session again.
func TestClient_PersistedSessionIsReused(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("KPM_DATA", tmp)

	var sessionCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/session":
			sessionCalls.Add(1)
			json.NewEncoder(w).Encode(SessionResponse{
				Token:     "should-not-be-used",
				TokenType: "Bearer",
				ExpiresIn: 900,
				SessionID: "JTI-FALLBACK",
			})
		case "/bindings":
			if r.Header.Get("Authorization") != "Bearer persisted-token" {
				http.Error(w, "wrong token", http.StatusUnauthorized)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"bindings": []any{}})
		default:
			http.Error(w, "unknown", 404)
		}
	}))
	defer srv.Close()

	// Pre-populate a persisted session.
	if err := SaveAuthSession(&AuthSession{
		Token:     "persisted-token",
		TokenType: "Bearer",
		SessionID: "JTI-PERSISTED",
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}); err != nil {
		t.Fatalf("SaveAuthSession: %v", err)
	}

	// New client should pick up the persisted token and NOT call /auth/session.
	c, _ := NewClientInsecure(srv.URL)
	if _, err := c.ListBindings(context.Background(), ""); err != nil {
		t.Fatalf("ListBindings: %v", err)
	}
	if got := sessionCalls.Load(); got != 0 {
		t.Errorf("/auth/session calls = %d, want 0 (persisted session should be used)", got)
	}
}

// TestClient_NoPersistedSession_FallsBack confirms the fallback path still
// works when there's no session on disk — backwards-compatible behavior.
func TestClient_NoPersistedSession_FallsBack(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("KPM_DATA", tmp)

	var sessionCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/session":
			sessionCalls.Add(1)
			json.NewEncoder(w).Encode(SessionResponse{
				Token:     "transient-token",
				TokenType: "Bearer",
				ExpiresIn: 900,
				SessionID: "JTI-TRANSIENT",
			})
		case "/bindings":
			if r.Header.Get("Authorization") != "Bearer transient-token" {
				http.Error(w, "wrong token", http.StatusUnauthorized)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"bindings": []any{}})
		default:
			http.Error(w, "unknown", 404)
		}
	}))
	defer srv.Close()

	c, _ := NewClientInsecure(srv.URL)
	if _, err := c.ListBindings(context.Background(), ""); err != nil {
		t.Fatalf("ListBindings: %v", err)
	}
	if got := sessionCalls.Load(); got != 1 {
		t.Errorf("/auth/session calls = %d, want 1 (fallback should authenticate)", got)
	}

	// And the fallback token should NOT have been persisted.
	if _, err := LoadAuthSession(); err == nil {
		t.Error("fallback /auth/session token must not be persisted")
	}
}

// TestClient_NearExpiryRefresh confirms that when a persisted session has
// less than 60s of life, the client calls /auth/refresh and persists the
// refreshed session.
func TestClient_NearExpiryRefresh(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("KPM_DATA", tmp)

	var refreshCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/refresh":
			if r.Header.Get("Authorization") != "Bearer near-expiry-token" {
				http.Error(w, "wrong token", http.StatusUnauthorized)
				return
			}
			refreshCalls.Add(1)
			json.NewEncoder(w).Encode(SessionResponse{
				Token:     "refreshed-token",
				TokenType: "Bearer",
				ExpiresIn: 900,
				SessionID: "JTI-REFRESHED",
			})
		case "/bindings":
			if r.Header.Get("Authorization") != "Bearer refreshed-token" {
				http.Error(w, "wrong token", http.StatusUnauthorized)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"bindings": []any{}})
		default:
			http.Error(w, "unknown", 404)
		}
	}))
	defer srv.Close()

	// Persist a session that's within 60s of expiry.
	if err := SaveAuthSession(&AuthSession{
		Token:     "near-expiry-token",
		TokenType: "Bearer",
		SessionID: "JTI-NEAR",
		ExpiresAt: time.Now().Add(30 * time.Second),
	}); err != nil {
		t.Fatalf("SaveAuthSession: %v", err)
	}

	c, _ := NewClientInsecure(srv.URL)
	if _, err := c.ListBindings(context.Background(), ""); err != nil {
		t.Fatalf("ListBindings: %v", err)
	}
	if refreshCalls.Load() != 1 {
		t.Errorf("/auth/refresh calls = %d, want 1", refreshCalls.Load())
	}

	// Refreshed session should be persisted.
	s, err := LoadAuthSession()
	if err != nil {
		t.Fatalf("LoadAuthSession after refresh: %v", err)
	}
	if s.Token != "refreshed-token" {
		t.Errorf("persisted token = %q, want refreshed-token", s.Token)
	}
	if s.SessionID != "JTI-REFRESHED" {
		t.Errorf("persisted session_id = %q, want JTI-REFRESHED", s.SessionID)
	}
}
