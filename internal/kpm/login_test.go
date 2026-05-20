package kpm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// makeFakeJWT builds a JWT-shaped string whose payload base64-decodes to the
// given claims map.  Signature is a placeholder — kpm never verifies.
func makeFakeJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"JWT"}`))
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	body := base64.RawURLEncoding.EncodeToString(payload)
	return header + "." + body + ".signature"
}

func TestRunLogin_PersistsSession(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("KPM_DATA", tmp)

	token := makeFakeJWT(t, map[string]any{
		"sub":    "bert@platform",
		"team":   "platform",
		"role":   "developer",
		"spiffe": "spiffe://c9.local/tenant/c9/human/bert",
		"as":     "cert-only",
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/session" || r.Method != http.MethodPost {
			http.Error(w, "unexpected", 404)
			return
		}
		json.NewEncoder(w).Encode(SessionResponse{
			Token:     token,
			TokenType: "Bearer",
			ExpiresIn: 900,
			SessionID: "JTI-LOGIN",
		})
	}))
	defer srv.Close()

	c, _ := NewClientInsecure(srv.URL)
	var buf bytes.Buffer
	if err := RunLogin(context.Background(), &buf, c); err != nil {
		t.Fatalf("RunLogin: %v", err)
	}

	got, err := LoadAuthSession()
	if err != nil {
		t.Fatalf("LoadAuthSession: %v", err)
	}
	if got.Token != token {
		t.Errorf("token = %q, want %q", got.Token, token)
	}
	if got.SessionID != "JTI-LOGIN" {
		t.Errorf("session_id = %q, want JTI-LOGIN", got.SessionID)
	}
	if got.Claims.Sub != "bert@platform" {
		t.Errorf("claims.Sub = %q, want bert@platform", got.Claims.Sub)
	}
	if !strings.Contains(buf.String(), "Logged in as bert@platform") {
		t.Errorf("stderr should mention identity; got: %q", buf.String())
	}
	if !strings.Contains(buf.String(), "JTI-LOGIN") {
		t.Errorf("stderr should mention session id; got: %q", buf.String())
	}
}

func TestRunLogout_RevokesAndDeletes(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("KPM_DATA", tmp)

	// Pre-populate a session.
	tok := makeFakeJWT(t, map[string]any{"sub": "x"})
	_ = SaveAuthSession(&AuthSession{
		Token:     tok,
		TokenType: "Bearer",
		SessionID: "JTI-LOGOUT",
		ExpiresAt: timeNowPlus(900),
	})

	revoked := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/revoke" && r.Method == http.MethodPost {
			if r.Header.Get("Authorization") != "Bearer "+tok {
				http.Error(w, "wrong token", 401)
				return
			}
			revoked = true
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Error(w, "unexpected", 404)
	}))
	defer srv.Close()

	c, _ := NewClientInsecure(srv.URL)
	var buf bytes.Buffer
	if err := RunLogout(context.Background(), &buf, c); err != nil {
		t.Fatalf("RunLogout: %v", err)
	}
	if !revoked {
		t.Error("server-side revoke was not called")
	}
	if _, err := LoadAuthSession(); !os.IsNotExist(err) {
		t.Errorf("session should be deleted, got: %v", err)
	}
	if !strings.Contains(buf.String(), "Logged out") {
		t.Errorf("stderr should say Logged out; got: %q", buf.String())
	}
}

func TestRunLogout_NoSession(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("KPM_DATA", tmp)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("no HTTP calls expected when no session is present")
	}))
	defer srv.Close()

	c, _ := NewClientInsecure(srv.URL)
	var buf bytes.Buffer
	if err := RunLogout(context.Background(), &buf, c); err != nil {
		t.Fatalf("RunLogout: %v", err)
	}
	if !strings.Contains(buf.String(), "Not logged in") {
		t.Errorf("expected 'Not logged in', got: %q", buf.String())
	}
}

func TestRunLogout_AlreadyRevoked401(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("KPM_DATA", tmp)

	_ = SaveAuthSession(&AuthSession{
		Token:     "expired-tok",
		TokenType: "Bearer",
		SessionID: "JTI-401",
		ExpiresAt: timeNowPlus(900),
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"token expired","code":"unauthorized"}`, http.StatusUnauthorized)
	}))
	defer srv.Close()

	c, _ := NewClientInsecure(srv.URL)
	var buf bytes.Buffer
	if err := RunLogout(context.Background(), &buf, c); err != nil {
		t.Fatalf("401 from revoke should be treated as success, got: %v", err)
	}
	if _, err := LoadAuthSession(); !os.IsNotExist(err) {
		t.Errorf("session should still be deleted after 401-already-revoked; got: %v", err)
	}
}

func TestRunWhoami_NoSession(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("KPM_DATA", tmp)

	err := RunWhoami(&bytes.Buffer{})
	if !os.IsNotExist(err) {
		t.Errorf("expected os.ErrNotExist, got: %v", err)
	}
}

func TestRunWhoami_PrintsClaims(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("KPM_DATA", tmp)

	_ = SaveAuthSession(&AuthSession{
		Token:     "tok",
		TokenType: "Bearer",
		SessionID: "JTI-WHO",
		ExpiresAt: timeNowPlus(900),
		Claims: AuthClaims{
			Sub:          "bert@platform",
			Team:         "platform",
			Role:         "developer",
			SPIFFE:       "spiffe://x/y/z",
			AuthStrength: "cert+human",
		},
	})

	var buf bytes.Buffer
	if err := RunWhoami(&buf); err != nil {
		t.Fatalf("RunWhoami: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"bert@platform",
		"platform",
		"developer",
		"spiffe://x/y/z",
		"JTI-WHO",
		"cert+human",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\nfull output:\n%s", want, out)
		}
	}
}

// TestRunLogin_NewStyle_PrintsUserAndDevice proves the per-spec login
// confirmation message: when the issued JWT carries both UserID and DeviceID,
// the stderr summary names them in the "on device" form.
func TestRunLogin_NewStyle_PrintsUserAndDevice(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("KPM_DATA", tmp)

	token := makeFakeJWT(t, map[string]any{
		"sub":  "bert",
		"usr":  "bert",
		"dev":  "bert-tp-dev",
		"tnt":  "catalyst9",
		"team": "platform",
		"role": "developer",
		"as":   "cert-only",
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/session" || r.Method != http.MethodPost {
			http.Error(w, "unexpected", 404)
			return
		}
		json.NewEncoder(w).Encode(SessionResponse{
			Token:     token,
			TokenType: "Bearer",
			ExpiresIn: 900,
			SessionID: "JTI-LOGIN-NEW",
		})
	}))
	defer srv.Close()

	c, _ := NewClientInsecure(srv.URL)
	var buf bytes.Buffer
	if err := RunLogin(context.Background(), &buf, c); err != nil {
		t.Fatalf("RunLogin: %v", err)
	}
	if !strings.Contains(buf.String(), "Logged in as bert on device bert-tp-dev") {
		t.Errorf("expected new-style login confirmation; got: %q", buf.String())
	}
}

// TestRunLogin_LegacyCert_PrintsLegacyHint proves the backward-compat
// confirmation message: when UserID == DeviceID (legacy device-only cert),
// the summary calls that out so the operator knows to re-enroll.
func TestRunLogin_LegacyCert_PrintsLegacyHint(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("KPM_DATA", tmp)

	token := makeFakeJWT(t, map[string]any{
		"sub":  "bert-tp-dev",
		"usr":  "bert-tp-dev",
		"dev":  "bert-tp-dev",
		"tnt":  "catalyst9",
		"team": "platform",
		"role": "developer",
		"as":   "cert-only",
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/session" || r.Method != http.MethodPost {
			http.Error(w, "unexpected", 404)
			return
		}
		json.NewEncoder(w).Encode(SessionResponse{
			Token:     token,
			TokenType: "Bearer",
			ExpiresIn: 900,
			SessionID: "JTI-LOGIN-LEGACY",
		})
	}))
	defer srv.Close()

	c, _ := NewClientInsecure(srv.URL)
	var buf bytes.Buffer
	if err := RunLogin(context.Background(), &buf, c); err != nil {
		t.Fatalf("RunLogin: %v", err)
	}
	if !strings.Contains(buf.String(), "Logged in as bert-tp-dev (legacy device-only cert)") {
		t.Errorf("expected legacy login confirmation; got: %q", buf.String())
	}
}

// TestRunWhoami_NewStyleClaims_RendersUserAndDevice proves the new whoami
// rendering for sessions that came from a cert following the user/device
// SPIFFE convention: both User and Device lines appear, with their distinct
// values.
func TestRunWhoami_NewStyleClaims_RendersUserAndDevice(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("KPM_DATA", tmp)

	_ = SaveAuthSession(&AuthSession{
		Token:     "tok",
		TokenType: "Bearer",
		SessionID: "JTI-NEW",
		ExpiresAt: timeNowPlus(900),
		Claims: AuthClaims{
			Sub:          "bert",
			UserID:       "bert",
			DeviceID:     "bert-tp-dev",
			Tenant:       "catalyst9",
			Team:         "platform",
			Role:         "developer",
			SPIFFE:       "spiffe://catalyst9.local/tenant/catalyst9/user/bert/device/bert-tp-dev",
			AuthStrength: "cert+human",
		},
	})

	var buf bytes.Buffer
	if err := RunWhoami(&buf); err != nil {
		t.Fatalf("RunWhoami: %v", err)
	}
	out := buf.String()

	// Both User and Device lines present.
	if !strings.Contains(out, "User:           bert\n") {
		t.Errorf("expected 'User: bert' line; got:\n%s", out)
	}
	if !strings.Contains(out, "Device:         bert-tp-dev\n") {
		t.Errorf("expected 'Device: bert-tp-dev' line; got:\n%s", out)
	}
	// Tenant should appear when populated.
	if !strings.Contains(out, "Tenant:         catalyst9\n") {
		t.Errorf("expected 'Tenant: catalyst9' line; got:\n%s", out)
	}
	// The legacy "Identity:" line MUST NOT appear when we have a real user.
	if strings.Contains(out, "Identity:") {
		t.Errorf("unexpected legacy 'Identity:' line for new-style claims; got:\n%s", out)
	}
	if !strings.Contains(out, "cert+human") {
		t.Errorf("expected auth strength rendered; got:\n%s", out)
	}
}

// TestRunWhoami_LegacyClaims_RendersDeviceOnly proves the backward-compat
// rendering: a session whose JWT carries UserID == DeviceID (the legacy
// device-only cert path) shows the Device line and a "(none — legacy cert)"
// User line so the operator knows to re-enroll.
func TestRunWhoami_LegacyClaims_RendersDeviceOnly(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("KPM_DATA", tmp)

	_ = SaveAuthSession(&AuthSession{
		Token:     "tok",
		TokenType: "Bearer",
		SessionID: "JTI-LEGACY",
		ExpiresAt: timeNowPlus(900),
		Claims: AuthClaims{
			Sub:      "bert-tp-dev",
			UserID:   "bert-tp-dev", // server synthesised this for legacy cert
			DeviceID: "bert-tp-dev",
			Tenant:   "catalyst9",
			Team:     "platform",
			Role:     "developer",
		},
	})

	var buf bytes.Buffer
	if err := RunWhoami(&buf); err != nil {
		t.Fatalf("RunWhoami: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "Device:         bert-tp-dev\n") {
		t.Errorf("expected 'Device: bert-tp-dev' line; got:\n%s", out)
	}
	if !strings.Contains(out, "User:           (none — legacy cert)") {
		t.Errorf("expected legacy 'User: (none — legacy cert)' line; got:\n%s", out)
	}
}

// timeNowPlus returns an absolute time N seconds in the future, suitable for
// AuthSession.ExpiresAt in test fixtures.
func timeNowPlus(seconds int) time.Time {
	return time.Now().Add(time.Duration(seconds) * time.Second)
}
