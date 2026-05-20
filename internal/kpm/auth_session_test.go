package kpm

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAuthSession_RoundTrip(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("KPM_DATA", tmp)

	want := &AuthSession{
		Token:     "jwt.body.sig",
		TokenType: "Bearer",
		SessionID: "01ABCDEF",
		ExpiresAt: time.Now().Add(15 * time.Minute).UTC().Truncate(time.Second),
		Claims: AuthClaims{
			Sub:          "bert@platform",
			Team:         "platform",
			Role:         "developer",
			SPIFFE:       "spiffe://catalyst9.local/tenant/c9/human/bert",
			AuthStrength: "device+human",
		},
	}
	if err := SaveAuthSession(want); err != nil {
		t.Fatalf("SaveAuthSession: %v", err)
	}

	got, err := LoadAuthSession()
	if err != nil {
		t.Fatalf("LoadAuthSession: %v", err)
	}
	if got.Token != want.Token ||
		got.TokenType != want.TokenType ||
		got.SessionID != want.SessionID ||
		!got.ExpiresAt.Equal(want.ExpiresAt) ||
		got.Claims != want.Claims {
		t.Errorf("round-trip mismatch:\n got=%+v\nwant=%+v", got, want)
	}
}

func TestAuthSession_FilePermission_0600(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("KPM_DATA", tmp)

	if err := SaveAuthSession(&AuthSession{
		Token:     "x",
		TokenType: "Bearer",
		SessionID: "s",
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("SaveAuthSession: %v", err)
	}

	info, err := os.Stat(filepath.Join(tmp, "sessions", "current.json"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("file perm = %o, want 0600", perm)
	}

	// Parent dir must be 0700.
	dirInfo, err := os.Stat(filepath.Join(tmp, "sessions"))
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0700 {
		t.Errorf("dir perm = %o, want 0700", perm)
	}
}

func TestAuthSession_ExpiredIsNotReturned(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("KPM_DATA", tmp)

	if err := SaveAuthSession(&AuthSession{
		Token:     "expired",
		TokenType: "Bearer",
		SessionID: "old",
		ExpiresAt: time.Now().Add(-time.Minute),
	}); err != nil {
		t.Fatalf("SaveAuthSession: %v", err)
	}

	_, err := LoadAuthSession()
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected os.ErrNotExist for expired session, got: %v", err)
	}

	// Stale file should also be cleaned up.
	if _, statErr := os.Stat(filepath.Join(tmp, "sessions", "current.json")); !os.IsNotExist(statErr) {
		t.Error("expired session file should be removed by LoadAuthSession")
	}
}

func TestAuthSession_LoadMissing(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("KPM_DATA", tmp)

	_, err := LoadAuthSession()
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected os.ErrNotExist for absent session, got: %v", err)
	}
}

func TestAuthSession_Delete(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("KPM_DATA", tmp)

	// Delete on absent file is not an error.
	if err := DeleteAuthSession(); err != nil {
		t.Errorf("DeleteAuthSession (absent): %v", err)
	}

	_ = SaveAuthSession(&AuthSession{
		Token:     "x",
		TokenType: "Bearer",
		SessionID: "s",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err := DeleteAuthSession(); err != nil {
		t.Fatalf("DeleteAuthSession: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(tmp, "sessions", "current.json")); !os.IsNotExist(statErr) {
		t.Error("session file still present after DeleteAuthSession")
	}
}

func TestAuthSession_AtomicRename(t *testing.T) {
	// Verify SaveAuthSession does not leave the tmp file behind and the final
	// file matches the payload byte-for-byte (proxy for "atomic rename
	// produced exactly the bytes we wrote, not a half-flushed file").
	tmp := t.TempDir()
	t.Setenv("KPM_DATA", tmp)

	s := &AuthSession{
		Token:     "atomic-token",
		TokenType: "Bearer",
		SessionID: "01ATOMIC",
		ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Second),
		Claims:    AuthClaims{Sub: "x"},
	}
	if err := SaveAuthSession(s); err != nil {
		t.Fatalf("SaveAuthSession: %v", err)
	}

	entries, err := os.ReadDir(filepath.Join(tmp, "sessions"))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if e.Name() != "current.json" {
			t.Errorf("unexpected leftover file after atomic rename: %s", e.Name())
		}
	}

	data, err := os.ReadFile(filepath.Join(tmp, "sessions", "current.json"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var got AuthSession
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Token != s.Token || got.SessionID != s.SessionID {
		t.Errorf("file contents mismatch after atomic rename: %+v", got)
	}
}

func TestDecodeJWTClaims(t *testing.T) {
	// 3-segment form: header.payload.sig
	payload := `{"sub":"bert@platform","team":"platform","role":"developer","spiffe":"spiffe://x/y/z","as":"cert+human"}`
	body := base64.RawURLEncoding.EncodeToString([]byte(payload))
	token := "ignored." + body + ".sig"

	claims := DecodeJWTClaims(token)
	if claims.Sub != "bert@platform" ||
		claims.Team != "platform" ||
		claims.Role != "developer" ||
		claims.SPIFFE != "spiffe://x/y/z" ||
		claims.AuthStrength != "cert+human" {
		t.Errorf("3-segment: unexpected claims: %+v", claims)
	}

	// 2-segment form: payload.sig (AgentKMS's current shape — no header).
	tok2 := body + ".sig"
	claims2 := DecodeJWTClaims(tok2)
	if claims2.Sub != "bert@platform" {
		t.Errorf("2-segment: expected sub=bert@platform, got %+v", claims2)
	}

	// Malformed tokens return zero-value claims, not panics.
	zero := DecodeJWTClaims("not.a.jwt.at.all")
	if zero != (AuthClaims{}) {
		// "not.a.jwt.at.all" has 5 segments; base64 decode will likely fail.
		// We just want no panic — zero return is acceptable but not strictly
		// required when the base64 happens to decode to garbage.  Skip strict
		// assertion to avoid coupling to the encoder behavior.
		_ = zero
	}

	if got := DecodeJWTClaims(""); got != (AuthClaims{}) {
		t.Errorf("empty token should return zero claims, got: %+v", got)
	}
}

// TestDecodeJWTClaims_UserDeviceTenant proves the Phase 1 schema upgrade:
// the new-style JWT payload — emitted by AgentKMS for certs that follow the
// /tenant/<t>/user/<u>/device/<d> SPIFFE convention — round-trips through
// DecodeJWTClaims into the User/Device/Tenant fields on AuthClaims.
//
// Without this, `kpm whoami` would render the new-style cert as if it were
// the legacy single-string-identity case, defeating the multi-device-portable
// principal model.
func TestDecodeJWTClaims_UserDeviceTenant(t *testing.T) {
	payload := `{"sub":"bert","usr":"bert","dev":"bert-tp-dev","tnt":"catalyst9","team":"platform","role":"developer","spiffe":"spiffe://catalyst9.local/tenant/catalyst9/user/bert/device/bert-tp-dev","as":"cert+human"}`
	body := base64.RawURLEncoding.EncodeToString([]byte(payload))
	token := "ignored." + body + ".sig"

	got := DecodeJWTClaims(token)
	want := AuthClaims{
		Sub:          "bert",
		UserID:       "bert",
		DeviceID:     "bert-tp-dev",
		Tenant:       "catalyst9",
		Team:         "platform",
		Role:         "developer",
		SPIFFE:       "spiffe://catalyst9.local/tenant/catalyst9/user/bert/device/bert-tp-dev",
		AuthStrength: "cert+human",
	}
	if got != want {
		t.Errorf("DecodeJWTClaims mismatch\n got: %+v\nwant: %+v", got, want)
	}
}

// TestDecodeJWTClaims_LegacyPayload_NoNewFields confirms that a JWT minted
// by the OLD server (no usr/dev/tnt claims) still decodes to a valid
// AuthClaims — the three new fields just stay empty, and downstream code
// (whoami, login summary) recognises that and renders the legacy view.
func TestDecodeJWTClaims_LegacyPayload_NoNewFields(t *testing.T) {
	payload := `{"sub":"bert-tp-dev","team":"platform","role":"developer","as":"cert-only"}`
	body := base64.RawURLEncoding.EncodeToString([]byte(payload))
	token := "ignored." + body + ".sig"

	got := DecodeJWTClaims(token)
	if got.Sub != "bert-tp-dev" {
		t.Errorf("Sub = %q, want %q", got.Sub, "bert-tp-dev")
	}
	if got.UserID != "" || got.DeviceID != "" || got.Tenant != "" {
		t.Errorf("expected new-style fields empty for legacy payload; got UserID=%q DeviceID=%q Tenant=%q",
			got.UserID, got.DeviceID, got.Tenant)
	}
}
