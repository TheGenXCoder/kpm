// Package kpm — auth session storage.
//
// This file persists the AgentKMS bearer-token session ("/auth/session"
// response) to disk so that successive kpm commands can reuse a single
// authenticated session instead of POSTing /auth/session on every call.
//
// Storage layout:
//
//	<DataDir>/sessions/current.json   — one active auth session per machine.
//
// File mode is 0600; the parent directory is 0700.  Writes are atomic via
// a tmp-file + os.Rename in the same directory.
//
// This is intentionally separate from the existing run-time "session" concept
// in session.go (which holds a per-`kpm env`/`kpm run` AES key + socket path
// keyed by a random session ID under <DataDir>/sessions/<sid>/).  The two
// namespaces don't collide because the auth session lives at the file
// `sessions/current.json` while run-time sessions live in directories
// `sessions/<sid>/`.

package kpm

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// AuthSession is the persisted representation of an AgentKMS bearer-token
// session.  It is a superset of the /auth/session response body, decorated
// with the absolute expiration time and the decoded JWT identity claims so
// that subsequent commands can answer `kpm whoami` without a network call.
type AuthSession struct {
	// Token is the bearer JWT returned by AgentKMS.  Send as
	// `Authorization: Bearer <token>` on every authenticated request.
	Token string `json:"token"`

	// TokenType is always "Bearer" today.
	TokenType string `json:"token_type"`

	// SessionID is the JWT JTI, used for audit correlation.
	SessionID string `json:"session_id"`

	// ExpiresAt is the absolute UTC expiry time (RFC3339).
	ExpiresAt time.Time `json:"expires_at"`

	// Claims is the decoded identity material from the JWT body.
	Claims AuthClaims `json:"claims"`

	// LastStepUp is the wall time of the most recent successful
	// WebAuthn step-up ("cert+human") for this session.  Used by the
	// client to enforce short-TTL re-auth for privileged operations
	// (admin commands, etc.) in the same way sudo remembers a password.
	LastStepUp time.Time `json:"last_step_up,omitempty"`
}

// AuthClaims captures the identity-shaped JWT claims we need for `kpm whoami`
// and any future policy-aware UX (auth_strength gating, etc.).  We do NOT
// verify the JWT signature client-side — verification is the server's job;
// the client trusts the token because it came over mTLS.
type AuthClaims struct {
	Sub          string `json:"sub,omitempty"`           // CallerID (UserID when known, else cert CN)
	UserID       string `json:"user_id,omitempty"`       // Logical user from SPIFFE /user/<u>
	DeviceID     string `json:"device_id,omitempty"`     // Specific device cert from SPIFFE /device/<d>
	Tenant       string `json:"tenant,omitempty"`        // Tenant from SPIFFE /tenant/<t>
	Team         string `json:"team,omitempty"`          // TeamID
	Role         string `json:"role,omitempty"`          // Role
	SPIFFE       string `json:"spiffe,omitempty"`        // SPIFFE URI (if present)
	AuthStrength string `json:"auth_strength,omitempty"` // "cert-only" or "cert+human"
}

// authSessionPath returns the absolute path to the persisted auth session
// file (<DataDir>/sessions/current.json).
func authSessionPath() string {
	return filepath.Join(SessionsDir(), "current.json")
}

// SaveAuthSession writes the session to disk atomically with mode 0600.
// The parent directory is created with mode 0700 if missing.
func SaveAuthSession(s *AuthSession) error {
	if s == nil {
		return errors.New("nil auth session")
	}
	dir := SessionsDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create sessions dir: %w", err)
	}

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal auth session: %w", err)
	}

	// Atomic write: create tmp file in the same dir, then rename.
	tmp, err := os.CreateTemp(dir, ".current.json.tmp-*")
	if err != nil {
		return fmt.Errorf("create tmp session file: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }

	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("chmod tmp session file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("write tmp session file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close tmp session file: %w", err)
	}
	if err := os.Rename(tmpPath, authSessionPath()); err != nil {
		cleanup()
		return fmt.Errorf("rename tmp session file: %w", err)
	}
	return nil
}

// LoadAuthSession reads the persisted auth session.  If the file does not
// exist, returns (nil, os.ErrNotExist).  If the session has expired, the
// stale file is deleted and (nil, os.ErrNotExist) is returned — callers
// treat "expired" and "absent" identically.
func LoadAuthSession() (*AuthSession, error) {
	path := authSessionPath()
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, os.ErrNotExist
		}
		return nil, fmt.Errorf("read auth session: %w", err)
	}

	var s AuthSession
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse auth session: %w", err)
	}

	// Stale-session detection: treat past-expiry files as "no session".
	if !s.ExpiresAt.IsZero() && time.Now().After(s.ExpiresAt) {
		_ = os.Remove(path)
		return nil, os.ErrNotExist
	}
	return &s, nil
}

// DeleteAuthSession removes the persisted session file.  Absence is not an
// error.
func DeleteAuthSession() error {
	err := os.Remove(authSessionPath())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove auth session: %w", err)
	}
	return nil
}

// DecodeJWTClaims decodes the payload of an unverified JWT and extracts the
// identity claims used by `kpm whoami`.  Signature verification is the
// server's responsibility; the client only needs the bearer claims for
// display purposes.
//
// Token shapes accepted:
//
//	header.payload.sig   — standard 3-segment JWT.  Payload is parts[1].
//	payload.sig          — 2-segment shape used by AgentKMS today (no header,
//	                       trust-domain key chosen out-of-band).  Payload is
//	                       parts[0].
//
// Returns a zero-value AuthClaims on parse failure rather than an error,
// because a token whose claims we can't read is still usable as a bearer —
// we just can't display nice metadata for it.
//
// Field names match AgentKMS's tokens.go: sub/team/role/spiffe/as.
func DecodeJWTClaims(token string) AuthClaims {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return AuthClaims{}
	}

	// Heuristic: a 3-segment JWT has the payload at index 1.  A 2-segment
	// token (AgentKMS's current shape) has it at index 0.  Anything longer
	// (4+) is malformed — try index 1 anyway.
	payloadIdx := 1
	if len(parts) == 2 {
		payloadIdx = 0
	}

	tryDecode := func(s string) ([]byte, bool) {
		if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
			return b, true
		}
		if b, err := base64.StdEncoding.DecodeString(s); err == nil {
			return b, true
		}
		return nil, false
	}

	payload, ok := tryDecode(parts[payloadIdx])
	if !ok {
		return AuthClaims{}
	}

	var raw struct {
		Sub     string `json:"sub"`
		User    string `json:"usr"`
		Device  string `json:"dev"`
		Tenant  string `json:"tnt"`
		Team    string `json:"team"`
		Role    string `json:"role"`
		SPIFFE  string `json:"spiffe"`
		AuthStr string `json:"as"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return AuthClaims{}
	}
	return AuthClaims{
		Sub:          raw.Sub,
		UserID:       raw.User,
		DeviceID:     raw.Device,
		Tenant:       raw.Tenant,
		Team:         raw.Team,
		Role:         raw.Role,
		SPIFFE:       raw.SPIFFE,
		AuthStrength: raw.AuthStr,
	}
}
