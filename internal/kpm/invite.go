package kpm

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const invitePrefix = "kpmi1_"

// InvitePayload is the decoded kpmi1 invite code (must match agentkms/internal/invite).
type InvitePayload struct {
	Version       int    `json:"v"`
	ServerURL     string `json:"url"`
	CAFingerprint string `json:"ca_fp"`
	Token         string `json:"token"`
	UserID        string `json:"user,omitempty"`
	Tenant        string `json:"tenant,omitempty"`
	ExpiresAt     int64  `json:"exp"`
}

// DecodeInvite parses a kpmi1 invite code.
func DecodeInvite(code string) (InvitePayload, error) {
	code = strings.TrimSpace(code)
	if !strings.HasPrefix(code, invitePrefix) {
		return InvitePayload{}, fmt.Errorf("expected invite code starting with %q", invitePrefix)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(code, invitePrefix))
	if err != nil {
		return InvitePayload{}, fmt.Errorf("decode invite: %w", err)
	}
	var p InvitePayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return InvitePayload{}, fmt.Errorf("parse invite: %w", err)
	}
	if p.Version != 1 || p.ServerURL == "" || p.CAFingerprint == "" || p.Token == "" {
		return InvitePayload{}, fmt.Errorf("invalid invite payload")
	}
	if p.ExpiresAt > 0 && time.Now().UTC().After(time.Unix(p.ExpiresAt, 0)) {
		return InvitePayload{}, fmt.Errorf("invite code expired")
	}
	return p, nil
}

// IsInviteCode returns true if s looks like a kpmi1 invite code.
func IsInviteCode(s string) bool {
	return strings.HasPrefix(strings.TrimSpace(s), invitePrefix)
}
