// Package kpm — login / logout / whoami commands.
//
// These subcommands are the human-facing UX over the persisted auth session
// storage in auth_session.go.  They are deliberately thin shims over the
// Client's Authenticate / Refresh / RevokeCurrent methods so the bulk of the
// protocol logic stays in one place.

package kpm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// RunLogin implements `kpm login`.  It POSTs /auth/session over mTLS using
// the supplied client, persists the resulting session, and prints a one-line
// summary to stderr.
//
// On any error it returns the error and DOES NOT touch the existing session
// file (so a failed login doesn't kick the user off the still-valid session
// they had before).
func RunLogin(ctx context.Context, stderr io.Writer, client *Client) error {
	sr, err := client.Authenticate(ctx)
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}
	claims := DecodeJWTClaims(sr.Token)
	expiresAt := time.Now().Add(time.Duration(sr.ExpiresIn) * time.Second)

	if err := SaveAuthSession(&AuthSession{
		Token:     sr.Token,
		TokenType: sr.TokenType,
		SessionID: sr.SessionID,
		ExpiresAt: expiresAt,
		Claims:    claims,
	}); err != nil {
		return fmt.Errorf("persist session: %w", err)
	}

	who := claims.Sub
	if who == "" {
		who = "(anonymous)"
	}
	fmt.Fprintf(stderr, "Logged in as %s (session expires in %s, session %s)\n",
		who, formatRemaining(time.Until(expiresAt)), sr.SessionID)
	return nil
}

// RunLogout implements `kpm logout`.  It loads the persisted session, calls
// /auth/revoke (treating 401 as already-revoked), and deletes the local
// session file.  Absence of a session is not an error: it prints
// "Not logged in" and returns nil.
func RunLogout(ctx context.Context, stderr io.Writer, client *Client) error {
	s, err := LoadAuthSession()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintln(stderr, "Not logged in")
			return nil
		}
		return fmt.Errorf("load session: %w", err)
	}

	// Adopt the persisted token on the client so RevokeCurrent uses it.
	client.SetToken(s.Token, s.ExpiresAt)

	revokeErr := client.RevokeCurrent(ctx)
	if revokeErr != nil && !errors.Is(revokeErr, ErrAlreadyRevoked) {
		// Network failure or 5xx — still remove the local session so the
		// user isn't stuck.  Surface the error so they know the server-side
		// state may be inconsistent.
		_ = DeleteAuthSession()
		return fmt.Errorf("revoke session %s: %w", s.SessionID, revokeErr)
	}

	if err := DeleteAuthSession(); err != nil {
		return fmt.Errorf("delete local session: %w", err)
	}

	fmt.Fprintf(stderr, "Logged out (session %s revoked)\n", s.SessionID)
	return nil
}

// RunWhoami implements `kpm whoami`.  Reads the persisted session and prints
// the identity material to stdout.  Returns os.ErrNotExist when there is no
// session (the caller maps that to exit code 1).
func RunWhoami(stdout io.Writer) error {
	s, err := LoadAuthSession()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return os.ErrNotExist
		}
		return fmt.Errorf("load session: %w", err)
	}

	identity := s.Claims.Sub
	if identity == "" {
		identity = "(anonymous)"
	}
	fmt.Fprintf(stdout, "Identity:       %s\n", identity)
	if s.Claims.Team != "" {
		fmt.Fprintf(stdout, "Team:           %s\n", s.Claims.Team)
	}
	if s.Claims.Role != "" {
		fmt.Fprintf(stdout, "Role:           %s\n", s.Claims.Role)
	}
	if s.Claims.SPIFFE != "" {
		fmt.Fprintf(stdout, "SPIFFE:         %s\n", s.Claims.SPIFFE)
	}
	fmt.Fprintf(stdout, "Session ID:     %s\n", s.SessionID)
	fmt.Fprintf(stdout, "Expires in:     %s\n", formatRemaining(time.Until(s.ExpiresAt)))
	if s.Claims.AuthStrength != "" {
		fmt.Fprintf(stdout, "Auth strength:  %s\n", s.Claims.AuthStrength)
	}
	return nil
}

// formatRemaining renders a duration as MM:SS for short windows, or
// "<hours>h<minutes>m" for longer ones.  Negative durations clamp to 00:00.
func formatRemaining(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	totalSeconds := int(d.Seconds())
	hours := totalSeconds / 3600
	minutes := (totalSeconds % 3600) / 60
	seconds := totalSeconds % 60
	if hours > 0 {
		return fmt.Sprintf("%dh%02dm", hours, minutes)
	}
	return fmt.Sprintf("%02d:%02d", minutes, seconds)
}
