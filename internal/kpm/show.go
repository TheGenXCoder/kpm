package kpm

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ManagedSecret represents a KPM-managed env var found in the current environment.
type ManagedSecret struct {
	Name        string
	SessionID   string
	Encrypted   bool
	BlobPreview string // first ~40 chars of the full blob
}

// ScanManagedSecrets scans os.Environ() for ENC[kpm:...] blobs.
// Returns the list of managed secrets and the session ID found (empty if none).
func ScanManagedSecrets() ([]ManagedSecret, string) {
	var secrets []ManagedSecret
	sessionID := ""

	for _, entry := range os.Environ() {
		eqIdx := strings.IndexByte(entry, '=')
		if eqIdx < 0 {
			continue
		}
		name := entry[:eqIdx]
		value := entry[eqIdx+1:]

		if strings.HasPrefix(value, "ENC[kpm:") {
			sid, _, err := ParseCiphertextBlob(value)
			if err != nil {
				continue
			}
			if sessionID == "" {
				sessionID = sid
			}

			preview := value
			if len(preview) > 40 {
				preview = preview[:40] + "..."
			}

			secrets = append(secrets, ManagedSecret{
				Name:        name,
				SessionID:   sid,
				Encrypted:   true,
				BlobPreview: preview,
			})
		}
	}

	return secrets, sessionID
}

// SessionTTLRemaining returns the remaining TTL for a session by checking the
// mtime of the session key file against the configured TTL. Returns 0 if the
// session is expired or cannot be found.
func SessionTTLRemaining(sessionID string, configuredTTL int) time.Duration {
	home, _ := os.UserHomeDir()
	keyPath := filepath.Join(home, ".kpm", "sessions", sessionID, "key")
	info, err := os.Stat(keyPath)
	if err != nil {
		return 0
	}
	created := info.ModTime()
	expires := created.Add(time.Duration(configuredTTL) * time.Second)
	remaining := time.Until(expires)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// PrintShow displays managed secrets for the `kpm show` command.
// If filterName is non-empty, only that variable is shown in detail.
// Plaintext values are never printed.
func PrintShow(w io.Writer, secrets []ManagedSecret, sessionID string, ttlRemaining time.Duration, filterName string) {
	if len(secrets) == 0 {
		fmt.Fprintln(w, "No KPM-managed secrets found in current environment.")
		fmt.Fprintln(w, "Load secrets with: eval $(kpm env --from <template> --output shell)")
		return
	}

	// Single variable mode
	if filterName != "" {
		for _, s := range secrets {
			if s.Name == filterName {
				fmt.Fprintf(w, "  %-25s ● encrypted\n", s.Name)
				fmt.Fprintf(w, "  Session: %s\n", s.SessionID)
				if ttlRemaining > 0 {
					fmt.Fprintf(w, "  TTL: %s remaining\n", formatShowDuration(ttlRemaining))
				}
				fmt.Fprintf(w, "  Value: %s (use 'kpm run' to decrypt)\n", s.BlobPreview)
				return
			}
		}
		fmt.Fprintf(w, "%s is not a KPM-managed secret in the current environment.\n", filterName)
		return
	}

	// List mode
	ttlStr := ""
	if ttlRemaining > 0 {
		ttlStr = fmt.Sprintf(" (TTL: %s remaining)", formatShowDuration(ttlRemaining))
	}
	fmt.Fprintf(w, "KPM Session: %s%s\n\n", sessionID, ttlStr)

	for _, s := range secrets {
		fmt.Fprintf(w, "  %-25s ● encrypted\n", s.Name)
	}

	fmt.Fprintf(w, "\n%d secrets managed\n", len(secrets))
}

// formatShowDuration formats a duration as "4m32s" or "45s".
func formatShowDuration(d time.Duration) string {
	m := int(d.Minutes())
	s := int(d.Seconds()) % 60
	if m > 0 {
		return fmt.Sprintf("%dm%02ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}
