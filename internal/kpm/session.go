package kpm

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SessionDir returns the session directory for a given session ID.
// Uses XDG-compliant SessionsDir() — see paths.go.
func SessionDir(sessionID string) string {
	return filepath.Join(SessionsDir(), sessionID)
}

// SaveSession persists session key and socket path for later use by kpm run.
func SaveSession(sessionID string, key []byte, socketPath string) error {
	dir := SessionDir(sessionID)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create session dir: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "key"), key, 0600); err != nil {
		return fmt.Errorf("write session key: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "socket"), []byte(socketPath), 0600); err != nil {
		return fmt.Errorf("write socket path: %w", err)
	}
	return nil
}

// LoadSession reads a persisted session.
func LoadSession(sessionID string) (key []byte, socketPath string, err error) {
	dir := SessionDir(sessionID)
	key, err = os.ReadFile(filepath.Join(dir, "key"))
	if err != nil {
		return nil, "", fmt.Errorf("read session key: %w", err)
	}
	sockBytes, err := os.ReadFile(filepath.Join(dir, "socket"))
	if err != nil {
		return nil, "", fmt.Errorf("read socket path: %w", err)
	}
	return key, string(sockBytes), nil
}

// CleanSession removes a persisted session directory.
func CleanSession(sessionID string) {
	dir := SessionDir(sessionID)
	os.RemoveAll(dir)
}

// FindActiveSession looks for KPM_SESSION env var, or scans env for the first
// ENC[kpm:...] blob to extract a session ID.
func FindActiveSession() (string, error) {
	// Check for explicit session ID hint
	if sid := os.Getenv("KPM_SESSION"); sid != "" {
		return sid, nil
	}
	// Scan env for first ENC blob to extract session ID
	for _, entry := range os.Environ() {
		eqIdx := strings.IndexByte(entry, '=')
		if eqIdx < 0 {
			continue
		}
		value := entry[eqIdx+1:]
		if strings.HasPrefix(value, "ENC[kpm:") {
			sid, _, err := ParseCiphertextBlob(value)
			if err == nil {
				return sid, nil
			}
		}
	}
	return "", fmt.Errorf("no active KPM session found (no KPM_SESSION env var and no ENC[kpm:...] blobs in environment)")
}

// DecryptEnv scans the current environment for ENC[kpm:...] ciphertext blobs,
// decrypts each one using the provided session key, and returns a clean env
// with plaintext values replacing ciphertext.
func DecryptEnv(sessionKey []byte, sessionID string) ([]string, int, error) {
	env := os.Environ()
	result := make([]string, 0, len(env))
	decrypted := 0

	for _, entry := range env {
		eqIdx := strings.IndexByte(entry, '=')
		if eqIdx < 0 {
			result = append(result, entry)
			continue
		}
		key := entry[:eqIdx]
		value := entry[eqIdx+1:]

		if strings.HasPrefix(value, "ENC[kpm:") {
			sid, ct, err := ParseCiphertextBlob(value)
			if err != nil {
				// Not a valid blob — pass through as-is
				result = append(result, entry)
				continue
			}
			if sid != sessionID {
				// Different session — pass through
				result = append(result, entry)
				continue
			}
			plain, err := DecryptLocal(sessionKey, ct)
			if err != nil {
				return nil, 0, fmt.Errorf("decrypt %s: %w", key, err)
			}
			result = append(result, key+"="+string(plain))
			ZeroBytes(plain)
			decrypted++
		} else {
			result = append(result, entry)
		}
	}

	return result, decrypted, nil
}
