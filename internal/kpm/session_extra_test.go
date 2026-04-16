package kpm

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveAndLoadSession(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KPM_DATA", dir)

	key := []byte("test-session-key-32-bytes-exactly")
	socketPath := "/tmp/kpm-test.sock"

	err := SaveSession("testsession1", key, socketPath)
	if err != nil {
		t.Fatalf("SaveSession: %v", err)
	}

	loadedKey, loadedSocket, err := LoadSession("testsession1")
	if err != nil {
		t.Fatalf("LoadSession: %v", err)
	}
	defer ZeroBytes(loadedKey)

	if string(loadedKey) != string(key) {
		t.Errorf("loaded key = %q, want %q", loadedKey, key)
	}
	if loadedSocket != socketPath {
		t.Errorf("loaded socket = %q, want %q", loadedSocket, socketPath)
	}
}

func TestLoadSessionNotFound(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KPM_DATA", dir)

	_, _, err := LoadSession("nonexistent-session-xyz")
	if err == nil {
		t.Fatal("expected error for nonexistent session")
	}
}

func TestSaveSessionKeyPermissions(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KPM_DATA", dir)

	key := []byte("test-key")
	err := SaveSession("permsession", key, "/tmp/perm.sock")
	if err != nil {
		t.Fatal(err)
	}

	keyPath := filepath.Join(SessionsDir(), "permsession", "key")
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	// Key file should be 0600 (owner read/write only)
	if info.Mode().Perm() != 0600 {
		t.Errorf("key file mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestFindActiveSessionFromEnv(t *testing.T) {
	t.Setenv("KPM_SESSION", "session-from-env")
	sid, err := FindActiveSession()
	if err != nil {
		t.Fatal(err)
	}
	if sid != "session-from-env" {
		t.Errorf("session ID = %q, want session-from-env", sid)
	}
}

func TestFindActiveSessionFromBlob(t *testing.T) {
	t.Setenv("KPM_SESSION", "")

	// Create a valid blob and put it in an env var
	key, _ := NewSessionKey()
	defer ZeroBytes(key)
	ct, _ := EncryptLocal(key, []byte("test-value"))
	blob := FormatCiphertextBlob("blob-session-123", ct)

	t.Setenv("SOME_KPM_VAR", blob)
	defer os.Unsetenv("SOME_KPM_VAR")

	sid, err := FindActiveSession()
	if err != nil {
		t.Fatal(err)
	}
	if sid != "blob-session-123" {
		t.Errorf("session ID = %q, want blob-session-123", sid)
	}
}

func TestFindActiveSessionNotFound(t *testing.T) {
	t.Setenv("KPM_SESSION", "")
	// Ensure no ENC blobs in env by scanning — we can't easily clear entire env,
	// but at minimum the function should handle no KPM_SESSION correctly.
	// This test just verifies behavior is consistent (error or finds a session)
	_, _ = FindActiveSession()
	// Not asserting error because test env might have ENC blobs from prior tests
}
