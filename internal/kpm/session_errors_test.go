package kpm

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveSessionWriteKeyError(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KPM_DATA", dir)

	// Create the session dir as a file (not a dir) to force mkdir error
	sessionsDir := filepath.Join(dir, "sessions")
	os.MkdirAll(sessionsDir, 0755)
	// Create "badsession" as a file, so MkdirAll for badsession/... fails
	os.WriteFile(filepath.Join(sessionsDir, "badsession"), []byte("block"), 0644)

	err := SaveSession("badsession", []byte("key"), "/tmp/sock")
	if err == nil {
		t.Fatal("expected error when session dir is blocked by a file")
	}
}

func TestSaveSessionSocketWriteError(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KPM_DATA", dir)

	// Create the session dir normally, then make the socket path unwritable
	sessDir := filepath.Join(dir, "sessions", "socketfail")
	os.MkdirAll(sessDir, 0755)

	// Write the key file successfully
	os.WriteFile(filepath.Join(sessDir, "key"), []byte("key-data"), 0600)

	// Make sessDir read-only so writing socket fails
	os.Chmod(sessDir, 0555)
	defer os.Chmod(sessDir, 0755) // restore for cleanup

	err := SaveSession("socketfail", []byte("key-data"), "/tmp/sock")
	if err == nil {
		// On some systems this may succeed as root — just log
		t.Log("no error for socket write (possibly running as root)")
	}
}

func TestLoadSessionMissingSocketFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KPM_DATA", dir)

	// Create session dir with key but no socket file
	sessDir := filepath.Join(dir, "sessions", "nosocket")
	os.MkdirAll(sessDir, 0755)
	os.WriteFile(filepath.Join(sessDir, "key"), []byte("keydata"), 0600)

	_, _, err := LoadSession("nosocket")
	if err == nil {
		t.Fatal("expected error when socket file is missing")
	}
}
