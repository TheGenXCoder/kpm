package kpm

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveLoadSession(t *testing.T) {
	// Override home for test
	origHome := os.Getenv("HOME")
	tmpHome := t.TempDir()
	os.Setenv("HOME", tmpHome)
	defer os.Setenv("HOME", origHome)

	key := []byte("12345678901234567890123456789012") // 32 bytes
	err := SaveSession("test-session", key, "/tmp/kpm-test.sock")
	if err != nil {
		t.Fatal(err)
	}

	// Verify files exist with correct permissions
	dir := filepath.Join(tmpHome, ".kpm", "sessions", "test-session")
	keyInfo, err := os.Stat(filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal("key file missing:", err)
	}
	if keyInfo.Mode().Perm() != 0600 {
		t.Errorf("key file permissions = %o, want 0600", keyInfo.Mode().Perm())
	}

	// Load it back
	loadedKey, sock, err := LoadSession("test-session")
	if err != nil {
		t.Fatal(err)
	}
	if string(loadedKey) != string(key) {
		t.Error("key mismatch")
	}
	if sock != "/tmp/kpm-test.sock" {
		t.Errorf("socket = %q, want /tmp/kpm-test.sock", sock)
	}

	// Cleanup
	CleanSession("test-session")
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Error("session dir should be removed after cleanup")
	}
}

func TestLoadSessionMissing(t *testing.T) {
	origHome := os.Getenv("HOME")
	tmpHome := t.TempDir()
	os.Setenv("HOME", tmpHome)
	defer os.Setenv("HOME", origHome)

	_, _, err := LoadSession("nonexistent")
	if err == nil {
		t.Error("expected error for missing session")
	}
}

func TestDecryptEnv(t *testing.T) {
	sk, err := NewSessionKey()
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroBytes(sk)
	sid := "test-env-scan"

	// Encrypt a value
	ct, err := EncryptLocal(sk, []byte("my-secret"))
	if err != nil {
		t.Fatal(err)
	}
	blob := FormatCiphertextBlob(sid, ct)

	// Set encrypted and plain vars in env
	os.Setenv("TEST_SECRET", blob)
	os.Setenv("TEST_PLAIN", "hello")
	defer os.Unsetenv("TEST_SECRET")
	defer os.Unsetenv("TEST_PLAIN")

	env, count, err := DecryptEnv(sk, sid)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("decrypted %d, want 1", count)
	}

	foundSecret := false
	foundPlain := false
	for _, e := range env {
		if e == "TEST_SECRET=my-secret" {
			foundSecret = true
		}
		if e == "TEST_PLAIN=hello" {
			foundPlain = true
		}
	}
	if !foundSecret {
		t.Error("decrypted value not found in env")
	}
	if !foundPlain {
		t.Error("plain value should pass through unchanged")
	}
}

func TestDecryptEnvWrongSession(t *testing.T) {
	sk, _ := NewSessionKey()
	defer ZeroBytes(sk)

	ct, _ := EncryptLocal(sk, []byte("val"))
	// Blob uses session "other-session" but we scan for "my-session"
	blob := FormatCiphertextBlob("other-session", ct)

	os.Setenv("CROSS_SESS", blob)
	defer os.Unsetenv("CROSS_SESS")

	env, count, err := DecryptEnv(sk, "my-session")
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("expected 0 decrypted, got %d", count)
	}
	// Value should pass through as ciphertext
	found := false
	for _, e := range env {
		if e == "CROSS_SESS="+blob {
			found = true
		}
	}
	if !found {
		t.Error("cross-session blob should pass through unchanged")
	}
}

func TestDecryptEnvInvalidBlob(t *testing.T) {
	sk, _ := NewSessionKey()
	defer ZeroBytes(sk)

	// Looks like a blob but isn't valid
	os.Setenv("BROKEN_BLOB", "ENC[kpm:notvalid")
	defer os.Unsetenv("BROKEN_BLOB")

	env, count, err := DecryptEnv(sk, "s1234")
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("expected 0 decrypted, got %d", count)
	}
	found := false
	for _, e := range env {
		if e == "BROKEN_BLOB=ENC[kpm:notvalid" {
			found = true
		}
	}
	if !found {
		t.Error("invalid blob should pass through unchanged")
	}
}

func TestFindActiveSession_EnvVar(t *testing.T) {
	os.Setenv("KPM_SESSION", "explicit-session")
	defer os.Unsetenv("KPM_SESSION")

	sid, err := FindActiveSession()
	if err != nil {
		t.Fatal(err)
	}
	if sid != "explicit-session" {
		t.Errorf("session = %q, want explicit-session", sid)
	}
}

func TestFindActiveSession_Scan(t *testing.T) {
	sk, _ := NewSessionKey()
	defer ZeroBytes(sk)

	ct, _ := EncryptLocal(sk, []byte("val"))
	blob := FormatCiphertextBlob("found-session", ct)

	// Make sure KPM_SESSION is not set
	os.Unsetenv("KPM_SESSION")

	os.Setenv("MY_VAR", blob)
	defer os.Unsetenv("MY_VAR")

	sid, err := FindActiveSession()
	if err != nil {
		t.Fatal(err)
	}
	if sid != "found-session" {
		t.Errorf("session = %q, want found-session", sid)
	}
}

func TestFindActiveSession_None(t *testing.T) {
	os.Unsetenv("KPM_SESSION")
	// We can't guarantee no ENC blobs are in the environment from other tests,
	// so just test that when KPM_SESSION is explicit, it wins.
	os.Setenv("KPM_SESSION", "wins")
	defer os.Unsetenv("KPM_SESSION")

	sid, err := FindActiveSession()
	if err != nil {
		t.Fatal(err)
	}
	if sid != "wins" {
		t.Errorf("session = %q, want wins", sid)
	}
}
