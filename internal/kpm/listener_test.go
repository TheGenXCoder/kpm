package kpm

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// shortSockPath returns a socket path guaranteed to be within the OS limit
// (macOS: 104 bytes). It prefers t.TempDir() but falls back to /tmp.
func shortSockPath(t *testing.T, name string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if len(p) <= 104 {
		return p
	}
	// Fall back to /tmp with a unique suffix derived from test name.
	p = fmt.Sprintf("/tmp/kpm-test-%d-%s", os.Getpid(), name)
	t.Cleanup(func() { os.Remove(p) })
	return p
}

func TestDecryptListener(t *testing.T) {
	sk, err := NewSessionKey()
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroBytes(sk)

	ct, err := EncryptLocal(sk, []byte("my-secret"))
	if err != nil {
		t.Fatal(err)
	}
	blob := FormatCiphertextBlob("test-session", ct)

	sockPath := shortSockPath(t, "kpm-test.sock")
	dl := &DecryptListener{
		SocketPath: sockPath,
		SessionKey: sk,
		SessionID:  "test-session",
		ExpiresAt:  time.Now().Add(5 * time.Minute),
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- dl.Serve()
	}()

	// Wait for socket.
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(sockPath); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}

	req := DecryptRequest{Ciphertext: blob}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatal(err)
	}

	var resp DecryptResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	conn.Close()

	if resp.Error != "" {
		t.Fatalf("decrypt error: %s", resp.Error)
	}
	if resp.Plaintext != "my-secret" {
		t.Errorf("plaintext = %q, want my-secret", resp.Plaintext)
	}

	dl.Close()
}

func TestDecryptListenerExpired(t *testing.T) {
	sk, _ := NewSessionKey()
	defer ZeroBytes(sk)

	ct, _ := EncryptLocal(sk, []byte("test"))
	blob := FormatCiphertextBlob("sess", ct)

	sockPath := shortSockPath(t, "kpm-expired.sock")
	dl := &DecryptListener{
		SocketPath: sockPath,
		SessionKey: sk,
		SessionID:  "sess",
		ExpiresAt:  time.Now().Add(-1 * time.Minute),
	}

	go dl.Serve()
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(sockPath); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	json.NewEncoder(conn).Encode(DecryptRequest{Ciphertext: blob})

	var resp DecryptResponse
	json.NewDecoder(conn).Decode(&resp)
	conn.Close()
	dl.Close()

	if resp.Error == "" {
		t.Error("expected error for expired session")
	}
}
