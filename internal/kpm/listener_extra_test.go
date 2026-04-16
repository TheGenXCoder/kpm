package kpm

import (
	"encoding/json"
	"net"
	"os"
	"testing"
	"time"
)

func startListener(t *testing.T, sessionID string, ttl time.Duration) (*DecryptListener, []byte, string) {
	t.Helper()
	sk, _ := NewSessionKey()
	t.Cleanup(func() { ZeroBytes(sk) })

	sockPath := shortSockPath(t, "kpm-extra.sock")
	dl := &DecryptListener{
		SocketPath: sockPath,
		SessionKey: sk,
		SessionID:  sessionID,
		ExpiresAt:  time.Now().Add(ttl),
	}
	go dl.Serve()

	// Wait for socket to appear
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(sockPath); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	return dl, sk, sockPath
}

func dialAndRequest(t *testing.T, sockPath string, req interface{}) DecryptResponse {
	t.Helper()
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	json.NewEncoder(conn).Encode(req)
	var resp DecryptResponse
	json.NewDecoder(conn).Decode(&resp)
	return resp
}

func TestHandleConnInvalidJSON(t *testing.T) {
	dl, _, sockPath := startListener(t, "test-session", 5*time.Minute)
	defer dl.Close()

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Send invalid JSON
	conn.Write([]byte("{not valid json\n"))

	var resp DecryptResponse
	json.NewDecoder(conn).Decode(&resp)
	if resp.Error == "" {
		t.Error("expected error for invalid JSON request")
	}
}

func TestHandleConnInvalidCiphertextFormat(t *testing.T) {
	dl, _, sockPath := startListener(t, "test-session", 5*time.Minute)
	defer dl.Close()

	resp := dialAndRequest(t, sockPath, DecryptRequest{
		Ciphertext: "this-is-not-a-valid-blob",
	})
	if resp.Error == "" {
		t.Error("expected error for invalid ciphertext format")
	}
}

func TestHandleConnSessionIDMismatch(t *testing.T) {
	dl, sk, sockPath := startListener(t, "correct-session", 5*time.Minute)
	defer dl.Close()

	// Encrypt with the correct key but tag with wrong session ID
	ct, _ := EncryptLocal(sk, []byte("secret"))
	blob := FormatCiphertextBlob("wrong-session-id", ct)

	resp := dialAndRequest(t, sockPath, DecryptRequest{Ciphertext: blob})
	if resp.Error == "" {
		t.Error("expected session ID mismatch error")
	}
}

func TestHandleConnDecryptFailure(t *testing.T) {
	dl, _, sockPath := startListener(t, "test-session", 5*time.Minute)
	defer dl.Close()

	// Encrypt with a DIFFERENT key, but tag with correct session ID
	wrongKey, _ := NewSessionKey()
	defer ZeroBytes(wrongKey)
	ct, _ := EncryptLocal(wrongKey, []byte("secret"))
	blob := FormatCiphertextBlob("test-session", ct)

	resp := dialAndRequest(t, sockPath, DecryptRequest{Ciphertext: blob})
	if resp.Error == "" {
		t.Error("expected decrypt failure error")
	}
}
