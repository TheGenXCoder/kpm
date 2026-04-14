package kpm

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

// DecryptRequest is the JSON request sent to the UDS listener.
type DecryptRequest struct {
	Ciphertext string `json:"ciphertext"`
}

// DecryptResponse is the JSON response from the UDS listener.
type DecryptResponse struct {
	Plaintext string `json:"plaintext,omitempty"`
	Error     string `json:"error,omitempty"`
}

// DecryptListener serves JIT decrypt requests over a Unix domain socket.
type DecryptListener struct {
	SocketPath string
	SessionKey []byte
	SessionID  string
	ExpiresAt  time.Time

	listener net.Listener
	mu       sync.Mutex
	closed   bool
}

// Serve starts the UDS listener. Blocks until Close() is called.
func (dl *DecryptListener) Serve() error {
	os.Remove(dl.SocketPath)

	ln, err := net.Listen("unix", dl.SocketPath)
	if err != nil {
		return fmt.Errorf("listen %s: %w", dl.SocketPath, err)
	}

	if err := os.Chmod(dl.SocketPath, 0600); err != nil {
		ln.Close()
		return fmt.Errorf("chmod socket: %w", err)
	}

	dl.mu.Lock()
	dl.listener = ln
	dl.mu.Unlock()

	for {
		conn, err := ln.Accept()
		if err != nil {
			dl.mu.Lock()
			wasClosed := dl.closed
			dl.mu.Unlock()
			if wasClosed {
				return nil
			}
			continue
		}
		go dl.handleConn(conn)
	}
}

func (dl *DecryptListener) handleConn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	var req DecryptRequest
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		json.NewEncoder(conn).Encode(DecryptResponse{Error: "invalid request"})
		return
	}

	if time.Now().After(dl.ExpiresAt) {
		json.NewEncoder(conn).Encode(DecryptResponse{Error: "session expired"})
		return
	}

	sid, ct, err := ParseCiphertextBlob(req.Ciphertext)
	if err != nil {
		json.NewEncoder(conn).Encode(DecryptResponse{Error: "invalid ciphertext format"})
		return
	}
	if sid != dl.SessionID {
		json.NewEncoder(conn).Encode(DecryptResponse{Error: "session ID mismatch"})
		return
	}

	plain, err := DecryptLocal(dl.SessionKey, ct)
	if err != nil {
		json.NewEncoder(conn).Encode(DecryptResponse{Error: "decrypt failed"})
		return
	}
	defer ZeroBytes(plain)

	json.NewEncoder(conn).Encode(DecryptResponse{Plaintext: string(plain)})
}

// Close stops the listener and removes the socket file.
func (dl *DecryptListener) Close() {
	dl.mu.Lock()
	dl.closed = true
	if dl.listener != nil {
		dl.listener.Close()
	}
	dl.mu.Unlock()
	os.Remove(dl.SocketPath)
}
