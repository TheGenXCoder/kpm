package kpm

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
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

	// StrictMode enables per-decrypt round-trips to AgentKMS.
	// When true, the listener does not use SessionKey for decryption.
	// Instead, it decodes the KMSReference from the blob and calls
	// AgentKMSClient.FetchByRef on each request.
	StrictMode bool

	// AgentKMSClient is required when StrictMode is true. It is used to
	// fetch secrets from AgentKMS on each decrypt request.
	AgentKMSClient *Client

	listener net.Listener
	mu       sync.Mutex
	closed   bool
}

// Serve starts the UDS listener. Blocks until Close() is called.
func (dl *DecryptListener) Serve() error {
	// Check if Close() was called before Serve() got a chance to run.
	// This can happen when the caller starts Serve in a goroutine and then
	// immediately calls Close() (e.g., due to a test timeout or early failure).
	dl.mu.Lock()
	if dl.closed {
		dl.mu.Unlock()
		return nil
	}
	dl.mu.Unlock()

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
	// Double-check: if Close() was called between our closed check and now,
	// clean up and return.
	if dl.closed {
		dl.mu.Unlock()
		ln.Close()
		os.Remove(dl.SocketPath)
		return nil
	}
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

	// Dispatch on blob tag: ENC[kpm-strict:...] vs ENC[kpm:...]
	if strings.HasPrefix(req.Ciphertext, "ENC[kpm-strict:") {
		dl.handleStrictConn(conn, req.Ciphertext)
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

// handleStrictConn handles a strict-mode decrypt request: decode the KMSReference
// from the blob and round-trip to AgentKMS to fetch the plaintext value.
func (dl *DecryptListener) handleStrictConn(conn net.Conn, blob string) {
	sid, ref, err := ParseStrictBlob(blob)
	if err != nil {
		json.NewEncoder(conn).Encode(DecryptResponse{Error: "invalid strict blob: " + err.Error()})
		return
	}
	if sid != dl.SessionID {
		json.NewEncoder(conn).Encode(DecryptResponse{Error: "session ID mismatch"})
		return
	}

	if dl.AgentKMSClient == nil {
		json.NewEncoder(conn).Encode(DecryptResponse{Error: "strict decrypt failed: no AgentKMS client configured"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	plain, err := dl.AgentKMSClient.FetchByRef(ctx, ref)
	if err != nil {
		errMsg := err.Error()
		// Provide informative error messages for common failure modes
		resp := DecryptResponse{}
		switch {
		case strings.Contains(errMsg, "403") || strings.Contains(errMsg, "forbidden") || strings.Contains(errMsg, "denied") || strings.Contains(errMsg, "policy"):
			resp.Error = "strict decrypt denied by policy: " + errMsg
		default:
			resp.Error = "strict decrypt failed: " + errMsg
		}
		json.NewEncoder(conn).Encode(resp)
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
