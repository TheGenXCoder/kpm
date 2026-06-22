package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func decryptEndpoint(sessionID string) string {
	if runtime.GOOS == "windows" {
		return fmt.Sprintf("tcp://%s", freeLoopbackAddress())
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("kpm-%s.sock", sessionID))
}

func freeLoopbackAddress() string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		// Fall back to a deterministic high port if ephemeral bind discovery fails;
		// the listener will report a clear bind error if it is unavailable.
		return "127.0.0.1:54931"
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func dialDecryptEndpoint(endpoint string) (net.Conn, error) {
	if strings.HasPrefix(endpoint, "tcp://") {
		return net.Dial("tcp", strings.TrimPrefix(endpoint, "tcp://"))
	}
	return net.Dial("unix", endpoint)
}

func waitForDecryptListener(endpoint string, attempts int, interval time.Duration) {
	for i := 0; i < attempts; i++ {
		conn, err := dialDecryptEndpoint(endpoint)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(interval)
	}
}
