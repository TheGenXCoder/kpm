// Package tlsutil provides TLS configuration helpers.
package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
)

// ClientTLSConfig builds a strict tls.Config for client connections (e.g. to Vault).
//
// Like server-side mTLS configs, it enforces TLS 1.3 as the minimum version.
// It configures the provided client cert/key for mutual TLS authentication
// and verifies the server's certificate against the provided CA bundle.
//
// Parameters:
//   - caCertPEM: PEM-encoded CA certificate(s) to verify the server against.
//   - clientCertPEM, clientKeyPEM: PEM-encoded leaf certificate and private key.
func ClientTLSConfig(caCertPEM, clientCertPEM, clientKeyPEM []byte) (*tls.Config, error) {
	// 1. Build the CA pool for verifying the server.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCertPEM) {
		return nil, errors.New("tlsutil: failed to parse root CA certificates")
	}

	// 2. Parse the client's mTLS certificate.
	cert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("tlsutil: parse client key pair: %w", err)
	}

	// 3. Construct the config with strict defaults.
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      pool,
		Certificates: []tls.Certificate{cert},
	}
	return cfg, nil
}
