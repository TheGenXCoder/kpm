package kpm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// generateSelfSignedCert generates a self-signed CA cert and a client cert/key
// signed by that CA. Returns PEM-encoded CA cert, client cert, client key.
func generateSelfSignedCerts(t *testing.T) (caPEM, certPEM, keyPEM []byte) {
	t.Helper()

	// Generate CA key
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	// Generate client key
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER})

	clientKeyDER, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: clientKeyDER})
	return
}

func TestNewClientMissingCAFile(t *testing.T) {
	_, err := NewClient("https://localhost:8443", "/nonexistent/ca.crt", "/tmp/cert.crt", "/tmp/key.pem")
	if err == nil {
		t.Fatal("expected error for missing CA file")
	}
}

func TestNewClientMissingCertFile(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	os.WriteFile(caPath, []byte("dummy"), 0644)

	_, err := NewClient("https://localhost:8443", caPath, "/nonexistent/cert.crt", "/tmp/key.pem")
	if err == nil {
		t.Fatal("expected error for missing cert file")
	}
}

func TestNewClientMissingKeyFile(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	certPath := filepath.Join(dir, "cert.crt")
	os.WriteFile(caPath, []byte("dummy"), 0644)
	os.WriteFile(certPath, []byte("dummy"), 0644)

	_, err := NewClient("https://localhost:8443", caPath, certPath, "/nonexistent/key.pem")
	if err == nil {
		t.Fatal("expected error for missing key file")
	}
}

func TestNewClientInvalidTLS(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	certPath := filepath.Join(dir, "cert.crt")
	keyPath := filepath.Join(dir, "key.pem")
	// Write invalid PEM data — TLS config construction should fail
	os.WriteFile(caPath, []byte("not a valid cert"), 0644)
	os.WriteFile(certPath, []byte("not a valid cert"), 0644)
	os.WriteFile(keyPath, []byte("not a valid key"), 0644)

	_, err := NewClient("https://localhost:8443", caPath, certPath, keyPath)
	if err == nil {
		t.Fatal("expected error for invalid TLS config")
	}
}

func TestNewClientSuccess(t *testing.T) {
	caPEM, certPEM, keyPEM := generateSelfSignedCerts(t)

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	certPath := filepath.Join(dir, "cert.crt")
	keyPath := filepath.Join(dir, "key.pem")

	os.WriteFile(caPath, caPEM, 0644)
	os.WriteFile(certPath, certPEM, 0644)
	os.WriteFile(keyPath, keyPEM, 0600)

	client, err := NewClient("https://localhost:8443", caPath, certPath, keyPath)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if client.baseURL != "https://localhost:8443" {
		t.Errorf("baseURL = %q, want https://localhost:8443", client.baseURL)
	}
	if client.httpClient == nil {
		t.Error("expected non-nil httpClient")
	}
}

func TestNewClientWithTLS(t *testing.T) {
	// newClientWithTLS is package-internal, verify it via NewClient
	// This also tests the happy path of newClientWithTLS directly
	client := newClientWithTLS("https://example.com:8443", nil)
	if client == nil {
		t.Fatal("newClientWithTLS returned nil")
	}
	if client.baseURL != "https://example.com:8443" {
		t.Errorf("baseURL = %q", client.baseURL)
	}
	if client.httpClient == nil {
		t.Error("httpClient is nil")
	}
	transport, ok := client.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Error("transport is not *http.Transport")
	}
	if transport == nil {
		t.Error("transport is nil")
	}
}
