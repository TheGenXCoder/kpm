// Package kpm — enroll.go implements `kpm enroll <bootstrap-token>`.
//
// The enroll command generates a local ECDSA P-256 keypair, builds a CSR,
// and POSTs it to /auth/cert/issue along with the bootstrap token.  On
// success it writes the private key, leaf cert, and CA chain to
// ~/.kpm/certs/ (or the XDG-equivalent path returned by CertsDir).
//
// The private key NEVER leaves this machine.

package kpm

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// ── wire types ────────────────────────────────────────────────────────────────

// CertIssueRequest is the POST /auth/cert/issue body.
// Exported so tests can construct it.
type CertIssueRequest struct {
	CSR            string `json:"csr"`
	DeviceName     string `json:"device_name"`
	BootstrapToken string `json:"bootstrap_token,omitempty"`
}

// certIssueRequest is an alias kept for internal callers.
type certIssueRequest = CertIssueRequest

// CertIssueResponse is the 200 body from POST /auth/cert/issue.
// Exported so tests can construct it.
type CertIssueResponse struct {
	Cert      string   `json:"cert"`
	CAChain   []string `json:"ca_chain"`
	Serial    string   `json:"serial"`
	ExpiresAt string   `json:"expires_at"`
}

// ── RunEnroll ─────────────────────────────────────────────────────────────────

// EnrollClient is the subset of Client used by RunEnroll.
// Tests inject a stub implementation.
type EnrollClient interface {
	IssueCert(ctx context.Context, req CertIssueRequest) (*CertIssueResponse, error)
}

// ClientEnrollAdapter adapts *Client to EnrollClient.
// Exported so external test packages can use it.
type ClientEnrollAdapter struct{ C *Client }

func (e *ClientEnrollAdapter) IssueCert(ctx context.Context, req CertIssueRequest) (*CertIssueResponse, error) {
	return e.C.IssueCert(ctx, req)
}

// RunEnroll implements `kpm enroll <bootstrap-token>`.
// Returns 0 on success, non-zero on error.
//
// Signature is designed to be testable: stdout/stderr are io.Writers,
// certsDir is injected so tests can use a temp dir, and the EnrollClient
// is injected so tests can mock the HTTP layer.
func RunEnroll(
	ctx context.Context,
	stdout, stderr io.Writer,
	client EnrollClient,
	certsDir string,
	cfg *Config,
	args []string,
) int {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	fs.SetOutput(stderr)
	deviceFlag := fs.String("device", "", "device name (default: hostname)")
	forceFlag := fs.Bool("force", false, "overwrite existing key without refusing")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintln(stderr, "error: bootstrap token required\nusage: kpm enroll <bootstrap-token> [--device <name>]")
		return 1
	}
	bootstrapToken := rest[0]

	// Resolve device name.
	deviceName := *deviceFlag
	if deviceName == "" {
		h, err := os.Hostname()
		if err != nil {
			fmt.Fprintf(stderr, "error: cannot determine hostname: %v\n", err)
			return 1
		}
		deviceName = h
	}

	// Resolve trust domain and tenant from config.
	trustDomain := "catalyst9.local"
	tenant := ""
	if cfg != nil {
		if cfg.TrustDomain != "" {
			trustDomain = cfg.TrustDomain
		}
		if cfg.Tenant != "" {
			tenant = cfg.Tenant
		}
	}

	// Guard: refuse to overwrite existing key unless --force.
	keyPath := filepath.Join(certsDir, "client.key")
	if !*forceFlag {
		if _, err := os.Stat(keyPath); err == nil {
			fmt.Fprintln(stderr, "error: client.key already exists — use --force to overwrite")
			return 1
		}
	}

	// Generate ECDSA P-256 keypair.
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Fprintf(stderr, "error: generate key: %v\n", err)
		return 1
	}

	// Build CSR subject and SAN URI.
	// SAN URI = spiffe://<trust-domain>/tenant/<tenant>/user/<user>/device/<device>
	// The user component is unknown until the server validates the bootstrap token,
	// so we use "self" as a placeholder; the server extracts the real user from the
	// bootstrap record and stamps the issued cert accordingly.
	sanURI := buildSPIFFEURI(trustDomain, tenant, deviceName)

	csrTemplate := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: deviceName},
		URIs:     mustParseURIs(sanURI),
		DNSNames: nil,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privKey)
	if err != nil {
		fmt.Fprintf(stderr, "error: create CSR: %v\n", err)
		return 1
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	// POST /auth/cert/issue.
	issueResp, err := client.IssueCert(ctx, certIssueRequest{
		CSR:            string(csrPEM),
		DeviceName:     deviceName,
		BootstrapToken: bootstrapToken,
	})
	if err != nil {
		// Translate well-known server error codes to user-friendly messages.
		msg := err.Error()
		switch {
		case strings.Contains(msg, "409") || strings.Contains(msg, "already enrolled"):
			fmt.Fprintf(stderr,
				"error: device %q already enrolled — use 'kpm device list' to inspect or 'kpm device revoke' to replace\n",
				deviceName)
		case strings.Contains(msg, "401") || strings.Contains(msg, "bootstrap token"):
			fmt.Fprintln(stderr, "error: bootstrap token invalid or already used — request a new one from your operator")
		default:
			fmt.Fprintf(stderr, "error: %v\n", err)
		}
		return 1
	}

	// Write files.
	if err := os.MkdirAll(certsDir, 0700); err != nil {
		fmt.Fprintf(stderr, "error: create certs dir: %v\n", err)
		return 1
	}

	// Private key → 0600, never overwrites without --force (already guarded above).
	privDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		fmt.Fprintf(stderr, "error: marshal private key: %v\n", err)
		return 1
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})
	if err := atomicWriteFile(keyPath, keyPEM, 0600); err != nil {
		fmt.Fprintf(stderr, "error: write private key: %v\n", err)
		return 1
	}

	// Leaf cert → 0644.
	certPath := filepath.Join(certsDir, "client.crt")
	if err := atomicWriteFile(certPath, []byte(issueResp.Cert), 0644); err != nil {
		fmt.Fprintf(stderr, "error: write cert: %v\n", err)
		return 1
	}

	// CA chain → 0644, append-only (don't replace existing CAs).
	caPath := filepath.Join(certsDir, "ca.crt")
	if err := appendCACerts(caPath, issueResp.CAChain); err != nil {
		fmt.Fprintf(stderr, "error: write CA chain: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "Enrolled device %s: serial=%s, expires=%s\n",
		deviceName, issueResp.Serial, issueResp.ExpiresAt)
	return 0
}

// ── Client method ─────────────────────────────────────────────────────────────

// IssueCert calls POST /auth/cert/issue.
// Uses the session bearer token if present; the bootstrap token is in the body.
func (c *Client) IssueCert(ctx context.Context, req CertIssueRequest) (*CertIssueResponse, error) {
	// For the enroll path we may not have a session yet — send the request
	// without ensureAuth so the bootstrap_token in the body is the sole
	// credential.  If the client already has a session token (self-add path)
	// include it via the normal Authorization header.
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(req); err != nil {
		return nil, fmt.Errorf("encode issue request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/auth/cert/issue", &buf)
	if err != nil {
		return nil, fmt.Errorf("build issue request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("issue cert: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, serverError(resp, "issue cert")
	}

	var out CertIssueResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode issue response: %w", err)
	}
	return &out, nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

// buildSPIFFEURI constructs the SPIFFE SAN URI.
// spiffe://<trust-domain>/tenant/<tenant>/user/self/device/<device>
// We use "self" for the user component because the server stamps the real
// user from the bootstrap record; the CSR user is advisory only.
func buildSPIFFEURI(trustDomain, tenant, device string) string {
	var b strings.Builder
	b.WriteString("spiffe://")
	b.WriteString(trustDomain)
	if tenant != "" {
		b.WriteString("/tenant/")
		b.WriteString(tenant)
	}
	b.WriteString("/user/self/device/")
	b.WriteString(device)
	return b.String()
}

func mustParseURIs(uris ...string) []*url.URL {
	out := make([]*url.URL, 0, len(uris))
	for _, u := range uris {
		parsed, err := url.Parse(u)
		if err != nil {
			panic(fmt.Sprintf("invalid URI %q: %v", u, err))
		}
		out = append(out, parsed)
	}
	return out
}

// appendCACerts appends any new PEM blocks in newChain to caPath.
// If the file doesn't exist it is created.  Existing blocks are preserved.
func appendCACerts(caPath string, newChain []string) error {
	// Read existing content (empty if file absent).
	existing, _ := os.ReadFile(caPath)

	var toAppend []byte
	for _, ca := range newChain {
		if len(bytes.TrimSpace([]byte(ca))) == 0 {
			continue
		}
		// Don't duplicate blocks already in the file.
		if bytes.Contains(existing, bytes.TrimSpace([]byte(ca))) {
			continue
		}
		toAppend = append(toAppend, []byte(ca)...)
		if !bytes.HasSuffix([]byte(ca), []byte("\n")) {
			toAppend = append(toAppend, '\n')
		}
	}

	if len(toAppend) == 0 && len(existing) > 0 {
		return nil // nothing new to add
	}

	combined := append(existing, toAppend...)
	return atomicWriteFile(caPath, combined, 0644)
}

// atomicWriteFile writes data to path atomically (tmp + rename) with the
// given file mode.
func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".kpm-tmp-*")
	if err != nil {
		return fmt.Errorf("create tmp: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }

	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		cleanup()
		return err
	}
	return nil
}
