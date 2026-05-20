// Package kpm — device.go implements `kpm device list` and `kpm device revoke`.
//
// Subcommands:
//
//	kpm device list [--json]
//	    GET /auth/cert/list and render a table.  The row matching this
//	    machine's client cert serial is annotated "<- this device".
//
//	kpm device revoke <device-name> [--yes] [--allow-self]
//	    POST /auth/certificate/revoke with {device_name: <name>}.
//	    Refuses to self-revoke without --allow-self.

package kpm

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
)

// ── wire types ────────────────────────────────────────────────────────────────

// DeviceCertEntry is one row in the GET /auth/cert/list response.
type DeviceCertEntry struct {
	DeviceName string `json:"device_name"`
	Serial     string `json:"serial"`
	SPIFFE     string `json:"spiffe"`
	IssuedAt   string `json:"issued_at"`
	ExpiresAt  string `json:"expires_at"`
	Revoked    bool   `json:"revoked"`
}

// certListResponse is the GET /auth/cert/list body.
type certListResponse struct {
	Certs []DeviceCertEntry `json:"certs"`
}

// CertRevokeRequest is the POST /auth/certificate/revoke body.
// Exported so tests can use it.
type CertRevokeRequest struct {
	Serial     string `json:"serial,omitempty"`
	DeviceName string `json:"device_name,omitempty"`
}

// certRevokeRequest is an alias for internal callers.
type certRevokeRequest = CertRevokeRequest

// ── DeviceClient interface ────────────────────────────────────────────────────

// DeviceClient is the subset of Client used by device subcommands.
// Tests inject a stub implementation.
type DeviceClient interface {
	ListCerts(ctx context.Context) ([]DeviceCertEntry, error)
	RevokeCert(ctx context.Context, req CertRevokeRequest) error
}

// clientDevice adapts *Client to DeviceClient.
type clientDevice struct{ c *Client }

func (d *clientDevice) ListCerts(ctx context.Context) ([]DeviceCertEntry, error) {
	return d.c.ListCerts(ctx)
}
func (d *clientDevice) RevokeCert(ctx context.Context, req CertRevokeRequest) error {
	return d.c.RevokeCert(ctx, req)
}

// ── RunDevice — top-level dispatcher ─────────────────────────────────────────

// RunDevice dispatches `kpm device <subcommand> [args...]`.
// Returns an exit code; 0 = success.
func RunDevice(ctx context.Context, stdout, stderr io.Writer, client *Client, certsDir string, args []string) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, deviceUsage)
		return 1
	}
	sub := args[0]
	rest := args[1:]

	dc := &clientDevice{c: client}

	switch sub {
	case "list":
		return runDeviceList(ctx, stdout, stderr, dc, certsDir, rest)
	case "revoke":
		return runDeviceRevoke(ctx, stdout, stderr, dc, certsDir, rest)
	case "help", "--help", "-h":
		fmt.Fprint(stderr, deviceUsage)
		return 0
	default:
		fmt.Fprintf(stderr, "kpm device: unknown subcommand %q\n\n%s", sub, deviceUsage)
		return 1
	}
}

const deviceUsage = `kpm device — manage enrolled device certificates

Subcommands:
  list [--json]                  List all enrolled devices for this account
  revoke <device-name> [flags]   Revoke a device certificate

Flags for list:
  --json    Machine-readable JSON output

Flags for revoke:
  --yes          Skip confirmation prompt
  --allow-self   Allow revoking the device you are currently using (footgun)
`

// ── kpm device list ───────────────────────────────────────────────────────────

// RunDeviceList implements `kpm device list`.
// Exported so tests in external packages can call it directly.
func RunDeviceList(ctx context.Context, stdout, stderr io.Writer, client DeviceClient, certsDir string, args []string) int {
	return runDeviceList(ctx, stdout, stderr, client, certsDir, args)
}

func runDeviceList(ctx context.Context, stdout, stderr io.Writer, client DeviceClient, certsDir string, args []string) int {
	fs := flag.NewFlagSet("device list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonFlag := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return 1
	}

	certs, err := client.ListCerts(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	// Determine current device serial from the client cert on disk.
	thisSerial := readThisDeviceSerial(certsDir)

	if *jsonFlag {
		type jsonRow struct {
			DeviceCertEntry
			ThisDevice bool `json:"this_device"`
		}
		rows := make([]jsonRow, len(certs))
		for i, c := range certs {
			rows[i] = jsonRow{
				DeviceCertEntry: c,
				ThisDevice:      thisSerial != "" && strings.EqualFold(c.Serial, thisSerial),
			}
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rows); err != nil {
			fmt.Fprintf(stderr, "error: encode json: %v\n", err)
			return 1
		}
		return 0
	}

	// Human table.
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "DEVICE\tSERIAL\tISSUED\tEXPIRES\tSTATUS\t")
	for _, cert := range certs {
		status := "active"
		if cert.Revoked {
			status = "revoked"
		}
		marker := ""
		if thisSerial != "" && strings.EqualFold(cert.Serial, thisSerial) {
			marker = "<- this device"
		}
		issuedShort := shortDate(cert.IssuedAt)
		expiresShort := shortDate(cert.ExpiresAt)
		serialShort := cert.Serial
		if len(serialShort) > 10 {
			serialShort = serialShort[:10] + "..."
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			cert.DeviceName, serialShort, issuedShort, expiresShort, status, marker)
	}
	tw.Flush()
	return 0
}

// shortDate trims RFC3339/ISO timestamps to YYYY-MM-DD for the table.
func shortDate(ts string) string {
	if len(ts) >= 10 {
		return ts[:10]
	}
	return ts
}

// readThisDeviceSerial reads the serial from ~/.kpm/certs/client.crt.
// Returns "" if the file is absent or unparsable — callers treat that
// as "we don't know which device is this one".
func readThisDeviceSerial(certsDir string) string {
	certPath := filepath.Join(certsDir, "client.crt")
	data, err := os.ReadFile(certPath)
	if err != nil {
		return ""
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%X", cert.SerialNumber)
}

// ── kpm device revoke ─────────────────────────────────────────────────────────

// RunDeviceRevoke implements `kpm device revoke`.
// Exported so tests in external packages can call it directly.
func RunDeviceRevoke(ctx context.Context, stdout, stderr io.Writer, client DeviceClient, certsDir string, args []string) int {
	return runDeviceRevoke(ctx, stdout, stderr, client, certsDir, args)
}

func runDeviceRevoke(ctx context.Context, stdout, stderr io.Writer, client DeviceClient, certsDir string, args []string) int {
	fs := flag.NewFlagSet("device revoke", flag.ContinueOnError)
	fs.SetOutput(stderr)
	yesFlag := fs.Bool("yes", false, "skip confirmation")
	allowSelfFlag := fs.Bool("allow-self", false, "allow revoking the device you are currently using")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if fs.NArg() == 0 {
		fmt.Fprintln(stderr, "error: device name required\nusage: kpm device revoke <device-name>")
		return 1
	}
	targetDevice := fs.Arg(0)

	// Look up the device in the list to get its serial (for confirmation message
	// and self-check).
	certs, err := client.ListCerts(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "error: list certs: %v\n", err)
		return 1
	}

	var target *DeviceCertEntry
	for i := range certs {
		if strings.EqualFold(certs[i].DeviceName, targetDevice) {
			target = &certs[i]
			break
		}
	}
	if target == nil {
		fmt.Fprintf(stderr, "error: device %q not found\n", targetDevice)
		return 1
	}

	// Self-revoke check.
	thisSerial := readThisDeviceSerial(certsDir)
	if thisSerial != "" && strings.EqualFold(target.Serial, thisSerial) && !*allowSelfFlag {
		fmt.Fprintf(stderr,
			"error: %q is the device you are currently using — add --allow-self to revoke it anyway\n",
			targetDevice)
		return 1
	}

	// Confirmation prompt.
	if !*yesFlag {
		fmt.Fprintf(stdout, "Revoke device %q (serial %s)? [y/N] ", targetDevice, target.Serial)
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		answer := strings.TrimSpace(strings.ToLower(scanner.Text()))
		if answer != "y" && answer != "yes" {
			fmt.Fprintln(stdout, "aborted")
			return 1
		}
	}

	if err := client.RevokeCert(ctx, certRevokeRequest{DeviceName: targetDevice}); err != nil {
		msg := err.Error()
		if strings.Contains(msg, "401") || strings.Contains(msg, "unauthorized") {
			fmt.Fprintln(stderr, "error: revoke requires step-up — run 'kpm login --step-up' first")
		} else {
			fmt.Fprintf(stderr, "error: %v\n", err)
		}
		return 1
	}

	fmt.Fprintf(stdout, "Revoked device %q (serial %s)\n", targetDevice, target.Serial)
	return 0
}

// ── Client methods ────────────────────────────────────────────────────────────

// ListCerts calls GET /auth/cert/list.
func (c *Client) ListCerts(ctx context.Context) ([]DeviceCertEntry, error) {
	resp, err := c.doGet(ctx, c.baseURL+"/auth/cert/list")
	if err != nil {
		return nil, fmt.Errorf("list certs: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, serverError(resp, "list certs")
	}

	var body certListResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode cert list: %w", err)
	}
	return body.Certs, nil
}

// RevokeCert calls POST /auth/certificate/revoke.
func (c *Client) RevokeCert(ctx context.Context, req CertRevokeRequest) error {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(req); err != nil {
		return fmt.Errorf("encode revoke request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/auth/certificate/revoke", &buf)
	if err != nil {
		return fmt.Errorf("build revoke request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if err := c.ensureAuth(ctx); err != nil {
		return err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("revoke cert: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK {
		return nil
	}
	return serverError(resp, "revoke cert")
}
