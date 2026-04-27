// Package kpm — ghapp.go implements the `kpm gh-app` subcommand family.
//
// Subcommands:
//
//	kpm gh-app new <name> [--homepage URL] [--permissions secrets+actions]
//	    Interactive walkthrough that guides the user through GitHub App creation,
//	    captures App ID, Installation ID, and private key, verifies credentials
//	    via a test token mint, then calls the register flow to store everything.
//
//	kpm gh-app register <name> --app-id <id> --installation-id <id> --private-key -
//	    Registers a GitHub App installation with AgentKMS.
//	    --private-key - reads the PEM from stdin; never written to disk.
//
//	kpm gh-app list
//	    Lists registered GitHub App installations (name, app_id, installation_id).
//	    Private key is never returned.
//
//	kpm gh-app inspect <name>
//	    Shows details for a single GitHub App installation.
//	    Private key is never returned.
//
//	kpm gh-app remove <name>
//	    Removes a registered GitHub App installation.
//
// All subcommands communicate with AgentKMS over the existing mTLS Client.

package kpm

import (
	"bufio"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// ── RunGhApp — top-level dispatcher ──────────────────────────────────────────

// RunGhApp dispatches `kpm gh-app <subcommand> [args...]`.
// It is the entry point called from cmd/kpm/main.go.
func RunGhApp(ctx context.Context, w io.Writer, errW io.Writer, client *Client, args []string) int {
	if len(args) == 0 {
		fmt.Fprint(errW, ghAppUsage)
		return 1
	}
	sub := args[0]
	rest := args[1:]

	switch sub {
	case "new":
		return RunGhAppNew(ctx, w, errW, client, rest, nil)
	case "register":
		return runGhAppRegister(ctx, w, errW, client, rest)
	case "list":
		return runGhAppList(ctx, w, errW, client, rest)
	case "inspect":
		return runGhAppInspect(ctx, w, errW, client, rest)
	case "remove":
		return runGhAppRemove(ctx, w, errW, client, rest)
	case "help", "--help", "-h":
		fmt.Fprint(errW, ghAppUsage)
		return 0
	default:
		fmt.Fprintf(errW, "kpm gh-app: unknown subcommand %q\n\n%s", sub, ghAppUsage)
		return 1
	}
}

const ghAppUsage = `kpm gh-app — manage GitHub App installations in AgentKMS

Usage:
  kpm gh-app new <name> [--homepage URL] [--permissions secrets+actions]
  kpm gh-app register <name> --app-id <id> --installation-id <id> --private-key -
  kpm gh-app list
  kpm gh-app inspect <name>
  kpm gh-app remove <name>

Flags:
  --app-id <id>            GitHub App ID (numeric, required for register)
  --installation-id <id>   GitHub App Installation ID (numeric, required for register)
  --private-key -          Read PEM private key from stdin (required for register)
  --homepage <url>         Homepage URL for new subcommand (default: https://github.com)
  --permissions <list>     Comma-separated permissions for new subcommand (default: secrets+actions)

Security:
  The private key PEM is transmitted over the mTLS connection and stored
  encrypted at rest. It is NEVER returned in list, inspect, or any other
  response. Use '--private-key -' to read from stdin — the key is never
  written to disk.

Examples:
  # Interactive first-time setup (recommended)
  kpm gh-app new agentkms-blog-audit-rotator --homepage https://blog.catalyst9.ai

  # Register a GitHub App (pipe key from kpm registry)
  kpm get github/blog-audit-app/private-key | \
    kpm gh-app register agentkms-blog-audit-rotator \
      --app-id 3512662 \
      --installation-id 127321567 \
      --private-key -

  # List all registered GitHub Apps
  kpm gh-app list

  # Inspect a specific GitHub App
  kpm gh-app inspect agentkms-blog-audit-rotator

  # Remove a GitHub App registration
  kpm gh-app remove agentkms-blog-audit-rotator
`

// ── gh-app new ────────────────────────────────────────────────────────────────

// GhAppNewDeps groups the injectable dependencies used by RunGhAppNew.
// Production callers pass nil to get the real defaults; tests inject stubs.
type GhAppNewDeps struct {
	// Stdin is read for all interactive prompts. Defaults to os.Stdin.
	Stdin io.Reader

	// OpenBrowser launches the URL in the system browser.
	// If nil, the platform default (open/xdg-open/cmd start) is used.
	// Return a non-nil error to signal failure; RunGhAppNew treats browser
	// failure as non-fatal and prints the URL for manual use.
	OpenBrowser func(url string) error

	// GlobPEM returns paths matching the given glob pattern.
	// Defaults to filepath.Glob.
	GlobPEM func(pattern string) ([]string, error)

	// GitHubTransport is used for the optional verification token mint.
	// Defaults to http.DefaultTransport. Tests inject an httptest.Server transport.
	GitHubTransport http.RoundTripper
}

// defaultDeps fills in nil fields with production defaults.
func defaultDeps(d *GhAppNewDeps) GhAppNewDeps {
	if d == nil {
		d = &GhAppNewDeps{}
	}
	out := *d
	if out.Stdin == nil {
		out.Stdin = os.Stdin
	}
	if out.OpenBrowser == nil {
		out.OpenBrowser = openBrowserDefault
	}
	if out.GlobPEM == nil {
		out.GlobPEM = filepath.Glob
	}
	if out.GitHubTransport == nil {
		out.GitHubTransport = http.DefaultTransport
	}
	return out
}

// openBrowserDefault launches a URL using the OS-appropriate command.
func openBrowserDefault(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Run()
}

// RunGhAppNew implements the interactive `kpm gh-app new <name>` walkthrough.
//
// It guides the user through creating a GitHub App registration, capturing the
// App ID, private key, and Installation ID, verifying them via a test token
// mint, then storing everything via the existing RegisterGithubApp flow.
//
// deps may be nil (production callers always pass nil). Tests inject stubs.
func RunGhAppNew(ctx context.Context, w io.Writer, errW io.Writer, client *Client, args []string, deps *GhAppNewDeps) int {
	d := defaultDeps(deps)

	// ── parse flags ───────────────────────────────────────────────────────────
	var name string
	var flagArgs []string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		name = args[0]
		flagArgs = args[1:]
	} else {
		flagArgs = args
	}

	fs := flag.NewFlagSet("gh-app new", flag.ContinueOnError)
	fs.SetOutput(errW)
	homepageFlag := fs.String("homepage", "https://github.com", "Homepage URL shown in the form instructions")
	permissionsFlag := fs.String("permissions", "secrets+actions", "Comma-separated permissions to request")

	if err := fs.Parse(flagArgs); err != nil {
		return 1
	}
	if name == "" {
		pos := fs.Args()
		if len(pos) < 1 {
			fmt.Fprintln(errW, "kpm gh-app new: app name is required")
			fmt.Fprintf(errW, "usage: kpm gh-app new <name> [--homepage URL]\n")
			return 1
		}
		name = pos[0]
	}

	homepage := *homepageFlag
	permissions := *permissionsFlag

	scanner := bufio.NewScanner(d.Stdin)

	// ── step 1: open browser ──────────────────────────────────────────────────
	const ghNewAppURL = "https://github.com/settings/apps/new"
	fmt.Fprintln(errW)
	fmt.Fprintln(errW, "==> Step 1 of 5: open the GitHub App creation page")
	fmt.Fprintln(errW)
	fmt.Fprintf(errW, "  Opening %s ...\n", ghNewAppURL)
	fmt.Fprintln(errW)

	if err := d.OpenBrowser(ghNewAppURL); err != nil {
		fmt.Fprintln(errW, "  (browser did not open automatically — paste the URL above into your browser)")
	}

	// ── step 2: form instructions ─────────────────────────────────────────────
	fmt.Fprintln(errW, "==> Step 2 of 5: fill the form")
	fmt.Fprintln(errW)
	fmt.Fprintf(errW, "  Name:                 %s\n", name)
	fmt.Fprintln(errW, "                        (copy-paste the name above into the \"GitHub App name\" field)")
	fmt.Fprintln(errW)
	fmt.Fprintf(errW, "  Homepage URL:         %s\n", homepage)
	fmt.Fprintln(errW, "                        (anything works — GitHub doesn't validate)")
	fmt.Fprintln(errW)
	fmt.Fprintln(errW, "  Webhook → Active:     UNCHECK")
	fmt.Fprintln(errW, "                        (no webhooks needed for rotation)")
	fmt.Fprintln(errW)

	// Parse and display permissions
	perms := strings.Split(permissions, "+")
	fmt.Fprintln(errW, "  Permissions → Repository:")
	for _, p := range perms {
		switch strings.TrimSpace(p) {
		case "secrets":
			fmt.Fprintln(errW, "    Secrets:            Read and write    (REQUIRED)")
		case "actions":
			fmt.Fprintln(errW, "    Actions:            Read and write    (recommended; enables verification)")
		default:
			fmt.Fprintf(errW, "    %s:            Read and write\n", p)
		}
	}
	fmt.Fprintln(errW)
	fmt.Fprintln(errW, "  Where can this be installed?")
	fmt.Fprintln(errW, "                        Only on this account")
	fmt.Fprintln(errW)
	fmt.Fprintln(errW, "  Click \"Create GitHub App\" at the bottom.")
	fmt.Fprintln(errW)
	fmt.Fprintln(errW, "  Press Enter when the App is created and you're on the App settings")
	fmt.Fprintln(errW, "  page (you'll see \"App ID\" near the top of the page)...")

	scanner.Scan()

	// ── step 3: App ID ────────────────────────────────────────────────────────
	fmt.Fprintln(errW)
	fmt.Fprintln(errW, "==> Step 3 of 5: capture the App ID")
	fmt.Fprintln(errW)
	fmt.Fprintln(errW, "  The App ID is shown near the top of the App settings page,")
	fmt.Fprintln(errW, "  labeled \"App ID:\" — it's a numeric value, typically 6-7 digits.")
	fmt.Fprintln(errW)

	var appID int64
	for {
		fmt.Fprint(errW, "  Paste the App ID: ")
		if !scanner.Scan() {
			fmt.Fprintln(errW, "\nkpm gh-app new: unexpected end of input")
			return 1
		}
		raw := strings.TrimSpace(scanner.Text())
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n <= 0 {
			fmt.Fprintf(errW, "  Invalid App ID %q — must be a positive integer. Try again.\n", raw)
			continue
		}
		appID = n
		break
	}

	// ── step 4: private key ───────────────────────────────────────────────────
	fmt.Fprintln(errW)
	fmt.Fprintln(errW, "==> Step 4 of 5: generate and capture the private key")
	fmt.Fprintln(errW)
	fmt.Fprintln(errW, "  Still on the App settings page, scroll down to \"Private keys\" and")
	fmt.Fprintln(errW, "  click \"Generate a private key\". A .pem file will download")
	fmt.Fprintln(errW, "  automatically (one-time download).")
	fmt.Fprintln(errW)
	fmt.Fprintln(errW, "  We'll auto-detect it from your Downloads folder. If you saved it")
	fmt.Fprintln(errW, "  elsewhere, you can specify the path manually.")
	fmt.Fprintln(errW)
	fmt.Fprintln(errW, "  Press Enter when the .pem file has finished downloading...")

	scanner.Scan()

	pemPath, code := detectPEMFile(errW, scanner, d.GlobPEM)
	if code != 0 {
		return code
	}

	pemBytes, err := os.ReadFile(pemPath)
	if err != nil {
		fmt.Fprintf(errW, "error reading PEM file %s: %v\n", pemPath, err)
		return 1
	}
	pemBytes = []byte(strings.TrimSpace(string(pemBytes)))

	// ── step 5: Installation ID ───────────────────────────────────────────────
	fmt.Fprintln(errW)
	fmt.Fprintln(errW, "==> Step 5 of 5: install the App on a repository")
	fmt.Fprintln(errW)
	fmt.Fprintln(errW, "  In the App settings page sidebar, click \"Install App\".")
	fmt.Fprintln(errW)
	fmt.Fprintln(errW, "  Click \"Install\" next to your account, then \"Only select repositories\"")
	fmt.Fprintln(errW, "  and pick the repo this App should rotate credentials for.")
	fmt.Fprintln(errW)
	fmt.Fprintln(errW, "  After installation, you'll be redirected to:")
	fmt.Fprintln(errW)
	fmt.Fprintln(errW, "    https://github.com/settings/installations/<INSTALLATION_ID>")
	fmt.Fprintln(errW)
	fmt.Fprintln(errW, "  The Installation ID is the last segment of that URL.")
	fmt.Fprintln(errW)

	var installationID int64
	for {
		fmt.Fprint(errW, "  Paste the Installation ID: ")
		if !scanner.Scan() {
			fmt.Fprintln(errW, "\nkpm gh-app new: unexpected end of input")
			return 1
		}
		raw := strings.TrimSpace(scanner.Text())
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n <= 0 {
			fmt.Fprintf(errW, "  Invalid Installation ID %q — must be a positive integer. Try again.\n", raw)
			continue
		}
		installationID = n
		break
	}

	// ── optional verification: mint a test installation token ─────────────────
	fmt.Fprintln(errW)
	fmt.Fprintln(errW, "==> Verifying credentials...")
	fmt.Fprintln(errW)

	// Re-prompt loop for app ID / installation ID if verification fails.
	for {
		permissions, err := verifyGitHubAppInstallation(ctx, appID, installationID, pemBytes, d.GitHubTransport)
		if err != nil {
			fmt.Fprintf(errW, "  error: %v\n", err)
			fmt.Fprintln(errW)
			fmt.Fprintln(errW, "  Most common causes:")
			fmt.Fprintln(errW, "    - App ID typo (double-check the number on the App settings page)")
			fmt.Fprintln(errW, "    - Installation ID typo (check the URL after installing)")
			fmt.Fprintln(errW, "    - App was installed on the wrong account/repo")
			fmt.Fprintln(errW)
			fmt.Fprint(errW, "  Re-enter App ID and Installation ID? [Y/n]: ")
			if !scanner.Scan() {
				return 1
			}
			resp := strings.TrimSpace(strings.ToLower(scanner.Text()))
			if resp != "" && resp != "y" && resp != "yes" {
				saveInputsToTmp(name, appID, installationID)
				fmt.Fprintf(errW, "\n  Your inputs were saved to /tmp/agentkms-gh-app-%s.json\n", name)
				fmt.Fprintf(errW, "  Retry later with:\n")
				fmt.Fprintf(errW, "    kpm gh-app register %s --app-id %d --installation-id %d --private-key -\n", name, appID, installationID)
				return 1
			}

			// Re-prompt App ID
			for {
				fmt.Fprint(errW, "  Paste the App ID: ")
				if !scanner.Scan() {
					return 1
				}
				raw := strings.TrimSpace(scanner.Text())
				n, parseErr := strconv.ParseInt(raw, 10, 64)
				if parseErr != nil || n <= 0 {
					fmt.Fprintf(errW, "  Invalid App ID %q — must be a positive integer. Try again.\n", raw)
					continue
				}
				appID = n
				break
			}

			// Re-prompt Installation ID
			for {
				fmt.Fprint(errW, "  Paste the Installation ID: ")
				if !scanner.Scan() {
					return 1
				}
				raw := strings.TrimSpace(scanner.Text())
				n, parseErr := strconv.ParseInt(raw, 10, 64)
				if parseErr != nil || n <= 0 {
					fmt.Fprintf(errW, "  Invalid Installation ID %q — must be a positive integer. Try again.\n", raw)
					continue
				}
				installationID = n
				break
			}
			continue
		}

		// Verification succeeded.
		fmt.Fprintf(errW, "  Token minted (App ID %d, install %d)\n", appID, installationID)
		if len(permissions) > 0 {
			parts := make([]string, 0, len(permissions))
			for k, v := range permissions {
				parts = append(parts, k+"="+v)
			}
			fmt.Fprintf(errW, "  Permissions: %s\n", strings.Join(parts, ", "))
		}
		break
	}

	// ── register with AgentKMS ─────────────────────────────────────────────────
	fmt.Fprintln(errW)
	fmt.Fprintln(errW, "==> Registering with AgentKMS")
	fmt.Fprintln(errW)

	req := RegisterGithubAppRequest{
		Name:           name,
		AppID:          appID,
		InstallationID: installationID,
		PrivateKeyPEM:  pemBytes,
	}

	summary, regErr := client.RegisterGithubApp(ctx, req)
	if regErr != nil {
		saveInputsToTmp(name, appID, installationID)
		fmt.Fprintf(errW, "  error: %v\n", regErr)
		fmt.Fprintln(errW)
		fmt.Fprintf(errW, "  Your inputs were saved to /tmp/agentkms-gh-app-%s.json\n", name)
		fmt.Fprintf(errW, "  Retry later with:\n")
		fmt.Fprintf(errW, "    kpm gh-app register %s --app-id %d --installation-id %d --private-key -\n", name, appID, installationID)
		return 1
	}

	fmt.Fprintf(errW, "  Registered %q\n", summary.Name)
	fmt.Fprintf(errW, "    App ID:           %d\n", summary.AppID)
	fmt.Fprintf(errW, "    Installation ID:  %d\n", summary.InstallationID)
	fmt.Fprintln(errW, "    Private key:      stored (encrypted at rest)")

	fmt.Fprintln(errW)
	fmt.Fprintln(errW, "==> Done. Next step:")
	fmt.Fprintln(errW)
	fmt.Fprintf(errW, "    kpm cred register <binding-name> \\\n")
	fmt.Fprintf(errW, "      --github-app %s \\\n", name)
	fmt.Fprintf(errW, "      --target <owner>/<repo>:<SECRET_NAME>\n")
	fmt.Fprintln(errW)

	// Single "ready" line to stdout (machine-parseable signal).
	fmt.Fprintf(w, "ready app=%s app_id=%d installation_id=%d\n", summary.Name, summary.AppID, summary.InstallationID)
	return 0
}

// detectPEMFile auto-detects the downloaded private key from ~/Downloads, or
// prompts the user to supply an explicit path.
func detectPEMFile(errW io.Writer, scanner *bufio.Scanner, globFn func(string) ([]string, error)) (string, int) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = ""
	}

	var candidates []string
	if homeDir != "" {
		pattern := filepath.Join(homeDir, "Downloads", "*.private-key.pem")
		candidates, _ = globFn(pattern)
	}

	switch len(candidates) {
	case 0:
		// No auto-detected files — prompt for explicit path.
		fmt.Fprintln(errW, "  No .private-key.pem files found in ~/Downloads.")
		fmt.Fprint(errW, "  Enter the path to the .pem file: ")
		if !scanner.Scan() {
			fmt.Fprintln(errW, "\nkpm gh-app new: unexpected end of input")
			return "", 1
		}
		return strings.TrimSpace(scanner.Text()), 0

	case 1:
		// Exactly one match — confirm with user.
		fmt.Fprintf(errW, "  Found: %s\n", candidates[0])
		fmt.Fprint(errW, "  Use this file? [Y/n]: ")
		if !scanner.Scan() {
			fmt.Fprintln(errW, "\nkpm gh-app new: unexpected end of input")
			return "", 1
		}
		resp := strings.TrimSpace(strings.ToLower(scanner.Text()))
		if resp == "" || resp == "y" || resp == "yes" {
			return candidates[0], 0
		}
		fmt.Fprint(errW, "  Enter the path to the .pem file: ")
		if !scanner.Scan() {
			return "", 1
		}
		return strings.TrimSpace(scanner.Text()), 0

	default:
		// Multiple matches — let user pick.
		fmt.Fprintln(errW, "  Multiple .pem files found in ~/Downloads:")
		for i, p := range candidates {
			fmt.Fprintf(errW, "    [%d] %s\n", i+1, p)
		}
		fmt.Fprintf(errW, "  Enter number (1-%d) or full path: ", len(candidates))
		if !scanner.Scan() {
			fmt.Fprintln(errW, "\nkpm gh-app new: unexpected end of input")
			return "", 1
		}
		raw := strings.TrimSpace(scanner.Text())
		// Try numeric index first.
		if idx, parseErr := strconv.Atoi(raw); parseErr == nil && idx >= 1 && idx <= len(candidates) {
			return candidates[idx-1], 0
		}
		// Fall back to treating input as an explicit path.
		return raw, 0
	}
}

// saveInputsToTmp writes a JSON file with the captured values so the user can
// retry with `kpm gh-app register` if registration fails.
func saveInputsToTmp(name string, appID, installationID int64) {
	path := fmt.Sprintf("/tmp/agentkms-gh-app-%s.json", name)
	data := map[string]any{
		"name":            name,
		"app_id":          appID,
		"installation_id": installationID,
		"saved_at":        time.Now().UTC().Format(time.RFC3339),
	}
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile(path, b, 0600) //nolint:errcheck
}

// verifyGitHubAppInstallation mints a GitHub App installation access token to
// confirm that the App ID, Installation ID, and PEM are all correct.
//
// It constructs a GitHub App JWT using RS256 (stdlib crypto/rsa only — no
// external JWT package), then POSTs to the GitHub API to obtain an
// installation token. The token is discarded immediately; it is never stored.
//
// On success it returns the permissions map from the token response.
// On failure it returns a descriptive error.
func verifyGitHubAppInstallation(ctx context.Context, appID, installationID int64, pemBytes []byte, transport http.RoundTripper) (map[string]string, error) {
	privateKey, err := parseRSAPrivateKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	jwt, err := mintGitHubAppJWT(appID, privateKey)
	if err != nil {
		return nil, fmt.Errorf("mint JWT: %w", err)
	}

	url := fmt.Sprintf("https://api.github.com/app/installations/%d/access_tokens", installationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	httpClient := &http.Client{
		Timeout:   15 * time.Second,
		Transport: transport,
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GitHub API request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		var ghErr struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(body, &ghErr) == nil && ghErr.Message != "" {
			return nil, fmt.Errorf("GitHub API returned %d: %s", resp.StatusCode, ghErr.Message)
		}
		return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var tokenResp struct {
		Token       string            `json:"token"`
		Permissions map[string]string `json:"permissions"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	// The token is discarded here — never stored.
	return tokenResp.Permissions, nil
}

// parseRSAPrivateKey decodes a PEM-encoded RSA private key (PKCS#1 or PKCS#8).
func parseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		// PKCS#1
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		// PKCS#8
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 key is not RSA")
		}
		return rsaKey, nil
	default:
		return nil, fmt.Errorf("unsupported PEM type %q (expected RSA PRIVATE KEY)", block.Type)
	}
}

// mintGitHubAppJWT creates a GitHub App JWT signed with RS256 using stdlib only.
//
// GitHub requires:
//   - iat: current time - 60 seconds (to account for clock skew)
//   - exp: iat + 10 minutes (maximum allowed)
//   - iss: App ID as string
//   - alg: RS256
func mintGitHubAppJWT(appID int64, key *rsa.PrivateKey) (string, error) {
	now := time.Now().Unix()
	iat := now - 60
	exp := iat + 600

	// Header: {"alg":"RS256","typ":"JWT"}
	headerJSON := `{"alg":"RS256","typ":"JWT"}`
	// Payload
	payloadJSON := fmt.Sprintf(`{"iat":%d,"exp":%d,"iss":"%d"}`, iat, exp, appID)

	enc := base64.RawURLEncoding
	headerB64 := enc.EncodeToString([]byte(headerJSON))
	payloadB64 := enc.EncodeToString([]byte(payloadJSON))

	signingInput := headerB64 + "." + payloadB64

	// Sign with RS256 = PKCS1v15 + SHA-256
	h := sha256.New()
	h.Write([]byte(signingInput))
	digest := h.Sum(nil)

	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
	if err != nil {
		return "", fmt.Errorf("sign JWT: %w", err)
	}

	return signingInput + "." + enc.EncodeToString(sig), nil
}

// ── register ──────────────────────────────────────────────────────────────────

func runGhAppRegister(ctx context.Context, w io.Writer, errW io.Writer, client *Client, args []string) int {
	// Extract name (first non-flag arg) before flag.Parse.
	var name string
	var flagArgs []string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		name = args[0]
		flagArgs = args[1:]
	} else {
		flagArgs = args
	}

	fs := flag.NewFlagSet("gh-app register", flag.ContinueOnError)
	fs.SetOutput(errW)
	appIDFlag := fs.Int64("app-id", 0, "GitHub App ID (required)")
	installationIDFlag := fs.Int64("installation-id", 0, "GitHub App Installation ID (required)")
	privateKeyFlag := fs.String("private-key", "", "PEM private key source: '-' reads from stdin (required)")

	if err := fs.Parse(flagArgs); err != nil {
		return 1
	}

	// Name may also appear after flags.
	if name == "" {
		pos := fs.Args()
		if len(pos) < 1 {
			fmt.Fprintln(errW, "kpm gh-app register: app name is required")
			fmt.Fprint(errW, ghAppUsage)
			return 1
		}
		name = pos[0]
	}

	if *appIDFlag == 0 {
		fmt.Fprintln(errW, "kpm gh-app register: --app-id is required")
		return 1
	}
	if *installationIDFlag == 0 {
		fmt.Fprintln(errW, "kpm gh-app register: --installation-id is required")
		return 1
	}
	if *privateKeyFlag == "" {
		fmt.Fprintln(errW, "kpm gh-app register: --private-key is required (use '-' to read from stdin)")
		return 1
	}
	if *privateKeyFlag != "-" {
		// Only stdin is supported; reject filesystem paths to avoid accidental
		// key exposure through shell history.
		fmt.Fprintln(errW, "kpm gh-app register: --private-key must be '-' (stdin); filesystem paths are not supported")
		fmt.Fprintln(errW, "  Pipe the key: kpm get github/<app>/private-key | kpm gh-app register <name> --private-key -")
		return 1
	}

	// Read PEM from stdin. The caller (cmd/kpm/main.go) owns os.Stdin.
	// In tests, pipe content to os.Stdin before calling this function.
	pemBytes, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(errW, "kpm gh-app register: error reading private key from stdin: %v\n", err)
		return 1
	}
	pemBytes = []byte(strings.TrimSpace(string(pemBytes)))
	if len(pemBytes) == 0 {
		fmt.Fprintln(errW, "kpm gh-app register: private key from stdin is empty")
		return 1
	}

	req := RegisterGithubAppRequest{
		Name:           name,
		AppID:          *appIDFlag,
		InstallationID: *installationIDFlag,
		PrivateKeyPEM:  pemBytes,
	}

	summary, regErr := client.RegisterGithubApp(ctx, req)
	if regErr != nil {
		fmt.Fprintf(errW, "error: %v\n", regErr)
		return 1
	}

	fmt.Fprintf(w, "Registered GitHub App %q\n", summary.Name)
	fmt.Fprintf(w, "  App ID:          %d\n", summary.AppID)
	fmt.Fprintf(w, "  Installation ID: %d\n", summary.InstallationID)
	fmt.Fprintln(w, "  Private key:     [stored encrypted, not retrievable]")
	return 0
}

// ── list ──────────────────────────────────────────────────────────────────────

func runGhAppList(ctx context.Context, w io.Writer, errW io.Writer, client *Client, args []string) int {
	fs := flag.NewFlagSet("gh-app list", flag.ContinueOnError)
	fs.SetOutput(errW)
	jsonFlag := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return 1
	}

	apps, err := client.ListGithubApps(ctx)
	if err != nil {
		fmt.Fprintf(errW, "error: %v\n", err)
		return 1
	}

	if *jsonFlag {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(apps) //nolint:errcheck
		return 0
	}

	if len(apps) == 0 {
		fmt.Fprintln(w, "No GitHub App registrations found. Add one with: kpm gh-app register <name> --app-id <id> --installation-id <id> --private-key -")
		return 0
	}

	fmt.Fprintf(w, "%-40s %-14s %s\n", "NAME", "APP ID", "INSTALLATION ID")
	fmt.Fprintf(w, "%s\n", strings.Repeat("-", 70))
	for _, a := range apps {
		fmt.Fprintf(w, "%-40s %-14d %d\n", a.Name, a.AppID, a.InstallationID)
	}
	fmt.Fprintf(w, "\n%d app(s)\n", len(apps))
	return 0
}

// ── inspect ───────────────────────────────────────────────────────────────────

func runGhAppInspect(ctx context.Context, w io.Writer, errW io.Writer, client *Client, args []string) int {
	var name string
	var flagArgs []string
	for _, a := range args {
		if name == "" && !strings.HasPrefix(a, "-") {
			name = a
		} else {
			flagArgs = append(flagArgs, a)
		}
	}

	fs := flag.NewFlagSet("gh-app inspect", flag.ContinueOnError)
	fs.SetOutput(errW)
	jsonFlag := fs.Bool("json", false, "output raw JSON")
	if err := fs.Parse(flagArgs); err != nil {
		return 1
	}

	if name == "" {
		fmt.Fprintln(errW, "kpm gh-app inspect: app name is required")
		return 1
	}

	app, err := client.GetGithubApp(ctx, name)
	if err != nil {
		fmt.Fprintf(errW, "error: %v\n", err)
		return 1
	}

	if *jsonFlag {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(app) //nolint:errcheck
		return 0
	}

	fmt.Fprintf(w, "GitHub App: %s\n", app.Name)
	fmt.Fprintf(w, "  App ID:          %d\n", app.AppID)
	fmt.Fprintf(w, "  Installation ID: %d\n", app.InstallationID)
	fmt.Fprintln(w, "  Private key:     [stored encrypted, not retrievable]")
	return 0
}

// ── remove ────────────────────────────────────────────────────────────────────

func runGhAppRemove(ctx context.Context, w io.Writer, errW io.Writer, client *Client, args []string) int {
	var name string
	var flagArgs []string
	for _, a := range args {
		if name == "" && !strings.HasPrefix(a, "-") {
			name = a
		} else {
			flagArgs = append(flagArgs, a)
		}
	}

	fs := flag.NewFlagSet("gh-app remove", flag.ContinueOnError)
	fs.SetOutput(errW)
	if err := fs.Parse(flagArgs); err != nil {
		return 1
	}

	if name == "" {
		fmt.Fprintln(errW, "kpm gh-app remove: app name is required")
		return 1
	}

	if err := client.RemoveGithubApp(ctx, name); err != nil {
		fmt.Fprintf(errW, "error: %v\n", err)
		return 1
	}

	fmt.Fprintf(w, "Removed GitHub App %q\n", name)
	return 0
}
