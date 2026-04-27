// Package kpm — ghapp.go implements the `kpm gh-app` subcommand family.
//
// Subcommands:
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
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
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
  kpm gh-app register <name> --app-id <id> --installation-id <id> --private-key -
  kpm gh-app list
  kpm gh-app inspect <name>
  kpm gh-app remove <name>

Flags:
  --app-id <id>            GitHub App ID (numeric, required for register)
  --installation-id <id>   GitHub App Installation ID (numeric, required for register)
  --private-key -          Read PEM private key from stdin (required for register)

Security:
  The private key PEM is transmitted over the mTLS connection and stored
  encrypted at rest. It is NEVER returned in list, inspect, or any other
  response. Use '--private-key -' to read from stdin — the key is never
  written to disk.

Examples:
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
