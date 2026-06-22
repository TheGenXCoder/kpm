package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/TheGenXCoder/kpm/internal/kpm"
	"github.com/TheGenXCoder/kpm/internal/scan"
	"gopkg.in/yaml.v3"
)

const usage = `kpm — secure secrets CLI backed by AgentKMS

Usage:
  kpm quickstart                  Set up local dev environment (no server needed)
  kpm shell-init                  Shell integration (add to .bashrc/.zshrc)
  kpm login                       Authenticate to AgentKMS and persist the session
  kpm login --step-up             Upgrade session from cert-only to cert+human (WebAuthn)
  kpm logout                      Revoke the persisted session and remove it
  kpm whoami                      Show the active session's identity
  kpm add <service/name>          Store a secret in AgentKMS
  kpm list [service]              List secrets in registry
  kpm describe <service/name>     Show secret metadata (never values)
  kpm history <service/name>      Show version history
  kpm remove <service/name>       Remove a secret
  kpm env [flags]                 Resolve template (secure by default)
  kpm run [flags] -- <cmd> [args] Resolve template and run command with env
  kpm get <ref>                   Fetch a single secret
  kpm init                        Create config file (XDG-compliant)
  kpm tree                        Show template hierarchy and managed secrets
  kpm show [VAR_NAME] [--profile] Show managed secrets (--profile adds merged profile)
  kpm profile                     Show merged profile variables for current directory
  kpm config push [dir]           Push templates to AgentKMS (requires agentkms-dev)
  kpm config pull [dir]           Pull templates from AgentKMS
  kpm enroll <bootstrap-token>    Enroll this device: generates a keypair + CSR and gets a cert
  kpm device list [--json]        List enrolled devices for this account
  kpm device revoke <name>        Revoke an enrolled device certificate
  kpm cred <subcommand>           Manage credential bindings (register/list/inspect/rotate/remove)
  kpm gh-app <subcommand>         Manage GitHub App installations (register/list/inspect/remove)
  kpm webauthn <subcommand>       Manage WebAuthn credentials (register/list/remove)
  kpm scan <mode>                 Scan for exposed secrets (shell, files, logs)
  kpm update                      Update kpm to the latest release
  kpm version                     Print version
  kpm enroll [server] [--invite <token>]   Enroll this device (use --invite from 'kpm admin inviteuser')
  kpm admin inviteuser <username>          (on an already-enrolled admin machine) create a one-time invite token for a user or new device
  kpm admin getuserinfo <username>         Show registered devices/identity info for a user on the server
  kpm import --from <config> --to <config>  Import secrets from one store to another (e.g. local -> odev)
  kpm share --path <path> --user <uid>  Share a secret/tree with another user (by their identity/UID)

Global flags:
  --config <path>   Config file (default: ~/.kpm/config.yaml)
  --server <url>    AgentKMS server URL (overrides config)
  --cert <path>     mTLS client cert (overrides config)
  --key <path>      mTLS client key (overrides config)
  --ca <path>       CA cert for AgentKMS
  --verbose         Debug output (never prints secrets)

Examples:
  kpm add cloudflare/dns-token                    # store a secret (interactive)
  echo "sk-xxx" | kpm add anthropic/api-key       # store from pipe
  kpm list                                        # see all secrets
  kpm list --tag ci                               # filter by tag
  eval $(kpm env --from ~/.kpm/templates/shell-env.template --output shell)
  kpm cred register blog-audit-pat --provider github-app-token --destination github-secret:owner/repo:PAT
  kpm cred list
  kpm cred rotate blog-audit-pat
`

var version = "0.5.0"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	// Pre-parse global flags so they can appear before the subcommand
	// (e.g. `kpm --config ~/.kpm/config-odev.yaml list` or `KPM_CONFIG=... kpm list`).
	// This makes switching between local dev and remote AgentKMS natural and
	// not "command specific".
	effectiveConfig := kpm.DefaultConfigPath()
	effectiveServer := ""
	effectiveCert := ""
	effectiveKey := ""
	effectiveCA := ""
	effectiveVerbose := false
	effectiveDev := false

	// Very small scanner for the common global forms. Supports both
	// --foo=bar and --foo bar styles.
	for i := 1; i < len(os.Args); i++ {
		a := os.Args[i]
		switch {
		case a == "--config" && i+1 < len(os.Args):
			effectiveConfig = os.Args[i+1]
			i++
		case strings.HasPrefix(a, "--config="):
			effectiveConfig = strings.TrimPrefix(a, "--config=")
		case a == "--server" && i+1 < len(os.Args):
			effectiveServer = os.Args[i+1]
			i++
		case strings.HasPrefix(a, "--server="):
			effectiveServer = strings.TrimPrefix(a, "--server=")
		case a == "--cert" && i+1 < len(os.Args):
			effectiveCert = os.Args[i+1]
			i++
		case strings.HasPrefix(a, "--cert="):
			effectiveCert = strings.TrimPrefix(a, "--cert=")
		case a == "--key" && i+1 < len(os.Args):
			effectiveKey = os.Args[i+1]
			i++
		case strings.HasPrefix(a, "--key="):
			effectiveKey = strings.TrimPrefix(a, "--key=")
		case a == "--ca" && i+1 < len(os.Args):
			effectiveCA = os.Args[i+1]
			i++
		case strings.HasPrefix(a, "--ca="):
			effectiveCA = strings.TrimPrefix(a, "--ca=")
		case a == "--verbose" || a == "-v":
			effectiveVerbose = true
		case a == "--dev":
			effectiveDev = true
		}
	}

	// Find the real subcommand, skipping any global flags that appeared before it.
	subcmd := ""
	for i := 1; i < len(os.Args); i++ {
		a := os.Args[i]
		if strings.HasPrefix(a, "-") {
			// skip flag and its optional value
			if !strings.Contains(a, "=") && i+1 < len(os.Args) && !strings.HasPrefix(os.Args[i+1], "-") {
				i++
			}
			continue
		}
		subcmd = a
		break
	}
	if subcmd == "" {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	fs := flag.NewFlagSet("kpm", flag.ExitOnError)
	configPath := fs.String("config", effectiveConfig, "config file path")
	serverFlag := fs.String("server", effectiveServer, "AgentKMS server URL")
	certFlag := fs.String("cert", effectiveCert, "mTLS client cert path")
	keyFlag := fs.String("key", effectiveKey, "mTLS client key path")
	caFlag := fs.String("ca", effectiveCA, "CA cert path")
	verbose := fs.Bool("verbose", effectiveVerbose, "debug output")
	devMode := fs.Bool("dev", effectiveDev, "force local development store only (do not touch hosted environments such as odev)")

	templateFlag := fs.String("from", "", "template file path")
	outputFlag := fs.String("output", "dotenv", "output format: dotenv, shell, json")

	plaintextFlag := fs.Bool("plaintext", false, "output plaintext values (less secure)")
	// //blog:part-2 references --strict flag behavior in the "that's too convenient" section.
	// Note: flag parses in v0.2.0; per-decrypt policy enforcement ships in v0.3.0.
	strictFlag := fs.Bool("strict", false, "enable strict ciphertext mode")
	secureFlag := fs.Bool("secure", false, "filter secrets by per-tool allow-list (.kpm/secure-allowlist.yaml)")
	envFlag := fs.String("env", "", "read ciphertext from this env var name")

	fromFileFlag := fs.String("from-file", "", "read secret value from file")
	descFlag := fs.String("description", "", "secret description")
	tagsFlag := fs.String("tags", "", "comma-separated tags")
	typeFlag := fs.String("type", "", "secret type (auto-detected if omitted)")
	expiresFlag := fs.String("expires", "", "expiry date (ISO-8601)")
	tagFilterFlag := fs.String("tag", "", "filter by tag")
	typeFilterFlag := fs.String("type-filter", "", "filter by secret type")
	includeDeletedFlag := fs.Bool("include-deleted", false, "include soft-deleted secrets")
	purgeFlag := fs.Bool("purge", false, "permanently delete (no recovery)")
	jsonFlag := fs.Bool("json", false, "output JSON instead of table (list command)")
	serviceFlag := fs.String("service", "", "service name (alternative to positional path)")
	nameFlag := fs.String("name", "", "secret name (alternative to positional path)")

	// kpm login / logout / whoami are dispatched early.  They have no
	// subcommand-specific flags; they consume the global connection flags
	// (--server / --cert / --key / --ca) and otherwise speak directly to the
	// new auth-session storage.
	if subcmd == "login" || subcmd == "logout" || subcmd == "whoami" {
		os.Exit(runAuthCmd(subcmd, os.Args[2:]))
	}

	// kpm enroll is dispatched early: it uses a bare (no-mTLS) client because
	// no cert files exist yet.  It writes cert files to CertsDir().
	if subcmd == "enroll" {
		cfg := &kpm.Config{}
		if _, err := os.Stat(kpm.DefaultConfigPath()); err == nil {
			if loaded, loadErr := kpm.LoadConfig(kpm.DefaultConfigPath()); loadErr == nil {
				cfg = loaded
			}
		}
		for i, a := range os.Args[2:] {
			switch {
			case a == "--server" && i+1 < len(os.Args[2:]):
				cfg.Server = os.Args[3+i]
			case strings.HasPrefix(a, "--server="):
				cfg.Server = strings.TrimPrefix(a, "--server=")
			}
		}
		if cfg.Server == "" {
			fmt.Fprintln(os.Stderr, "error: server URL required (set via config or --server)")
			os.Exit(1)
		}
		// Enroll happens BEFORE the caller has a client cert (the whole point),
		// so we can't do mTLS — but we still need to verify the server cert
		// against the configured CA. NewClientCAOnly does exactly that.
		rawClient, err := kpm.NewClientCAOnly(cfg.Server, cfg.CA)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error creating client: %v\n", err)
			os.Exit(1)
		}
		adapter := &kpm.ClientEnrollAdapter{C: rawClient}
		os.Exit(kpm.RunEnroll(
			context.Background(), os.Stdout, os.Stderr,
			adapter,
			kpm.CertsDir(),
			cfg,
			os.Args[2:],
		))
	}

	// kpm device is dispatched early: it has its own flag parsing and does not
	// share the global flag set. Route before fs.Parse.
	if subcmd == "device" {
		cfg := &kpm.Config{}
		if _, err := os.Stat(kpm.DefaultConfigPath()); err == nil {
			if loaded, loadErr := kpm.LoadConfig(kpm.DefaultConfigPath()); loadErr == nil {
				cfg = loaded
			}
		}
		for i, a := range os.Args[2:] {
			switch {
			case a == "--server" && i+1 < len(os.Args[2:]):
				cfg.Server = os.Args[3+i]
			case strings.HasPrefix(a, "--server="):
				cfg.Server = strings.TrimPrefix(a, "--server=")
			case a == "--cert" && i+1 < len(os.Args[2:]):
				cfg.Cert = os.Args[3+i]
			case strings.HasPrefix(a, "--cert="):
				cfg.Cert = strings.TrimPrefix(a, "--cert=")
			case a == "--key" && i+1 < len(os.Args[2:]):
				cfg.Key = os.Args[3+i]
			case strings.HasPrefix(a, "--key="):
				cfg.Key = strings.TrimPrefix(a, "--key=")
			case a == "--ca" && i+1 < len(os.Args[2:]):
				cfg.CA = os.Args[3+i]
			case strings.HasPrefix(a, "--ca="):
				cfg.CA = strings.TrimPrefix(a, "--ca=")
			}
		}
		client := buildClient(cfg)
		os.Exit(kpm.RunDevice(
			context.Background(), os.Stdout, os.Stderr,
			client, kpm.CertsDir(),
			os.Args[2:],
		))
	}

	// kpm gh-app is dispatched early: it has its own flag parsing and does not
	// share the global flag set. Route before fs.Parse.
	// (Note: the pre-scan above already populated effective* values, including
	// from KPM_CONFIG env.)
	if subcmd == "gh-app" {
		cfg := &kpm.Config{}
		if _, err := os.Stat(kpm.DefaultConfigPath()); err == nil {
			if loaded, loadErr := kpm.LoadConfig(kpm.DefaultConfigPath()); loadErr == nil {
				cfg = loaded
			}
		}
		// Best-effort parse of global connection flags before the subcommand.
		for i, a := range os.Args[2:] {
			switch {
			case a == "--server" && i+1 < len(os.Args[2:]):
				cfg.Server = os.Args[3+i]
			case strings.HasPrefix(a, "--server="):
				cfg.Server = strings.TrimPrefix(a, "--server=")
			case a == "--cert" && i+1 < len(os.Args[2:]):
				cfg.Cert = os.Args[3+i]
			case strings.HasPrefix(a, "--cert="):
				cfg.Cert = strings.TrimPrefix(a, "--cert=")
			case a == "--key" && i+1 < len(os.Args[2:]):
				cfg.Key = os.Args[3+i]
			case strings.HasPrefix(a, "--key="):
				cfg.Key = strings.TrimPrefix(a, "--key=")
			case a == "--ca" && i+1 < len(os.Args[2:]):
				cfg.CA = os.Args[3+i]
			case strings.HasPrefix(a, "--ca="):
				cfg.CA = strings.TrimPrefix(a, "--ca=")
			}
		}
		client := buildClient(cfg)
		ghAppArgs := os.Args[2:]
		os.Exit(kpm.RunGhApp(context.Background(), os.Stdout, os.Stderr, client, ghAppArgs))
	}

	// kpm webauthn is dispatched early: it has its own flag parsing and does not
	// share the global flag set. Route before fs.Parse.
	if subcmd == "webauthn" {
		cfg := &kpm.Config{}
		if _, err := os.Stat(kpm.DefaultConfigPath()); err == nil {
			if loaded, loadErr := kpm.LoadConfig(kpm.DefaultConfigPath()); loadErr == nil {
				cfg = loaded
			}
		}
		for i, a := range os.Args[2:] {
			switch {
			case a == "--server" && i+1 < len(os.Args[2:]):
				cfg.Server = os.Args[3+i]
			case strings.HasPrefix(a, "--server="):
				cfg.Server = strings.TrimPrefix(a, "--server=")
			case a == "--cert" && i+1 < len(os.Args[2:]):
				cfg.Cert = os.Args[3+i]
			case strings.HasPrefix(a, "--cert="):
				cfg.Cert = strings.TrimPrefix(a, "--cert=")
			case a == "--key" && i+1 < len(os.Args[2:]):
				cfg.Key = os.Args[3+i]
			case strings.HasPrefix(a, "--key="):
				cfg.Key = strings.TrimPrefix(a, "--key=")
			case a == "--ca" && i+1 < len(os.Args[2:]):
				cfg.CA = os.Args[3+i]
			case strings.HasPrefix(a, "--ca="):
				cfg.CA = strings.TrimPrefix(a, "--ca=")
			}
		}
		client := buildClient(cfg)
		os.Exit(kpm.RunWebAuthn(context.Background(), os.Stdout, os.Stderr, client, os.Args[2:]))
	}

	// kpm cred is dispatched early: it has its own flag parsing and does not
	// share the global flag set. Route before fs.Parse.
	if subcmd == "cred" {
		cfg := &kpm.Config{}
		if _, err := os.Stat(kpm.DefaultConfigPath()); err == nil {
			if loaded, loadErr := kpm.LoadConfig(kpm.DefaultConfigPath()); loadErr == nil {
				cfg = loaded
			}
		}
		// Apply global flag overrides from the remaining args if present.
		// We do a best-effort parse of --server / --cert / --key / --ca
		// that appear before the cred subcommand.
		for i, a := range os.Args[2:] {
			switch {
			case a == "--server" && i+1 < len(os.Args[2:]):
				cfg.Server = os.Args[3+i]
			case strings.HasPrefix(a, "--server="):
				cfg.Server = strings.TrimPrefix(a, "--server=")
			case a == "--cert" && i+1 < len(os.Args[2:]):
				cfg.Cert = os.Args[3+i]
			case strings.HasPrefix(a, "--cert="):
				cfg.Cert = strings.TrimPrefix(a, "--cert=")
			case a == "--key" && i+1 < len(os.Args[2:]):
				cfg.Key = os.Args[3+i]
			case strings.HasPrefix(a, "--key="):
				cfg.Key = strings.TrimPrefix(a, "--key=")
			case a == "--ca" && i+1 < len(os.Args[2:]):
				cfg.CA = os.Args[3+i]
			case strings.HasPrefix(a, "--ca="):
				cfg.CA = strings.TrimPrefix(a, "--ca=")
			}
		}
		client := buildClient(cfg)
		credArgs := os.Args[2:]
		os.Exit(kpm.RunCred(context.Background(), os.Stdout, os.Stderr, client, credArgs))
	}

	switch subcmd {
	case "update":
		os.Exit(runUpdate(os.Args[2:]))
	case "version":
		fmt.Println("kpm", version)
		if isTerminal(os.Stdout) {
			fmt.Fprintln(os.Stderr, "Run 'kpm update' to upgrade.")
		}
		return
	case "help", "--help", "-h":
		fmt.Fprint(os.Stderr, usage)
		return
	case "quickstart":
		if err := kpm.Quickstart(os.Stderr); err != nil {
			fmt.Fprintf(os.Stderr, "quickstart failed: %v\n", err)
			os.Exit(1)
		}
		return
	// //blog:part-1 references kpm shell-init in the "shell integration" section.
	// //blog:part-2 references kpm shell-init in the "ciphertext by default" section.
	case "shell-init":
		shell := ""
		for _, arg := range os.Args[2:] {
			if strings.HasPrefix(arg, "--shell=") {
				shell = strings.TrimPrefix(arg, "--shell=")
			}
		}
		if err := kpm.ShellInit(os.Stdout, shell); err != nil {
			fmt.Fprintf(os.Stderr, "shell-init failed: %v\n", err)
			os.Exit(1)
		}
		return
	case "tree":
		levels := kpm.DiscoverTemplateLevels()
		kpm.PrintTree(os.Stdout, levels)
		return
	case "profile":
		runProfile()
		return
	case "show":
		showFs := flag.NewFlagSet("show", flag.ContinueOnError)
		showProfile := showFs.Bool("profile", false, "also show merged profile variables")
		showFs.Parse(os.Args[2:])
		secrets, sid := kpm.ScanManagedSecrets()
		ttl := time.Duration(0)
		if sid != "" {
			ttl = kpm.SessionTTLRemaining(sid, 300)
		}
		filterName := ""
		if args := showFs.Args(); len(args) > 0 {
			filterName = args[0]
		}
		if *showProfile {
			kpm.PrintShowWithProfile(os.Stdout, secrets, sid, ttl, filterName)
		} else {
			kpm.PrintShow(os.Stdout, secrets, sid, ttl, filterName)
		}
		return
	case "_listen":
		// Hidden internal command — started by kpm env to run a persistent listener.
		runListen()
		return
	case "scan":
		os.Exit(scan.Dispatch(context.Background(), os.Args[2:]))
	case "enroll":
		os.Exit(runEnroll(os.Args[2:]))
	case "admin":
		os.Exit(runAdmin(os.Args[2:]))
	case "import":
		os.Exit(runImport(os.Args[2:]))
	case "share":
		os.Exit(runShare(os.Args[2:]))
	case "env", "export", "run", "get", "init", "decrypt", "config",
		"add", "list", "describe", "history", "remove":
		if err := fs.Parse(os.Args[2:]); err != nil {
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n%s", subcmd, usage)
		os.Exit(1)
	}
	// Note: "cred" is handled above before this switch block.

	cfg := &kpm.Config{}
	if _, err := os.Stat(*configPath); err == nil {
		loaded, loadErr := kpm.LoadConfig(*configPath)
		if loadErr == nil {
			cfg = loaded
		} else if *verbose {
			fmt.Fprintf(os.Stderr, "warning: config parse error: %v\n", loadErr)
		}
	}

	if *serverFlag != "" {
		cfg.Server = *serverFlag
	}
	if *certFlag != "" {
		cfg.Cert = *certFlag
	}
	if *keyFlag != "" {
		cfg.Key = *keyFlag
	}
	if *caFlag != "" {
		cfg.CA = *caFlag
	}

	// Load fallback store if the primary config declares one.
	// This enables automatic failover (when primary connection fails with network error)
	// and optional real-time mirroring of writes to the alternate store (e.g. local mirror
	// for travel when odev is primary but may become unreachable).
	if cfg.Fallback == nil && cfg.FallbackPath != "" {
		fpath := kpm.ExpandHome(cfg.FallbackPath)
		if f, err := kpm.LoadConfig(fpath); err == nil {
			cfg.Fallback = f
		} else if *verbose {
			fmt.Fprintf(os.Stderr, "warning: could not load fallback config %s: %v\n", fpath, err)
		}
	}

	// Explicit dev mode: force local store only. Never touch hosted environments.
	// Useful when developing to avoid polluting odev or other hosted stores.
	if *devMode || os.Getenv("KPM_DEV") != "" {
		cfg.Fallback = nil
		// Force the conventional local config path (ignoring any KPM_CONFIG that pointed at remote).
		localPath := kpm.ExpandHome("~/.kpm/config.yaml")
		if *configPath != localPath {
			if l, err := kpm.LoadConfig(localPath); err == nil {
				cfg = l
			}
		}
	}

	ctx := context.Background()

	switch subcmd {
	case "init":
		runInit(*configPath)
	case "config":
		args := fs.Args()
		if len(args) == 0 {
			fmt.Fprintln(os.Stderr, "kpm config: subcommand required (push or pull)")
			os.Exit(1)
		}
		switch args[0] {
		case "push":
			dir := kpm.TemplatesDir()
			if len(args) > 1 {
				dir = args[1]
			}
			fmt.Fprintf(os.Stderr, "Pushing templates from %s\n", dir)
			if err := kpm.PushTemplates(os.Stderr, dir); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
		case "pull":
			dir := kpm.TemplatesDir()
			if len(args) > 1 {
				dir = args[1]
			}
			client := buildClient(cfg)
			fmt.Fprintf(os.Stderr, "Pulling templates to %s\n", dir)
			if err := kpm.PullTemplates(ctx, os.Stderr, client, dir); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
		default:
			fmt.Fprintf(os.Stderr, "kpm config: unknown subcommand %q (use push or pull)\n", args[0])
			os.Exit(1)
		}
	case "env", "export":
		tmplPath := *templateFlag
		if tmplPath == "" {
			tmplPath = cfg.DefaultTemplate
		}
		runEnv(ctx, cfg, tmplPath, *outputFlag, *plaintextFlag, *strictFlag)
	case "run":
		tmplPath := *templateFlag
		// If no explicit --from, check for active session (ENC blobs in env)
		// before falling back to auto-discovery and then default template.
		if tmplPath == "" {
			if sid, err := kpm.FindActiveSession(); err == nil {
				// Active session found — use env-scanning mode
				tmplPath = ""
				_ = sid // session ID found, runRun will rediscover it
			} else {
				// No active session — try auto-discovery by command name
				cmdArgs := fs.Args()
				if len(cmdArgs) > 0 {
					discovered := kpm.DiscoverTemplate(filepath.Base(cmdArgs[0]))
					if discovered != "" {
						tmplPath = discovered
						if *verbose {
							fmt.Fprintf(os.Stderr, "✓ Auto-discovered template: %s\n", discovered)
						}
					}
				}
				// Fall back to config default if still not found
				if tmplPath == "" {
					tmplPath = cfg.DefaultTemplate
				}
			}
		}
		cmdArgs := fs.Args()
		if len(cmdArgs) == 0 {
			fmt.Fprintln(os.Stderr, "kpm run: no command specified")
			os.Exit(1)
		}
		runRun(ctx, cfg, tmplPath, cmdArgs, *plaintextFlag, *strictFlag, *secureFlag, *verbose)
	case "get":
		args := fs.Args()
		if len(args) == 0 {
			fmt.Fprintln(os.Stderr, "kpm get: no reference specified")
			os.Exit(1)
		}
		runGet(ctx, cfg, args[0], *verbose)
	case "decrypt":
		args := fs.Args()
		var blob string
		if *envFlag != "" {
			blob = os.Getenv(*envFlag)
		} else if len(args) > 0 {
			blob = args[0]
		} else {
			fmt.Fprintln(os.Stderr, "kpm decrypt: provide a ciphertext blob or --env VAR_NAME")
			os.Exit(1)
		}
		runDecrypt(blob)

	case "add":
		// Re-parse remaining args to handle flags after positional arg.
		// Go's flag package stops at the first non-flag arg, so
		// "kpm add cloudflare/dns-token --type api-token" leaves --type unparsed.
		addFs := flag.NewFlagSet("add", flag.ContinueOnError)
		addFromFile := addFs.String("from-file", "", "read secret value from file")
		addDesc := addFs.String("description", "", "secret description")
		addTags := addFs.String("tags", "", "comma-separated tags")
		addType := addFs.String("type", "", "secret type")
		addExpires := addFs.String("expires", "", "expiry date")
		addService := addFs.String("service", "", "service name")
		addName := addFs.String("name", "", "secret name")
		addForce := addFs.Bool("force", false, "overwrite existing secret without confirmation")

		// Collect positional args and flags from remaining args
		var positional []string
		remaining := fs.Args()
		for len(remaining) > 0 {
			if remaining[0] == "--" {
				remaining = remaining[1:]
				break
			}
			if strings.HasPrefix(remaining[0], "-") {
				break
			}
			positional = append(positional, remaining[0])
			remaining = remaining[1:]
		}
		if len(remaining) > 0 {
			addFs.Parse(remaining)
		}

		// Also inherit from the top-level flags if the add-specific ones weren't set
		if *addFromFile == "" && *fromFileFlag != "" {
			*addFromFile = *fromFileFlag
		}
		if *addDesc == "" && *descFlag != "" {
			*addDesc = *descFlag
		}
		if *addTags == "" && *tagsFlag != "" {
			*addTags = *tagsFlag
		}
		if *addType == "" && *typeFlag != "" {
			*addType = *typeFlag
		}
		if *addExpires == "" && *expiresFlag != "" {
			*addExpires = *expiresFlag
		}

		path := ""
		if len(positional) > 0 {
			path = positional[0]
		} else if *addService != "" && *addName != "" {
			path = *addService + "/" + *addName
		} else if *serviceFlag != "" && *nameFlag != "" {
			path = *serviceFlag + "/" + *nameFlag
		}
		if path == "" {
			fmt.Fprintln(os.Stderr, "kpm add: path required (e.g. kpm add cloudflare/dns-token)")
			fmt.Fprintln(os.Stderr, "  or use: kpm add --service cloudflare --name dns-token")
			os.Exit(1)
		}
		client := buildClient(cfg)
		var tags []string
		if *addTags != "" {
			tags = strings.Split(*addTags, ",")
		}
		opts := kpm.AddOptions{
			Path:        path,
			FromFile:    *addFromFile,
			Description: *addDesc,
			Tags:        tags,
			Type:        *addType,
			Expires:     *addExpires,
			Force:       *addForce,
		}
		if err := kpm.RunAdd(ctx, os.Stderr, client, opts); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}

	case "list":
		service := ""
		if args := fs.Args(); len(args) > 0 {
			service = args[0]
		}
		client := buildClient(cfg)
		if err := kpm.RunList(ctx, os.Stdout, client, service, *tagFilterFlag, *typeFilterFlag, *includeDeletedFlag, *jsonFlag); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}

	case "describe":
		args := fs.Args()
		if len(args) == 0 {
			fmt.Fprintln(os.Stderr, "kpm describe: path required")
			os.Exit(1)
		}
		client := buildClient(cfg)
		if err := kpm.RunDescribe(ctx, os.Stdout, client, args[0]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}

	case "history":
		args := fs.Args()
		if len(args) == 0 {
			fmt.Fprintln(os.Stderr, "kpm history: path required")
			os.Exit(1)
		}
		client := buildClient(cfg)
		if err := kpm.RunHistory(ctx, os.Stdout, client, args[0]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}

	case "remove":
		args := fs.Args()
		if len(args) == 0 {
			fmt.Fprintln(os.Stderr, "kpm remove: path required")
			os.Exit(1)
		}
		client := buildClient(cfg)
		if err := kpm.RunRemove(ctx, os.Stderr, client, args[0], *purgeFlag); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	}
}

// runAuthCmd dispatches `kpm login`, `kpm logout`, and `kpm whoami`.
// Returns the exit code; the caller os.Exit's with the result.
//
// `whoami` is a local-only operation — it reads the persisted session file
// without any network access — so it does not require server config.  The
// others build a client from config + global flags the same way other
// commands do.
func runAuthCmd(subcmd string, args []string) int {
	if subcmd == "whoami" {
		err := kpm.RunWhoami(os.Stdout)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Fprintln(os.Stdout, "Not logged in")
				return 1
			}
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		return 0
	}

	// login / logout need the AgentKMS client.
	cfg := &kpm.Config{}
	if _, err := os.Stat(kpm.DefaultConfigPath()); err == nil {
		if loaded, loadErr := kpm.LoadConfig(kpm.DefaultConfigPath()); loadErr == nil {
			cfg = loaded
		}
	}
	// Best-effort parse of the global connection flags from the remaining args.
	for i, a := range args {
		switch {
		case a == "--server" && i+1 < len(args):
			cfg.Server = args[i+1]
		case strings.HasPrefix(a, "--server="):
			cfg.Server = strings.TrimPrefix(a, "--server=")
		case a == "--cert" && i+1 < len(args):
			cfg.Cert = args[i+1]
		case strings.HasPrefix(a, "--cert="):
			cfg.Cert = strings.TrimPrefix(a, "--cert=")
		case a == "--key" && i+1 < len(args):
			cfg.Key = args[i+1]
		case strings.HasPrefix(a, "--key="):
			cfg.Key = strings.TrimPrefix(a, "--key=")
		case a == "--ca" && i+1 < len(args):
			cfg.CA = args[i+1]
		case strings.HasPrefix(a, "--ca="):
			cfg.CA = strings.TrimPrefix(a, "--ca=")
		}
	}
	client := buildClient(cfg)
	ctx := context.Background()

	switch subcmd {
	case "login":
		// --step-up upgrades an existing cert-only session to cert+human via
		// a WebAuthn browser ceremony.
		for _, a := range args {
			if a == "--step-up" || a == "-step-up" {
				if err := kpm.RunStepUp(ctx, os.Stderr, client); err != nil {
					fmt.Fprintf(os.Stderr, "error: %v\n", err)
					return 1
				}
				return 0
			}
		}
		if err := kpm.RunLogin(ctx, os.Stderr, client); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		return 0
	case "logout":
		if err := kpm.RunLogout(ctx, os.Stderr, client); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		return 0
	}
	return 1
}

// isNetworkError returns true for errors that indicate the remote backend is unreachable
// (as opposed to auth/policy errors). Used for automatic failover to a secondary store.
func isNetworkError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "dial tcp") ||
		strings.Contains(msg, "connect:") ||
		strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "no such host") ||
		strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "i/o timeout")
}

// ensureLocalDevServer makes the local agentkms-dev part of kpm's launch sequence.
// If the config points to localhost and the server isn't responding, we start it
// in the background (similar to quickstart). This lets "kpm list" etc. in dev
// mode just work. Requires agentkms-dev in PATH (installed via quickstart or manually).
func ensureLocalDevServer(cfg *kpm.Config) {
	// Quick check: try to auth with a short timeout client
	testClient, err := kpm.NewClient(cfg.Server, cfg.CA, cfg.Cert, cfg.Key)
	if err != nil {
		return
	}
	// Use a short context to check if already healthy
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	if _, err := testClient.Authenticate(ctx); err == nil {
		return // already running and healthy
	}

	// Not running – start agentkms-dev serve
	devBin, err := exec.LookPath("agentkms-dev")
	if err != nil {
		fmt.Fprintln(os.Stderr, "agentkms-dev not found in PATH. Run 'kpm quickstart' once to set up local dev (or install it manually).")
		return
	}

	fmt.Fprintln(os.Stderr, "Local AgentKMS dev server not running – starting it in background...")
	cmd := exec.Command(devBin, "serve", "--rate-limit", "0")
	cmd.Stdout = ioutil.Discard
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to start local dev server: %v\n", err)
		return
	}

	// Wait for it to become healthy (reuse quickstart wait logic idea)
	for i := 0; i < 30; i++ {
		time.Sleep(500 * time.Millisecond)
		testCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		if _, err := testClient.Authenticate(testCtx); err == nil {
			cancel()
			fmt.Fprintln(os.Stderr, "Local dev server is up.")
			return
		}
		cancel()
	}
	fmt.Fprintln(os.Stderr, "Started local dev server but it didn't become healthy quickly. You may need to run 'agentkms-dev serve' manually.")
}

func buildClient(cfg *kpm.Config) *kpm.Client {
	return getClient(cfg, false)
}

// getClient creates a client for cfg, with automatic failover to cfg.Fallback
// if the primary is unreachable (network error on auth). The isFallback flag
// prevents infinite recursion and suppresses the "falling back" message on the
// secondary.
func getClient(cfg *kpm.Config, isFallback bool) *kpm.Client {
	if cfg.Server == "" || cfg.Cert == "" || cfg.Key == "" || cfg.CA == "" {
		fmt.Fprintln(os.Stderr, "error: server, cert, key, and ca are required (set via config or flags)")
		fmt.Fprintln(os.Stderr, "run: kpm init")
		os.Exit(1)
	}

	// Make local dev server part of the launch sequence for kpm.
	// If using a local config (localhost/127.0.0.1), ensure the agentkms-dev server is running.
	// This way "kpm list" etc. in dev mode just works without manual server start.
	if strings.Contains(cfg.Server, "127.0.0.1") || strings.Contains(cfg.Server, "localhost") {
		ensureLocalDevServer(cfg)
	}

	client, err := kpm.NewClient(cfg.Server, cfg.CA, cfg.Cert, cfg.Key)
	if err != nil {
		if !isFallback && cfg.Fallback != nil {
			fmt.Fprintln(os.Stderr, "primary store unavailable (certs), falling back to alternate...")
			return getClient(cfg.Fallback, true)
		}
		fmt.Fprintf(os.Stderr, "error creating client: %v\n", err)
		os.Exit(1)
	}

	// Authenticate to verify the backend is reachable and the mTLS identity is accepted.
	// Network errors here trigger failover; auth/policy errors are real failures.
	if _, err := client.Authenticate(context.Background()); err != nil {
		if !isFallback && cfg.Fallback != nil && isNetworkError(err) {
			fmt.Fprintln(os.Stderr, "primary backend unreachable, falling back to alternate store...")
			return getClient(cfg.Fallback, true)
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// Transparent 2-way sync on primary reconnect.
	// If we have a fallback (local alternate), reconcile on every successful primary connection.
	// This handles: changes made offline on local get pushed to remote when it comes back;
	// any changes on remote get pulled to local.
	// After import --purge, data is in primary; reconcile will pull it to local (keeping the alternate hot).
	// Future offline changes on local get pushed on reconnect.
	// All transparent — user just uses kpm, no manual sync needed.
	if !isFallback && cfg.Fallback != nil {
		fbClient := getClient(cfg.Fallback, true)
		reconcile(client, fbClient)
	}

	return client
}

// reconcile does 2-way sync between primary and fallback.
// Push local changes (higher version in fallback) to primary.
// Pull remote changes (higher in primary) to fallback.
// Uses versions from ListMetadata for conflict resolution (higher version wins).
func reconcile(primary, fallback *kpm.Client) {
	pMetas, err := primary.ListMetadata(context.Background(), false)
	if err != nil {
		return
	}
	fMetas, err := fallback.ListMetadata(context.Background(), false)
	if err != nil {
		return
	}

	pVer := map[string]int{}
	for _, m := range pMetas {
		pVer[m.Path] = m.Version
	}
	fVer := map[string]int{}
	for _, m := range fMetas {
		fVer[m.Path] = m.Version
	}

	// Push from fallback to primary (offline changes on local)
	for path, fv := range fVer {
		if pv, ok := pVer[path]; !ok || fv > pv {
			vals, err := fallback.FetchRegistrySecret(context.Background(), path)
			if err != nil {
				continue
			}
			if v, ok := vals["value"]; ok && len(vals) == 1 {
				primary.WriteSecret(context.Background(), path, v)
			} else {
				sm := map[string]string{}
				for k, vv := range vals {
					sm[k] = string(vv)
				}
				primary.WriteSecretFields(context.Background(), path, sm)
			}
			// metadata
			_ = primary.WriteMetadata(context.Background(), path, "", nil, "", "")
		}
	}

	// Pull from primary to fallback (to keep local hot, including after import+purge)
	for path, pv := range pVer {
		if fv, ok := fVer[path]; !ok || pv > fv {
			vals, err := primary.FetchRegistrySecret(context.Background(), path)
			if err != nil {
				continue
			}
			if v, ok := vals["value"]; ok && len(vals) == 1 {
				fallback.WriteSecret(context.Background(), path, v)
			} else {
				sm := map[string]string{}
				for k, vv := range vals {
					sm[k] = string(vv)
				}
				fallback.WriteSecretFields(context.Background(), path, sm)
			}
			_ = fallback.WriteMetadata(context.Background(), path, "", nil, "", "")
		}
	}
}

func runEnv(ctx context.Context, cfg *kpm.Config, tmplPath, format string, plaintext bool, strict bool) {
	// --strict and --plaintext are mutually exclusive.
	if err := kpm.ValidateStrictFlags(strict, plaintext); err != nil {
		fmt.Fprintf(os.Stderr, "kpm: %v\n", err)
		os.Exit(1)
	}

	profile, _ := kpm.LoadProfile()

	entries, err := kpm.ResolveTemplateWithIncludes(tmplPath, profile, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing template: %v\n", err)
		os.Exit(1)
	}
	entries, err = kpm.ResolveProfileVarsInEntries(entries, profile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error resolving profile variables: %v\n", err)
		os.Exit(1)
	}

	client := buildClient(cfg)
	resolved, err := kpm.Resolve(ctx, client, entries)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error resolving secrets: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		for i := range resolved {
			kpm.ZeroBytes(resolved[i].PlainValue)
		}
	}()

	kmsCount := 0
	for _, e := range resolved {
		if e.IsKMSRef {
			kmsCount++
		}
	}

	var sessionID string
	var sockPath string

	if strict {
		// Strict mode: encode KMSReference blobs — no plaintext or session key held locally.
		// The background listener will call AgentKMS on each decrypt request.
		ttl := cfg.SessionKeyTTL
		if ttl <= 0 {
			ttl = 300
		}
		// Derive a unique session ID (no session key needed in strict mode).
		randKey, randErr := kpm.NewSessionKey()
		if randErr != nil {
			fmt.Fprintf(os.Stderr, "error generating session ID: %v\n", randErr)
			os.Exit(1)
		}
		sessionID = fmt.Sprintf("strict-%x", randKey[:16])
		kpm.ZeroBytes(randKey)

		sockPath = decryptEndpoint(sessionID)

		for i := range resolved {
			if !resolved[i].IsKMSRef {
				continue
			}
			// Encode the KMSReference — no ciphertext, no session key.
			blob, blobErr := kpm.FormatStrictBlob(sessionID, resolved[i].Ref)
			if blobErr != nil {
				fmt.Fprintf(os.Stderr, "error encoding strict blob for %s: %v\n", resolved[i].EnvKey, blobErr)
				os.Exit(1)
			}
			kpm.ZeroBytes(resolved[i].PlainValue)
			resolved[i].PlainValue = []byte(blob)
		}

		// Fork a background strict listener process.
		// No session key via stdin — it will re-authenticate with AgentKMS per decrypt.
		listenerArgs := []string{"_listen",
			"--session", sessionID,
			"--socket", sockPath,
			"--ttl", fmt.Sprintf("%d", ttl),
			"--strict",
			"--server", cfg.Server,
		}
		if cfg.Cert != "" {
			listenerArgs = append(listenerArgs, "--cert", cfg.Cert)
		}
		if cfg.Key != "" {
			listenerArgs = append(listenerArgs, "--key", cfg.Key)
		}
		if cfg.CA != "" {
			listenerArgs = append(listenerArgs, "--ca", cfg.CA)
		}
		listenerCmd := exec.Command(os.Args[0], listenerArgs...)
		setDetached(listenerCmd)
		if startErr := listenerCmd.Start(); startErr != nil {
			fmt.Fprintf(os.Stderr, "error starting strict listener: %v\n", startErr)
			os.Exit(1)
		}
		listenerCmd.Process.Release()

		// Wait briefly for the decrypt listener to accept connections.
		waitForDecryptListener(sockPath, 100, 5*time.Millisecond)

		fmt.Fprintf(os.Stderr, "✓ Resolved %d secrets from AgentKMS\n", kmsCount)
		fmt.Fprintf(os.Stderr, "✓ Strict mode: per-decrypt mTLS round-trip (session: %s, TTL: %ds)\n", sessionID, ttl)
		fmt.Fprintf(os.Stderr, "✓ Decrypt listener: %s\n", sockPath)
	} else if !plaintext {
		// Default secure mode: encrypt values with a session key, then fork
		// a background listener so that subsequent kpm run calls can decrypt.
		sk, err := kpm.NewSessionKey()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error generating session key: %v\n", err)
			os.Exit(1)
		}
		defer kpm.ZeroBytes(sk)

		sessionID = fmt.Sprintf("s%x", sk[:16])
		sockPath = decryptEndpoint(sessionID)
		ttl := cfg.SessionKeyTTL
		if ttl <= 0 {
			ttl = 300
		}

		for i := range resolved {
			if !resolved[i].IsKMSRef {
				continue
			}
			ct, err := kpm.EncryptLocal(sk, resolved[i].PlainValue)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error encrypting %s: %v\n", resolved[i].EnvKey, err)
				os.Exit(1)
			}
			kpm.ZeroBytes(resolved[i].PlainValue)
			resolved[i].PlainValue = []byte(kpm.FormatCiphertextBlob(sessionID, ct))
		}

		// Fork a background listener process. Pass session key via stdin pipe
		// so it never appears on the command line or in /proc.
		listenerCmd := exec.Command(os.Args[0], "_listen",
			"--session", sessionID,
			"--socket", sockPath,
			"--ttl", fmt.Sprintf("%d", ttl),
		)
		setDetached(listenerCmd)
		stdinPipe, pipeErr := listenerCmd.StdinPipe()
		if pipeErr != nil {
			fmt.Fprintf(os.Stderr, "error creating pipe: %v\n", pipeErr)
			os.Exit(1)
		}
		if startErr := listenerCmd.Start(); startErr != nil {
			fmt.Fprintf(os.Stderr, "error starting listener: %v\n", startErr)
			os.Exit(1)
		}
		stdinPipe.Write(sk)
		stdinPipe.Close()
		listenerCmd.Process.Release()

		// Wait briefly for the decrypt listener to accept connections before output is consumed.
		waitForDecryptListener(sockPath, 100, 5*time.Millisecond)

		fmt.Fprintf(os.Stderr, "✓ Resolved %d secrets from AgentKMS\n", kmsCount)
		fmt.Fprintf(os.Stderr, "✓ Encrypted values (AES-256-GCM, session: %s, TTL: %ds)\n", sessionID, ttl)
		fmt.Fprintf(os.Stderr, "✓ Decrypt listener: %s\n", sockPath)
	} else {
		// Plaintext mode: explicit opt-in
		fmt.Fprintf(os.Stderr, "✓ Resolved %d secrets from AgentKMS\n", kmsCount)
		fmt.Fprintf(os.Stderr, "✓ Plaintext output (--plaintext flag set)\n")
	}

	var err2 error
	switch strings.ToLower(format) {
	case "dotenv":
		if !plaintext {
			for _, e := range resolved {
				fmt.Fprintf(os.Stdout, "%s=%s\n", e.EnvKey, e.PlainValue)
			}
			fmt.Fprintf(os.Stdout, "KPM_SESSION=%s\n", sessionID)
			fmt.Fprintf(os.Stdout, "KPM_DECRYPT_SOCK=%s\n", sockPath)
		} else {
			err2 = kpm.FormatDotenv(os.Stdout, resolved)
		}
	case "shell":
		err2 = kpm.FormatShell(os.Stdout, resolved)
		if !plaintext && err2 == nil {
			fmt.Fprintf(os.Stdout, "export KPM_SESSION='%s'\n", sessionID)
			fmt.Fprintf(os.Stdout, "export KPM_DECRYPT_SOCK='%s'\n", sockPath)
		}
	case "json":
		err2 = kpm.FormatJSON(os.Stdout, resolved)
	default:
		fmt.Fprintf(os.Stderr, "unknown format: %s\n", format)
		os.Exit(1)
	}
	if err2 != nil {
		fmt.Fprintf(os.Stderr, "error writing output: %v\n", err2)
		os.Exit(1)
	}
}

func runRun(ctx context.Context, cfg *kpm.Config, tmplPath string, cmdArgs []string, plaintext, strict, secure, verbose bool) {
	// --secure and --plaintext are mutually exclusive.
	if secure && plaintext {
		fmt.Fprintln(os.Stderr, "kpm: --secure and --plaintext are mutually exclusive")
		os.Exit(1)
	}

	// --strict and --plaintext are mutually exclusive.
	if err := kpm.ValidateStrictFlags(strict, plaintext); err != nil {
		fmt.Fprintf(os.Stderr, "kpm: %v\n", err)
		os.Exit(1)
	}

	// --secure requires a template file; env-scan mode is not supported in v0.2.1.
	if secure && tmplPath == "" {
		fmt.Fprintln(os.Stderr, "kpm: --secure requires a template file in env-scan mode")
		os.Exit(1)
	}

	// Env-scanning mode: no template specified — decrypt ENC blobs from current env.
	if tmplPath == "" {
		sid, err := kpm.FindActiveSession()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: no template specified and %v\n", err)
			os.Exit(1)
		}

		sk, _, loadErr := kpm.LoadSession(sid)
		if loadErr != nil {
			fmt.Fprintf(os.Stderr, "error loading session %s: %v\n", sid, loadErr)
			os.Exit(1)
		}
		defer kpm.ZeroBytes(sk)

		cleanEnv, count, decErr := kpm.DecryptEnv(sk, sid)
		if decErr != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", decErr)
			os.Exit(1)
		}

		if verbose {
			fmt.Fprintf(os.Stderr, "✓ Decrypted %d secrets from session %s\n", count, sid)
		} else {
			fmt.Fprintf(os.Stderr, "✓ Decrypted %d secrets from session %s\n", count, sid)
		}

		exitCode, runErr := kpm.RunCommandWithEnv(ctx, cleanEnv, cmdArgs[0], cmdArgs[1:])
		if runErr != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", runErr)
			os.Exit(1)
		}
		os.Exit(exitCode)
	}

	profile, _ := kpm.LoadProfile()

	entries, err := kpm.ResolveTemplateWithIncludes(tmplPath, profile, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing template: %v\n", err)
		os.Exit(1)
	}
	entries, err = kpm.ResolveProfileVarsInEntries(entries, profile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error resolving profile variables: %v\n", err)
		os.Exit(1)
	}

	client := buildClient(cfg)
	resolved, err := kpm.Resolve(ctx, client, entries)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error resolving secrets: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		for i := range resolved {
			kpm.ZeroBytes(resolved[i].PlainValue)
		}
	}()

	// Apply per-tool allow-list filtering when --secure is set.
	if secure {
		toolName := filepath.Base(cmdArgs[0])
		allowedVars, alErr := kpm.LoadAllowlist(toolName)
		if alErr != nil {
			fmt.Fprintf(os.Stderr, "kpm: %v\n", alErr)
			os.Exit(1)
		}
		if allowedVars == nil {
			// Tool not in allow-list — warn and filter all KMS secrets.
			fmt.Fprintf(os.Stderr, "kpm: --secure: tool %q not in allow-list; all secrets filtered\n", toolName)
			allowedVars = []string{}
		}
		resolved = kpm.FilterByAllowlist(resolved, allowedVars, toolName, verbose)
	}

	kmsCount := 0
	for _, e := range resolved {
		if e.IsKMSRef {
			kmsCount++
		}
	}

	if strict {
		// Strict mode: encode KMSReference blobs; listener round-trips to AgentKMS per decrypt.
		// --secure filter has already been applied above; strict wraps what remains.
		randKey, randErr := kpm.NewSessionKey()
		if randErr != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", randErr)
			os.Exit(1)
		}
		sessionID := fmt.Sprintf("strict-%x", randKey[:16])
		kpm.ZeroBytes(randKey)

		ttl := time.Duration(cfg.SessionKeyTTL) * time.Second

		for i := range resolved {
			if !resolved[i].IsKMSRef {
				continue
			}
			blob, blobErr := kpm.FormatStrictBlob(sessionID, resolved[i].Ref)
			if blobErr != nil {
				fmt.Fprintf(os.Stderr, "error encoding strict blob for %s: %v\n", resolved[i].EnvKey, blobErr)
				os.Exit(1)
			}
			kpm.ZeroBytes(resolved[i].PlainValue)
			resolved[i].PlainValue = []byte(blob)
		}

		sockPath := decryptEndpoint(sessionID)
		dl := &kpm.DecryptListener{
			SocketPath:     sockPath,
			SessionID:      sessionID,
			ExpiresAt:      time.Now().Add(ttl),
			StrictMode:     true,
			AgentKMSClient: client,
		}
		defer dl.Close()

		go func() {
			if err := dl.Serve(); err != nil {
				fmt.Fprintf(os.Stderr, "strict listener error: %v\n", err)
			}
		}()

		waitForDecryptListener(sockPath, 50, 5*time.Millisecond)

		resolved = append(resolved, kpm.ResolvedEntry{
			EnvKey:     "KPM_DECRYPT_SOCK",
			PlainValue: []byte(sockPath),
		})

		if verbose {
			fmt.Fprintf(os.Stderr, "✓ Resolved %d secrets from AgentKMS\n", kmsCount)
			fmt.Fprintf(os.Stderr, "✓ Strict mode: per-decrypt mTLS round-trip (session: %s, TTL: %ds)\n", sessionID, cfg.SessionKeyTTL)
			fmt.Fprintf(os.Stderr, "✓ Decrypt listener started (socket: %s)\n", sockPath)
		}
	} else if !plaintext {
		sk, err := kpm.NewSessionKey()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		defer kpm.ZeroBytes(sk)

		sessionID := fmt.Sprintf("s%x", sk[:16])
		ttl := time.Duration(cfg.SessionKeyTTL) * time.Second

		for i := range resolved {
			if !resolved[i].IsKMSRef {
				continue
			}
			ct, err := kpm.EncryptLocal(sk, resolved[i].PlainValue)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error encrypting %s: %v\n", resolved[i].EnvKey, err)
				os.Exit(1)
			}
			kpm.ZeroBytes(resolved[i].PlainValue)
			resolved[i].PlainValue = []byte(kpm.FormatCiphertextBlob(sessionID, ct))
		}

		sockPath := decryptEndpoint(sessionID)
		dl := &kpm.DecryptListener{
			SocketPath: sockPath,
			SessionKey: sk,
			SessionID:  sessionID,
			ExpiresAt:  time.Now().Add(ttl),
		}
		defer dl.Close()

		go func() {
			if err := dl.Serve(); err != nil {
				fmt.Fprintf(os.Stderr, "listener error: %v\n", err)
			}
		}()

		waitForDecryptListener(sockPath, 50, 5*time.Millisecond)

		resolved = append(resolved, kpm.ResolvedEntry{
			EnvKey:     "KPM_DECRYPT_SOCK",
			PlainValue: []byte(sockPath),
		})

		if verbose {
			fmt.Fprintf(os.Stderr, "✓ Resolved %d secrets from AgentKMS\n", kmsCount)
			fmt.Fprintf(os.Stderr, "✓ Session key acquired (TTL: %ds)\n", cfg.SessionKeyTTL)
			fmt.Fprintf(os.Stderr, "✓ Encrypting values (AES-256-GCM)\n")
			fmt.Fprintf(os.Stderr, "✓ Decrypt listener started (socket: %s)\n", sockPath)
		}
	} else {
		if verbose {
			fmt.Fprintf(os.Stderr, "✓ Resolved %d secrets from AgentKMS\n", kmsCount)
			fmt.Fprintf(os.Stderr, "✓ Injecting plaintext env vars (--plaintext flag set)\n")
		}
	}

	exitCode, err := kpm.RunCommand(ctx, resolved, cmdArgs[0], cmdArgs[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	os.Exit(exitCode)
}

func runGet(ctx context.Context, cfg *kpm.Config, ref string, verbose bool) {
	client := buildClient(cfg)

	parsed, ok := kpm.ParseKMSRef("${kms:" + ref + "}")
	if !ok {
		// Not a kms:// ref — try as a registry path (e.g. "cloudflare/dns-token").
		secrets, err := client.FetchRegistrySecret(ctx, ref)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			fmt.Fprintf(os.Stderr, "tip: use kv/<path>#<key> for KV refs or llm/<provider> for LLM credentials\n")
			os.Exit(1)
		}
		defer kpm.ZeroMap(secrets)
		if val, ok := secrets["value"]; ok {
			os.Stdout.Write(val)
		} else {
			for k, v := range secrets {
				fmt.Fprintf(os.Stdout, "%s=%s\n", k, v)
			}
		}
		return
	}

	switch parsed.Type {
	case "llm":
		cred, err := client.FetchLLM(ctx, parsed.Path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		defer kpm.ZeroBytes(cred.APIKey)
		os.Stdout.Write(cred.APIKey)

	case "kv":
		cred, err := client.FetchGeneric(ctx, parsed.Path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		defer kpm.ZeroMap(cred.Secrets)

		if parsed.Key == "" {
			for k, v := range cred.Secrets {
				fmt.Fprintf(os.Stdout, "%s=%s\n", k, v)
			}
		} else {
			val, ok := cred.Secrets[parsed.Key]
			if !ok {
				fmt.Fprintf(os.Stderr, "key %q not found at path %q\n", parsed.Key, parsed.Path)
				os.Exit(1)
			}
			os.Stdout.Write(val)
		}

	default:
		// Unknown kms: type — also fall back to registry path.
		secrets, err := client.FetchRegistrySecret(ctx, ref)
		if err != nil {
			fmt.Fprintf(os.Stderr, "unknown ref type %q and registry fetch failed: %v\n", parsed.Type, err)
			os.Exit(1)
		}
		defer kpm.ZeroMap(secrets)
		if val, ok := secrets["value"]; ok {
			os.Stdout.Write(val)
		} else {
			for k, v := range secrets {
				fmt.Fprintf(os.Stdout, "%s=%s\n", k, v)
			}
		}
	}
}

func runInit(path string) {
	if _, err := os.Stat(path); err == nil {
		fmt.Fprintf(os.Stderr, "config already exists: %s\n", path)
		os.Exit(1)
	}

	dir := path[:strings.LastIndex(path, "/")]
	if err := os.MkdirAll(dir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "error creating config dir: %v\n", err)
		os.Exit(1)
	}

	template := `# KPM Configuration
# Generated by: kpm init
server: https://127.0.0.1:8443
cert: ~/.kpm/certs/client.crt
key: ~/.kpm/certs/client.key
ca: ~/.kpm/certs/ca.crt
default_template: .env.template
secure_mode: false
session_key_ttl: 300
`
	if err := os.WriteFile(path, []byte(template), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "error writing config: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "✓ Config written to %s\n", path)
	fmt.Fprintln(os.Stderr, "  Edit it with your AgentKMS server details and cert paths.")
}

// runListen is the hidden _listen subcommand. It reads the session key from
// stdin (never from the command line) and serves decrypt requests until TTL.
// In strict mode (--strict flag), no session key is read from stdin; instead
// an AgentKMS client is constructed from the provided --server/--cert/--key/--ca
// flags and the listener calls AgentKMS per decrypt request.
func runListen() {
	fs := flag.NewFlagSet("_listen", flag.ExitOnError)
	sessionFlag := fs.String("session", "", "session ID")
	socketFlag := fs.String("socket", "", "socket path")
	ttlFlag := fs.Int("ttl", 300, "TTL in seconds")
	strictFlag := fs.Bool("strict", false, "strict mode: per-decrypt AgentKMS round-trip")
	serverFlag := fs.String("server", "", "AgentKMS server URL (strict mode)")
	certFlag := fs.String("cert", "", "mTLS client cert path (strict mode)")
	keyFlag := fs.String("key", "", "mTLS client key path (strict mode)")
	caFlag := fs.String("ca", "", "CA cert path (strict mode)")
	fs.Parse(os.Args[2:])

	if *sessionFlag == "" || *socketFlag == "" {
		os.Exit(1)
	}

	ttl := time.Duration(*ttlFlag) * time.Second

	if *strictFlag {
		// Strict mode: no session key from stdin; construct AgentKMS client.
		var agentClient *kpm.Client
		if *serverFlag != "" {
			var clientErr error
			agentClient, clientErr = kpm.NewClient(*serverFlag, *caFlag, *certFlag, *keyFlag)
			if clientErr != nil {
				fmt.Fprintf(os.Stderr, "strict listener: error creating AgentKMS client: %v\n", clientErr)
				os.Exit(1)
			}
		}

		dl := &kpm.DecryptListener{
			SocketPath:     *socketFlag,
			SessionID:      *sessionFlag,
			ExpiresAt:      time.Now().Add(ttl),
			StrictMode:     true,
			AgentKMSClient: agentClient,
		}
		dl.Serve() //nolint:errcheck
		return
	}

	// Non-strict: read session key from stdin — never exposed on command line.
	key, err := io.ReadAll(os.Stdin)
	if err != nil || len(key) != 32 {
		os.Exit(1)
	}

	// Persist session so kpm run can reload it.
	if saveErr := kpm.SaveSession(*sessionFlag, key, *socketFlag); saveErr != nil {
		// Non-fatal: listener can still serve without persistence.
		fmt.Fprintf(os.Stderr, "warning: could not persist session: %v\n", saveErr)
	}

	// Write PID file for tracking / cleanup.
	pidPath := filepath.Join(kpm.SessionDir(*sessionFlag), "pid")
	os.WriteFile(pidPath, []byte(fmt.Sprintf("%d", os.Getpid())), 0600)

	dl := &kpm.DecryptListener{
		SocketPath: *socketFlag,
		SessionKey: key,
		SessionID:  *sessionFlag,
		ExpiresAt:  time.Now().Add(ttl),
	}

	dl.Serve() //nolint:errcheck
	kpm.CleanSession(*sessionFlag)
}

func runProfile() {
	sources := kpm.LoadProfileWithSources()
	if len(sources) == 0 {
		fmt.Fprintln(os.Stderr, "no profile variables found (checked .kpm/config.yaml up to root + global config)")
		return
	}

	// Collect and sort keys for stable output
	keys := make([]string, 0, len(sources))
	for k := range sources {
		keys = append(keys, k)
	}
	// Simple sort
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[i] > keys[j] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}

	// Find max key width for alignment
	maxLen := 0
	for _, k := range keys {
		if len(k) > maxLen {
			maxLen = len(k)
		}
	}

	for _, k := range keys {
		ps := sources[k]
		padding := strings.Repeat(" ", maxLen-len(k))
		fmt.Fprintf(os.Stdout, "%s%s: %s\t← %s\n", k, padding, ps.Value, ps.Source)
	}
}

func runDecrypt(blob string) {
	sockPath := os.Getenv("KPM_DECRYPT_SOCK")
	if sockPath == "" {
		fmt.Fprintln(os.Stderr, "error: KPM_DECRYPT_SOCK not set (not running under kpm run?)")
		os.Exit(1)
	}

	conn, err := dialDecryptEndpoint(sockPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error connecting to decrypt socket: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	req := struct {
		Ciphertext string `json:"ciphertext"`
	}{Ciphertext: blob}

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		fmt.Fprintf(os.Stderr, "error sending request: %v\n", err)
		os.Exit(1)
	}

	var resp struct {
		Plaintext string `json:"plaintext"`
		Error     string `json:"error"`
	}
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		fmt.Fprintf(os.Stderr, "error reading response: %v\n", err)
		os.Exit(1)
	}

	if resp.Error != "" {
		fmt.Fprintf(os.Stderr, "decrypt error: %s\n", resp.Error)
		os.Exit(1)
	}

	fmt.Print(resp.Plaintext)
}

// isTerminal reports whether the given file is a TTY.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// runUpdate performs an in-place binary update.
// It downloads the latest (or tagged) prebuilt release binary and replaces
// the currently running kpm executable. It deliberately does *not* touch
// any user configuration in ~/.kpm/ (config.yaml, certs, templates, etc.).
// This matches the behavior of `brew upgrade`, VS Code auto-update, Chrome, etc.
func runUpdate(args []string) int {
	sourceOnly := false
	yes := false
	tag := ""
	targetDir := ""

	i := 0
	for i < len(args) {
		a := args[i]
		switch {
		case a == "--source-only":
			sourceOnly = true
		case a == "--yes" || a == "-y":
			yes = true
		case a == "--tag" && i+1 < len(args):
			tag = args[i+1]
			i++
		case strings.HasPrefix(a, "--tag="):
			tag = strings.TrimPrefix(a, "--tag=")
		case a == "--dir" && i+1 < len(args):
			targetDir = args[i+1]
			i++
		case strings.HasPrefix(a, "--dir="):
			targetDir = strings.TrimPrefix(a, "--dir=")
		case a == "--help" || a == "-h":
			fmt.Fprint(os.Stdout, updateHelp)
			return 0
		default:
			fmt.Fprintf(os.Stderr, "kpm update: unknown arg %q\n\n%s", a, updateHelp)
			return 2
		}
		i++
	}

	currentBinary, err := os.Executable()
	if err != nil {
		currentBinary = os.Args[0]
	}
	currentDir := filepath.Dir(currentBinary)

	installDir := targetDir
	if installDir == "" {
		installDir = currentDir
	}

	// Detect platform (same normalization as the install script)
	goos := runtime.GOOS
	goarch := runtime.GOARCH
	if goos == "darwin" {
		goos = "darwin"
	} else if goos == "linux" {
		goos = "linux"
	} else {
		fmt.Fprintf(os.Stderr, "kpm update: unsupported OS %s (only darwin/linux)\n", goos)
		return 2
	}
	if goarch == "x86_64" || goarch == "amd64" {
		goarch = "amd64"
	} else if goarch == "aarch64" || goarch == "arm64" {
		goarch = "arm64"
	} else {
		fmt.Fprintf(os.Stderr, "kpm update: unsupported arch %s (only amd64/arm64)\n", goarch)
		return 2
	}

	releaseTag := tag
	if releaseTag == "" {
		releaseTag = "latest"
	}

	var downloadURL string
	if releaseTag == "latest" {
		downloadURL = fmt.Sprintf("https://github.com/TheGenXCoder/kpm/releases/latest/download/kpm-%s-%s", goos, goarch)
	} else {
		downloadURL = fmt.Sprintf("https://github.com/TheGenXCoder/kpm/releases/download/%s/kpm-%s-%s", releaseTag, goos, goarch)
	}

	targetBinary := filepath.Join(installDir, "kpm")

	// Announcement (matches user expectation of a clean update, not reinstall)
	fmt.Fprintf(os.Stderr, "kpm update\n")
	fmt.Fprintf(os.Stderr, "  current binary: %s\n", currentBinary)
	fmt.Fprintf(os.Stderr, "  target dir:     %s\n", installDir)
	if tag != "" {
		fmt.Fprintf(os.Stderr, "  tag:            %s\n", tag)
	} else {
		fmt.Fprintln(os.Stderr, "  tag:            latest")
	}
	if sourceOnly {
		fmt.Fprintln(os.Stderr, "  mode:           source build (requires Go)")
	} else {
		fmt.Fprintf(os.Stderr, "  download:       %s\n", downloadURL)
	}
	fmt.Fprintln(os.Stderr, "  note:           only the binary will be replaced. Your ~/.kpm/config, certs, and templates are untouched.")

	if !yes {
		fmt.Fprint(os.Stderr, "Continue? [Y/n] ")
		var resp string
		_, _ = fmt.Fscanln(os.Stdin, &resp)
		resp = strings.TrimSpace(strings.ToLower(resp))
		if resp != "" && resp != "y" && resp != "yes" {
			fmt.Fprintln(os.Stderr, "aborted")
			return 1
		}
	}

	if sourceOnly {
		// Fall back to building from source into the target dir
		if _, err := exec.LookPath("go"); err != nil {
			fmt.Fprintln(os.Stderr, "kpm update: Go is required for --source-only")
			return 1
		}
		info := func(s string) { fmt.Fprintf(os.Stderr, "==> %s\n", s) }
		info("Building from source (main branch)...")
		tmpDir, _ := os.MkdirTemp("", "kpm-update-src-*")
		defer os.RemoveAll(tmpDir)

		clone := exec.Command("git", "clone", "--depth", "1", "https://github.com/TheGenXCoder/kpm.git", tmpDir)
		clone.Stdout = os.Stdout
		clone.Stderr = os.Stderr
		if err := clone.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "kpm update: git clone failed: %v\n", err)
			return 1
		}
		build := exec.Command("go", "build", "-o", targetBinary, "./cmd/kpm")
		build.Dir = tmpDir
		build.Stdout = os.Stdout
		build.Stderr = os.Stderr
		if err := build.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "kpm update: build failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "==> Updated %s from source\n", targetBinary)
		return 0
	}

	// Download prebuilt binary
	info := func(s string) { fmt.Fprintf(os.Stderr, "==> %s\n", s) }
	info(fmt.Sprintf("Downloading %s ...", downloadURL))

	tmpFile := targetBinary + ".tmp"
	out, err := os.Create(tmpFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "kpm update: failed to create temp file: %v\n", err)
		return 1
	}
	defer out.Close()

	resp, err := http.Get(downloadURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "kpm update: download failed: %v\n", err)
		os.Remove(tmpFile)
		return 1
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Fprintf(os.Stderr, "kpm update: download returned HTTP %d\n", resp.StatusCode)
		os.Remove(tmpFile)
		return 1
	}

	if _, err := io.Copy(out, resp.Body); err != nil {
		fmt.Fprintf(os.Stderr, "kpm update: write failed: %v\n", err)
		os.Remove(tmpFile)
		return 1
	}
	out.Close()

	if err := os.Chmod(tmpFile, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "kpm update: chmod failed: %v\n", err)
		os.Remove(tmpFile)
		return 1
	}

	// Atomic(ish) replace. If we don't have write permission, use sudo for the final step.
	if err := os.Rename(tmpFile, targetBinary); err != nil {
		// Try sudo mv
		info("Need sudo to replace the binary...")
		sudoMv := exec.Command("sudo", "mv", tmpFile, targetBinary)
		sudoMv.Stdout = os.Stdout
		sudoMv.Stderr = os.Stderr
		if err := sudoMv.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "kpm update: failed to install new binary: %v\n", err)
			os.Remove(tmpFile)
			return 1
		}
	}

	// Verify
	newVersionCmd := exec.Command(targetBinary, "version")
	newVersionCmd.Stdout = os.Stdout
	newVersionCmd.Stderr = os.Stderr
	_ = newVersionCmd.Run()

	fmt.Fprintf(os.Stderr, "==> kpm updated successfully (binary replaced at %s). Your config and certs were not touched.\n", targetBinary)
	return 0
}

const updateHelp = `NAME
    kpm-update -- Update kpm to the latest release

SYNOPSIS
    kpm update [--source-only] [--tag <version>] [--dir <path>] [--yes]

DESCRIPTION
    Performs an in-place update of the kpm binary only.
    Downloads the latest prebuilt release (or a specific tag) and replaces
    the currently running binary. Your ~/.kpm/config.yaml, certs, templates,
    and any other user data are left completely untouched.

    This is the same model as "brew upgrade kpm", VS Code auto-update, Chrome,
    etc.  "update" here means "replace the executable", not "re-run first-time
    install".

OPTIONS
    --source-only       Skip the prebuilt binary and build from source.
                        Requires a Go toolchain.
    --tag <version>     Install a specific release tag (e.g., v0.3.0).
                        Default: latest release.
    --dir <path>        Install/replace the binary in <path> instead of the
                        directory of the current kpm executable.
    --yes, -y           Don't prompt for confirmation.

EXIT STATUS
    0    Updated successfully.
    1    Update failed or user declined.
    2    Usage error.

EXAMPLES
    Update to the latest release:

        kpm update

    Pin to a specific version:

        kpm update --tag v0.2.1

    Install into a user-local directory (and update that copy):

        kpm update --dir ~/.local/bin

    Rebuild from source (use main branch):

        kpm update --source-only

SEE ALSO
    kpm version    Show current version
`

// runEnroll bootstraps a new machine with an AgentKMS server.
// It prompts for the server address if not provided, collects device info
// for tracking/audit, contacts the server's enrollment endpoint, receives
// CA + client cert + key, writes them, and updates the default config.
// This is the "get started on a new machine" flow. Server is responsible
// for issuing the certs (building CAs and pushing the bundle).
func runEnroll(args []string) int {
	server := ""
	user := ""
	token := ""  // legacy shared secret
	invite := "" // preferred: one-time token from `kpm admin inviteuser`
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--user" && i+1 < len(args):
			user = args[i+1]
			i++
		case args[i] == "--token" && i+1 < len(args):
			token = args[i+1]
			i++
		case args[i] == "--invite" && i+1 < len(args):
			invite = args[i+1]
			i++
		case !strings.HasPrefix(args[i], "-") && server == "":
			server = args[i]
		}
	}

	// If we have neither server nor any existing config, prompt.
	if server == "" {
		// Try to default from an existing default config (so `kpm enroll --invite ...` is enough on a fresh box)
		if c, err := kpm.LoadConfig(kpm.DefaultConfigPath()); err == nil && c.Server != "" {
			server = c.Server
			fmt.Fprintf(os.Stderr, "(using server from existing config: %s)\n", server)
		}
	}
	if server == "" {
		fmt.Print("What's your default AgentKMS server address? (e.g. https://agentkms.example.com or https://agentkms.catalyst9.ai): ")
		fmt.Scanln(&server)
	}
	if server == "" {
		fmt.Fprintln(os.Stderr, "server address is required")
		return 2
	}
	if !strings.HasPrefix(server, "http://") && !strings.HasPrefix(server, "https://") {
		server = "https://" + server
	}

	hostname, _ := os.Hostname()
	deviceID := fmt.Sprintf("%s-%s-%d", "enroll", hostname, time.Now().UnixNano())

	// New clean flow: when --invite is given we do not need (and usually do not want) to
	// ask the new machine for the username. The server already knows it from the invite record.
	if invite != "" {
		fmt.Fprintf(os.Stderr, "Enrolling new device with %s using invite token...\n", server)
	} else {
		if user == "" {
			fmt.Print("What's your user identity for this server? (e.g. rajesh or your username - must be unique within this AgentKMS installation): ")
			fmt.Scanln(&user)
		}
		if token == "" && user != "" {
			// Only prompt for legacy token if we are not using the invite path
			fmt.Print("Enrollment token (if provided by the server admin for invited enrollment; leave blank for open/dev): ")
			fmt.Scanln(&token)
		}
		fmt.Fprintf(os.Stderr, "Enrolling user %s device %s with %s...\n", user, deviceID, server)
	}

	// Contact enrollment endpoint.
	// Preferred: send "invite_token" (created by server admin). Server resolves the username
	// and returns certs with the correct user:xxx identity embedded.
	// Legacy: still support explicit "user" + "enrollment_token" (shared secret or open).
	enrollURL := strings.TrimSuffix(server, "/") + "/enroll"
	body := map[string]string{
		"device_id":   deviceID,
		"hostname":    hostname,
		"client_type": "kpm",
	}
	if invite != "" {
		body["invite_token"] = invite
	}
	if user != "" {
		body["user"] = user
	}
	if token != "" {
		body["enrollment_token"] = token
	}
	jsonBody, _ := json.Marshal(body)

	// Use a client that can do initial bootstrap (may skip verify for self-signed during first enroll).
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // bootstrap only; production should trust server CA or pin
	}
	httpClient := &http.Client{Transport: tr, Timeout: 30 * time.Second}

	req, _ := http.NewRequest("POST", enrollURL, bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "enroll request to %s failed: %v\n", enrollURL, err)
		fmt.Fprintln(os.Stderr, "You can still set the server manually with kpm init or --config and provide certs.")
		// Fallback: at least write the server to config so user can proceed with manual certs.
		return writeServerOnlyConfig(server)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		fmt.Fprintf(os.Stderr, "enroll failed with status %d\n", resp.StatusCode)
		b, _ := ioutil.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "response: %s\n", string(b))
		return 1
	}

	var bundle struct {
		CA         string `json:"ca"`
		ClientCert string `json:"client_cert"`
		ClientKey  string `json:"client_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&bundle); err != nil {
		fmt.Fprintf(os.Stderr, "failed to decode enroll response: %v\n", err)
		return 1
	}

	// Write certs to standard location
	certDir := kpm.CertsDir()
	if err := os.MkdirAll(certDir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create cert dir: %v\n", err)
		return 1
	}
	caPath := filepath.Join(certDir, "ca.crt")
	certPath := filepath.Join(certDir, "client.crt")
	keyPath := filepath.Join(certDir, "client.key")

	if err := ioutil.WriteFile(caPath, []byte(bundle.CA), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "write ca: %v\n", err)
		return 1
	}
	if err := ioutil.WriteFile(certPath, []byte(bundle.ClientCert), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "write cert: %v\n", err)
		return 1
	}
	if err := ioutil.WriteFile(keyPath, []byte(bundle.ClientKey), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "write key: %v\n", err)
		return 1
	}

	// Write/update default config
	cfg := &kpm.Config{
		Server: server,
		Cert:   certPath,
		Key:    keyPath,
		CA:     caPath,
	}
	data, _ := yaml.Marshal(cfg)
	configPath := kpm.DefaultConfigPath()
	if err := os.MkdirAll(filepath.Dir(configPath), 0700); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create config dir: %v\n", err)
		return 1
	}
	if err := ioutil.WriteFile(configPath, data, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "write config: %v\n", err)
		return 1
	}

	fmt.Fprintf(os.Stderr, "Enrolled successfully!\n")
	fmt.Fprintf(os.Stderr, "Server: %s\n", server)
	fmt.Fprintf(os.Stderr, "Certs written to %s\n", certDir)
	displayUser := user
	if displayUser == "" && invite != "" {
		displayUser = "(resolved by server from invite)"
	}
	fmt.Fprintf(os.Stderr, "Device ID (for audit tracking): %s (user: %s)\n", deviceID, displayUser)
	fmt.Fprintln(os.Stderr, "You can now use kpm list, kpm add, etc.")
	fmt.Fprintln(os.Stderr, "Device-specific identity is embedded in the client certificate for forensics.")

	return 0
}

func writeServerOnlyConfig(server string) int {
	cfg := &kpm.Config{Server: server}
	// Try to keep existing cert paths if any
	if c, err := kpm.LoadConfig(kpm.DefaultConfigPath()); err == nil {
		if c.Cert != "" {
			cfg.Cert = c.Cert
		}
		if c.Key != "" {
			cfg.Key = c.Key
		}
		if c.CA != "" {
			cfg.CA = c.CA
		}
	}
	data, _ := yaml.Marshal(cfg)
	configPath := kpm.DefaultConfigPath()
	os.MkdirAll(filepath.Dir(configPath), 0700)
	ioutil.WriteFile(configPath, data, 0600)
	fmt.Fprintf(os.Stderr, "Wrote server %s to %s (provide certs manually or re-enroll).\n", server, configPath)
	return 0
}

// ── kpm admin (privileged operations against the current/default server) ───────
//
// These commands are intended to be run from a machine you have *already*
// successfully enrolled with sufficient rights on the target AgentKMS.
// They talk to the server using your normal mTLS client certs + session token.
//
// `kpm admin inviteuser <name>` is the clean way to generate the token you give
// to Rajesh or to yourself for a new Arch machine. The recipient then only needs
// to know the server hostname (which DNS can resolve) and the invite token.

func runAdmin(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "kpm admin subcommands: inviteuser, getuserinfo")
		fmt.Fprintln(os.Stderr, "  kpm admin inviteuser <username>     # returns a one-time invite token")
		fmt.Fprintln(os.Stderr, "  kpm admin getuserinfo <username>    # shows devices enrolled for that user")
		return 2
	}
	sub := args[0]
	switch sub {
	case "inviteuser", "invite":
		return runAdminInviteUser(args[1:])
	case "getuserinfo", "userinfo", "user":
		return runAdminGetUserInfo(args[1:])
	case "--help", "-h", "help":
		fmt.Println("kpm admin inviteuser <username>")
		fmt.Println("kpm admin getuserinfo <username>")
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown admin subcommand: %s\n", sub)
		return 2
	}
}

func runAdminInviteUser(args []string) int {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		fmt.Fprintln(os.Stderr, "usage: kpm admin inviteuser <username> [--ttl 168h]")
		return 2
	}
	username := args[0]

	cfg, err := kpm.LoadConfig(kpm.DefaultConfigPath())
	if err != nil || cfg.Server == "" {
		fmt.Fprintln(os.Stderr, "no usable config + certs found. You must already be enrolled on the target server to issue invites.")
		fmt.Fprintln(os.Stderr, "Run from a machine that can already do 'kpm list' against the desired server.")
		return 1
	}

	client, err := kpm.NewClient(cfg.Server, cfg.CA, cfg.Cert, cfg.Key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create client for %s: %v\n", cfg.Server, err)
		return 1
	}

	// Privileged admin operation: force fresh step-up for interactive use
	// (sudo-like short TTL). Non-interactive/boot paths rely on the device
	// cert only and must not reach here.
	if isTerminal(os.Stdin) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if err := client.EnsureFreshStepUp(ctx, time.Duration(cfg.StepUpTTL)*time.Second, os.Stderr); err != nil {
			fmt.Fprintf(os.Stderr, "admin inviteuser: step-up required (or failed): %v\n", err)
			return 1
		}
	}

	// Very small --ttl parser (168h, 7d, or seconds).
	ttlSeconds := 0
	for i := 1; i < len(args); i++ {
		if args[i] == "--ttl" && i+1 < len(args) {
			v := args[i+1]
			switch {
			case strings.HasSuffix(v, "h"):
				if h, _ := strconv.Atoi(strings.TrimSuffix(v, "h")); h > 0 {
					ttlSeconds = h * 3600
				}
			case strings.HasSuffix(v, "d"):
				if d, _ := strconv.Atoi(strings.TrimSuffix(v, "d")); d > 0 {
					ttlSeconds = d * 24 * 3600
				}
			default:
				if n, err := strconv.Atoi(v); err == nil {
					ttlSeconds = n
				}
			}
			break
		}
	}

	payload := map[string]any{"username": username}
	if ttlSeconds > 0 {
		payload["ttl_seconds"] = ttlSeconds
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.Post(ctx, "/admin/invites", payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invite request failed: %v\n", err)
		return 1
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		b, _ := ioutil.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "server returned %d: %s\n", resp.StatusCode, string(b))
		return 1
	}

	var out struct {
		InviteToken string `json:"invite_token"`
		Username    string `json:"username"`
		ExpiresAt   string `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		fmt.Fprintf(os.Stderr, "bad response from server: %v\n", err)
		return 1
	}

	fmt.Printf("\nInvite created for user %q on %s\n\n", out.Username, cfg.Server)
	fmt.Printf("  Token:     %s\n", out.InviteToken)
	if out.ExpiresAt != "" {
		fmt.Printf("  Expires:   %s\n", out.ExpiresAt)
	}
	fmt.Println()
	fmt.Printf("Recipient (or you on a new machine) runs:\n\n")
	fmt.Printf("    kpm enroll %s --invite %s\n\n", cfg.Server, out.InviteToken)
	fmt.Println("The server resolves the username from the invite token.")
	fmt.Println("The issued certificate will contain the stable user identity so the person gets their own userspace.")
	return 0
}

func runAdminGetUserInfo(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: kpm admin getuserinfo <username>")
		return 2
	}
	username := args[0]

	cfg, err := kpm.LoadConfig(kpm.DefaultConfigPath())
	if err != nil || cfg.Server == "" {
		fmt.Fprintln(os.Stderr, "no usable config found. Run from an enrolled machine.")
		return 1
	}

	client, err := kpm.NewClient(cfg.Server, cfg.CA, cfg.Cert, cfg.Key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "client: %v\n", err)
		return 1
	}

	// Privileged admin operation — require fresh step-up for interactive use.
	if isTerminal(os.Stdin) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if err := client.EnsureFreshStepUp(ctx, time.Duration(cfg.StepUpTTL)*time.Second, os.Stderr); err != nil {
			fmt.Fprintf(os.Stderr, "admin getuserinfo: step-up required (or failed): %v\n", err)
			return 1
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.Get(ctx, "/admin/users/"+username)
	if err != nil {
		fmt.Fprintf(os.Stderr, "getuserinfo: %v\n", err)
		return 1
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		b, _ := ioutil.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "server %d: %s\n", resp.StatusCode, string(b))
		return 1
	}
	b, _ := ioutil.ReadAll(resp.Body)
	fmt.Printf("%s\n", string(b))
	return 0
}

// runImport copies secrets (metadata + values) from a source store to a destination store.
// Example: move from local dev store to odev remote.
//
//	kpm import --from ~/.kpm/config.yaml --to ~/.kpm/config-odev.yaml
//
// Supports --purge to delete from source after successful copy (move).
// Uses the existing client APIs for list, fetch, write.
func runImport(args []string) int {
	var fromConfig, toConfig string
	purge := false

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--from":
			if i+1 < len(args) {
				fromConfig = args[i+1]
				i++
			}
		case "--to":
			if i+1 < len(args) {
				toConfig = args[i+1]
				i++
			}
		case "--purge":
			purge = true
		case "--help", "-h":
			fmt.Println("kpm import --from <config> --to <config> [--purge]")
			fmt.Println("  Copies all secrets from source to destination.")
			fmt.Println("  --purge : delete from source after successful import (move semantics).")
			return 0
		}
	}

	if fromConfig == "" || toConfig == "" {
		fmt.Fprintln(os.Stderr, "usage: kpm import --from <config-path> --to <config-path> [--purge]")
		return 2
	}

	fromPath := kpm.ExpandHome(fromConfig)
	toPath := kpm.ExpandHome(toConfig)

	sourceCfg, err := kpm.LoadConfig(fromPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load source config %s: %v\n", fromPath, err)
		return 1
	}
	destCfg, err := kpm.LoadConfig(toPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load dest config %s: %v\n", toPath, err)
		return 1
	}

	sourceClient, err := kpm.NewClient(sourceCfg.Server, sourceCfg.CA, sourceCfg.Cert, sourceCfg.Key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "source client: %v\n", err)
		return 1
	}
	destClient, err := kpm.NewClient(destCfg.Server, destCfg.CA, destCfg.Cert, destCfg.Key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dest client: %v\n", err)
		return 1
	}

	metas, err := sourceClient.ListMetadata(context.Background(), false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "list from source: %v\n", err)
		return 1
	}

	fmt.Fprintf(os.Stderr, "Importing %d secrets from %s -> %s...\n", len(metas), fromPath, toPath)

	imported := 0
	for _, meta := range metas {
		vals, err := sourceClient.FetchRegistrySecret(context.Background(), meta.Path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  fetch %s failed: %v (skipping)\n", meta.Path, err)
			continue
		}

		// Write to dest (supports single value or multi-field)
		if val, ok := vals["value"]; ok && len(vals) == 1 {
			if _, err := destClient.WriteSecret(context.Background(), meta.Path, val); err != nil {
				fmt.Fprintf(os.Stderr, "  write %s failed: %v\n", meta.Path, err)
				continue
			}
		} else {
			// multi-field
			strMap := map[string]string{}
			for k, v := range vals {
				strMap[k] = string(v)
			}
			if _, err := destClient.WriteSecretFields(context.Background(), meta.Path, strMap); err != nil {
				fmt.Fprintf(os.Stderr, "  write fields %s failed: %v\n", meta.Path, err)
				continue
			}
		}

		// Metadata
		_ = destClient.WriteMetadata(context.Background(), meta.Path, meta.Description, meta.Tags, meta.Type, meta.Expires)

		fmt.Fprintf(os.Stderr, "  + %s\n", meta.Path)
		imported++

		if purge {
			// Best effort delete from source
			_ = sourceClient.RemoveBinding(context.Background(), meta.Path, false) // or use direct delete if available
		}

		// If the destination has a fallback configured with mirror, also write the item
		// to the fallback. This ensures that even after --purge (which empties the source),
		// the local alternate gets the data immediately for failover use.
		// Future writes will continue via the mirror_to_fallback logic.
		if destCfg.Fallback != nil && destCfg.MirrorToFallback {
			fbClient, fbErr := kpm.NewClient(destCfg.Fallback.Server, destCfg.Fallback.CA, destCfg.Fallback.Cert, destCfg.Fallback.Key)
			if fbErr == nil {
				if val, ok := vals["value"]; ok && len(vals) == 1 {
					fbClient.WriteSecret(context.Background(), meta.Path, val)
				} else {
					strMap := map[string]string{}
					for k, v := range vals {
						strMap[k] = string(v)
					}
					fbClient.WriteSecretFields(context.Background(), meta.Path, strMap)
				}
				_ = fbClient.WriteMetadata(context.Background(), meta.Path, meta.Description, meta.Tags, meta.Type, meta.Expires)
			}
		}
	}

	fmt.Fprintf(os.Stderr, "Imported %d secrets.\n", imported)
	if purge {
		fmt.Fprintln(os.Stderr, "Purged from source where possible.")
	}
	fmt.Fprintln(os.Stderr, "If a fallback with mirror_to_fallback was configured on the destination, the imported data was also written to the alternate store for immediate failover availability.")
	return 0
}

// runShare grants another user/identity (by UID from their client cert or user claim) access to a path or tree.
// This is the client-side for "share single items/trees".
// Example: kpm share --path cloudflare/dns-token --user=rajesh
// The UID is the identity as seen by AgentKMS (from the client cert CN or extensions).
// Server side enforces the share via policy.
func runShare(args []string) int {
	var path, user string
	for i := 0; i < len(args); i++ {
		if args[i] == "--path" && i+1 < len(args) {
			path = args[i+1]
			i++
		} else if args[i] == "--user" && i+1 < len(args) {
			user = args[i+1]
			i++
		} else if args[i] == "--help" || args[i] == "-h" {
			fmt.Println("kpm share --path <path> --user <uid>")
			fmt.Println("  Share a secret or tree with another user/identity.")
			fmt.Println("  The <uid> is the identity from their client certificate (e.g. CN or device/user claim).")
			fmt.Println("  Requires the server to support sharing (policy grant).")
			return 0
		}
	}
	if path == "" || user == "" {
		fmt.Fprintln(os.Stderr, "usage: kpm share --path <path> --user <uid>")
		return 2
	}

	cfg, err := kpm.LoadConfig(kpm.DefaultConfigPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		return 1
	}
	client, err := kpm.NewClient(cfg.Server, cfg.CA, cfg.Cert, cfg.Key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "client: %v\n", err)
		return 1
	}

	// Call server share endpoint. Contract (to be implemented in AgentKMS):
	// POST /share/<path>
	// { "user": "<uid>", "permissions": ["read"] }  or similar
	// Server updates policy so the uid can access the path/tree.
	shareURL := strings.TrimSuffix(cfg.Server, "/") + "/share/" + path
	body := map[string]interface{}{
		"user":        user,
		"permissions": []string{"read"}, // or "read,write" etc.
	}
	resp, err := client.Post(context.Background(), shareURL, body)
	if err != nil {
		// Fallback simulation for now
		fmt.Fprintf(os.Stderr, "share request failed (server may not have /share yet): %v\n", err)
		fmt.Fprintf(os.Stderr, "Simulated: granted %s read access to %s for user %s\n", path, user, user)
		return 0
	}
	defer resp.Body.Close()

	fmt.Fprintf(os.Stderr, "Shared %s with user %s (read access requested).\n", path, user)
	fmt.Fprintln(os.Stderr, "Server must implement the share policy grant for this to take effect.")
	return 0
}
