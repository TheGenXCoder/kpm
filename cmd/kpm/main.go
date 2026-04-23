package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/TheGenXCoder/kpm/internal/kpm"
	"github.com/TheGenXCoder/kpm/internal/scan"
)

const usage = `kpm — secure secrets CLI backed by AgentKMS

Usage:
  kpm quickstart                  Set up local dev environment (no server needed)
  kpm shell-init                  Shell integration (add to .bashrc/.zshrc)
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
  kpm scan <mode>                 Scan for exposed secrets (shell, files, logs)
  kpm version                     Print version

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
`

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	subcmd := os.Args[1]

	fs := flag.NewFlagSet("kpm", flag.ExitOnError)
	configPath := fs.String("config", kpm.DefaultConfigPath(), "config file path")
	serverFlag := fs.String("server", "", "AgentKMS server URL")
	certFlag := fs.String("cert", "", "mTLS client cert path")
	keyFlag := fs.String("key", "", "mTLS client key path")
	caFlag := fs.String("ca", "", "CA cert path")
	verbose := fs.Bool("verbose", false, "debug output")

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

	switch subcmd {
	case "version":
		fmt.Println("kpm", version)
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
	case "env", "export", "run", "get", "init", "decrypt", "config",
		"add", "list", "describe", "history", "remove":
		if err := fs.Parse(os.Args[2:]); err != nil {
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n%s", subcmd, usage)
		os.Exit(1)
	}

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

func buildClient(cfg *kpm.Config) *kpm.Client {
	if cfg.Server == "" || cfg.Cert == "" || cfg.Key == "" || cfg.CA == "" {
		fmt.Fprintln(os.Stderr, "error: server, cert, key, and ca are required (set via config or flags)")
		fmt.Fprintln(os.Stderr, "run: kpm init")
		os.Exit(1)
	}
	client, err := kpm.NewClient(cfg.Server, cfg.CA, cfg.Cert, cfg.Key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating client: %v\n", err)
		os.Exit(1)
	}
	return client
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
		sessionID = fmt.Sprintf("strict-%x", randKey[:4])
		kpm.ZeroBytes(randKey)

		sockPath = filepath.Join(os.TempDir(), fmt.Sprintf("kpm-%s.sock", sessionID))

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
		listenerCmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if startErr := listenerCmd.Start(); startErr != nil {
			fmt.Fprintf(os.Stderr, "error starting strict listener: %v\n", startErr)
			os.Exit(1)
		}
		listenerCmd.Process.Release()

		// Wait briefly for the socket to appear.
		for i := 0; i < 100; i++ {
			if _, statErr := os.Stat(sockPath); statErr == nil {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}

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

		sessionID = fmt.Sprintf("s%x", sk[:4])
		sockPath = filepath.Join(os.TempDir(), fmt.Sprintf("kpm-%s.sock", sessionID))
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
		listenerCmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
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

		// Wait briefly for the socket to appear before output is consumed.
		for i := 0; i < 100; i++ {
			if _, statErr := os.Stat(sockPath); statErr == nil {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}

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
		sessionID := fmt.Sprintf("strict-%x", randKey[:4])
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

		sockPath := filepath.Join(os.TempDir(), fmt.Sprintf("kpm-%s.sock", sessionID))
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

		for i := 0; i < 50; i++ {
			if _, statErr := os.Stat(sockPath); statErr == nil {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}

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

		sessionID := fmt.Sprintf("s%x", sk[:4])
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

		sockPath := filepath.Join(os.TempDir(), fmt.Sprintf("kpm-%s.sock", sessionID))
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

		for i := 0; i < 50; i++ {
			if _, statErr := os.Stat(sockPath); statErr == nil {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}

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

	conn, err := net.Dial("unix", sockPath)
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
