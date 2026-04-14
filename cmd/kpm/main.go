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
)

const usage = `kpm — secure secrets CLI backed by AgentKMS

Usage:
  kpm quickstart                  Set up local dev environment (no server needed)
  kpm env [flags]                 Resolve template (secure by default)
  kpm run [flags] -- <cmd> [args] Resolve template and run command with env
  kpm get <ref>                   Fetch a single secret
  kpm init                        Create ~/.kpm/config.yaml
  kpm tree                        Show template hierarchy and managed secrets
  kpm show [VAR_NAME]             Show managed secrets in current environment
  kpm config push [dir]           Push templates to AgentKMS (requires agentkms-dev)
  kpm config pull [dir]           Pull templates from AgentKMS
  kpm version                     Print version

Global flags:
  --config <path>   Config file (default: ~/.kpm/config.yaml)
  --server <url>    AgentKMS server URL (overrides config)
  --cert <path>     mTLS client cert (overrides config)
  --key <path>      mTLS client key (overrides config)
  --ca <path>       CA cert for AgentKMS
  --verbose         Debug output (never prints secrets)
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
	strictFlag := fs.Bool("strict", false, "enable strict ciphertext mode")
	envFlag := fs.String("env", "", "read ciphertext from this env var name")

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
	case "tree":
		levels := kpm.DiscoverTemplateLevels()
		kpm.PrintTree(os.Stdout, levels)
		return
	case "show":
		fs.Parse(os.Args[2:])
		secrets, sid := kpm.ScanManagedSecrets()
		ttl := time.Duration(0)
		if sid != "" {
			// Try to get TTL — use default 300s if no config loaded
			ttl = kpm.SessionTTLRemaining(sid, 300)
		}
		filterName := ""
		if args := fs.Args(); len(args) > 0 {
			filterName = args[0]
		}
		kpm.PrintShow(os.Stdout, secrets, sid, ttl, filterName)
		return
	case "_listen":
		// Hidden internal command — started by kpm env to run a persistent listener.
		runListen()
		return
	case "env", "export", "run", "get", "init", "decrypt", "config":
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

	home, _ := os.UserHomeDir()

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
			dir := filepath.Join(home, ".kpm", "templates")
			if len(args) > 1 {
				dir = args[1]
			}
			fmt.Fprintf(os.Stderr, "Pushing templates from %s\n", dir)
			if err := kpm.PushTemplates(os.Stderr, dir); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
		case "pull":
			dir := filepath.Join(home, ".kpm", "templates")
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
		// before falling back to default template.
		if tmplPath == "" {
			if sid, err := kpm.FindActiveSession(); err == nil {
				// Active session found — use env-scanning mode
				tmplPath = ""
				_ = sid // session ID found, runRun will rediscover it
			} else {
				tmplPath = cfg.DefaultTemplate
			}
		}
		cmdArgs := fs.Args()
		if len(cmdArgs) == 0 {
			fmt.Fprintln(os.Stderr, "kpm run: no command specified")
			os.Exit(1)
		}
		runRun(ctx, cfg, tmplPath, cmdArgs, *plaintextFlag, *strictFlag, *verbose)
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
	f, err := os.Open(tmplPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening template %s: %v\n", tmplPath, err)
		os.Exit(1)
	}
	defer f.Close()

	entries, err := kpm.ParseTemplate(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing template: %v\n", err)
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

	if !plaintext {
		// Secure mode (default): encrypt values with a session key, then fork
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

	_ = strict // strict mode reserved for future validation enforcement
}

func runRun(ctx context.Context, cfg *kpm.Config, tmplPath string, cmdArgs []string, plaintext, strict, verbose bool) {
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

	f, err := os.Open(tmplPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening template %s: %v\n", tmplPath, err)
		os.Exit(1)
	}
	defer f.Close()

	entries, err := kpm.ParseTemplate(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing template: %v\n", err)
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

	if !plaintext {
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
	parsed, ok := kpm.ParseKMSRef("${kms:" + ref + "}")
	if !ok {
		fmt.Fprintf(os.Stderr, "invalid reference: %s\nFormat: kv/path#key or llm/provider\n", ref)
		os.Exit(1)
	}

	client := buildClient(cfg)

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
		fmt.Fprintf(os.Stderr, "unknown ref type: %s\n", parsed.Type)
		os.Exit(1)
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
func runListen() {
	fs := flag.NewFlagSet("_listen", flag.ExitOnError)
	sessionFlag := fs.String("session", "", "session ID")
	socketFlag := fs.String("socket", "", "socket path")
	ttlFlag := fs.Int("ttl", 300, "TTL in seconds")
	fs.Parse(os.Args[2:])

	if *sessionFlag == "" || *socketFlag == "" {
		os.Exit(1)
	}

	// Read session key from stdin — never exposed on command line.
	key, err := io.ReadAll(os.Stdin)
	if err != nil || len(key) != 32 {
		os.Exit(1)
	}

	ttl := time.Duration(*ttlFlag) * time.Second

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
