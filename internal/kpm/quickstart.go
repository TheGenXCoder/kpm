package kpm

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/TheGenXCoder/kpm/pkg/tlsutil"
)

// Quickstart sets up a complete local KPM + AgentKMS dev environment.
// It enrolls PKI, starts the dev server, seeds demo secrets, and writes
// ~/.kpm/ config + templates. Designed to run before ~/.kpm/config.yaml exists.
func Quickstart(w io.Writer) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot determine home directory: %w", err)
	}
	devDir := filepath.Join(home, ".agentkms", "dev")
	kpmDir := filepath.Join(home, ".kpm")

	// Step 1: Check agentkms-dev is available — build it if not
	devBin, err := exec.LookPath("agentkms-dev")
	if err != nil {
		fmt.Fprintln(w, "  agentkms-dev not found — building from source...")
		devBin, err = buildDevServer(w)
		if err != nil {
			return fmt.Errorf("failed to build agentkms-dev: %w", err)
		}
	}
	fmt.Fprintf(w, "✓ Found agentkms-dev at %s\n", devBin)

	// Step 2: Enroll (generate PKI) — skip if certs already exist
	caPath := filepath.Join(devDir, "ca.crt")
	if _, err := os.Stat(caPath); os.IsNotExist(err) {
		fmt.Fprintln(w, "  Generating PKI (CA + server + client certificates)...")
		cmd := exec.Command("agentkms-dev", "enroll")
		cmd.Stdout = io.Discard
		cmd.Stderr = w
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("enrollment failed: %w", err)
		}
		fmt.Fprintln(w, "✓ PKI generated")
	} else {
		fmt.Fprintln(w, "✓ PKI already exists (skipping enrollment)")
	}

	// Step 3: Start dev server in background
	fmt.Fprintln(w, "  Starting AgentKMS dev server...")
	serverCmd := exec.Command("agentkms-dev", "serve", "--rate-limit", "0")
	serverCmd.Stdout = io.Discard
	serverCmd.Stderr = io.Discard
	if err := serverCmd.Start(); err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}
	fmt.Fprintf(w, "✓ AgentKMS dev server started (PID %d)\n", serverCmd.Process.Pid)

	// Step 4: Wait for healthy — poll /healthz with mTLS
	fmt.Fprintln(w, "  Waiting for server to be healthy...")
	clientCertDir := filepath.Join(devDir, "clients", "forge-gateway")
	healthy := waitForHealthy(clientCertDir, 30, 500*time.Millisecond)
	if !healthy {
		// Server started but not healthy — kill it so we don't leave a zombie
		serverCmd.Process.Kill() //nolint:errcheck
		return fmt.Errorf("server did not become healthy within 15 seconds\n" +
			"  Check: agentkms-dev serve --rate-limit 0")
	}
	fmt.Fprintln(w, "✓ Server healthy")

	// Step 5: Seed demo secrets (best-effort — paths may already exist)
	fmt.Fprintln(w, "  Seeding demo secrets...")
	seeds := [][]string{
		{"secrets", "set", "generic/db/prod", "host=db.prod.internal", "port=5432", "password=s3cret-pg-pass", "user=app_service"},
		{"secrets", "set", "generic/app/config", "jwt_secret=hmac-demo-key-2026", "session_timeout=3600"},
		{"secrets", "set", "generic/github", "token=ghp_demo1234567890abcdef"},
		{"secrets", "set", "llm/anthropic", "api_key=sk-demo-anthropic-key-for-testing"},
		{"secrets", "set", "llm/openai", "api_key=sk-demo-openai-key-for-testing"},
	}
	for _, args := range seeds {
		cmd := exec.Command("agentkms-dev", args...)
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		cmd.Run() //nolint:errcheck — best-effort; some paths may already exist
	}
	fmt.Fprintln(w, "✓ Demo secrets loaded (5 credential paths)")

	// Step 6: Set up ~/.kpm/
	fmt.Fprintln(w, "  Setting up KPM config and templates...")

	// Certs
	certsDir := filepath.Join(kpmDir, "certs")
	if err := os.MkdirAll(certsDir, 0700); err != nil {
		return fmt.Errorf("create certs dir: %w", err)
	}
	for _, name := range []string{"ca.crt", "client.crt", "client.key"} {
		src := filepath.Join(clientCertDir, name)
		dst := filepath.Join(certsDir, name)
		data, err := os.ReadFile(src)
		if err != nil {
			return fmt.Errorf("read cert %s: %w", name, err)
		}
		if err := os.WriteFile(dst, data, 0600); err != nil {
			return fmt.Errorf("write cert %s: %w", name, err)
		}
	}

	// Config
	configYAML := `server: https://127.0.0.1:8443
cert: ~/.kpm/certs/client.crt
key: ~/.kpm/certs/client.key
ca: ~/.kpm/certs/ca.crt
default_template: .env.template
secure_mode: false
session_key_ttl: 3600
`
	if err := os.WriteFile(filepath.Join(kpmDir, "config.yaml"), []byte(configYAML), 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	// User templates (global, in ~/.kpm/templates/)
	userTmplDir := filepath.Join(kpmDir, "templates")
	if err := os.MkdirAll(userTmplDir, 0755); err != nil {
		return fmt.Errorf("create user templates dir: %w", err)
	}

	shellEnv := `# Shell environment — add to .zshrc:
# eval $(kpm env --from ~/.kpm/templates/shell-env.template --plaintext --output shell 2>/dev/null)
ANTHROPIC_API_KEY=${kms:llm/anthropic}
OPENAI_API_KEY=${kms:llm/openai}
GITHUB_TOKEN=${kms:kv/github#token}
`
	if err := os.WriteFile(filepath.Join(userTmplDir, "shell-env.template"), []byte(shellEnv), 0644); err != nil {
		return fmt.Errorf("write shell-env.template: %w", err)
	}

	// Project-level example template in the current working directory
	appEnv := `# Project .env.template — commit this file, not your .env
APP_NAME=my-service
LOG_LEVEL=info
PORT=8080
DB_HOST=${kms:kv/db/prod#host}
DB_PORT=${kms:kv/db/prod#port}
DB_PASSWORD=${kms:kv/db/prod#password}
JWT_SECRET=${kms:kv/app/config#jwt_secret}
`
	if err := os.MkdirAll(".kpm/templates", 0755); err == nil {
		// Best-effort — don't fail if cwd is read-only
		os.WriteFile(".kpm/templates/.env.template", []byte(appEnv), 0644) //nolint:errcheck
	}

	fmt.Fprintln(w, "✓ Config, certs, and templates ready")

	// Step 7: Summary
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "KPM quickstart complete!")
	fmt.Fprintln(w, "")
	fmt.Fprintf(w, "AgentKMS dev server running at https://127.0.0.1:8443\n")
	fmt.Fprintf(w, "Server PID: %d  (stop with: kill %d)\n", serverCmd.Process.Pid, serverCmd.Process.Pid)
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Try these:")
	fmt.Fprintln(w, "  kpm tree")
	fmt.Fprintln(w, "  kpm env --from .kpm/templates/.env.template             # secure (default)")
	fmt.Fprintln(w, "  kpm env --from .kpm/templates/.env.template --plaintext # raw values")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Add to your .zshrc:")
	fmt.Fprintln(w, `  eval $(kpm env --from ~/.kpm/templates/shell-env.template --plaintext --output shell 2>/dev/null)`)

	// Detach the server process so it survives kpm exit
	serverCmd.Process.Release() //nolint:errcheck

	return nil
}

// buildDevServer clones the repo and builds agentkms-dev from source.
// This is called by quickstart when agentkms-dev is not in PATH.
func buildDevServer(w io.Writer) (string, error) {
	// Check for go
	if _, err := exec.LookPath("go"); err != nil {
		return "", fmt.Errorf("go is required to build agentkms-dev")
	}
	if _, err := exec.LookPath("git"); err != nil {
		return "", fmt.Errorf("git is required to build agentkms-dev")
	}

	buildDir, err := os.MkdirTemp("", "kpm-dev-build-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(buildDir)

	// Clone
	fmt.Fprintln(w, "  Cloning agentkms repo...")
	clone := exec.Command("git", "clone", "--depth", "1", "--branch", "feat/kpm-go-rewrite",
		"https://github.com/TheGenXCoder/agentkms.git", filepath.Join(buildDir, "agentkms"))
	clone.Stdout = io.Discard
	clone.Stderr = io.Discard
	if err := clone.Run(); err != nil {
		return "", fmt.Errorf("git clone: %w", err)
	}

	// Build
	fmt.Fprintln(w, "  Building agentkms-dev server...")
	outPath := filepath.Join(buildDir, "agentkms-dev")
	build := exec.Command("go", "build", "-o", outPath, "./cmd/dev/")
	build.Dir = filepath.Join(buildDir, "agentkms")
	build.Stdout = io.Discard
	build.Stderr = w
	if err := build.Run(); err != nil {
		return "", fmt.Errorf("go build: %w", err)
	}

	// Install to /usr/local/bin or ~/go/bin
	installDir := "/usr/local/bin"
	destPath := filepath.Join(installDir, "agentkms-dev")

	// Try direct move first, sudo if needed
	if err := os.Rename(outPath, destPath); err != nil {
		sudo := exec.Command("sudo", "mv", outPath, destPath)
		sudo.Stderr = w
		if err := sudo.Run(); err != nil {
			// Fallback: install to ~/go/bin
			home, _ := os.UserHomeDir()
			installDir = filepath.Join(home, "go", "bin")
			os.MkdirAll(installDir, 0755)
			destPath = filepath.Join(installDir, "agentkms-dev")
			if err := os.Rename(outPath, destPath); err != nil {
				return "", fmt.Errorf("install: %w", err)
			}
		}
	}
	os.Chmod(destPath, 0755)

	return destPath, nil
}

// waitForHealthy polls /healthz over mTLS until the server responds 200 OK.
// It returns true if the server became healthy before attempts were exhausted.
func waitForHealthy(clientCertDir string, attempts int, interval time.Duration) bool {
	caBytes, err := os.ReadFile(filepath.Join(clientCertDir, "ca.crt"))
	if err != nil {
		return false
	}
	certBytes, err := os.ReadFile(filepath.Join(clientCertDir, "client.crt"))
	if err != nil {
		return false
	}
	keyBytes, err := os.ReadFile(filepath.Join(clientCertDir, "client.key"))
	if err != nil {
		return false
	}

	tlsCfg, err := tlsutil.ClientTLSConfig(caBytes, certBytes, keyBytes)
	if err != nil {
		return false
	}

	hc := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	}

	for i := 0; i < attempts; i++ {
		time.Sleep(interval)
		resp, err := hc.Get("https://127.0.0.1:8443/healthz")
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return true
		}
	}
	return false
}

