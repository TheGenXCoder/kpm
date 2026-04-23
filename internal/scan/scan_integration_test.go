package scan_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const canary = "sk-proj-verySecretCanaryValue1234567f2a"

// init blocks the process when acting as a canary subprocess.
// The integration test binary re-execs itself with KPM_INTEG_CHILD=1 so that
// ps -E can observe its environment — this avoids spawning SIP-protected
// binaries (e.g. /bin/sleep, /usr/bin/tail) whose env is hidden on macOS.
func init() {
	if os.Getenv("KPM_INTEG_CHILD") != "1" {
		return
	}
	// Block until killed. Listen on a signal channel to prevent Go's
	// runtime deadlock detector from firing on an empty select.
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	<-ch
	os.Exit(0)
}

func buildKpm(t *testing.T) string {
	t.Helper()
	binPath := filepath.Join(t.TempDir(), "kpm")
	cmd := exec.Command("go", "build", "-o", binPath, "./cmd/kpm")
	cmd.Dir = findRepoRoot(t)
	cmd.Env = append(os.Environ(), "GOWORK=off")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build kpm: %v: %s", err, stderr.String())
	}
	return binPath
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	cwd, _ := os.Getwd()
	dir := cwd
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not find repo root")
	return ""
}

func runKpm(bin string, args ...string) (stdout, stderr string, exitCode int) {
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "GOWORK=off")
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	exitCode = 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}
	return out.String(), errb.String(), exitCode
}

func TestE2E_ScanFiles_NeverLeaksCanary(t *testing.T) {
	bin := buildKpm(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"),
		[]byte("api_key: "+canary+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"scan", "files", dir},
		{"scan", "files", "--json", dir},
		{"scan", "files", "--quiet", dir},
	} {
		stdout, stderr, _ := runKpm(bin, args...)
		if strings.Contains(stdout+stderr, canary) {
			t.Errorf("%v leaked canary:\nSTDOUT:\n%s\nSTDERR:\n%s", args, stdout, stderr)
		}
	}
}

func TestE2E_ScanLogs_NeverLeaksCanary(t *testing.T) {
	bin := buildKpm(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "app.log")
	if err := os.WriteFile(logPath,
		[]byte("line 1\nkey="+canary+"\nline 3\n"), 0644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"scan", "logs", logPath},
		{"scan", "logs", "--json", logPath},
		{"scan", "logs", "--quiet", logPath},
	} {
		stdout, stderr, _ := runKpm(bin, args...)
		if strings.Contains(stdout+stderr, canary) {
			t.Errorf("%v leaked canary:\nSTDOUT:\n%s\nSTDERR:\n%s", args, stdout, stderr)
		}
	}
}

// TestE2E_ScanShell_NeverLeaksCanary spawns the test binary itself as a
// subprocess with LEAK_CANARY_TOKEN set. This avoids spawning SIP-protected
// system binaries (e.g. /usr/bin/tail, /bin/sleep) whose environment is
// hidden from ps -E on macOS. The subprocess blocks in the init() hook above
// until killed.
func TestE2E_ScanShell_NeverLeaksCanary(t *testing.T) {
	bin := buildKpm(t)

	// Re-exec the test binary as a blocking child that holds the canary env var.
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	sub := exec.Command(exe, "-test.run=^$")
	sub.Env = append(os.Environ(),
		"KPM_INTEG_CHILD=1",
		"LEAK_CANARY_TOKEN="+canary,
	)
	if err := sub.Start(); err != nil {
		t.Fatalf("spawn canary child: %v", err)
	}
	defer func() { _ = sub.Process.Kill() }()
	// Give ps time to register the new process.
	time.Sleep(300 * time.Millisecond)

	for _, args := range [][]string{
		{"scan", "shell"},
		{"scan", "shell", "--json"},
		{"scan", "shell", "--quiet"},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Env = append(os.Environ(), "GOWORK=off")
		var out, errb bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &errb
		_ = cmd.Run()
		cancel()
		if strings.Contains(out.String()+errb.String(), canary) {
			t.Errorf("%v leaked canary:\nSTDOUT:\n%s\nSTDERR:\n%s",
				args, out.String(), errb.String())
		}
	}
}

func TestE2E_ExitCodes(t *testing.T) {
	bin := buildKpm(t)

	// Clean directory — exit 0
	clean := t.TempDir()
	if err := os.WriteFile(filepath.Join(clean, "hello.txt"), []byte("hello\n"), 0644); err != nil {
		t.Fatal(err)
	}
	_, _, code := runKpm(bin, "scan", "files", "--quiet", clean)
	if code != 0 {
		t.Errorf("clean scan: want 0, got %d", code)
	}

	// Dirty directory — exit 1
	dirty := t.TempDir()
	if err := os.WriteFile(filepath.Join(dirty, "config.yaml"),
		[]byte("api_key: "+canary+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	_, _, code = runKpm(bin, "scan", "files", "--quiet", dirty)
	if code != 1 {
		t.Errorf("dirty scan: want 1, got %d", code)
	}

	// Unknown mode — exit 2
	_, _, code = runKpm(bin, "scan", "bogus")
	if code != 2 {
		t.Errorf("unknown mode: want 2, got %d", code)
	}
}
