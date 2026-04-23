//go:build darwin

package scan

import (
	"context"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

// TestMain handles the child-worker re-exec pattern.
// When KPM_TEST_CHILD_WORKER=1, the process simply blocks so the parent test
// can enumerate it via ps -E.
func TestMain(m *testing.M) {
	if os.Getenv("KPM_TEST_CHILD_WORKER") == "1" {
		// Block on a signal channel to avoid Go runtime deadlock detection.
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
		<-c
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestRunShell_Darwin_DetectsCanaryInSubprocess(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	cmd := exec.Command(exe, "-test.run=^$")
	cmd.Env = append(os.Environ(),
		"KPM_TEST_CHILD_WORKER=1",
		"LEAK_CANARY_SECRET=sk-proj-verySecretCanaryValue1234567f2a",
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to spawn worker: %v", err)
	}
	defer func() { _ = cmd.Process.Kill() }()
	time.Sleep(300 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := RunShell(ctx, ShellOptions{Mode: ModeDefault})
	if err != nil {
		t.Fatalf("RunShell: %v", err)
	}

	found := false
	for _, f := range result.Findings {
		s, ok := f.Source.(ShellRef)
		if !ok {
			continue
		}
		if s.PID == cmd.Process.Pid && f.Variable == "LEAK_CANARY_SECRET" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected to find LEAK_CANARY_SECRET on pid %d; got %d findings total",
			cmd.Process.Pid, len(result.Findings))
	}

	_, err = RunShell(context.Background(), ShellOptions{AllUsers: true})
	if err == nil {
		t.Errorf("expected error for --all-users, got nil")
	}
}
