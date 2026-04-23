//go:build linux

package scan

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestRunShell_Linux_DetectsCanaryInSubprocess(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	cmd.Env = append(os.Environ(),
		"LEAK_CANARY_SECRET=sk-proj-verySecretCanaryValue1234567f2a",
		"LEAK_CANARY_BENIGN=hello")
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to spawn: %v", err)
	}
	defer func() { _ = cmd.Process.Kill() }()

	time.Sleep(200 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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
		t.Errorf("expected to find LEAK_CANARY_SECRET on pid %d; got %d findings",
			cmd.Process.Pid, len(result.Findings))
	}
}

func TestRunShell_Linux_AllUsersReservedReturnsError(t *testing.T) {
	ctx := context.Background()
	_, err := RunShell(ctx, ShellOptions{AllUsers: true})
	if err == nil {
		t.Errorf("expected error for --all-users, got nil")
	}
}
