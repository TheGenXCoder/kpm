package kpm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
)

// BuildEnv creates a process environment from resolved entries.
// Inherits the current process env, then overlays the resolved values.
func BuildEnv(entries []ResolvedEntry) []string {
	env := os.Environ()
	for _, e := range entries {
		env = append(env, fmt.Sprintf("%s=%s", e.EnvKey, e.PlainValue))
	}
	return env
}

// RunCommandWithEnv executes a command with an explicit []string environment.
// Returns the exit code. Stdin, stdout, and stderr are inherited.
func RunCommandWithEnv(ctx context.Context, env []string, name string, args []string) (int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err == nil {
		return 0, nil
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), nil
	}

	return -1, fmt.Errorf("run %s: %w", name, err)
}

// RunCommand executes a command with resolved entries injected as env vars.
// Returns the exit code. Stdin, stdout, and stderr are inherited.
func RunCommand(ctx context.Context, entries []ResolvedEntry, name string, args []string) (int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = BuildEnv(entries)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err == nil {
		return 0, nil
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), nil
	}

	return -1, fmt.Errorf("run %s: %w", name, err)
}
