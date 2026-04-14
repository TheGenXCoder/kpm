package kpm

import (
	"context"
	"runtime"
	"testing"
)

func TestBuildEnv(t *testing.T) {
	entries := []ResolvedEntry{
		{EnvKey: "APP_NAME", PlainValue: []byte("test")},
		{EnvKey: "SECRET", PlainValue: []byte("s3cret")},
	}

	env := BuildEnv(entries)

	found := map[string]bool{}
	for _, e := range env {
		if e == "APP_NAME=test" {
			found["APP_NAME"] = true
		}
		if e == "SECRET=s3cret" {
			found["SECRET"] = true
		}
	}
	if !found["APP_NAME"] || !found["SECRET"] {
		t.Errorf("missing expected env vars in %v", env)
	}

	if len(env) <= 2 {
		t.Error("expected inherited env vars too")
	}
}

func TestRunCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skip on windows")
	}

	entries := []ResolvedEntry{
		{EnvKey: "KPM_TEST_VAR", PlainValue: []byte("hello")},
	}

	exitCode, err := RunCommand(context.Background(), entries, "sh", []string{"-c", "echo $KPM_TEST_VAR"})
	if err != nil {
		t.Fatalf("RunCommand: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exit code = %d, want 0", exitCode)
	}
}

func TestRunCommandFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skip on windows")
	}

	entries := []ResolvedEntry{}
	exitCode, err := RunCommand(context.Background(), entries, "sh", []string{"-c", "exit 42"})
	if err != nil {
		t.Fatalf("RunCommand: %v", err)
	}
	if exitCode != 42 {
		t.Errorf("exit code = %d, want 42", exitCode)
	}
}

func TestRunCommandNotFound(t *testing.T) {
	entries := []ResolvedEntry{}
	_, err := RunCommand(context.Background(), entries, "/nonexistent/binary", nil)
	if err == nil {
		t.Fatal("expected error for missing binary")
	}
}
