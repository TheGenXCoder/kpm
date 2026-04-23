//go:build darwin

package scan

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
)

func enumerateProcesses(ctx context.Context) ([]process, error) {
	uid := os.Getuid()
	userName := strconv.Itoa(uid)
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		userName = u.Username
	}

	cmd := exec.CommandContext(ctx, "ps", "-U", strconv.Itoa(uid), "-o", "pid=,comm=,command=")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ps failed: %v: %s", err, stderr.String())
	}

	envCmd := exec.CommandContext(ctx, "ps", "-U", strconv.Itoa(uid), "-E", "-o", "pid=,command=")
	var envOut bytes.Buffer
	envCmd.Stdout = &envOut
	if err := envCmd.Run(); err != nil {
		return nil, fmt.Errorf("ps -E failed: %w", err)
	}

	type basic struct {
		pid           int
		comm, command string
	}
	basics := map[int]basic{}
	for _, line := range strings.Split(strings.TrimRight(stdout.String(), "\n"), "\n") {
		if line == "" {
			continue
		}
		fields := strings.SplitN(strings.TrimLeft(line, " "), " ", 3)
		if len(fields) < 3 {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(fields[0]))
		if err != nil {
			continue
		}
		basics[pid] = basic{pid: pid, comm: strings.TrimSpace(fields[1]), command: fields[2]}
	}

	var procs []process
	for _, line := range strings.Split(strings.TrimRight(envOut.String(), "\n"), "\n") {
		if line == "" {
			continue
		}
		trimmed := strings.TrimLeft(line, " ")
		space := strings.Index(trimmed, " ")
		if space < 0 {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(trimmed[:space]))
		if err != nil {
			continue
		}
		rest := trimmed[space+1:]
		env := parseDarwinEnvLine(rest)

		b := basics[pid]
		procs = append(procs, process{PID: pid, User: userName, Comm: b.comm, Command: b.command, Env: env})
	}
	return procs, nil
}

func parseDarwinEnvLine(s string) map[string]string {
	env := map[string]string{}
	remaining := s
	for remaining != "" {
		space := strings.Index(remaining, " ")
		var token string
		if space < 0 {
			token = remaining
			remaining = ""
		} else {
			token = remaining[:space]
			remaining = remaining[space+1:]
		}
		eq := strings.Index(token, "=")
		if eq <= 0 {
			// Not an env token (could be command name or arg); skip it.
			continue
		}
		name := token[:eq]
		if !looksLikeEnvName(name) {
			// Doesn't look like a valid env var name; skip.
			continue
		}
		env[name] = token[eq+1:]
	}
	return env
}

func looksLikeEnvName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if i == 0 && !(r == '_' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z')) {
			return false
		}
		if !(r == '_' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}
