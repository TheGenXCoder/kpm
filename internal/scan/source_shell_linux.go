//go:build linux

package scan

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// enumerateProcesses on Linux walks /proc/<pid>/ for the current UID.
func enumerateProcesses(ctx context.Context) ([]process, error) {
	uid := os.Getuid()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("read /proc: %w", err)
	}

	// User name lookup (best-effort).
	userName := strconv.Itoa(uid)
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		userName = u.Username
	}

	var procs []process
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}

		statInfo, err := os.Stat(filepath.Join("/proc", e.Name()))
		if err != nil {
			continue
		}
		if !isOwnedByUID(statInfo, uid) {
			continue
		}

		env, err := readEnviron(pid)
		if err != nil {
			continue // skip; probably exited
		}
		comm, _ := readComm(pid)
		cmdline, _ := readCmdline(pid)

		procs = append(procs, process{
			PID:     pid,
			User:    userName,
			Comm:    comm,
			Command: cmdline,
			Env:     env,
		})
	}
	return procs, nil
}

func readEnviron(pid int) (map[string]string, error) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "environ"))
	if err != nil {
		return nil, err
	}
	env := map[string]string{}
	for _, entry := range bytes.Split(data, []byte{0}) {
		if len(entry) == 0 {
			continue
		}
		eq := bytes.IndexByte(entry, '=')
		if eq < 0 {
			continue
		}
		env[string(entry[:eq])] = string(entry[eq+1:])
	}
	return env, nil
}

func readComm(pid int) (string, error) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func readCmdline(pid int) (string, error) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(strings.ReplaceAll(string(data), "\x00", " ")), nil
}

func isOwnedByUID(info os.FileInfo, uid int) bool {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(stat.Uid) == uid
	}
	return false
}
