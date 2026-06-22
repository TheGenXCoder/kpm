//go:build !windows

package scan

import "syscall"

type syscallStatT = syscall.Stat_t
