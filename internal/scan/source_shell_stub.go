//go:build !linux && !darwin

package scan

import (
	"context"
	"fmt"
	"runtime"
)

func enumerateProcesses(ctx context.Context) ([]process, error) {
	return nil, fmt.Errorf("%w: %s", ErrUnsupportedPlatform, runtime.GOOS)
}
