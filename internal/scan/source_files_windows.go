//go:build windows

package scan

// syscallStatT is a placeholder on Windows. dirInodeKey will not match it
// against os.FileInfo.Sys(), so directory cycle detection falls back to treating
// directories as unique on Windows.
type syscallStatT struct {
	Dev uint64
	Ino uint64
}
