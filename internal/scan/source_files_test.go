package scan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunFiles_DetectsCanaryInFile(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "config.yaml"),
		[]byte("api_key: sk-proj-verySecretCanaryValue1234567f2a\nother: harmless\n"), 0644)
	result, err := RunFiles(context.Background(), FileOptions{Paths: []string{dir}, Mode: ModeDefault})
	if err != nil {
		t.Fatalf("RunFiles: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Fatalf("expected finding, got 0")
	}
}

func TestRunFiles_RespectsGitignore(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, ".gitignore"), []byte("ignored.yaml\n"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "ignored.yaml"),
		[]byte("api_key: sk-proj-verySecretCanaryValue1234567f2a\n"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "tracked.yaml"),
		[]byte("api_key: sk-proj-verySecretCanaryValue1234567f2a\n"), 0644)
	result, err := RunFiles(context.Background(), FileOptions{Paths: []string{dir}, Mode: ModeDefault})
	if err != nil {
		t.Fatalf("RunFiles: %v", err)
	}
	for _, f := range result.Findings {
		if filepath.Base(f.Source.(FileRef).Path) == "ignored.yaml" {
			t.Errorf("gitignored file was scanned: %s", f.Source.(FileRef).Path)
		}
	}
}

func TestRunFiles_NoGitignoreFlag_ScansIgnored(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, ".gitignore"), []byte("ignored.yaml\n"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "ignored.yaml"),
		[]byte("api_key: sk-proj-verySecretCanaryValue1234567f2a\n"), 0644)
	result, err := RunFiles(context.Background(), FileOptions{Paths: []string{dir}, Mode: ModeDefault, NoGitignore: true})
	if err != nil {
		t.Fatalf("RunFiles: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Error("expected finding from ignored file when --no-gitignore, got 0")
	}
}

func TestRunFiles_SkipsBinaryByDefault(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "blob.bin"),
		[]byte("\x00\x00api_key: sk-proj-verySecretCanaryValue1234567f2a\x00"), 0644)
	result, err := RunFiles(context.Background(), FileOptions{Paths: []string{dir}, Mode: ModeDefault})
	if err != nil {
		t.Fatalf("RunFiles: %v", err)
	}
	for _, f := range result.Findings {
		if filepath.Base(f.Source.(FileRef).Path) == "blob.bin" {
			t.Errorf("binary file was scanned by default")
		}
	}
}

func TestRunFiles_IncludeBinaryFlag(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "blob.bin"),
		[]byte("\x00\x00api_key=sk-proj-verySecretCanaryValue1234567f2a\x00"), 0644)
	result, err := RunFiles(context.Background(), FileOptions{Paths: []string{dir}, Mode: ModeDefault, IncludeBinary: true})
	if err != nil {
		t.Fatalf("RunFiles: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Error("expected binary finding with --include-binary, got 0")
	}
}

func TestRunFiles_MaxDepth(t *testing.T) {
	dir := t.TempDir()
	deep := filepath.Join(dir, "a", "b", "c")
	_ = os.MkdirAll(deep, 0755)
	_ = os.WriteFile(filepath.Join(deep, "deep.yaml"),
		[]byte("api_key: sk-proj-verySecretCanaryValue1234567f2a\n"), 0644)
	result, err := RunFiles(context.Background(), FileOptions{Paths: []string{dir}, Mode: ModeDefault, MaxDepth: 1})
	if err != nil {
		t.Fatalf("RunFiles: %v", err)
	}
	if len(result.Findings) > 0 {
		t.Errorf("expected depth-1 to miss depth-3 file, got %d findings", len(result.Findings))
	}
}

func TestRunFiles_NoRecurse(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	_ = os.MkdirAll(sub, 0755)
	_ = os.WriteFile(filepath.Join(sub, "nested.yaml"),
		[]byte("api_key: sk-proj-verySecretCanaryValue1234567f2a\n"), 0644)
	result, err := RunFiles(context.Background(), FileOptions{Paths: []string{dir}, Mode: ModeDefault, NoRecurse: true})
	if err != nil {
		t.Fatalf("RunFiles: %v", err)
	}
	if len(result.Findings) > 0 {
		t.Errorf("expected no-recurse to miss nested file, got %d findings", len(result.Findings))
	}
}

func TestRunFiles_SkipsNodeModulesByDefault(t *testing.T) {
	dir := t.TempDir()
	nm := filepath.Join(dir, "node_modules", "leaky-pkg")
	if err := os.MkdirAll(nm, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nm, "config.yaml"),
		[]byte("api_key: sk-proj-verySecretCanaryValue1234567f2a\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// Also put a real finding outside node_modules so we confirm the scan ran.
	if err := os.WriteFile(filepath.Join(dir, "real.yaml"),
		[]byte("api_key: sk-proj-verySecretCanaryValue1234567f2a\n"), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := RunFiles(context.Background(), FileOptions{Paths: []string{dir}, Mode: ModeDefault})
	if err != nil {
		t.Fatalf("RunFiles: %v", err)
	}

	// The node_modules finding must NOT appear.
	for _, f := range result.Findings {
		fr := f.Source.(FileRef)
		if strings.Contains(fr.Path, "node_modules") {
			t.Errorf("node_modules was scanned by default: %s", fr.Path)
		}
	}

	// The real.yaml finding SHOULD appear.
	foundReal := false
	for _, f := range result.Findings {
		fr := f.Source.(FileRef)
		if strings.HasSuffix(fr.Path, "real.yaml") {
			foundReal = true
		}
	}
	if !foundReal {
		t.Errorf("expected real.yaml to be scanned, got %d findings", len(result.Findings))
	}
}

func TestRunFiles_NoSkipDirsFlag_ScansNodeModules(t *testing.T) {
	dir := t.TempDir()
	nm := filepath.Join(dir, "node_modules", "leaky-pkg")
	_ = os.MkdirAll(nm, 0755)
	_ = os.WriteFile(filepath.Join(nm, "config.yaml"),
		[]byte("api_key: sk-proj-verySecretCanaryValue1234567f2a\n"), 0644)

	result, err := RunFiles(context.Background(), FileOptions{
		Paths: []string{dir}, Mode: ModeDefault, NoSkipDirs: true,
	})
	if err != nil {
		t.Fatalf("RunFiles: %v", err)
	}

	found := false
	for _, f := range result.Findings {
		fr := f.Source.(FileRef)
		if strings.Contains(fr.Path, "node_modules") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected node_modules to be scanned with --no-skip-dirs, got %d findings", len(result.Findings))
	}
}

func TestRunFiles_SkipsGitDirByDefault(t *testing.T) {
	dir := t.TempDir()
	gitDir := filepath.Join(dir, ".git")
	_ = os.MkdirAll(gitDir, 0755)
	_ = os.WriteFile(filepath.Join(gitDir, "config"),
		[]byte("[remote \"origin\"]\n\turl = https://user:sk-proj-verySecretCanaryValue1234567f2a@host/x\n"), 0644)

	result, err := RunFiles(context.Background(), FileOptions{Paths: []string{dir}, Mode: ModeDefault})
	if err != nil {
		t.Fatalf("RunFiles: %v", err)
	}
	for _, f := range result.Findings {
		fr := f.Source.(FileRef)
		if strings.Contains(fr.Path, "/.git/") {
			t.Errorf(".git was scanned by default: %s", fr.Path)
		}
	}
}

func TestRunFiles_Exclude(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "testdata"), 0755)
	_ = os.WriteFile(filepath.Join(dir, "testdata", "fixture.yaml"),
		[]byte("api_key: sk-proj-verySecretCanaryValue1234567f2a\n"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "real.yaml"),
		[]byte("api_key: sk-proj-verySecretCanaryValue1234567f2a\n"), 0644)
	result, err := RunFiles(context.Background(), FileOptions{
		Paths: []string{dir}, Mode: ModeDefault, Excludes: []string{"testdata/**"},
	})
	if err != nil {
		t.Fatalf("RunFiles: %v", err)
	}
	for _, f := range result.Findings {
		if filepath.Base(filepath.Dir(f.Source.(FileRef).Path)) == "testdata" {
			t.Errorf("excluded path was scanned: %s", f.Source.(FileRef).Path)
		}
	}
}

func TestRunFiles_SymlinkCycleDoesNotHang(t *testing.T) {
	dir := t.TempDir()
	// Create a real file with a secret at the root so we know the scan ran.
	if err := os.WriteFile(filepath.Join(dir, "real.yaml"),
		[]byte("api_key: sk-proj-verySecretCanaryValue1234567f2a\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a subdir that symlinks back to the scan root — a classic cycle.
	sub := filepath.Join(dir, "cycle")
	if err := os.Symlink(dir, sub); err != nil {
		t.Skipf("symlinks not supported on this filesystem: %v", err)
	}

	done := make(chan struct{})
	var result Result
	var scanErr error
	go func() {
		defer close(done)
		result, scanErr = RunFiles(context.Background(), FileOptions{
			Paths: []string{dir}, Mode: ModeDefault,
		})
	}()

	select {
	case <-done:
		// Good — scan terminated.
	case <-time.After(5 * time.Second):
		t.Fatal("scan did not terminate within 5s (symlink cycle not handled)")
	}

	if scanErr != nil {
		t.Fatalf("RunFiles error: %v", scanErr)
	}
	// We should find at least the one real secret; not an exponential blowup.
	if len(result.Findings) == 0 {
		t.Errorf("expected to find real.yaml finding, got 0")
	}
	if len(result.Findings) > 10 {
		t.Errorf("excessive findings suggests cycle wasn't broken: got %d", len(result.Findings))
	}
}
