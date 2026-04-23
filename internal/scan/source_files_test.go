package scan

import (
	"context"
	"os"
	"path/filepath"
	"testing"
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
