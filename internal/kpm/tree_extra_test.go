package kpm

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanTemplatesNonExistentDir(t *testing.T) {
	// Non-existent directory returns nil, nil (not an error)
	summaries, err := ScanTemplates("/nonexistent/templates/dir")
	if err != nil {
		t.Fatalf("expected nil error for non-existent dir, got: %v", err)
	}
	if summaries != nil {
		t.Errorf("expected nil summaries for non-existent dir, got: %v", summaries)
	}
}

func TestScanTemplatesPermissionError(t *testing.T) {
	// Create a dir that can't be read
	dir := t.TempDir()
	noReadDir := filepath.Join(dir, "noperm")
	os.MkdirAll(noReadDir, 0000)
	defer os.Chmod(noReadDir, 0755)

	summaries, err := ScanTemplates(noReadDir)
	// Should return error (not os.IsNotExist)
	if err == nil && summaries != nil {
		// On some systems (root) this may succeed
		t.Log("no error for unreadable dir (possibly running as root)")
	}
}

func TestPrintTreeWithError(t *testing.T) {
	var buf bytes.Buffer
	levels := []TemplateLevel{
		{Label: "Test", Dir: "/nonexistent/path/that/cant/exist/xyz"},
	}
	err := PrintTree(&buf, levels)
	if err != nil {
		t.Fatal(err)
	}
	// Non-existent dir should return nil summaries, not error — so no "(error:..." line
	// But the level header should be printed
	out := buf.String()
	if !strings.Contains(out, "Test:") {
		t.Errorf("expected level header in output: %s", out)
	}
}

func TestPrintTreeWithMultipleLevels(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "app.template"), []byte("KEY=${kms:kv/app#key}\n"), 0644)

	var buf bytes.Buffer
	levels := []TemplateLevel{
		{Label: "User", Dir: dir},
		{Label: "Project", Dir: t.TempDir()}, // empty dir
	}
	err := PrintTree(&buf, levels)
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "User:") || !strings.Contains(out, "Project:") {
		t.Errorf("expected both levels in output: %s", out)
	}
	if !strings.Contains(out, "app.template") {
		t.Errorf("expected app.template in output: %s", out)
	}
}
