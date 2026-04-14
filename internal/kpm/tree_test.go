package kpm

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanTemplates(t *testing.T) {
	dir := t.TempDir()

	// Write a test template
	tmpl := "APP=test\nDB_PASS=${kms:kv/db/prod#password}\nKEY=${kms:llm/openai}\n"
	os.WriteFile(filepath.Join(dir, "app.template"), []byte(tmpl), 0644)

	// Write a non-template file (should be ignored)
	os.WriteFile(filepath.Join(dir, "README.md"), []byte("hello"), 0644)

	summaries, err := ScanTemplates(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(summaries) != 1 {
		t.Fatalf("got %d summaries, want 1", len(summaries))
	}
	if summaries[0].Name != "app.template" {
		t.Errorf("name = %q, want app.template", summaries[0].Name)
	}
	if len(summaries[0].Refs) != 2 {
		t.Errorf("got %d refs, want 2", len(summaries[0].Refs))
	}
}

func TestScanTemplatesEmpty(t *testing.T) {
	summaries, err := ScanTemplates("/nonexistent/path")
	if err != nil {
		t.Fatal(err)
	}
	if summaries != nil {
		t.Errorf("expected nil for nonexistent dir, got %v", summaries)
	}
}

func TestPrintTree(t *testing.T) {
	dir := t.TempDir()
	tmpl := "SECRET=${kms:kv/app#key}\n"
	os.WriteFile(filepath.Join(dir, "test.template"), []byte(tmpl), 0644)

	levels := []TemplateLevel{
		{Label: "Test", Dir: dir},
		{Label: "Empty", Dir: "/nonexistent"},
	}

	var buf bytes.Buffer
	PrintTree(&buf, levels)

	out := buf.String()
	if !strings.Contains(out, "test.template") {
		t.Errorf("missing template name in output:\n%s", out)
	}
	if !strings.Contains(out, "kv/app#key") {
		t.Errorf("missing ref in output:\n%s", out)
	}
	if !strings.Contains(out, "(no templates found)") {
		t.Errorf("missing empty message:\n%s", out)
	}
}
