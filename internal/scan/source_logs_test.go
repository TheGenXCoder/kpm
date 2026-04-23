package scan

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunLogs_DetectsCanaryInFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	content := "2026-04-23 INFO starting\n2026-04-23 DEBUG calling OpenAI with key=sk-proj-verySecretCanary1234567f2a\n2026-04-23 INFO success\n"
	_ = os.WriteFile(path, []byte(content), 0644)
	result, err := RunLogs(context.Background(), LogOptions{Path: path, Mode: ModeDefault})
	if err != nil {
		t.Fatalf("RunLogs: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Fatalf("expected finding, got 0")
	}
	if lr, ok := result.Findings[0].Source.(LogRef); !ok || lr.Line != 2 {
		t.Errorf("expected line 2, got %+v", result.Findings[0].Source)
	}
}

func TestRunLogs_ReadsFromStdin(t *testing.T) {
	content := "header\ntoken=sk-proj-verySecretCanary1234567f2a\nfooter\n"
	result, err := RunLogs(context.Background(), LogOptions{Mode: ModeDefault, Stdin: strings.NewReader(content)})
	if err != nil {
		t.Fatalf("RunLogs stdin: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected finding from stdin, got 0")
	}
}

func TestRunLogs_ValueOnlyByDefault(t *testing.T) {
	content := "OPENAI_API_KEY=notASecret123\nplain sk-proj-verySecretCanary1234567f2a\n"
	result, err := RunLogs(context.Background(), LogOptions{Mode: ModeDefault, Stdin: strings.NewReader(content)})
	if err != nil {
		t.Fatalf("RunLogs: %v", err)
	}
	for _, f := range result.Findings {
		if f.Variable != "" {
			t.Errorf("default logs mode should produce Variable='', got %q", f.Variable)
		}
	}
}

func TestRunLogs_IncludeNames_AddsStructuredDetection(t *testing.T) {
	content := `api_key=sk-proj-verySecretCanary1234567f2a
{"api_token":"ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
`
	result, err := RunLogs(context.Background(), LogOptions{
		Mode: ModeDefault, Stdin: strings.NewReader(content), IncludeNames: true,
	})
	if err != nil {
		t.Fatalf("RunLogs: %v", err)
	}
	foundWithVar := false
	for _, f := range result.Findings {
		if f.Variable != "" {
			foundWithVar = true
		}
	}
	if !foundWithVar {
		t.Error("expected at least one finding with Variable when --include-names")
	}
}

func TestRunLogs_SnippetIsRedacted(t *testing.T) {
	content := "calling OpenAI with key=sk-proj-verySecretCanary1234567f2a after startup\n"
	result, err := RunLogs(context.Background(), LogOptions{Mode: ModeDefault, Stdin: strings.NewReader(content)})
	if err != nil {
		t.Fatalf("RunLogs: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected finding")
	}
	lr := result.Findings[0].Source.(LogRef)
	if strings.Contains(lr.Snippet, "sk-proj-verySecretCanary1234567f2a") {
		t.Errorf("snippet leaked raw value: %s", lr.Snippet)
	}
	if lr.Snippet == "" {
		t.Error("expected non-empty snippet")
	}
}

func TestRunLogs_FileNotFound_ReturnsError(t *testing.T) {
	_, err := RunLogs(context.Background(), LogOptions{Path: "/definitely/does/not/exist.log"})
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestRunLogs_NoLeakInOutput(t *testing.T) {
	canary := "sk-proj-verySecretCanary1234567f2a"
	content := "line one\nkey=" + canary + "\nline three\n"
	result, err := RunLogs(context.Background(), LogOptions{Mode: ModeDefault, Stdin: strings.NewReader(content)})
	if err != nil {
		t.Fatalf("RunLogs: %v", err)
	}
	var buf bytes.Buffer
	WriteTable(&buf, result)
	if strings.Contains(buf.String(), canary) {
		t.Errorf("table leaked canary:\n%s", buf.String())
	}
	buf.Reset()
	WriteJSON(&buf, result)
	if strings.Contains(buf.String(), canary) {
		t.Errorf("JSON leaked canary:\n%s", buf.String())
	}
}
