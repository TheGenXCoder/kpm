package scan

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func fixtureShellResult() Result {
	return Result{
		Scanned:  47,
		Affected: 2,
		Findings: []Finding{
			{
				Source:   ShellRef{PID: 4291, User: "bert", Comm: "node", Command: "node server.js"},
				Variable: "OPENAI_API_KEY",
				Detector: "value:openai-proj",
				Value:    "sk-proj-verySecretValue1234567f2a",
			},
			{
				Source:   ShellRef{PID: 8821, User: "bert", Comm: "python", Command: "python app.py"},
				Variable: "AWS_SECRET_ACCESS_KEY",
				Detector: "name:secret_access_key",
				Value:    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYxQ9/",
			},
		},
	}
}

func fixtureFilesResult() Result {
	return Result{
		Scanned:  120,
		Affected: 1,
		Findings: []Finding{
			{
				Source:   FileRef{Path: "config/local.yaml", Line: 14},
				Variable: "api_key",
				Detector: "value:openai-proj",
				Value:    "sk-proj-verySecretValue1234567f2a",
			},
		},
	}
}

func fixtureLogsResult() Result {
	return Result{
		Scanned:  3200,
		Affected: 1,
		Findings: []Finding{
			{
				Source:   LogRef{Path: "app.log", Line: 1247, Snippet: "calling OpenAI with key=sk-proj-••••7f2a"},
				Variable: "",
				Detector: "value:openai-proj",
				Value:    "sk-proj-verySecretValue1234567f2a",
			},
		},
	}
}

func TestTableOutput_Shell_ContainsExpectedColumns(t *testing.T) {
	var buf bytes.Buffer
	WriteTable(&buf, fixtureShellResult())
	out := buf.String()

	for _, col := range []string{"PID", "USER", "PROCESS", "VARIABLE", "PREVIEW"} {
		if !strings.Contains(out, col) {
			t.Errorf("table missing column %q in output:\n%s", col, out)
		}
	}
	if !strings.Contains(out, "4291") || !strings.Contains(out, "bert") {
		t.Errorf("expected process row, got:\n%s", out)
	}
}

func TestTableOutput_Files_ContainsExpectedColumns(t *testing.T) {
	var buf bytes.Buffer
	WriteTable(&buf, fixtureFilesResult())
	out := buf.String()

	for _, col := range []string{"FILE", "LINE", "VARIABLE", "PREVIEW"} {
		if !strings.Contains(out, col) {
			t.Errorf("table missing column %q in output:\n%s", col, out)
		}
	}
	if !strings.Contains(out, "config/local.yaml") {
		t.Errorf("expected path, got:\n%s", out)
	}
}

func TestTableOutput_Logs_ContainsExpectedColumns(t *testing.T) {
	var buf bytes.Buffer
	WriteTable(&buf, fixtureLogsResult())
	out := buf.String()

	for _, col := range []string{"LINE", "PREVIEW", "SNIPPET"} {
		if !strings.Contains(out, col) {
			t.Errorf("table missing column %q in output:\n%s", col, out)
		}
	}
}

func TestTableOutput_ZeroFindings_ShowsCleanMessage(t *testing.T) {
	var buf bytes.Buffer
	WriteTable(&buf, Result{Scanned: 47})
	out := buf.String()
	if !strings.Contains(out, "no exposed secrets found") {
		t.Errorf("expected clean-scan message, got:\n%s", out)
	}
}

func TestJSONOutput_ShapeIsStable(t *testing.T) {
	var buf bytes.Buffer
	WriteJSON(&buf, fixtureShellResult())

	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("JSON output did not parse: %v\noutput:\n%s", err, buf.String())
	}
	for _, key := range []string{"scanned", "affected", "findings"} {
		if _, ok := parsed[key]; !ok {
			t.Errorf("JSON missing top-level key %q", key)
		}
	}
}

// NON-LEAK INVARIANT at the output layer: no formatter may emit Finding.Value.
func TestOutput_NeverLeaksRawValue_Table(t *testing.T) {
	for _, fix := range []Result{fixtureShellResult(), fixtureFilesResult(), fixtureLogsResult()} {
		var buf bytes.Buffer
		WriteTable(&buf, fix)
		out := buf.String()
		for _, f := range fix.Findings {
			if f.Value != "" && strings.Contains(out, f.Value) {
				t.Errorf("table leaked raw value %q in output:\n%s", f.Value, out)
			}
		}
	}
}

func TestOutput_NeverLeaksRawValue_JSON(t *testing.T) {
	for _, fix := range []Result{fixtureShellResult(), fixtureFilesResult(), fixtureLogsResult()} {
		var buf bytes.Buffer
		WriteJSON(&buf, fix)
		out := buf.String()
		for _, f := range fix.Findings {
			if f.Value != "" && strings.Contains(out, f.Value) {
				t.Errorf("JSON leaked raw value %q in output:\n%s", f.Value, out)
			}
		}
	}
}
