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

// fixtureSummaryResult returns a Result with 4 findings: 3 share the same
// (variable, redacted preview) and 1 is unique.
func fixtureSummaryResult() Result {
	sharedValue := "sk-proj-verySecretValue1234567f2a"
	return Result{
		Scanned:  50,
		Affected: 4,
		Findings: []Finding{
			{
				Source:   ShellRef{PID: 100, User: "bert", Comm: "node"},
				Variable: "OPENAI_API_KEY",
				Detector: "value:openai-proj",
				Value:    sharedValue,
			},
			{
				Source:   ShellRef{PID: 200, User: "bert", Comm: "python"},
				Variable: "OPENAI_API_KEY",
				Detector: "value:openai-proj",
				Value:    sharedValue,
			},
			{
				Source:   ShellRef{PID: 300, User: "bert", Comm: "ruby"},
				Variable: "OPENAI_API_KEY",
				Detector: "value:openai-proj",
				Value:    sharedValue,
			},
			{
				Source:   ShellRef{PID: 400, User: "bert", Comm: "go"},
				Variable: "GITHUB_TOKEN",
				Detector: "name:github-token",
				Value:    "ghp_uniqueToken9d1e99999",
			},
		},
	}
}

func TestSummaryTable_CollapsesDuplicates(t *testing.T) {
	var buf bytes.Buffer
	WriteSummaryTable(&buf, fixtureSummaryResult(), "shell")
	out := buf.String()

	// Should have exactly 2 data rows (OPENAI_API_KEY + GITHUB_TOKEN).
	lines := strings.Split(strings.TrimSpace(out), "\n")
	// Count non-empty, non-header lines that are data rows.
	// Header line contains "VARIABLE", blank line separates summary line from table.
	dataLines := 0
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if trimmed == "" || strings.HasPrefix(trimmed, "⚠") || strings.HasPrefix(trimmed, "VARIABLE") {
			continue
		}
		dataLines++
	}
	if dataLines != 2 {
		t.Errorf("expected 2 unique rows, got %d\noutput:\n%s", dataLines, out)
	}

	// The collapsed row must show count 3 (three distinct PIDs).
	if !strings.Contains(out, "3") {
		t.Errorf("expected count 3 for collapsed OPENAI_API_KEY row:\n%s", out)
	}
	// Must contain both variable names.
	if !strings.Contains(out, "OPENAI_API_KEY") {
		t.Errorf("expected OPENAI_API_KEY in output:\n%s", out)
	}
	if !strings.Contains(out, "GITHUB_TOKEN") {
		t.Errorf("expected GITHUB_TOKEN in output:\n%s", out)
	}
}

func TestSummaryTable_SortsDescending(t *testing.T) {
	var buf bytes.Buffer
	WriteSummaryTable(&buf, fixtureSummaryResult(), "shell")
	out := buf.String()

	// OPENAI_API_KEY (count=3) must appear before GITHUB_TOKEN (count=1).
	idxOpenAI := strings.Index(out, "OPENAI_API_KEY")
	idxGitHub := strings.Index(out, "GITHUB_TOKEN")
	if idxOpenAI < 0 || idxGitHub < 0 {
		t.Fatalf("missing expected variable names in output:\n%s", out)
	}
	if idxOpenAI > idxGitHub {
		t.Errorf("expected OPENAI_API_KEY (count=3) before GITHUB_TOKEN (count=1):\n%s", out)
	}
}

func TestSummaryJSON_Shape(t *testing.T) {
	var buf bytes.Buffer
	WriteSummaryJSON(&buf, fixtureSummaryResult())

	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("summary JSON did not parse: %v\noutput:\n%s", err, buf.String())
	}

	for _, key := range []string{"scanned", "affected", "total_findings", "unique_secrets", "summary"} {
		if _, ok := parsed[key]; !ok {
			t.Errorf("summary JSON missing top-level key %q", key)
		}
	}

	totalFindings, _ := parsed["total_findings"].(float64)
	if int(totalFindings) != 4 {
		t.Errorf("expected total_findings=4, got %v", totalFindings)
	}

	uniqueSecrets, _ := parsed["unique_secrets"].(float64)
	if int(uniqueSecrets) != 2 {
		t.Errorf("expected unique_secrets=2, got %v", uniqueSecrets)
	}

	summaryArr, _ := parsed["summary"].([]any)
	if len(summaryArr) != 2 {
		t.Errorf("expected 2 entries in summary array, got %d", len(summaryArr))
	}
}

func TestSummary_NoLeak(t *testing.T) {
	fix := fixtureSummaryResult()

	// Table output must not contain raw values.
	var tableBuf bytes.Buffer
	WriteSummaryTable(&tableBuf, fix, "shell")
	tableOut := tableBuf.String()
	for _, f := range fix.Findings {
		if f.Value != "" && strings.Contains(tableOut, f.Value) {
			t.Errorf("summary table leaked raw value %q:\n%s", f.Value, tableOut)
		}
	}

	// JSON output must not contain raw values.
	var jsonBuf bytes.Buffer
	WriteSummaryJSON(&jsonBuf, fix)
	jsonOut := jsonBuf.String()
	for _, f := range fix.Findings {
		if f.Value != "" && strings.Contains(jsonOut, f.Value) {
			t.Errorf("summary JSON leaked raw value %q:\n%s", f.Value, jsonOut)
		}
	}
}

func TestSummaryTable_EmptyVariable_ShowsDash(t *testing.T) {
	fix := Result{
		Scanned:  100,
		Affected: 1,
		Findings: []Finding{
			{
				Source:   LogRef{Path: "app.log", Line: 42, Snippet: "...leaked..."},
				Variable: "",
				Detector: "value:openai-proj",
				Value:    "sk-proj-verySecretValue1234567f2a",
			},
		},
	}
	var buf bytes.Buffer
	WriteSummaryTable(&buf, fix, "logs")
	out := buf.String()

	if !strings.Contains(out, "-") {
		t.Errorf("expected '-' for empty variable name, got:\n%s", out)
	}
	// Must NOT display an empty variable cell (just a dash).
	// The variable column header is "VARIABLE" — after that, empty var should show "-".
	lines := strings.Split(out, "\n")
	for _, l := range lines {
		if strings.Contains(l, "VARIABLE") {
			continue // skip header
		}
		if strings.TrimSpace(l) == "" {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(l), "⚠") {
			continue
		}
		// Data row: first field should be "-" not ""
		fields := strings.Fields(l)
		if len(fields) > 0 && fields[0] == "" {
			t.Errorf("empty variable not replaced with '-': %q", l)
		}
	}
}
