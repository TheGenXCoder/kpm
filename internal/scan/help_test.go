package scan

import (
	"strings"
	"testing"
)

func TestHelp_TopLevel_ContainsAllModes(t *testing.T) {
	h := HelpText("")
	for _, kw := range []string{"shell", "files", "logs", "EXIT STATUS", "SEE ALSO"} {
		if !strings.Contains(h, kw) {
			t.Errorf("top-level help missing %q", kw)
		}
	}
}

func TestHelp_Shell_HasExamples(t *testing.T) {
	h := HelpText("shell")
	for _, kw := range []string{"SYNOPSIS", "OPTIONS", "EXIT STATUS", "EXAMPLES", "--paranoid", "--json", "--quiet"} {
		if !strings.Contains(h, kw) {
			t.Errorf("shell help missing %q", kw)
		}
	}
}

func TestHelp_Files_HasRecurseExamples(t *testing.T) {
	h := HelpText("files")
	for _, kw := range []string{"--recurse", "--no-recurse", "--max-depth", "--exclude", "--no-gitignore", "pr-branch"} {
		if !strings.Contains(h, kw) {
			t.Errorf("files help missing %q", kw)
		}
	}
}

func TestHelp_Logs_HasStdinExample(t *testing.T) {
	h := HelpText("logs")
	for _, kw := range []string{"--follow", "--include-names", "tail -f", "stdin"} {
		if !strings.Contains(h, kw) {
			t.Errorf("logs help missing %q", kw)
		}
	}
}
