package scan

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"
)

// WriteTable formats a Result as a human-readable table. Mode (columns) is
// inferred from the first finding's SourceRef kind, or skipped entirely when
// there are no findings.
//
// SECURITY: this function receives Finding.Value but MUST NOT emit it.
// Only Redact(f.Value) or the redacted preview should appear in output.
func WriteTable(w io.Writer, r Result) {
	if len(r.Findings) == 0 {
		fmt.Fprintf(w, "✓  KPM scan: no exposed secrets found across %d units\n", r.Scanned)
		return
	}

	kind := r.Findings[0].Source.Kind()
	fmt.Fprintf(w, "⚠  KPM scan: %d secrets exposed across %d %s\n\n",
		len(r.Findings), r.Affected, unitLabel(kind))

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	switch kind {
	case "shell":
		fmt.Fprintln(tw, "PID\tUSER\tPROCESS\tVARIABLE\tPREVIEW")
		for _, f := range r.Findings {
			s := f.Source.(ShellRef)
			fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\n",
				s.PID, s.User, s.Comm, f.Variable, Redact(f.Value))
		}
	case "files":
		fmt.Fprintln(tw, "FILE\tLINE\tVARIABLE\tPREVIEW")
		for _, f := range r.Findings {
			fr := f.Source.(FileRef)
			varCol := f.Variable
			if varCol == "" {
				varCol = "-"
			}
			fmt.Fprintf(tw, "%s\t%d\t%s\t%s\n",
				fr.Path, fr.Line, varCol, Redact(f.Value))
		}
	case "logs":
		fmt.Fprintln(tw, "LINE\tPREVIEW\tSNIPPET")
		for _, f := range r.Findings {
			lr := f.Source.(LogRef)
			fmt.Fprintf(tw, "%d\t%s\t%s\n",
				lr.Line, Redact(f.Value), lr.Snippet)
		}
	}
	tw.Flush()
}

// WriteJSON formats a Result as a JSON document. Raw values are never included.
func WriteJSON(w io.Writer, r Result) {
	findings := make([]map[string]any, 0, len(r.Findings))
	for _, f := range r.Findings {
		entry := map[string]any{
			"detector":     f.Detector,
			"variable":     f.Variable,
			"preview":      Redact(f.Value),
			"value_length": len(f.Value),
			"source":       sourceJSON(f.Source),
		}
		findings = append(findings, entry)
	}
	doc := map[string]any{
		"scanned":  r.Scanned,
		"affected": r.Affected,
		"findings": findings,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(doc)
}

func sourceJSON(s SourceRef) map[string]any {
	switch v := s.(type) {
	case ShellRef:
		return map[string]any{
			"kind": "shell", "pid": v.PID, "user": v.User,
			"process": v.Comm, "command": v.Command,
		}
	case FileRef:
		return map[string]any{
			"kind": "files", "path": v.Path, "line": v.Line,
		}
	case LogRef:
		return map[string]any{
			"kind": "logs", "path": v.Path, "line": v.Line, "snippet": v.Snippet,
		}
	}
	return map[string]any{"kind": "unknown"}
}

func unitLabel(kind string) string {
	switch kind {
	case "shell":
		return "processes"
	case "files":
		return "files"
	case "logs":
		return "log lines"
	}
	return "units"
}
