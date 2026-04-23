package scan

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
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

// summaryColumnLabel returns the column header for the source-count column.
func summaryColumnLabel(kind string) string {
	switch kind {
	case "shell":
		return "PROCESSES"
	case "files":
		return "FILES"
	case "logs":
		return "LINES"
	}
	return "SOURCES"
}

// sourceID returns a string that uniquely identifies a source within its kind.
func sourceID(s SourceRef) string {
	switch v := s.(type) {
	case ShellRef:
		return strconv.Itoa(v.PID)
	case FileRef:
		return v.Path
	case LogRef:
		return strconv.Itoa(v.Line) + "\x00" + v.Path
	}
	return fmt.Sprintf("%v", s)
}

// summaryEntry is one collapsed row for summary output.
type summaryEntry struct {
	variable    string
	preview     string
	valueLength int
	sources     int
}

// buildSummary collapses r.Findings into unique (variable, preview) entries,
// counting distinct sources per entry, sorted descending by source count.
func buildSummary(r Result) []summaryEntry {
	type bucket struct {
		entry   Finding
		sources map[string]struct{}
	}
	buckets := map[string]*bucket{}
	var order []string // insertion order for stable key tracking

	for _, f := range r.Findings {
		key := f.Variable + "\x00" + Redact(f.Value)
		b, ok := buckets[key]
		if !ok {
			b = &bucket{entry: f, sources: map[string]struct{}{}}
			buckets[key] = b
			order = append(order, key)
		}
		b.sources[sourceID(f.Source)] = struct{}{}
	}

	entries := make([]summaryEntry, 0, len(order))
	for _, key := range order {
		b := buckets[key]
		entries = append(entries, summaryEntry{
			variable:    b.entry.Variable,
			preview:     Redact(b.entry.Value),
			valueLength: len(b.entry.Value),
			sources:     len(b.sources),
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].sources > entries[j].sources
	})
	return entries
}

// WriteSummaryTable formats a collapsed summary as a human-readable table.
// kind is the scan mode ("shell", "files", "logs"); pass "" to auto-detect.
//
// SECURITY: this function receives Finding.Value indirectly through Redact().
// Raw values are never emitted.
func WriteSummaryTable(w io.Writer, r Result, kind string) {
	if len(r.Findings) == 0 {
		fmt.Fprintf(w, "✓  KPM scan: no exposed secrets found across %d units\n", r.Scanned)
		return
	}

	if kind == "" && len(r.Findings) > 0 {
		kind = r.Findings[0].Source.Kind()
	}

	entries := buildSummary(r)
	colLabel := summaryColumnLabel(kind)

	fmt.Fprintf(w, "⚠  KPM scan: %d unique secrets across %d %s (%d total findings)\n\n",
		len(entries), r.Affected, unitLabel(kind), len(r.Findings))

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "VARIABLE\tPREVIEW\t%s\n", colLabel)
	for _, e := range entries {
		varCol := e.variable
		if varCol == "" {
			varCol = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\n", varCol, e.preview, e.sources)
	}
	tw.Flush()
}

// WriteSummaryJSON formats a collapsed summary as a JSON document.
// Raw values are never included.
func WriteSummaryJSON(w io.Writer, r Result) {
	entries := buildSummary(r)

	summaryArr := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		summaryArr = append(summaryArr, map[string]any{
			"variable":     e.variable,
			"preview":      e.preview,
			"value_length": e.valueLength,
			"sources":      e.sources,
		})
	}

	doc := map[string]any{
		"scanned":        r.Scanned,
		"affected":       r.Affected,
		"total_findings": len(r.Findings),
		"unique_secrets": len(entries),
		"summary":        summaryArr,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(doc)
}
