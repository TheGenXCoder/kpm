// Package kpm — cred.go implements the `kpm cred` subcommand family.
//
// Subcommands:
//
//	kpm cred register <name> --provider <kind> --provider-params <json>
//	    --scope <name> --destination <kind>:<target_id>[:<params_json>]
//	    [--destination ...] [--ttl <seconds>] [--tag <tag>] ...
//	kpm cred list [--tag <tag>]
//	kpm cred inspect <name> [--json]
//	kpm cred rotate <name>
//	kpm cred remove <name> [--purge]
//
// All subcommands communicate with AgentKMS over the existing mTLS Client.

package kpm

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"
)

// ── Wire types (match the server-side binding JSON schema) ────────────────────

// CredentialBinding is the client-side representation of a server binding.
// Field names must match the server JSON schema exactly.
type CredentialBinding struct {
	Name           string            `json:"name"`
	ProviderKind   string            `json:"provider_kind"`
	ProviderParams map[string]any    `json:"provider_params,omitempty"`
	Scope          BindingScope      `json:"scope"`
	Destinations   []DestinationSpec `json:"destinations"`
	RotationPolicy RotationPolicy    `json:"rotation_policy"`
	Metadata       BindingMetadata   `json:"metadata"`
}

// BindingScope matches the server's credentials.Scope type.
type BindingScope struct {
	Kind   string         `json:"kind"`
	Params map[string]any `json:"params,omitempty"`
}

// DestinationSpec matches the server's binding.DestinationSpec type.
type DestinationSpec struct {
	Kind     string         `json:"kind"`
	TargetID string         `json:"target_id"`
	Params   map[string]any `json:"params,omitempty"`
}

// RotationPolicy matches the server's binding.RotationPolicy type.
type RotationPolicy struct {
	TTLHintSeconds int64 `json:"ttl_hint_seconds,omitempty"`
	ManualOnly     bool  `json:"manual_only"`
}

// BindingMetadata matches the server's binding.BindingMetadata type.
type BindingMetadata struct {
	CreatedAt      string   `json:"created_at,omitempty"`
	LastRotatedAt  string   `json:"last_rotated_at,omitempty"`
	LastGeneration uint64   `json:"last_generation"`
	Tags           []string `json:"tags,omitempty"`
}

// BindingSummary is the list-endpoint shape.
type BindingSummary struct {
	Name             string   `json:"name"`
	ProviderKind     string   `json:"provider_kind"`
	DestinationCount int      `json:"destination_count"`
	LastRotatedAt    string   `json:"last_rotated_at,omitempty"`
	Tags             []string `json:"tags,omitempty"`
}

// DestinationResult is one entry in the rotate response.
type DestinationResult struct {
	Kind        string `json:"kind"`
	TargetID    string `json:"target_id"`
	Success     bool   `json:"success"`
	IsTransient bool   `json:"is_transient,omitempty"`
	Error       string `json:"error,omitempty"`
}

// RotateResponse is the rotate endpoint response body.
type RotateResponse struct {
	Name       string              `json:"name"`
	Generation uint64              `json:"generation"`
	RotatedAt  string              `json:"rotated_at"`
	Results    []DestinationResult `json:"results"`
}

// ── RunCred — top-level dispatcher ───────────────────────────────────────────

// RunCred dispatches `kpm cred <subcommand> [args...]`.
// It is the entry point called from cmd/kpm/main.go.
func RunCred(ctx context.Context, w io.Writer, errW io.Writer, client *Client, args []string) int {
	if len(args) == 0 {
		fmt.Fprint(errW, credUsage)
		return 1
	}
	sub := args[0]
	rest := args[1:]

	switch sub {
	case "register":
		return runCredRegister(ctx, w, errW, client, rest)
	case "list":
		return runCredList(ctx, w, errW, client, rest)
	case "inspect":
		return runCredInspect(ctx, w, errW, client, rest)
	case "rotate":
		return runCredRotate(ctx, w, errW, client, rest)
	case "remove":
		return runCredRemove(ctx, w, errW, client, rest)
	case "help", "--help", "-h":
		fmt.Fprint(errW, credUsage)
		return 0
	default:
		fmt.Fprintf(errW, "kpm cred: unknown subcommand %q\n\n%s", sub, credUsage)
		return 1
	}
}

const credUsage = `kpm cred — manage credential bindings in AgentKMS

Usage:
  kpm cred register <name> --provider <kind> --provider-params <json>
      --scope <scope-kind> --destination <kind>:<target_id>[:<params_json>]
      [--destination ...] [--ttl <seconds>] [--tag <tag>] [--manual-only]
  kpm cred list [--tag <tag>]
  kpm cred inspect <name> [--json]
  kpm cred rotate <name>
  kpm cred remove <name> [--purge]

Examples:
  kpm cred register blog-audit-pat \
      --provider github-app-token \
      --provider-params '{"app_name":"agentkms-blog-audit"}' \
      --scope llm-session \
      --destination github-secret:owner/repo:BLOG_PAT \
      --tag ci

  kpm cred list
  kpm cred list --tag ci
  kpm cred inspect blog-audit-pat
  kpm cred rotate blog-audit-pat
  kpm cred remove blog-audit-pat
`

// ── register ──────────────────────────────────────────────────────────────────

func runCredRegister(ctx context.Context, w io.Writer, errW io.Writer, client *Client, args []string) int {
	// Extract the name (first non-flag arg) and all --destination values
	// before passing the remainder to flag.FlagSet.  This is necessary because
	// flag.FlagSet stops parsing at the first non-flag argument, so
	// "register <name> --provider ..." would leave --provider unparsed.
	if len(args) == 0 {
		fmt.Fprintln(errW, "kpm cred register: binding name is required")
		fmt.Fprint(errW, credUsage)
		return 1
	}

	// First positional arg is the binding name if it doesn't start with '-'.
	var name string
	var remainingArgs []string
	if !strings.HasPrefix(args[0], "-") {
		name = args[0]
		remainingArgs = args[1:]
	} else {
		remainingArgs = args
	}

	fs := flag.NewFlagSet("cred register", flag.ContinueOnError)
	fs.SetOutput(errW)

	providerFlag := fs.String("provider", "", "credential provider kind (required)")
	providerParamsFlag := fs.String("provider-params", "", "provider-specific parameters as JSON object")
	scopeFlag := fs.String("scope", "generic", "scope kind (e.g. llm-session, generic)")
	ttlFlag := fs.Int64("ttl", 0, "TTL hint in seconds (0 = use provider default)")
	manualOnlyFlag := fs.Bool("manual-only", true, "mark binding as manual-only (default: true)")
	tagFlag := fs.String("tag", "", "comma-separated tags")

	// --destination may appear multiple times; extract before flag.Parse.
	var destinationStrs []string
	var flagArgs []string
	for i := 0; i < len(remainingArgs); i++ {
		if remainingArgs[i] == "--destination" && i+1 < len(remainingArgs) {
			destinationStrs = append(destinationStrs, remainingArgs[i+1])
			i++
		} else if strings.HasPrefix(remainingArgs[i], "--destination=") {
			destinationStrs = append(destinationStrs, strings.TrimPrefix(remainingArgs[i], "--destination="))
		} else {
			flagArgs = append(flagArgs, remainingArgs[i])
		}
	}

	if err := fs.Parse(flagArgs); err != nil {
		return 1
	}

	// If name was not the first positional, check fs.Args() for it.
	if name == "" {
		positional := fs.Args()
		if len(positional) < 1 {
			fmt.Fprintln(errW, "kpm cred register: binding name is required")
			fmt.Fprint(errW, credUsage)
			return 1
		}
		name = positional[0]
	}

	if *providerFlag == "" {
		fmt.Fprintln(errW, "kpm cred register: --provider is required")
		return 1
	}
	if len(destinationStrs) == 0 {
		fmt.Fprintln(errW, "kpm cred register: at least one --destination is required")
		return 1
	}

	// Parse --provider-params JSON.
	var providerParams map[string]any
	if *providerParamsFlag != "" {
		if err := json.Unmarshal([]byte(*providerParamsFlag), &providerParams); err != nil {
			fmt.Fprintf(errW, "kpm cred register: invalid --provider-params JSON: %v\n", err)
			return 1
		}
	}

	// Parse destinations: each is "<kind>:<target_id>[:<params_json>]"
	dests, err := parseDestinations(destinationStrs)
	if err != nil {
		fmt.Fprintf(errW, "kpm cred register: %v\n", err)
		return 1
	}

	// Parse tags.
	var tags []string
	if *tagFlag != "" {
		for _, t := range strings.Split(*tagFlag, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				tags = append(tags, t)
			}
		}
	}

	b := CredentialBinding{
		Name:           name,
		ProviderKind:   *providerFlag,
		ProviderParams: providerParams,
		Scope:          BindingScope{Kind: *scopeFlag},
		Destinations:   dests,
		RotationPolicy: RotationPolicy{
			TTLHintSeconds: *ttlFlag,
			ManualOnly:     *manualOnlyFlag,
		},
		Metadata: BindingMetadata{Tags: tags},
	}

	registered, regErr := client.RegisterBinding(ctx, b)
	if regErr != nil {
		fmt.Fprintf(errW, "error: %v\n", regErr)
		return 1
	}

	fmt.Fprintf(w, "Registered binding %q\n", registered.Name)
	fmt.Fprintf(w, "  Provider:     %s\n", registered.ProviderKind)
	fmt.Fprintf(w, "  Destinations: %d\n", len(registered.Destinations))
	if len(tags) > 0 {
		fmt.Fprintf(w, "  Tags:         %s\n", strings.Join(tags, ", "))
	}
	return 0
}

// ParseDestinations is the exported wrapper around parseDestinations,
// used by tests and the CLI dispatcher.
func ParseDestinations(strs []string) ([]DestinationSpec, error) {
	return parseDestinations(strs)
}

// parseDestinations parses a slice of "kind:target_id[:params_json]" strings.
func parseDestinations(strs []string) ([]DestinationSpec, error) {
	out := make([]DestinationSpec, 0, len(strs))
	for _, s := range strs {
		d, err := parseDestination(s)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

// parseDestination parses "kind:target_id[:params_json]".
func parseDestination(s string) (DestinationSpec, error) {
	// Split on first colon to get kind.
	idx := strings.Index(s, ":")
	if idx < 0 {
		return DestinationSpec{}, fmt.Errorf("invalid destination %q: expected kind:target_id[:params_json]", s)
	}
	kind := s[:idx]
	rest := s[idx+1:]

	// The target_id may itself contain colons (e.g. "owner/repo:SECRET_NAME").
	// We look for a potential trailing ":{...}" params segment.
	var targetID string
	var params map[string]any

	lastBrace := strings.LastIndex(rest, ":{")
	if lastBrace >= 0 && strings.HasSuffix(rest, "}") {
		targetID = rest[:lastBrace]
		paramsStr := rest[lastBrace+1:]
		if err := json.Unmarshal([]byte(paramsStr), &params); err != nil {
			// Not valid JSON — treat the whole remainder as target_id.
			targetID = rest
			params = nil
		}
	} else {
		targetID = rest
	}

	if kind == "" {
		return DestinationSpec{}, fmt.Errorf("invalid destination %q: kind is empty", s)
	}
	if targetID == "" {
		return DestinationSpec{}, fmt.Errorf("invalid destination %q: target_id is empty", s)
	}

	return DestinationSpec{Kind: kind, TargetID: targetID, Params: params}, nil
}

// ── list ──────────────────────────────────────────────────────────────────────

func runCredList(ctx context.Context, w io.Writer, errW io.Writer, client *Client, args []string) int {
	fs := flag.NewFlagSet("cred list", flag.ContinueOnError)
	fs.SetOutput(errW)
	tagFlag := fs.String("tag", "", "filter by tag")
	jsonFlag := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return 1
	}

	bindings, err := client.ListBindings(ctx, *tagFlag)
	if err != nil {
		fmt.Fprintf(errW, "error: %v\n", err)
		return 1
	}

	if *jsonFlag {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(bindings)
		return 0
	}

	if len(bindings) == 0 {
		fmt.Fprintln(w, "No credential bindings found. Add one with: kpm cred register <name> --provider <kind> --destination <kind>:<target_id>")
		return 0
	}

	fmt.Fprintf(w, "%-30s %-22s %-6s %-22s %s\n", "NAME", "PROVIDER", "DESTS", "LAST ROTATED", "TAGS")
	fmt.Fprintf(w, "%s\n", strings.Repeat("-", 90))
	for _, b := range bindings {
		lastRotated := b.LastRotatedAt
		if lastRotated == "" {
			lastRotated = "never"
		} else if t, err := time.Parse(time.RFC3339, lastRotated); err == nil {
			lastRotated = t.Format("2006-01-02 15:04")
		}
		tagStr := ""
		if len(b.Tags) > 0 {
			tagStr = strings.Join(b.Tags, ",")
		}
		fmt.Fprintf(w, "%-30s %-22s %-6d %-22s %s\n",
			b.Name, b.ProviderKind, b.DestinationCount, lastRotated, tagStr)
	}
	fmt.Fprintf(w, "\n%d binding(s)\n", len(bindings))
	return 0
}

// ── inspect ───────────────────────────────────────────────────────────────────

func runCredInspect(ctx context.Context, w io.Writer, errW io.Writer, client *Client, args []string) int {
	// Extract binding name (first non-flag arg) before flag.Parse so that
	// flags after the name are not lost.
	var name string
	var flagArgs []string
	for _, a := range args {
		if name == "" && !strings.HasPrefix(a, "-") {
			name = a
		} else {
			flagArgs = append(flagArgs, a)
		}
	}

	fs := flag.NewFlagSet("cred inspect", flag.ContinueOnError)
	fs.SetOutput(errW)
	jsonFlag := fs.Bool("json", false, "output raw JSON")
	if err := fs.Parse(flagArgs); err != nil {
		return 1
	}

	if name == "" {
		fmt.Fprintln(errW, "kpm cred inspect: binding name is required")
		return 1
	}

	b, err := client.GetBinding(ctx, name)
	if err != nil {
		fmt.Fprintf(errW, "error: %v\n", err)
		return 1
	}

	if *jsonFlag {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(b)
		return 0
	}

	// Pretty format.
	fmt.Fprintf(w, "Binding: %s\n", b.Name)
	fmt.Fprintf(w, "  Provider kind:   %s\n", b.ProviderKind)
	if len(b.ProviderParams) > 0 {
		pp, _ := json.Marshal(b.ProviderParams)
		fmt.Fprintf(w, "  Provider params: %s\n", pp)
	}
	fmt.Fprintf(w, "  Scope kind:      %s\n", b.Scope.Kind)
	fmt.Fprintf(w, "  Destinations:    %d\n", len(b.Destinations))
	for i, d := range b.Destinations {
		fmt.Fprintf(w, "    [%d] %s → %s\n", i, d.Kind, d.TargetID)
		if len(d.Params) > 0 {
			pp, _ := json.Marshal(d.Params)
			fmt.Fprintf(w, "        params: %s\n", pp)
		}
	}
	fmt.Fprintf(w, "  Manual only:     %v\n", b.RotationPolicy.ManualOnly)
	if b.RotationPolicy.TTLHintSeconds > 0 {
		fmt.Fprintf(w, "  TTL hint:        %ds\n", b.RotationPolicy.TTLHintSeconds)
	}
	if b.Metadata.CreatedAt != "" {
		fmt.Fprintf(w, "  Created:         %s\n", b.Metadata.CreatedAt)
	}
	if b.Metadata.LastRotatedAt != "" {
		fmt.Fprintf(w, "  Last rotated:    %s (generation %d)\n",
			b.Metadata.LastRotatedAt, b.Metadata.LastGeneration)
	} else {
		fmt.Fprintf(w, "  Last rotated:    never\n")
	}
	if len(b.Metadata.Tags) > 0 {
		fmt.Fprintf(w, "  Tags:            %s\n", strings.Join(b.Metadata.Tags, ", "))
	}
	return 0
}

// ── rotate ────────────────────────────────────────────────────────────────────

func runCredRotate(ctx context.Context, w io.Writer, errW io.Writer, client *Client, args []string) int {
	// Extract name before flag.Parse (same pattern as inspect).
	var name string
	var flagArgs []string
	for _, a := range args {
		if name == "" && !strings.HasPrefix(a, "-") {
			name = a
		} else {
			flagArgs = append(flagArgs, a)
		}
	}

	fs := flag.NewFlagSet("cred rotate", flag.ContinueOnError)
	fs.SetOutput(errW)
	if err := fs.Parse(flagArgs); err != nil {
		return 1
	}

	if name == "" {
		fmt.Fprintln(errW, "kpm cred rotate: binding name is required")
		return 1
	}

	result, err := client.RotateBinding(ctx, name)
	if err != nil {
		fmt.Fprintf(errW, "error: %v\n", err)
		return 1
	}

	fmt.Fprintf(w, "Rotated %q (generation %d, at %s)\n", result.Name, result.Generation, result.RotatedAt)
	fmt.Fprintf(w, "  Destinations:\n")
	exitCode := 0
	for _, r := range result.Results {
		status := "OK"
		if !r.Success {
			if r.IsTransient {
				status = "TRANSIENT ERROR"
			} else {
				status = "ERROR"
			}
			exitCode = 1
		}
		line := fmt.Sprintf("    %-14s %-40s %s", r.Kind, r.TargetID, status)
		if r.Error != "" {
			line += " — " + r.Error
		}
		fmt.Fprintln(w, line)
	}
	return exitCode
}

// ── remove ────────────────────────────────────────────────────────────────────

func runCredRemove(ctx context.Context, w io.Writer, errW io.Writer, client *Client, args []string) int {
	// Extract name before flag.Parse (same pattern as inspect).
	var name string
	var flagArgs []string
	for _, a := range args {
		if name == "" && !strings.HasPrefix(a, "-") {
			name = a
		} else {
			flagArgs = append(flagArgs, a)
		}
	}

	fs := flag.NewFlagSet("cred remove", flag.ContinueOnError)
	fs.SetOutput(errW)
	purgeFlag := fs.Bool("purge", false, "permanently delete (no recovery)")
	if err := fs.Parse(flagArgs); err != nil {
		return 1
	}

	if name == "" {
		fmt.Fprintln(errW, "kpm cred remove: binding name is required")
		return 1
	}

	if err := client.RemoveBinding(ctx, name, *purgeFlag); err != nil {
		fmt.Fprintf(errW, "error: %v\n", err)
		return 1
	}

	verb := "Removed"
	if *purgeFlag {
		verb = "Purged"
	}
	fmt.Fprintf(w, "%s binding %q\n", verb, name)
	return 0
}
