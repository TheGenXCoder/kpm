package kpm

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// AddOptions for the kpm add command.
type AddOptions struct {
	Path        string
	FromFile    string
	Description string
	Tags        []string
	Type        string
	Expires     string
}

// RunAdd stores a secret in AgentKMS.
func RunAdd(ctx context.Context, w io.Writer, client *Client, opts AddOptions) error {
	if opts.Path == "" {
		return fmt.Errorf("path required (format: service/name)")
	}
	if !strings.Contains(opts.Path, "/") {
		return fmt.Errorf("path must be service/name (e.g. cloudflare/dns-token)")
	}

	// Check existing
	existing, _ := client.GetMetadata(ctx, opts.Path)
	if existing != nil && !existing.Deleted {
		fmt.Fprintf(w, "%s exists (v%d). Update to v%d? [y/N] ", opts.Path, existing.Version, existing.Version+1)
		reader := bufio.NewReader(os.Stdin)
		answer, _ := reader.ReadString('\n')
		if strings.TrimSpace(strings.ToLower(answer)) != "y" {
			return fmt.Errorf("cancelled")
		}
	}

	// Read value
	var value []byte
	var err error

	if opts.FromFile != "" {
		value, err = os.ReadFile(opts.FromFile)
		if err != nil {
			return fmt.Errorf("read file: %w", err)
		}
	} else if !term.IsTerminal(int(os.Stdin.Fd())) {
		value, err = io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("read stdin: %w", err)
		}
		value = []byte(strings.TrimRight(string(value), "\n"))
	} else {
		fmt.Fprint(w, "Value: ")
		value, err = term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(w)
		if err != nil {
			return fmt.Errorf("read value: %w", err)
		}
	}
	// Zero after use
	defer ZeroBytes(value)

	if len(value) == 0 {
		return fmt.Errorf("empty value")
	}

	// Auto-detect type
	secretType := opts.Type
	if secretType == "" {
		secretType = DetectSecretType(string(value))
	}

	// Write secret
	result, err := client.WriteSecret(ctx, opts.Path, value)
	if err != nil {
		return fmt.Errorf("store secret: %w", err)
	}

	// Write metadata
	if opts.Description != "" || opts.Tags != nil || secretType != "generic" || opts.Expires != "" {
		_ = client.WriteMetadata(ctx, opts.Path, opts.Description, opts.Tags, secretType, opts.Expires)
	}

	tagStr := ""
	if len(opts.Tags) > 0 {
		tagStr = fmt.Sprintf(" (tagged: %s)", strings.Join(opts.Tags, ", "))
	}
	fmt.Fprintf(w, "Stored %s v%d%s [%s]\n", result.Path, result.Version, tagStr, secretType)
	return nil
}
