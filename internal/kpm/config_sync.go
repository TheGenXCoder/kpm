package kpm

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// PushTemplates uploads all *.template files from dir to AgentKMS KV store.
// Each template is stored at kpm/templates/<basename-without-.template> with two
// fields: content (base64-encoded) and filename (original name).
// Writing uses `agentkms-dev secrets set` because the REST API is read-only.
func PushTemplates(w io.Writer, dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read templates dir %s: %w", dir, err)
	}

	pushed := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".template") {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		content, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(w, "  warning: could not read %s: %v\n", entry.Name(), err)
			continue
		}

		// Store as base64 to preserve newlines and special chars in the KV value.
		encoded := base64.StdEncoding.EncodeToString(content)
		name := strings.TrimSuffix(entry.Name(), ".template")
		kvPath := "kpm/templates/" + name

		cmd := exec.Command("agentkms-dev", "secrets", "set", kvPath,
			"content="+encoded,
			"filename="+entry.Name(),
		)
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(w, "  warning: failed to push %s: %v\n", entry.Name(), err)
			continue
		}

		fmt.Fprintf(w, "  pushed %s → kv/%s\n", entry.Name(), kvPath)
		pushed++
	}

	fmt.Fprintf(w, "✓ %d template(s) pushed to AgentKMS\n", pushed)
	return nil
}

// PullTemplates downloads templates from AgentKMS into dir.
// It first tries to fetch each well-known template name individually via
// GET /credentials/generic/kpm/templates/<name>.
func PullTemplates(ctx context.Context, w io.Writer, client *Client, dir string) error {
	return pullIndividualTemplates(ctx, w, client, dir)
}

// pullIndividualTemplates attempts to fetch a fixed list of known template names.
// This is the pragmatic approach while the REST API lacks a list/write endpoint.
func pullIndividualTemplates(ctx context.Context, w io.Writer, client *Client, dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create templates dir %s: %w", dir, err)
	}

	// Known template names to probe. Extend this list as new templates are pushed.
	names := []string{"shell-env", "ssh-keys", "env", "aws", "gcp", "docker"}
	pulled := 0

	for _, name := range names {
		cred, err := client.FetchGeneric(ctx, "kpm/templates/"+name)
		if err != nil {
			// 404 is expected for names that don't exist — skip silently.
			continue
		}

		content, ok := cred.Secrets["content"]
		if !ok {
			ZeroMap(cred.Secrets)
			continue
		}

		// Decode base64-encoded template content.
		// Copy content and filename out of the secrets map before ZeroMap clears it.
		decoded, decErr := base64.StdEncoding.DecodeString(string(content))
		if decErr != nil {
			// Not base64 (e.g. stored raw) — copy to avoid aliasing the map value.
			decoded = make([]byte, len(content))
			copy(decoded, content)
		}

		// Use stored filename if present, otherwise derive from key name.
		filename := name + ".template"
		if fn, ok := cred.Secrets["filename"]; ok {
			filename = string(fn) // string() copies the bytes
		}

		ZeroMap(cred.Secrets)

		destPath := filepath.Join(dir, filename)
		if err := os.WriteFile(destPath, decoded, 0644); err != nil {
			fmt.Fprintf(w, "  warning: could not write %s: %v\n", filename, err)
			continue
		}

		fmt.Fprintf(w, "  pulled %s\n", filename)
		pulled++
	}

	if pulled == 0 {
		fmt.Fprintln(w, "  no templates found in AgentKMS (push some first with: kpm config push)")
	} else {
		fmt.Fprintf(w, "✓ %d template(s) pulled from AgentKMS\n", pulled)
	}
	return nil
}
