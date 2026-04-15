package kpm

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
)

func RunRemove(ctx context.Context, w io.Writer, client *Client, path string, purge bool) error {
	meta, err := client.GetMetadata(ctx, path)
	if err != nil || meta == nil {
		return fmt.Errorf("%s not found", path)
	}

	if purge {
		fmt.Fprintf(w, "PERMANENTLY delete %s (v%d) and all versions? This cannot be undone. [y/N] ", path, meta.Version)
	} else {
		fmt.Fprintf(w, "Remove %s (v%d)? [y/N] ", path, meta.Version)
	}

	reader := bufio.NewReader(os.Stdin)
	answer, _ := reader.ReadString('\n')
	if strings.TrimSpace(strings.ToLower(answer)) != "y" {
		return fmt.Errorf("cancelled")
	}

	if err := client.DeleteSecret(ctx, path, purge); err != nil {
		return err
	}

	if purge {
		fmt.Fprintf(w, "Purged %s\n", path)
	} else {
		fmt.Fprintf(w, "Removed %s\n", path)
	}
	return nil
}
