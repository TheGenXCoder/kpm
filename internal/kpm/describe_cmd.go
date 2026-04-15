package kpm

import (
	"context"
	"fmt"
	"io"
	"strings"
)

func RunDescribe(ctx context.Context, w io.Writer, client *Client, path string) error {
	meta, err := client.GetMetadata(ctx, path)
	if err != nil {
		return err
	}
	if meta == nil {
		return fmt.Errorf("%s not found", path)
	}

	fmt.Fprintf(w, "%s/%s\n", meta.Service, meta.Name)
	if meta.Type != "" {
		fmt.Fprintf(w, "  Type:        %s\n", meta.Type)
	}
	if len(meta.Tags) > 0 {
		fmt.Fprintf(w, "  Tags:        %s\n", strings.Join(meta.Tags, ", "))
	}
	if meta.Description != "" {
		fmt.Fprintf(w, "  Description: %s\n", meta.Description)
	}
	fmt.Fprintf(w, "  Created:     %s\n", meta.Created)
	fmt.Fprintf(w, "  Updated:     %s\n", meta.Updated)
	if meta.Expires != "" {
		fmt.Fprintf(w, "  Expires:     %s\n", meta.Expires)
	}
	fmt.Fprintf(w, "  Version:     %d\n", meta.Version)
	if meta.Deleted {
		fmt.Fprintln(w, "  Status:      DELETED")
	}
	return nil
}
