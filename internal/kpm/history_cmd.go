package kpm

import (
	"context"
	"fmt"
	"io"
)

func RunHistory(ctx context.Context, w io.Writer, client *Client, path string) error {
	versions, err := client.GetHistory(ctx, path)
	if err != nil {
		return err
	}

	if len(versions) == 0 {
		fmt.Fprintf(w, "%s — no version history\n", path)
		return nil
	}

	fmt.Fprintf(w, "%s — %d versions\n\n", path, len(versions))
	for i := len(versions) - 1; i >= 0; i-- {
		v := versions[i]
		current := ""
		if i == len(versions)-1 {
			current = "(current)"
		}
		fmt.Fprintf(w, "  v%-3d %s  %-12s %s\n", v.Version, v.Created, v.Caller, current)
	}
	return nil
}
