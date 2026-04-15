package kpm

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// RunList displays secrets grouped by service.
func RunList(ctx context.Context, w io.Writer, client *Client, service, tag, secretType string, includeDeleted bool) error {
	secrets, err := client.ListMetadata(ctx, includeDeleted)
	if err != nil {
		return err
	}

	if len(secrets) == 0 {
		fmt.Fprintln(w, "No secrets found. Add one with: kpm add service/name")
		return nil
	}

	// Filter
	var filtered []SecretMetadata
	for _, s := range secrets {
		if service != "" && s.Service != service {
			continue
		}
		if tag != "" && !containsStr(s.Tags, tag) {
			continue
		}
		if secretType != "" && s.Type != secretType {
			continue
		}
		filtered = append(filtered, s)
	}

	if len(filtered) == 0 {
		fmt.Fprintln(w, "No secrets match the filter.")
		return nil
	}

	// Group by service
	grouped := map[string][]SecretMetadata{}
	for _, s := range filtered {
		grouped[s.Service] = append(grouped[s.Service], s)
	}

	services := make([]string, 0, len(grouped))
	for k := range grouped {
		services = append(services, k)
	}
	sort.Strings(services)

	for _, svc := range services {
		fmt.Fprintf(w, "%s/\n", svc)
		for _, s := range grouped[svc] {
			tp := s.Type
			if tp == "" {
				tp = "generic"
			}
			tagStr := ""
			if len(s.Tags) > 0 {
				tagStr = "[" + strings.Join(s.Tags, ", ") + "]"
			}
			desc := ""
			if s.Description != "" {
				if len(s.Description) > 30 {
					desc = "\"" + s.Description[:27] + "...\""
				} else {
					desc = "\"" + s.Description + "\""
				}
			}
			extra := ""
			if s.Expires != "" {
				if t, err := time.Parse(time.RFC3339, s.Expires); err == nil {
					d := time.Until(t)
					if d < 0 {
						extra = "EXPIRED"
					} else if d < 30*24*time.Hour {
						extra = fmt.Sprintf("EXPIRES %dd", int(d.Hours()/24))
					}
				}
			}
			if s.Deleted {
				extra = "DELETED"
			}
			fmt.Fprintf(w, "  %-20s %-14s %-18s %-30s v%d %s\n", s.Name, tp, tagStr, desc, s.Version, extra)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "%d secrets across %d services\n", len(filtered), len(services))
	return nil
}

func containsStr(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
