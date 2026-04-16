package kpm

import (
	"context"
	"fmt"
)

// ResolvedEntry is a template entry with its value filled in.
type ResolvedEntry struct {
	EnvKey     string
	PlainValue []byte // SECURITY: call ZeroBytes after use
	IsKMSRef   bool
	Ref        KMSReference
	Source     string // "agentkms", "cache", "default", or "" (passthrough)
}

// Resolve takes parsed template entries and fetches all KMS values.
// It batches requests: multiple refs to the same KV path produce one API call.
func Resolve(ctx context.Context, client *Client, entries []TemplateEntry) ([]ResolvedEntry, error) {
	type kvResult struct {
		secrets map[string][]byte
		err     error
	}
	kvCache := map[string]*kvResult{}

	// Prefetch: collect unique KV paths.
	for _, e := range entries {
		if !e.IsKMSRef || e.Ref.Type != "kv" {
			continue
		}
		if _, ok := kvCache[e.Ref.Path]; !ok {
			cred, err := client.FetchGeneric(ctx, e.Ref.Path)
			if err != nil {
				kvCache[e.Ref.Path] = &kvResult{err: err}
			} else {
				kvCache[e.Ref.Path] = &kvResult{secrets: cred.Secrets}
			}
		}
	}

	llmCache := map[string]*LLMCredential{}

	resolved := make([]ResolvedEntry, 0, len(entries))
	for _, e := range entries {
		re := ResolvedEntry{
			EnvKey:   e.EnvKey,
			IsKMSRef: e.IsKMSRef,
			Ref:      e.Ref,
		}

		if !e.IsKMSRef {
			re.PlainValue = make([]byte, len(e.PlainValue))
			copy(re.PlainValue, e.PlainValue)
			resolved = append(resolved, re)
			continue
		}

		switch e.Ref.Type {
		case "kv":
			result := kvCache[e.Ref.Path]
			if result.err != nil {
				if e.Ref.Default != "" {
					re.PlainValue = []byte(e.Ref.Default)
					re.Source = "default"
					resolved = append(resolved, re)
					continue
				}
				return nil, fmt.Errorf("resolve %s: %w", e.EnvKey, result.err)
			}
			val, ok := result.secrets[e.Ref.Key]
			if !ok {
				if e.Ref.Default != "" {
					re.PlainValue = []byte(e.Ref.Default)
					re.Source = "default"
					resolved = append(resolved, re)
					continue
				}
				return nil, fmt.Errorf("resolve %s: key %q not found at path %q", e.EnvKey, e.Ref.Key, e.Ref.Path)
			}
			re.PlainValue = make([]byte, len(val))
			copy(re.PlainValue, val)
			re.Source = "agentkms"

		case "llm":
			if _, ok := llmCache[e.Ref.Path]; !ok {
				cred, err := client.FetchLLM(ctx, e.Ref.Path)
				if err != nil {
					if e.Ref.Default != "" {
						re.PlainValue = []byte(e.Ref.Default)
						re.Source = "default"
						resolved = append(resolved, re)
						continue
					}
					return nil, fmt.Errorf("resolve %s: %w", e.EnvKey, err)
				}
				llmCache[e.Ref.Path] = cred
			}
			cred := llmCache[e.Ref.Path]
			re.PlainValue = make([]byte, len(cred.APIKey))
			copy(re.PlainValue, cred.APIKey)
			re.Source = "agentkms"

		default:
			// Registry path (service/name format, no llm/ or kv/ prefix).
			// e.Ref.Type is the service, e.Ref.Path is the name.
			registryPath := e.Ref.Type + "/" + e.Ref.Path
			secrets, err := client.FetchRegistrySecret(ctx, registryPath)
			if err != nil {
				if e.Ref.Default != "" {
					re.PlainValue = []byte(e.Ref.Default)
					re.Source = "default"
					resolved = append(resolved, re)
					continue
				}
				return nil, fmt.Errorf("resolve %s: %w", e.EnvKey, err)
			}

			// If a specific field was requested via #key, use it
			var val []byte
			if e.Ref.Key != "" {
				v, ok := secrets[e.Ref.Key]
				if !ok {
					ZeroMap(secrets)
					return nil, fmt.Errorf("resolve %s: field %q not found at %q", e.EnvKey, e.Ref.Key, registryPath)
				}
				val = v
			} else if v, ok := secrets["value"]; ok {
				val = v
			} else {
				// No "value" field and no key specified — fail
				ZeroMap(secrets)
				return nil, fmt.Errorf("resolve %s: multi-field secret at %q, specify field with #key", e.EnvKey, registryPath)
			}

			re.PlainValue = make([]byte, len(val))
			copy(re.PlainValue, val)
			re.Source = "agentkms"
			ZeroMap(secrets)
		}

		resolved = append(resolved, re)
	}

	return resolved, nil
}
