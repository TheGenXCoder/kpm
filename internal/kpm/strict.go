package kpm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// FormatStrictBlob encodes a KMSReference as a strict-mode blob:
// ENC[kpm-strict:<sessionID>:<base64-JSON-ref>]
//
// The blob encodes the KMS reference rather than ciphertext. When the
// DecryptListener receives a blob with the "kpm-strict" tag, it round-trips
// to AgentKMS over mTLS to fetch the secret — no local session key is used.
func FormatStrictBlob(sessionID string, ref KMSReference) (string, error) {
	if sessionID == "" {
		return "", fmt.Errorf("FormatStrictBlob: sessionID must not be empty")
	}
	if ref.Type == "" {
		return "", fmt.Errorf("FormatStrictBlob: KMSReference.Type must not be empty")
	}
	b, err := json.Marshal(ref)
	if err != nil {
		return "", fmt.Errorf("FormatStrictBlob: marshal ref: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(b)
	return fmt.Sprintf("ENC[kpm-strict:%s:%s]", sessionID, encoded), nil
}

// ParseStrictBlob extracts the session ID and KMSReference from a strict-mode blob.
func ParseStrictBlob(blob string) (sessionID string, ref KMSReference, err error) {
	const prefix = "ENC[kpm-strict:"
	if !strings.HasPrefix(blob, prefix) || !strings.HasSuffix(blob, "]") {
		return "", KMSReference{}, fmt.Errorf("ParseStrictBlob: invalid blob format: %q", blob)
	}
	inner := blob[len(prefix) : len(blob)-1]
	idx := strings.Index(inner, ":")
	if idx < 0 {
		return "", KMSReference{}, fmt.Errorf("ParseStrictBlob: missing sessionID separator in %q", inner)
	}
	sid := inner[:idx]
	b64 := inner[idx+1:]
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", KMSReference{}, fmt.Errorf("ParseStrictBlob: base64 decode: %w", err)
	}
	var r KMSReference
	if err := json.Unmarshal(raw, &r); err != nil {
		return "", KMSReference{}, fmt.Errorf("ParseStrictBlob: unmarshal ref: %w", err)
	}
	return sid, r, nil
}

// ValidateStrictFlags returns an error if --strict and --plaintext are both set.
// These flags are mutually exclusive: --strict means no plaintext leaves AgentKMS
// except on demand to the child process; --plaintext means output is unencrypted.
func ValidateStrictFlags(strict, plaintext bool) error {
	if strict && plaintext {
		return fmt.Errorf("--strict and --plaintext are mutually exclusive: cannot use both flags together")
	}
	return nil
}

// FetchByRef fetches a secret value from AgentKMS given a KMSReference.
// This is used by the strict-mode listener to perform one AgentKMS call per decrypt request.
//
// For Type=="kv": calls GET /credentials/generic/{path} and returns secrets[ref.Key].
// For Type=="llm": calls GET /credentials/llm/{path} and returns the api_key.
// For other types (registry): calls GET /credentials/generic/{type}/{path}.
func (c *Client) FetchByRef(ctx context.Context, ref KMSReference) ([]byte, error) {
	switch ref.Type {
	case "llm":
		cred, err := c.FetchLLM(ctx, ref.Path)
		if err != nil {
			return nil, fmt.Errorf("strict fetch llm/%s: %w", ref.Path, err)
		}
		defer ZeroBytes(cred.APIKey)
		result := make([]byte, len(cred.APIKey))
		copy(result, cred.APIKey)
		return result, nil

	case "kv":
		cred, err := c.FetchGeneric(ctx, ref.Path)
		if err != nil {
			return nil, fmt.Errorf("strict fetch kv/%s: %w", ref.Path, err)
		}
		defer ZeroMap(cred.Secrets)
		key := ref.Key
		if key == "" {
			// No specific key — return "value" field or fail
			v, ok := cred.Secrets["value"]
			if !ok {
				return nil, fmt.Errorf("strict fetch kv/%s: no key specified and no 'value' field found", ref.Path)
			}
			result := make([]byte, len(v))
			copy(result, v)
			return result, nil
		}
		v, ok := cred.Secrets[key]
		if !ok {
			return nil, fmt.Errorf("strict fetch kv/%s: key %q not found", ref.Path, key)
		}
		result := make([]byte, len(v))
		copy(result, v)
		return result, nil

	default:
		// Registry-style reference: type is service name, path is item name
		registryPath := ref.Type + "/" + ref.Path
		secrets, err := c.FetchRegistrySecret(ctx, registryPath)
		if err != nil {
			return nil, fmt.Errorf("strict fetch registry/%s: %w", registryPath, err)
		}
		defer ZeroMap(secrets)
		var val []byte
		if ref.Key != "" {
			v, ok := secrets[ref.Key]
			if !ok {
				return nil, fmt.Errorf("strict fetch registry/%s: key %q not found", registryPath, ref.Key)
			}
			val = v
		} else if v, ok := secrets["value"]; ok {
			val = v
		} else {
			return nil, fmt.Errorf("strict fetch registry/%s: multi-field secret, specify field with #key", registryPath)
		}
		result := make([]byte, len(val))
		copy(result, val)
		return result, nil
	}
}
