package kpm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// SecretMetadata is metadata for a secret (never contains values).
type SecretMetadata struct {
	Path        string   `json:"path,omitempty"`
	Service     string   `json:"service,omitempty"`
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Type        string   `json:"type,omitempty"`
	Created     string   `json:"created"`
	Updated     string   `json:"updated"`
	Expires     string   `json:"expires,omitempty"`
	Version     int      `json:"version"`
	Deleted     bool     `json:"deleted"`
}

// populateServiceName splits the Path field (e.g. "cloudflare/dns-token") into
// Service and Name. If Service/Name are already set they are left unchanged.
func (m *SecretMetadata) populateServiceName() {
	if m.Service != "" || m.Name != "" {
		return
	}
	if m.Path == "" {
		return
	}
	idx := strings.Index(m.Path, "/")
	if idx < 0 {
		m.Service = m.Path
		return
	}
	m.Service = m.Path[:idx]
	m.Name = m.Path[idx+1:]
}

// VersionEntry is one version in a secret's history.
type VersionEntry struct {
	Version int    `json:"version"`
	Created string `json:"created"`
	Caller  string `json:"caller"`
}

// WriteResult is returned by WriteSecret.
type WriteResult struct {
	Path    string `json:"path"`
	Version int    `json:"version"`
	Status  string `json:"status"`
}

// WriteSecret stores a secret value in AgentKMS.
// The value parameter is []byte and should be zeroed by the caller after this returns.
func (c *Client) WriteSecret(ctx context.Context, path string, value []byte) (*WriteResult, error) {
	url := c.baseURL + "/secrets/" + path
	body := map[string]string{"value": string(value)}

	resp, err := c.doPost(ctx, url, body)
	if err != nil {
		return nil, fmt.Errorf("write secret: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, serverError(resp, "write " + path)
	}

	var result WriteResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &result, nil
}

// WriteSecretFields stores a multi-field secret in AgentKMS.
func (c *Client) WriteSecretFields(ctx context.Context, path string, fields map[string]string) (*WriteResult, error) {
	url := c.baseURL + "/secrets/" + path

	resp, err := c.doPost(ctx, url, fields)
	if err != nil {
		return nil, fmt.Errorf("write secret: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, serverError(resp, "write " + path)
	}

	var result WriteResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &result, nil
}

// WriteMetadata updates metadata for a secret.
func (c *Client) WriteMetadata(ctx context.Context, path, desc string, tags []string, secretType, expires string) error {
	url := c.baseURL + "/metadata/" + path
	body := map[string]any{}
	if desc != "" {
		body["description"] = desc
	}
	if tags != nil {
		body["tags"] = tags
	}
	if secretType != "" {
		body["type"] = secretType
	}
	if expires != "" {
		body["expires"] = expires
	}

	resp, err := c.doPost(ctx, url, body)
	if err != nil {
		return fmt.Errorf("write metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return serverError(resp, "request")
	}
	return nil
}

// ListMetadata returns metadata for all secrets (never values).
func (c *Client) ListMetadata(ctx context.Context, includeDeleted bool) ([]SecretMetadata, error) {
	url := c.baseURL + "/metadata"
	if includeDeleted {
		url += "?include_deleted=true"
	}

	resp, err := c.doGet(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("list metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, serverError(resp, "request")
	}

	var body struct {
		Secrets []SecretMetadata `json:"secrets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	for i := range body.Secrets {
		body.Secrets[i].populateServiceName()
	}
	return body.Secrets, nil
}

// GetMetadata returns metadata for a specific secret.
func (c *Client) GetMetadata(ctx context.Context, path string) (*SecretMetadata, error) {
	url := c.baseURL + "/metadata/" + path

	resp, err := c.doGet(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("get metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, serverError(resp, "request")
	}

	var meta SecretMetadata
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	meta.populateServiceName()
	return &meta, nil
}

// DeleteSecret soft-deletes or purges a secret.
func (c *Client) DeleteSecret(ctx context.Context, path string, purge bool) error {
	url := c.baseURL + "/secrets/" + path
	if purge {
		url += "?purge=true"
	}

	resp, err := c.doDelete(ctx, url)
	if err != nil {
		return fmt.Errorf("delete: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return serverError(resp, "request")
	}
	return nil
}

// GetHistory returns version history (metadata only, never values).
func (c *Client) GetHistory(ctx context.Context, path string) ([]VersionEntry, error) {
	url := c.baseURL + "/secrets/" + path + "?action=history"

	resp, err := c.doGet(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("get history: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, serverError(resp, "request")
	}

	var body struct {
		Versions []VersionEntry `json:"versions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return body.Versions, nil
}
