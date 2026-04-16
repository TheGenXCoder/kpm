package kpm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestPullTemplatesNonBase64Content(t *testing.T) {
	// Server returns raw (non-base64) content for "env" template
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/credentials/generic/kpm/templates/env" {
			json.NewEncoder(w).Encode(map[string]any{
				"path": "kpm/templates/env",
				"secrets": map[string]string{
					"content":  "MYKEY=${kms:kv/myapp#key}\n", // raw, not base64
					"filename": "env.template",
				},
			})
			return
		}
		http.Error(w, "not found", 404)
	})
	defer srv.Close()

	dir := t.TempDir()
	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}

	var buf bytes.Buffer
	err := PullTemplates(context.Background(), &buf, c, dir)
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "pulled") {
		t.Errorf("expected 'pulled' in output: %s", out)
	}
	// Verify the file was written
	if _, statErr := os.Stat(dir + "/env.template"); statErr != nil {
		t.Errorf("env.template not written: %v", statErr)
	}
}

func TestPullTemplatesBase64Content(t *testing.T) {
	// Server returns proper base64-encoded content
	templateContent := "DB_HOST=${kms:kv/db/prod#host}\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(templateContent))

	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/credentials/generic/kpm/templates/aws" {
			json.NewEncoder(w).Encode(map[string]any{
				"path": "kpm/templates/aws",
				"secrets": map[string]string{
					"content":  encoded,
					"filename": "aws.template",
				},
			})
			return
		}
		http.Error(w, "not found", 404)
	})
	defer srv.Close()

	dir := t.TempDir()
	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}

	var buf bytes.Buffer
	err := PullTemplates(context.Background(), &buf, c, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "aws.template") {
		t.Errorf("expected aws.template in output: %s", buf.String())
	}

	// Verify content was decoded correctly
	content, err := os.ReadFile(dir + "/aws.template")
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != templateContent {
		t.Errorf("content = %q, want %q", string(content), templateContent)
	}
}

func TestPullTemplatesNoContentKey(t *testing.T) {
	// Server returns secret without "content" key — should be silently skipped
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/credentials/generic/kpm/templates/gcp" {
			json.NewEncoder(w).Encode(map[string]any{
				"path": "kpm/templates/gcp",
				"secrets": map[string]string{
					"other_field": "value", // no "content" key
				},
			})
			return
		}
		http.Error(w, "not found", 404)
	})
	defer srv.Close()

	dir := t.TempDir()
	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}

	var buf bytes.Buffer
	err := PullTemplates(context.Background(), &buf, c, dir)
	if err != nil {
		t.Fatal(err)
	}
	// Should report no templates found since content was skipped
	if !strings.Contains(buf.String(), "no templates found") {
		t.Errorf("expected 'no templates found': %s", buf.String())
	}
}

func TestPullTemplatesWriteFailure(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/credentials/generic/kpm/templates/docker" {
			json.NewEncoder(w).Encode(map[string]any{
				"path": "kpm/templates/docker",
				"secrets": map[string]string{
					"content": "DOCKER_TOKEN=${kms:kv/docker#token}\n",
				},
			})
			return
		}
		http.Error(w, "not found", 404)
	})
	defer srv.Close()

	// Make the dir read-only to force WriteFile failure
	dir := t.TempDir()
	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}

	// Pre-create the directory, then make it read-only
	os.MkdirAll(dir, 0755)
	os.Chmod(dir, 0555)
	defer os.Chmod(dir, 0755)

	var buf bytes.Buffer
	err := PullTemplates(context.Background(), &buf, c, dir)
	if err != nil {
		// MkdirAll might fail on read-only parent, which returns an error
		return
	}
	// If it got past MkdirAll, it should have printed a warning about write failure
	out := buf.String()
	if !strings.Contains(out, "warning") && !strings.Contains(out, "no templates found") {
		t.Errorf("expected warning or no-templates message: %s", out)
	}
}

func TestPullTemplatesCreateDirFailure(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", 404)
	})
	defer srv.Close()

	c := &Client{baseURL: srv.URL, httpClient: srv.Client()}

	// Try to create dir under a file (will fail)
	dir := t.TempDir()
	blockFile := dir + "/block"
	os.WriteFile(blockFile, []byte("block"), 0644)

	var buf bytes.Buffer
	err := PullTemplates(context.Background(), &buf, c, blockFile+"/subdir")
	if err == nil {
		t.Fatal("expected error when can't create templates dir")
	}
}
