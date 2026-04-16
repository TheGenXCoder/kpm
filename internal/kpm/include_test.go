package kpm

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveTemplateWithIncludes(t *testing.T) {
	dir := t.TempDir()

	// Set up .kpm/templates/ under dir so ProjectTemplatesDir() finds them.
	tmplDir := filepath.Join(dir, ".kpm", "templates")
	os.MkdirAll(tmplDir, 0755)

	// base.template
	os.WriteFile(filepath.Join(tmplDir, "base.template"), []byte(
		"BASE_KEY=${kms:kv/base#key}\n"+
			"SHARED=${kms:kv/shared#val}\n",
	), 0644)

	// app.template includes base and overrides SHARED
	os.WriteFile(filepath.Join(tmplDir, "app.template"), []byte(
		"${kms:include/base}\n"+
			"APP_KEY=${kms:kv/app#key}\n"+
			"SHARED=${kms:kv/app#override}\n",
	), 0644)

	origDir, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(origDir)

	entries, err := ResolveTemplateWithIncludes(filepath.Join(tmplDir, "app.template"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Verify include entries are present
	found := map[string]bool{}
	for _, e := range entries {
		if e.EnvKey != "" {
			found[e.EnvKey] = true
		}
	}
	if !found["BASE_KEY"] {
		t.Error("missing BASE_KEY from include")
	}
	if !found["APP_KEY"] {
		t.Error("missing APP_KEY")
	}
	// SHARED should be present (overridden by app)
	if !found["SHARED"] {
		t.Error("missing SHARED")
	}

	// Verify override: SHARED from app should win (kv/app#override, not kv/shared#val)
	for _, e := range entries {
		if e.EnvKey == "SHARED" {
			if e.Ref.Path != "app" || e.Ref.Key != "override" {
				t.Errorf("SHARED should be overridden to kv/app#override, got path=%q key=%q", e.Ref.Path, e.Ref.Key)
			}
		}
	}
}

func TestCircularIncludeDetected(t *testing.T) {
	dir := t.TempDir()
	tmplDir := filepath.Join(dir, ".kpm", "templates")
	os.MkdirAll(tmplDir, 0755)

	// a includes b, b includes a
	os.WriteFile(filepath.Join(tmplDir, "a.template"), []byte("${kms:include/b}\nA=${kms:kv/a#v}\n"), 0644)
	os.WriteFile(filepath.Join(tmplDir, "b.template"), []byte("${kms:include/a}\nB=${kms:kv/b#v}\n"), 0644)

	origDir, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(origDir)

	_, err := ResolveTemplateWithIncludes(filepath.Join(tmplDir, "a.template"), nil, nil)
	if err == nil {
		t.Error("expected circular include error")
	}
}

func TestIncludeWithProfileVariables(t *testing.T) {
	dir := t.TempDir()
	tmplDir := filepath.Join(dir, ".kpm", "templates")
	os.MkdirAll(filepath.Join(tmplDir, "customers", "acme"), 0755)

	os.WriteFile(filepath.Join(tmplDir, "customers", "acme", "db.template"),
		[]byte("DB_HOST=${kms:kv/acme/db#host}\n"), 0644)

	os.WriteFile(filepath.Join(tmplDir, "app.template"),
		[]byte("${kms:include/customers/{{profile:customer}}/db}\nAPP_KEY=${kms:kv/app#key}\n"), 0644)

	origDir, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(origDir)

	profile := Profile{"customer": "acme"}
	entries, err := ResolveTemplateWithIncludes(filepath.Join(tmplDir, "app.template"), profile, nil)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, e := range entries {
		if e.EnvKey == "DB_HOST" {
			found = true
		}
	}
	if !found {
		t.Error("DB_HOST from included template not found")
	}
}

func TestResolveProfileVarsInEntries(t *testing.T) {
	profile := Profile{"customer": "acme", "region": "us-east"}

	entries := []TemplateEntry{
		{EnvKey: "DB_HOST", IsKMSRef: true, Ref: KMSReference{Type: "kv", Path: "{{profile:customer}}/db", Key: "host"}},
		{EnvKey: "PLAIN", IsKMSRef: false, PlainValue: []byte("static")},
		{EnvKey: "API_KEY", IsKMSRef: true, Ref: KMSReference{Type: "kv", Path: "services/{{profile:region}}", Key: "api-key"}},
	}

	resolved, err := ResolveProfileVarsInEntries(entries, profile)
	if err != nil {
		t.Fatal(err)
	}

	if resolved[0].Ref.Path != "acme/db" {
		t.Errorf("DB_HOST path = %q, want acme/db", resolved[0].Ref.Path)
	}
	if resolved[2].Ref.Path != "services/us-east" {
		t.Errorf("API_KEY path = %q, want services/us-east", resolved[2].Ref.Path)
	}
}
