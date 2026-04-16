package kpm

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadProfileMerge(t *testing.T) {
	// Create a nested directory structure with configs at each level
	root := t.TempDir()

	// Level 1: customer
	l1 := filepath.Join(root, "clients", "acme")
	os.MkdirAll(filepath.Join(l1, ".kpm"), 0755)
	os.WriteFile(filepath.Join(l1, ".kpm", "config.yaml"), []byte("profile:\n  customer: acme\n"), 0644)

	// Level 2: region
	l2 := filepath.Join(l1, "us-east")
	os.MkdirAll(filepath.Join(l2, ".kpm"), 0755)
	os.WriteFile(filepath.Join(l2, ".kpm", "config.yaml"), []byte("profile:\n  region: us-east\n"), 0644)

	// Level 3: project
	l3 := filepath.Join(l2, "project-x")
	os.MkdirAll(filepath.Join(l3, ".kpm"), 0755)
	os.WriteFile(filepath.Join(l3, ".kpm", "config.yaml"), []byte("profile:\n  project: project-x\n  environment: staging\n"), 0644)

	// cd into the deepest level
	origDir, _ := os.Getwd()
	os.Chdir(l3)
	defer os.Chdir(origDir)

	profile, err := LoadProfile()
	if err != nil {
		t.Fatal(err)
	}

	if profile["customer"] != "acme" {
		t.Errorf("customer = %q, want acme", profile["customer"])
	}
	if profile["region"] != "us-east" {
		t.Errorf("region = %q, want us-east", profile["region"])
	}
	if profile["project"] != "project-x" {
		t.Errorf("project = %q, want project-x", profile["project"])
	}
	if profile["environment"] != "staging" {
		t.Errorf("environment = %q, want staging", profile["environment"])
	}
}

func TestLoadProfileChildOverridesParent(t *testing.T) {
	root := t.TempDir()

	parent := filepath.Join(root, "parent")
	os.MkdirAll(filepath.Join(parent, ".kpm"), 0755)
	os.WriteFile(filepath.Join(parent, ".kpm", "config.yaml"), []byte("profile:\n  env: production\n  region: us-west\n"), 0644)

	child := filepath.Join(parent, "child")
	os.MkdirAll(filepath.Join(child, ".kpm"), 0755)
	os.WriteFile(filepath.Join(child, ".kpm", "config.yaml"), []byte("profile:\n  env: staging\n"), 0644)

	origDir, _ := os.Getwd()
	os.Chdir(child)
	defer os.Chdir(origDir)

	profile, _ := LoadProfile()

	if profile["env"] != "staging" {
		t.Errorf("env = %q, want staging (child should override)", profile["env"])
	}
	if profile["region"] != "us-west" {
		t.Errorf("region = %q, want us-west (inherited from parent)", profile["region"])
	}
}

func TestProfileResolve(t *testing.T) {
	p := Profile{"customer": "acme", "region": "us-east", "project": "widget"}

	tests := []struct {
		input string
		want  string
	}{
		{"customers/{{profile:customer}}/db", "customers/acme/db"},
		{"{{profile:customer}}/{{profile:region}}/{{profile:project}}/db", "acme/us-east/widget/db"},
		{"{{profile:missing:-default}}", "default"},
		{"no-variables-here", "no-variables-here"},
	}

	for _, tt := range tests {
		got, err := p.Resolve(tt.input)
		if err != nil {
			t.Errorf("Resolve(%q) error: %v", tt.input, err)
			continue
		}
		if got != tt.want {
			t.Errorf("Resolve(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestProfileResolveMissing(t *testing.T) {
	p := Profile{"customer": "acme"}

	_, err := p.Resolve("{{profile:missing}}")
	if err == nil {
		t.Error("expected error for missing profile variable")
	}
}
