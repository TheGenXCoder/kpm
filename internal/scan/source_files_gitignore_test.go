package scan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGitignore_MatchesPatterns(t *testing.T) {
	dir := t.TempDir()
	content := "node_modules/\n*.log\nsecret.yaml\n# comment\n\n"
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	gi, err := LoadGitignore(dir)
	if err != nil {
		t.Fatalf("LoadGitignore: %v", err)
	}
	cases := []struct {
		path string
		want bool
	}{
		{"node_modules/foo.js", true},
		{"node_modules", true},
		{"app.log", true},
		{"logs/app.log", true},
		{"secret.yaml", true},
		{"subdir/secret.yaml", true},
		{"src/app.go", false},
		{"README.md", false},
	}
	for _, c := range cases {
		if got := gi.Match(c.path); got != c.want {
			t.Errorf("Match(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestGitignore_NoFile_ReturnsEmptyMatcher(t *testing.T) {
	dir := t.TempDir()
	gi, err := LoadGitignore(dir)
	if err != nil {
		t.Fatalf("LoadGitignore: %v", err)
	}
	if gi.Match("anything") {
		t.Error("empty gitignore should match nothing")
	}
}
