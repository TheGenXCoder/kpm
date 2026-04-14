package kpm

import (
	"strings"
	"testing"
)

func TestParseKMSRef(t *testing.T) {
	tests := []struct {
		input string
		want  KMSReference
		ok    bool
	}{
		{
			input: "${kms:llm/openai}",
			want:  KMSReference{Type: "llm", Path: "openai", Key: "", Default: ""},
			ok:    true,
		},
		{
			input: "${kms:kv/db/prod#password}",
			want:  KMSReference{Type: "kv", Path: "db/prod", Key: "password", Default: ""},
			ok:    true,
		},
		{
			input: "${kms:kv/db/prod#host:-localhost}",
			want:  KMSReference{Type: "kv", Path: "db/prod", Key: "host", Default: "localhost"},
			ok:    true,
		},
		{
			input: "${kms:kv/app/config#port:-8080}",
			want:  KMSReference{Type: "kv", Path: "app/config", Key: "port", Default: "8080"},
			ok:    true,
		},
		{
			input: "plain-value",
			ok:    false,
		},
		{
			input: "${env:HOME}",
			ok:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			ref, ok := ParseKMSRef(tt.input)
			if ok != tt.ok {
				t.Fatalf("ParseKMSRef(%q) ok = %v, want %v", tt.input, ok, tt.ok)
			}
			if !ok {
				return
			}
			if ref != tt.want {
				t.Errorf("ParseKMSRef(%q) = %+v, want %+v", tt.input, ref, tt.want)
			}
		})
	}
}

func TestParseTemplate(t *testing.T) {
	input := `# comment line
APP_NAME=my-service
LOG_LEVEL=info
DB_PASSWORD=${kms:kv/db/prod#password}
DB_HOST=${kms:kv/db/prod#host}
OPENAI_KEY=${kms:llm/openai}
FALLBACK=${kms:kv/app/config#port:-8080}
`
	entries, err := ParseTemplate(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}

	if len(entries) != 6 {
		t.Fatalf("got %d entries, want 6", len(entries))
	}

	// Plain values
	if entries[0].EnvKey != "APP_NAME" || entries[0].IsKMSRef {
		t.Errorf("entry 0: want plain APP_NAME, got %+v", entries[0])
	}
	if string(entries[0].PlainValue) != "my-service" {
		t.Errorf("entry 0 value = %q, want my-service", entries[0].PlainValue)
	}

	// KMS ref: kv with key
	if entries[2].EnvKey != "DB_PASSWORD" || !entries[2].IsKMSRef {
		t.Errorf("entry 2: want KMS ref DB_PASSWORD, got %+v", entries[2])
	}
	if entries[2].Ref.Type != "kv" || entries[2].Ref.Path != "db/prod" || entries[2].Ref.Key != "password" {
		t.Errorf("entry 2 ref = %+v", entries[2].Ref)
	}

	// KMS ref: llm
	if entries[4].Ref.Type != "llm" || entries[4].Ref.Path != "openai" {
		t.Errorf("entry 4 ref = %+v", entries[4].Ref)
	}

	// KMS ref with default
	if entries[5].Ref.Default != "8080" {
		t.Errorf("entry 5 default = %q, want 8080", entries[5].Ref.Default)
	}
}

func TestParseTemplateEmpty(t *testing.T) {
	entries, err := ParseTemplate(strings.NewReader(""))
	if err != nil {
		t.Fatalf("ParseTemplate empty: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("got %d entries for empty input, want 0", len(entries))
	}
}
