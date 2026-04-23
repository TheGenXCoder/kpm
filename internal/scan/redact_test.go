package scan

import (
	"strings"
	"testing"
)

func TestRedact_KnownPrefix_OpenAIProj(t *testing.T) {
	got := Redact("sk-proj-verySecretValue1234567f2a")
	// "sk-proj-verySecretValue1234567f2a" is 33 bytes.
	// The spec listed 31 — that was a typo in the golden value.
	want := "sk-proj-••••7f2a (33 chars)"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestRedact_KnownPrefix_GitHub(t *testing.T) {
	got := Redact("ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if !strings.HasPrefix(got, "ghp_") {
		t.Errorf("expected ghp_ prefix, got %q", got)
	}
	if !strings.Contains(got, "••••") {
		t.Errorf("expected bullets, got %q", got)
	}
	if !strings.Contains(got, "AAAA") {
		t.Errorf("expected last-4 suffix, got %q", got)
	}
	if !strings.Contains(got, "(44 chars)") {
		t.Errorf("expected length 44, got %q", got)
	}
}

func TestRedact_KnownPrefix_AWSAccessKey(t *testing.T) {
	got := Redact("AKIAIOSFODNN7EXAMPLE")
	if !strings.HasPrefix(got, "AKIA") {
		t.Errorf("expected AKIA prefix, got %q", got)
	}
}

func TestRedact_UnknownPrefix(t *testing.T) {
	got := Redact("someRandomLookingValue9d1e")
	if !strings.Contains(got, "••••") {
		t.Errorf("expected bullets, got %q", got)
	}
	if !strings.Contains(got, "9d1e") {
		t.Errorf("expected last-4 suffix, got %q", got)
	}
	if !strings.Contains(got, "(26 chars)") {
		t.Errorf("expected length 26, got %q", got)
	}
}

func TestRedact_ShortValue_NoTail(t *testing.T) {
	got := Redact("short123")
	if strings.Contains(got, "123") {
		t.Errorf("short value must not reveal tail, got %q", got)
	}
	if !strings.Contains(got, "••••") {
		t.Errorf("expected bullets, got %q", got)
	}
	if !strings.Contains(got, "(8 chars)") {
		t.Errorf("expected length 8, got %q", got)
	}
}

func TestRedact_EmptyValue(t *testing.T) {
	got := Redact("")
	want := "•••• (0 chars)"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

// NON-LEAK INVARIANT: no redaction output may contain the full value.
func TestRedact_NeverLeaksFullValue(t *testing.T) {
	canaries := []string{
		"sk-proj-verySecretValue1234567f2a",
		"ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"AKIAIOSFODNN7EXAMPLE",
		"someRandomLookingValue9d1e",
		"short123",
		"-----BEGIN RSA PRIVATE KEY-----MIIEpAIBAAKCAQEA...",
	}
	for _, c := range canaries {
		got := Redact(c)
		if strings.Contains(got, c) {
			t.Errorf("Redact(%q) leaked full value in output: %q", c, got)
		}
	}
}
