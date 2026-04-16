package kpm

import (
	"strings"
	"testing"
)

func TestDetectSecretType(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		// API tokens — provider-specific
		{"OpenAI sk-", "sk-proj-abc123def456", "api-token"},
		{"Anthropic oat01", "sk-ant-oat01-" + strings.Repeat("a", 80), "api-token"},
		{"GitHub classic PAT", "ghp_" + strings.Repeat("a", 36), "api-token"},
		{"GitHub OAuth", "gho_" + strings.Repeat("a", 36), "api-token"},
		{"GitHub server-to-server", "ghs_" + strings.Repeat("a", 36), "api-token"},
		{"GitHub user-to-server", "ghu_" + strings.Repeat("a", 36), "api-token"},
		{"GitHub refresh", "ghr_" + strings.Repeat("a", 36), "api-token"},
		{"AWS access key ID", "AKIAIOSFODNN7EXAMPL", "generic"}, // 19 chars, not 20
		{"AWS access key ID exact", "AKIAIOSFODNN7EXAMPLE", "api-token"},
		{"Stripe test secret", "sk_test_" + strings.Repeat("a", 24), "api-token"},
		{"Stripe live secret", "sk_live_" + strings.Repeat("a", 24), "api-token"},
		{"Stripe publishable test", "pk_test_" + strings.Repeat("a", 24), "api-token"},
		{"Slack bot token", "xoxb-1234-5678-abcd", "api-token"},
		{"Slack user token", "xoxp-1234-5678-abcd", "api-token"},
		{"SendGrid", "SG.abc.xyz", "api-token"},
		{"Bearer token", "Bearer abc123xyz", "api-token"},

		// Hex keys (typical lengths for 128/160/256-bit keys)
		{"32 hex chars (128-bit)", strings.Repeat("a", 32), "api-token"},
		{"40 hex chars (SHA-1 size)", strings.Repeat("f", 40), "api-token"},
		{"64 hex chars (256-bit)", strings.Repeat("0", 64), "api-token"},
		{"31 hex chars (odd length)", strings.Repeat("a", 31), "generic"},

		// SSH / private keys
		{"OpenSSH", "-----BEGIN OPENSSH PRIVATE KEY-----\ndata\n-----END", "ssh-key"},
		{"RSA private", "-----BEGIN RSA PRIVATE KEY-----\ndata", "ssh-key"},
		{"EC private", "-----BEGIN EC PRIVATE KEY-----\ndata", "ssh-key"},
		{"Generic PKCS#8", "-----BEGIN PRIVATE KEY-----\ndata", "ssh-key"},
		{"DSA private", "-----BEGIN DSA PRIVATE KEY-----\ndata", "ssh-key"},
		{"Encrypted private", "-----BEGIN ENCRYPTED PRIVATE KEY-----\ndata", "ssh-key"},

		// Certificates
		{"X.509 cert", "-----BEGIN CERTIFICATE-----\ndata", "certificate"},
		{"Trusted cert", "-----BEGIN TRUSTED CERTIFICATE-----\ndata", "certificate"},

		// Connection strings
		{"Postgres", "postgres://user:pass@host:5432/db", "connection-string"},
		{"PostgreSQL alt", "postgresql://user:pass@host/db", "connection-string"},
		{"MongoDB", "mongodb://user:pass@host/db", "connection-string"},
		{"MongoDB SRV", "mongodb+srv://user:pass@cluster/db", "connection-string"},
		{"MySQL", "mysql://user:pass@host/db", "connection-string"},
		{"Redis", "redis://user:pass@host:6379", "connection-string"},
		{"Redis TLS", "rediss://user:pass@host:6380", "connection-string"},
		{"AMQP", "amqp://user:pass@rabbit", "connection-string"},
		{"SQL Server", "sqlserver://user:pass@host", "connection-string"},

		// JWTs — must match strict 3-segment format
		{"Valid JWT", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456_ghi789-jkl", "jwt"},
		{"Not a JWT (eyJ prefix only)", "eyJabc", "generic"},
		{"Not a JWT (only 2 segments)", "eyJabc.def", "generic"},

		// Edge cases / false-positive protection
		{"Plain word", "password", "generic"},
		{"Empty string", "", "generic"},
		{"URL (http)", "https://example.com/path", "generic"},
		{"Email address", "user@example.com", "generic"},
		{"UUID", "a1b2c3d4-e5f6-7890-abcd-ef1234567890", "generic"},

		// Whitespace tolerance
		{"Trimmed leading space", "  ghp_" + strings.Repeat("a", 36), "api-token"},
		{"Trimmed trailing newline", "ghp_" + strings.Repeat("a", 36) + "\n", "api-token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectSecretType(tt.value)
			if got != tt.want {
				t.Errorf("DetectSecretType(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

// TestDetectSecretTypeFalsePositives ensures benign strings don't get misclassified.
// This is security-relevant: a false positive could cause a user to think they
// have a secret when they don't, leading to inappropriate storage or policy.
func TestDetectSecretTypeFalsePositives(t *testing.T) {
	benign := []string{
		"hello world",
		"log_level=info",
		"MAX_RETRIES=3",
		"true",
		"false",
		"null",
		"2026-04-15T10:30:00Z",
		"192.168.1.1",
		"localhost:8080",
	}
	for _, v := range benign {
		t.Run(v, func(t *testing.T) {
			got := DetectSecretType(v)
			if got != "generic" {
				t.Errorf("DetectSecretType(%q) = %q, want generic (benign strings should not be classified as secrets)", v, got)
			}
		})
	}
}

func TestIsHexString(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"abc123", true},
		{"ABC123", true},
		{"deadbeef", true},
		{"0123456789abcdef", true},
		{"0123456789ABCDEF", true},
		{"", false},
		{"xyz", false},
		{"abc-123", false},
		{"abc 123", false},
		{"0x1234", false}, // x is not hex
	}
	for _, tt := range tests {
		if got := isHexString(tt.s); got != tt.want {
			t.Errorf("isHexString(%q) = %v, want %v", tt.s, got, tt.want)
		}
	}
}
