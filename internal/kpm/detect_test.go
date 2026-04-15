package kpm

import "testing"

func TestDetectSecretType(t *testing.T) {
	tests := []struct {
		value string
		want  string
	}{
		{"sk-ant-oat01-xxx", "api-token"},
		{"ghp_1234567890abcdef", "api-token"},
		{"AKIAIOSFODNN7EXAMPLE", "api-token"},
		{"-----BEGIN OPENSSH PRIVATE KEY-----\nxxx", "ssh-key"},
		{"-----BEGIN CERTIFICATE-----\nxxx", "certificate"},
		{"postgres://user:pass@host/db", "connection-string"},
		{"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456ghi789", "jwt"},
		{"just-a-plain-value", "generic"},
	}
	for _, tt := range tests {
		label := tt.value
		if len(label) > 25 {
			label = label[:25] + "..."
		}
		t.Run(label, func(t *testing.T) {
			got := DetectSecretType(tt.value)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
