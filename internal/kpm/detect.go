package kpm

import "strings"

// DetectSecretType guesses the type from value content.
func DetectSecretType(value string) string {
	apiPrefixes := []string{"sk-", "pk_", "ghp_", "gho_", "ghs_", "AKIA", "sg-", "xoxb-", "xoxp-", "Bearer "}
	for _, p := range apiPrefixes {
		if strings.HasPrefix(value, p) {
			return "api-token"
		}
	}

	if strings.Contains(value, "-----BEGIN OPENSSH PRIVATE KEY-----") ||
		strings.Contains(value, "-----BEGIN RSA PRIVATE KEY-----") ||
		strings.Contains(value, "-----BEGIN EC PRIVATE KEY-----") ||
		strings.Contains(value, "-----BEGIN PRIVATE KEY-----") {
		return "ssh-key"
	}

	if strings.Contains(value, "-----BEGIN CERTIFICATE-----") {
		return "certificate"
	}

	connPrefixes := []string{"postgres://", "postgresql://", "mongodb://", "mysql://", "redis://", "amqp://"}
	for _, p := range connPrefixes {
		if strings.HasPrefix(value, p) {
			return "connection-string"
		}
	}

	if strings.HasPrefix(value, "eyJ") && strings.Count(value, ".") >= 2 && len(value) > 40 {
		return "jwt"
	}

	return "generic"
}
