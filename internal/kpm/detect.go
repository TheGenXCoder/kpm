package kpm

import (
	"regexp"
	"strings"
)

// Pre-compiled regex patterns for expensive checks.
var (
	// AWS: AKIA followed by 16 uppercase alphanumeric.
	awsAccessKeyRe = regexp.MustCompile(`^AKIA[0-9A-Z]{16}$`)
	// Stripe: sk_live_ or sk_test_ followed by alphanumeric.
	stripeKeyRe = regexp.MustCompile(`^(sk|pk|rk)_(live|test)_[A-Za-z0-9]{16,}$`)
	// Slack: xoxp/xoxb/xoxa/xoxs followed by dashes and alphanumeric.
	slackTokenRe = regexp.MustCompile(`^xox[apbsr]-[0-9A-Za-z-]{10,}$`)
	// GitHub: ghp/gho/ghs/ghu/ghr followed by alphanumeric.
	githubTokenRe = regexp.MustCompile(`^gh[pousr]_[A-Za-z0-9]{36,}$`)
	// JWT: three base64url segments separated by periods.
	jwtRe = regexp.MustCompile(`^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)
)

// DetectSecretType guesses the secret type from value content.
//
// Detection is conservative: returns "generic" when no pattern matches
// strongly. Never returns false-positive for ambiguous content.
//
// Recognized types:
//   - api-token: API keys/bearer tokens from major providers
//   - ssh-key: SSH private keys (OpenSSH, RSA, EC, PKCS#8)
//   - certificate: X.509 certificates
//   - connection-string: database URIs with credentials
//   - jwt: JSON Web Tokens
//   - generic: anything else
func DetectSecretType(value string) string {
	v := strings.TrimSpace(value)

	// Private key material — highest specificity, check first.
	if strings.Contains(v, "-----BEGIN OPENSSH PRIVATE KEY-----") ||
		strings.Contains(v, "-----BEGIN RSA PRIVATE KEY-----") ||
		strings.Contains(v, "-----BEGIN EC PRIVATE KEY-----") ||
		strings.Contains(v, "-----BEGIN PRIVATE KEY-----") ||
		strings.Contains(v, "-----BEGIN DSA PRIVATE KEY-----") ||
		strings.Contains(v, "-----BEGIN ENCRYPTED PRIVATE KEY-----") {
		return "ssh-key"
	}

	// X.509 certificates.
	if strings.Contains(v, "-----BEGIN CERTIFICATE-----") ||
		strings.Contains(v, "-----BEGIN TRUSTED CERTIFICATE-----") {
		return "certificate"
	}

	// Connection strings (before API tokens — some DBs use sk- internally).
	connPrefixes := []string{
		"postgres://", "postgresql://",
		"mongodb://", "mongodb+srv://",
		"mysql://", "mysql+ssl://",
		"redis://", "rediss://",
		"amqp://", "amqps://",
		"sqlserver://", "mssql://",
		"oracle://",
		"clickhouse://",
	}
	for _, p := range connPrefixes {
		if strings.HasPrefix(v, p) {
			return "connection-string"
		}
	}

	// JWT: 3 base64url segments. More strict than just "eyJ" prefix.
	if jwtRe.MatchString(v) {
		return "jwt"
	}

	// Provider-specific API token patterns (regex-validated).
	if githubTokenRe.MatchString(v) {
		return "api-token"
	}
	if stripeKeyRe.MatchString(v) {
		return "api-token"
	}
	if slackTokenRe.MatchString(v) {
		return "api-token"
	}
	if awsAccessKeyRe.MatchString(v) {
		return "api-token"
	}

	// Weaker prefix patterns (matched last to prevent false positives).
	apiPrefixes := []string{
		"sk-",       // OpenAI, Anthropic, many AI providers
		"sk_test_",  // Stripe test (partial match covered above)
		"sk_live_",  // Stripe live
		"pk_test_",  // Stripe publishable
		"pk_live_",
		"rk_test_",  // Stripe restricted
		"rk_live_",
		"sg-",       // SendGrid
		"SG.",       // SendGrid newer format
		"Bearer ",   // Generic bearer tokens
		"token_",
		"key-",
		"api_",
	}
	for _, p := range apiPrefixes {
		if strings.HasPrefix(v, p) {
			return "api-token"
		}
	}

	// Hex-encoded keys (typically 32 or 64 hex chars = 128 or 256 bit keys).
	if isHexString(v) && (len(v) == 32 || len(v) == 40 || len(v) == 64) {
		return "api-token"
	}

	return "generic"
}

// isHexString reports whether s contains only hex characters.
func isHexString(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}
