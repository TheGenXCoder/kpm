package scan

import "regexp"

// namePatternsHighConfidence are glob-like suffixes/exact names that reliably
// indicate a secret-holding variable.
var namePatternsHighConfidence = []string{
	"*_KEY",
	"*_TOKEN",
	"*_SECRET",
	"*_PASSWORD",
	"*_PASSWD",
	"*_CREDENTIALS",
	"*_API_KEY",
	"*_ACCESS_KEY",
	"AWS_SECRET_ACCESS_KEY",
	"AWS_SESSION_TOKEN",
}

// namePatternsParanoid is added on top of high-confidence in paranoid mode.
var namePatternsParanoid = []string{
	"*PASS*",
	"*AUTH*",
	"*PRIVATE*",
	"DATABASE_URL",
}

// nameDenyList contains names that look secret-ish but are known-safe.
// These are NEVER flagged by the name detector.
var nameDenyList = map[string]bool{
	"SSH_AUTH_SOCK": true,
	"GPG_TTY":       true,
	"LESSKEY":       true,
	"HISTFILE":      true,
	"PATH":          true,
}

// valuePattern pairs a compiled regex with a stable detector ID.
type valuePattern struct {
	id    string
	regex *regexp.Regexp
}

// valuePatternsHighConfidence fires on well-known vendor formats.
var valuePatternsHighConfidence = []valuePattern{
	{"value:openai-proj", regexp.MustCompile(`\bsk-proj-[A-Za-z0-9_-]{20,}\b`)},
	{"value:openai", regexp.MustCompile(`\bsk-[A-Za-z0-9]{20,}\b`)},
	{"value:anthropic", regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}\b`)},
	{"value:github", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`)},
	{"value:slack", regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`)},
	{"value:aws-access-key", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{"value:jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.`)},
	{"value:pem-private-key", regexp.MustCompile(`-----BEGIN [A-Z ]+PRIVATE KEY-----`)},
}

// valuePatternsParanoid fires on URL-embedded credentials.
var valuePatternsParanoid = []valuePattern{
	{"value:url-credentials", regexp.MustCompile(`://[^:/\s]+:[^@/\s]+@`)},
}

// knownPrefixesForRedaction maps a detector ID to the prefix the redactor
// should preserve when formatting. (Kept for documentation; redact.go uses
// its own ordered list.)
var knownPrefixesForRedaction = map[string]string{
	"value:openai-proj":     "sk-proj-",
	"value:openai":          "sk-",
	"value:anthropic":       "sk-ant-",
	"value:github":          "gh",
	"value:slack":           "xox",
	"value:aws-access-key":  "AKIA",
	"value:jwt":             "eyJ",
	"value:pem-private-key": "-----BEGIN",
}
