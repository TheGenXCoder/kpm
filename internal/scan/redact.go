package scan

import (
	"fmt"
	"strings"
)

// Redact returns a safe preview of a secret value. Rules:
//  1. Known prefix (sk-proj-, ghp_, AKIA, etc.): preserve up to 8 chars of
//     prefix, then ••••, then last 4 chars, then (N chars).
//  2. Unknown prefix, value >= 12 chars: •••• + last 4 + (N chars).
//  3. Value < 12 chars: •••• + (N chars). No tail revealed.
//  4. Empty value: •••• (0 chars).
//
// INVARIANT: the output must never contain the full input value as a substring.
func Redact(value string) string {
	if value == "" {
		return "•••• (0 chars)"
	}

	length := len(value)

	if prefix, ok := matchKnownPrefix(value); ok && length >= 12 {
		tail := value[length-4:]
		return fmt.Sprintf("%s••••%s (%d chars)", prefix, tail, length)
	}

	if length < 12 {
		return fmt.Sprintf("•••• (%d chars)", length)
	}

	tail := value[length-4:]
	return fmt.Sprintf("••••%s (%d chars)", tail, length)
}

// matchKnownPrefix returns the prefix string to preserve, up to 8 chars.
// Longest/most-specific prefixes checked first so "sk-proj-" wins over "sk-".
func matchKnownPrefix(value string) (string, bool) {
	prefixes := []string{
		"-----BEGIN ",
		"sk-proj-",
		"sk-ant-",
		"ghp_", "ghs_", "gho_", "ghu_", "ghr_",
		"xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-",
		"AKIA",
		"eyJ",
		"sk-",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(value, p) {
			display := p
			if len(display) > 8 {
				display = display[:8]
			}
			return display, true
		}
	}
	return "", false
}
