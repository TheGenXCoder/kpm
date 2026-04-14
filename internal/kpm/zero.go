// Package kpm implements the KPM local secrets CLI.
package kpm

// ZeroBytes overwrites b with zeros. Call in defer after using secret material.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ZeroMap zeros all values in a map[string][]byte.
func ZeroMap(m map[string][]byte) {
	for _, v := range m {
		ZeroBytes(v)
	}
}
