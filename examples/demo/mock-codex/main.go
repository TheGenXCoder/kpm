// mock-codex: A tiny demo app that simulates an AI coding tool.
// It reads API keys from environment variables — just like the real tools do.
//
// Usage: mock-codex "your prompt here"
package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	prompt := "explain this code"
	if len(os.Args) > 1 {
		prompt = strings.Join(os.Args[1:], " ")
	}

	fmt.Println("mock-codex v0.1 — AI coding assistant (demo)")
	fmt.Println()

	// Check for API keys — this is exactly what real tools do
	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	openaiKey := os.Getenv("OPENAI_API_KEY")

	if apiKey == "" && openaiKey == "" {
		fmt.Println("ERROR: No API key found.")
		fmt.Println("Set ANTHROPIC_API_KEY or OPENAI_API_KEY in your environment.")
		os.Exit(1)
	}

	// Show which provider we're using (mask the key — like a real tool would log)
	if apiKey != "" {
		masked := maskKey(apiKey)
		fmt.Printf("Provider: Anthropic (key: %s)\n", masked)
	} else {
		masked := maskKey(openaiKey)
		fmt.Printf("Provider: OpenAI (key: %s)\n", masked)
	}

	// Detect if the key is still ciphertext (KPM wasn't used to decrypt)
	if strings.HasPrefix(apiKey, "ENC[kpm:") || strings.HasPrefix(openaiKey, "ENC[kpm:") {
		fmt.Println()
		fmt.Println("WARNING: API key is still encrypted (ENC[kpm:...]).")
		fmt.Println("Run this tool with: kpm run -- mock-codex \"your prompt\"")
		os.Exit(1)
	}

	fmt.Printf("Prompt: %q\n", prompt)
	fmt.Println()
	fmt.Println("Connecting to API...")
	fmt.Println("Response: The code looks good. Ship it.")
	fmt.Println()
	fmt.Println("---")
	fmt.Println("(This is a mock. In production, this would call the real API.)")
}

func maskKey(key string) string {
	if len(key) <= 8 {
		return "****"
	}
	return key[:4] + "..." + key[len(key)-4:]
}
