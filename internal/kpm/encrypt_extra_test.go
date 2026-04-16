package kpm

import (
	"strings"
	"testing"
)

// --- EncryptLocal error paths ---

func TestEncryptLocalWrongKeySize(t *testing.T) {
	// AES requires 16, 24, or 32-byte key. A 10-byte key must error.
	badKey := make([]byte, 10)
	_, err := EncryptLocal(badKey, []byte("hello"))
	if err == nil {
		t.Fatal("expected error for wrong key size")
	}
}

func TestEncryptLocalEmptyPlaintext(t *testing.T) {
	key, err := NewSessionKey()
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroBytes(key)

	ct, err := EncryptLocal(key, []byte{})
	if err != nil {
		t.Fatal(err)
	}
	// Must decrypt back to empty
	plain, err := DecryptLocal(key, ct)
	if err != nil {
		t.Fatal(err)
	}
	if len(plain) != 0 {
		t.Errorf("expected empty plaintext, got %d bytes", len(plain))
	}
}

// --- DecryptLocal error paths ---

func TestDecryptLocalWrongKeySizeError(t *testing.T) {
	badKey := make([]byte, 7)
	_, err := DecryptLocal(badKey, []byte("some ciphertext longer than nonce"))
	if err == nil {
		t.Fatal("expected error for wrong key size")
	}
}

func TestDecryptLocalTruncatedCiphertext(t *testing.T) {
	key, _ := NewSessionKey()
	defer ZeroBytes(key)

	// Ciphertext shorter than GCM nonce size (12 bytes) must error.
	short := make([]byte, 5)
	_, err := DecryptLocal(key, short)
	if err == nil {
		t.Fatal("expected error for truncated ciphertext")
	}
	if !strings.Contains(err.Error(), "too short") {
		t.Errorf("expected 'too short' error, got: %v", err)
	}
}

func TestDecryptLocalTamperedCiphertext(t *testing.T) {
	key, _ := NewSessionKey()
	defer ZeroBytes(key)

	ct, _ := EncryptLocal(key, []byte("tamper me"))
	// Flip a bit in the ciphertext body (after nonce)
	ct[len(ct)-1] ^= 0xFF
	_, err := DecryptLocal(key, ct)
	if err == nil {
		t.Fatal("expected authentication error for tampered ciphertext")
	}
}

func TestDecryptLocalAuthError(t *testing.T) {
	key1, _ := NewSessionKey()
	key2, _ := NewSessionKey()
	defer ZeroBytes(key1)
	defer ZeroBytes(key2)

	ct, _ := EncryptLocal(key1, []byte("secret-data"))
	_, err := DecryptLocal(key2, ct)
	if err == nil {
		t.Fatal("expected auth error when decrypting with wrong key")
	}
}

// --- NewSessionKey entropy ---

func TestNewSessionKeyLength(t *testing.T) {
	key, err := NewSessionKey()
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroBytes(key)
	if len(key) != 32 {
		t.Errorf("key length = %d, want 32", len(key))
	}
}

func TestNewSessionKeyUniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 5; i++ {
		key, err := NewSessionKey()
		if err != nil {
			t.Fatal(err)
		}
		s := string(key)
		if seen[s] {
			t.Fatal("duplicate session key generated")
		}
		seen[s] = true
		ZeroBytes(key)
	}
}

// --- FormatCiphertextBlob / ParseCiphertextBlob round-trip ---

func TestBlobRoundTrip(t *testing.T) {
	key, _ := NewSessionKey()
	defer ZeroBytes(key)

	plain := []byte("round-trip test payload")
	ct, _ := EncryptLocal(key, plain)

	blob := FormatCiphertextBlob("session-abc123", ct)
	sid, parsed, err := ParseCiphertextBlob(blob)
	if err != nil {
		t.Fatal(err)
	}
	if sid != "session-abc123" {
		t.Errorf("sessionID = %q, want session-abc123", sid)
	}
	if string(parsed) != string(ct) {
		t.Error("round-trip ciphertext mismatch")
	}

	// Full decrypt round-trip
	recovered, err := DecryptLocal(key, parsed)
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroBytes(recovered)
	if string(recovered) != string(plain) {
		t.Errorf("decrypted = %q, want %q", recovered, plain)
	}
}

// --- ParseCiphertextBlob malformed inputs ---

func TestParseCiphertextBlobMissingPrefix(t *testing.T) {
	_, _, err := ParseCiphertextBlob("NOTENC[kpm:sess:abc]")
	if err == nil {
		t.Fatal("expected error for missing ENC[kpm: prefix")
	}
}

func TestParseCiphertextBlobMissingSuffix(t *testing.T) {
	_, _, err := ParseCiphertextBlob("ENC[kpm:sess:abc")
	if err == nil {
		t.Fatal("expected error for missing closing ]")
	}
}

func TestParseCiphertextBlobEmptyString(t *testing.T) {
	_, _, err := ParseCiphertextBlob("")
	if err == nil {
		t.Fatal("expected error for empty string")
	}
}

func TestParseCiphertextBlobMissingSessionID(t *testing.T) {
	// No colon separator after prefix — SplitN will produce 1 part
	// Manually craft: ENC[kpm:noseparatorhere]
	_, _, err := ParseCiphertextBlob("ENC[kpm:noseparatorhere]")
	if err == nil {
		t.Fatal("expected error for missing session:ciphertext separator")
	}
}

func TestParseCiphertextBlobBadBase64(t *testing.T) {
	// Valid structure but ciphertext is not base64
	_, _, err := ParseCiphertextBlob("ENC[kpm:sess123:!!!not-base64!!!]")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestParseCiphertextBlobEmptySessionID(t *testing.T) {
	// session ID can be empty string with valid base64 ciphertext
	import64 := "aGVsbG8=" // base64("hello")
	blob := "ENC[kpm::" + import64 + "]"
	sid, ct, err := ParseCiphertextBlob(blob)
	if err != nil {
		t.Fatal(err)
	}
	if sid != "" {
		t.Errorf("expected empty session ID, got %q", sid)
	}
	if string(ct) != "hello" {
		t.Errorf("expected 'hello', got %q", string(ct))
	}
}
