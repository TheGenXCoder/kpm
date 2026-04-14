package kpm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
)

// NewSessionKey generates a random 32-byte AES-256 key.
func NewSessionKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate session key: %w", err)
	}
	return key, nil
}

// EncryptLocal encrypts plaintext with AES-256-GCM using the given key.
// Returns nonce || ciphertext (nonce is 12 bytes prepended).
func EncryptLocal(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// DecryptLocal decrypts ciphertext (nonce || ciphertext) with AES-256-GCM.
func DecryptLocal(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}

// FormatCiphertextBlob wraps raw ciphertext in the KPM envelope format:
// ENC[kpm:<sessionID>:<base64-ciphertext>]
func FormatCiphertextBlob(sessionID string, ciphertext []byte) string {
	return fmt.Sprintf("ENC[kpm:%s:%s]", sessionID, base64.StdEncoding.EncodeToString(ciphertext))
}

// ParseCiphertextBlob extracts session ID and raw ciphertext from an ENC[kpm:...] blob.
func ParseCiphertextBlob(blob string) (sessionID string, ciphertext []byte, err error) {
	if !strings.HasPrefix(blob, "ENC[kpm:") || !strings.HasSuffix(blob, "]") {
		return "", nil, fmt.Errorf("invalid blob format: %q", blob)
	}
	inner := blob[8 : len(blob)-1]
	parts := strings.SplitN(inner, ":", 2)
	if len(parts) != 2 {
		return "", nil, fmt.Errorf("invalid blob: expected sessionID:ciphertext in %q", inner)
	}
	ct, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	return parts[0], ct, nil
}
