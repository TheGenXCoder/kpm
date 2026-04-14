package kpm

import (
	"bytes"
	"strings"
	"testing"
)

func TestNewSessionKey(t *testing.T) {
	sk, err := NewSessionKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(sk) != 32 {
		t.Fatalf("session key length = %d, want 32", len(sk))
	}
	defer ZeroBytes(sk)

	sk2, _ := NewSessionKey()
	defer ZeroBytes(sk2)
	if bytes.Equal(sk, sk2) {
		t.Error("two session keys should not be equal")
	}
}

func TestEncryptDecryptLocal(t *testing.T) {
	sk, err := NewSessionKey()
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroBytes(sk)

	plaintext := []byte("super-secret-api-key")
	ciphertext, err := EncryptLocal(sk, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(ciphertext, plaintext) {
		t.Error("ciphertext equals plaintext")
	}

	recovered, err := DecryptLocal(sk, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroBytes(recovered)

	if !bytes.Equal(recovered, plaintext) {
		t.Errorf("recovered = %q, want %q", recovered, plaintext)
	}
}

func TestEncryptLocalProducesBlobFormat(t *testing.T) {
	sk, _ := NewSessionKey()
	defer ZeroBytes(sk)

	ct, err := EncryptLocal(sk, []byte("test"))
	if err != nil {
		t.Fatal(err)
	}

	blob := FormatCiphertextBlob("sess123", ct)
	if !strings.HasPrefix(blob, "ENC[kpm:") {
		t.Errorf("blob format wrong: %s", blob)
	}

	sid, raw, err := ParseCiphertextBlob(blob)
	if err != nil {
		t.Fatal(err)
	}
	if sid != "sess123" {
		t.Errorf("session ID = %q, want sess123", sid)
	}
	if !bytes.Equal(raw, ct) {
		t.Error("parsed ciphertext doesn't match original")
	}
}

func TestDecryptLocalWrongKey(t *testing.T) {
	sk1, _ := NewSessionKey()
	sk2, _ := NewSessionKey()
	defer ZeroBytes(sk1)
	defer ZeroBytes(sk2)

	ct, _ := EncryptLocal(sk1, []byte("secret"))
	_, err := DecryptLocal(sk2, ct)
	if err == nil {
		t.Error("expected error decrypting with wrong key")
	}
}
