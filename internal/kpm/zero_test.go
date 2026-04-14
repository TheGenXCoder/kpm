package kpm

import (
	"bytes"
	"testing"
)

func TestZeroBytes(t *testing.T) {
	secret := []byte("super-secret-api-key")
	original := make([]byte, len(secret))
	copy(original, secret)

	ZeroBytes(secret)

	if bytes.Equal(secret, original) {
		t.Fatal("ZeroBytes did not overwrite the buffer")
	}
	for i, b := range secret {
		if b != 0 {
			t.Fatalf("byte %d is %d, want 0", i, b)
		}
	}
}

func TestZeroBytesNil(t *testing.T) {
	ZeroBytes(nil)
}

func TestZeroMap(t *testing.T) {
	m := map[string][]byte{
		"password": []byte("s3cret"),
		"token":    []byte("tok-abc"),
	}
	ZeroMap(m)
	for k, v := range m {
		for i, b := range v {
			if b != 0 {
				t.Fatalf("key %q byte %d is %d, want 0", k, i, b)
			}
		}
	}
}
