package kpm

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"
)

func TestScanManagedSecrets(t *testing.T) {
	sk, err := NewSessionKey()
	if err != nil {
		t.Fatalf("NewSessionKey: %v", err)
	}
	defer ZeroBytes(sk)

	ct, err := EncryptLocal(sk, []byte("secret-val"))
	if err != nil {
		t.Fatalf("EncryptLocal: %v", err)
	}
	blob := FormatCiphertextBlob("show-test", ct)

	os.Setenv("KPM_TEST_SHOW", blob)
	os.Setenv("KPM_PLAIN_VAR", "not-encrypted")
	defer os.Unsetenv("KPM_TEST_SHOW")
	defer os.Unsetenv("KPM_PLAIN_VAR")

	secrets, sid := ScanManagedSecrets()
	if sid != "show-test" {
		t.Errorf("session = %q, want show-test", sid)
	}

	found := false
	for _, s := range secrets {
		if s.Name == "KPM_TEST_SHOW" {
			found = true
			if !s.Encrypted {
				t.Error("should be encrypted")
			}
		}
		if s.Name == "KPM_PLAIN_VAR" {
			t.Error("plain var should not appear in managed secrets")
		}
	}
	if !found {
		t.Error("KPM_TEST_SHOW not found")
	}
}

func TestScanManagedSecrets_BlobPreviewTruncated(t *testing.T) {
	sk, _ := NewSessionKey()
	defer ZeroBytes(sk)

	ct, _ := EncryptLocal(sk, []byte("a-longer-secret-value-that-produces-a-big-blob"))
	blob := FormatCiphertextBlob("preview-test", ct)

	os.Setenv("KPM_PREVIEW_TEST", blob)
	defer os.Unsetenv("KPM_PREVIEW_TEST")

	secrets, _ := ScanManagedSecrets()
	for _, s := range secrets {
		if s.Name == "KPM_PREVIEW_TEST" {
			if len(blob) > 40 && !strings.HasSuffix(s.BlobPreview, "...") {
				t.Errorf("BlobPreview should be truncated with '...', got: %q", s.BlobPreview)
			}
			if len(s.BlobPreview) > 43 { // 40 chars + "..."
				t.Errorf("BlobPreview too long: %d chars", len(s.BlobPreview))
			}
			return
		}
	}
	t.Error("KPM_PREVIEW_TEST not found in scan")
}

func TestPrintShowList(t *testing.T) {
	secrets := []ManagedSecret{
		{Name: "API_KEY", SessionID: "s123", Encrypted: true, BlobPreview: "ENC[kpm:s123:abc...]"},
		{Name: "DB_PASS", SessionID: "s123", Encrypted: true, BlobPreview: "ENC[kpm:s123:def...]"},
	}

	var buf bytes.Buffer
	PrintShow(&buf, secrets, "s123", 4*time.Minute+32*time.Second, "")

	out := buf.String()
	if !strings.Contains(out, "KPM Session: s123") {
		t.Error("missing session header")
	}
	if !strings.Contains(out, "API_KEY") {
		t.Error("missing API_KEY")
	}
	if !strings.Contains(out, "DB_PASS") {
		t.Error("missing DB_PASS")
	}
	if !strings.Contains(out, "2 secrets managed") {
		t.Errorf("missing count, got:\n%s", out)
	}
	if !strings.Contains(out, "4m32s") {
		t.Errorf("missing TTL, got:\n%s", out)
	}
	if !strings.Contains(out, "● encrypted") {
		t.Error("missing encrypted marker")
	}
}

func TestPrintShowSingle(t *testing.T) {
	secrets := []ManagedSecret{
		{Name: "API_KEY", SessionID: "s123", Encrypted: true, BlobPreview: "ENC[kpm:s123:abc...]"},
	}

	var buf bytes.Buffer
	PrintShow(&buf, secrets, "s123", 3*time.Minute, "API_KEY")

	out := buf.String()
	if !strings.Contains(out, "kpm run") {
		t.Error("should suggest kpm run for decryption")
	}
	if !strings.Contains(out, "API_KEY") {
		t.Error("missing var name")
	}
	if !strings.Contains(out, "s123") {
		t.Error("missing session ID")
	}
	if !strings.Contains(out, "3m00s") {
		t.Errorf("missing TTL, got:\n%s", out)
	}
}

func TestPrintShowSingleNotFound(t *testing.T) {
	secrets := []ManagedSecret{
		{Name: "API_KEY", SessionID: "s123", Encrypted: true, BlobPreview: "ENC[kpm:s123:abc...]"},
	}

	var buf bytes.Buffer
	PrintShow(&buf, secrets, "s123", 0, "MISSING_VAR")

	out := buf.String()
	if !strings.Contains(out, "not a KPM-managed secret") {
		t.Errorf("expected not-found message, got:\n%s", out)
	}
}

func TestPrintShowEmpty(t *testing.T) {
	var buf bytes.Buffer
	PrintShow(&buf, nil, "", 0, "")

	out := buf.String()
	if !strings.Contains(out, "No KPM-managed secrets") {
		t.Error("should show empty message")
	}
	if !strings.Contains(out, "kpm env") {
		t.Error("should suggest kpm env command")
	}
}

func TestFormatShowDuration(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{4*time.Minute + 32*time.Second, "4m32s"},
		{1*time.Minute + 0*time.Second, "1m00s"},
		{45 * time.Second, "45s"},
		{0, "0s"},
	}
	for _, tc := range cases {
		got := formatShowDuration(tc.d)
		if got != tc.want {
			t.Errorf("formatShowDuration(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}
