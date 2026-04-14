package kpm

import (
	"bytes"
	"testing"
)

func TestFormatDotenv(t *testing.T) {
	entries := []ResolvedEntry{
		{EnvKey: "APP_NAME", PlainValue: []byte("my-service")},
		{EnvKey: "DB_PASSWORD", PlainValue: []byte("s3cret"), IsKMSRef: true, Source: "agentkms"},
	}

	var buf bytes.Buffer
	if err := FormatDotenv(&buf, entries); err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	if !bytes.Contains([]byte(out), []byte("# WARNING")) {
		t.Error("missing warning header")
	}
	if !bytes.Contains([]byte(out), []byte("APP_NAME=my-service")) {
		t.Error("missing APP_NAME")
	}
	if !bytes.Contains([]byte(out), []byte("DB_PASSWORD=s3cret")) {
		t.Error("missing DB_PASSWORD")
	}
}

func TestFormatShell(t *testing.T) {
	entries := []ResolvedEntry{
		{EnvKey: "DB_PASSWORD", PlainValue: []byte("s3cret")},
	}

	var buf bytes.Buffer
	if err := FormatShell(&buf, entries); err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	if !bytes.Contains([]byte(out), []byte("export DB_PASSWORD='s3cret'")) {
		t.Errorf("unexpected shell output: %s", out)
	}
}

func TestFormatJSON(t *testing.T) {
	entries := []ResolvedEntry{
		{EnvKey: "APP", PlainValue: []byte("test")},
		{EnvKey: "KEY", PlainValue: []byte("val")},
	}

	var buf bytes.Buffer
	if err := FormatJSON(&buf, entries); err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	if !bytes.Contains([]byte(out), []byte(`"APP"`)) {
		t.Errorf("missing APP in JSON: %s", out)
	}
}
