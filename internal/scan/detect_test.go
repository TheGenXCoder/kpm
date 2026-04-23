package scan

import "testing"

func TestNameDetector_HighConfidence_Hits(t *testing.T) {
	cases := []struct {
		name string
	}{
		{"OPENAI_API_KEY"},
		{"GITHUB_TOKEN"},
		{"DB_PASSWORD"},
		{"FOO_SECRET"},
		{"AWS_SECRET_ACCESS_KEY"},
		{"AWS_SESSION_TOKEN"},
		{"MY_CREDENTIALS"},
		{"openai_api_key"}, // case-insensitive
	}
	d := NewNameDetector(ModeDefault)
	for _, c := range cases {
		matched, id := d.Detect(c.name, "anyvalue")
		if !matched {
			t.Errorf("expected match for %q, got miss", c.name)
		}
		if id == "" {
			t.Errorf("expected non-empty detector id for %q", c.name)
		}
	}
}

func TestNameDetector_HighConfidence_Misses(t *testing.T) {
	cases := []string{
		"PATH",
		"HOME",
		"SSH_AUTH_SOCK", // deny-listed
		"SHELL",
		"USER",
		"TERM",
	}
	d := NewNameDetector(ModeDefault)
	for _, name := range cases {
		matched, _ := d.Detect(name, "anyvalue")
		if matched {
			t.Errorf("expected miss for %q, got match", name)
		}
	}
}

func TestNameDetector_Paranoid_AddsMore(t *testing.T) {
	cases := []string{
		"MY_AUTH_BEARER",
		"PASS_THROUGH",
		"PRIVATE_FOO",
		"DATABASE_URL",
	}
	defaultDet := NewNameDetector(ModeDefault)
	paranoidDet := NewNameDetector(ModeParanoid)
	for _, name := range cases {
		def, _ := defaultDet.Detect(name, "x")
		par, _ := paranoidDet.Detect(name, "x")
		if def {
			t.Errorf("high-confidence should not match %q", name)
		}
		if !par {
			t.Errorf("paranoid should match %q", name)
		}
	}
}

func TestValueDetector_Hits(t *testing.T) {
	cases := []struct {
		value  string
		wantID string
	}{
		{"sk-proj-abcdefghijklmnopqrstuvwx", "value:openai-proj"},
		{"sk-abcdefghijklmnopqrstuvwx", "value:openai"},
		{"sk-ant-abcdefghijklmnopqrstuvwx", "value:anthropic"},
		{"ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "value:github"},
		{"xoxb-1234567890-abcdefg", "value:slack"},
		{"AKIAIOSFODNN7EXAMPLE", "value:aws-access-key"},
		{"eyJhbGciOiJIUzI1NiJ9.payload", "value:jwt"},
		{"-----BEGIN RSA PRIVATE KEY-----", "value:pem-private-key"},
	}
	d := NewValueDetector(ModeDefault)
	for _, c := range cases {
		matched, id := d.Detect("anyname", c.value)
		if !matched {
			t.Errorf("expected match for %q", c.value)
		}
		if id != c.wantID {
			t.Errorf("value=%q: got id=%q want %q", c.value, id, c.wantID)
		}
	}
}

func TestValueDetector_Misses(t *testing.T) {
	cases := []string{
		"hello world",
		"just some text",
		"not-a-secret",
		"sk-", // too short to match OpenAI
	}
	d := NewValueDetector(ModeDefault)
	for _, v := range cases {
		matched, _ := d.Detect("anyname", v)
		if matched {
			t.Errorf("expected miss for %q", v)
		}
	}
}

func TestValueDetector_Paranoid_URLCredentials(t *testing.T) {
	v := "postgres://user:supersecret@localhost:5432/db"
	defaultDet := NewValueDetector(ModeDefault)
	paranoidDet := NewValueDetector(ModeParanoid)
	if m, _ := defaultDet.Detect("x", v); m {
		t.Errorf("high-confidence should not match URL creds")
	}
	if m, _ := paranoidDet.Detect("x", v); !m {
		t.Errorf("paranoid should match URL creds")
	}
}

func TestEntropyDetector_OnlyInParanoid(t *testing.T) {
	// A 40-char random-looking string has high entropy.
	highEntropy := "Xq9kLmNpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUv"
	defaultDet := NewEntropyDetector(ModeDefault)
	paranoidDet := NewEntropyDetector(ModeParanoid)
	if m, _ := defaultDet.Detect("x", highEntropy); m {
		t.Errorf("entropy detector must be a no-op in default mode")
	}
	if m, _ := paranoidDet.Detect("x", highEntropy); !m {
		t.Errorf("paranoid entropy detector should match high-entropy strings")
	}
}

func TestEntropyDetector_LowEntropyValue_Miss(t *testing.T) {
	lowEntropy := "hello hello hello hello"
	d := NewEntropyDetector(ModeParanoid)
	if m, _ := d.Detect("x", lowEntropy); m {
		t.Errorf("low-entropy value should not match")
	}
}
