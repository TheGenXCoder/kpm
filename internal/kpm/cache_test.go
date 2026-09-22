package kpm

import (
	"os"
	"testing"
)

func testCache(t *testing.T) *SecretCache {
	t.Helper()
	return &SecretCache{dir: t.TempDir()}
}

func TestSecretCacheRoundTrip(t *testing.T) {
	c := testCache(t)
	if err := c.Put("mail/box", []byte("v2")); err != nil {
		t.Fatal(err)
	}
	got, ok := c.Get("mail/box", 900)
	if !ok || string(got) != "v2" {
		t.Fatalf("Get = %q ok=%v", got, ok)
	}
	info, err := os.Stat(c.fileKey("mail/box"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("mode = %o, want 0600", info.Mode().Perm())
	}
}

func TestSecretCacheExpiredEntryDeleted(t *testing.T) {
	c := testCache(t)
	path := c.fileKey("mail/box")
	if err := os.WriteFile(path, []byte(`{"fetched_at":1,"value":"b2xk"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Get("mail/box", 900); ok {
		t.Fatal("expired entry was served")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expired cache file still present: %v", err)
	}
}

func TestSecretCacheDisabledDeletesEntry(t *testing.T) {
	c := testCache(t)
	if err := c.Put("mail/box", []byte("v")); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Get("mail/box", 0); ok {
		t.Fatal("disabled cache served a value")
	}
	if _, err := os.Stat(c.fileKey("mail/box")); !os.IsNotExist(err) {
		t.Fatalf("disabled cache left a file: %v", err)
	}
}

func TestSecretCacheSweep(t *testing.T) {
	c := testCache(t)
	if err := c.Put("fresh/one", []byte("a")); err != nil {
		t.Fatal(err)
	}
	old := c.fileKey("old/one")
	if err := os.WriteFile(old, []byte(`{"fetched_at":1,"value":"Yg=="}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := c.Sweep(900); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Get("fresh/one", 900); !ok {
		t.Fatal("fresh entry was swept")
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("expired entry survived sweep")
	}
	if err := c.Sweep(0); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(c.fileKey("fresh/one")); !os.IsNotExist(err) {
		t.Fatal("ttl 0 left a cache file")
	}
}

func TestSecretCacheInvalidateIgnoresMissing(t *testing.T) {
	c := testCache(t)
	if err := c.Invalidate("no/such"); err != nil {
		t.Fatal(err)
	}
}

func TestCacheRefsForPath(t *testing.T) {
	refs := CacheRefsForPath(nil, "mail/box")
	if len(refs) != 1 || refs[0] != "mail/box" {
		t.Fatalf("nil config refs = %v", refs)
	}
	cfg := &Config{
		DefaultBackend: "mstr",
		Backends: map[string]*BackendConfig{
			"mstr": {Server: "https://mstr.example"},
			"uta":  {Server: "https://uta.example"},
		},
	}
	got := map[string]bool{}
	for _, ref := range CacheRefsForPath(cfg, "mail/box") {
		got[ref] = true
	}
	for _, want := range []string{"mail/box", "@mstr/mail/box", "@uta/mail/box"} {
		if !got[want] {
			t.Errorf("missing cache ref %s in %v", want, got)
		}
	}
	if len(got) != 3 {
		t.Errorf("refs = %v, want 3", got)
	}
}
