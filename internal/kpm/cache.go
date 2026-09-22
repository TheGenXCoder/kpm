package kpm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type cacheEntry struct {
	FetchedAt int64  `json:"fetched_at"`
	Value     []byte `json:"value"`
}

// SecretCache stores fetched secret values with TTL (0600 files under ~/.kpm/cache/).
type SecretCache struct {
	dir string
	mu  sync.Mutex
}

func NewSecretCache() (*SecretCache, error) {
	dir := filepath.Join(DataDir(), "cache")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	return &SecretCache{dir: dir}, nil
}

func (c *SecretCache) fileKey(ref string) string {
	safe := strings.NewReplacer("/", "_", ":", "_", "..", "_").Replace(ref)
	return filepath.Join(c.dir, safe+".json")
}

// Get returns a cached value if present and not expired.
// ttlSec <= 0 disables the cache: the entry is deleted and reported as a miss.
// Expired and unreadable entries are deleted rather than left on disk.
func (c *SecretCache) Get(ref string, ttlSec int) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	path := c.fileKey(ref)
	if ttlSec <= 0 {
		_ = os.Remove(path)
		return nil, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var e cacheEntry
	if json.Unmarshal(data, &e) != nil {
		_ = os.Remove(path)
		return nil, false
	}
	if time.Now().Unix()-e.FetchedAt > int64(ttlSec) {
		_ = os.Remove(path)
		return nil, false
	}
	out := make([]byte, len(e.Value))
	copy(out, e.Value)
	return out, true
}

// Sweep deletes cache files that must not be served.
// ttlSec <= 0 removes every cached file (cache disabled).
// ttlSec > 0 removes expired or unreadable entries and leaves fresh ones.
func (c *SecretCache) Sweep(ttlSec int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		path := filepath.Join(c.dir, ent.Name())
		if ttlSec <= 0 {
			_ = os.Remove(path)
			continue
		}
		if !strings.HasSuffix(ent.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var e cacheEntry
		if json.Unmarshal(data, &e) != nil || now-e.FetchedAt > int64(ttlSec) {
			_ = os.Remove(path)
		}
	}
	return nil
}

// Invalidate removes cache entries for the given refs. Missing files are not an error.
func (c *SecretCache) Invalidate(refs ...string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var first error
	for _, ref := range refs {
		if ref == "" {
			continue
		}
		if err := os.Remove(c.fileKey(ref)); err != nil && !os.IsNotExist(err) && first == nil {
			first = err
		}
	}
	return first
}

// CacheRefsForPath returns the cache keys that may hold path.
// kpm get stores the ref the user typed, which is either path or @backend/path.
func CacheRefsForPath(cfg *Config, path string) []string {
	refs := make([]string, 0, 4)
	seen := map[string]bool{}
	add := func(ref string) {
		if ref == "" || seen[ref] {
			return
		}
		seen[ref] = true
		refs = append(refs, ref)
	}
	add(path)
	if cfg == nil {
		return refs
	}
	if cfg.DefaultBackend != "" {
		add("@" + cfg.DefaultBackend + "/" + path)
	}
	for name := range cfg.Backends {
		add("@" + name + "/" + path)
	}
	for name := range cfg.backendByName {
		add("@" + name + "/" + path)
	}
	return refs
}

// Put stores a value in the cache.
func (c *SecretCache) Put(ref string, value []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := cacheEntry{FetchedAt: time.Now().Unix(), Value: append([]byte(nil), value...)}
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return os.WriteFile(c.fileKey(ref), data, 0600)
}

// Clear removes all cached entries (kpm sync --force refresh).
func (c *SecretCache) Clear() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return err
	}
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		_ = os.Remove(filepath.Join(c.dir, ent.Name()))
	}
	return nil
}
