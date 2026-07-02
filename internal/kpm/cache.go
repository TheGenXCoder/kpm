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
func (c *SecretCache) Get(ref string, ttlSec int) ([]byte, bool) {
	if ttlSec <= 0 {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	data, err := os.ReadFile(c.fileKey(ref))
	if err != nil {
		return nil, false
	}
	var e cacheEntry
	if json.Unmarshal(data, &e) != nil {
		return nil, false
	}
	if time.Now().Unix()-e.FetchedAt > int64(ttlSec) {
		return nil, false
	}
	out := make([]byte, len(e.Value))
	copy(out, e.Value)
	return out, true
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
