package kpm

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config holds KPM CLI configuration.
type Config struct {
	Server          string `yaml:"server"`
	Cert            string `yaml:"cert"`
	Key             string `yaml:"key"`
	CA              string `yaml:"ca"`
	DefaultTemplate string `yaml:"default_template"`
	SecureMode      bool   `yaml:"secure_mode"`
	SessionKeyTTL   int    `yaml:"session_key_ttl"`

	// FallbackPath points to an alternate config to use for automatic failover
	// (e.g. local store when the primary remote is unreachable). Set this in your
	// primary config (e.g. odev config has "fallback: ~/.kpm/config.yaml").
	FallbackPath string `yaml:"fallback"`

	// MirrorToFallback causes successful writes (add, remove, etc.) against the
	// primary to also be applied to the fallback store. This keeps the alternate
	// "synced in real-time" whenever the primary is available.
	MirrorToFallback bool `yaml:"mirror_to_fallback"`

	// Fallback is populated at runtime when FallbackPath is set (or via auto logic).
	// It is not read from YAML directly.
	Fallback *Config `yaml:"-"`
}

// DefaultConfigPath returns the default config file path.
// Uses XDG-compliant ConfigDir() — see paths.go.
//
// If $KPM_CONFIG points directly to a .yaml file (e.g. export KPM_CONFIG=~/.kpm/config-odev.yaml),
// that file is used as the config. This makes it easy to target different AgentKMS
// servers (local vs remote) for a whole shell session or script without sprinkling
// --config on every single command.
func DefaultConfigPath() string {
	if d := os.Getenv("KPM_CONFIG"); d != "" {
		if strings.HasSuffix(d, ".yaml") || strings.HasSuffix(d, ".yml") {
			// Expand ~ for convenience
			if len(d) > 0 && d[0] == '~' {
				if home, err := os.UserHomeDir(); err == nil {
					d = filepath.Join(home, d[1:])
				}
			}
			if fi, err := os.Stat(d); err == nil && !fi.IsDir() {
				return d
			}
		}
	}
	return filepath.Join(ConfigDir(), "config.yaml")
}

// LoadConfig reads and parses a YAML config file. Applies defaults for unset fields.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	if cfg.DefaultTemplate == "" {
		cfg.DefaultTemplate = ".env.template"
	}
	if cfg.SessionKeyTTL <= 0 {
		cfg.SessionKeyTTL = 3600
	}

	// Expand ~ in paths.
	cfg.Cert = ExpandHome(cfg.Cert)
	cfg.Key = ExpandHome(cfg.Key)
	cfg.CA = ExpandHome(cfg.CA)

	return cfg, nil
}

// ExpandHome replaces a leading ~ with the user's home directory.
// It is exported so it can be used from cmd/kpm for config path handling.
func ExpandHome(path string) string {
	if len(path) == 0 || path[0] != '~' {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	return filepath.Join(home, path[1:])
}
