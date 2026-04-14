package kpm

import (
	"fmt"
	"os"
	"path/filepath"

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
}

// DefaultConfigPath returns ~/.kpm/config.yaml.
func DefaultConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".kpm", "config.yaml")
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
	cfg.Cert = expandHome(cfg.Cert)
	cfg.Key = expandHome(cfg.Key)
	cfg.CA = expandHome(cfg.CA)

	return cfg, nil
}

// expandHome replaces a leading ~ with the user's home directory.
func expandHome(path string) string {
	if len(path) == 0 || path[0] != '~' {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	return filepath.Join(home, path[1:])
}
