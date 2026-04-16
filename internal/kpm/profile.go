package kpm

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Profile holds resolved profile variables from merged .kpm/config.yaml files.
type Profile map[string]string

// ProfileSource records where a profile key was set (for kpm profile output).
type ProfileSource struct {
	Value  string
	Source string // file path that set this key
}

// LoadProfile walks from cwd up to root, merging .kpm/config.yaml profile sections.
// Child overrides parent for the same key. Final fallback: global config.
func LoadProfile() (Profile, error) {
	_, merged := loadProfileWithSources()
	result := Profile{}
	for k, ps := range merged {
		result[k] = ps.Value
	}
	return result, nil
}

// LoadProfileWithSources returns the merged profile and source annotations.
func LoadProfileWithSources() map[string]ProfileSource {
	_, sources := loadProfileWithSources()
	return sources
}

func loadProfileWithSources() ([]string, map[string]ProfileSource) {
	sources := map[string]ProfileSource{}

	cwd, err := os.Getwd()
	if err != nil {
		return nil, sources
	}

	// Collect config paths from cwd upward (cwd first = highest priority)
	var configs []string
	dir := cwd
	for {
		cfgPath := filepath.Join(dir, ".kpm", "config.yaml")
		if _, err := os.Stat(cfgPath); err == nil {
			configs = append(configs, cfgPath)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break // reached root
		}
		dir = parent
	}

	// Global fallback
	globalCfg := filepath.Join(ConfigDir(), "config.yaml")
	if _, err := os.Stat(globalCfg); err == nil {
		configs = append(configs, globalCfg)
	}

	// Apply in reverse order (root/global first, cwd last — so cwd wins)
	var ordered []string
	for i := len(configs) - 1; i >= 0; i-- {
		cfgPath := configs[i]
		p, err := loadProfileFromFile(cfgPath)
		if err != nil {
			continue
		}
		for k, v := range p {
			sources[k] = ProfileSource{Value: v, Source: cfgPath}
		}
		ordered = append(ordered, cfgPath)
	}

	return ordered, sources
}

func loadProfileFromFile(path string) (Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg struct {
		Profile map[string]string `yaml:"profile"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if cfg.Profile == nil {
		return Profile{}, nil
	}
	return Profile(cfg.Profile), nil
}

// Resolve replaces {{profile:key}} and {{profile:key:-default}} in a string.
func (p Profile) Resolve(s string) (string, error) {
	result := s
	for {
		start := strings.Index(result, "{{profile:")
		if start < 0 {
			break
		}
		end := strings.Index(result[start:], "}}")
		if end < 0 {
			return "", fmt.Errorf("unterminated profile variable in %q", s)
		}
		end += start + 2

		inner := result[start+len("{{profile:") : end-2]

		// Check for default: {{profile:key:-default}}
		key := inner
		defaultVal := ""
		hasDefault := false
		if idx := strings.Index(inner, ":-"); idx >= 0 {
			key = inner[:idx]
			defaultVal = inner[idx+2:]
			hasDefault = true
		}

		val, ok := p[key]
		if !ok {
			if hasDefault {
				val = defaultVal
			} else {
				return "", fmt.Errorf("profile variable %q not found (checked .kpm/config.yaml up to root + global config)", key)
			}
		}

		result = result[:start] + val + result[end:]
	}
	return result, nil
}
