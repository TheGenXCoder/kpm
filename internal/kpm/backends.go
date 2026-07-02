package kpm

import (
	"fmt"
	"strings"
)

// BackendConfig is one named AgentKMS connection (server + optional cert paths).
type BackendConfig struct {
	Server      string `yaml:"server"`
	Cert        string `yaml:"cert"`
	Key         string `yaml:"key"`
	CA          string `yaml:"ca"`
	TrustDomain string `yaml:"trust_domain"`
	Tenant      string `yaml:"tenant"`
}

// FinalizeBackends builds runtime backend map from backends: and legacy server:.
func (cfg *Config) FinalizeBackends() error {
	cfg.backendByName = map[string]*Config{}

	if len(cfg.Backends) == 0 {
		_ = cfg.ResolveIdentityPaths()
		return nil
	}

	defaultName := cfg.DefaultBackend
	if defaultName == "" {
		defaultName = "default"
	}

	for name, bc := range cfg.Backends {
		if bc == nil || strings.TrimSpace(bc.Server) == "" {
			return fmt.Errorf("backends.%s: server is required", name)
		}
		sub := &Config{
			Server:          ExpandHome(bc.Server),
			Cert:            ExpandHome(bc.Cert),
			Key:             ExpandHome(bc.Key),
			CA:              ExpandHome(bc.CA),
			TrustDomain:     bc.TrustDomain,
			Tenant:          bc.Tenant,
			DefaultTemplate: cfg.DefaultTemplate,
			SessionKeyTTL:   cfg.SessionKeyTTL,
			StepUpTTL:       cfg.StepUpTTL,
			CacheTTLSec:     cfg.CacheTTLSec,
		}
		if sub.TrustDomain == "" {
			sub.TrustDomain = cfg.TrustDomain
		}
		if sub.Tenant == "" {
			sub.Tenant = cfg.Tenant
		}
		_ = sub.ResolveIdentityPaths()
		cfg.backendByName[name] = sub
	}

	// Legacy top-level server: becomes default backend when not already defined.
	if cfg.Server != "" {
		if _, ok := cfg.backendByName[defaultName]; !ok {
			legacy := &Config{
				Server:          cfg.Server,
				Cert:            cfg.Cert,
				Key:             cfg.Key,
				CA:              cfg.CA,
				TrustDomain:     cfg.TrustDomain,
				Tenant:          cfg.Tenant,
				DefaultTemplate: cfg.DefaultTemplate,
				SessionKeyTTL:   cfg.SessionKeyTTL,
				StepUpTTL:       cfg.StepUpTTL,
				CacheTTLSec:     cfg.CacheTTLSec,
			}
			_ = legacy.ResolveIdentityPaths()
			cfg.backendByName[defaultName] = legacy
		}
	}

	if _, ok := cfg.backendByName[defaultName]; !ok {
		return fmt.Errorf("default_backend %q not found in backends", defaultName)
	}

	cfg.DefaultBackend = defaultName
	// Promote default backend to top-level for commands that still read cfg.Server.
	def := cfg.backendByName[defaultName]
	cfg.Server = def.Server
	cfg.Cert = def.Cert
	cfg.Key = def.Key
	cfg.CA = def.CA
	return nil
}

// ConfigForBackend returns the connection config for a named backend.
// Empty name uses default_backend.
func (cfg *Config) ConfigForBackend(name string) (*Config, error) {
	if len(cfg.backendByName) == 0 {
		if cfg.Server == "" {
			return nil, fmt.Errorf("no server configured")
		}
		return cfg, nil
	}
	if name == "" {
		name = cfg.DefaultBackend
	}
	sub, ok := cfg.backendByName[name]
	if !ok {
		return nil, fmt.Errorf("unknown backend %q (configured: %s)", name, strings.Join(cfg.BackendNames(), ", "))
	}
	return sub, nil
}

// BackendNames returns sorted backend keys for error messages.
func (cfg *Config) BackendNames() []string {
	if len(cfg.backendByName) == 0 {
		return nil
	}
	names := make([]string, 0, len(cfg.backendByName))
	for n := range cfg.backendByName {
		names = append(names, n)
	}
	return names
}

// SplitBackendRef splits "@mstr/path/to/secret" into ("mstr", "path/to/secret").
// Plain paths are returned with an empty backend.
func SplitBackendRef(ref string) (backend, rest string) {
	ref = strings.TrimSpace(ref)
	if !strings.HasPrefix(ref, "@") {
		return "", ref
	}
	ref = ref[1:]
	slash := strings.IndexByte(ref, '/')
	if slash < 0 {
		return ref, ""
	}
	return ref[:slash], ref[slash+1:]
}
