package detection

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// ModelProviderConfig is the Stage B provider block. Stage A always runs
// with Enabled=false; every other field is only required when enabled
// (spec §41.1's inputRules, mirrored here for the binary's own config
// validation).
type ModelProviderConfig struct {
	Enabled   bool                        `yaml:"enabled"`
	Protocol  string                      `yaml:"protocol"`
	BaseURL   string                      `yaml:"baseUrl"`
	Model     string                      `yaml:"model"`
	Auth      string                      `yaml:"auth"`
	APIKeyEnv string                      `yaml:"apiKeyEnv"`
	External  bool                        `yaml:"external"`
	Fallback  ModelProviderFallbackConfig `yaml:"fallback"`
}

// ModelProviderFallbackConfig is an optional second provider (spec1.md
// §35's "Level 2: alternate backend" — not required by that spec's own
// v1, but reconciled here as a generic, protocol-agnostic primary+
// fallback mechanism: any protocol may be primary or fallback, an
// operator just happens to configure flm as primary with
// ollama-chat/openai-responses as fallback for an NPU-first deployment).
// It never nests a fallback of its own.
type ModelProviderFallbackConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Protocol  string `yaml:"protocol"`
	BaseURL   string `yaml:"baseUrl"`
	Model     string `yaml:"model"`
	Auth      string `yaml:"auth"`
	APIKeyEnv string `yaml:"apiKeyEnv"`
}

// LogSourceConfig is the optional log pipeline block (spec1.md §14) — a
// third, equally-weighted peer to baseline/cohort, not part of the
// original detection-engine spec (whose Non-Goals excludes logs
// entirely). Disabled by default; every existing Stage A/B behavior stays
// byte-identical when Enabled is false.
type LogSourceConfig struct {
	Enabled bool   `yaml:"enabled"`
	BaseURL string `yaml:"baseUrl"`
	// Query is a raw LogQL selector (spec1.md §14) — this package assumes
	// no particular label scheme beyond requiring a pilot_host label (and
	// optional site/level) on whatever streams it matches.
	Query string `yaml:"query"`
	// CurrentWindow/BaselineWindow are Go duration strings (e.g. "10m",
	// "6h"); empty defaults to DefaultLogCurrentWindow/DefaultLogBaselineWindow.
	CurrentWindow  string `yaml:"currentWindow"`
	BaselineWindow string `yaml:"baselineWindow"`
}

// Config is the Detection Engine's config.yaml shape (spec §8, §33: the
// file itself never contains a secret — only api_key_env, the name of an
// environment variable the secret arrives through).
type Config struct {
	MetricsSourceBaseURL string              `yaml:"metricsSourceBaseUrl"`
	AlertmanagerBaseURL  string              `yaml:"alertmanagerBaseUrl"`
	FeatureProfilePath   string              `yaml:"featureProfilePath"`
	DBPath               string              `yaml:"dbPath"`
	StatusPath           string              `yaml:"statusPath"`
	TextfileMetricsPath  string              `yaml:"textfileMetricsPath"`
	ModelProvider        ModelProviderConfig `yaml:"modelProvider"`
	LogSource            LogSourceConfig     `yaml:"logSource"`
}

// LoadConfig reads and validates config.yaml.
func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %s: %w", path, err)
	}
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("decode config %s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// Validate checks the config shape invariants (spec §8/§33/§41.1). It does
// not check network reachability — that is the apply-time preflight's job
// (spec §44), not the binary's.
func (c Config) Validate() error {
	if c.MetricsSourceBaseURL == "" {
		return fmt.Errorf("config: metricsSourceBaseUrl is required")
	}
	if c.AlertmanagerBaseURL == "" {
		return fmt.Errorf("config: alertmanagerBaseUrl is required")
	}
	if c.FeatureProfilePath == "" {
		return fmt.Errorf("config: featureProfilePath is required")
	}
	if c.DBPath == "" {
		return fmt.Errorf("config: dbPath is required")
	}
	if err := c.ModelProvider.validate(); err != nil {
		return err
	}
	return c.LogSource.validate()
}

func (l LogSourceConfig) validate() error {
	if !l.Enabled {
		return nil
	}
	if l.BaseURL == "" {
		return fmt.Errorf("config: logSource.baseUrl is required when enabled")
	}
	if l.Query == "" {
		return fmt.Errorf("config: logSource.query is required when enabled")
	}
	if l.CurrentWindow != "" {
		if _, err := time.ParseDuration(l.CurrentWindow); err != nil {
			return fmt.Errorf("config: logSource.currentWindow: %w", err)
		}
	}
	if l.BaselineWindow != "" {
		if _, err := time.ParseDuration(l.BaselineWindow); err != nil {
			return fmt.Errorf("config: logSource.baselineWindow: %w", err)
		}
	}
	return nil
}

func (m ModelProviderConfig) validate() error {
	if !m.Enabled {
		// Stage A: disabled provider requires nothing else — spec §33/§41.1.
		// A disabled primary can't have an enabled fallback either — there
		// would be nothing for it to be a fallback FROM.
		if m.Fallback.Enabled {
			return fmt.Errorf("config: modelProvider.fallback.enabled requires modelProvider.enabled")
		}
		return nil
	}
	if err := validateProviderProtocolAuth(m.Protocol, m.BaseURL, m.Model, m.Auth, m.APIKeyEnv); err != nil {
		return fmt.Errorf("config: modelProvider.%w", err)
	}
	if m.Fallback.Enabled {
		if err := validateProviderProtocolAuth(m.Fallback.Protocol, m.Fallback.BaseURL, m.Fallback.Model, m.Fallback.Auth, m.Fallback.APIKeyEnv); err != nil {
			return fmt.Errorf("config: modelProvider.fallback.%w", err)
		}
	}
	return nil
}

// validateProviderProtocolAuth is shared by the primary and fallback
// provider blocks — same shape, same rules.
func validateProviderProtocolAuth(protocol, baseURL, model, auth, apiKeyEnv string) error {
	if protocol != "openai-responses" && protocol != "ollama-chat" && protocol != "flm" {
		return fmt.Errorf("protocol must be openai-responses, ollama-chat, or flm, got %q", protocol)
	}
	if baseURL == "" {
		return fmt.Errorf("baseUrl is required when enabled")
	}
	if model == "" {
		return fmt.Errorf("model is required when enabled")
	}
	if auth != "none" && auth != "bearer" {
		return fmt.Errorf("auth must be none or bearer, got %q", auth)
	}
	if auth == "bearer" && apiKeyEnv == "" {
		return fmt.Errorf("apiKeyEnv is required when auth=bearer")
	}
	return nil
}
