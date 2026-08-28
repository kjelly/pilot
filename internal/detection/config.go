package detection

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ModelProviderConfig is the Stage B provider block. Stage A always runs
// with Enabled=false; every other field is only required when enabled
// (spec §41.1's inputRules, mirrored here for the binary's own config
// validation).
type ModelProviderConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Protocol  string `yaml:"protocol"`
	BaseURL   string `yaml:"baseUrl"`
	Model     string `yaml:"model"`
	Auth      string `yaml:"auth"`
	APIKeyEnv string `yaml:"apiKeyEnv"`
	External  bool   `yaml:"external"`
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
	return c.ModelProvider.validate()
}

func (m ModelProviderConfig) validate() error {
	if !m.Enabled {
		// Stage A: disabled provider requires nothing else — spec §33/§41.1.
		return nil
	}
	if m.Protocol != "openai-responses" && m.Protocol != "ollama-chat" {
		return fmt.Errorf("config: modelProvider.protocol must be openai-responses or ollama-chat, got %q", m.Protocol)
	}
	if m.BaseURL == "" {
		return fmt.Errorf("config: modelProvider.baseUrl is required when enabled")
	}
	if m.Model == "" {
		return fmt.Errorf("config: modelProvider.model is required when enabled")
	}
	if m.Auth != "none" && m.Auth != "bearer" {
		return fmt.Errorf("config: modelProvider.auth must be none or bearer, got %q", m.Auth)
	}
	if m.Auth == "bearer" && m.APIKeyEnv == "" {
		return fmt.Errorf("config: modelProvider.apiKeyEnv is required when auth=bearer")
	}
	return nil
}
