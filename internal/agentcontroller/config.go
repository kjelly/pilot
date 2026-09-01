package agentcontroller

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// DispatcherConfig configures how the controller talks to the external
// Agent Runtime through the AgentDispatcher interface (spec §12). "fake"
// is a deterministic in-process dispatcher used for tests and the
// disposable-lane evidence; "http" is a generic JSON-over-HTTP adapter —
// no protocol-specific (vendor) field lives in this type or in
// IncidentEnvelopeV1/DiagnosisResult, so a Runtime-specific adapter can
// be added later without changing either (spec §4's adapter boundary).
type DispatcherConfig struct {
	Kind           string `yaml:"kind"` // "fake" | "http"
	Endpoint       string `yaml:"endpoint,omitempty"`
	TimeoutSeconds int    `yaml:"timeoutSeconds"`
}

// Config is pilot-agent-controller's config.yaml shape (spec §14). The
// webhook shared secret never lands in this file — only the name of the
// environment variable it arrives through (same convention as Detection
// Engine's modelProvider.apiKeyEnv).
type Config struct {
	ListenAddr          string           `yaml:"listenAddr"`
	DBPath              string           `yaml:"dbPath"`
	StatusPath          string           `yaml:"statusPath"`
	TextfileMetricsPath string           `yaml:"textfileMetricsPath"`
	WebhookSecretEnv    string           `yaml:"webhookSecretEnv"`
	MaxBodyBytes        int64            `yaml:"maxBodyBytes"`
	MaxConcurrentRuns   int              `yaml:"maxConcurrentRuns"`
	MaxRunsPerHost      int              `yaml:"maxRunsPerHost"`
	Dispatcher          DispatcherConfig `yaml:"dispatcher"`
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

// Validate checks the config shape invariants (spec §5/§14). It does not
// check network reachability — that is the apply-time preflight's job,
// not the binary's.
func (c Config) Validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("config: listenAddr is required")
	}
	if c.DBPath == "" {
		return fmt.Errorf("config: dbPath is required")
	}
	if c.WebhookSecretEnv == "" {
		return fmt.Errorf("config: webhookSecretEnv is required — unauthenticated webhooks must fail closed (spec §5)")
	}
	if c.MaxBodyBytes <= 0 {
		return fmt.Errorf("config: maxBodyBytes must be > 0")
	}
	if c.MaxConcurrentRuns <= 0 {
		return fmt.Errorf("config: maxConcurrentRuns must be > 0")
	}
	if c.MaxRunsPerHost <= 0 {
		return fmt.Errorf("config: maxRunsPerHost must be > 0")
	}
	switch c.Dispatcher.Kind {
	case "fake":
	case "http":
		if c.Dispatcher.Endpoint == "" {
			return fmt.Errorf("config: dispatcher.endpoint is required when dispatcher.kind=http")
		}
	default:
		return fmt.Errorf("config: dispatcher.kind must be fake or http, got %q", c.Dispatcher.Kind)
	}
	if c.Dispatcher.TimeoutSeconds <= 0 {
		return fmt.Errorf("config: dispatcher.timeoutSeconds must be > 0")
	}
	return nil
}
