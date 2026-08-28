package detection

import (
	"fmt"
	"os"
	"time"
)

// protocolTimeout implements spec §34's per-protocol default timeout.
func protocolTimeout(protocol string) (time.Duration, error) {
	switch protocol {
	case "openai-responses":
		return OpenAITimeout, nil
	case "ollama-chat":
		return OllamaTimeout, nil
	default:
		return 0, fmt.Errorf("unknown model provider protocol %q", protocol)
	}
}

// NewManagedProviderFromConfig builds the protocol adapter spec §31/§32
// call for, wrapped in spec §34's retry/circuit/timeout policy (spec
// §41.1/§45: the API key, when auth=bearer, arrives only via the
// APIKeyEnv-named environment variable — never read from config.yaml,
// never logged). Returns (nil, nil) when the provider is disabled (Stage
// A's default).
func NewManagedProviderFromConfig(cfg ModelProviderConfig) (*ManagedProvider, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	var apiKey string
	if cfg.Auth == "bearer" {
		apiKey = os.Getenv(cfg.APIKeyEnv)
		if apiKey == "" {
			return nil, fmt.Errorf("model provider auth=bearer but %s is empty/unset", cfg.APIKeyEnv)
		}
	}

	var base ModelProvider
	switch cfg.Protocol {
	case "openai-responses":
		base = &OpenAIProvider{BaseURL: cfg.BaseURL, Model: cfg.Model, APIKey: apiKey}
	case "ollama-chat":
		base = &OllamaProvider{BaseURL: cfg.BaseURL, Model: cfg.Model}
	default:
		return nil, fmt.Errorf("unknown model provider protocol %q", cfg.Protocol)
	}

	timeout, err := protocolTimeout(cfg.Protocol)
	if err != nil {
		return nil, err
	}
	return NewManagedProvider(base, cfg.Protocol, timeout), nil
}
