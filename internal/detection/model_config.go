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
	case "flm":
		return FLMTimeout, nil
	default:
		return 0, fmt.Errorf("unknown model provider protocol %q", protocol)
	}
}

// NewManagedProviderFromConfig builds the protocol adapter spec §31/§32
// call for, wrapped in spec §34's retry/circuit/timeout policy (spec
// §41.1/§45: the API key, when auth=bearer, arrives only via the
// APIKeyEnv-named environment variable — never read from config.yaml,
// never logged). Returns (nil, nil) when the provider is disabled (Stage
// A's default). When cfg.Fallback.Enabled, the returned ModelProvider is
// a *FallbackProvider that tries the fallback protocol/backend after any
// primary failure (spec1.md §35's alternate-backend fallback — e.g. flm
// primary for local NPU inference, ollama-chat/openai-responses fallback
// for when the NPU backend is unavailable).
func NewManagedProviderFromConfig(cfg ModelProviderConfig) (ModelProvider, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	primary, err := newManagedProviderForProtocol(cfg.Protocol, cfg.BaseURL, cfg.Model, cfg.Auth, cfg.APIKeyEnv)
	if err != nil {
		return nil, fmt.Errorf("model provider: %w", err)
	}
	if !cfg.Fallback.Enabled {
		return primary, nil
	}

	fb := cfg.Fallback
	fallback, err := newManagedProviderForProtocol(fb.Protocol, fb.BaseURL, fb.Model, fb.Auth, fb.APIKeyEnv)
	if err != nil {
		return nil, fmt.Errorf("model provider fallback: %w", err)
	}
	return &FallbackProvider{Primary: primary, Fallback: fallback}, nil
}

// newManagedProviderForProtocol builds one fully-managed single-protocol
// provider — shared by the primary and fallback provider blocks.
func newManagedProviderForProtocol(protocol, baseURL, model, auth, apiKeyEnv string) (*ManagedProvider, error) {
	var apiKey string
	if auth == "bearer" {
		apiKey = os.Getenv(apiKeyEnv)
		if apiKey == "" {
			return nil, fmt.Errorf("auth=bearer but %s is empty/unset", apiKeyEnv)
		}
	}

	var base ModelProvider
	switch protocol {
	case "openai-responses":
		base = &OpenAIProvider{BaseURL: baseURL, Model: model, APIKey: apiKey}
	case "ollama-chat":
		base = &OllamaProvider{BaseURL: baseURL, Model: model}
	case "flm":
		base = &FLMProvider{BaseURL: baseURL, Model: model, APIKey: apiKey}
	default:
		return nil, fmt.Errorf("unknown model provider protocol %q", protocol)
	}

	timeout, err := protocolTimeout(protocol)
	if err != nil {
		return nil, err
	}
	return NewManagedProvider(base, protocol, timeout), nil
}
