package detection

import "testing"

func baseConfig() Config {
	return Config{
		MetricsSourceBaseURL: "http://thanos:10912",
		AlertmanagerBaseURL:  "http://alertmanager:9093",
		FeatureProfilePath:   "/etc/profile.yaml",
		DBPath:               "/var/lib/state.db",
		ModelProvider:        ModelProviderConfig{Enabled: false, Auth: "none"},
	}
}

func TestLogSourceConfig_DisabledRequiresNothing(t *testing.T) {
	c := baseConfig()
	c.LogSource = LogSourceConfig{Enabled: false}
	if err := c.Validate(); err != nil {
		t.Fatalf("expected disabled logSource to validate, got %v", err)
	}
}

func TestLogSourceConfig_EnabledRequiresBaseURLAndQuery(t *testing.T) {
	c := baseConfig()
	c.LogSource = LogSourceConfig{Enabled: true}
	if err := c.Validate(); err == nil {
		t.Fatal("expected an error for enabled logSource with no baseUrl/query")
	}

	c.LogSource = LogSourceConfig{Enabled: true, BaseURL: "http://loki:3100"}
	if err := c.Validate(); err == nil {
		t.Fatal("expected an error for enabled logSource with no query")
	}

	c.LogSource = LogSourceConfig{Enabled: true, BaseURL: "http://loki:3100", Query: `{job=~".+"}`}
	if err := c.Validate(); err != nil {
		t.Fatalf("expected a valid minimal logSource config to validate, got %v", err)
	}
}

func TestLogSourceConfig_InvalidWindowDurationRejected(t *testing.T) {
	c := baseConfig()
	c.LogSource = LogSourceConfig{Enabled: true, BaseURL: "http://loki:3100", Query: `{job=~".+"}`, CurrentWindow: "not-a-duration"}
	if err := c.Validate(); err == nil {
		t.Fatal("expected an error for an invalid currentWindow duration string")
	}

	c.LogSource = LogSourceConfig{Enabled: true, BaseURL: "http://loki:3100", Query: `{job=~".+"}`, CurrentWindow: "10m", BaselineWindow: "6h"}
	if err := c.Validate(); err != nil {
		t.Fatalf("expected valid duration strings to validate, got %v", err)
	}
}
