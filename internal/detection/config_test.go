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

// TestConfig_FeatureProfilePathAndFeatureProfilesAreMutuallyExclusive is
// spec §9.5's compatibility rule.
func TestConfig_FeatureProfilePathAndFeatureProfilesAreMutuallyExclusive(t *testing.T) {
	c := baseConfig()
	c.FeatureProfiles = []FeatureProfileEntry{{Path: "/etc/other.yaml", Enabled: true}}
	if err := c.Validate(); err == nil {
		t.Fatal("expected an error when both featureProfilePath and featureProfiles are set")
	}
}

func TestConfig_NeitherFeatureProfilePathNorFeatureProfilesIsRejected(t *testing.T) {
	c := baseConfig()
	c.FeatureProfilePath = ""
	if err := c.Validate(); err == nil {
		t.Fatal("expected an error when neither featureProfilePath nor featureProfiles is set")
	}
}

func TestConfig_ResolveFeatureProfilePaths_SingleModeReturnsThePath(t *testing.T) {
	c := baseConfig()
	got := c.ResolveFeatureProfilePaths()
	if len(got) != 1 || got[0] != "/etc/profile.yaml" {
		t.Fatalf("ResolveFeatureProfilePaths() = %v, want [\"/etc/profile.yaml\"]", got)
	}
}

func TestConfig_ResolveFeatureProfilePaths_MultiModeSkipsDisabled(t *testing.T) {
	c := baseConfig()
	c.FeatureProfilePath = ""
	c.FeatureProfiles = []FeatureProfileEntry{
		{Path: "/etc/linux-host-v1.yaml", Enabled: true},
		{Path: "/etc/disabled.yaml", Enabled: false},
		{Path: "/etc/network-device-ifmib-v1.yaml", Enabled: true},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("expected a valid multi-profile config to validate, got %v", err)
	}
	got := c.ResolveFeatureProfilePaths()
	want := []string{"/etc/linux-host-v1.yaml", "/etc/network-device-ifmib-v1.yaml"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("ResolveFeatureProfilePaths() = %v, want %v", got, want)
	}
}
