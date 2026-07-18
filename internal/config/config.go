// Package config loads pilot's small YAML config file. Most of the
// former knobs belonged to the LLM-agent surface retired on 2026-07-17;
// what remains is the data directory and the sandbox-container settings
// used by `pilot vm-target run --sandbox`.
package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Config struct {
	DataDir string        `yaml:"data_dir"`
	Sandbox SandboxConfig `yaml:"sandbox,omitempty"`
}

// SandboxConfig configures the optional Docker-sandbox mode used by
// `pilot vm-target run --sandbox-image`: the playbook run happens inside
// a managed container with the vm-target SSH keys mounted read-only.
type SandboxConfig struct {
	// Image is the docker image to run.
	Image string `yaml:"image,omitempty"`

	// Pull is the docker --pull strategy. Default: "missing".
	// Values: "always" | "missing" | "never".
	Pull string `yaml:"pull,omitempty"`
}

func Default() *Config {
	home, _ := os.UserHomeDir()
	return &Config{
		DataDir: filepath.Join(home, ".local", "share", "pilot"),
		Sandbox: SandboxConfig{
			Pull: "missing",
		},
	}
}

func Load(path string) (*Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
