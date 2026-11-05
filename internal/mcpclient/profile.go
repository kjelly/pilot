// Package mcpclient is pilot-mcp: the user-side half of the remote MCP
// access. It fetches the configuration from GitHub with the user's own Git
// credentials, builds the snapshot, runs one `docker run` on the deploy
// node over SSH, and relays MCP between the coding agent and that
// container. It imports nothing Linux-only, so cmd/pilot-mcp builds for
// darwin.
//
// Spec: docs/superpowers/specs/2026-10-30-pilot-mcp-remote-access-spec.md §5-§6.
package mcpclient

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/kjelly/pilot/internal/mcpwire"
	"go.yaml.in/yaml/v3"
)

// Profile is one entry of profiles.yaml.
type Profile struct {
	Source   SourceConfig  `yaml:"source"`
	Target   TargetConfig  `yaml:"target"`
	Mode     string        `yaml:"mode"`
	Timeouts TimeoutConfig `yaml:"timeouts"`
}

// SourceConfig names the Git repository and the environment's workspace.
type SourceConfig struct {
	URL    string `yaml:"url"`
	Ref    string `yaml:"ref"`
	Subdir string `yaml:"subdir"`
}

// TargetConfig names the deploy node and how to run the container there.
type TargetConfig struct {
	SSHHost     string `yaml:"ssh_host"`
	SSHConfig   string `yaml:"ssh_config"`
	Env         string `yaml:"env"`
	EnvRoot     string `yaml:"env_root"`
	Image       string `yaml:"image"`
	Docker      string `yaml:"docker"`
	NetworkHost bool   `yaml:"network_host"`
}

// TimeoutConfig bounds the network steps, in seconds.
type TimeoutConfig struct {
	GitSeconds     int `yaml:"git_seconds"`
	SSHSeconds     int `yaml:"ssh_seconds"`
	StartupSeconds int `yaml:"startup_seconds"`
}

type profileFile struct {
	Version  int                `yaml:"version"`
	Profiles map[string]Profile `yaml:"profiles"`
}

// DefaultProfilePath is $XDG_CONFIG_HOME/pilot-mcp/profiles.yaml, falling
// back to ~/.config.
func DefaultProfilePath() (string, error) {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "pilot-mcp", "profiles.yaml"), nil
}

// LoadProfile reads profiles.yaml strictly and returns the named profile
// with defaults applied and every field validated.
func LoadProfile(path, name string) (Profile, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Profile{}, fmt.Errorf("profile file: %w", err)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return Profile{}, fmt.Errorf("profile file %s is writable by group or others (mode %04o); chmod 600 it", path, info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Profile{}, fmt.Errorf("profile file: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var pf profileFile
	if err := dec.Decode(&pf); err != nil {
		return Profile{}, fmt.Errorf("profile file %s: %w", path, err)
	}
	if pf.Version != 1 {
		return Profile{}, fmt.Errorf("profile file %s: version must be 1", path)
	}
	if !profileNamePattern.MatchString(name) {
		return Profile{}, fmt.Errorf("profile name %q must match %s", name, profileNamePattern)
	}
	p, ok := pf.Profiles[name]
	if !ok {
		return Profile{}, fmt.Errorf("profile %q not found in %s", name, path)
	}
	p.applyDefaults()
	if err := p.Validate(); err != nil {
		return Profile{}, fmt.Errorf("profile %q: %w", name, err)
	}
	return p, nil
}

func (p *Profile) applyDefaults() {
	if p.Target.Docker == "" {
		p.Target.Docker = "docker"
	}
	if p.Timeouts.GitSeconds == 0 {
		p.Timeouts.GitSeconds = 60
	}
	if p.Timeouts.SSHSeconds == 0 {
		p.Timeouts.SSHSeconds = 15
	}
	if p.Timeouts.StartupSeconds == 0 {
		p.Timeouts.StartupSeconds = 60
	}
}

var (
	profileNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,47}$`)
	sshHostPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	safePathPattern    = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)
	imageRepoPattern   = regexp.MustCompile(`^[a-z0-9]+([._/-][a-z0-9]+)*$`)
	imageTagPattern    = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	fullSHAPattern     = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)
	hexPattern         = regexp.MustCompile(`^[0-9a-fA-F]{7,}$`)
	refPattern         = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)
)

// Validate checks every field against spec §5.3.
func (p Profile) Validate() error {
	if err := ValidateRepoURL(p.Source.URL); err != nil {
		return fmt.Errorf("source.url: %w", err)
	}
	if err := validateRef(p.Source.Ref); err != nil {
		return fmt.Errorf("source.ref: %w", err)
	}
	if err := validateSubdir(p.Source.Subdir); err != nil {
		return fmt.Errorf("source.subdir: %w", err)
	}
	if !sshHostPattern.MatchString(p.Target.SSHHost) {
		return fmt.Errorf("target.ssh_host %q must match %s", p.Target.SSHHost, sshHostPattern)
	}
	if p.Target.SSHConfig != "" {
		cfg, err := ExpandHome(p.Target.SSHConfig)
		if err != nil {
			return fmt.Errorf("target.ssh_config: %w", err)
		}
		info, err := os.Stat(cfg)
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("target.ssh_config %s is not a regular file", p.Target.SSHConfig)
		}
	}
	if !mcpwire.ValidEnv(p.Target.Env) {
		return fmt.Errorf("target.env must be one of %s", strings.Join(mcpwire.Envs, ", "))
	}
	if err := validateRemotePath(p.Target.EnvRoot, true); err != nil {
		return fmt.Errorf("target.env_root: %w", err)
	}
	if err := validateRemotePath(p.Target.Docker, false); err != nil {
		return fmt.Errorf("target.docker: %w", err)
	}
	if p.Target.Image != "" {
		if err := ValidateImage(p.Target.Image); err != nil {
			return fmt.Errorf("target.image: %w", err)
		}
	}
	if !mcpwire.ValidMode(p.Mode) {
		return fmt.Errorf("mode must be %s or %s", mcpwire.ModeObserve, mcpwire.ModeEdit)
	}
	for name, v := range map[string]int{"git_seconds": p.Timeouts.GitSeconds, "ssh_seconds": p.Timeouts.SSHSeconds, "startup_seconds": p.Timeouts.StartupSeconds} {
		if v < 1 || v > 3600 {
			return fmt.Errorf("timeouts.%s must be between 1 and 3600", name)
		}
	}
	return nil
}

func validateRef(ref string) error {
	switch {
	case ref == "":
		return errors.New("is required")
	case fullSHAPattern.MatchString(ref):
		return nil
	case hexPattern.MatchString(ref) && len(ref) < 40:
		return errors.New("abbreviated commit SHAs are not accepted; use the full SHA")
	case strings.HasPrefix(ref, "-"), strings.HasPrefix(ref, "/"), strings.HasSuffix(ref, "/"),
		strings.HasSuffix(ref, ".lock"), strings.Contains(ref, ".."), strings.Contains(ref, "//"),
		strings.Contains(ref, "@{"), !refPattern.MatchString(ref):
		return fmt.Errorf("%q is not a valid branch or tag name", ref)
	}
	return nil
}

func validateSubdir(subdir string) error {
	if subdir == "" {
		return errors.New("is required (use . for the repository root)")
	}
	if subdir == "." {
		return nil
	}
	if strings.HasPrefix(subdir, "/") || filepath.ToSlash(filepath.Clean(subdir)) != subdir || strings.Contains("/"+subdir+"/", "/../") {
		return fmt.Errorf("%q must be a clean relative path without parent-directory segments", subdir)
	}
	return nil
}

// validateRemotePath keeps a path that ends up in the remote command line
// within a charset that needs no quoting and has no comma.
func validateRemotePath(p string, absolute bool) error {
	switch {
	case p == "":
		return errors.New("is required")
	case !safePathPattern.MatchString(p):
		return fmt.Errorf("%q may contain only letters, digits, '.', '_', '/' and '-'", p)
	case strings.HasPrefix(p, "-"):
		return fmt.Errorf("%q must not start with '-'", p)
	case strings.Contains("/"+p+"/", "/../"):
		return fmt.Errorf("%q must not contain parent-directory segments", p)
	case absolute && !strings.HasPrefix(p, "/"):
		return fmt.Errorf("%q must be absolute", p)
	}
	return nil
}

// ValidateImage accepts <repo>:<tag>, never a digest.
func ValidateImage(image string) error {
	i := strings.LastIndex(image, ":")
	if i <= 0 || strings.Contains(image, "@") {
		return fmt.Errorf("%q must be <repository>:<tag>", image)
	}
	repo, tag := image[:i], image[i+1:]
	if strings.Contains(tag, "/") || !imageRepoPattern.MatchString(repo) || !imageTagPattern.MatchString(tag) {
		return fmt.Errorf("%q must be <repository>:<tag>", image)
	}
	return nil
}

// ExpandHome expands a leading ~/ to the user's home directory.
func ExpandHome(p string) (string, error) {
	if p == "~" || strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, strings.TrimPrefix(p, "~")), nil
	}
	return p, nil
}

// Timeouts converts the profile's seconds to durations.
func (p Profile) gitTimeout() time.Duration {
	return time.Duration(p.Timeouts.GitSeconds) * time.Second
}

func (p Profile) startupTimeout() time.Duration {
	return time.Duration(p.Timeouts.StartupSeconds) * time.Second
}
