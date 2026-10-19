// Package loginprobe implements pilot-login-probe: a daemon that, on a
// fixed cadence, runs a real OpenSSH login as a least-privileged directory
// (FreeIPA) canary account against every configured host and publishes the
// outcome through the node_exporter textfile collector (GitHub issue
// kjelly/pilot#11). It never implements SSH itself: it spawns the system
// OpenSSH client with a pinned ssh_config whose host-key trust comes from
// SSSD (sss_ssh_knownhostsproxy), the same path pilot-access-gateway uses.
package loginprobe

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Defaults applied by LoadConfig when the file leaves a field empty.
const (
	DefaultInterval       = 60 * time.Second
	DefaultConnectTimeout = 10 * time.Second
	DefaultTotalTimeout   = 30 * time.Second
	DefaultConcurrency    = 4
	DefaultUser           = "pilot-login-canary"
	DefaultCommand        = "/bin/true"
	DefaultSSHBinary      = "/usr/bin/ssh"
	DefaultSSHConfig      = "/etc/pilot/login-probe/ssh_config"
	DefaultTextfile       = "/var/lib/node_exporter/textfile/pilot_login_probe.prom"
	DefaultPort           = 22

	// MinInterval is the shortest cadence accepted: one login per target per
	// 10 s is already far beyond what the issue asks for (60 s).
	MinInterval = 10 * time.Second
)

// Target is one host the probe logs in to.
type Target struct {
	// Name is the probe_target label value: the host's lower-case inventory
	// name (never its connection address, AGENTS.md §5.13).
	Name string `yaml:"name"`
	// Host is what OpenSSH connects to: the host's FreeIPA FQDN, because
	// sss_ssh_knownhostsproxy looks the host key up in IPA by that name.
	Host string `yaml:"host"`
	// Port is the sshd port (default 22).
	Port int `yaml:"port"`
}

// Config is /etc/pilot/login-probe/config.yml.
type Config struct {
	Interval       time.Duration `yaml:"interval"`
	ConnectTimeout time.Duration `yaml:"connect_timeout"`
	TotalTimeout   time.Duration `yaml:"total_timeout"`
	Concurrency    int           `yaml:"concurrency"`
	User           string        `yaml:"user"`
	Command        string        `yaml:"command"`
	SSHBinary      string        `yaml:"ssh_binary"`
	SSHConfig      string        `yaml:"ssh_config"`
	Textfile       string        `yaml:"textfile"`
	Targets        []Target      `yaml:"targets"`
}

var (
	targetNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	hostRe       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]*$`)
	userRe       = regexp.MustCompile(`^[a-z_][a-z0-9._-]*$`)
)

// LoadConfig reads, defaults and validates a config file. Unknown keys are
// an error so a typo never silently falls back to a default.
func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	return ParseConfig(data)
}

// ParseConfig is LoadConfig for in-memory YAML.
func ParseConfig(data []byte) (Config, error) {
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Interval == 0 {
		c.Interval = DefaultInterval
	}
	if c.ConnectTimeout == 0 {
		c.ConnectTimeout = DefaultConnectTimeout
	}
	if c.TotalTimeout == 0 {
		c.TotalTimeout = DefaultTotalTimeout
	}
	if c.Concurrency == 0 {
		c.Concurrency = DefaultConcurrency
	}
	if c.User == "" {
		c.User = DefaultUser
	}
	if c.Command == "" {
		c.Command = DefaultCommand
	}
	if c.SSHBinary == "" {
		c.SSHBinary = DefaultSSHBinary
	}
	if c.SSHConfig == "" {
		c.SSHConfig = DefaultSSHConfig
	}
	if c.Textfile == "" {
		c.Textfile = DefaultTextfile
	}
	for i := range c.Targets {
		if c.Targets[i].Port == 0 {
			c.Targets[i].Port = DefaultPort
		}
	}
}

// Validate reports the first contract violation. An empty target list is
// valid (the daemon then publishes pilot_login_probe_targets 0, which the
// PilotLoginProbeNoTargets alert turns into an operator signal).
func (c Config) Validate() error {
	if c.Interval < MinInterval {
		return fmt.Errorf("interval %s is below the minimum %s", c.Interval, MinInterval)
	}
	if c.ConnectTimeout < time.Second {
		return fmt.Errorf("connect_timeout %s must be at least 1s", c.ConnectTimeout)
	}
	if c.TotalTimeout < c.ConnectTimeout {
		return fmt.Errorf("total_timeout %s must not be shorter than connect_timeout %s", c.TotalTimeout, c.ConnectTimeout)
	}
	if c.TotalTimeout >= c.Interval {
		return fmt.Errorf("total_timeout %s must be shorter than interval %s (a round must finish before the next starts)", c.TotalTimeout, c.Interval)
	}
	if c.Concurrency < 1 {
		return fmt.Errorf("concurrency %d must be at least 1", c.Concurrency)
	}
	if !userRe.MatchString(c.User) {
		return fmt.Errorf("user %q is not a valid POSIX account name", c.User)
	}
	if strings.TrimSpace(c.Command) == "" || strings.ContainsAny(c.Command, "\n\r") {
		return fmt.Errorf("command must be a single non-empty line")
	}
	for name, p := range map[string]string{"ssh_binary": c.SSHBinary, "ssh_config": c.SSHConfig, "textfile": c.Textfile} {
		if !filepath.IsAbs(p) {
			return fmt.Errorf("%s %q must be an absolute path", name, p)
		}
	}
	seen := make(map[string]int, len(c.Targets))
	for i, t := range c.Targets {
		if !targetNameRe.MatchString(t.Name) || net.ParseIP(t.Name) != nil {
			return fmt.Errorf("targets[%d].name %q must be a lower-case host name, not an address (label-safe identity)", i, t.Name)
		}
		if j, dup := seen[t.Name]; dup {
			return fmt.Errorf("targets[%d].name %q duplicates targets[%d]", i, t.Name, j)
		}
		seen[t.Name] = i
		if !hostRe.MatchString(t.Host) {
			return fmt.Errorf("targets[%d].host %q must be a host name (FQDN)", i, t.Host)
		}
		if t.Port < 1 || t.Port > 65535 {
			return fmt.Errorf("targets[%d].port %d is out of range", i, t.Port)
		}
	}
	return nil
}
