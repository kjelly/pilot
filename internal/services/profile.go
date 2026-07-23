// Package services manages long-lived host services used by disposable
// vm-target guests.
package services

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Profile describes one host-service bundle. Credentials are deliberately not
// part of this type; they are supplied to Compose through host-side secret
// files and never projected into a guest.
type Profile struct {
	Name      string        `yaml:"name"`
	Apt       AptProfile    `yaml:"apt"`
	RPM       RPMProfile    `yaml:"rpm"`
	OCI       OCIProfile    `yaml:"oci"`
	Harbor    HarborProfile `yaml:"harbor"`
	Storage   StoragePolicy `yaml:"storage"`
	Retention Retention     `yaml:"retention"`
}

// AptProfile configures the Ubuntu package upstream and local proxy port.
type AptProfile struct {
	Upstream  string   `yaml:"upstream"`
	Allowlist []string `yaml:"allowlist"`
	Port      int      `yaml:"port"`
}

// RPMProfile configures Pulp RPM repository feeds.
type RPMProfile struct {
	Repos     []RPMRepository `yaml:"repos"`
	Port      int             `yaml:"port"`
	GPGKeyURL string          `yaml:"gpg_key_url,omitempty"`
}

// RPMRepository identifies one upstream repository that Pulp may sync.
type RPMRepository struct {
	Name      string `yaml:"name"`
	Upstream  string `yaml:"upstream"`
	GPGKeyURL string `yaml:"gpg_key_url,omitempty"`
}

// OCIProfile configures Harbor proxy-cache projects.
type OCIProfile struct {
	Registries []OCIRegistry `yaml:"registries"`
	Port       int           `yaml:"port"`
}

// OCIRegistry identifies an allowed upstream OCI registry and Harbor project.
type OCIRegistry struct {
	Name         string `yaml:"name"`
	Upstream     string `yaml:"upstream"`
	ProxyProject string `yaml:"proxy_project"`
}

// HarborProfile identifies the official Harbor installer bundle. The bundle
// generates Harbor's supported internal Compose topology; pilot does not
// duplicate that topology in its own template.
type HarborProfile struct {
	Version      string `yaml:"version"`
	InstallerURL string `yaml:"installer_url"`
	HTTPPort     int    `yaml:"http_port"`
}

// StoragePolicy bounds host-side cache growth.
type StoragePolicy struct {
	MaxBytes int64 `yaml:"max_bytes"`
}

// Retention controls cleanup of non-release cache entries.
type Retention struct {
	CacheTTLHours int `yaml:"cache_ttl_hours"`
}

// ClientConfig is the non-secret contract injected into an opted-in VM.
type ClientConfig struct {
	Profile           string            `yaml:"profile"`
	Fingerprint       string            `yaml:"fingerprint"`
	Hostname          string            `yaml:"hostname"`
	AptProxyURL       string            `yaml:"apt_proxy_url"`
	RPMBaseURL        string            `yaml:"rpm_base_url"`
	RegistryMirrorURL string            `yaml:"registry_mirror_url"`
	RegistryProjects  map[string]string `yaml:"registry_projects,omitempty"`
	CAPEM             string            `yaml:"ca_pem"`
}

// BuiltInDevLite is the portable development profile. It deliberately uses
// on-demand upstream content; reproducible release promotion is a separate
// profile concern.
func BuiltInDevLite() Profile {
	return Profile{
		Name: "dev-lite",
		Apt: AptProfile{
			Upstream:  "http://archive.ubuntu.com/ubuntu",
			Allowlist: []string{"archive.ubuntu.com", "security.ubuntu.com"},
			Port:      3142,
		},
		RPM: RPMProfile{
			Port: 8443,
			Repos: []RPMRepository{{
				Name:     "almalinux-9-baseos",
				Upstream: "https://repo.almalinux.org/almalinux/9/BaseOS/x86_64/os/",
			}},
		},
		OCI: OCIProfile{
			Port: 5000,
			Registries: []OCIRegistry{{
				Name:         "docker-hub",
				Upstream:     "https://registry-1.docker.io",
				ProxyProject: "dockerhub",
			}},
		},
		Harbor: HarborProfile{
			Version:      "v2.15.1",
			InstallerURL: "https://github.com/goharbor/harbor/releases/download/v2.15.1/harbor-online-installer-v2.15.1.tgz",
			HTTPPort:     8081,
		},
		Storage:   StoragePolicy{MaxBytes: 100 * 1024 * 1024 * 1024},
		Retention: Retention{CacheTTLHours: 168},
	}
}

// LoadProfile resolves a built-in profile name or a YAML profile path.
func LoadProfile(ref string) (Profile, error) {
	if ref == "" || ref == "local" || ref == "dev-lite" {
		p := BuiltInDevLite()
		return p, p.Validate()
	}
	b, err := os.ReadFile(ref)
	if err != nil {
		return Profile{}, fmt.Errorf("read service profile %q: %w", ref, err)
	}
	var p Profile
	if err := yaml.Unmarshal(b, &p); err != nil {
		return Profile{}, fmt.Errorf("parse service profile %q: %w", ref, err)
	}
	if p.Name == "" {
		p.Name = strings.TrimSuffix(filepath.Base(ref), filepath.Ext(ref))
	}
	if err := p.Validate(); err != nil {
		return Profile{}, fmt.Errorf("service profile %q: %w", ref, err)
	}
	return p, nil
}

// Validate rejects profiles that could result in an unbounded, ambiguous, or
// unsafe host service deployment.
func (p Profile) Validate() error {
	if p.Name == "" || strings.ContainsAny(p.Name, "/\\") {
		return errors.New("name must be non-empty and contain no path separators")
	}
	if p.Apt.Port < 1 || p.Apt.Port > 65535 {
		return fmt.Errorf("apt port %d is invalid", p.Apt.Port)
	}
	if err := validateURL("apt upstream", p.Apt.Upstream, false); err != nil {
		return err
	}
	if len(p.Apt.Allowlist) == 0 {
		return errors.New("apt allowlist must not be empty")
	}
	if p.RPM.Port < 1 || p.RPM.Port > 65535 {
		return fmt.Errorf("rpm port %d is invalid", p.RPM.Port)
	}
	if len(p.RPM.Repos) == 0 {
		return errors.New("rpm repos must not be empty")
	}
	for _, repo := range p.RPM.Repos {
		if repo.Name == "" {
			return errors.New("rpm repository name must not be empty")
		}
		if err := validateURL("rpm upstream", repo.Upstream, true); err != nil {
			return err
		}
	}
	if p.OCI.Port < 1 || p.OCI.Port > 65535 {
		return fmt.Errorf("oci port %d is invalid", p.OCI.Port)
	}
	if len(p.OCI.Registries) == 0 {
		return errors.New("oci registries must not be empty")
	}
	for _, registry := range p.OCI.Registries {
		if registry.Name == "" || registry.ProxyProject == "" {
			return errors.New("oci registry name and proxy_project must not be empty")
		}
		if err := validateURL("oci upstream", registry.Upstream, true); err != nil {
			return err
		}
	}
	if p.Harbor.Version == "" {
		return errors.New("harbor version must not be empty")
	}
	if err := validateURL("harbor installer", p.Harbor.InstallerURL, true); err != nil {
		return err
	}
	if p.Harbor.HTTPPort < 1 || p.Harbor.HTTPPort > 65535 {
		return fmt.Errorf("harbor http port %d is invalid", p.Harbor.HTTPPort)
	}
	if p.Storage.MaxBytes <= 0 {
		return errors.New("storage max_bytes must be positive")
	}
	if p.Retention.CacheTTLHours <= 0 {
		return errors.New("retention cache_ttl_hours must be positive")
	}
	return nil
}

func validateURL(label, raw string, httpsOnly bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("%s must be an absolute URL", label)
	}
	if httpsOnly && u.Scheme != "https" {
		return fmt.Errorf("%s must use https", label)
	}
	return nil
}

// Fingerprint returns a stable content hash for profile identity and state
// invalidation. yaml.v3 preserves struct field order, so map ordering cannot
// change this value.
func (p Profile) Fingerprint() (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	b, err := yaml.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("marshal profile: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// DataRoot returns the persistent host-service root below pilot's data dir.
func DataRoot(dataDir string) string { return filepath.Join(dataDir, "cache") }
