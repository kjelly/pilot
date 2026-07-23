package vmtarget

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var safeServiceHostname = regexp.MustCompile(`^[A-Za-z0-9.-]+$`)

// ServiceBootstrap is the non-secret host-service client contract rendered
// into a VM's cloud-init seed.
type ServiceBootstrap struct {
	Profile           string
	Fingerprint       string
	HostIP            string
	Hostname          string
	AptProxyURL       string
	RPMBaseURL        string
	RegistryMirrorURL string
	RegistryProjects  map[string]string
	CAPEM             string
}

// Validate checks values before they become cloud-init content.
func (s ServiceBootstrap) Validate() error {
	if s.Profile == "" || s.Fingerprint == "" {
		return errors.New("service profile and fingerprint are required")
	}
	if !safeServiceHostname.MatchString(s.Hostname) {
		return fmt.Errorf("service hostname %q is invalid", s.Hostname)
	}
	if s.HostIP != "" && net.ParseIP(s.HostIP) == nil {
		return fmt.Errorf("service host IP %q is invalid", s.HostIP)
	}
	for label, raw := range map[string]string{"apt proxy": s.AptProxyURL, "rpm base": s.RPMBaseURL, "registry mirror": s.RegistryMirrorURL} {
		if err := validateServiceURL(label, raw); err != nil {
			return err
		}
	}
	if s.CAPEM == "" {
		return errors.New("service CA is required")
	}
	block := strings.TrimSpace(s.CAPEM)
	decoded, _ := pem.Decode([]byte(block))
	if decoded == nil || decoded.Type != "CERTIFICATE" {
		return errors.New("service CA is not a valid PEM certificate")
	}
	if _, err := x509.ParseCertificate(decoded.Bytes); err != nil {
		return fmt.Errorf("service CA is not a valid certificate: %w", err)
	}
	for name, target := range s.RegistryProjects {
		if name == "" || strings.ContainsAny(name, "\n\r/ ") {
			return fmt.Errorf("registry project name %q is invalid", name)
		}
		if err := validateServiceURL("registry project "+name, target); err != nil {
			return err
		}
	}
	return nil
}

func validateServiceURL(label, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || strings.ContainsAny(raw, "\n\r\t") {
		return fmt.Errorf("%s URL is invalid", label)
	}
	return nil
}

// RenderCloudInit returns the write_files/runcmd fragment for an existing
// cloud-config document. Values are validated and JSON-quoted where they are
// embedded in shell command arguments.
func (s ServiceBootstrap) RenderCloudInit() (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("write_files:\n")
	b.WriteString("  - path: /usr/local/share/ca-certificates/pilot-services.crt\n")
	b.WriteString("    permissions: '0644'\n    content: |\n")
	for _, line := range strings.Split(strings.TrimSpace(s.CAPEM), "\n") {
		fmt.Fprintf(&b, "      %s\n", line)
	}
	b.WriteString("  - path: /etc/apt/apt.conf.d/99pilot-services\n")
	b.WriteString("    permissions: '0644'\n    content: |\n")
	fmt.Fprintf(&b, "      Acquire::http::Proxy %s;\n", strconv.Quote(s.AptProxyURL))
	fmt.Fprintf(&b, "      Acquire::https::Proxy %s;\n", strconv.Quote(s.AptProxyURL))
	b.WriteString("  - path: /etc/yum.repos.d/pilot-services.repo\n")
	b.WriteString("    permissions: '0644'\n    content: |\n")
	b.WriteString("      [pilot-pulp]\n      name=pilot-pulp\n      enabled=1\n      gpgcheck=0\n")
	fmt.Fprintf(&b, "      baseurl=%s\n", s.RPMBaseURL)
	projects, _ := json.Marshal(s.RegistryProjects)
	b.WriteString("  - path: /etc/pilot/registry-projects.json\n")
	b.WriteString("    permissions: '0644'\n    content: |\n")
	fmt.Fprintf(&b, "      %s\n", projects)
	b.WriteString("  - path: /etc/docker/daemon.json\n")
	b.WriteString("    permissions: '0644'\n    content: |\n")
	config, _ := json.Marshal(map[string]any{
		"registry-mirrors":    []string{s.RegistryMirrorURL},
		"insecure-registries": []string{strings.TrimPrefix(s.RegistryMirrorURL, "http://")},
	})
	fmt.Fprintf(&b, "      %s\n", config)
	b.WriteString("runcmd:\n")
	if s.HostIP != "" {
		fmt.Fprintf(&b, "  - [sh, -c, 'grep -qF %s /etc/hosts || printf \"%%s %%s\\n\" %s %s >> /etc/hosts']\n", strconv.Quote(s.HostIP+" "+s.Hostname), strconv.Quote(s.HostIP), strconv.Quote(s.Hostname))
	}
	b.WriteString("  - [sh, -c, 'if command -v update-ca-certificates >/dev/null 2>&1; then update-ca-certificates; elif command -v update-ca-trust >/dev/null 2>&1; then update-ca-trust extract; else exit 1; fi']\n")
	fmt.Fprintf(&b, "  - [sh, -c, 'if command -v curl >/dev/null 2>&1; then curl --fail --silent --show-error --cacert /usr/local/share/ca-certificates/pilot-services.crt %s/pulp/api/v3/status/; elif command -v wget >/dev/null 2>&1; then wget --ca-certificate=/usr/local/share/ca-certificates/pilot-services.crt -qO- %s/pulp/api/v3/status/; else exit 1; fi']\n", s.RPMBaseURL, s.RPMBaseURL)
	fmt.Fprintf(&b, "  - [sh, -c, 'if command -v curl >/dev/null 2>&1; then curl --fail --silent --show-error %s/v2/; elif command -v wget >/dev/null 2>&1; then wget -qO- %s/v2/; else exit 1; fi']\n", s.RegistryMirrorURL, s.RegistryMirrorURL)
	return b.String(), nil
}
