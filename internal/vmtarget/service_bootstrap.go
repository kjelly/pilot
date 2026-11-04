package vmtarget

import (
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/kjelly/pilot/internal/services"
)

//go:embed service_probe.py
var serviceProbePython string

var safeServiceHostname = regexp.MustCompile(`^[A-Za-z0-9.-]+$`)

// ServiceBootstrap is the non-secret host-service client contract rendered
// into a VM's cloud-init seed.
type ServiceBootstrap struct {
	DiscoveryDirectory string
	InstanceID         string
	Generation         uint64
	Profile            string
	Fingerprint        string
	HostIP             string
	Hostname           string
	AptProxyURL        string
	RPMBaseURL         string
	RPMRepositories    map[string]string
	RegistryMirrorURL  string
	RegistryProjects   map[string]string
	CAPEM              string
	PhysicalProfile    *services.Profile
	Requirements       services.Requirements
	DataProbes         map[services.Capability]services.DataProbe
}

// Validate checks values before they become cloud-init content.
func (s ServiceBootstrap) Validate() error {
	required, err := services.NormalizeRequirements(s.Requirements)
	if err != nil {
		return err
	}
	for _, c := range required {
		probe, ok := s.DataProbes[c]
		if !ok {
			return fmt.Errorf("required %s cache missing data_probes descriptor", c)
		}
		if e := probe.Validate(c); e != nil {
			return e
		}
	}
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
		if (label == "apt proxy" && !s.Requirements.Has(services.APT)) || (label == "rpm base" && !s.Requirements.Has(services.RPM)) || (label == "registry mirror" && !s.Requirements.Has(services.OCI)) {
			continue
		}
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
	if s.InstanceID != "" {
		identity, _ := json.Marshal(map[string]any{"instance_id": s.InstanceID, "generation": s.Generation})
		b.WriteString("  - path: /etc/pilot/service-instance.json\n    permissions: '0644'\n    content: |\n")
		fmt.Fprintf(&b, "      %s\n", identity)
	}
	b.WriteString("  - path: /usr/local/share/ca-certificates/pilot-services.crt\n")
	b.WriteString("    permissions: '0644'\n    content: |\n")
	for _, line := range strings.Split(strings.TrimSpace(s.CAPEM), "\n") {
		fmt.Fprintf(&b, "      %s\n", line)
	}
	if s.Requirements.Has(services.APT) {
		b.WriteString("  - path: /etc/apt/apt.conf.d/99pilot-services\n")
		b.WriteString("    permissions: '0644'\n    content: |\n")
		fmt.Fprintf(&b, "      Acquire::http::Proxy %s;\n", strconv.Quote(s.AptProxyURL))
		fmt.Fprintf(&b, "      Acquire::https::Proxy %s;\n", strconv.Quote(s.AptProxyURL))
	}
	if s.Requirements.Has(services.RPM) {
		b.WriteString("  - path: /etc/yum.repos.d/pilot-services.repo\n")
		b.WriteString("    permissions: '0644'\n    content: |\n")
		repositories := s.RPMRepositories
		if len(repositories) == 0 {
			repositories = map[string]string{"pilot": s.RPMBaseURL}
		}
		names := make([]string, 0, len(repositories))
		for name := range repositories {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			fmt.Fprintf(&b, "      [pilot-pulp-%s]\n      name=pilot-pulp-%s\n      enabled=1\n      gpgcheck=0\n      baseurl=%s\n", name, name, repositories[name])
		}
	}
	if s.Requirements.Has(services.OCI) {
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
	}
	b.WriteString("  - path: /usr/local/lib/pilot-service-probe.py\n    permissions: '0644'\n    content: |\n")
	for _, line := range strings.Split(strings.TrimRight(serviceProbePython, "\n"), "\n") {
		fmt.Fprintf(&b, "      %s\n", line)
	}
	b.WriteString("runcmd:\n")
	if s.HostIP != "" {
		fmt.Fprintf(&b, "  - [sh, -c, 'grep -qF %s /etc/hosts || printf \"%%s %%s\\n\" %s %s >> /etc/hosts']\n", strconv.Quote(s.HostIP+" "+s.Hostname), strconv.Quote(s.HostIP), strconv.Quote(s.Hostname))
	}
	b.WriteString("  - [sh, -c, 'if command -v update-ca-certificates >/dev/null 2>&1; then update-ca-certificates; elif command -v update-ca-trust >/dev/null 2>&1; then update-ca-trust extract; else exit 1; fi']\n")
	for _, c := range []services.Capability{services.APT, services.RPM, services.OCI} {
		if !s.Requirements.Has(c) {
			continue
		}
		descriptor, ok := s.DataProbes[c]
		if !ok {
			continue
		}
		if e := descriptor.Validate(c); e != nil {
			return "", e
		}
		endpoint := s.AptProxyURL
		if c == services.RPM {
			endpoint = s.RPMBaseURL
		}
		if c == services.OCI {
			endpoint = s.RegistryMirrorURL
		}
		config, _ := json.Marshal(map[string]string{"capability": string(c), "endpoint": endpoint, "bind_ip": s.HostIP, "resource": descriptor.Resource, "sha256": descriptor.SHA256, "contains": descriptor.Contains})
		command, _ := json.Marshal([]string{"timeout", "10", "python3", "/usr/local/lib/pilot-service-probe.py", string(config)})
		fmt.Fprintf(&b, "  - %s\n", command)
	}
	return b.String(), nil
}
