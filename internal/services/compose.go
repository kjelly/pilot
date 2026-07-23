package services

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	serviceHostname = "cache.pilot.internal"
	aptImage        = "sameersbn/apt-cacher-ng:3.7.4"
	pulpImage       = "pulp/pulp:3.85.25"
)

// Bundle identifies generated host-service artifacts and the non-secret
// client contract that can be projected into a VM.
type Bundle struct {
	Root             string
	ComposePath      string
	HarborConfigPath string
	CAPEMPath        string
	CAKeyPath        string
	Client           ClientConfig
}

// RenderBundle creates a deterministic, persistent host-service bundle. Pulp
// follows the official OCI single-container layout; Harbor configuration is
// rendered for the official installer, which owns Harbor's internal Compose
// topology.
func RenderBundle(profile Profile, root string, bindIP net.IP) (Bundle, error) {
	if err := profile.Validate(); err != nil {
		return Bundle{}, err
	}
	if bindIP == nil || bindIP.IsUnspecified() {
		return Bundle{}, fmt.Errorf("service bind IP is required")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return Bundle{}, fmt.Errorf("resolve service root: %w", err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return Bundle{}, fmt.Errorf("create service root: %w", err)
	}
	for _, dir := range []string{"apt", "pulp/settings/certs", "pulp/pulp_storage", "pulp/pgsql", "pulp/containers", "pulp/container_build", "harbor", "ca"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o700); err != nil {
			return Bundle{}, fmt.Errorf("create service directory %s: %w", dir, err)
		}
	}

	caPEM, caKeyPEM, err := loadOrCreateCA(filepath.Join(root, "ca"))
	if err != nil {
		return Bundle{}, err
	}
	caPath := filepath.Join(root, "ca", "ca.pem")
	caKeyPath := filepath.Join(root, "ca", "ca-key.pem")
	if err := writeAtomicMode(caPath, caPEM, 0o644); err != nil {
		return Bundle{}, err
	}
	if err := writeAtomicMode(caKeyPath, caKeyPEM, 0o600); err != nil {
		return Bundle{}, err
	}

	host := bindIP.String()
	compose := renderCompose(profile, root, host)
	composePath := filepath.Join(root, "docker-compose.yml")
	if err := writeAtomicMode(composePath, []byte(compose), 0o600); err != nil {
		return Bundle{}, err
	}
	harborPath := filepath.Join(root, "harbor", "harbor.yml")
	if err := writeAtomicMode(harborPath, []byte(renderHarborYML(profile, root, host)), 0o600); err != nil {
		return Bundle{}, err
	}
	fingerprint, err := profile.Fingerprint()
	if err != nil {
		return Bundle{}, err
	}
	projects := make(map[string]string, len(profile.OCI.Registries))
	for _, registry := range profile.OCI.Registries {
		projects[registry.Name] = fmt.Sprintf("http://%s:%d/%s", serviceHostname, profile.Harbor.HTTPPort, registry.ProxyProject)
	}
	return Bundle{
		Root:             root,
		ComposePath:      composePath,
		HarborConfigPath: harborPath,
		CAPEMPath:        caPath,
		CAKeyPath:        caKeyPath,
		Client: ClientConfig{
			Profile:           profile.Name,
			Fingerprint:       fingerprint,
			Hostname:          serviceHostname,
			AptProxyURL:       fmt.Sprintf("http://%s:%d", serviceHostname, profile.Apt.Port),
			RPMBaseURL:        fmt.Sprintf("http://%s:8080/pulp/content", serviceHostname),
			RegistryMirrorURL: fmt.Sprintf("http://%s:%d", serviceHostname, profile.Harbor.HTTPPort),
			RegistryProjects:  projects,
			CAPEM:             string(caPEM),
		},
	}, nil
}

func renderCompose(profile Profile, root, bindIP string) string {
	q := strconv.Quote
	return strings.Join([]string{
		"services:",
		"  apt-cacher-ng:",
		"    image: " + aptImage,
		"    restart: unless-stopped",
		"    ports:",
		fmt.Sprintf("      - %s", q(fmt.Sprintf("%s:%d:%d", bindIP, profile.Apt.Port, profile.Apt.Port))),
		"    volumes:",
		"      - " + q(filepath.Join(root, "apt")) + ":/var/cache/apt-cacher-ng",
		"    healthcheck:",
		"      test: [\"CMD-SHELL\", \"wget -q -O /dev/null http://127.0.0.1:3142/acng-report.html || exit 1\"]",
		"      interval: 10s",
		"      timeout: 5s",
		"      retries: 12",
		"  pulp:",
		"    image: " + pulpImage,
		"    restart: unless-stopped",
		"    ports:",
		fmt.Sprintf("      - %s", q(fmt.Sprintf("%s:8080:80", bindIP))),
		"    environment:",
		"      PULP_HTTPS: \"false\"",
		fmt.Sprintf("      CONTENT_ORIGIN: %s", q("http://"+serviceHostname+":8080")),
		"    volumes:",
		"      - " + q(filepath.Join(root, "pulp", "settings")) + ":/etc/pulp",
		"      - " + q(filepath.Join(root, "pulp", "pulp_storage")) + ":/var/lib/pulp",
		"      - " + q(filepath.Join(root, "pulp", "pgsql")) + ":/var/lib/pgsql",
		"      - " + q(filepath.Join(root, "pulp", "containers")) + ":/var/lib/containers",
		"      - " + q(filepath.Join(root, "pulp", "container_build")) + ":/var/lib/pulp/.local/share/containers",
		"    devices:",
		"      - /dev/fuse:/dev/fuse",
		"    healthcheck:",
		"      test: [\"CMD-SHELL\", \"curl -fsS http://127.0.0.1/pulp/api/v3/status/ || exit 1\"]",
		"      interval: 15s",
		"      timeout: 5s",
		"      retries: 20",
		"", // Harbor is generated by its official installer in harbor/.
	}, "\n")
}

func renderHarborYML(profile Profile, root, host string) string {
	data := filepath.Join(root, "harbor", "data")
	return strings.Join([]string{
		"hostname: " + host,
		"http:",
		fmt.Sprintf("  port: %d", profile.Harbor.HTTPPort),
		"harbor_admin_password: change-me-before-production",
		"database:",
		"  password: change-me-before-production",
		"  max_idle_conns: 100",
		"  max_open_conns: 900",
		"data_volume: " + data,
		"log:",
		"  level: info",
		"  rotate_count: 10",
		"  rotate_size: 100M",
		"  location: " + filepath.Join(root, "harbor", "logs"),
		"", // Harbor installer fills the generated Compose topology.
	}, "\n")
}

func loadOrCreateCA(dir string) ([]byte, []byte, error) {
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")
	cert, certErr := os.ReadFile(certPath)
	key, keyErr := os.ReadFile(keyPath)
	if certErr == nil && keyErr == nil {
		return cert, key, nil
	}
	if !os.IsNotExist(certErr) || !os.IsNotExist(keyErr) {
		return nil, nil, fmt.Errorf("read service CA: cert=%v key=%v", certErr, keyErr)
	}
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate service CA key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("generate service CA serial: %w", err)
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "pilot host services CA"},
		NotBefore:    now.Add(-time.Minute), NotAfter: now.AddDate(10, 0, 0),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &private.PublicKey, private)
	if err != nil {
		return nil, nil, fmt.Errorf("create service CA: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal service CA key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

func writeAtomicMode(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".pilot-service-*.tmp")
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("install %s: %w", path, err)
	}
	return nil
}
