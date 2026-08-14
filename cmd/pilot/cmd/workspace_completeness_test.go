package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/inventory"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func findCheck(t *testing.T, checks []completenessCheck, label string) completenessCheck {
	t.Helper()
	for _, c := range checks {
		if c.Label == label {
			return c
		}
	}
	t.Fatalf("no check with label %q in %+v", label, checks)
	return completenessCheck{}
}

func TestCheckWorkspaceCompleteness_NoHostsYmlReportsOnlyTheTwoFiles(t *testing.T) {
	dir := t.TempDir()

	got := checkWorkspaceCompleteness(dir)

	if len(got) != 2 {
		t.Fatalf("checkWorkspaceCompleteness() = %+v, want exactly 2 rows", got)
	}
	if got[0].Label != "hosts.yml" || got[0].OK {
		t.Fatalf("row 0 = %+v, want hosts.yml/not-OK", got[0])
	}
	if got[1].Label != "inventory.yml" || got[1].OK {
		t.Fatalf("row 1 = %+v, want inventory.yml/not-OK", got[1])
	}
}

func TestCheckWorkspaceCompleteness_InventoryYmlOKWhenFreshlyGenerated(t *testing.T) {
	dir := t.TempDir()
	hostsData := "hosts: {}\n"
	writeFile(t, filepath.Join(dir, "hosts.yml"), hostsData)

	hf, err := inventory.Parse([]byte(hostsData))
	if err != nil {
		t.Fatalf("inventory.Parse() error = %v", err)
	}
	rendered, err := inventory.Generate(hf)
	if err != nil {
		t.Fatalf("inventory.Generate() error = %v", err)
	}
	writeFile(t, filepath.Join(dir, "inventory.yml"), rendered)

	got := checkWorkspaceCompleteness(dir)

	if c := findCheck(t, got, "hosts.yml"); !c.OK {
		t.Fatalf("hosts.yml = %+v, want OK", c)
	}
	if c := findCheck(t, got, "inventory.yml"); !c.OK {
		t.Fatalf("inventory.yml = %+v, want OK", c)
	}
}

func TestCheckWorkspaceCompleteness_InventoryYmlStaleWhenHostsYmlChangedSince(t *testing.T) {
	dir := t.TempDir()
	// inventory.yml reflects an empty hosts.yml; hosts.yml now has a host —
	// `pilot inventory generate` was never rerun since.
	writeFile(t, filepath.Join(dir, "hosts.yml"), `hosts:
  nexus:
    ansible_host: 10.0.0.1
    roles: [dns]
`)
	staleHf, err := inventory.Parse([]byte("hosts: {}\n"))
	if err != nil {
		t.Fatalf("inventory.Parse() error = %v", err)
	}
	staleRendered, err := inventory.Generate(staleHf)
	if err != nil {
		t.Fatalf("inventory.Generate() error = %v", err)
	}
	writeFile(t, filepath.Join(dir, "inventory.yml"), staleRendered)

	got := checkWorkspaceCompleteness(dir)

	c := findCheck(t, got, "inventory.yml")
	if c.OK {
		t.Fatalf("inventory.yml = %+v, want not-OK (stale relative to hosts.yml)", c)
	}
}

func TestCheckWorkspaceCompleteness_InventoryYmlMissingReportsNotExist(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "hosts.yml"), "hosts: {}\n")

	got := checkWorkspaceCompleteness(dir)

	c := findCheck(t, got, "inventory.yml")
	if c.OK || len(c.Details) != 1 || c.Details[0] != "不存在" {
		t.Fatalf("inventory.yml = %+v, want not-OK/不存在", c)
	}
}

func TestCheckWorkspaceCompleteness_ReportsMissingGroupVarsStem(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "hosts.yml"), `hosts:
  nexus:
    ansible_host: 10.0.0.1
    roles: [dns]
`)

	got := checkWorkspaceCompleteness(dir)

	c := findCheck(t, got, filepath.Join("group_vars", "dns.yml"))
	if c.OK {
		t.Fatalf("group_vars/dns.yml = %+v, want not-OK (file missing)", c)
	}
}

func TestCheckWorkspaceCompleteness_GroupVarsOKWhenFileExists(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "hosts.yml"), `hosts:
  nexus:
    ansible_host: 10.0.0.1
    roles: [dns]
`)
	writeFile(t, filepath.Join(dir, "group_vars", "dns.yml"), "---\ndns_forwarders: [1.1.1.1]\n")

	got := checkWorkspaceCompleteness(dir)

	if c := findCheck(t, got, filepath.Join("group_vars", "dns.yml")); !c.OK {
		t.Fatalf("group_vars/dns.yml = %+v, want OK", c)
	}
}

const workspaceHostsWithPrometheus = `hosts:
  nexus:
    ansible_host: 10.0.0.1
    roles: [prometheus]
`

// TestCheckWorkspaceCompleteness_ReportsUnfilledS3EitherOr covers finding
// #3: an unedited copy of group_vars/prometheus.example.yml (thanos_s3_target_host
// left at its shipped "" default, thanos_s3_endpoint never uncommented) must
// not read as complete — prometheus-apply.yml's own gate would fail on it.
func TestCheckWorkspaceCompleteness_ReportsUnfilledS3EitherOr(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "hosts.yml"), workspaceHostsWithPrometheus)
	writeFile(t, filepath.Join(dir, "group_vars", "prometheus.yml"), `---
thanos_s3_target_host: ""
# thanos_s3_endpoint: "s3.internal.example.com:443"
`)

	got := checkWorkspaceCompleteness(dir)

	c := findCheck(t, got, filepath.Join("group_vars", "prometheus.yml"))
	if c.OK {
		t.Fatalf("group_vars/prometheus.yml = %+v, want not-OK (neither S3 setting resolved)", c)
	}
	if len(c.Details) == 0 || !strings.Contains(c.Details[0], "thanos_s3_target_host") {
		t.Fatalf("group_vars/prometheus.yml details = %v, want a thanos_s3_target_host complaint", c.Details)
	}
}

func TestCheckWorkspaceCompleteness_S3EitherOrOKWhenTargetHostFilled(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "hosts.yml"), workspaceHostsWithPrometheus)
	writeFile(t, filepath.Join(dir, "group_vars", "prometheus.yml"), "---\nthanos_s3_target_host: \"10.0.0.50\"\n")

	got := checkWorkspaceCompleteness(dir)

	if c := findCheck(t, got, filepath.Join("group_vars", "prometheus.yml")); !c.OK {
		t.Fatalf("group_vars/prometheus.yml = %+v, want OK", c)
	}
}

func TestCheckWorkspaceCompleteness_S3EitherOrOKWhenEndpointOverridden(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "hosts.yml"), workspaceHostsWithPrometheus)
	writeFile(t, filepath.Join(dir, "group_vars", "prometheus.yml"), `---
thanos_s3_target_host: ""
thanos_s3_endpoint: "s3.internal.example.com:443"
`)

	got := checkWorkspaceCompleteness(dir)

	if c := findCheck(t, got, filepath.Join("group_vars", "prometheus.yml")); !c.OK {
		t.Fatalf("group_vars/prometheus.yml = %+v, want OK (endpoint overridden away from the shared alias)", c)
	}
}

func TestCheckWorkspaceCompleteness_S3EitherOrAutoDetectsSeaweedfsForPrometheus(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "hosts.yml"), `hosts:
  nexus:
    ansible_host: 10.0.0.1
    roles: [prometheus, seaweedfs-s3]
`)
	writeFile(t, filepath.Join(dir, "group_vars", "prometheus.yml"), "---\nthanos_s3_target_host: \"\"\n")

	got := checkWorkspaceCompleteness(dir)
	if c := findCheck(t, got, filepath.Join("group_vars", "prometheus.yml")); !c.OK {
		t.Fatalf("group_vars/prometheus.yml = %+v, want OK (seaweedfs-s3 provides the auto-detected target)", c)
	}
}

func TestCheckWorkspaceCompleteness_S3EitherOrAutoDetectsSeaweedfsForThanosQuery(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "hosts.yml"), `hosts:
  nexus:
    ansible_host: 10.0.0.1
    roles: [thanos-query, seaweedfs-s3]
`)
	writeFile(t, filepath.Join(dir, "group_vars", "thanos-query.yml"), "---\nthanos_s3_target_host: \"\"\n")

	got := checkWorkspaceCompleteness(dir)
	if c := findCheck(t, got, filepath.Join("group_vars", "thanos-query.yml")); !c.OK {
		t.Fatalf("group_vars/thanos-query.yml = %+v, want OK (seaweedfs-s3 provides the auto-detected target)", c)
	}
}

// TestCheckWorkspaceCompleteness_S3EitherOrAppliesToResticBackupToo proves
// the catalog isn't hardcoded to prometheus's key names — restic-backup
// uses a different alias/key pair for the same shape of gate.
func TestCheckWorkspaceCompleteness_S3EitherOrAppliesToResticBackupToo(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "hosts.yml"), `hosts:
  nexus:
    ansible_host: 10.0.0.1
    roles: [restic-backup]
`)
	writeFile(t, filepath.Join(dir, "group_vars", "restic-backup.yml"), "---\nrestic_s3_target_host: \"\"\n")

	got := checkWorkspaceCompleteness(dir)

	c := findCheck(t, got, filepath.Join("group_vars", "restic-backup.yml"))
	if c.OK {
		t.Fatalf("group_vars/restic-backup.yml = %+v, want not-OK", c)
	}
	if len(c.Details) == 0 || !strings.Contains(c.Details[0], "restic_s3_target_host") {
		t.Fatalf("group_vars/restic-backup.yml details = %v, want a restic_s3_target_host complaint", c.Details)
	}
}

// TestCheckWorkspaceCompleteness_ResticS3EitherOrOKWhenSeaweedfsS3Present
// covers finding #1: restic-backup-apply.yml auto-derives
// restic_s3_target_host at runtime whenever the inventory has a
// seaweedfs-s3 host, regardless of group_vars content — so this should
// not read as a violation, just an informational note.
func TestCheckWorkspaceCompleteness_ResticS3EitherOrOKWhenSeaweedfsS3Present(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "hosts.yml"), `hosts:
  nexus:
    ansible_host: 10.0.0.1
    roles: [restic-backup]
  s3-1:
    ansible_host: 10.0.0.2
    roles: [seaweedfs-s3]
`)
	writeFile(t, filepath.Join(dir, "group_vars", "restic-backup.yml"), "---\nrestic_s3_target_host: \"\"\n")

	got := checkWorkspaceCompleteness(dir)

	c := findCheck(t, got, filepath.Join("group_vars", "restic-backup.yml"))
	if !c.OK {
		t.Fatalf("group_vars/restic-backup.yml = %+v, want OK (seaweedfs-s3 present, auto-derived at runtime)", c)
	}
	if len(c.Details) == 0 || !strings.Contains(c.Details[0], "seaweedfs-s3") {
		t.Fatalf("group_vars/restic-backup.yml details = %v, want a note about the seaweedfs-s3 auto-derivation", c.Details)
	}
}

// TestCheckWorkspaceCompleteness_ResticS3AutoDetectSkippedWhenRepositoryExplicitlyBlank
// covers a review finding on top of #1: the carve-out must not apply once
// restic_repository has been explicitly set to something — even a blank
// string. restic-backup-apply.yml's own auto-detect task only fires `when:
// ... and (restic_s3_alias in restic_repository) and ...`; an explicit blank
// value makes that condition false too, so this would silently strand the
// deploy with no real destination instead of the fail-fast this gate
// promises.
func TestCheckWorkspaceCompleteness_ResticS3AutoDetectSkippedWhenRepositoryExplicitlyBlank(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "hosts.yml"), `hosts:
  nexus:
    ansible_host: 10.0.0.1
    roles: [restic-backup]
  s3-1:
    ansible_host: 10.0.0.2
    roles: [seaweedfs-s3]
`)
	writeFile(t, filepath.Join(dir, "group_vars", "restic-backup.yml"), "---\nrestic_s3_target_host: \"\"\nrestic_repository: \"\"\n")

	got := checkWorkspaceCompleteness(dir)

	c := findCheck(t, got, filepath.Join("group_vars", "restic-backup.yml"))
	if c.OK {
		t.Fatalf("group_vars/restic-backup.yml = %+v, want not-OK (repository explicitly blank — the playbook's own auto-detect condition would also be false)", c)
	}
	if len(c.Details) == 0 || !strings.Contains(c.Details[0], "restic_s3_target_host") {
		t.Fatalf("group_vars/restic-backup.yml details = %v, want a restic_s3_target_host complaint", c.Details)
	}
}

// TestCheckWorkspaceCompleteness_PrometheusS3AutoDetectedWithSeaweedfsS3 verifies
// the completeness report matches pilot deploy's inventory-derived prompt.
func TestCheckWorkspaceCompleteness_PrometheusS3AutoDetectedWithSeaweedfsS3(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "hosts.yml"), `hosts:
  nexus:
    ansible_host: 10.0.0.1
    roles: [prometheus]
  s3-1:
    ansible_host: 10.0.0.2
    roles: [seaweedfs-s3]
`)
	writeFile(t, filepath.Join(dir, "group_vars", "prometheus.yml"), "---\nthanos_s3_target_host: \"\"\n")

	got := checkWorkspaceCompleteness(dir)

	c := findCheck(t, got, filepath.Join("group_vars", "prometheus.yml"))
	if !c.OK {
		t.Fatalf("group_vars/prometheus.yml = %+v, want OK — pilot deploy auto-detects seaweedfs-s3", c)
	}
}

// TestCheckWorkspaceCompleteness_ReportsActiveEmptyEndpointAsUnsatisfied
// covers finding #2: an active-but-blank thanos_s3_endpoint must not read
// as "overridden away from the alias" — it isn't a resolvable address.
func TestCheckWorkspaceCompleteness_ReportsActiveEmptyEndpointAsUnsatisfied(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "hosts.yml"), workspaceHostsWithPrometheus)
	writeFile(t, filepath.Join(dir, "group_vars", "prometheus.yml"), `---
thanos_s3_target_host: ""
thanos_s3_endpoint: ""
`)

	got := checkWorkspaceCompleteness(dir)

	c := findCheck(t, got, filepath.Join("group_vars", "prometheus.yml"))
	if c.OK {
		t.Fatalf("group_vars/prometheus.yml = %+v, want not-OK (active but blank endpoint isn't a real override)", c)
	}
}

// TestCheckWorkspaceCompleteness_NoRosterRowForClientOnlyRoles covers
// finding #3: freeipa-client/freeipa-nfs-client enrollment never reads
// the roster, so their mere presence shouldn't trigger a "prepare a
// roster" guess the way freeipa-server/-nfs-server does.
func TestCheckWorkspaceCompleteness_NoRosterRowForClientOnlyRoles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "hosts.yml"), `hosts:
  client-1:
    ansible_host: 10.0.0.1
    roles: [freeipa-client]
  client-2:
    ansible_host: 10.0.0.2
    roles: [freeipa-nfs-client]
`)

	got := checkWorkspaceCompleteness(dir)

	for _, c := range got {
		if strings.HasPrefix(c.Label, "roster") {
			t.Fatalf("unexpected roster row %+v — client-only roles never read the roster", c)
		}
	}
}

func TestCheckWorkspaceCompleteness_NoInternalEndpointRowWhenManifestAbsent(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "hosts.yml"), `hosts:
  nexus:
    ansible_host: 10.0.0.10
    roles: []
`)

	got := checkWorkspaceCompleteness(dir)

	for _, c := range got {
		if c.Label == "internal-endpoints.yaml" {
			t.Fatalf("unexpected internal-endpoints.yaml row %+v — the manifest is opt-in and doesn't exist", c)
		}
	}
}

func TestCheckWorkspaceCompleteness_InternalEndpointReportsUnresolvedInventoryHost(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "hosts.yml"), `hosts:
  nexus:
    ansible_host: 10.0.0.10
    roles: []
`)
	iepPath := filepath.Join(dir, "internal-endpoints.yaml")
	if err := inventory.CreateMinimalInternalEndpointManifest(iepPath); err != nil {
		t.Fatalf("CreateMinimalInternalEndpointManifest() error = %v", err)
	}
	if err := inventory.AppendInternalEndpoint(iepPath, map[string]any{
		"fqdn":  "direct.svc.pilot.internal",
		"state": "present",
		"dns":   map[string]any{"zone": "svc.pilot.internal."},
		"route": map[string]any{"mode": "direct", "target": map[string]any{"inventory_host": "does-not-exist"}},
		"tls":   map[string]any{"mode": "disabled"},
	}); err != nil {
		t.Fatalf("AppendInternalEndpoint() error = %v", err)
	}

	got := checkWorkspaceCompleteness(dir)

	c := findCheck(t, got, "internal-endpoints.yaml")
	if c.OK {
		t.Fatalf("internal-endpoints.yaml = %+v, want not-OK for an unresolvable route.target.inventory_host", c)
	}
	if !strings.Contains(strings.Join(c.Details, "\n"), "does-not-exist") {
		t.Fatalf("internal-endpoints.yaml details = %v, want a complaint naming does-not-exist", c.Details)
	}
}

func TestCheckWorkspaceCompleteness_InternalEndpointOKWithValidDirectAndProxyRoutes(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "hosts.yml"), `hosts:
  app01:
    ansible_host: 10.0.0.11
    roles: []
  lb01:
    ansible_host: 10.0.0.12
    roles: [reverse-proxy]
`)
	iepPath := filepath.Join(dir, "internal-endpoints.yaml")
	if err := inventory.CreateMinimalInternalEndpointManifest(iepPath); err != nil {
		t.Fatalf("CreateMinimalInternalEndpointManifest() error = %v", err)
	}
	if err := inventory.AppendInternalEndpoint(iepPath, map[string]any{
		"fqdn":  "direct.svc.pilot.internal",
		"state": "present",
		"dns":   map[string]any{"zone": "svc.pilot.internal."},
		"route": map[string]any{"mode": "direct", "target": map[string]any{"inventory_host": "app01"}},
		"tls":   map[string]any{"mode": "disabled"},
	}); err != nil {
		t.Fatalf("AppendInternalEndpoint(direct) error = %v", err)
	}
	if err := inventory.AppendInternalEndpoint(iepPath, map[string]any{
		"fqdn":  "proxy.svc.pilot.internal",
		"state": "present",
		"dns":   map[string]any{"zone": "svc.pilot.internal."},
		"route": map[string]any{
			"mode":     "reverse_proxy",
			"proxy":    map[string]any{"provider": "nginx", "inventory_host": "lb01"},
			"upstream": map[string]any{"scheme": "http", "inventory_host": "app01", "port": 8080},
		},
		"tls": map[string]any{"mode": "disabled"},
	}); err != nil {
		t.Fatalf("AppendInternalEndpoint(proxy) error = %v", err)
	}

	got := checkWorkspaceCompleteness(dir)

	c := findCheck(t, got, "internal-endpoints.yaml")
	if !c.OK {
		t.Fatalf("internal-endpoints.yaml = %+v, want OK", c)
	}
}

func TestCheckWorkspaceCompleteness_InternalEndpointReportsProxyHostWithoutReverseProxyRole(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "hosts.yml"), `hosts:
  app01:
    ansible_host: 10.0.0.11
    roles: []
  lb01:
    ansible_host: 10.0.0.12
    roles: []
`)
	iepPath := filepath.Join(dir, "internal-endpoints.yaml")
	if err := inventory.CreateMinimalInternalEndpointManifest(iepPath); err != nil {
		t.Fatalf("CreateMinimalInternalEndpointManifest() error = %v", err)
	}
	if err := inventory.AppendInternalEndpoint(iepPath, map[string]any{
		"fqdn":  "proxy.svc.pilot.internal",
		"state": "present",
		"dns":   map[string]any{"zone": "svc.pilot.internal."},
		"route": map[string]any{
			"mode":     "reverse_proxy",
			"proxy":    map[string]any{"provider": "nginx", "inventory_host": "lb01"},
			"upstream": map[string]any{"scheme": "http", "inventory_host": "app01", "port": 8080},
		},
		"tls": map[string]any{"mode": "disabled"},
	}); err != nil {
		t.Fatalf("AppendInternalEndpoint(proxy) error = %v", err)
	}

	got := checkWorkspaceCompleteness(dir)

	c := findCheck(t, got, "internal-endpoints.yaml")
	if c.OK {
		t.Fatalf("internal-endpoints.yaml = %+v, want not-OK — lb01 lacks the reverse-proxy role", c)
	}
}

func TestCheckWorkspaceCompleteness_ReportsMissingVaultFile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "hosts.yml"), workspaceHostsWithPrometheus)

	got := checkWorkspaceCompleteness(dir)

	c := findCheck(t, got, filepath.Join(".vault", "main.yaml"))
	if c.OK || len(c.Details) != 1 || c.Details[0] != "不存在" {
		t.Fatalf(".vault/main.yaml = %+v, want not-OK/不存在", c)
	}
}

func TestCheckWorkspaceCompleteness_ReportsVaultChangeMePlaceholder(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "hosts.yml"), workspaceHostsWithPrometheus)
	writeFile(t, filepath.Join(dir, ".vault", "main.yaml"),
		"---\nthanos_aws_access_key_id: \"CHANGE-ME-thanos-access-key\"\nthanos_aws_secret_access_key: \"real-secret\"\n")

	got := checkWorkspaceCompleteness(dir)

	c := findCheck(t, got, filepath.Join(".vault", "main.yaml"))
	if c.OK {
		t.Fatalf(".vault/main.yaml = %+v, want not-OK", c)
	}
	joined := strings.Join(c.Details, "\n")
	if !strings.Contains(joined, "thanos_aws_access_key_id") || !strings.Contains(joined, "CHANGE-ME") {
		t.Fatalf(".vault/main.yaml details = %v, want a CHANGE-ME complaint about thanos_aws_access_key_id", c.Details)
	}
}

func TestCheckWorkspaceCompleteness_VaultOKWhenFilledIn(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "hosts.yml"), workspaceHostsWithPrometheus)
	writeFile(t, filepath.Join(dir, ".vault", "main.yaml"),
		"---\nthanos_aws_access_key_id: \"AKIAEXAMPLE\"\nthanos_aws_secret_access_key: \"a-real-secret\"\nnode_exporter_basic_auth_password: \"a-real-password\"\n")

	got := checkWorkspaceCompleteness(dir)

	if c := findCheck(t, got, filepath.Join(".vault", "main.yaml")); !c.OK {
		t.Fatalf(".vault/main.yaml = %+v, want OK", c)
	}
}

func TestCheckWorkspaceCompleteness_VaultEncryptedSkipsContentCheck(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "hosts.yml"), workspaceHostsWithPrometheus)
	writeFile(t, filepath.Join(dir, ".vault", "main.yaml"), "$ANSIBLE_VAULT;1.1;AES256\n633864363...\n")

	got := checkWorkspaceCompleteness(dir)

	c := findCheck(t, got, filepath.Join(".vault", "main.yaml"))
	if !c.OK {
		t.Fatalf(".vault/main.yaml = %+v, want OK (can't verify, but not a violation)", c)
	}
}

func TestCheckWorkspaceCompleteness_ReportsUnfilledHostVarsKey(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "hosts.yml"), workspaceHostsWithPrometheus)

	got := checkWorkspaceCompleteness(dir)

	c := findCheck(t, got, filepath.Join("host_vars", "nexus.yml"))
	if c.OK {
		t.Fatalf("host_vars/nexus.yml = %+v, want not-OK", c)
	}
	if len(c.Details) != 1 || !strings.Contains(c.Details[0], "prometheus_site_label") {
		t.Fatalf("host_vars/nexus.yml details = %v, want a prometheus_site_label complaint", c.Details)
	}
}

func TestCheckWorkspaceCompleteness_HostVarsOKWhenFileFillsKey(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "hosts.yml"), workspaceHostsWithPrometheus)
	writeFile(t, filepath.Join(dir, "host_vars", "nexus.yml"), "---\nprometheus_site_label: site-nexus\n")

	got := checkWorkspaceCompleteness(dir)

	if c := findCheck(t, got, filepath.Join("host_vars", "nexus.yml")); !c.OK {
		t.Fatalf("host_vars/nexus.yml = %+v, want OK", c)
	}
}

func TestCheckWorkspaceCompleteness_HostVarsOKWhenSetViaHostsYmlExtra(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "hosts.yml"), `hosts:
  nexus:
    ansible_host: 10.0.0.1
    roles: [prometheus]
    prometheus_site_label: site-nexus
`)

	got := checkWorkspaceCompleteness(dir)

	if c := findCheck(t, got, filepath.Join("host_vars", "nexus.yml")); !c.OK {
		t.Fatalf("host_vars/nexus.yml = %+v, want OK (satisfied via hosts.yml extra)", c)
	}
}

func TestCheckWorkspaceCompleteness_NoRosterRowWithoutAnyFreeIPARole(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "hosts.yml"), workspaceHostsWithPrometheus)

	got := checkWorkspaceCompleteness(dir)

	for _, c := range got {
		if strings.HasPrefix(c.Label, "roster") {
			t.Fatalf("unexpected roster row %+v — no host carries any FreeIPA role", c)
		}
	}
}

// TestCheckWorkspaceCompleteness_RosterCheckedForFreeIPAServerWithoutNFSRole
// covers finding #1: `pilot reconcile`'s freeipa-identity entry targets
// freeipa-server, not freeipa-nfs-server (see deploy_catalog.go), so a
// roster referenced from a freeipa-server-only host must still be checked.
func TestCheckWorkspaceCompleteness_RosterCheckedForFreeIPAServerWithoutNFSRole(t *testing.T) {
	dir := t.TempDir()
	rosterPath := filepath.Join(dir, "custom-roster.yaml")
	writeFile(t, filepath.Join(dir, "hosts.yml"), `hosts:
  ipa1:
    ansible_host: 10.0.0.1
    roles: [freeipa-server]
    freeipa_roster_file: custom-roster.yaml
`)
	// missing schema_version — proves the full structural validator ran,
	// not just a "file exists" check.
	writeFile(t, rosterPath, "---\nfreeipa:\n  domain: ipa.pilot.internal\n")

	got := checkWorkspaceCompleteness(dir)

	c := findCheck(t, got, "roster")
	if c.OK {
		t.Fatalf("roster = %+v, want not-OK", c)
	}
	if len(c.Details) == 0 || !strings.Contains(c.Details[0], "schema_version") {
		t.Fatalf("roster details = %v, want a schema_version complaint", c.Details)
	}
}

// TestCheckWorkspaceCompleteness_RosterFallsBackToDefaultPathForFreeIPAServer
// covers the other half of finding #1: `pilot reconcile`'s roster path is
// typed in interactively (promptVault/defaultVaultFile, deploy.go), so
// nothing in hosts.yml has to name it — the check still shouldn't stay
// silent about the workspace's most important config file.
func TestCheckWorkspaceCompleteness_RosterFallsBackToDefaultPathForFreeIPAServer(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "hosts.yml"), `hosts:
  ipa1:
    ansible_host: 10.0.0.1
    roles: [freeipa-server]
`)
	writeFile(t, filepath.Join(dir, ".vault", "ipa-identity.yaml"), "---\nschema_version: 1\nfreeipa:\n  domain: ipa.pilot.internal\n")

	got := checkWorkspaceCompleteness(dir)

	c := findCheck(t, got, "roster (預設路徑，hosts.yml 未明確指定 freeipa_roster_file)")
	if !c.OK {
		t.Fatalf("roster (default path) = %+v, want OK", c)
	}
}

func TestCheckWorkspaceCompleteness_RosterFallbackReportsMissingWhenDefaultPathAbsent(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "hosts.yml"), `hosts:
  ipa1:
    ansible_host: 10.0.0.1
    roles: [freeipa-server]
`)

	got := checkWorkspaceCompleteness(dir)

	c := findCheck(t, got, "roster (預設路徑，hosts.yml 未明確指定 freeipa_roster_file)")
	if c.OK {
		t.Fatalf("roster (default path) = %+v, want not-OK (default file doesn't exist)", c)
	}
}

func TestCheckWorkspaceCompleteness_ReportsMissingRosterStructure(t *testing.T) {
	dir := t.TempDir()
	rosterPath := filepath.Join(dir, ".vault", "ipa-identity.yaml")
	writeFile(t, filepath.Join(dir, "hosts.yml"), `hosts:
  nexus:
    ansible_host: 10.0.0.1
    roles: [freeipa-nfs-server]
    freeipa_roster_file: .vault/ipa-identity.yaml
`)
	// missing schema_version — checkSchemaVersion should flag it.
	writeFile(t, rosterPath, "---\nfreeipa:\n  domain: ipa.pilot.internal\n")

	got := checkWorkspaceCompleteness(dir)

	c := findCheck(t, got, "roster")
	if c.OK {
		t.Fatalf("roster = %+v, want not-OK", c)
	}
	if len(c.Details) == 0 || !strings.Contains(c.Details[0], "schema_version") {
		t.Fatalf("roster details = %v, want a schema_version complaint", c.Details)
	}
}

func TestCheckWorkspaceCompleteness_RosterOKWhenValid(t *testing.T) {
	dir := t.TempDir()
	rosterPath := filepath.Join(dir, ".vault", "ipa-identity.yaml")
	writeFile(t, filepath.Join(dir, "hosts.yml"), `hosts:
  nexus:
    ansible_host: 10.0.0.1
    roles: [freeipa-nfs-server]
    freeipa_roster_file: .vault/ipa-identity.yaml
`)
	writeFile(t, rosterPath, "---\nschema_version: 1\nfreeipa:\n  domain: ipa.pilot.internal\n")

	got := checkWorkspaceCompleteness(dir)

	if c := findCheck(t, got, "roster"); !c.OK {
		t.Fatalf("roster = %+v, want OK", c)
	}
}

func TestCheckWorkspaceCompleteness_RosterEncryptedSkipsContentCheck(t *testing.T) {
	dir := t.TempDir()
	rosterPath := filepath.Join(dir, ".vault", "ipa-identity.yaml")
	writeFile(t, filepath.Join(dir, "hosts.yml"), `hosts:
  nexus:
    ansible_host: 10.0.0.1
    roles: [freeipa-nfs-server]
    freeipa_roster_file: .vault/ipa-identity.yaml
`)
	writeFile(t, rosterPath, "$ANSIBLE_VAULT;1.1;AES256\n633864363...\n")

	got := checkWorkspaceCompleteness(dir)

	if c := findCheck(t, got, "roster"); !c.OK {
		t.Fatalf("roster = %+v, want OK (can't verify, but not a violation)", c)
	}
}

func TestFormatCompletenessReport_RendersIconsAndBullets(t *testing.T) {
	report := formatCompletenessReport([]completenessCheck{
		{Label: "hosts.yml", OK: true},
		{Label: "group_vars/freeipa.yml", OK: false, Details: []string{"freeipa_realm 未填"}},
	})

	for _, want := range []string{"設定完整性檢查", "✅ hosts.yml", "❌ group_vars/freeipa.yml", "freeipa_realm 未填"} {
		if !strings.Contains(report, want) {
			t.Fatalf("formatCompletenessReport() = %q, missing %q", report, want)
		}
	}
}
