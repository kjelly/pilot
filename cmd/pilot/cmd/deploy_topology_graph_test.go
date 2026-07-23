package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/contract"
)

// testTopologyCatalog builds a small but representative contract catalog:
// a docker base (multi-host), two dedicated services hanging off it, an
// optional-dep overlay, a cross-host required chain, and one component with
// no hosts in the inventory.
func testTopologyCatalog(t *testing.T) contract.Catalog {
	t.Helper()
	c := func(id, role, card string, order int, deps ...contract.Dependency) contract.Contract {
		return contract.Contract{
			ID: id, Role: role, HostCardinality: card,
			Resources:    contract.Resources{MinCPU: 2, MinRAMMiB: 2048, MinDiskGiB: 10},
			Dependencies: deps,
			Site:         contract.Site{Include: true, Order: order},
		}
	}
	dep := func(to string, required bool, rel string) contract.Dependency {
		return contract.Dependency{Component: to, Required: required, Relation: rel}
	}
	catalog, err := contract.NewCatalog([]contract.Contract{
		c("docker", "docker", "one-or-more", 30),
		c("seaweedfs-s3", "seaweedfs-s3", "exactly-one", 120, dep("docker", true, "sameHosts")),
		c("wazuh-manager", "wazuh-manager", "exactly-one", 100, dep("docker", true, "sameHosts")),
		c("wazuh-fim", "wazuh-fim", "one-or-more", 110, dep("wazuh-manager", true, "providerEndpoint")),
		c("restic-backup", "restic-backup", "one-or-more", 130, dep("seaweedfs-s3", false, "providerEndpoint")),
		c("keycloak", "keycloak", "exactly-one", 70, dep("docker", true, "sameHosts")),
	})
	if err != nil {
		t.Fatalf("NewCatalog: %v", err)
	}
	return catalog
}

func testTopologyGroups() map[string][]string {
	// keycloak has no hosts -> inactive. restic + wazuh-fim span all 2 hosts.
	return map[string][]string{
		"docker":        {"nexus", "edge"},
		"seaweedfs-s3":  {"nexus"},
		"wazuh-manager": {"nexus"},
		"wazuh-fim":     {"nexus", "edge"},
		"restic-backup": {"nexus", "edge"},
	}
}

func TestBuildInventoryTopologyClassifiesNodes(t *testing.T) {
	topo := buildInventoryTopology(testTopologyCatalog(t), testTopologyGroups())

	if got := len(topo.Hosts); got != 2 {
		t.Fatalf("hosts = %d, want 2 (%v)", got, topo.Hosts)
	}
	if kc := topo.Nodes["keycloak"]; kc.Active {
		t.Errorf("keycloak should be inactive (no hosts)")
	}
	if sw := topo.Nodes["seaweedfs-s3"]; !sw.Active || sw.overlay() {
		t.Errorf("seaweedfs-s3 should be active & not overlay: active=%v overlay=%v", sw.Active, sw.overlay())
	}
	if wf := topo.Nodes["wazuh-fim"]; !wf.overlay() || !wf.spansAll(len(topo.Hosts)) {
		t.Errorf("wazuh-fim should be overlay spanning all: overlay=%v spansAll=%v", wf.overlay(), wf.spansAll(len(topo.Hosts)))
	}
	// nexus carries 5 active roles (docker, seaweedfs-s3, wazuh-manager,
	// wazuh-fim, restic-backup); edge carries 3 (docker, wazuh-fim, restic).
	if got := len(topo.HostRoles["nexus"]); got != 5 {
		t.Errorf("nexus roles = %d, want 5 (%v)", got, topo.HostRoles["nexus"])
	}
	if got := len(topo.HostRoles["edge"]); got != 3 {
		t.Errorf("edge roles = %d, want 3 (%v)", got, topo.HostRoles["edge"])
	}
}

func TestPrimaryParentPrefersActiveRequiredDep(t *testing.T) {
	topo := buildInventoryTopology(testTopologyCatalog(t), testTopologyGroups())

	if p := topo.primaryParent("seaweedfs-s3"); p != "docker" {
		t.Errorf("seaweedfs-s3 primary parent = %q, want docker", p)
	}
	if p := topo.primaryParent("wazuh-fim"); p != "wazuh-manager" {
		t.Errorf("wazuh-fim primary parent = %q, want wazuh-manager", p)
	}
	// restic depends on seaweedfs only via an optional edge -> it is a root.
	if p := topo.primaryParent("restic-backup"); p != "" {
		t.Errorf("restic-backup primary parent = %q, want \"\" (root; optional dep)", p)
	}
	// docker has no deps -> root.
	if p := topo.primaryParent("docker"); p != "" {
		t.Errorf("docker primary parent = %q, want \"\"", p)
	}
}

func TestRenderInventoryTopologyStructure(t *testing.T) {
	topo := buildInventoryTopology(testTopologyCatalog(t), testTopologyGroups())
	var b strings.Builder
	renderInventoryTopology(&b, topo, "inv.yml")
	out := b.String()

	for _, want := range []string{
		"部署拓樸圖 — inventory: inv.yml",
		"5 個已部署元件 / 2 台主機",
		"wazuh-fim [ALL] ⚠overlay",     // overlay spanning all hosts
		"restic-backup [ALL] ⚠overlay", // root overlay
		"┄▶選填 seaweedfs-s3",            // optional edge annotation on restic
		"未部署（inventory 無對應主機",          // skipped section
		"keycloak",                     // the inactive component is listed
		"各主機承載：",                       // per-host summary
	} {
		if !strings.Contains(out, want) {
			t.Errorf("render output missing %q\n---\n%s", want, out)
		}
	}
	// seaweedfs-s3 must appear nested under docker (indented tree child).
	if !strings.Contains(out, "──▶ seaweedfs-s3 [nexus]") {
		t.Errorf("seaweedfs-s3 should render as a docker child\n---\n%s", out)
	}
	// The inactive keycloak must NOT be drawn as an active tree node.
	if strings.Contains(out, "──▶ keycloak [") {
		t.Errorf("inactive keycloak should not be a tree node\n---\n%s", out)
	}
}

func TestHostCrossDepsAreCrossHostOnly(t *testing.T) {
	topo := buildInventoryTopology(testTopologyCatalog(t), testTopologyGroups())

	// nexus co-locates docker, seaweedfs-s3, wazuh-manager — every provider it
	// needs lives on nexus itself, so it has no cross-host dependency. (restic's
	// only dep is optional to seaweedfs-s3, which is also on nexus.)
	if deps := topo.hostCrossDeps("nexus"); len(deps) != 0 {
		t.Errorf("nexus should have no cross-host deps, got %+v", deps)
	}

	// edge runs wazuh-fim (needs wazuh-manager@nexus, required) and
	// restic-backup (needs seaweedfs-s3@nexus, optional). docker is a base
	// (sameHosts deps never count) so it contributes nothing.
	deps := topo.hostCrossDeps("edge")
	byVia := map[string]crossHostDep{}
	for _, d := range deps {
		byVia[d.Via] = d
	}
	wf, ok := byVia["wazuh-fim"]
	if !ok || !wf.Required || len(wf.ToHosts) != 1 || wf.ToHosts[0] != "nexus" {
		t.Errorf("edge wazuh-fim cross-host dep wrong: %+v (ok=%v)", wf, ok)
	}
	rb, ok := byVia["restic-backup"]
	if !ok || rb.Required || len(rb.ToHosts) != 1 || rb.ToHosts[0] != "nexus" {
		t.Errorf("edge restic-backup cross-host dep wrong: %+v (ok=%v)", rb, ok)
	}
	if _, isCross := byVia["docker"]; isCross {
		t.Errorf("docker (sameHosts base) must not appear as a cross-host dep")
	}
}

func TestRenderHostTopologyStructure(t *testing.T) {
	topo := buildInventoryTopology(testTopologyCatalog(t), testTopologyGroups())
	var b strings.Builder
	renderHostTopology(&b, topo, "inv.yml")
	out := b.String()

	for _, want := range []string{
		"主機拓樸圖 — inventory: inv.yml",
		"nexus — 5 角色",                            // nexus carries the most here
		"⚠ 承載最多",                                  // heaviest marker
		"無（全部同機自足）",                               // nexus self-sufficient
		"wazuh-fim ──▶ wazuh-manager@nexus",       // required cross-host edge
		"restic-backup ┄▶ seaweedfs-s3@nexus（選填）", // optional cross-host edge
	} {
		if !strings.Contains(out, want) {
			t.Errorf("host view missing %q\n---\n%s", want, out)
		}
	}
	// The heaviest host must be printed before the lighter ones.
	if strings.Index(out, "▪ nexus") > strings.Index(out, "▪ edge") {
		t.Errorf("nexus (heaviest) should sort before edge\n---\n%s", out)
	}
}

func TestExpandIfSimplifiedHostsDetectsAndExpands(t *testing.T) {
	dir := t.TempDir()

	// The pilot "host → roles" source format must be expanded to a real
	// inventory (its top-level hosts: entries carry a roles: list).
	simplified := filepath.Join(dir, "hosts.yml")
	if err := os.WriteFile(simplified, []byte(`hosts:
  it-freeipa:
    ansible_host: "10.0.0.1"
    ansible_user: ubuntu
    roles: [freeipa-server]
  it-service:
    ansible_host: "10.0.0.2"
    ansible_user: ubuntu
    roles: [docker, wazuh-manager]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	path, notice, cleanup, err := expandIfSimplifiedHosts(simplified)
	if err != nil {
		t.Fatalf("expand simplified: %v", err)
	}
	defer cleanup()
	if path == simplified {
		t.Errorf("simplified hosts.yml should expand to a different (temp) path, got the original")
	}
	if notice == "" {
		t.Errorf("expansion should return a notice for the caller to print")
	}
	rendered, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read expanded inventory: %v", err)
	}
	for _, want := range []string{"freeipa-server:", "wazuh-manager:", "docker:", "it-service:"} {
		if !strings.Contains(string(rendered), want) {
			t.Errorf("expanded inventory missing %q\n---\n%s", want, rendered)
		}
	}
	cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("cleanup should remove the temp inventory, stat err = %v", err)
	}
}

func TestExpandIfSimplifiedHostsLeavesRealInventoryUnchanged(t *testing.T) {
	dir := t.TempDir()
	// A normal Ansible inventory (group tree, no top-level roled hosts).
	real := filepath.Join(dir, "inventory.yml")
	if err := os.WriteFile(real, []byte(`---
all:
  hosts:
    it-freeipa:
      ansible_host: "10.0.0.1"
  children:
    freeipa-server:
      hosts:
        it-freeipa:
`), 0o600); err != nil {
		t.Fatal(err)
	}
	path, notice, cleanup, err := expandIfSimplifiedHosts(real)
	if err != nil {
		t.Fatalf("expand real inventory: %v", err)
	}
	defer cleanup()
	if path != real {
		t.Errorf("a real inventory must be returned unchanged, got %q", path)
	}
	if notice != "" {
		t.Errorf("a real inventory must not produce an expansion notice, got %q", notice)
	}
}
