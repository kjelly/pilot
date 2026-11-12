package vmtarget

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestMinimalPoCTopologyMatchesRunbook(t *testing.T) {
	path := filepath.Join("..", "..", "docs", "topologies", "minimal-poc-topology.yaml")
	spec, err := LoadTopologySpec(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(spec.Nodes) != 5 {
		t.Fatalf("node count = %d, want 5", len(spec.Nodes))
	}

	want := map[string]struct {
		image  string
		memory int
		vcpus  int
		disk   int
		groups []string
	}{
		"freeipa-server": {"almalinux-9", 4608, 2, 30, []string{"freeipa-server", "freeipa-dns-client", "host-monitoring", "audit-log-forwarding", "wazuh-fim", "restic-backup"}},
		// 2026-11-10 revision: staging/prod-aligned 5-node layout (runbook §0.6).
		// The replica needs the same 4608 MiB as the primary: its contract's
		// minRAMMiB is 4096 and an AlmaLinux guest sees ~95% of what it is given.
		"freeipa-replica": {"almalinux-9", 4608, 2, 30, []string{"freeipa-server-replica", "host-monitoring", "audit-log-forwarding", "wazuh-fim", "restic-backup"}},
		"nexus":           {"ubuntu-24.04", 12288, 6, 80, []string{"freeipa-client", "freeipa-dns-client", "reverse-proxy", "host-monitoring", "docker", "audit-log-forwarding", "log-server", "wazuh-manager", "wazuh-fim", "seaweedfs-s3", "restic-backup", "prometheus", "thanos-query", "alertmanager", "dashboard", "freeipa-nfs-server", "agent-controller", "detection-engine"}},
		"client-vm":       {"ubuntu-24.04", 2560, 2, 20, []string{"freeipa-client", "freeipa-dns-client", "host-monitoring", "docker", "audit-log-forwarding", "wazuh-fim", "restic-backup", "freeipa-nfs-client", "dns"}},
		"bastion":         {"ubuntu-24.04", 2048, 2, 20, []string{"freeipa-client", "pilot-access-gateway"}},
	}
	for _, node := range spec.Nodes {
		got, ok := want[node.Name]
		if !ok {
			t.Fatalf("unexpected node %q", node.Name)
		}
		if node.BaseImage != got.image || node.MemoryMB != got.memory || node.VCPUs != got.vcpus || node.DiskGB != got.disk {
			t.Errorf("%s resources = %s/%d/%d/%d, want %s/%d/%d/%d", node.Name, node.BaseImage, node.MemoryMB, node.VCPUs, node.DiskGB, got.image, got.memory, got.vcpus, got.disk)
		}
		if !reflect.DeepEqual(node.Groups, got.groups) {
			t.Errorf("%s groups = %v, want %v", node.Name, node.Groups, got.groups)
		}
	}
	order, groups := spec.Groups()
	if len(order) != 23 {
		t.Fatalf("group count = %d, want 23", len(order))
	}
	if len(groups["freeipa-server"]) != 1 || groups["freeipa-server"][0] != "freeipa-server" {
		t.Fatalf("freeipa-server group = %v", groups["freeipa-server"])
	}
	if !reflect.DeepEqual(groups["docker"], []string{"nexus", "client-vm"}) {
		t.Fatalf("docker group = %v", groups["docker"])
	}
	if !reflect.DeepEqual(groups["freeipa-client"], []string{"nexus", "client-vm", "bastion"}) {
		t.Fatalf("freeipa-client group = %v", groups["freeipa-client"])
	}
	if !reflect.DeepEqual(groups["freeipa-nfs-server"], []string{"nexus"}) {
		t.Fatalf("freeipa-nfs-server group = %v", groups["freeipa-nfs-server"])
	}
	if !reflect.DeepEqual(groups["log-server"], []string{"nexus"}) {
		t.Fatalf("log-server group = %v", groups["log-server"])
	}
	if !reflect.DeepEqual(groups["freeipa-nfs-client"], []string{"client-vm"}) {
		t.Fatalf("freeipa-nfs-client group = %v", groups["freeipa-nfs-client"])
	}
	// Merged in from the retired delivery-test skill (2026-08-14).
	if !reflect.DeepEqual(groups["freeipa-dns-client"], []string{"freeipa-server", "nexus", "client-vm"}) {
		t.Fatalf("freeipa-dns-client group = %v", groups["freeipa-dns-client"])
	}
	if !reflect.DeepEqual(groups["host-monitoring"], []string{"freeipa-server", "freeipa-replica", "nexus", "client-vm"}) {
		t.Fatalf("host-monitoring group = %v", groups["host-monitoring"])
	}
	if !reflect.DeepEqual(groups["reverse-proxy"], []string{"nexus"}) {
		t.Fatalf("reverse-proxy group = %v", groups["reverse-proxy"])
	}
	// 2026-11-10: roles added so the PoC mirrors infra-config staging/prod.
	for group, want := range map[string][]string{
		"freeipa-server-replica": {"freeipa-replica"},
		"dns":                    {"client-vm"},
		"agent-controller":       {"nexus"},
		"detection-engine":       {"nexus"},
		"pilot-access-gateway":   {"bastion"},
	} {
		if !reflect.DeepEqual(groups[group], want) {
			t.Fatalf("%s group = %v, want %v", group, groups[group], want)
		}
	}
	// dns conflicts with the FreeIPA server roles by contract (contracts/dns.yaml):
	// no node may carry both.
	for _, node := range spec.Nodes {
		hasDNS, hasIPA := false, false
		for _, g := range node.Groups {
			hasDNS = hasDNS || g == "dns"
			hasIPA = hasIPA || g == "freeipa-server" || g == "freeipa-server-replica"
		}
		if hasDNS && hasIPA {
			t.Errorf("%s carries dns together with a FreeIPA server role", node.Name)
		}
	}
}
