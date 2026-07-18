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
	if len(spec.Nodes) != 3 {
		t.Fatalf("node count = %d, want 3", len(spec.Nodes))
	}

	want := map[string]struct {
		image  string
		memory int
		vcpus  int
		disk   int
		groups []string
	}{
		"freeipa-server": {"almalinux-9", 4096, 2, 30, []string{"freeipa-server", "audit-log-forwarding", "wazuh-fim", "restic-backup"}},
		"nexus":          {"ubuntu-24.04", 12288, 6, 80, []string{"docker", "audit-log-forwarding", "wazuh-manager", "wazuh-fim", "seaweedfs-s3", "restic-backup", "prometheus", "thanos-query", "alertmanager", "dashboard"}},
		"client-vm":      {"ubuntu-24.04", 2048, 2, 20, []string{"freeipa-client", "docker", "audit-log-forwarding", "wazuh-fim", "restic-backup"}},
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
	if len(order) != 12 {
		t.Fatalf("group count = %d, want 12", len(order))
	}
	if len(groups["freeipa-server"]) != 1 || groups["freeipa-server"][0] != "freeipa-server" {
		t.Fatalf("freeipa-server group = %v", groups["freeipa-server"])
	}
	if !reflect.DeepEqual(groups["docker"], []string{"nexus", "client-vm"}) {
		t.Fatalf("docker group = %v", groups["docker"])
	}
}
