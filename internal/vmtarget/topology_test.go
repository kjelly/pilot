package vmtarget

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func writeTopologySpec(t *testing.T, yamlBody string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "topology.yaml")
	if err := os.WriteFile(path, []byte(yamlBody), 0o644); err != nil {
		t.Fatalf("write spec: %v", err)
	}
	return path
}

func TestLoadTopologySpec_ValidSpecParses(t *testing.T) {
	path := writeTopologySpec(t, `
services: local
nodes:
  - name: ipa-primary
    base_image: rocky9
    groups: [ipa_masters]
    wire: [ipa-replica]
  - name: ipa-replica
    base_image: rocky9
    disk: 20
    groups: [ipa_replicas]
    wire: ["ipa-primary=ipa1.example.internal"]
`)
	spec, err := LoadTopologySpec(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(spec.Nodes) != 2 {
		t.Fatalf("len(Nodes) = %d, want 2", len(spec.Nodes))
	}
	if spec.Services != "local" {
		t.Fatalf("services = %q, want local", spec.Services)
	}
	if spec.Nodes[1].DiskGB != 20 {
		t.Errorf("Nodes[1].DiskGB = %d, want 20", spec.Nodes[1].DiskGB)
	}
	order, groups := spec.Groups()
	wantOrder := []string{"ipa_masters", "ipa_replicas"}
	if !reflect.DeepEqual(order, wantOrder) {
		t.Errorf("order = %v, want %v", order, wantOrder)
	}
	if !reflect.DeepEqual(groups["ipa_masters"], []string{"ipa-primary"}) {
		t.Errorf("groups[ipa_masters] = %v", groups["ipa_masters"])
	}
}

func TestTopologySpecValidate_InvalidServices(t *testing.T) {
	spec := &TopologySpec{Services: " local ", Nodes: []TopologyNode{{Name: "a"}}}
	if err := spec.Validate(); err == nil || !strings.Contains(err.Error(), "services") {
		t.Fatalf("want services validation error, got %v", err)
	}
}

func TestLoadTopologySpec_MissingFileErrors(t *testing.T) {
	if _, err := LoadTopologySpec("/nonexistent/topology.yaml"); err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

func TestTopologySpecValidate_NoNodesErrors(t *testing.T) {
	spec := &TopologySpec{}
	if err := spec.Validate(); err == nil {
		t.Fatal("expected an error for an empty spec")
	}
}

func TestTopologySpecValidate_DuplicateNameErrors(t *testing.T) {
	spec := &TopologySpec{Nodes: []TopologyNode{{Name: "a"}, {Name: "a"}}}
	if err := spec.Validate(); err == nil {
		t.Fatal("expected an error for a duplicate node name")
	}
}

func TestTopologySpecValidate_WireSelfErrors(t *testing.T) {
	spec := &TopologySpec{Nodes: []TopologyNode{{Name: "a", Wire: []string{"a"}}}}
	if err := spec.Validate(); err == nil {
		t.Fatal("expected an error for a node wiring itself")
	}
}

func TestTopologySpecValidate_WireUnknownPeerErrors(t *testing.T) {
	spec := &TopologySpec{Nodes: []TopologyNode{{Name: "a", Wire: []string{"b"}}}}
	if err := spec.Validate(); err == nil {
		t.Fatal("expected an error for an unknown wire peer")
	}
}

func TestTopologySpecValidate_WireAliasFormAccepted(t *testing.T) {
	spec := &TopologySpec{Nodes: []TopologyNode{
		{Name: "a", Wire: []string{"b=alias-for-b"}},
		{Name: "b"},
	}}
	if err := spec.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTopologySpecValidate_InvalidNodeNameErrors(t *testing.T) {
	spec := &TopologySpec{Nodes: []TopologyNode{{Name: "not a valid name!"}}}
	if err := spec.Validate(); err == nil {
		t.Fatal("expected an error for an invalid node name")
	}
}

func TestTopologySpecNode_LooksUpByName(t *testing.T) {
	spec := &TopologySpec{Nodes: []TopologyNode{{Name: "a"}, {Name: "b", BaseImage: "rocky9"}}}
	n, ok := spec.Node("b")
	if !ok || n.BaseImage != "rocky9" {
		t.Fatalf("Node(b) = %+v, %v", n, ok)
	}
	if _, ok := spec.Node("missing"); ok {
		t.Fatal("expected Node(missing) to report not found")
	}
}

func TestTopologyNodeToOptions_DefaultsBaseImageOnly(t *testing.T) {
	n := TopologyNode{Name: "a"}
	opt, err := n.ToOptions()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opt.BaseImage != "ubuntu-24.04" {
		t.Errorf("BaseImage = %q, want ubuntu-24.04 default", opt.BaseImage)
	}
	if opt.SSHUser != "" || opt.VCPUs != 0 || opt.MemoryMB != 0 || opt.DiskGB != 0 || opt.Network != "" {
		t.Errorf("expected zero-value passthrough (Manager.Up applies these defaults), got %+v", opt)
	}

	n2 := TopologyNode{Name: "b", BaseImage: "rocky9", SSHUser: "cloud", VCPUs: 4}
	opt2, err := n2.ToOptions()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opt2.BaseImage != "rocky9" || opt2.SSHUser != "cloud" || opt2.VCPUs != 4 {
		t.Errorf("ToOptions() = %+v, want explicit values preserved", opt2)
	}
}

func TestTopologyNodeToOptions_ParsesTimeouts(t *testing.T) {
	n := TopologyNode{Name: "a", SSHTimeout: "8m", BootTimeout: "8m", KeepOnFailure: true}
	opt, err := n.ToOptions()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opt.SSHTimeout != 8*time.Minute || opt.BootTimeout != 8*time.Minute {
		t.Errorf("SSHTimeout/BootTimeout = %v/%v, want 8m/8m", opt.SSHTimeout, opt.BootTimeout)
	}
	if !opt.KeepOnFailure {
		t.Error("KeepOnFailure = false, want true")
	}
}

func TestTopologySpecValidate_InvalidTimeoutErrors(t *testing.T) {
	spec := &TopologySpec{Nodes: []TopologyNode{{Name: "a", SSHTimeout: "not-a-duration"}}}
	if err := spec.Validate(); err == nil {
		t.Fatal("expected an error for an invalid ssh_timeout")
	}
}
