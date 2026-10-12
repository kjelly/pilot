package vmtarget

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPerHostRecordingTopologyMatchesScript keeps the committed topology,
// its test wrapper and its script referring to the same nodes.
func TestPerHostRecordingTopologyMatchesScript(t *testing.T) {
	root := filepath.Join("..", "..")
	spec, err := LoadTopologySpec(filepath.Join(root, "docs", "topologies", "per-host-recording-topology.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := spec.Validate(); err != nil {
		t.Fatal(err)
	}
	groups := map[string][]string{}
	for _, node := range spec.Nodes {
		for _, g := range node.Groups {
			groups[g] = append(groups[g], node.Name)
		}
	}
	for _, g := range []string{"freeipa-server", "pilot-access-gateway", "pilot-session-store", "pilot-access-directory"} {
		if len(groups[g]) != 1 {
			t.Errorf("group %s has nodes %v, want exactly one", g, groups[g])
		}
	}
	clients := strings.Join(groups["freeipa-client"], " ")

	wrapper, err := os.ReadFile(filepath.Join(root, "playbooks", "test", "per-host-recording-topology.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(wrapper), "default('rec-tb')") || !strings.Contains(clients, "rec-tb") {
		t.Errorf("the wrapper's marked target rec-tb must be a freeipa-client node (clients: %s)", clients)
	}
	script, err := os.ReadFile(filepath.Join(root, "scripts", "per-host-recording-topology-test.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range []string{"rec-ta", "rec-tb"} {
		if !strings.Contains(string(script), `"`+node+`.ipa.pilot.internal"`) || !strings.Contains(clients, node) {
			t.Errorf("gateway_scope_hosts target %s must be in the script and a freeipa-client node", node)
		}
	}
	for _, want := range []string{
		"https://" + groups["pilot-session-store"][0] + ".ipa.pilot.internal:8443",
		"PILOT_INPUT_GATEWAY_ID=", "PILOT_INPUT_GATEWAY_SCOPE=",
		"docs/topologies/per-host-recording-topology.yaml", "playbooks/test/per-host-recording-topology.yml",
	} {
		if !strings.Contains(string(script), want) {
			t.Errorf("script is missing %q", want)
		}
	}
}
