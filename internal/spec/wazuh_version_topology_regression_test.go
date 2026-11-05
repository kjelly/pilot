package spec

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Issue #244 part A target topology: one manager that also carries the agent
// role (so the central gate and the agent contract meet on one host), a Debian
// agent and an EL agent, and a wrapper that applies docker, then the manager,
// then the agents. A fresh agent can only observe its manager's release if the
// manager play ran first, so the order is the contract.
func validateWazuhVersionTopology(topology, wrapper []byte) error {
	var descriptor struct {
		Nodes []struct {
			Name      string
			BaseImage string `yaml:"base_image"`
			Groups    []string
		}
	}
	var imports []map[string]any
	if err := yaml.Unmarshal(topology, &descriptor); err != nil {
		return err
	}
	if err := yaml.Unmarshal(wrapper, &imports); err != nil {
		return err
	}
	groups := map[string][]string{}
	images := map[string]bool{}
	for _, n := range descriptor.Nodes {
		images[n.BaseImage] = true
		for _, g := range n.Groups {
			groups[g] = append(groups[g], n.Name)
		}
	}
	if len(groups["wazuh-manager"]) != 1 || len(groups["docker"]) != 1 || groups["docker"][0] != groups["wazuh-manager"][0] {
		return fmt.Errorf("exactly one manager node, and it alone provides docker (got manager=%v docker=%v)", groups["wazuh-manager"], groups["docker"])
	}
	if len(groups["wazuh-fim"]) < 3 || !contains(groups["wazuh-fim"], groups["wazuh-manager"][0]) {
		return fmt.Errorf("agents must include the manager host itself and at least two other hosts, got %v", groups["wazuh-fim"])
	}
	if !images["ubuntu-24.04"] || !images["almalinux-9"] {
		return fmt.Errorf("both package families are required (Ubuntu 24.04 and AlmaLinux 9), got %v", images)
	}
	if images["ubuntu-22.04"] {
		return fmt.Errorf("Ubuntu 22.04 is not part of this topology")
	}
	want := []string{"../../apply/docker-apply.yml", "../../apply/wazuh-manager-apply.yml", "../../apply/wazuh-fim-apply.yml"}
	if len(imports) != len(want) {
		return fmt.Errorf("wrapper imports %d playbooks, want %d", len(imports), len(want))
	}
	for i, file := range want {
		if got, _ := imports[i]["ansible.builtin.import_playbook"].(string); got != file {
			return fmt.Errorf("import %d is %q, want %q (docker, then the manager, then the agents)", i, got, file)
		}
		if len(imports[i]) != 3 || imports[i]["when"] != nil || imports[i]["vars"] != nil {
			return fmt.Errorf("import %s must keep the component's own hosts, defaults and check mode", file)
		}
	}
	return nil
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func TestWazuhVersionTopologyFixture(t *testing.T) {
	topology, err := os.ReadFile("../../docs/topologies/wazuh-version-topology.yaml")
	if err != nil {
		t.Fatal(err)
	}
	wrapper, err := os.ReadFile("../../playbooks/test/fixtures/wazuh-version-topology.yml")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateWazuhVersionTopology(topology, wrapper); err != nil {
		t.Fatal(err)
	}
	swap := func(s, a, b string) string {
		return strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(s, a, "SWAP"), b, a), "SWAP", b)
	}
	// Each withdrawal removes one invariant; the checker must notice every one.
	for name, pair := range map[string][2][]byte{
		"agents before the manager": {topology, []byte(swap(string(wrapper), "../../apply/wazuh-manager-apply.yml", "../../apply/wazuh-fim-apply.yml"))},
		"docker after the manager":  {topology, []byte(swap(string(wrapper), "../../apply/docker-apply.yml", "../../apply/wazuh-manager-apply.yml"))},
		"a limited import":          {topology, []byte(strings.Replace(string(wrapper), "tags: [wazuh-manager]", "tags: [wazuh-manager]\n  when: not ansible_check_mode", 1))},
		"no EL agent":               {[]byte(strings.Replace(string(topology), "almalinux-9", "ubuntu-24.04", 1)), wrapper},
		"an Ubuntu 22.04 node":      {[]byte(strings.Replace(string(topology), "name: wf244-deb\n    base_image: ubuntu-24.04", "name: wf244-deb\n    base_image: ubuntu-22.04", 1)), wrapper},
		"manager is not an agent":   {[]byte(strings.Replace(string(topology), "groups: [sandbox, docker, wazuh-manager, wazuh-fim]", "groups: [sandbox, docker, wazuh-manager]", 1)), wrapper},
		"two managers":              {[]byte(strings.Replace(string(topology), "groups: [sandbox, wazuh-fim]", "groups: [sandbox, wazuh-manager, wazuh-fim]", 1)), wrapper},
	} {
		t.Run(name, func(t *testing.T) {
			if validateWazuhVersionTopology(pair[0], pair[1]) == nil {
				t.Fatal("withdrawal accepted")
			}
		})
	}
}
