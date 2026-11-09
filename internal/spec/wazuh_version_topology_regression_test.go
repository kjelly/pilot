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
// agent that also hosts the log receiver the manager forwards to, an EL agent, and
// a wrapper that applies docker, the receiver, the manager, then the agents. A fresh
// agent can only observe its manager's release if the manager play ran first, and
// the manager's C10/C11 rows (siem-log-server pin, host imfile reader) are only
// applicable when a receiver is in the inventory, so the order and the receiver are
// the contract (native finding D2: without a receiver the chain cannot verify clean).
func validateWazuhVersionTopology(topology, wrapper []byte) error {
	var descriptor struct {
		Nodes []struct {
			Name      string
			BaseImage string `yaml:"base_image"`
			Memory    int
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
	nodeImages := map[string][]string{}
	for _, n := range descriptor.Nodes {
		images[n.BaseImage] = true
		nodeImages[n.Name] = append(nodeImages[n.Name], n.BaseImage)
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
	// The manager forwards to exactly one receiver (the contract is hostCardinality exactly-one), which is an
	// Ubuntu 24.04 agent that is not the manager host: forwarding is only supported on Ubuntu without SELinux.
	if len(groups["log-server"]) != 1 || groups["log-server"][0] == groups["wazuh-manager"][0] || !contains(groups["wazuh-fim"], groups["log-server"][0]) {
		return fmt.Errorf("exactly one log receiver on an agent node other than the manager, got %v", groups["log-server"])
	}
	if len(nodeImages[groups["log-server"][0]]) != 1 || nodeImages[groups["log-server"][0]][0] != "ubuntu-24.04" {
		return fmt.Errorf("the receiver node must be ubuntu-24.04, got %v", nodeImages[groups["log-server"][0]])
	}
	for _, n := range descriptor.Nodes {
		if n.Name == groups["log-server"][0] && n.Memory < 2048 {
			return fmt.Errorf("the receiver node has %d MiB, below the log-server contract's 2048", n.Memory)
		}
	}
	if !images["ubuntu-24.04"] || !images["almalinux-9"] {
		return fmt.Errorf("both package families are required (Ubuntu 24.04 and AlmaLinux 9), got %v", images)
	}
	if images["ubuntu-22.04"] {
		return fmt.Errorf("Ubuntu 22.04 is not part of this topology")
	}
	want := []string{"../../apply/docker-apply.yml", "../../apply/log-server-apply.yml", "../../apply/audit-log-forwarding-apply.yml",
		"../../apply/wazuh-manager-apply.yml", "../../apply/wazuh-fim-apply.yml"}
	// The explicit diagnostic fixture (a fresh native alert challenge) may follow the
	// agents, and only as the last import, deferred in check mode.
	if n := len(imports); n == len(want)+1 {
		last := imports[n-1]
		if got, _ := last["ansible.builtin.import_playbook"].(string); got != "wazuh-alert-delivery-fixtures.yml" || last["when"] != "not ansible_check_mode" {
			return fmt.Errorf("a sixth import must be the check-mode-deferred alert-delivery fixture, got %v", last)
		}
		imports = imports[:len(want)]
	}
	if len(imports) != len(want) {
		return fmt.Errorf("wrapper imports %d playbooks, want %d", len(imports), len(want))
	}
	for i, file := range want {
		if got, _ := imports[i]["ansible.builtin.import_playbook"].(string); got != file {
			return fmt.Errorf("import %d is %q, want %q (docker, the receiver and its sender, the manager, then the agents)", i, got, file)
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
		"agents before the manager":              {topology, []byte(swap(string(wrapper), "../../apply/wazuh-manager-apply.yml", "../../apply/wazuh-fim-apply.yml"))},
		"docker after the manager":               {topology, []byte(swap(string(wrapper), "../../apply/docker-apply.yml", "../../apply/wazuh-manager-apply.yml"))},
		"receiver after the manager":             {topology, []byte(swap(string(wrapper), "../../apply/log-server-apply.yml", "../../apply/wazuh-manager-apply.yml"))},
		"no receiver import":                     {topology, []byte(strings.Replace(string(wrapper), "- name: Deploy the actual independent SIEM receiver before forwarding\n  ansible.builtin.import_playbook: ../../apply/log-server-apply.yml\n  tags: [log-server]\n", "", 1))},
		"no receiver node":                       {[]byte(strings.Replace(string(topology), "groups: [sandbox, log-server, audit-log-forwarding, wazuh-fim]", "groups: [sandbox, wazuh-fim]", 1)), wrapper},
		"receiver on the manager":                {[]byte(strings.Replace(strings.Replace(string(topology), "groups: [sandbox, log-server, audit-log-forwarding, wazuh-fim]", "groups: [sandbox, wazuh-fim]", 1), "groups: [sandbox, docker, wazuh-manager, wazuh-fim]", "groups: [sandbox, docker, wazuh-manager, log-server, wazuh-fim]", 1)), wrapper},
		"receiver on EL":                         {[]byte(strings.Replace(strings.Replace(string(topology), "groups: [sandbox, log-server, audit-log-forwarding, wazuh-fim]", "groups: [sandbox, wazuh-fim]", 1), "name: wf244-el\n    base_image: almalinux-9\n    memory: 2048\n    vcpus: 2\n    disk: 30\n    ssh_user: root\n    ssh_timeout: 5m\n    boot_timeout: 8m\n    groups: [sandbox, wazuh-fim]", "name: wf244-el\n    base_image: almalinux-9\n    memory: 2048\n    vcpus: 2\n    disk: 30\n    ssh_user: root\n    ssh_timeout: 5m\n    boot_timeout: 8m\n    groups: [sandbox, log-server, wazuh-fim]", 1)), wrapper},
		"receiver below its minimum":             {[]byte(strings.Replace(string(topology), "memory: 4096", "memory: 1024", 1)), wrapper},
		"a sixth import that runs in check mode": {topology, []byte(strings.Replace(string(wrapper), "  when: not ansible_check_mode\n", "", 1))},
		"a limited import":                       {topology, []byte(strings.Replace(string(wrapper), "tags: [wazuh-manager]", "tags: [wazuh-manager]\n  when: not ansible_check_mode", 1))},
		"no EL agent":                            {[]byte(strings.Replace(string(topology), "almalinux-9", "ubuntu-24.04", 1)), wrapper},
		"an Ubuntu 22.04 node":                   {[]byte(strings.Replace(string(topology), "name: wf244-deb\n    base_image: ubuntu-24.04", "name: wf244-deb\n    base_image: ubuntu-22.04", 1)), wrapper},
		"manager is not an agent":                {[]byte(strings.Replace(string(topology), "groups: [sandbox, docker, wazuh-manager, wazuh-fim]", "groups: [sandbox, docker, wazuh-manager]", 1)), wrapper},
		"two managers":                           {[]byte(strings.Replace(string(topology), "groups: [sandbox, log-server, audit-log-forwarding, wazuh-fim]", "groups: [sandbox, log-server, wazuh-manager, wazuh-fim]", 1)), wrapper},
	} {
		t.Run(name, func(t *testing.T) {
			if validateWazuhVersionTopology(pair[0], pair[1]) == nil {
				t.Fatal("withdrawal accepted")
			}
		})
	}
}
