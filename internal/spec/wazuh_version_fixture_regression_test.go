package spec

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Receiver C7/C8 inject into its local default ruleset: the canonical sender
// must return those records to the receiver's isolated network ruleset.
func validateWazuhReceiverPrerequisite(topology, wrapper []byte) error {
	var descriptor struct {
		Nodes []struct {
			Name   string
			Groups []string
		}
	}
	var imports []map[string]any
	if err := yaml.Unmarshal(topology, &descriptor); err != nil {
		return err
	}
	if err := yaml.Unmarshal(wrapper, &imports); err != nil {
		return err
	}
	receivers, senders := []string{}, []string{}
	for _, n := range descriptor.Nodes {
		for _, group := range n.Groups {
			if group == "log-server" {
				receivers = append(receivers, n.Name)
			}
			if group == "audit-log-forwarding" {
				senders = append(senders, n.Name)
			}
		}
	}
	if len(receivers) != 1 || len(senders) != 1 || receivers[0] != senders[0] {
		return fmt.Errorf("self-forwarding must be exclusive to the sole receiver")
	}
	positions := map[string]int{}
	for i, item := range imports {
		file, _ := item["ansible.builtin.import_playbook"].(string)
		if _, exists := positions[file]; exists {
			return fmt.Errorf("duplicate import %s", file)
		}
		positions[file] = i
		if strings.HasSuffix(file, "/audit-log-forwarding-apply.yml") {
			if len(item) != 3 || item["when"] != nil || item["vars"] != nil {
				return fmt.Errorf("canonical sender must retain native hosts/defaults/checkmode")
			}
			tags, _ := item["tags"].([]any)
			if len(tags) != 2 || tags[0] != "log-server" || tags[1] != "audit-log-forwarding" {
				return fmt.Errorf("receiver selection must include canonical sender prerequisite")
			}
		}
	}
	files := []string{"../../apply/docker-apply.yml", "../../apply/log-server-apply.yml", "../../apply/audit-log-forwarding-apply.yml", "../../apply/wazuh-manager-apply.yml", "../../apply/wazuh-fim-apply.yml", "wazuh-alert-delivery-fixtures.yml"}
	if len(imports) != len(files) {
		return fmt.Errorf("unexpected wrapper import count")
	}
	for i, f := range files {
		if p, ok := positions[f]; !ok || p != i {
			return fmt.Errorf("prerequisite import order differs at %s", f)
		}
	}
	return nil
}

func TestWazuhVersionReceiverFixturePrerequisite(t *testing.T) {
	topology, err := os.ReadFile("../../docs/topologies/wazuh-version-topology.yaml")
	if err != nil {
		t.Fatal(err)
	}
	wrapper, err := os.ReadFile("../../playbooks/test/fixtures/wazuh-version-topology.yml")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateWazuhReceiverPrerequisite(topology, wrapper); err != nil {
		t.Fatal(err)
	}
	// Single-invariant withdrawals must catch the original omission and both
	// cohost/selector mistakes without executing any package or service task.
	for name, pair := range map[string][2][]byte{
		"missing receiver group":    {[]byte(strings.Replace(string(topology), "log-server, audit-log-forwarding,", "log-server,", 1)), wrapper},
		"foreign sender group":      {[]byte(strings.Replace(string(topology), "groups: [sandbox, wazuh-fim]", "groups: [sandbox, audit-log-forwarding, wazuh-fim]", 1)), wrapper},
		"missing sender import":     {topology, []byte(strings.Replace(string(wrapper), "../../apply/audit-log-forwarding-apply.yml", "../../apply/log-server-apply.yml", 1))},
		"wrong order":               {topology, []byte(strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(string(wrapper), "../../apply/audit-log-forwarding-apply.yml", "SWAP"), "../../apply/wazuh-fim-apply.yml", "../../apply/audit-log-forwarding-apply.yml"), "SWAP", "../../apply/wazuh-fim-apply.yml"))},
		"missing receiver selector": {topology, []byte(strings.Replace(string(wrapper), "[log-server, audit-log-forwarding]", "[audit-log-forwarding]", 1))},
	} {
		t.Run(name, func(t *testing.T) {
			if validateWazuhReceiverPrerequisite(pair[0], pair[1]) == nil {
				t.Fatal("withdrawal accepted")
			}
		})
	}
}

func TestWazuhVersionReceiverFixtureResolution(t *testing.T) {
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Fatal(err)
	}
	canonical := loadFirstPlay(t, "audit-log-forwarding-apply.yml")
	// Only the real canonical read-only gates/default facts are executed here.
	// Package, service and audit operations remain exclusively native target work.
	names := []string{"Gate: siem_forward_port is a TCP port number", "Resolve inventory-overridable defaults without shadowing group_vars/host_vars", "Gate: siem_forward_port matches the inventory log-server's siem_receiver_tcp_port"}
	for _, tc := range []struct {
		name, sender, receiver string
		fail                   bool
	}{
		{name: "default TCP self target", receiver: "514"},
		{name: "custom TCP self target", sender: "2514", receiver: "2514"},
		{name: "different port refuses", sender: "2514", receiver: "514", fail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			inventory := map[string]any{"all": map[string]any{"children": map[string]any{
				"log-server":           map[string]any{"hosts": map[string]any{"receiver": map[string]any{"ansible_connection": "local", "ansible_host": "192.0.2.24", "siem_receiver_tcp_port": tc.receiver}}},
				"audit-log-forwarding": map[string]any{"hosts": map[string]any{"receiver": nil}},
				"wazuh-manager":        map[string]any{"hosts": map[string]any{"manager": map[string]any{"ansible_host": "192.0.2.25"}}},
			}}}
			tasks := []any{}
			for _, name := range names {
				tasks = append(tasks, findNamedTask(t, canonical, name))
			}
			tasks = append(tasks, map[string]any{"ansible.builtin.assert": map[string]any{"that": []string{"siem_forward_effective_host == '192.0.2.24'", "siem_forward_transport == 'tcp'", "(siem_forward_port | string) == (siem_receiver_tcp_port | string)"}}})
			vars := map[string]any{}
			for k, v := range canonical["vars"].(map[string]any) {
				vars[k] = v
			}
			if tc.sender != "" {
				vars["siem_forward_port"] = tc.sender
			}
			play := []any{map[string]any{"hosts": "audit-log-forwarding", "gather_facts": false, "vars": vars, "tasks": tasks}}
			for file, value := range map[string]any{"inventory.yml": inventory, "play.yml": play} {
				data, err := yaml.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, file), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			config := filepath.Join(root, "ansible.cfg")
			if err := os.WriteFile(config, []byte("[defaults]\nfact_caching=memory\n"), 0600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("ansible-playbook", "-i", filepath.Join(root, "inventory.yml"), filepath.Join(root, "play.yml"), "--check")
			cmd.Env = append(os.Environ(), "ANSIBLE_CONFIG="+config, "ANSIBLE_LOCAL_TEMP="+root)
			out, err := cmd.CombinedOutput()
			if (err != nil) != tc.fail {
				t.Fatalf("refused=%v want=%v: %s", err != nil, tc.fail, out)
			}
			if tc.fail && !strings.Contains(string(out), "but log-server receiver has port 514") {
				t.Fatalf("wrong refusal: %s", out)
			}
		})
	}
}

// Expand the actual wrapper with Ansible's own static import/tag logic. Listing
// tasks is read-only: no controller package, service or remote action can run.
func TestWazuhVersionReceiverFixtureSelectors(t *testing.T) {
	data, err := os.ReadFile("../../docs/topologies/wazuh-version-topology.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var descriptor struct {
		Nodes []struct {
			Name   string
			Groups []string
		}
	}
	if err := yaml.Unmarshal(data, &descriptor); err != nil {
		t.Fatal(err)
	}
	children := map[string]any{}
	for i, node := range descriptor.Nodes {
		for _, group := range node.Groups {
			child, ok := children[group].(map[string]any)
			if !ok {
				child = map[string]any{"hosts": map[string]any{}}
				children[group] = child
			}
			child["hosts"].(map[string]any)[node.Name] = map[string]any{"ansible_host": fmt.Sprintf("192.0.2.%d", i+10)}
		}
	}
	root := t.TempDir()
	inv := filepath.Join(root, "inventory.yml")
	body, err := yaml.Marshal(map[string]any{"all": map[string]any{"children": children}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inv, body, 0600); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(root, "ansible.cfg")
	if err := os.WriteFile(config, []byte("[defaults]\nfact_caching=memory\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		args   []string
		sender bool
	}{
		{name: "full", sender: true},
		{name: "receiver", args: []string{"--tags", "log-server"}, sender: true},
		{name: "sender", args: []string{"--tags", "audit-log-forwarding"}, sender: true},
		{name: "manager only", args: []string{"--tags", "wazuh-manager"}},
		{name: "explicit prerequisite skip", args: []string{"--tags", "log-server", "--skip-tags", "audit-log-forwarding"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{"-i", inv, "../../playbooks/test/fixtures/wazuh-version-topology.yml", "--check", "--list-tasks"}
			args = append(args, tc.args...)
			cmd := exec.Command("ansible-playbook", args...)
			cmd.Env = append(os.Environ(), "ANSIBLE_CONFIG="+config, "ANSIBLE_LOCAL_TEMP="+root)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("static expansion failed: %v\n%s", err, out)
			}
			if strings.Contains(string(out), "Step 1: Install auditd + audispd-plugins + rsyslog") != tc.sender {
				t.Fatalf("sender selection differs: %s", out)
			}
		})
	}
}
