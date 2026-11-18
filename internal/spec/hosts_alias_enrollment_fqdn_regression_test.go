package spec

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

// TestRegression_HostsAliasResolvesNotYetEnrolledInventoryFQDN runs the real
// shared tasks/resolve-hosts-alias-target.yml under Ansible.
//
// `pilot deploy` proposes the FreeIPA FQDN of a cross-role target (for example
// -e loki_target_host=nexus.ipa.pilot.internal) as soon as the target is a
// freeipa-client and every consumer group declares freeipa-dns-client. On a
// genuinely fresh host the enrollment has not run, so the target's gathered
// ansible_fqdn is still its short hostname, nothing resolves the FQDN, and
// `--check` never performs the enrollment either. The helper then fell through
// to a live lookup that can only fail and the whole site-wide preview stopped on
// that one host (minimal-PoC 5-node clean-room acceptance, nexus, 2026-11-12).
// The helper must resolve the FQDN the inventory host WILL carry from the
// inventory itself, and must still refuse names outside the inventory.
func TestRegression_HostsAliasResolvesNotYetEnrolledInventoryFQDN(t *testing.T) {
	ansible, err := exec.LookPath("ansible-playbook")
	if err != nil {
		t.Skip("ansible-playbook unavailable")
	}
	helper, err := filepath.Abs("../../playbooks/apply/tasks/resolve-hosts-alias-target.yml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(helper); err != nil {
		t.Fatal(err)
	}
	play := []any{map[string]any{
		"hosts":        "runner",
		"gather_facts": false,
		"tasks": []any{
			map[string]any{
				"name":          "Resolve the alias target through the shared helper",
				"include_tasks": helper,
				"vars":          map[string]any{"hosts_alias_target_host": "{{ alias_target }}"},
			},
			map[string]any{
				"name": "Report what the helper resolved",
				"ansible.builtin.assert": map[string]any{
					"that":     []string{"hosts_alias_resolved_ip == expected_ip"},
					"fail_msg": "resolved {{ hosts_alias_resolved_ip }}, want {{ expected_ip }}",
				},
			},
		},
	}}
	playYAML, err := yaml.Marshal(play)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	playPath := filepath.Join(dir, "resolve.yml")
	if err := os.WriteFile(playPath, playYAML, 0600); err != nil {
		t.Fatal(err)
	}

	type host = map[string]any
	// fresh: the host has not been enrolled, so its gathered fact is the short name.
	fresh := func(extra host) host {
		h := host{"ansible_host": "192.0.2.6", "ansible_fqdn": "nexus", "ansible_hostname": "nexus", "freeipa_domain": "ipa.pilot.internal"}
		for k, v := range extra {
			h[k] = v
		}
		return h
	}
	for _, tc := range []struct {
		name     string
		hosts    map[string]host
		target   string
		wantIP   string
		wantFail string // substring of the failure; empty means the run must succeed
	}{
		{
			name:   "fresh-host-inventory-name-plus-domain",
			hosts:  map[string]host{"nexus": fresh(nil)},
			target: "nexus.ipa.pilot.internal", wantIP: "192.0.2.6",
		},
		{
			name:   "fresh-host-short-hostname-differs-from-inventory-name",
			hosts:  map[string]host{"stg-nexus": fresh(nil)},
			target: "nexus.ipa.pilot.internal", wantIP: "192.0.2.6",
		},
		{
			name:   "fresh-host-explicit-ipa-client-fqdn",
			hosts:  map[string]host{"core": fresh(map[string]any{"ansible_hostname": "core-vm", "ipa_client_fqdn": "it-core.ipa.pilot.internal"})},
			target: "it-core.ipa.pilot.internal", wantIP: "192.0.2.6",
		},
		{
			name:   "fresh-host-target-case-is-ignored",
			hosts:  map[string]host{"nexus": fresh(nil)},
			target: "NEXUS.IPA.PILOT.INTERNAL", wantIP: "192.0.2.6",
		},
		{
			name:   "already-enrolled-host-still-matches-its-gathered-fqdn",
			hosts:  map[string]host{"nexus": fresh(map[string]any{"ansible_fqdn": "nexus.ipa.pilot.internal"})},
			target: "nexus.ipa.pilot.internal", wantIP: "192.0.2.6",
		},
		{
			name:   "ip-literal-passes-through",
			hosts:  map[string]host{"nexus": fresh(nil)},
			target: "192.0.2.99", wantIP: "192.0.2.99",
		},
		{
			// The match must only cover hosts of this inventory: another
			// domain falls through to the live lookup, which fails for .invalid.
			name:   "other-domain-is-not-an-inventory-host",
			hosts:  map[string]host{"nexus": fresh(nil)},
			target: "nexus.other.invalid", wantFail: "socket.gaierror",
		},
		{
			name:   "unknown-short-name-under-the-domain-is-not-an-inventory-host",
			hosts:  map[string]host{"nexus": fresh(nil)},
			target: "ghost.ipa.invalid", wantFail: "socket.gaierror",
		},
		{
			// Without freeipa_domain the host does not carry an enrollment FQDN
			// the inventory can derive, so nothing may be guessed.
			name: "host-without-freeipa-domain-is-not-matched",
			hosts: map[string]host{"nexus": {
				"ansible_host": "192.0.2.6", "ansible_fqdn": "nexus", "ansible_hostname": "nexus",
			}},
			target: "nexus.ipa.invalid", wantFail: "socket.gaierror",
		},
		{
			name: "host-without-connection-address-is-not-matched",
			hosts: map[string]host{"nexus": {
				"ansible_fqdn": "nexus", "ansible_hostname": "nexus", "freeipa_domain": "ipa.invalid",
			}},
			target: "nexus.ipa.invalid", wantFail: "socket.gaierror",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hosts := map[string]any{"runner": host{"ansible_connection": "local"}}
			for name, h := range tc.hosts {
				hosts[name] = h
			}
			inventory, err := yaml.Marshal(map[string]any{"all": map[string]any{"hosts": hosts}})
			if err != nil {
				t.Fatal(err)
			}
			invPath := filepath.Join(dir, tc.name+".yml")
			if err := os.WriteFile(invPath, inventory, 0600); err != nil {
				t.Fatal(err)
			}
			vars, _ := json.Marshal(map[string]any{"alias_target": tc.target, "expected_ip": tc.wantIP})
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, ansible, "-i", invPath, playPath, "-e", string(vars))
			cmd.Env = append(os.Environ(), "ANSIBLE_LOCAL_TEMP="+dir, "ANSIBLE_REMOTE_TEMP="+dir, "ANSIBLE_CACHE_PLUGIN=memory")
			out, err := cmd.CombinedOutput()
			if tc.wantFail != "" {
				if err == nil || !strings.Contains(string(out), tc.wantFail) {
					t.Fatalf("expected the live lookup to fail with %q: %v\n%s", tc.wantFail, err, out)
				}
				return
			}
			if err != nil {
				t.Fatalf("helper did not resolve %s: %v\n%s", tc.target, err, out)
			}
		})
	}
}
