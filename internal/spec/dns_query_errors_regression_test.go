package spec

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// dnsQueryErrorsIgnored lists, by "<playbook>::<task name>", every task
// under playbooks/** that runs `ipa dnsrecord-show`/`dnsrecord-find` with
// `failed_when: false`, and why it is still there. Such a task reads a
// Kerberos, LDAP or connection error exactly like "no record": the record
// is never deleted, or a check passes, while the run reports success
// (issue #105). Entries may only be removed: fix the task to fail on every
// error except the captured "absent" ones (see
// freeipa-identity-apply.yml's decommission DNS lookups), then delete its
// entry here.
var dnsQueryErrorsIgnored = map[string]string{
	// Not part of #105's freeipa-client fix; each needs its own vm-target
	// test of the component it belongs to.
	"playbooks/apply/freeipa-dns-apply.yml::Discover current DNS records for each manifest zone (raw ipa CLI output)":                                        "freeipa-dns: a zone that does not exist yet fails here as expected, but so does any other error, which then reads as an empty zone: authoritative-mode pruning removes nothing and the run passes",
	"playbooks/apply/freeipa-dns-apply.yml::Discover current state for each declared A/AAAA/CNAME record":                                                    "freeipa-dns: an error reads as 'record absent', so an explicit `state: absent` record is planned as noop and never deleted while the run passes (a present record is planned as dnsrecord-add, which usually fails on the same error)",
	"playbooks/apply/internal-endpoint-apply.yml::Look up the current live DNS A/AAAA record for the query target endpoint (read-only, decommission verify)": "internal-endpoint decommission verify: InternalEndpointProvider.Verify passes endpoint_dns only on a `not found`, so an error is reported as active_residue (fails closed), but so is `DNS is not configured`: on a server without integrated DNS endpoint_dns can never pass",
	"playbooks/apply/tasks/internal-endpoint-delete.yml::Check current DNS record state for this owner (delete step 1)":                                      "internal-endpoint delete: an error leaves no record value, so the ledger-owned record is silently not deleted and the delete sequence continues",
	"playbooks/apply/tasks/internal-endpoint-direct-dns.yml::Check current DNS record state for this owner":                                                  "internal-endpoint reconcile: an error picks dnsrecord-add instead of dnsrecord-mod; the add usually fails on the same error, but after a transient read error it adds the new value next to the old one",
}

// TestRegression_DNSRecordQueriesFailOnErrors is a repo-wide lint over
// playbooks/**: a task running `ipa dnsrecord-show` or `dnsrecord-find`
// must not set `failed_when: false` unless dnsQueryErrorsIgnored lists it
// with a reason. Issue #105: host decommission's two DNS lookups read any
// error as "no record", so the roster-owned A record was never deleted and
// Verify passed. #102 fixed the sibling lookups but only in one playbook;
// this keeps new DNS lookups anywhere from repeating the pattern
// (AGENTS.md §5.10).
func TestRegression_DNSRecordQueriesFailOnErrors(t *testing.T) {
	var found []string
	for _, path := range playbookFiles(t) {
		rel := strings.TrimPrefix(path, "../../")
		for _, name := range dnsQueriesIgnoringErrors(loadYAML(t, path)) {
			found = append(found, rel+"::"+name)
		}
	}
	for _, key := range found {
		if _, ok := dnsQueryErrorsIgnored[key]; !ok {
			t.Errorf("%s runs an ipa DNS query with failed_when: false, so an error reads as \"no record\"; fail on every error except the captured absent ones (issue #105), or list it in dnsQueryErrorsIgnored with the reason", key)
		}
	}
	for key := range dnsQueryErrorsIgnored {
		if !slices.Contains(found, key) {
			t.Errorf("dnsQueryErrorsIgnored lists %s, which no longer runs an ipa DNS query with failed_when: false; remove it", key)
		}
	}
}

// dnsQueriesIgnoringErrors returns the names of the tasks in a playbook or
// task file (blocks, rescue and always included) that run `ipa
// dnsrecord-show`/`dnsrecord-find` with `failed_when: false`.
func dnsQueriesIgnoringErrors(doc any) []string {
	var names []string
	visit := func(task map[string]any, _ []string) {
		if v, ok := task["failed_when"].(bool); !ok || v {
			return
		}
		for _, module := range []string{"ansible.builtin.command", "command", "ansible.builtin.shell", "shell"} {
			cmd, ok := task[module]
			if !ok {
				continue
			}
			text := fmt.Sprint(cmd)
			if strings.Contains(text, "ipa") && (strings.Contains(text, "dnsrecord-show") || strings.Contains(text, "dnsrecord-find")) {
				name, _ := task["name"].(string)
				names = append(names, name)
			}
		}
	}
	items, _ := doc.([]any)
	for _, item := range items {
		play, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if _, isPlay := play["hosts"]; !isPlay {
			walkTaskTree([]any{play}, nil, visit)
			continue
		}
		for _, section := range []string{"pre_tasks", "tasks", "post_tasks", "handlers"} {
			walkTaskTree(play[section], nil, visit)
		}
	}
	return names
}

func TestDNSQueriesIgnoringErrors(t *testing.T) {
	for _, tc := range []struct {
		name, yaml string
		want       []string
	}{
		{"argv in a play's block", `
- hosts: all
  tasks:
    - block:
        - name: q
          ansible.builtin.command:
            argv: [ipa, dnsrecord-show, zone, name, --all, --raw]
          failed_when: false
`, []string{"q"}},
		{"free-form in a task file", `
- name: q
  ansible.builtin.command: ipa dnsrecord-find zone --all
  failed_when: false
`, []string{"q"}},
		{"failing on unexpected errors is fine", `
- name: q
  ansible.builtin.command:
    argv: [ipa, dnsrecord-show, zone, name]
  failed_when:
    - q.rc != 0
    - "'DNS resource record not found' not in q.stderr"
`, nil},
		{"another ipa command is out of scope", `
- name: q
  ansible.builtin.command: ipa host-show h
  failed_when: false
`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var doc any
			if err := yaml.Unmarshal([]byte(tc.yaml), &doc); err != nil {
				t.Fatal(err)
			}
			if got := dnsQueriesIgnoringErrors(doc); !slices.Equal(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}
