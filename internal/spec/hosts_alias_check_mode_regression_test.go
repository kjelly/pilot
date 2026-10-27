package spec

import (
	"os"
	"testing"

	"go.yaml.in/yaml/v3"
)

// TestRegression_HostsAliasLookupRunsUnderCheckMode pins check_mode: false on
// the lookup in the shared tasks/resolve-hosts-alias-target.yml. It is a
// read-only command (an IP-literal check or a resolver lookup) whose stdout
// becomes hosts_alias_resolved_ip. Skipped under --check, the register has
// no stdout, the fact is "", and every apply playbook that includes the file
// (prometheus, thanos-query, detection-engine, wazuh-*, restic-backup,
// log-shipping, audit-log-forwarding) previews its /etc/hosts pin as
// "\t<alias>" — a false "changed" that read as the IP being removed. Seen on a
// reconcile preview of prometheus: thanos-s3-backend and alertmanager-backend
// went from 10.1.58.12 to nothing, so the preview looked like it would break
// both backends.
func TestRegression_HostsAliasLookupRunsUnderCheckMode(t *testing.T) {
	const path = "../../playbooks/apply/tasks/resolve-hosts-alias-target.yml"
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var tasks []map[string]any
	if err := yaml.Unmarshal(raw, &tasks); err != nil {
		t.Fatalf("%s: parse: %v", path, err)
	}
	found := 0
	for _, task := range tasks {
		if task["register"] != "hosts_alias_dns_lookup" {
			continue
		}
		found++
		if got, ok := task["check_mode"].(bool); !ok || got {
			t.Errorf("%v: check_mode = %v, want false so the lookup also runs under --check", task["name"], task["check_mode"])
		}
	}
	if found != 1 {
		t.Fatalf("%s: found %d tasks registering hosts_alias_dns_lookup, want exactly 1", path, found)
	}
}
