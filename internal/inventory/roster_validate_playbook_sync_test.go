package inventory

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestKnownTopLevelKeysV3_StaysInSyncWithPlaybookGate guards against the
// exact incident class AGENTS.md §0 documents: knownTopLevelKeysV3 here
// and freeipa-identity-apply.yml's "Gate: canonical top-level and FreeIPA
// keys are known" assert are two independent, hand-maintained allowlists
// that MUST agree — a roster the Go validator accepts but the Ansible gate
// rejects (or vice versa) is exactly how a past `domain`/`realm` drift
// broke every roster the sanctioned tooling produced. This only checks the
// schema-v3-only addition (the `if freeipa_roster.schema_version | int >=
// 3` branch) since that's the part most recently touched (grants,
// auth_policies, security — spec.md §5/§21).
func TestKnownTopLevelKeysV3_StaysInSyncWithPlaybookGate(t *testing.T) {
	path := filepath.Join("..", "..", "playbooks", "apply", "freeipa-identity-apply.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("playbook not found: %v", err)
	}

	re := regexp.MustCompile(`schema_version \| int >= 3 else \[\]\)\)\) \| length == 0`)
	if !re.MatchString(string(data)) {
		t.Fatalf("could not find the schema_version >= 3 branch in the playbook's top-level-keys gate; did its shape change?")
	}
	listRe := regexp.MustCompile(`\+ \(\[([^\]]*)\] if freeipa_roster\.schema_version \| int >= 3 else \[\]\)\)\) \| length == 0`)
	m := listRe.FindStringSubmatch(string(data))
	if m == nil {
		t.Fatalf("could not extract the v3-only key list from the playbook gate")
	}
	var playbookKeys []string
	for _, raw := range strings.Split(m[1], ",") {
		playbookKeys = append(playbookKeys, strings.Trim(strings.TrimSpace(raw), "'"))
	}
	sort.Strings(playbookKeys)

	var goV3Only []string
	v2 := map[string]bool{}
	for _, k := range knownTopLevelKeysV2 {
		v2[k] = true
	}
	for _, k := range knownTopLevelKeysV3 {
		if !v2[k] {
			goV3Only = append(goV3Only, k)
		}
	}
	sort.Strings(goV3Only)

	if strings.Join(playbookKeys, ",") != strings.Join(goV3Only, ",") {
		t.Fatalf("playbook gate's v3-only keys %v do not match knownTopLevelKeysV3's v3-only keys %v — update both together", playbookKeys, goV3Only)
	}
}
