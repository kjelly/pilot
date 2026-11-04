package spec

import (
	"os"
	"os/exec"
	"slices"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestRegression_GatewayScopeLifecycleModel(t *testing.T) {
	command := exec.Command("python3", "../../scripts/test-freeipa-gateway-scope.py")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("gateway ownership/retirement model: %v\n%s", err, output)
	}
}

func TestRegression_GatewayCleanupPrecedesUnchangedDeletionGates(t *testing.T) {
	source, err := os.ReadFile("../../playbooks/apply/freeipa-identity-apply.yml")
	if err != nil {
		t.Fatal(err)
	}
	var plays []map[string]any
	if err := yaml.Unmarshal(source, &plays); err != nil {
		t.Fatal(err)
	}
	block := plays[0]["tasks"].([]any)[0].(map[string]any)["block"].([]any)
	index := map[string]int{}
	for position, value := range block {
		task := value.(map[string]any)
		name, _ := task["name"].(string)
		index[name] = position
	}
	preflight := "Validate absent host gateway ownership before managed identity mutations"
	cleanup := "Retire proven gateway memberships and persist re-add barriers"
	for _, name := range []string{preflight, cleanup} {
		if _, ok := index[name]; !ok {
			t.Fatalf("production gateway lifecycle task missing: %s", name)
		}
	}
	if index[preflight] >= index["Ensure IPA groups exist"] {
		t.Fatal("gateway ownership preflight must precede the first managed IPA mutation")
	}
	for _, gate := range []string{
		"Look up the current live host object for each absent roster host (spec.md §16.6/§16.7)",
		"Gate: no unknown/unproven service principal remains before deleting an absent host",
		"Gate: no residual hostgroup/netgroup membership before deleting an absent host",
		"Check the current DNS A record value for each absent host's owner (surgical delete step 1)",
	} {
		position, exists := index[gate]
		if !exists || position <= index[cleanup] {
			t.Fatalf("gateway cleanup must precede live re-probe and existing deletion gate %s", gate)
		}
	}
	task := block[index[cleanup]].(map[string]any)
	if !slices.Contains(task["tags"].([]any), any("hosts")) || !slices.Contains(task["tags"].([]any), any("identity")) {
		t.Fatal("gateway cleanup must be selected with existing identity/hosts deletion")
	}
	request := task["vars"].(map[string]any)["ipa_gateway_lifecycle_request"].(map[string]any)
	if request["retirements"] != "{{ ipa_ssh_cache_retirements }}" {
		t.Fatal("gateway retirement must reuse preflight-authorized exact identities")
	}
}
