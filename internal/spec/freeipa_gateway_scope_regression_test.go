package spec

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

type gatewayCommandObservation struct {
	RC                int    `json:"rc"`
	Stderr            string `json:"stderr"`
	Changed           bool   `json:"changed"`
	Failed            bool   `json:"failed"`
	ChangedWhenResult any    `json:"changed_when_result"`
}

// Ansible callbacks may omit/null this diagnostic or emit the evaluated
// boolean. A conditional-error payload is never a successful changed result.
func checkGatewayCommandObservation(raw string, want gatewayCommandObservation) (gatewayCommandObservation, error) {
	var callback struct {
		Plays []struct {
			Tasks []struct {
				Hosts map[string]gatewayCommandObservation
			}
		}
	}
	if err := json.Unmarshal([]byte(raw), &callback); err != nil {
		return gatewayCommandObservation{}, err
	}
	var observations []gatewayCommandObservation
	for _, play := range callback.Plays {
		for _, task := range play.Tasks {
			for _, host := range task.Hosts {
				observations = append(observations, host)
			}
		}
	}
	if len(observations) != 1 {
		return gatewayCommandObservation{}, fmt.Errorf("expected one command observation, got %d", len(observations))
	}
	got := observations[0]
	switch value := got.ChangedWhenResult.(type) {
	case nil:
	case bool:
		if value != want.Changed {
			return got, fmt.Errorf("changed_when_result boolean %t does not match expected changed=%t", value, want.Changed)
		}
	default:
		return got, fmt.Errorf("changed_when_result contains a conditional-error payload (%T)", value)
	}
	if got.RC != want.RC || got.Stderr != want.Stderr || got.Changed != want.Changed || got.Failed != want.Failed {
		return got, fmt.Errorf("unexpected command observation: got %+v, want %+v", got, want)
	}
	return got, nil
}

func TestRegression_GatewayScopeChangedWhenObservationTypes(t *testing.T) {
	for _, tc := range []struct {
		name, diagnostic string
		changed, failed  bool
		valid            bool
	}{
		{"missing", "", true, true, true},
		{"null", "null", true, true, true},
		{"true failure", "true", true, true, true},
		{"true changed success", "true", true, false, true},
		{"false unchanged success", "false", false, false, true},
		{"null unchanged success", "null", false, false, true},
		{"missing unchanged success", "", false, false, true},
		{"string true", `"true"`, true, true, false},
		{"padded string true", `" true"`, true, true, false},
		{"conditional error", `"Error while evaluating from_json: Expecting value"`, true, true, false},
		{"map", `{"error":"from_json"}`, true, true, false},
		{"array", `["from_json"]`, true, true, false},
		{"number", "1", true, true, false},
		{"true mismatch", "true", false, false, false},
		{"false mismatch", "false", true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := gatewayCommandObservation{Changed: tc.changed, Failed: tc.failed}
			if tc.failed {
				want.RC, want.Stderr = 7, "native-failure"
			}
			host, _ := json.Marshal(want)
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(host, &fields); err != nil {
				t.Fatal(err)
			}
			delete(fields, "changed_when_result")
			if tc.diagnostic != "" {
				fields["changed_when_result"] = json.RawMessage(tc.diagnostic)
			}
			raw, err := json.Marshal(map[string]any{"plays": []any{map[string]any{"tasks": []any{map[string]any{"hosts": map[string]any{"localhost": fields}}}}}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := checkGatewayCommandObservation(string(raw), want); (err == nil) != tc.valid {
				t.Fatalf("valid=%v observation=%s err=%v", tc.valid, raw, err)
			}
		})
	}
}

func TestRegression_GatewayScopeLifecycleModel(t *testing.T) {
	command := exec.Command("python3", "../../scripts/test-freeipa-gateway-scope.py")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("gateway ownership/retirement model: %v\n%s", err, output)
	}
}

func TestRegression_GatewayScopeAuthorityInventoryContract(t *testing.T) {
	source, err := os.ReadFile("../../contracts/pilot-gateway-scope.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var contract struct {
		GroupVars []struct{ Name string } `yaml:"groupVars"`
	}
	if err := yaml.Unmarshal(source, &contract); err != nil {
		t.Fatal(err)
	}
	canonical := false
	for _, input := range contract.GroupVars {
		if input.Name == "ipa_server_fqdn" {
			t.Fatal("derived/one-shot IPA alias must not become a global inventory input")
		}
		canonical = canonical || input.Name == "freeipa_server_fqdn"
	}
	if !canonical {
		t.Fatal("canonical freeipa_server_fqdn authority input is missing")
	}
	document, err := os.ReadFile("../../docs/verification/pilot-gateway-scope.md")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(document), "| `freeipa_server_fqdn` |") || strings.Contains(string(document), "| `ipa_server_fqdn`") {
		t.Fatal("inventory-input table must document the canonical authority; keep one-shot alias compatibility outside it")
	}
}

func TestRegression_GatewayRetirementFixtureNativeSequenceBehavior(t *testing.T) {
	command := exec.Command("python3", "../../scripts/test-gateway-scope-retirement-fixture.py", "-v")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("exact fixture script native-type behavior: %v\n%s", err, output)
	}
}

func TestRegression_GatewayRetirementFixturePreservesNativeFailure(t *testing.T) {
	source, err := os.ReadFile("../../playbooks/test/fixtures/gateway-scope-retirement-fixtures.yml")
	if err != nil {
		t.Fatal(err)
	}
	var plays []map[string]any
	if err := yaml.Unmarshal(source, &plays); err != nil {
		t.Fatal(err)
	}
	block := plays[3]["tasks"].([]any)[0].(map[string]any)["block"].([]any)
	task := block[2].(map[string]any)
	task["ansible.builtin.command"].(map[string]any)["argv"] = []string{"/bin/sh", "-c", "echo fixture-native-failure >&2; exit 7"}
	for _, control := range []string{"guarded", "unguarded-json-negative-control"} {
		t.Run(control, func(t *testing.T) {
			if control != "guarded" {
				task["changed_when"] = "(issue227_fixture_authorization.stdout | from_json).changed | bool"
			}
			result := runGatewayTasks(t, t.TempDir(), []any{task}, nil, nil)
			if result.rc == 0 || len(result.failures) != 1 {
				t.Fatalf("native fixture failure was swallowed: rc=%d failures=%v", result.rc, result.failures)
			}
			want := gatewayCommandObservation{RC: 7, Stderr: "fixture-native-failure", Changed: true, Failed: true}
			got, err := checkGatewayCommandObservation(result.raw, want)
			if control == "guarded" {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				assertGatewayConditionalError(t, got, want, err)
			}
		})
	}
}

func assertGatewayConditionalError(t *testing.T, got, want gatewayCommandObservation, err error) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), "changed_when_result contains a conditional-error payload") ||
		!strings.Contains(fmt.Sprint(got.ChangedWhenResult), "from_json") ||
		got.RC != want.RC || got.Stderr != want.Stderr || !got.Failed || !got.Changed {
		t.Fatalf("unguarded JSON must fail specifically with its conditional error while retaining native failure: observation=%+v err=%v", got, err)
	}
}

func TestRegression_GatewayLifecyclePreservesFailureAndStructuredChange(t *testing.T) {
	source, err := os.ReadFile("../../playbooks/apply/tasks/freeipa-gateway-scope-lifecycle.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"failure", "unchanged", "changed"} {
		t.Run(scenario, func(t *testing.T) {
			var tasks []map[string]any
			if err := yaml.Unmarshal(source, &tasks); err != nil {
				t.Fatal(err)
			}
			task := tasks[1]
			delete(task, "become")
			script := `printf '%s' '{"changed":false}'`
			switch scenario {
			case "changed":
				script = `printf '%s' '{"changed":true}'`
			case "failure":
				script = "echo lifecycle-native-failure >&2; exit 7"
			}
			task["ansible.builtin.command"].(map[string]any)["argv"] = []string{"/bin/sh", "-c", script}
			vars := map[string]any{"ipa_gateway_lifecycle_request": map[string]any{}, "ipa_gateway_lifecycle_authority": "ipa.ipa227.test", "freeipa_domain": "ipa227.test"}
			result := runGatewayTasks(t, t.TempDir(), []any{task}, vars, nil)
			if (result.rc != 0) != (scenario == "failure") {
				t.Fatalf("wrong lifecycle status for %s: rc=%d failures=%v", scenario, result.rc, result.failures)
			}
			if result.changed["Run the serialized gateway scope lifecycle"] != (scenario != "unchanged") {
				t.Fatalf("lifecycle must retain structured change or conservatively report partial failure: %v", result.changed)
			}
			want := gatewayCommandObservation{Changed: scenario != "unchanged", Failed: scenario == "failure"}
			if scenario == "failure" {
				want.RC, want.Stderr = 7, "lifecycle-native-failure"
				if len(result.failures) != 1 {
					t.Fatalf("expected exactly one failed command: %v", result.failures)
				}
			}
			if _, err := checkGatewayCommandObservation(result.raw, want); err != nil {
				t.Fatal(err)
			}
			if scenario == "failure" {
				t.Run("unguarded-json-negative-control", func(t *testing.T) {
					task["changed_when"] = "(ipa_gateway_lifecycle_result.stdout | from_json).changed | bool"
					negative := runGatewayTasks(t, t.TempDir(), []any{task}, vars, nil)
					if negative.rc == 0 || len(negative.failures) != 1 {
						t.Fatalf("negative control must retain the failed execution: rc=%d failures=%v", negative.rc, negative.failures)
					}
					got, err := checkGatewayCommandObservation(negative.raw, want)
					assertGatewayConditionalError(t, got, want, err)
				})
			}
		})
	}
}

func TestRegression_GatewayDisableMasksInheritedHostsAtTaskBoundary(t *testing.T) {
	publisherSource, err := os.ReadFile("../../playbooks/apply/gateway-scope-apply.yml")
	if err != nil {
		t.Fatal(err)
	}
	includeSource, err := os.ReadFile("../../playbooks/apply/tasks/freeipa-gateway-scope-lifecycle.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"disable-stale", "disable-malformed", "disable-undefined", "none", "enable", "canonical-authority", "one-shot-authority"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			var plays []map[string]any
			if err := yaml.Unmarshal(publisherSource, &plays); err != nil {
				t.Fatal(err)
			}
			var publication map[string]any
			for _, value := range plays[0]["tasks"].([]any) {
				if block, ok := value.(map[string]any)["block"].([]any); ok {
					for _, task := range block {
						if task.(map[string]any)["name"] == "Publish the owned gateway scope under its lifecycle lock" {
							publication = task.(map[string]any)
						}
					}
				}
			}
			if publication == nil {
				t.Fatal("production publisher boundary missing")
			}
			var include []map[string]any
			if err := yaml.Unmarshal(includeSource, &include); err != nil {
				t.Fatal(err)
			}
			expected := []string{"keep.ipa227.test"}
			action := scenario
			if scenario == "canonical-authority" || scenario == "one-shot-authority" {
				action = "none"
			}
			if strings.HasPrefix(scenario, "disable-") {
				action, expected = "disable", []string{}
			}
			authority := "ipa.ipa227.test"
			if scenario == "one-shot-authority" {
				authority = "override.ipa227.test"
			}
			program := "import json,sys; data=json.load(sys.stdin); assert data['hosts']==json.loads(sys.argv[1]); assert data['authority']==sys.argv[2]; print(json.dumps({'changed':False}))"
			rawExpected, _ := json.Marshal(expected)
			delete(include[1], "become")
			include[1]["ansible.builtin.command"].(map[string]any)["argv"] = []string{"python3", "-c", program, string(rawExpected), authority}
			body, err := yaml.Marshal(include)
			if err != nil {
				t.Fatal(err)
			}
			includePath := filepath.Join(dir, "request-observer.yml")
			if err := os.WriteFile(includePath, body, 0o600); err != nil {
				t.Fatal(err)
			}
			publication["ansible.builtin.include_tasks"].(map[string]any)["file"] = includePath
			vars := map[string]any{"freeipa_server_fqdn": "ipa.ipa227.test", "freeipa_domain": "ipa227.test", "gateway_scope": "i227", "gateway_scope_plan_only": true, "gateway_scope_automember_action": action, "gateway_scope_hosts": []string{"keep.ipa227.test"}}
			switch scenario {
			case "disable-stale":
				vars["gateway_scope_hosts"] = []string{"deleted.ipa227.test", "ambiguous"}
			case "disable-malformed":
				vars["gateway_scope_hosts"] = map[string]any{"not": "a host list"}
			case "disable-undefined":
				delete(vars, "gateway_scope_hosts")
			case "one-shot-authority":
				vars["ipa_server_fqdn"] = authority
			}
			result := runGatewayTasks(t, dir, []any{publication}, vars, nil)
			if result.rc != 0 {
				t.Fatalf("publisher action=%s must send the correct action-specific host input: failures=%v stderr=%s", scenario, result.failures, result.stderr)
			}
		})
	}
}

func TestRegression_GatewayRetirementFixtureHasOneTimeImmutableSetup(t *testing.T) {
	source, err := os.ReadFile("../../playbooks/test/fixtures/gateway-scope-retirement-fixtures.yml")
	if err != nil {
		t.Fatal(err)
	}
	var plays []map[string]any
	if err := yaml.Unmarshal(source, &plays); err != nil {
		t.Fatal(err)
	}
	if len(plays) != 5 {
		t.Fatalf("fixture must retain marker, user, publisher, auth setup, identity stages: %d", len(plays))
	}
	for index, path := range map[int]string{1: "freeipa-client-fixtures.yml", 2: "../../apply/gateway-scope-apply.yml", 4: "../../apply/freeipa-identity-apply.yml"} {
		if plays[index]["ansible.builtin.import_playbook"] != path {
			t.Fatalf("stage %d must use canonical production/fixture entry %s", index, path)
		}
	}
	for _, index := range []int{1, 2} {
		if plays[index]["when"] != "issue227_fixture_prepare | bool" {
			t.Fatal("one-time user/publication setup must use the frozen marker decision")
		}
	}
	if plays[1]["vars"].(map[string]any)["ipa_fixture_manage_sudorule"] != false {
		t.Fatal("canonical user fixture must not create a broad pilot-all sudo rule")
	}
	if strings.Count(string(source), "issue227_fixture_prepare:") != 1 {
		t.Fatal("setup gate must be assigned once before imports, never changed inside its gated block")
	}
	setup := plays[3]["tasks"].([]any)[0].(map[string]any)
	if setup["when"] != "issue227_fixture_prepare | bool" || setup["always"] == nil {
		t.Fatal("scoped authorization setup must use the frozen decision and always close its private ticket")
	}
	if plays[3]["environment"] != nil || setup["environment"] == nil {
		t.Fatal("fixture credential environment belongs to its private-cache block, never the play")
	}
	block := setup["block"].([]any)
	marker := block[len(block)-1].(map[string]any)
	copyTask := marker["ansible.builtin.copy"].(map[string]any)
	if copyTask["dest"] != "/var/lib/pilot-identity/issue227-fixture-ready" || marker["when"] != "not ansible_check_mode" {
		t.Fatal("explicit readiness marker must be last and must not publish from check mode")
	}
	program, err := os.ReadFile("../../playbooks/test/fixtures/files/gateway-scope-retirement-setup.py")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(program), "user_add") || !strings.Contains(string(program), "('sshd', 'sudo')") || !strings.Contains(string(program), "!authenticate") {
		t.Fatal("setup must retain canonical-only user creation and scoped sshd/sudo authorization")
	}
	guard := plays[0]["tasks"].([]any)[0]
	for _, selection := range []string{"full", "tags", "skip-tags"} {
		t.Run(selection, func(t *testing.T) {
			dir := t.TempDir()
			marker := filepath.Join(dir, "fixture-mutation")
			tasks := []any{guard, map[string]any{"name": "fixture mutation sentinel", "tags": []string{"always"}, "ansible.builtin.command": map[string]any{"argv": []string{"touch", marker}}}}
			var args []string
			switch selection {
			case "tags":
				args = []string{"--tags", "identity"}
			case "skip-tags":
				args = []string{"--skip-tags", "fixtures"}
			}
			result := runGatewayTasks(t, dir, tasks, nil, nil, args...)
			_, markerErr := os.Stat(marker)
			allowed := selection == "full"
			if (markerErr == nil) != allowed || (result.rc == 0) != allowed {
				t.Fatalf("fixture selector guard allowed=%v mutation=%v rc=%d failures=%v stderr=%s", allowed, markerErr == nil, result.rc, result.failures, result.stderr)
			}
			if !allowed && !strings.Contains(fmt.Sprint(result.failures), "standalone full run") {
				t.Fatalf("fixture refused for wrong reason: %v", result.failures)
			}
		})
	}
}

func TestRegression_GatewayRetirementSpecsUseEffectiveRoleScopedOracles(t *testing.T) {
	for _, tc := range []struct {
		name, role, os, version string
		expected                []string
	}{
		{"server", "freeipa-server", "almalinux", "9", []string{"scope-preserved-retiring-member-absent", "retiring-host-absent"}},
		{"client", "freeipa-client", "ubuntu", "24.04", []string{"survivor-sshd-account-allowed", "0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := Parse("../../docs/verification/gateway-scope-retirement-" + tc.name + ".md")
			if err != nil {
				t.Fatal(err)
			}
			if spec.SchemaVersion != 2 || !slices.Equal(spec.Roles, []string{tc.role}) || len(spec.Rows) != 2 {
				t.Fatalf("scope/row contract changed: %+v", spec)
			}
			if len(spec.Platforms) != 1 || spec.Platforms[0].OS != tc.os || !slices.Equal(spec.Platforms[0].Versions, []string{tc.version}) {
				t.Fatalf("%s acceptance must declare its actual %s %s target: %+v", tc.role, tc.os, tc.version, spec.Platforms)
			}
			for index, row := range spec.Rows {
				if row.ID != fmt.Sprint("C", index+1) || !row.VerifyOnly || row.Become == nil || !*row.Become {
					t.Fatalf("root effective-state row contract changed: %+v", row)
				}
				if row.Expect.ExitCode == nil || *row.Expect.ExitCode != 0 || row.Expect.Stdout == nil || row.Expect.Stdout.Equals == nil || *row.Expect.Stdout.Equals != tc.expected[index] {
					t.Fatalf("row %s must require both rc0 and exact effective-state output", row.ID)
				}
				for _, observation := range []ProbeResult{{Stdout: "wrong", ExitCode: 0}, {Stdout: tc.expected[index], ExitCode: 1}} {
					if row.Expect.Eval(observation).Pass {
						t.Fatalf("row %s accepted a failed effective-state observation: %+v", row.ID, observation)
					}
				}
				if !row.Expect.Eval(ProbeResult{Stdout: tc.expected[index], ExitCode: 0}).Pass {
					t.Fatalf("row %s rejected the captured positive observation", row.ID)
				}
			}
			if tc.name == "server" {
				if !strings.Contains(spec.Rows[0].Command, "keep.ipa227.test") || !strings.Contains(spec.Rows[0].Command, "retire.ipa227.test") || !strings.Contains(spec.Rows[1].Command, "retire.ipa227.test") {
					t.Fatal("server oracle lost exact keeper/retiring identities")
				}
			} else if !strings.Contains(spec.Rows[0].Command, "pam_acct_mgmt: Success") || !strings.Contains(spec.Rows[1].Command, "runuser -u pilotuser -- sudo -n /usr/bin/id -u") {
				t.Fatal("client oracle must test the real sshd PAM decision and sudo result")
			}
		})
	}
}

// Exercise actual production when/tag selection and the existing retirement
// planner before an external mutation sentinel. Only the native IPA backend
// is replaced by the captured-envelope model; no direct host mapping is
// invented by this harness. Real FreeIPA behavior remains a target gate.
func TestRegression_GatewayAbsentMappingRefusesBeforeUnrelatedMutation(t *testing.T) {
	preflightName := "Validate absent host gateway ownership before managed identity mutations"
	sshProgram, err := os.ReadFile("../../playbooks/apply/files/freeipa-ssh-key-cache.py")
	if err != nil {
		t.Fatal(err)
	}
	modelPath, err := filepath.Abs("../../scripts/test-freeipa-gateway-scope.py")
	if err != nil {
		t.Fatal(err)
	}
	sshInclude, err := filepath.Abs("../../playbooks/apply/tasks/freeipa-ssh-cache-preflight.yml")
	if err != nil {
		t.Fatal(err)
	}
	lifecycleSource, err := os.ReadFile("../../playbooks/apply/tasks/freeipa-gateway-scope-lifecycle.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"unmapped", "unknown", "explicit", "receipt", "inventory", "legacy-no-gateway", "auto-no-membership", "pending-no-membership", "counterexample-old-selector"} {
		selectors := []string{"all"}
		if scenario == "unmapped" || scenario == "unknown" {
			selectors = []string{"all", "identity", "hosts", "users", "check"}
		}
		for _, selector := range selectors {
			t.Run(scenario+"/"+selector, func(t *testing.T) {
				dir := t.TempDir()
				journal, sentinel := filepath.Join(dir, "ssh-cache.json"), filepath.Join(dir, "unrelated-mutation")
				state := map[string]any{"version": 1, "domain": "ipa227.test", "users": map[string]any{}}
				retirement := map[string]any{"alias": "old", "fqdn": "cap-a.ipa227.test", "stage": "sandbox", "reason": "approved", "origin": "test-plan"}
				if scenario == "receipt" {
					state["retired"] = map[string]any{"old": retirement}
				}
				jsonState, err := json.Marshal(state)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(journal, jsonState, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(journal+".lock", nil, 0o600); err != nil {
					t.Fatal(err)
				}
				var lifecycle []map[string]any
				if err := yaml.Unmarshal(lifecycleSource, &lifecycle); err != nil {
					t.Fatal(err)
				}
				command := lifecycle[1]
				delete(command, "become")
				program := `import importlib.util,json,sys
spec=importlib.util.spec_from_file_location('gateway_model',sys.argv[1])
module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
case=module.LifecycleTest(); case.setUp()
scenario=sys.argv[2]; data=json.load(sys.stdin)
if scenario=='unknown': case.state['scopes']={}
if scenario in ('legacy-no-gateway','auto-no-membership','pending-no-membership'):
 case.model.hosts.remove(case.model.a)
 if scenario=='auto-no-membership': case.model.rules[case.model.name]['automemberinclusiveregex']=['fqdn=.*']
 else: del case.model.rules[case.model.name]
 if scenario=='pending-no-membership': case.state['retired'][case.model.a]={'status':'pending'}
try: print(json.dumps(case.helper().retire(case.state,data,True)))
finally: case.tearDown(); case.doCleanups()
`
				command["ansible.builtin.command"].(map[string]any)["argv"] = []string{"python3", "-c", program, modelPath, scenario}
				includeBody, err := yaml.Marshal(lifecycle)
				if err != nil {
					t.Fatal(err)
				}
				includePath := filepath.Join(dir, "gateway-native-model.yml")
				if err := os.WriteFile(includePath, includeBody, 0o600); err != nil {
					t.Fatal(err)
				}
				production := identityTasks(t, []string{retirementPreflight, preflightName})
				if len(production) != 2 {
					t.Fatal("production retirement preflights missing")
				}
				production[0].(map[string]any)["ansible.builtin.include_tasks"].(map[string]any)["file"] = sshInclude
				production[1].(map[string]any)["ansible.builtin.include_tasks"].(map[string]any)["file"] = includePath
				if scenario == "counterexample-old-selector" {
					// Bounded negative control: the old production selector skips
					// the ownership probe when the real planner has no mapping.
					// The independent sentinel must demonstrate that old mutation.
					production[1].(map[string]any)["when"] = []string{"pilot_decommission_query | default('') | length == 0", "ipa_ssh_cache_retirements | default([]) | length > 0"}
				}
				tasks := []any{}
				tasks = append(tasks, production...)
				tasks = append(tasks, map[string]any{"name": "unrelated managed mutation", "tags": []string{"always"}, "ansible.builtin.command": map[string]any{"argv": []string{"touch", sentinel}}})
				vars := map[string]any{"stage": "sandbox", "freeipa_domain": "ipa227.test", "ipa_domain": "ipa227.test", "ipa_ssh_cache_program": string(sshProgram),
					"ipa_gateway_lifecycle_designated_authority": "ipa.ipa227.test", "ipa_identity_ssh_cache_state_file": journal,
					"ipa_identity_cache_recovery_tags": []string{"identity", "hosts", "users"},
					"freeipa_roster":                   map[string]any{"hosts": []any{map[string]any{"name": "cap-a.ipa227.test", "state": "absent"}}}}
				if scenario == "explicit" {
					vars["ipa_identity_ssh_cache_retirements"] = []any{retirement}
				}
				args := []string{"--tags", selector}
				if selector == "check" {
					args = []string{"--check", "--tags", "identity"}
				}
				if scenario == "inventory" {
					// Static inventory keeps the play's actual target singleton;
					// add_host changes ansible_play_hosts_all during a running play.
					inventoryPath := filepath.Join(dir, "inventory.yml")
					inventory := "all:\n  children:\n    freeipa-client:\n      hosts:\n        old:\n          ipa_client_fqdn: cap-a.ipa227.test\n"
					if err := os.WriteFile(inventoryPath, []byte(inventory), 0o600); err != nil {
						t.Fatal(err)
					}
					args = append(args, "-i", inventoryPath)
				}
				result := runGatewayTasks(t, dir, tasks, vars, nil, args...)
				var callback struct {
					Plays []struct {
						Tasks []struct {
							Hosts map[string]struct{ Stderr string }
						}
					}
				}
				if err := json.Unmarshal([]byte(result.raw), &callback); err != nil {
					t.Fatal(err)
				}
				var diagnostics strings.Builder
				for _, play := range callback.Plays {
					for _, task := range play.Tasks {
						for _, host := range task.Hosts {
							diagnostics.WriteString(host.Stderr)
						}
					}
				}
				allowed := slices.Contains([]string{"explicit", "receipt", "inventory", "legacy-no-gateway", "counterexample-old-selector"}, scenario)
				_, markerErr := os.Stat(sentinel)
				if (markerErr == nil) != allowed || (result.rc == 0) != allowed {
					t.Fatalf("allowed=%v mutation=%v rc=%d failures=%v\n%s\n%s", allowed, markerErr == nil, result.rc, result.failures, result.stderr, diagnostics.String())
				}
				if !allowed {
					want := "exact authorized alias/FQDN/stage mapping"
					if scenario == "unknown" {
						want = "unproven hostgroup ownership"
					}
					if !strings.Contains(fmt.Sprint(result.failures)+diagnostics.String(), want) {
						t.Fatalf("wrong early refusal, want %s: %v\n%s", want, result.failures, diagnostics.String())
					}
				}
			})
		}
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
	if index[preflight] >= index["Prepare legacy authorization cache recovery"] {
		t.Fatal("gateway ownership preflight must precede unrelated cache recovery journal mutation")
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
