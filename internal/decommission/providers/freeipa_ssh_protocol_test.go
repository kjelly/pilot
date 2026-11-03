package providers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/ansible"
	"go.yaml.in/yaml/v3"
)

const retirementTestFQDN = "retired.ipa.pilot.internal"
const retirementTestAlias = "transport-[old]:1"

func typedRetirementFixture(t *testing.T, status string) map[string]any {
	t.Helper()
	return map[string]any{"schema_version": 1, "kind": "ssh_retirement", "fqdn": retirementTestFQDN,
		"alias": retirementTestAlias, "stage": "sandbox", "status": status}
}

func encodedRetirementFixture(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return "PILOT_SSH_RETIREMENT_V1:" + base64.StdEncoding.EncodeToString(raw)
}

func TestFreeIPAProvider_TypedRetirementRejectsInvalidProof(t *testing.T) {
	valid := encodedRetirementFixture(t, typedRetirementFixture(t, "settled"))
	for _, field := range []string{"schema_version", "kind", "fqdn", "alias", "stage", "status"} {
		t.Run("missing "+field, func(t *testing.T) {
			value := typedRetirementFixture(t, "settled")
			delete(value, field)
			if _, err := retirementObservation(encodedRetirementFixture(t, value), retirementTestFQDN, retirementTestAlias, "sandbox"); err == nil {
				t.Fatal("missing typed field accepted")
			}
		})
	}
	for name, change := range map[string]map[string]any{
		"version": {"schema_version": 2}, "kind": {"kind": "host_object"},
		"fqdn": {"fqdn": "other.ipa.pilot.internal"}, "alias": {"alias": "transport-old"},
		"stage": {"stage": "prod"}, "unknown status": {"status": "unknown"},
		"truthy status": {"status": true}, "null status": {"status": nil},
		"fractional version": {"schema_version": 1.5}, "stage type": {"stage": []string{"sandbox"}},
		"extra field": {"unexpected": true}, "field case": {"Alias": retirementTestAlias},
	} {
		t.Run(name, func(t *testing.T) {
			value := typedRetirementFixture(t, "settled")
			for key, val := range change {
				value[key] = val
			}
			if _, err := retirementObservation(encodedRetirementFixture(t, value), retirementTestFQDN, retirementTestAlias, "sandbox"); err == nil {
				t.Fatal("invalid typed identity/status accepted")
			}
		})
	}
	native, err := os.ReadFile("testdata/ssh-retirement/native-same-host.stdout")
	if err != nil {
		t.Fatal(err)
	}
	for name, output := range map[string]string{
		"native legacy only": string(native), "missing": "", "malformed": "PILOT_SSH_RETIREMENT_V1:%%%",
		"duplicate":            valid + "\n" + valid,
		"contradictory":        valid + "\n" + encodedRetirementFixture(t, typedRetirementFixture(t, "pending")),
		"malformed second":     valid + "\nPILOT_SSH_RETIREMENT_V1:%%%",
		"suffixed token":       valid + "!",
		"duplicate JSON field": "PILOT_SSH_RETIREMENT_V1:" + base64.StdEncoding.EncodeToString([]byte(`{"schema_version":1,"kind":"ssh_retirement","fqdn":"retired.ipa.pilot.internal","alias":"transport-[old]:1","stage":"sandbox","status":"pending","status":"settled"}`)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := retirementObservation(output, retirementTestFQDN, retirementTestAlias, "sandbox"); err == nil {
				t.Fatal("missing, malformed or duplicate proof accepted")
			}
		})
	}
	p := NewFreeIPAClientProvider(FreeIPAClientProviderConfig{Executor: &fakeAnsibleExecutor{fn: func([]string) (*ansible.Result, error) {
		return &ansible.Result{ExitCode: 2, Stdout: valid}, nil
	}}})
	if settled, err := p.retirementSettled(context.Background(), retirementTestFQDN, retirementTestAlias); err == nil || settled {
		t.Fatal("failed Ansible query accepted despite typed-looking stdout")
	}
}

type retirementAnsibleExecutor struct{ stdout string }

func (e *retirementAnsibleExecutor) Run(ctx context.Context, args ...string) (*ansible.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "ansible-playbook", args...)
	command.Env = append(os.Environ(), "ANSIBLE_STDOUT_CALLBACK=default", "ANSIBLE_NOCOLOR=1", "ANSIBLE_CACHE_PLUGIN=memory")
	var stderr strings.Builder
	command.Stderr = &stderr
	out, err := command.Output()
	e.stdout = string(out)
	result := &ansible.Result{Stdout: string(out), Stderr: stderr.String()}
	if exit, ok := err.(*exec.ExitError); ok {
		result.ExitCode = exit.ExitCode()
		return result, nil
	}
	return result, err
}

func retirementQueryHarness(t *testing.T, status string) (string, string) {
	t.Helper()
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		if os.Getenv("PILOT_REQUIRE_CONTAINER_TESTS") == "1" {
			t.Fatal(err)
		}
		t.Skip("ansible-playbook unavailable")
	}
	dir := t.TempDir()
	journal := filepath.Join(dir, "journal.json")
	pending := []string{retirementTestAlias}
	retired := map[string]any{}
	if status == "settled" {
		pending = []string{}
		retired[retirementTestAlias] = map[string]any{"alias": retirementTestAlias, "fqdn": retirementTestFQDN, "stage": "sandbox"}
	}
	state := map[string]any{"version": 1, "domain": "ipa.pilot.internal", "retired": retired,
		"users": map[string]any{"alice": map[string]any{"epoch": "e", "keys": []string{}, "pending": pending}}}
	stateBytes, _ := json.Marshal(state)
	if err := os.WriteFile(journal, stateBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	helper, err := os.ReadFile("../../../playbooks/apply/files/freeipa-ssh-key-cache.py")
	if err != nil {
		t.Fatal(err)
	}
	native, err := os.ReadFile("testdata/ssh-retirement/native-same-host.stdout")
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile("../../../playbooks/apply/freeipa-identity-apply.yml")
	if err != nil {
		t.Fatal(err)
	}
	var plays []map[string]any
	if err := yaml.Unmarshal(source, &plays); err != nil {
		t.Fatal(err)
	}
	receipt := filepath.Join(dir, "resolved-controls.json")
	tasks := []any{map[string]any{"tags": []string{"always"}, "ansible.builtin.debug": map[string]any{"msg": string(native)}},
		map[string]any{"tags": []string{"always"}, "name": "record actual resolved query command inputs", "ansible.builtin.command": map[string]any{
			"argv": []string{"python3", "-c", "import json,pathlib,sys; pathlib.Path(sys.argv[1]).write_text(json.dumps(sys.argv[2:]))",
				receipt, "{{ pilot_decommission_query }}", "{{ pilot_decommission_target_fqdn }}", "{{ pilot_decommission_target_alias }}", "{{ pilot_decommission_retirement_stage }}"}}}}
	block := plays[0]["tasks"].([]any)[0].(map[string]any)["block"].([]any)
	for _, value := range block {
		task := value.(map[string]any)
		if task["name"] == "Inspect durable SSH retirement for the query target (read-only)" || task["name"] == "Print durable SSH retirement inspection for external tooling (read-only)" {
			delete(task, "become")
			tasks = append(tasks, task)
		}
	}
	if len(tasks) != 4 {
		t.Fatal("production typed query emitter missing")
	}
	// The generic query kinds retain their existing envelope/guard. The command
	// receipt independently proves which controls Ansible really resolved.
	tasks = append(tasks, map[string]any{"tags": []string{"always"}, "ansible.builtin.debug": map[string]any{"msg": "HOST_INSPECT[{{ pilot_decommission_target_fqdn }}]: native-query-harness"}})
	play := []map[string]any{{"hosts": "localhost", "connection": "local", "gather_facts": false,
		"vars": map[string]any{"ipa_domain": "ipa.pilot.internal", "ipa_ssh_cache_program": string(helper), "ipa_identity_ssh_cache_state_file": journal}, "tasks": tasks}}
	raw, err := yaml.Marshal(play)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "query.yml")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, receipt
}

func TestFreeIPAProvider_RealTypedRetirementIgnoresNativeCollision(t *testing.T) {
	for _, status := range []string{"pending", "settled"} {
		t.Run(status, func(t *testing.T) {
			path, _ := retirementQueryHarness(t, status)
			real := &retirementAnsibleExecutor{}
			p := NewFreeIPAClientProvider(FreeIPAClientProviderConfig{Executor: real, ServerInventory: "localhost,", IdentityApplyPlaybook: path})
			settled, err := p.retirementSettled(context.Background(), retirementTestFQDN, retirementTestAlias)
			if err != nil || settled != (status == "settled") {
				t.Fatalf("real callback/production parser %s: settled=%v err=%v\n%s", status, settled, err, real.stdout)
			}
			if !strings.Contains(real.stdout, "HOST_INSPECT["+retirementTestFQDN+"]") || !strings.Contains(real.stdout, "PILOT_SSH_RETIREMENT_V1:") {
				t.Fatal("real generic collision and typed emitter did not both execute")
			}
			captured := real.stdout
			p.cfg.Executor = &fakeAnsibleExecutor{fn: func(args []string) (*ansible.Result, error) {
				switch queryKind(args) {
				case "ssh_retirement":
					return &ansible.Result{Stdout: captured}, nil
				case "host_dns":
					return &ansible.Result{Stdout: "HOST_INSPECT[" + retirementTestFQDN + "]: " + dnsShowNotFound}, nil
				default:
					return &ansible.Result{Stdout: "HOST_INSPECT[" + retirementTestFQDN + "]: host not found"}, nil
				}
			}}
			step, err := p.ExecutorForStep(Step{Action: ActionFreeIPAIdentityApplyConverge, TargetIdentity: retirementTestFQDN, Params: map[string]string{"inventory_alias": retirementTestAlias}})
			if err != nil {
				t.Fatal(err)
			}
			if done, err := step.Inspect(context.Background()); err != nil || done != settled {
				t.Fatalf("central Inspect=%v,%v expected settled=%v", done, err, settled)
			}
			rows, err := p.Verify(context.Background(), VerifyInput{FQDN: retirementTestFQDN, InventoryAlias: retirementTestAlias})
			if err != nil {
				t.Fatal(err)
			}
			if row := findVerification(t, rows, "ssh_cache_retirement"); row.Active == settled {
				t.Fatalf("independent Verify ignored typed status: %+v", row)
			}
		})
	}
}

func TestFreeIPAProvider_RealQueryControlsOverrideExtraVars(t *testing.T) {
	for _, kind := range []string{"host_object", "host_dns", "hbac_references", "sudo_references", "ssh_retirement"} {
		t.Run(kind, func(t *testing.T) {
			path, receipt := retirementQueryHarness(t, "pending")
			bad := map[string]string{"pilot_decommission_query": "wrong", "pilot_decommission_target_fqdn": "wrong.invalid",
				"pilot_decommission_target_alias": "wrong-alias", "pilot_decommission_retirement_stage": "prod"}
			body, _ := json.Marshal(bad)
			varsFile := filepath.Join(t.TempDir(), "conflicting-vars.json")
			if err := os.WriteFile(varsFile, body, 0o600); err != nil {
				t.Fatal(err)
			}
			p := NewFreeIPAClientProvider(FreeIPAClientProviderConfig{Executor: &retirementAnsibleExecutor{}, ServerInventory: "localhost,", IdentityApplyPlaybook: path,
				ExtraArgs: []string{"-e", string(body), "-e", "@" + varsFile}})
			_, err := p.queryWithAlias(context.Background(), kind, retirementTestFQDN, retirementTestAlias)
			raw, readErr := os.ReadFile(receipt)
			if readErr != nil {
				t.Fatalf("actual query command never recorded controls: %v (query error %v)", readErr, err)
			}
			var got []string
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatal(err)
			}
			want := []string{kind, retirementTestFQDN, retirementTestAlias, "sandbox"}
			if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
				t.Fatalf("resolved query controls changed: got %q want %q", got, want)
			}
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
