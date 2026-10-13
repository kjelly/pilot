package cmd

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/ansible"
	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/delivery"
)

// Captured from ansible-core 2.19.2 running the provider playbook below with
// `--limit provider-b -e target_group=provider -e @vars.yml`, where vars.yml
// sets target_group: consumer (the PR #39 review's reproduction). rc was 0.
const recapNoHostsMatched = `
PLAY [Provider apply] **********************************************************
skipping: no hosts matched

PLAY RECAP *********************************************************************

`

// Captured from the same run with `-e target_group=provider` repeated last.
const recapProviderApplied = `
PLAY [Provider apply] **********************************************************

TASK [Write marker] ************************************************************
changed: [provider-b]

PLAY RECAP *********************************************************************
provider-b                 : ok=1    changed=1    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0

`

func TestCheckAppliedHosts(t *testing.T) {
	colored := strings.Replace(recapProviderApplied, "provider-b                 :", "\x1b[0;33mprovider-b\x1b[0m                 :", 1)
	for _, tc := range []struct {
		name         string
		output       string
		hosts        []string
		requireEvery bool
		wantErr      string
	}{
		{"no hosts matched", recapNoHostsMatched, []string{"provider-b"}, false, "沒有比對到任何預定主機"},
		{"no hosts matched, dependency", recapNoHostsMatched, []string{"provider-b"}, true, "沒有比對到任何預定主機"},
		{"applied", recapProviderApplied, []string{"provider-b"}, true, ""},
		{"colored recap", colored, []string{"provider-b"}, true, ""},
		{"one of two applied", recapProviderApplied, []string{"consumer-a", "provider-b"}, false, ""},
		{"one of two applied, dependency", recapProviderApplied, []string{"consumer-a", "provider-b"}, true, "consumer-a"},
		{"no recap", "PLAY [x] ***\n", []string{"provider-b"}, false, ""},
		{"no recap, dependency", "PLAY [x] ***\n", []string{"provider-b"}, true, "沒有 PLAY RECAP"},
		{"nothing expected", recapNoHostsMatched, nil, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkAppliedHosts(tc.output, tc.hosts, tc.requireEvery)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("err = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

func TestAnsibleExtraVarArgsRepeatsTargetGroupAfterVarsFile(t *testing.T) {
	vault := vaultInput{ExtraVarsFile: "/vault/main.yaml", VaultPasswordFile: "/vault/pass"}
	got := ansibleExtraVarArgs([]string{"target_group=dashboard", "stage=sandbox", "target_group=thanos-query"}, vault)
	want := []string{
		"-e", "target_group=dashboard", "-e", "stage=sandbox", "-e", "target_group=thanos-query",
		"-e", "@/vault/main.yaml", "--vault-password-file", "/vault/pass",
		"-e", "target_group=thanos-query",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args = %q\nwant %q", got, want)
	}
	got = ansibleExtraVarArgs([]string{"stage=sandbox"}, vault)
	want = []string{"-e", "stage=sandbox", "-e", "@/vault/main.yaml", "--vault-password-file", "/vault/pass"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("without target_group: args = %q\nwant %q", got, want)
	}
}

func TestDeploymentAppliedHosts(t *testing.T) {
	applied := []contract.Contract{{ID: "dashboard", Role: "dashboard"}}
	scope := delivery.Scope{HostsByRole: map[string][]string{
		"dashboard":    {"consumer-a", "consumer-b"},
		"thanos-query": {"provider-b"},
	}}
	got := deploymentAppliedHosts(applied, scope, []string{"consumer-a", "localhost", "provider-b"})
	if !reflect.DeepEqual(got, []string{"consumer-a"}) {
		t.Fatalf("applied hosts = %v, want only the included hosts of the applied role", got)
	}
}

// TestDependencyRunIgnoresVarsFileTargetGroup_RealAnsible is the PR #39
// review's reproduction through the real transaction and ansible-playbook: a
// dependency run for provider-b, with the operator's vars file setting
// target_group to the consumer group. The vars file used to come last, so the
// play matched no hosts, exited 0 and was reported as applied.
func TestDependencyRunIgnoresVarsFileTargetGroup_RealAnsible(t *testing.T) {
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	t.Setenv("ANSIBLE_LOCAL_TEMP", t.TempDir())
	t.Setenv("ANSIBLE_CACHE_PLUGIN", "memory")
	t.Setenv("ANSIBLE_FORCE_COLOR", "0")
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("python3 not installed: %v", err)
	}
	dir := t.TempDir()
	write := func(name, content string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	inv := write("inventory.yml", `all:
  vars:
    ansible_connection: local
    ansible_python_interpreter: `+python+`
  hosts:
    consumer-a: {}
    provider-b: {}
  children:
    consumer: {hosts: {consumer-a: {}}}
    provider: {hosts: {provider-b: {}}}
`)
	providerPlaybook := write("provider-apply.yml", `- name: Provider apply
  hosts: "{{ target_group | default('provider') }}"
  gather_facts: false
  tasks:
    - name: Write marker
      ansible.builtin.copy:
        content: "applied\n"
        dest: "{{ marker_dir }}/{{ inventory_hostname }}"
        mode: "0600"
`)
	consumerOnlyPlaybook := write("consumer-only-apply.yml", `- name: Consumer-only apply
  hosts: consumer
  gather_facts: false
  tasks:
    - name: Write marker
      ansible.builtin.copy:
        content: "applied\n"
        dest: "{{ marker_dir }}/{{ inventory_hostname }}"
        mode: "0600"
`)
	varsFile := write("vars.yml", "target_group: consumer\n")

	run := func(t *testing.T, playbook, limit string, hosts []string, requireEvery, preview bool) (string, delivery.Result, error) {
		t.Helper()
		markers := t.TempDir()
		extraVars := dependencyTargetVars([]string{"stage=sandbox", "marker_dir=" + markers}, "provider")
		var out bytes.Buffer
		var result delivery.Result
		err := executeDeploymentTransaction(context.Background(), ansible.NewRunner(), &out, playbook, inv, limit, "", extraVars,
			vaultInput{ExtraVarsFile: varsFile}, deploymentTransactionOptions{
				Authorization: &deploymentAuthorization{Preview: preview}, ResultOut: &result,
				AppliedHosts: hosts, RequireEveryAppliedHost: requireEvery,
			})
		t.Log(out.String())
		return markers, result, err
	}
	marker := func(dir, host string) bool {
		_, err := os.Stat(filepath.Join(dir, host))
		return err == nil
	}

	t.Run("dependency target_group wins over the vars file", func(t *testing.T) {
		markers, result, err := run(t, providerPlaybook, "provider-b", []string{"provider-b"}, true, true)
		if err != nil {
			t.Fatalf("dependency run failed: %v", err)
		}
		if result.Outcome != delivery.OutcomeSuccess || !marker(markers, "provider-b") {
			t.Fatalf("outcome=%s provider marker=%v: the provider was not applied", result.Outcome, marker(markers, "provider-b"))
		}
		if marker(markers, "consumer-a") {
			t.Fatal("the dependency run reached the consumer")
		}
	})

	for _, tc := range []struct {
		name         string
		requireEvery bool
		preview      bool
		failedStep   string
	}{
		{"dependency apply", true, false, "apply"},
		{"dependency preview", true, true, "preview"},
		{"component apply", false, false, "apply"},
	} {
		t.Run("no hosts matched fails the "+tc.name, func(t *testing.T) {
			markers, result, err := run(t, consumerOnlyPlaybook, "provider-b", []string{"provider-b"}, tc.requireEvery, tc.preview)
			if err == nil || !strings.Contains(err.Error(), "沒有比對到任何預定主機") {
				t.Fatalf("err = %v, want the no-hosts-matched failure", err)
			}
			if result.Outcome != delivery.OutcomeFailed || result.FailedStep != tc.failedStep {
				t.Fatalf("result = %+v, want failed at %s", result, tc.failedStep)
			}
			if marker(markers, "provider-b") || marker(markers, "consumer-a") {
				t.Fatal("a marker was written by a run that should have matched no hosts")
			}
		})
	}

	t.Run("a dependency host the play skipped fails the run", func(t *testing.T) {
		_, result, err := run(t, providerPlaybook, "provider-b,consumer-a", []string{"consumer-a", "provider-b"}, true, false)
		if err == nil || !strings.Contains(err.Error(), "consumer-a") {
			t.Fatalf("err = %v, want consumer-a reported as not applied", err)
		}
		if result.Outcome != delivery.OutcomeFailed {
			t.Fatalf("outcome = %s, want failed", result.Outcome)
		}
	})
}
