package providers

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/ansible"
)

func TestFreeIPAQuery_NoHostsIsRequiredByCI(t *testing.T) {
	data, err := os.ReadFile("../../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^\tPILOT_REQUIRE_CONTAINER_TESTS=1 go test .* -run '([^']+)' ./internal/decommission/providers/`).FindSubmatch(data)
	if m == nil || !regexp.MustCompile(strings.ReplaceAll(string(m[1]), "$$", "$")).MatchString("TestFreeIPAQuery_NoHostsIsNotAnObservation") {
		t.Fatal("CI's required Ansible recipe does not select the no-hosts regression")
	}
}

// A successful process is insufficient: Ansible deliberately exits zero
// when its host pattern matches no inventory host.
func TestFreeIPAQuery_NoHostsIsNotAnObservation(t *testing.T) {
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		if os.Getenv("PILOT_REQUIRE_CONTAINER_TESTS") == "1" {
			t.Fatal(err)
		}
		t.Skip(err)
	}
	dir := t.TempDir()
	t.Setenv("ANSIBLE_LOCAL_TEMP", filepath.Join(dir, "ansible-local"))
	pb := filepath.Join(dir, "query.yml")
	if err := os.WriteFile(pb, []byte("- hosts: absent_servers\n  gather_facts: false\n  tasks:\n    - ansible.builtin.fail:\n        msg: must never execute\n"), 0600); err != nil {
		t.Fatal(err)
	}
	runner := ansible.NewRunner()
	res, err := runner.Run(context.Background(), pb, "-i", "localhost,")
	if err != nil || res.ExitCode != 0 || !strings.Contains(res.Stdout, "no hosts matched") {
		t.Fatalf("negative control must be a real exit-zero no-hosts run: result=%+v err=%v", res, err)
	}
	p := NewFreeIPAClientProvider(FreeIPAClientProviderConfig{Executor: runner, IdentityApplyPlaybook: pb, ServerInventory: "localhost,"})
	if _, err := p.Plan(context.Background(), PlanInput{HostName: "web1", FQDN: "web1.example.test"}); err == nil {
		t.Fatal("Plan accepted a query that observed no server")
	}
	if _, err := p.Verify(context.Background(), VerifyInput{FQDN: "web1.example.test"}); err == nil {
		t.Fatal("Verify accepted a query that observed no server")
	}
}

func TestFreeIPAQuery_RequiresTheTargetsObservation(t *testing.T) {
	for name, stdout := range map[string]string{
		"empty":                    "",
		"no marker":                hostShowNotFound,
		"other tombstone only":     `{"msg": "HOST_INSPECT[retired.example.test]: host not found"}`,
		"empty matching body":      `{"msg": "HOST_INSPECT[web1.example.test]: "}`,
		"whitespace matching body": `{"msg": "HOST_INSPECT[web1.example.test]: \n "}`,
	} {
		t.Run(name, func(t *testing.T) {
			p := NewFreeIPAClientProvider(FreeIPAClientProviderConfig{Executor: &fakeAnsibleExecutor{fn: func([]string) (*ansible.Result, error) {
				return &ansible.Result{Stdout: stdout}, nil
			}}})
			for _, kind := range []string{"host_object", "host_dns", "hbac_references", "sudo_references"} {
				if _, err := p.query(context.Background(), kind, "web1.example.test"); err == nil {
					t.Errorf("%s accepted missing/empty target observation", kind)
				}
			}
			if _, _, err := p.discoverUnknownServicePrincipals(context.Background(), "web1.example.test"); err == nil {
				t.Error("service ownership discovery accepted missing target")
			}
			step := &freeipaIdentityConvergeStep{provider: p, fqdn: "web1.example.test"}
			if converged, err := step.Inspect(context.Background()); err == nil || converged {
				t.Errorf("converge inspection = %v, %v; want false/error", converged, err)
			}
		})
	}
}
