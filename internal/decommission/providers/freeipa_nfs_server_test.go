package providers

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/ansible"
)

func writeNFSRoster(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "roster.yaml")
	content := `
schema_version: 1
freeipa:
  domain: ipa.pilot.internal
users: []
nfs:
  servers:
    - host: nfs1.ipa.pilot.internal
      state: present
      service_principal:
        ensure: true
        principal: nfs/nfs1.ipa.pilot.internal
        keytab: /etc/krb5.keytab
      shares: []
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write roster: %v", err)
	}
	return path
}

const nfsDecommissionedMarker = "NFS_SERVER_DECOMMISSIONED=true"
const nfsNotDecommissionedMarker = "NFS_SERVER_DECOMMISSIONED=false"

func TestFreeIPANFSServerProvider_FullCycle(t *testing.T) {
	dir := t.TempDir()
	roster := writeNFSRoster(t, dir)

	inspected := 0
	fake := &fakeAnsibleExecutor{fn: func(args []string) (*ansible.Result, error) {
		if argsContain(args, "--tags") && argsContain(args, "inspect") {
			inspected++
			if inspected == 1 {
				return &ansible.Result{Stdout: nfsNotDecommissionedMarker}, nil
			}
			return &ansible.Result{Stdout: nfsDecommissionedMarker}, nil
		}
		return &ansible.Result{}, nil
	}}
	p := NewFreeIPANFSServerProvider(FreeIPANFSServerProviderConfig{
		Executor:             fake,
		Inventory:            "inventory.yml",
		DecommissionPlaybook: "playbooks/decommission/freeipa-nfs-server-decommission.yml",
	})

	steps, err := p.Plan(context.Background(), PlanInput{HostName: "nfs1.ipa.pilot.internal", RosterPath: roster})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(steps) != 2 {
		t.Fatalf("expected 2 steps, got %d: %v", len(steps), steps)
	}

	for _, step := range steps {
		se, err := p.ExecutorForStep(step)
		if err != nil {
			t.Fatalf("ExecutorForStep(%s): %v", step.Action, err)
		}
		converged, err := se.Inspect(context.Background())
		if err != nil {
			t.Fatalf("Inspect(%s): %v", step.Action, err)
		}
		if converged {
			t.Fatalf("step %s reported converged before Execute ran", step.Action)
		}
		if err := se.Execute(context.Background()); err != nil {
			t.Fatalf("Execute(%s): %v", step.Action, err)
		}
	}

	absent, err := readNFSServerState(roster)
	if err != nil {
		t.Fatalf("read roster: %v", err)
	}
	if !absent {
		t.Errorf("expected the roster nfs.servers entry to converge to state: absent")
	}

	verifs, err := p.Verify(context.Background(), VerifyInput{FQDN: "nfs1.ipa.pilot.internal"})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(verifs) != 1 || verifs[0].Active {
		t.Fatalf("expected 1 verification with Active=false after cleanup, got %+v", verifs)
	}
}

func TestFreeIPANFSServerProvider_VerifyDetectsActiveResidue(t *testing.T) {
	fake := &fakeAnsibleExecutor{fn: func(args []string) (*ansible.Result, error) {
		return &ansible.Result{Stdout: nfsNotDecommissionedMarker}, nil
	}}
	p := NewFreeIPANFSServerProvider(FreeIPANFSServerProviderConfig{Executor: fake, DecommissionPlaybook: "playbooks/decommission/freeipa-nfs-server-decommission.yml"})
	verifs, err := p.Verify(context.Background(), VerifyInput{FQDN: "nfs1.ipa.pilot.internal"})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(verifs) != 1 || !verifs[0].Active {
		t.Fatalf("expected Active=true for a still-decommissioned=false host, got %+v", verifs)
	}
}

func TestFreeIPANFSServerProvider_AnsibleFailureIsNotTreatedAsDecommissioned(t *testing.T) {
	fake := &fakeAnsibleExecutor{fn: func(args []string) (*ansible.Result, error) {
		return &ansible.Result{ExitCode: 1, Stderr: "unreachable"}, nil
	}}
	p := NewFreeIPANFSServerProvider(FreeIPANFSServerProviderConfig{Executor: fake, DecommissionPlaybook: "playbooks/decommission/freeipa-nfs-server-decommission.yml"})
	if _, err := p.Verify(context.Background(), VerifyInput{FQDN: "nfs1.ipa.pilot.internal"}); err == nil {
		t.Fatalf("expected a genuinely failed ansible-playbook run to surface as an error, not a silent pass")
	}
}

func readNFSServerState(path string) (absent bool, err error) {
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		return false, readErr
	}
	return strings.Contains(string(data), "state: absent"), nil
}
