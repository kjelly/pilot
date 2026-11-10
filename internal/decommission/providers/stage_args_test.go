package providers

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/ansible"
)

var (
	hostStageArgs   = []string{"-e", "stage=staging", "-e", "confirm_staging=true"}
	serverStageArgs = []string{"-e", "stage=prod", "-e", "confirm_prod=true", "-e", "staging_attested_within_hours=24"}
)

func stageFunc(args []string) func() ([]string, error) {
	return func() ([]string, error) { return args, nil }
}

func hasArgs(call, want []string) bool {
	for i := 0; i+len(want) <= len(call); i++ {
		if slices.Equal(call[i:i+len(want)], want) {
			return true
		}
	}
	return false
}

func hasAnyStage(call []string) bool {
	for _, a := range call {
		if strings.HasPrefix(a, "stage=") {
			return true
		}
	}
	return false
}

// TestFreeIPAProvider_StageArgsPerTarget: runs on the retired host carry its
// stage; the freeipa-identity-apply.yml converge carries the freeipa-server
// hosts' stage; the read-only query, which also runs during `plan`, carries
// none.
func TestFreeIPAProvider_StageArgsPerTarget(t *testing.T) {
	exec := &fakeAnsibleExecutor{fn: func(args []string) (*ansible.Result, error) {
		if queryKind(args) != "" {
			// Native host-show resolves the short transport alias; this fixture
			// must not turn an unclassified string into an absence observation.
			body := "Host name: c1.ipa.pilot.internal\n0 services matched"
			if queryKind(args) == "gateway_scope" {
				body = "GATEWAY_SCOPE_READY=true"
			}
			return &ansible.Result{Stdout: "HOST_INSPECT[" + queryControl(args, "pilot_decommission_target_fqdn") + "]: " + body}, nil
		}
		return &ansible.Result{Stdout: "IPA_CLIENT_ENROLLED=true"}, nil
	}}
	p := NewFreeIPAClientProvider(FreeIPAClientProviderConfig{
		Executor:              exec,
		DecommissionPlaybook:  "playbooks/decommission/freeipa-client-decommission.yml",
		IdentityApplyPlaybook: "playbooks/apply/freeipa-identity-apply.yml",
		ClientStageArgs:       stageFunc(hostStageArgs),
		ServerStageArgs:       stageFunc(serverStageArgs),
	})
	// The converge step runs inside a run whose owner holds the identity lock.
	ctx := heldIdentityLock(t)
	if _, err := p.Inspect(ctx, InspectInput{HostName: "c1"}); err != nil {
		t.Fatal(err)
	}
	for _, step := range []Step{{Action: ActionFreeIPAClientUninstall, TargetIdentity: "c1"}, {Action: ActionFreeIPAIdentityApplyConverge, TargetIdentity: "c1.ipa.pilot.internal", Params: map[string]string{"inventory_alias": "c1"}}} {
		ex, err := p.ExecutorForStep(step)
		if err != nil {
			t.Fatal(err)
		}
		if err := ex.Execute(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.query(ctx, "host_object", "c1.ipa.pilot.internal"); err != nil {
		t.Fatal(err)
	}
	if len(exec.calls) != 6 {
		t.Fatalf("got %d ansible-playbook calls, want 6 including both read-only pre-uninstall probes", len(exec.calls))
	}
	for i, want := range map[int][]string{0: hostStageArgs, 3: hostStageArgs, 4: serverStageArgs} {
		if !hasArgs(exec.calls[i], want) {
			t.Errorf("call %d = %v, want %v", i, exec.calls[i], want)
		}
	}
	for _, i := range []int{1, 2, 5} {
		if hasAnyStage(exec.calls[i]) {
			t.Errorf("read-only query call %v carries a stage", exec.calls[i])
		}
	}

	// A stage error stops the run before ansible-playbook starts.
	stop := errors.New("prod needs --confirm-prod")
	exec.calls = nil
	p.cfg.ServerStageArgs = func() ([]string, error) { return nil, stop }
	ex, _ := p.ExecutorForStep(Step{Action: ActionFreeIPAIdentityApplyConverge, TargetIdentity: "c1.ipa.pilot.internal", Params: map[string]string{"inventory_alias": "c1"}})
	if err := ex.Execute(ctx); !errors.Is(err, stop) {
		t.Fatalf("Execute with a stage error = %v, want it to wrap %v", err, stop)
	}
	if len(exec.calls) != 0 {
		t.Fatalf("ansible-playbook ran despite the stage error: %v", exec.calls)
	}
}

// TestWazuhAgentProvider_StageArgsPerTarget: the agent's inspect and
// uninstall carry the retired host's stage, the deregistration the
// wazuh-manager hosts' stage, and the read-only agent_query neither.
func TestWazuhAgentProvider_StageArgsPerTarget(t *testing.T) {
	exec := &fakeAnsibleExecutor{fn: func(args []string) (*ansible.Result, error) {
		if argsContain(args, "agent_deregister") {
			return &ansible.Result{Stdout: "Agent '001' removed."}, nil
		}
		return &ansible.Result{Stdout: wazuhAgentListTwo}, nil
	}}
	p := NewWazuhAgentProvider(WazuhAgentProviderConfig{
		Executor:                  exec,
		AgentDecommissionPlaybook: "playbooks/decommission/wazuh-agent-decommission.yml",
		ManagerDeregisterPlaybook: "playbooks/decommission/wazuh-manager-agent-deregister.yml",
		AgentStageArgs:            stageFunc(hostStageArgs),
		ManagerStageArgs:          stageFunc(serverStageArgs),
	})
	ctx := context.Background()
	if _, err := p.Inspect(ctx, InspectInput{HostName: "web1.ipa.pilot.internal"}); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{ActionWazuhAgentUninstall, ActionWazuhAgentDeregister} {
		ex, err := p.ExecutorForStep(Step{Action: action, TargetIdentity: "web1.ipa.pilot.internal"})
		if err != nil {
			t.Fatal(err)
		}
		if err := ex.Execute(ctx); err != nil {
			t.Fatal(err)
		}
	}
	sawDeregister := false
	for _, call := range exec.calls {
		switch {
		case argsContain(call, "agent_deregister"):
			sawDeregister = true
			if !hasArgs(call, serverStageArgs) {
				t.Errorf("deregister call %v lacks the manager stage", call)
			}
		case argsContain(call, "agent_query"):
			if hasAnyStage(call) {
				t.Errorf("read-only agent_query call %v carries a stage", call)
			}
		case argsContain(call, "wazuh-agent-decommission.yml"):
			if !hasArgs(call, hostStageArgs) {
				t.Errorf("agent call %v lacks the retired host's stage", call)
			}
		}
	}
	if !sawDeregister {
		t.Fatal("no deregister call was made")
	}
}

// TestInternalEndpointProvider_StageArgs: apply-converge carries the stage
// of every host; the read-only query carries none.
func TestInternalEndpointProvider_StageArgs(t *testing.T) {
	exec := &fakeAnsibleExecutor{}
	p := NewInternalEndpointProvider(InternalEndpointProviderConfig{
		Executor:       exec,
		ApplyPlaybook:  "playbooks/apply/internal-endpoint-apply.yml",
		ApplyStageArgs: stageFunc(serverStageArgs),
	})
	ctx := context.Background()
	ex, err := p.ExecutorForStep(Step{Action: ActionInternalEndpointApplyConverge, TargetIdentity: "app.apps.pilot.internal"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ex.Execute(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := p.query(ctx, "endpoint_object", "app.apps.pilot.internal"); err != nil {
		t.Fatal(err)
	}
	if len(exec.calls) != 2 || !hasArgs(exec.calls[0], serverStageArgs) || hasAnyStage(exec.calls[1]) {
		t.Fatalf("calls = %v, want apply-converge with the stage and the query without", exec.calls)
	}
}

// TestFreeIPANFSServerProvider_StageArgs: both runs target the retired host.
func TestFreeIPANFSServerProvider_StageArgs(t *testing.T) {
	exec := &fakeAnsibleExecutor{}
	p := NewFreeIPANFSServerProvider(FreeIPANFSServerProviderConfig{
		Executor:             exec,
		DecommissionPlaybook: "playbooks/decommission/freeipa-nfs-server-decommission.yml",
		StageArgs:            stageFunc(hostStageArgs),
	})
	ctx := context.Background()
	if _, err := p.Inspect(ctx, InspectInput{HostName: "nfs1"}); err != nil {
		t.Fatal(err)
	}
	ex, err := p.ExecutorForStep(Step{Action: ActionFreeIPANFSDecommission, TargetIdentity: "nfs1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ex.Execute(ctx); err != nil {
		t.Fatal(err)
	}
	if len(exec.calls) != 2 || !hasArgs(exec.calls[0], hostStageArgs) || !hasArgs(exec.calls[1], hostStageArgs) {
		t.Fatalf("calls = %v, want both with the retired host's stage", exec.calls)
	}
}
