package providers

import (
	"context"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/ansible"
)

const wazuhAgentListTwo = "AGENT_LIST[web1.ipa.pilot.internal]:    ID: 000, Name: wazuh-manager, IP: 127.0.0.1\n   ID: 001, Name: web1.ipa.pilot.internal, IP: any\n"
const wazuhAgentListEmpty = "AGENT_LIST[web1.ipa.pilot.internal]:    ID: 000, Name: wazuh-manager, IP: 127.0.0.1\n"

// TestWazuhProvider_RemovedByStableIdentity is HD14's exact acceptance
// probe (docs/verification/host-decommission.md): the manager-side agent
// registration is removed by an EXACT recorded identity match, never a
// hostname substring.
func TestWazuhProvider_RemovedByStableIdentity(t *testing.T) {
	var deregisterCalls int
	fake := &fakeAnsibleExecutor{fn: func(args []string) (*ansible.Result, error) {
		if argsContain(args, "agent_deregister") {
			deregisterCalls++
			if !argsContain(args, "pilot_decommission_target_agent_id=001") {
				t.Errorf("deregister call did not carry the exact resolved agent id 001: %v", args)
			}
			return &ansible.Result{Stdout: "Agent '001' removed."}, nil
		}
		if argsContain(args, "agent_query") {
			return &ansible.Result{Stdout: wazuhAgentListTwo}, nil
		}
		// local uninstall playbook run
		return &ansible.Result{}, nil
	}}
	p := NewWazuhAgentProvider(WazuhAgentProviderConfig{
		Executor:                  fake,
		ManagerDeregisterPlaybook: "playbooks/decommission/wazuh-manager-agent-deregister.yml",
		AgentDecommissionPlaybook: "playbooks/decommission/wazuh-agent-decommission.yml",
	})

	steps, err := p.Plan(context.Background(), PlanInput{HostName: "web1.ipa.pilot.internal"})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(steps) != 2 {
		t.Fatalf("expected 2 steps, got %d: %v", len(steps), steps)
	}

	var deregisterStep *Step
	for i := range steps {
		if steps[i].Action == ActionWazuhAgentDeregister {
			deregisterStep = &steps[i]
		}
	}
	if deregisterStep == nil {
		t.Fatalf("expected an %s step in the plan", ActionWazuhAgentDeregister)
	}

	se, err := p.ExecutorForStep(*deregisterStep)
	if err != nil {
		t.Fatalf("ExecutorForStep: %v", err)
	}
	converged, err := se.Inspect(context.Background())
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if converged {
		t.Fatalf("expected not-yet-converged while the agent is still listed")
	}
	if err := se.Execute(context.Background()); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if deregisterCalls != 1 {
		t.Errorf("expected exactly 1 deregister call, got %d", deregisterCalls)
	}
}

// TestWazuhProvider_ExactMatchNeverSubstring proves a host whose name is a
// SUBSTRING of a different registered agent's name is never matched or
// deregistered — spec.md §5.6's "name similarity or hostname substring
// alone is NOT ownership evidence".
func TestWazuhProvider_ExactMatchNeverSubstring(t *testing.T) {
	const listWithSimilarNames = "AGENT_LIST[web1]:    ID: 001, Name: web1.ipa.pilot.internal, IP: any\n   ID: 002, Name: web1.ipa.pilot.internal.staging, IP: any\n"
	fake := &fakeAnsibleExecutor{fn: func(args []string) (*ansible.Result, error) {
		return &ansible.Result{Stdout: listWithSimilarNames}, nil
	}}
	p := NewWazuhAgentProvider(WazuhAgentProviderConfig{Executor: fake, ManagerDeregisterPlaybook: "playbooks/decommission/wazuh-manager-agent-deregister.yml"})

	id, found, err := p.findAgentID(context.Background(), "web1.ipa.pilot.internal")
	if err != nil {
		t.Fatalf("findAgentID: %v", err)
	}
	if !found || id != "001" {
		t.Fatalf("expected exact match id=001, got id=%q found=%v", id, found)
	}

	// A name that is only a SUBSTRING of a registered agent (not an exact
	// match) must never resolve to that agent.
	_, found, err = p.findAgentID(context.Background(), "web1")
	if err != nil {
		t.Fatalf("findAgentID: %v", err)
	}
	if found {
		t.Fatalf("a substring match must never be treated as found")
	}
}

func TestWazuhProvider_AgentAlreadyGoneIsNoOp(t *testing.T) {
	var deregisterCalls int
	fake := &fakeAnsibleExecutor{fn: func(args []string) (*ansible.Result, error) {
		if argsContain(args, "agent_deregister") {
			deregisterCalls++
		}
		return &ansible.Result{Stdout: wazuhAgentListEmpty}, nil
	}}
	p := NewWazuhAgentProvider(WazuhAgentProviderConfig{Executor: fake, ManagerDeregisterPlaybook: "playbooks/decommission/wazuh-manager-agent-deregister.yml"})

	se, err := p.ExecutorForStep(Step{Action: ActionWazuhAgentDeregister, TargetIdentity: "web1.ipa.pilot.internal"})
	if err != nil {
		t.Fatalf("ExecutorForStep: %v", err)
	}
	converged, err := se.Inspect(context.Background())
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if !converged {
		t.Fatalf("expected converged=true when the agent is already absent from the manager's list")
	}
	if err := se.Execute(context.Background()); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if deregisterCalls != 0 {
		t.Errorf("Execute must not issue a deregister call when the agent is already gone, got %d calls", deregisterCalls)
	}
}

func TestWazuhProvider_VerifyDetectsActiveResidue(t *testing.T) {
	fake := &fakeAnsibleExecutor{fn: func(args []string) (*ansible.Result, error) {
		return &ansible.Result{Stdout: wazuhAgentListTwo}, nil
	}}
	p := NewWazuhAgentProvider(WazuhAgentProviderConfig{Executor: fake, ManagerDeregisterPlaybook: "playbooks/decommission/wazuh-manager-agent-deregister.yml"})
	verifs, err := p.Verify(context.Background(), VerifyInput{HostName: "web1.ipa.pilot.internal"})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(verifs) != 1 || !verifs[0].Active {
		t.Errorf("expected one Active=true verification for a still-registered agent, got %+v", verifs)
	}
}

func TestWazuhProvider_AnsibleFailureIsNotTreatedAsAbsent(t *testing.T) {
	fake := &fakeAnsibleExecutor{fn: func(args []string) (*ansible.Result, error) {
		return &ansible.Result{ExitCode: 1, Stderr: "unreachable"}, nil
	}}
	p := NewWazuhAgentProvider(WazuhAgentProviderConfig{Executor: fake, ManagerDeregisterPlaybook: "playbooks/decommission/wazuh-manager-agent-deregister.yml"})
	if _, err := p.Verify(context.Background(), VerifyInput{HostName: "web1.ipa.pilot.internal"}); err == nil {
		t.Fatalf("expected a genuinely failed ansible-playbook run to surface as an error, not a silent pass")
	}
}

func TestWazuhProvider_InspectReadsEnrollmentMarker(t *testing.T) {
	fake := &fakeAnsibleExecutor{fn: func(args []string) (*ansible.Result, error) {
		if !argsContain(args, "--tags") || !strings.Contains(strings.Join(args, " "), "inspect") {
			t.Errorf("Inspect must restrict execution to --tags inspect, got %v", args)
		}
		return &ansible.Result{Stdout: "WAZUH_AGENT_ENROLLED=true"}, nil
	}}
	p := NewWazuhAgentProvider(WazuhAgentProviderConfig{Executor: fake, AgentDecommissionPlaybook: "playbooks/decommission/wazuh-agent-decommission.yml"})
	insp, err := p.Inspect(context.Background(), InspectInput{HostName: "web1.ipa.pilot.internal"})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if !insp.Found {
		t.Errorf("expected Found=true for WAZUH_AGENT_ENROLLED=true, got %+v", insp)
	}
}
