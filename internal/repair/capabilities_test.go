package repair

import (
	"testing"

	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/networkcheck"
)

func testCatalog(t *testing.T, contracts ...contract.Contract) contract.Catalog {
	t.Helper()
	catalog, err := contract.NewCatalog(contracts)
	if err != nil {
		t.Fatalf("NewCatalog: %v", err)
	}
	return catalog
}

func TestListCapabilities_OnlyR1AndOnlyAssignedHosts(t *testing.T) {
	prometheus := contract.Contract{
		ID: "prometheus", Role: "prometheus",
		Playbooks: contract.Playbooks{Apply: "playbooks/apply/prometheus-apply.yml"},
		Remediation: contract.Remediation{Actions: []contract.RemediationAction{
			{ID: "restart", Risk: "R1", Executor: contract.RemediationActionExecutor{Kind: "docker_restart", Target: "pilot-prometheus"}, MaxTargets: 1},
		}},
	}
	freeipa := contract.Contract{
		ID: "freeipa-server", Role: "freeipa-server",
		Playbooks: contract.Playbooks{Apply: "playbooks/apply/freeipa-server-apply.yml"},
		Remediation: contract.Remediation{Actions: []contract.RemediationAction{
			{ID: "reconcile", Risk: "R2", Executor: contract.RemediationActionExecutor{Kind: "systemd_restart", Target: "ipa.service"}, MaxTargets: 1},
		}},
	}
	docker := contract.Contract{ID: "docker", Role: "docker", Playbooks: contract.Playbooks{Apply: "playbooks/apply/docker-apply.yml"}}
	catalog := testCatalog(t, prometheus, freeipa, docker)

	resolved := networkcheck.ResolvedInventory{
		GroupHosts: map[string][]string{"prometheus": {"web-1", "web-2"}, "freeipa-server": {"ipa-1"}},
		HostVars:   map[string]map[string]any{"web-1": {}, "web-2": {}, "ipa-1": {}},
	}

	caps := ListCapabilities(catalog, resolved)
	if len(caps) != 2 {
		t.Fatalf("caps = %+v, want 2 (prometheus restart x2 hosts, freeipa R2 excluded)", caps)
	}
	for _, c := range caps {
		if c.Risk != "R1" {
			t.Errorf("capability %+v has non-R1 risk", c)
		}
		if c.Component != "prometheus" {
			t.Errorf("capability %+v: only prometheus should appear (freeipa is R2)", c)
		}
	}
}

func TestListCapabilities_ComponentWithNoRemediationBlockContributesNothing(t *testing.T) {
	docker := contract.Contract{ID: "docker", Role: "docker", Playbooks: contract.Playbooks{Apply: "playbooks/apply/docker-apply.yml"}}
	catalog := testCatalog(t, docker)
	resolved := networkcheck.ResolvedInventory{GroupHosts: map[string][]string{"docker": {"web-1"}}, HostVars: map[string]map[string]any{"web-1": {}}}
	caps := ListCapabilities(catalog, resolved)
	if len(caps) != 0 {
		t.Fatalf("caps = %+v, want empty", caps)
	}
}
