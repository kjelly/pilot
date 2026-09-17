package spec

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestRegression_FreeipaServerPoolTask_TopologyModeGate locks that
// playbooks/apply/tasks/freeipa-server-pool.yml validates
// freeipa_client_topology_mode against the three legal values
// (docs/tmp/now/freeipa-client-ha-spec.md §2.2) before doing anything else,
// and defaults to "auto" when unset — existing single-server inventories
// must not need any new variable to keep working.
func TestRegression_FreeipaServerPoolTask_TopologyModeGate(t *testing.T) {
	const taskPath = "../../playbooks/apply/tasks/freeipa-server-pool.yml"
	raw, err := os.ReadFile(taskPath)
	if err != nil {
		t.Fatalf("read %s: %v", taskPath, err)
	}
	task := string(raw)

	if !strings.Contains(task, "freeipa_client_topology_mode | default('auto')") {
		t.Errorf("task must default freeipa_client_topology_mode to 'auto' when unset")
	}
	if !strings.Contains(task, "freeipa_client_topology_mode_input in ['auto', 'single', 'ha']") {
		t.Errorf("task must gate topology_mode against exactly auto|single|ha")
	}
}

// TestRegression_FreeipaServerPoolTask_PoolSourceFixed locks spec §3.1: pool
// membership comes ONLY from groups['freeipa-server'] then
// groups['freeipa-server-replica'] — never from DNS SRV discovery or an
// existing client's sssd.conf, both of which would make "desired state"
// drift with whatever happens to be reachable/configured right now instead
// of staying a pure inventory-driven declaration.
func TestRegression_FreeipaServerPoolTask_PoolSourceFixed(t *testing.T) {
	const taskPath = "../../playbooks/apply/tasks/freeipa-server-pool.yml"
	raw, err := os.ReadFile(taskPath)
	if err != nil {
		t.Fatalf("read %s: %v", taskPath, err)
	}
	task := string(raw)

	for _, want := range []string{
		"groups['freeipa-server']",
		"groups['freeipa-server-replica']",
	} {
		if !strings.Contains(task, want) {
			t.Errorf("task must read pool membership from %q", want)
		}
	}
	// Pool membership must be pure inventory/Jinja computation — no task in
	// this file may execute a remote command or read remote file state
	// (which is how a "derive from sssd.conf" or "derive from what's
	// currently reachable" anti-pattern would sneak in). Only
	// set_fact/assert/debug are allowed.
	for _, forbiddenModule := range []string{
		"ansible.builtin.command",
		"ansible.builtin.shell",
		"ansible.builtin.slurp",
		"ansible.builtin.uri",
		"ansible.builtin.raw",
	} {
		if strings.Contains(task, forbiddenModule) {
			t.Errorf("task must be pure inventory/Jinja computation — found remote-executing module %q (spec §3.1 forbids reachability/sssd.conf-derived pool membership)", forbiddenModule)
		}
	}
}

// TestRegression_FreeipaServerPoolTask_HAModeRequiresTwo locks spec §3.2:
// an operator-forced `ha` topology_mode with fewer than 2 pool members must
// fail closed, and this gate must only fire for ha mode — auto/single with
// a single provider must NOT be blocked by it (spec §2.1: single-node is a
// first-class, not degraded, mode).
func TestRegression_FreeipaServerPoolTask_HAModeRequiresTwo(t *testing.T) {
	const taskPath = "../../playbooks/apply/tasks/freeipa-server-pool.yml"
	raw, err := os.ReadFile(taskPath)
	if err != nil {
		t.Fatalf("read %s: %v", taskPath, err)
	}
	task := string(raw)

	gateIdx := strings.Index(task, "ha mode requires >= 2 providers")
	if gateIdx == -1 {
		t.Fatalf("could not find the ha->2-providers gate task")
	}
	// The gate task's `when:` must scope it to topology_mode_input == 'ha'
	// specifically, not fire unconditionally.
	gateBlock := task[gateIdx:]
	whenIdx := strings.Index(gateBlock, "when:")
	if whenIdx == -1 || !strings.Contains(gateBlock[whenIdx:whenIdx+120], "freeipa_client_topology_mode_input == 'ha'") {
		t.Errorf("the >=2-providers gate must be scoped to `when: freeipa_client_topology_mode_input == 'ha'`, not fire for auto/single")
	}
}

// TestRegression_FreeipaServerPoolTask_DuplicateInvariants locks spec §3.2's
// fail-closed duplicate checks: no two pool members may share an FQDN
// (which also covers "primary FQDN == replica FQDN" as a special case), and
// no two DIFFERENT FQDNs may share a non-empty IP.
func TestRegression_FreeipaServerPoolTask_DuplicateInvariants(t *testing.T) {
	const taskPath = "../../playbooks/apply/tasks/freeipa-server-pool.yml"
	raw, err := os.ReadFile(taskPath)
	if err != nil {
		t.Fatalf("read %s: %v", taskPath, err)
	}
	task := string(raw)

	if !strings.Contains(task, "no duplicate FQDNs in the pool") {
		t.Errorf("task must gate against duplicate FQDNs across the whole pool")
	}
	if !strings.Contains(task, "no IP reused across different FQDNs") {
		t.Errorf("task must gate against the same IP bound to two different FQDNs")
	}
}

// TestRegression_FreeipaServerPoolTask_MultiReplicaFQDNGate locks spec
// §3.2's "Replica FQDN backward compatibility" rule: a SINGLE replica may
// still rely on the legacy ipa2.<domain> default, but as soon as a second
// replica is present, every replica host must set its own
// freeipa_replica_fqdn — the task must fail closed rather than let two
// replicas silently collide on the same default FQDN.
func TestRegression_FreeipaServerPoolTask_MultiReplicaFQDNGate(t *testing.T) {
	const taskPath = "../../playbooks/apply/tasks/freeipa-server-pool.yml"
	raw, err := os.ReadFile(taskPath)
	if err != nil {
		t.Fatalf("read %s: %v", taskPath, err)
	}
	task := string(raw)

	gateIdx := strings.Index(task, "each need an explicit freeipa_replica_fqdn host var")
	if gateIdx == -1 {
		t.Fatalf("could not find the multi-replica FQDN gate task")
	}
	gateBlock := task[gateIdx:]
	whenIdx := strings.Index(gateBlock, "when:")
	if whenIdx == -1 || !strings.Contains(gateBlock[whenIdx:whenIdx+150], "groups['freeipa-server-replica'] | default([]) | length) > 1") {
		t.Errorf("the multi-replica FQDN gate must only fire when there is more than one replica host, so a single replica keeps the legacy ipa2.<domain> default")
	}
	if !strings.Contains(task, "'ipa2.' ~ freeipa_domain") {
		t.Errorf("task must still preserve the single-replica legacy default (ipa2.<domain>) for backward compatibility")
	}
}

// TestRegression_FreeipaServerPoolTask_SingleModeActiveUsesPrimaryOnly locks
// that a forced `single` topology_mode uses ONLY the primary for the active
// pool (freeipa_server_fqdns/ips/dns_server_ips), even when a replica is
// present in inventory — while freeipa_server_pool itself (the full
// discovered pool) still lists every member, so Phase 4 Day-2 reconciliation
// always has the true desired pool to converge toward without
// re-discovery when an operator later switches back to auto/ha.
func TestRegression_FreeipaServerPoolTask_SingleModeActiveUsesPrimaryOnly(t *testing.T) {
	const taskPath = "../../playbooks/apply/tasks/freeipa-server-pool.yml"
	raw, err := os.ReadFile(taskPath)
	if err != nil {
		t.Fatalf("read %s: %v", taskPath, err)
	}
	task := string(raw)

	activeIdx := strings.Index(task, "freeipa_server_pool_active:")
	if activeIdx == -1 {
		t.Fatalf("could not find freeipa_server_pool_active computation")
	}
	activeBlock := task[activeIdx : activeIdx+400]
	if !strings.Contains(activeBlock, "freeipa_server_pool_primary") {
		t.Errorf("freeipa_server_pool_active must fall back to freeipa_server_pool_primary (not the full pool) outside ha mode")
	}
	if !strings.Contains(activeBlock, "== 'ha'") {
		t.Errorf("freeipa_server_pool_active must branch on freeipa_client_topology_mode_effective == 'ha'")
	}
}

// TestRegression_FreeipaClientContract_TopologyModeGroupVar locks that
// contracts/freeipa-client.yaml declares freeipa_client_topology_mode as an
// optional group var, so `pilot contract lint` and any future
// contract-driven UI (pilot edit) surface it.
func TestRegression_FreeipaClientContract_TopologyModeGroupVar(t *testing.T) {
	const contractPath = "../../contracts/freeipa-client.yaml"
	raw, err := os.ReadFile(contractPath)
	if err != nil {
		t.Fatalf("read %s: %v", contractPath, err)
	}
	var doc struct {
		GroupVars []struct {
			Name     string `yaml:"name"`
			Type     string `yaml:"type"`
			Required bool   `yaml:"required"`
		} `yaml:"groupVars"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", contractPath, err)
	}
	for _, gv := range doc.GroupVars {
		if gv.Name == "freeipa_client_topology_mode" {
			if gv.Required {
				t.Errorf("freeipa_client_topology_mode must be optional (default auto) — existing single-server inventories must not need to set it")
			}
			if gv.Type != "string" {
				t.Errorf("freeipa_client_topology_mode type = %q, want string", gv.Type)
			}
			return
		}
	}
	t.Fatalf("contracts/freeipa-client.yaml groupVars is missing freeipa_client_topology_mode")
}
