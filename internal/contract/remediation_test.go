package contract

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// baseRemediationContract returns a minimally-valid Contract with one
// valid remediation action — each test below mutates a copy to exercise
// exactly one rejection path (Agent Monitoring Phase 3 §12).
func baseRemediationContract() Contract {
	return Contract{
		SchemaVersion: SchemaVersion, ID: "prometheus", Role: "prometheus",
		Specs:           []Spec{{Path: "docs/verification/prometheus.md", Rows: RowSelector{All: true}}},
		Playbooks:       Playbooks{Apply: "playbooks/apply/prometheus-apply.yml"},
		HostCardinality: "one-or-more", StagePolicy: StagePolicy{Variable: "stage", Default: "sandbox"},
		EvidenceRequirement: Evidence{TargetTest: "topology", Idempotency: "required"},
		Verification:        Verification{AutoDeploy: boolPtr(false)},
		Remediation: Remediation{Actions: []RemediationAction{
			{ID: "restart", Risk: "R1", Executor: RemediationActionExecutor{Kind: "docker_restart", Target: "pilot-prometheus"},
				MaxTargets: 1, RequiresApproval: true, Verification: RemediationVerification{Spec: "docs/verification/prometheus.md"}},
		}},
	}
}

func boolPtr(b bool) *bool { return &b }

func TestValidateRemediation_ValidContractPasses(t *testing.T) {
	c := baseRemediationContract()
	if err := validateLocal(c); err != nil {
		t.Fatalf("validateLocal: %v", err)
	}
}

func TestValidateRemediation_NoBlockIsValid(t *testing.T) {
	c := baseRemediationContract()
	c.Remediation = Remediation{}
	if err := validateLocal(c); err != nil {
		t.Fatalf("validateLocal (no remediation block): %v", err)
	}
}

func TestValidateRemediation_DuplicateIDsRejected(t *testing.T) {
	c := baseRemediationContract()
	c.Remediation.Actions = append(c.Remediation.Actions, c.Remediation.Actions[0])
	if err := validateLocal(c); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("err = %v, want a duplicate-id error", err)
	}
}

func TestValidateRemediation_InvalidRiskRejected(t *testing.T) {
	c := baseRemediationContract()
	c.Remediation.Actions[0].Risk = "R5"
	if err := validateLocal(c); err == nil {
		t.Fatal("expected an error for an invalid risk value")
	}
}

func TestValidateRemediation_InvalidExecutorKindRejected(t *testing.T) {
	c := baseRemediationContract()
	c.Remediation.Actions[0].Executor.Kind = "shell_exec"
	if err := validateLocal(c); err == nil {
		t.Fatal("expected an error for an invalid executor kind")
	}
}

func TestValidateRemediation_EmptyExecutorTargetRejected(t *testing.T) {
	c := baseRemediationContract()
	c.Remediation.Actions[0].Executor.Target = ""
	if err := validateLocal(c); err == nil {
		t.Fatal("expected an error for an empty executor target")
	}
}

func TestValidateRemediation_WildcardExecutorTargetRejected(t *testing.T) {
	c := baseRemediationContract()
	c.Remediation.Actions[0].Executor.Target = "pilot-*"
	if err := validateLocal(c); err == nil {
		t.Fatal("expected an error for a wildcard executor target")
	}
}

func TestValidateRemediation_MaxTargetsNotOneRejected(t *testing.T) {
	for _, n := range []int{0, 2, 5} {
		c := baseRemediationContract()
		c.Remediation.Actions[0].MaxTargets = n
		if err := validateLocal(c); err == nil {
			t.Fatalf("maxTargets=%d: expected an error (Phase 3 requires exactly 1)", n)
		}
	}
}

func TestValidateRemediation_MissingVerificationSpecRejected(t *testing.T) {
	c := baseRemediationContract()
	c.Remediation.Actions[0].Verification.Spec = ""
	if err := validateLocal(c); err == nil {
		t.Fatal("expected an error for a missing verification.spec")
	}
}

func TestValidateRemediation_VerificationSpecMustBelongToComponent(t *testing.T) {
	c := baseRemediationContract()
	c.Remediation.Actions[0].Verification.Spec = "docs/verification/some-other-component.md"
	if err := validateLocal(c); err == nil {
		t.Fatal("expected an error: verification.spec must match one of this component's own specs[].path")
	}
}

// TestRemediation_CommandFieldCannotBeRepresentedByTypedSchema locks in
// spec §12's structural guarantee: KnownFields(true) YAML decoding
// rejects an unknown "command" key outright — there is no way to author
// a contract that smuggles a generic executor through this metadata,
// not even by a future careless edit to a contract YAML file.
func TestRemediation_CommandFieldCannotBeRepresentedByTypedSchema(t *testing.T) {
	yamlWithCommand := `
executor:
  kind: docker_restart
  target: pilot-prometheus
  command: "rm -rf /"
`
	dec := yaml.NewDecoder(strings.NewReader(yamlWithCommand))
	dec.KnownFields(true)
	var wrapper struct {
		Executor RemediationActionExecutor `yaml:"executor"`
	}
	if err := dec.Decode(&wrapper); err == nil {
		t.Fatal("expected KnownFields(true) decoding to reject an unknown 'command' key under executor")
	}
}
