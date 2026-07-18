package spec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validV2 = `---
schemaVersion: 2
compatibility: {minPilotVersion: "0.9"}
intent: {summary: v2-fixture, source: test, maintainer: sre}
targets:
  roles: [docker]
  hostScope: per-host
  platforms:
    - {os: ubuntu, versions: ["22.04", "24.04"]}
  hosts:
    - hostname: host-a
      group: docker
inputs: []
traceability: {components: [docker]}
defaults:
  become: false
  timeout: 10s
  action: {mode: readOnly}
evidencePolicy: {captureStdout: true, retention: default}
---
# Verification Spec — v2 fixture

## Checks

` + "```yaml" + `
- id: C1
  category: service
  check: daemon active
  probe: systemctl is-active docker
  expect:
    exitCode: 0
    stdout: {equals: active}
- id: C2
  category: api
  check: aggregate status
  probe: echo ready
  scope: aggregate
  expect: {stdout: {contains: ready}}
` + "```" + `
`

func writeV2(path, body string) error { return os.WriteFile(path, []byte(body), 0o644) }

func TestParseV2(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v2.md")
	if err := writeV2(path, validV2); err != nil {
		t.Fatal(err)
	}
	s, err := Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.SchemaVersion != 2 || len(s.Rows) != 2 || len(s.Hosts) != 1 {
		t.Fatalf("spec=%+v", s)
	}
	if s.MinPilotVersion != "0.9" || s.HostScope != "per-host" || len(s.Platforms) != 1 || s.EvidencePolicy.CaptureStdout == nil {
		t.Fatalf("front matter was not preserved: %+v", s)
	}
	if s.Rows[0].Expect.ExitCode == nil || *s.Rows[0].Expect.ExitCode != 0 || s.Rows[0].Action.Mode != "readOnly" {
		t.Fatalf("row=%+v", s.Rows[0])
	}
	if s.Rows[1].Scope != "aggregate" {
		t.Fatalf("scope=%q", s.Rows[1].Scope)
	}
}

func TestParseReaderDispatchesV2(t *testing.T) {
	s, err := ParseReader(strings.NewReader(validV2))
	if err != nil {
		t.Fatal(err)
	}
	if s.SchemaVersion != 2 || len(s.Rows) != 2 {
		t.Fatalf("spec=%+v", s)
	}
}

func TestParseV2RepositoryFixture(t *testing.T) {
	s, err := Parse(filepath.Join("testdata", "v2", "read-only.md"))
	if err != nil {
		t.Fatal(err)
	}
	if s.SchemaVersion != 2 || len(s.Rows) != 1 || s.Rows[0].Action.Mode != "readOnly" {
		t.Fatalf("spec=%+v", s)
	}
}

func TestParseV2RejectsStructuralErrors(t *testing.T) {
	tests := []struct{ name, mutate, want string }{
		{"unknown version", "schemaVersion: 3", "schemaVersion must be 2"},
		{"unknown field", "intent: {summary: v2-fixture, source: test, maintainer: sre, nope: true}", "field nope not found"},
		{"missing compatibility", "compatibility: {minPilotVersion: \"0.9\"}", "compatibility.minPilotVersion is required"},
		{"empty roles", "  roles: [docker]", "targets.roles must not be empty"},
		{"missing action", "  action: {mode: readOnly}", "defaults.become and defaults.action are required"},
		{"scalar action", "  action: readOnly", "cannot unmarshal !!str"},
		{"boolean secret ref", "inputs: []", "cannot unmarshal !!bool"},
		{"empty matcher", "expect: {}", "at least one matcher"},
		{"bad union", "expect: {stdout: {equals: active, contains: act}}", "exactly one predicate"},
		{"bad applicability union", "  expect: {stdout: {contains: ready}}", "must set exactly one of always, all, any"},
		{"unterminated checks", "```", "unterminated checks YAML block"},
		{"multiple YAML documents", "schemaVersion: 2", "multiple YAML documents"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := validV2
			switch tt.name {
			case "unknown version":
				raw = strings.Replace(raw, "schemaVersion: 2", tt.mutate, 1)
			case "unknown field":
				raw = strings.Replace(raw, "intent: {summary: v2-fixture, source: test, maintainer: sre}", tt.mutate, 1)
			case "missing compatibility":
				raw = strings.Replace(raw, tt.mutate+"\n", "", 1)
			case "empty roles":
				raw = strings.Replace(raw, tt.mutate, "  roles: []", 1)
			case "missing action":
				raw = strings.Replace(raw, tt.mutate+"\n", "", 1)
			case "scalar action":
				raw = strings.Replace(raw, "  action: {mode: readOnly}", tt.mutate, 1)
			case "boolean secret ref":
				raw = strings.Replace(raw, tt.mutate, "inputs: [{name: token, required: true, secretRef: true}]", 1)
			case "empty matcher", "bad union":
				raw = strings.Replace(raw, "expect:\n    exitCode: 0\n    stdout: {equals: active}", tt.mutate, 1)
			case "bad applicability union":
				raw = strings.Replace(raw, tt.mutate, "  appliesWhen: {always: true, all: [{stage: {in: [sandbox]}}]}\n"+tt.mutate, 1)
			case "unterminated checks":
				raw = strings.TrimSuffix(raw, tt.mutate+"\n")
			case "multiple YAML documents":
				raw = strings.Replace(raw, "  expect: {stdout: {contains: ready}}", "  expect: {stdout: {contains: ready}}\n---\n[]", 1)
			}
			path := filepath.Join(t.TempDir(), "bad.md")
			if err := writeV2(path, raw); err != nil {
				t.Fatal(err)
			}
			_, err := Parse(path)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err=%v want=%q", err, tt.want)
			}
		})
	}
}

func TestV2ApplicabilityValidationAndEvaluation(t *testing.T) {
	inputs := []Input{{Name: "feature"}}
	components := []string{"db"}
	value := "on"
	valid := &Applicability{All: []Condition{{Input: &InputCondition{Name: "feature", Operator: "equals", Value: &value}}, {Dependency: &DependencyCondition{Component: "db", State: "selected"}}}}
	if err := validateApplicability(valid, inputs, components); err != nil {
		t.Fatal(err)
	}
	result, err := EvaluateApplicability(valid, ApplicabilityContext{Inputs: map[string]string{"feature": "on"}, Components: map[string]bool{"db": true}, Stage: "sandbox"})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Applicable {
		t.Fatalf("result=%+v", result)
	}
	result, err = EvaluateApplicability(valid, ApplicabilityContext{Inputs: map[string]string{"feature": "off"}, Components: map[string]bool{"db": true}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Applicable {
		t.Fatalf("result=%+v", result)
	}
	_, err = EvaluateApplicability(&Applicability{All: []Condition{{Dependency: &DependencyCondition{Component: "db", State: "selected"}}}}, ApplicabilityContext{})
	if err == nil {
		t.Fatal("missing dependency selection did not fail closed")
	}
	bad := &Applicability{All: []Condition{{Input: &InputCondition{Name: "missing", Operator: "set"}}}}
	if err := validateApplicability(bad, inputs, components); err == nil {
		t.Fatal("undeclared input accepted")
	}
}

func TestLintV2ReadOnlyMutation(t *testing.T) {
	s := &Spec{SchemaVersion: 2, Rows: []Row{{ID: "C1", Expected: "typed", Command: "curl -X POST https://example.invalid", Action: &Action{Mode: "readOnly"}, Line: 1}}}
	if !HasErrors(Lint(s)) {
		t.Fatal("readOnly POST did not produce lint error")
	}
}

func TestLintV2OptionalInputRequiresApplicability(t *testing.T) {
	s := &Spec{
		SchemaVersion: 2,
		Inputs:        []Input{{Name: "feature"}},
		Rows: []Row{{
			ID:       "C1",
			Expected: "typed",
			Command:  `test "$PILOT_VAR_FEATURE" = on`,
			Expect:   Expect{ExitCode: intPtr(0)},
			Action:   &Action{Mode: "readOnly"},
			Line:     1,
		}},
	}
	if !HasErrors(Lint(s)) {
		t.Fatal("optional input without applicability did not produce lint error")
	}
	s.Rows[0].AppliesWhen = &Applicability{All: []Condition{{Input: &InputCondition{Name: "feature", Operator: "set"}}}}
	if HasErrors(Lint(s)) {
		t.Fatalf("applicability did not satisfy optional-input lint: %v", Lint(s))
	}
}

func TestValidateActionRequiresCompleteCleanup(t *testing.T) {
	action := &Action{Mode: "isolatedMutation", Authorization: "explicit", ResidualRisk: "temporary object", Cleanup: &Cleanup{Required: true}}
	if err := validateAction(action); err == nil {
		t.Fatal("incomplete isolatedMutation cleanup accepted")
	}
	action.Cleanup.Probe = "true"
	action.Cleanup.Expect = &Expect{ExitCode: intPtr(0)}
	if err := validateAction(action); err != nil {
		t.Fatalf("complete isolatedMutation rejected: %v", err)
	}
}
