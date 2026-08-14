package spec

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestRegression_InternalEndpointSpec locks the Phase 1 shape (spec.md §63)
// of docs/verification/internal-endpoint.md: all 32 rows (the v1.0
// acceptance set C1-C26 plus the v1.1 reverse-proxy HTTPS-upstream
// revision C27-C32, spec.md §67) exist with a non-empty command/expected,
// and the spec lints clean.
func TestRegression_InternalEndpointSpec(t *testing.T) {
	const specPath = "../../docs/verification/internal-endpoint.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}

	wantIDs := make([]string, 0, 32)
	for i := 1; i <= 32; i++ {
		wantIDs = append(wantIDs, "C"+itoaInternalEndpoint(i))
	}
	if len(s.Rows) != len(wantIDs) {
		t.Fatalf("rows=%d want=%d", len(s.Rows), len(wantIDs))
	}
	gotIDs := make([]string, 0, len(s.Rows))
	seen := map[string]bool{}
	for _, row := range s.Rows {
		if seen[row.ID] {
			t.Errorf("duplicate row ID %q", row.ID)
		}
		seen[row.ID] = true
		gotIDs = append(gotIDs, row.ID)
		if strings.TrimSpace(row.Command) == "" || strings.TrimSpace(row.Expected) == "" {
			t.Errorf("row %s has an empty command or expected value", row.ID)
		}
	}
	if strings.Join(gotIDs, ",") != strings.Join(wantIDs, ",") {
		t.Errorf("row IDs=%v want=%v", gotIDs, wantIDs)
	}
	if findings := Lint(s); HasErrors(findings) {
		t.Errorf("spec lint errors:\n%s", fsToString(findings))
	}
}

func itoaInternalEndpoint(i int) string {
	if i < 10 {
		return string(rune('0' + i))
	}
	tens := i / 10
	ones := i % 10
	return string(rune('0'+tens)) + string(rune('0'+ones))
}

// internalEndpointContract is a minimal local decode of
// contracts/internal-endpoint.yaml — just the fields this test locks — so
// this test doesn't need to import internal/contract (which itself
// imports internal/spec).
type internalEndpointContract struct {
	ID              string                           `yaml:"id"`
	Role            string                           `yaml:"role"`
	HostCardinality string                           `yaml:"hostCardinality"`
	Dependencies    []internalEndpointDependency     `yaml:"dependencies"`
	GroupVars       []internalEndpointGroupVar       `yaml:"groupVars"`
	Traceability    internalEndpointTraceability     `yaml:"traceability"`
	Site            internalEndpointSite             `yaml:"site"`
	Playbooks       map[string]string                `yaml:"playbooks"`
	RegressionTests []string                         `yaml:"regressionTests"`
	Specs           []internalEndpointContractedSpec `yaml:"specs"`
}

type internalEndpointDependency struct {
	Component string `yaml:"component"`
	Required  bool   `yaml:"required"`
	Relation  string `yaml:"relation"`
	Reason    string `yaml:"reason"`
}

type internalEndpointGroupVar struct {
	Name     string `yaml:"name"`
	Required bool   `yaml:"required"`
	Secret   bool   `yaml:"secret"`
}

type internalEndpointTraceability struct {
	Mode       string                               `yaml:"mode"`
	Tag        *internalEndpointTagStrategy         `yaml:"tag"`
	Exemptions map[string]internalEndpointExemption `yaml:"exemptions"`
}

type internalEndpointTagStrategy struct {
	Kind   string `yaml:"kind"`
	Prefix string `yaml:"prefix"`
}

type internalEndpointExemption struct {
	Kind   string   `yaml:"kind"`
	Tags   []string `yaml:"tags"`
	Reason string   `yaml:"reason"`
}

type internalEndpointSite struct {
	Include bool `yaml:"include"`
	OptIn   bool `yaml:"optIn"`
}

type internalEndpointContractedSpec struct {
	Path string `yaml:"path"`
}

// TestRegression_InternalEndpointContract locks spec.md §43.3's
// contract-shape requirements: day-2 (site.include: false), sameHosts on
// freeipa-server, the required-secret ipa_admin_password + required
// internal_endpoint_manifest_file group vars, and hostCardinality:
// exactly-one.
func TestRegression_InternalEndpointContract(t *testing.T) {
	const contractPath = "../../contracts/internal-endpoint.yaml"
	raw, err := os.ReadFile(contractPath)
	if err != nil {
		t.Fatalf("read %s: %v", contractPath, err)
	}
	var c internalEndpointContract
	if err := yaml.Unmarshal(raw, &c); err != nil {
		t.Fatalf("parse %s: %v", contractPath, err)
	}

	if c.ID != "internal-endpoint" {
		t.Errorf("id = %q, want internal-endpoint", c.ID)
	}
	if c.HostCardinality != "exactly-one" {
		t.Errorf("hostCardinality = %q, want exactly-one (spec.md §43.3)", c.HostCardinality)
	}
	if c.Site.Include {
		t.Error("site.include must be false — internal-endpoint is a day-2 reconciler, not part of site.yml (spec.md §7)")
	}
	if !c.Site.OptIn {
		t.Error("site.optIn must be true")
	}

	foundSameHosts := false
	for _, dep := range c.Dependencies {
		if dep.Component == "freeipa-server" {
			foundSameHosts = true
			if dep.Relation != "sameHosts" {
				t.Errorf("freeipa-server dependency relation = %q, want sameHosts", dep.Relation)
			}
			if !dep.Required {
				t.Error("freeipa-server dependency must be required")
			}
		}
		if dep.Relation == "planOnly" && dep.Reason == "" {
			t.Errorf("planOnly dependency %q requires a reason", dep.Component)
		}
	}
	if !foundSameHosts {
		t.Error("contract must declare a sameHosts dependency on freeipa-server")
	}

	wantGroupVars := map[string]struct {
		required bool
		secret   bool
	}{
		"ipa_admin_password":              {required: true, secret: true},
		"internal_endpoint_manifest_file": {required: true, secret: false},
	}
	seenGroupVars := map[string]bool{}
	for _, gv := range c.GroupVars {
		want, ok := wantGroupVars[gv.Name]
		if !ok {
			continue
		}
		seenGroupVars[gv.Name] = true
		if gv.Required != want.required || gv.Secret != want.secret {
			t.Errorf("groupVar %s = {required:%v secret:%v}, want {required:%v secret:%v}", gv.Name, gv.Required, gv.Secret, want.required, want.secret)
		}
	}
	for name := range wantGroupVars {
		if !seenGroupVars[name] {
			t.Errorf("contract must declare groupVar %s", name)
		}
	}

	if c.Traceability.Mode != "rowTags" {
		t.Fatalf("traceability.mode = %q, want rowTags", c.Traceability.Mode)
	}
	if c.Traceability.Tag == nil || c.Traceability.Tag.Kind != "bare" {
		t.Fatal("traceability.tag.kind must be bare")
	}

	verifyOnlyRows := []string{"C1", "C2", "C3", "C11", "C14", "C16", "C17", "C18", "C19", "C20", "C26", "C28", "C29", "C30", "C31", "C32"}
	for _, id := range verifyOnlyRows {
		ref := "docs/verification/internal-endpoint.md#" + id
		exemption, ok := c.Traceability.Exemptions[ref]
		if !ok {
			t.Errorf("traceability.exemptions is missing %s", ref)
			continue
		}
		if exemption.Reason == "" {
			t.Errorf("exemption %s must have a reason", ref)
		}
		if len(exemption.Tags) != 0 {
			t.Errorf("exemption %s is verifyOnly and must not reference tags", ref)
		}
	}

	const derivedRef = "docs/verification/internal-endpoint.md#C25"
	derived, ok := c.Traceability.Exemptions[derivedRef]
	if !ok {
		t.Fatalf("traceability.exemptions is missing %s", derivedRef)
	}
	if derived.Reason == "" {
		t.Errorf("exemption %s must have a reason", derivedRef)
	}
	if len(derived.Tags) != 1 || derived.Tags[0] != "C4" {
		t.Errorf("exemption %s tags = %v, want [C4]", derivedRef, derived.Tags)
	}

	tagged := []string{"C4", "C5", "C6", "C7", "C8", "C9", "C10", "C12", "C13", "C15", "C21", "C22", "C23", "C24", "C27"}
	for _, id := range tagged {
		ref := "docs/verification/internal-endpoint.md#" + id
		if _, exempt := c.Traceability.Exemptions[ref]; exempt {
			t.Errorf("row %s must not be exempted — it should be tagged", ref)
		}
	}

	if c.Playbooks["apply"] != "playbooks/apply/internal-endpoint-apply.yml" {
		t.Errorf("playbooks.apply = %q, want playbooks/apply/internal-endpoint-apply.yml", c.Playbooks["apply"])
	}
	wantSpec := "docs/verification/internal-endpoint.md"
	foundSpec := false
	for _, s := range c.Specs {
		if s.Path == wantSpec {
			foundSpec = true
		}
	}
	if !foundSpec {
		t.Errorf("contract must reference spec %s", wantSpec)
	}
}

// TestRegression_InternalEndpointApplyPlaybookCoversContractTags locks that
// every non-exempt row's bare tag (plus C25's derived tag C4) exists in the
// apply playbook, and that no exempted row's own bare tag leaked in (which
// would make that exemption stale).
func TestRegression_InternalEndpointApplyPlaybookCoversContractTags(t *testing.T) {
	contractRaw, err := os.ReadFile("../../contracts/internal-endpoint.yaml")
	if err != nil {
		t.Fatalf("read contract: %v", err)
	}
	var c internalEndpointContract
	if err := yaml.Unmarshal(contractRaw, &c); err != nil {
		t.Fatalf("parse contract: %v", err)
	}

	const playbookPath = "../../playbooks/apply/internal-endpoint-apply.yml"
	playbookRaw, err := os.ReadFile(playbookPath)
	if err != nil {
		t.Fatalf("read %s: %v", playbookPath, err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(playbookRaw, &doc); err != nil {
		t.Fatalf("parse %s: %v", playbookPath, err)
	}
	tags := map[string]bool{}
	collectInternalEndpointPlaybookTags(&doc, tags)

	tagged := []string{"C4", "C5", "C6", "C7", "C8", "C9", "C10", "C12", "C13", "C15", "C21", "C22", "C23", "C24", "C27"}
	for _, id := range tagged {
		if !tags[id] {
			t.Errorf("%s has no tag %q required by traceability", playbookPath, id)
		}
	}
	verifyOnlyRows := []string{"C1", "C2", "C3", "C11", "C14", "C16", "C17", "C18", "C19", "C20", "C25", "C26", "C28", "C29", "C30", "C31", "C32"}
	for _, id := range verifyOnlyRows {
		if tags[id] {
			t.Errorf("%s unexpectedly has tag %q — its exemption is now stale", playbookPath, id)
		}
	}
	if derived, ok := c.Traceability.Exemptions["docs/verification/internal-endpoint.md#C25"]; ok {
		for _, tag := range derived.Tags {
			if !tags[tag] {
				t.Errorf("%s C25's derived tag %q is missing from the playbook", playbookPath, tag)
			}
		}
	}
}

func collectInternalEndpointPlaybookTags(n *yaml.Node, out map[string]bool) {
	if n == nil {
		return
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if k.Kind == yaml.ScalarNode && k.Value == "tags" {
				switch v.Kind {
				case yaml.ScalarNode:
					out[v.Value] = true
				case yaml.SequenceNode:
					for _, item := range v.Content {
						if item.Kind == yaml.ScalarNode {
							out[item.Value] = true
						}
					}
				}
			}
			collectInternalEndpointPlaybookTags(v, out)
		}
		return
	}
	for _, c := range n.Content {
		collectInternalEndpointPlaybookTags(c, out)
	}
}
